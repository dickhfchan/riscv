// ramfs — Phase 16: in-memory filesystem.
//
// Each inode occupies one 4 KiB page allocated from the buddy allocator.
// Directories store their entries in a separate data page (64 entries × 64 B).
// Files store up to 4 KiB of data in a single data page.
// The root inode PA is held in ROOT_PA.

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::mm::{self, buddy::PAGE_SIZE};

// ── DirEntry ──────────────────────────────────────────────────────────────────

pub const MAX_NAME: usize = 52;
const ENTRIES_PER_PAGE: usize = PAGE_SIZE / core::mem::size_of::<DirEntry>();

#[repr(C)]
pub struct DirEntry {
    pub name:     [u8; MAX_NAME], // null-padded
    pub kind:     u8,
    pub _pad:     [u8; 3],
    pub inode_pa: usize,          // 0 = free slot
}
// sizeof = 52 + 1 + 3 + 8 = 64 bytes → 64 entries / 4 KiB page

// ── Inode ─────────────────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum InodeKind { File = 1, Dir = 2 }

impl InodeKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v { 1 => Some(Self::File), 2 => Some(Self::Dir), _ => None }
    }
}

#[repr(C)]
struct Inode {
    kind:    InodeKind,
    _pad:    [u8; 7],
    size:    usize,   // dir: live entry count; file: byte count
    data_pa: usize,   // first data page (0 = empty)
}

// ── File descriptor entry (stored in the per-process FdTable page) ─────────────

#[derive(Copy, Clone, Default)]
pub struct FdEntry {
    pub inode_pa: usize, // 0 = free
    pub offset:   usize, // current read position (byte index for files, entry index for dirs)
    pub flags:    u32,   // Linux open flags (Phase A3); only O_APPEND is honoured
    pub _pad:     u32,
}

pub const MAX_FDS: usize = 16;
pub const MAX_CWD: usize = 128;

/// Marks fd-table slots 0–2 (stdin/stdout/stderr) as reserved in Linux
/// processes: present (so fd_alloc skips them) but not backed by an inode.
pub const FD_STDIO_SENTINEL: usize = usize::MAX;

#[repr(C)]
pub struct FdTable {
    pub entries: [FdEntry; MAX_FDS],
    /// Per-process working directory (Phase A3). Null-padded absolute path;
    /// empty means "/" (the default).
    pub cwd:     [u8; MAX_CWD],
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    NotFound        = 1,
    Exists          = 2,
    NotADirectory   = 3,
    NotAFile        = 4,
    NoMemory        = 5,
    NoSpace         = 6,
    NameTooLong     = 7,
    DirectoryFull   = 8,
    BadDescriptor   = 9,
    TooManyOpen     = 10,
    InvalidPath     = 11,
    NotEmpty        = 12,
}

// ── Root inode ────────────────────────────────────────────────────────────────

static ROOT_PA: AtomicUsize = AtomicUsize::new(0);

pub fn init() {
    let pa = alloc_inode(InodeKind::Dir).expect("ramfs root alloc");
    ROOT_PA.store(pa, Ordering::Release);
}

pub fn root_pa() -> usize { ROOT_PA.load(Ordering::Acquire) }

// ── Internal allocation ───────────────────────────────────────────────────────

fn alloc_inode(kind: InodeKind) -> Option<usize> {
    let pa = mm::alloc_page()?;
    unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
    let n = unsafe { &mut *(pa as *mut Inode) };
    n.kind    = kind;
    n.size    = 0;
    n.data_pa = 0;
    Some(pa)
}

fn alloc_data_page() -> Option<usize> {
    let pa = mm::alloc_page()?;
    unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
    Some(pa)
}

// ── Name helpers ──────────────────────────────────────────────────────────────

fn name_len(name: &[u8; MAX_NAME]) -> usize {
    name.iter().position(|&b| b == 0).unwrap_or(MAX_NAME)
}

fn name_eq(stored: &[u8; MAX_NAME], query: &[u8]) -> bool {
    let l = name_len(stored);
    l == query.len() && &stored[..l] == query
}

// ── Directory operations ──────────────────────────────────────────────────────

fn ensure_data_page(inode_pa: usize) -> Result<usize, FsError> {
    let inode = unsafe { &mut *(inode_pa as *mut Inode) };
    if inode.data_pa == 0 {
        inode.data_pa = alloc_data_page().ok_or(FsError::NoMemory)?;
    }
    Ok(inode.data_pa)
}

fn entries_slice(data_pa: usize) -> &'static [DirEntry] {
    unsafe { core::slice::from_raw_parts(data_pa as *const DirEntry, ENTRIES_PER_PAGE) }
}

fn entries_slice_mut(data_pa: usize) -> &'static mut [DirEntry] {
    unsafe { core::slice::from_raw_parts_mut(data_pa as *mut DirEntry, ENTRIES_PER_PAGE) }
}

/// Insert a child entry into `dir_pa`.
fn insert_entry(dir_pa: usize, name: &[u8], kind: InodeKind, child_pa: usize) -> Result<(), FsError> {
    if name.len() > MAX_NAME { return Err(FsError::NameTooLong); }
    let inode = unsafe { &*(dir_pa as *const Inode) };
    if inode.kind != InodeKind::Dir { return Err(FsError::NotADirectory); }

    let data_pa = ensure_data_page(dir_pa)?;
    let entries = entries_slice(data_pa);

    // Duplicate check
    for e in entries { if e.inode_pa != 0 && name_eq(&e.name, name) { return Err(FsError::Exists); } }

    // Find free slot
    let entries_mut = entries_slice_mut(data_pa);
    for e in entries_mut {
        if e.inode_pa == 0 {
            e.name = [0u8; MAX_NAME];
            e.name[..name.len()].copy_from_slice(name);
            e.kind     = kind as u8;
            e.inode_pa = child_pa;
            unsafe { (*(dir_pa as *mut Inode)).size += 1; }
            return Ok(());
        }
    }
    Err(FsError::DirectoryFull)
}

/// Find name in dir_pa, return child inode PA.
fn find_in_dir(dir_pa: usize, name: &[u8]) -> Option<usize> {
    let inode = unsafe { &*(dir_pa as *const Inode) };
    if inode.kind != InodeKind::Dir || inode.data_pa == 0 { return None; }
    for e in entries_slice(inode.data_pa) {
        if e.inode_pa != 0 && name_eq(&e.name, name) { return Some(e.inode_pa); }
    }
    None
}

// ── Path resolution ───────────────────────────────────────────────────────────

fn strip_leading_slash(p: &[u8]) -> &[u8] {
    let mut s = p;
    while !s.is_empty() && s[0] == b'/' { s = &s[1..]; }
    s
}

/// Walk `path` from the root, return (parent_pa, leaf_name) or Err.
fn resolve_parent<'a>(path: &'a [u8]) -> Result<(usize, &'a [u8]), FsError> {
    let path = strip_leading_slash(path);
    if path.is_empty() { return Err(FsError::InvalidPath); }
    let slash = path.iter().rposition(|&b| b == b'/');
    let (parent_path, name) = match slash {
        None    => (&[][..], path),
        Some(i) => (&path[..i], &path[i+1..]),
    };
    let parent_pa = if parent_path.is_empty() {
        root_pa()
    } else {
        lookup_path(parent_path).ok_or(FsError::NotFound)?
    };
    if name.is_empty() { return Err(FsError::InvalidPath); }
    Ok((parent_pa, name))
}

/// Resolve an absolute path to its inode PA.
pub fn lookup_path(path: &[u8]) -> Option<usize> {
    let path = strip_leading_slash(path);
    let mut cur = root_pa();
    if path.is_empty() { return Some(cur); }
    for component in path.split(|&b| b == b'/') {
        if component.is_empty() { continue; }
        cur = find_in_dir(cur, component)?;
    }
    Some(cur)
}

// ── Public filesystem operations ──────────────────────────────────────────────

pub fn fs_mkdir(path: &[u8]) -> Result<(), FsError> {
    let (parent_pa, name) = resolve_parent(path)?;
    let child_pa = alloc_inode(InodeKind::Dir).ok_or(FsError::NoMemory)?;
    insert_entry(parent_pa, name, InodeKind::Dir, child_pa)
}

pub fn fs_create(path: &[u8]) -> Result<usize, FsError> {
    let (parent_pa, name) = resolve_parent(path)?;
    let child_pa = alloc_inode(InodeKind::File).ok_or(FsError::NoMemory)?;
    insert_entry(parent_pa, name, InodeKind::File, child_pa)?;
    Ok(child_pa)
}

pub fn fs_open(path: &[u8]) -> Option<usize> {
    lookup_path(path)
}

/// Remove a file or empty directory entry from its parent directory.
pub fn fs_unlink(path: &[u8]) -> Result<(), FsError> {
    let (parent_pa, name) = resolve_parent(path)?;
    let parent = unsafe { &mut *(parent_pa as *mut Inode) };
    if parent.kind != InodeKind::Dir { return Err(FsError::NotADirectory); }
    if parent.data_pa == 0 { return Err(FsError::NotFound); }

    for e in entries_slice_mut(parent.data_pa) {
        if e.inode_pa != 0 && name_eq(&e.name, name) {
            let child = unsafe { &*(e.inode_pa as *const Inode) };
            if child.kind == InodeKind::Dir && child.size > 0 {
                return Err(FsError::NotEmpty);
            }
            e.inode_pa = 0;
            e.name = [0u8; MAX_NAME];
            parent.size -= 1;
            return Ok(());
        }
    }
    Err(FsError::NotFound)
}

/// Rename (move) a path to a new location.  Both paths must share the same
/// filesystem root.  Overwrites an existing file at `new_path` if it is a
/// file; refuses if it is a non-empty directory.
pub fn fs_rename(old_path: &[u8], new_path: &[u8]) -> Result<(), FsError> {
    let (old_dir_pa, old_name) = resolve_parent(old_path)?;
    let (new_dir_pa, new_name) = resolve_parent(new_path)?;
    if new_name.len() > MAX_NAME { return Err(FsError::NameTooLong); }

    // Locate the source entry.
    let (src_pa, src_kind) = {
        let old_dir = unsafe { &*(old_dir_pa as *const Inode) };
        if old_dir.data_pa == 0 { return Err(FsError::NotFound); }
        let e = entries_slice(old_dir.data_pa).iter()
            .find(|e| e.inode_pa != 0 && name_eq(&e.name, old_name))
            .ok_or(FsError::NotFound)?;
        (e.inode_pa, InodeKind::from_u8(e.kind).ok_or(FsError::NotFound)?)
    };

    // If a destination entry already exists, remove it (file only; reject non-empty dir).
    {
        let new_dir = unsafe { &*(new_dir_pa as *const Inode) };
        if new_dir.data_pa != 0 {
            for e in entries_slice_mut(new_dir.data_pa) {
                if e.inode_pa != 0 && name_eq(&e.name, new_name) {
                    let dst = unsafe { &*(e.inode_pa as *const Inode) };
                    if dst.kind == InodeKind::Dir && dst.size > 0 {
                        return Err(FsError::NotEmpty);
                    }
                    e.inode_pa = 0;
                    e.name = [0u8; MAX_NAME];
                    unsafe { (*(new_dir_pa as *mut Inode)).size -= 1; }
                    break;
                }
            }
        }
    }

    // Remove source entry.
    {
        let old_dir = unsafe { &mut *(old_dir_pa as *mut Inode) };
        for e in entries_slice_mut(old_dir.data_pa) {
            if e.inode_pa != 0 && name_eq(&e.name, old_name) {
                e.inode_pa = 0;
                e.name = [0u8; MAX_NAME];
                old_dir.size -= 1;
                break;
            }
        }
    }

    // Insert at new location.
    insert_entry(new_dir_pa, new_name, src_kind, src_pa)
}

pub fn fs_read(inode_pa: usize, offset: usize, dst: &mut [u8]) -> usize {
    let inode = unsafe { &*(inode_pa as *const Inode) };
    if inode.kind != InodeKind::File || inode.data_pa == 0 || offset >= inode.size { return 0; }
    let avail = inode.size - offset;
    let n = dst.len().min(avail);
    let src = unsafe { core::slice::from_raw_parts((inode.data_pa + offset) as *const u8, n) };
    dst[..n].copy_from_slice(src);
    n
}

pub fn fs_write(inode_pa: usize, offset: usize, src: &[u8]) -> Result<usize, FsError> {
    let inode = unsafe { &mut *(inode_pa as *mut Inode) };
    if inode.kind != InodeKind::File { return Err(FsError::NotAFile); }
    if inode.data_pa == 0 {
        inode.data_pa = alloc_data_page().ok_or(FsError::NoMemory)?;
    }
    let space = PAGE_SIZE.saturating_sub(offset);
    let n = src.len().min(space);
    if n == 0 { return Err(FsError::NoSpace); }
    let dst = unsafe { core::slice::from_raw_parts_mut((inode.data_pa + offset) as *mut u8, n) };
    dst.copy_from_slice(&src[..n]);
    if offset + n > inode.size { inode.size = offset + n; }
    Ok(n)
}

/// Truncate a file to zero length (keeps the data page for reuse).
pub fn fs_truncate(inode_pa: usize) -> Result<(), FsError> {
    let inode = unsafe { &mut *(inode_pa as *mut Inode) };
    if inode.kind != InodeKind::File { return Err(FsError::NotAFile); }
    inode.size = 0;
    Ok(())
}

/// Read the `idx`-th directory entry, returning (name length, kind, inode PA).
/// Unlike fs_readdir, the raw name is returned (no '/' suffix) along with the
/// entry type — needed by Linux getdents64 (Phase A3).
pub fn fs_readdir_ex(dir_pa: usize, idx: usize, name_buf: &mut [u8]) -> Option<(usize, InodeKind, usize)> {
    let inode = unsafe { &*(dir_pa as *const Inode) };
    if inode.kind != InodeKind::Dir || inode.data_pa == 0 { return None; }
    let mut count = 0usize;
    for e in entries_slice(inode.data_pa) {
        if e.inode_pa != 0 {
            if count == idx {
                let len = name_len(&e.name);
                let copy = len.min(name_buf.len());
                name_buf[..copy].copy_from_slice(&e.name[..copy]);
                let kind = InodeKind::from_u8(e.kind)?;
                return Some((copy, kind, e.inode_pa));
            }
            count += 1;
        }
    }
    None
}

/// Read the `idx`-th directory entry name into `buf`. Returns name length, or 0 at end.
pub fn fs_readdir(dir_pa: usize, idx: usize, name_buf: &mut [u8]) -> usize {
    let inode = unsafe { &*(dir_pa as *const Inode) };
    if inode.kind != InodeKind::Dir || inode.data_pa == 0 { return 0; }
    let mut count = 0usize;
    for e in entries_slice(inode.data_pa) {
        if e.inode_pa != 0 {
            if count == idx {
                let len = name_len(&e.name);
                let copy = len.min(name_buf.len().saturating_sub(1));
                name_buf[..copy].copy_from_slice(&e.name[..copy]);
                if copy < name_buf.len() { name_buf[copy] = 0; }
                // Append '/' if directory
                if e.kind == InodeKind::Dir as u8 && copy + 1 < name_buf.len() {
                    name_buf[copy] = b'/';
                    if copy + 1 < name_buf.len() { name_buf[copy + 1] = 0; }
                    return copy + 1;
                }
                return copy;
            }
            count += 1;
        }
    }
    0
}

pub fn inode_kind(pa: usize) -> InodeKind {
    unsafe { (*(pa as *const Inode)).kind }
}
pub fn inode_size(pa: usize) -> usize {
    unsafe { (*(pa as *const Inode)).size }
}

// ── FdTable helpers ───────────────────────────────────────────────────────────

pub fn alloc_fd_table() -> Option<usize> {
    let pa = mm::alloc_page()?;
    unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
    Some(pa)
}

/// Allocate an fd table with slots 0–2 reserved for stdin/stdout/stderr,
/// matching Linux process conventions (first openat returns fd 3).
pub fn alloc_fd_table_stdio() -> Option<usize> {
    let pa = alloc_fd_table()?;
    let table = unsafe { &mut *(pa as *mut FdTable) };
    for e in table.entries.iter_mut().take(3) {
        e.inode_pa = FD_STDIO_SENTINEL;
    }
    Some(pa)
}

pub fn fd_alloc(table_pa: usize, inode_pa: usize, flags: u32) -> Option<usize> {
    let table = unsafe { &mut *(table_pa as *mut FdTable) };
    for (i, e) in table.entries.iter_mut().enumerate() {
        if e.inode_pa == 0 {
            e.inode_pa = inode_pa;
            e.offset   = 0;
            e.flags    = flags;
            return Some(i);
        }
    }
    None
}

pub fn fd_get(table_pa: usize, fd: usize) -> Option<FdEntry> {
    if fd >= MAX_FDS { return None; }
    let table = unsafe { &*(table_pa as *const FdTable) };
    let e = table.entries[fd];
    if e.inode_pa == 0 { None } else { Some(e) }
}

pub fn fd_advance(table_pa: usize, fd: usize, delta: usize) {
    if fd >= MAX_FDS { return; }
    unsafe { (*(table_pa as *mut FdTable)).entries[fd].offset += delta; }
}

pub fn fd_close(table_pa: usize, fd: usize) {
    if fd >= MAX_FDS { return; }
    unsafe { (*(table_pa as *mut FdTable)).entries[fd] = FdEntry::default(); }
}

/// Set the offset of an open fd (lseek). Returns the new offset.
pub fn fd_seek(table_pa: usize, fd: usize, new_offset: usize) -> Option<usize> {
    if fd >= MAX_FDS { return None; }
    let table = unsafe { &mut *(table_pa as *mut FdTable) };
    if table.entries[fd].inode_pa == 0 { return None; }
    table.entries[fd].offset = new_offset;
    Some(new_offset)
}

/// Copy `src_fd` into `dst_fd` (dup2/dup3).
pub fn fd_dup(table_pa: usize, src_fd: usize, dst_fd: usize) -> Option<()> {
    if src_fd >= MAX_FDS || dst_fd >= MAX_FDS { return None; }
    let table = unsafe { &mut *(table_pa as *mut FdTable) };
    let e = table.entries[src_fd];
    if e.inode_pa == 0 { return None; }
    table.entries[dst_fd] = e;
    Some(())
}

/// Read the per-process working directory. Returns "/" when unset.
pub fn fd_cwd(table_pa: usize, buf: &mut [u8]) -> usize {
    let table = unsafe { &*(table_pa as *const FdTable) };
    let len = name_len_cwd(&table.cwd);
    if len == 0 {
        if !buf.is_empty() { buf[0] = b'/'; }
        return 1;
    }
    let copy = len.min(buf.len());
    buf[..copy].copy_from_slice(&table.cwd[..copy]);
    copy
}

/// Store the per-process working directory (must be a normalized absolute path).
pub fn fd_set_cwd(table_pa: usize, path: &[u8]) -> bool {
    if path.len() > MAX_CWD { return false; }
    let table = unsafe { &mut *(table_pa as *mut FdTable) };
    table.cwd = [0u8; MAX_CWD];
    table.cwd[..path.len()].copy_from_slice(path);
    true
}

fn name_len_cwd(cwd: &[u8; MAX_CWD]) -> usize {
    cwd.iter().position(|&b| b == 0).unwrap_or(MAX_CWD)
}
