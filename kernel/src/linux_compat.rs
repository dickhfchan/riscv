// linux_compat.rs — Phases A1–A5: Linux RISC-V syscall ABI compatibility.
//
// When a TCB has linux_compat=true, the trap handler calls dispatch() instead
// of the Ferrite capability handler. Syscall number is in a7; args in a0-a5;
// return value in a0 (negative = errno, two's complement).
//
//   A1  dispatch + TCB flag + stubs
//   A2  brk / mmap / munmap
//   A3  file I/O on ramfs: openat (O_CREAT/O_TRUNC/O_APPEND), read, write,
//       close, lseek, dup3, fstat, newfstatat, getdents64, getcwd, chdir,
//       faccessat
//   A4  process lifecycle: clone (fork with full user-space copy), execve
//       (argv block on the new stack), wait4 (pid + wstatus), getpid/getppid
//   A5  harmless stubs: rt_sig*, futex, prlimit64, umask, fcntl, uname, …
//
// Memory model note: the trap handler runs under the TRAPPED thread's satp
// (trap.S never switches on entry) with sstatus.SUM=1, so syscall handlers can
// dereference user pointers directly. Every ELF VSpace also maps the kernel
// RAM superpage and the shared user mirror, so kernel data and thread stacks
// (user-mirror VAs) are reachable from any address space.

use crate::arch::riscv64::trap::TrapFrame;
use crate::arch::riscv64::vspace;
use crate::arch::riscv64::uart;
use crate::mm;
use crate::sched;
use crate::thread::{Tcb, TcbState, TCB_LIST_HEAD};

// ── Linux errno ───────────────────────────────────────────────────────────────
const ENOSYS:  isize = -38;
const EINVAL:  isize = -22;
const EBADF:   isize = -9;
const ENOMEM:  isize = -12;
const ENOENT:  isize = -2;
const EFAULT:  isize = -14;
const ECHILD:  isize = -10;
const EEXIST:  isize = -17;
const ENOTDIR: isize = -20;
const ERANGE:  isize = -34;

// ── Linux RISC-V syscall numbers ──────────────────────────────────────────────
const SYS_GETCWD:          usize = 17;
const SYS_DUP:             usize = 23;
const SYS_DUP3:            usize = 24;
const SYS_FCNTL:           usize = 25;
const SYS_IOCTL:           usize = 29;
const SYS_MKDIRAT:         usize = 34;
const SYS_UNLINKAT:        usize = 35;
const SYS_FACCESSAT:       usize = 48;
const SYS_CHDIR:           usize = 49;
const SYS_OPENAT:          usize = 56;
const SYS_CLOSE:           usize = 57;
const SYS_PIPE2:           usize = 59;
const SYS_GETDENTS64:      usize = 61;
const SYS_LSEEK:           usize = 62;
const SYS_READ:            usize = 63;
const SYS_WRITE:           usize = 64;
const SYS_WRITEV:          usize = 66;
const SYS_PPOLL:           usize = 73;
const SYS_READLINKAT:      usize = 78;
const SYS_NEWFSTATAT:      usize = 79;
const SYS_FSTAT:           usize = 80;
const SYS_EXIT:            usize = 93;
const SYS_EXIT_GROUP:      usize = 94;
const SYS_SET_TID_ADDR:    usize = 96;
const SYS_FUTEX:           usize = 98;
const SYS_SET_ROBUST_LIST: usize = 99;
const SYS_CLOCK_GETTIME:   usize = 113;
const SYS_SCHED_YIELD:     usize = 124;
const SYS_KILL:            usize = 129;
const SYS_TKILL:           usize = 130;
const SYS_TGKILL:          usize = 131;
const SYS_RT_SIGACTION:    usize = 134;
const SYS_RT_SIGPROCMASK:  usize = 135;
const SYS_UNAME:           usize = 160;
const SYS_UMASK:           usize = 166;
const SYS_GETPID:          usize = 172;
const SYS_GETPPID:         usize = 173;
const SYS_GETUID:          usize = 174;
const SYS_GETEUID:         usize = 175;
const SYS_GETGID:          usize = 176;
const SYS_GETEGID:         usize = 177;
const SYS_GETTID:          usize = 178;
const SYS_BRK:             usize = 214;
const SYS_MUNMAP:          usize = 215;
const SYS_CLONE:           usize = 220;
const SYS_EXECVE:          usize = 221;
const SYS_MMAP:            usize = 222;
const SYS_MPROTECT:        usize = 226;
const SYS_WAIT4:           usize = 260;
const SYS_PRLIMIT64:       usize = 261;

// ── openat flags ──────────────────────────────────────────────────────────────
const O_CREAT:  usize = 0o100;
const O_TRUNC:  usize = 0o1000;
const O_APPEND: usize = 0o2000;
const AT_FDCWD: isize = -100;

// ── clone flags ───────────────────────────────────────────────────────────────
const CLONE_VM: usize = 0x100;

// ── getdents64 record types ───────────────────────────────────────────────────
const DT_REG: u8 = 8;
const DT_DIR: u8 = 4;

// ── stat mode bits ────────────────────────────────────────────────────────────
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

const MAX_PATH: usize = 256;
const MAX_ARGS: usize = 8;
const MAX_ARG_LEN: usize = 64;

// ── uname struct (Linux ABI) ──────────────────────────────────────────────────
#[repr(C)]
struct Utsname {
    sysname:    [u8; 65],
    nodename:   [u8; 65],
    release:    [u8; 65],
    version:    [u8; 65],
    machine:    [u8; 65],
    domainname: [u8; 65],
}

fn fill_str(dst: &mut [u8; 65], src: &[u8]) {
    let n = src.len().min(64);
    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
}

// ── Main dispatch ─────────────────────────────────────────────────────────────

/// Called from trap_handler when TCB.linux_compat == true.
/// Linux convention: a7 = syscall number, a0-a5 = args, a0 = return.
pub fn dispatch(frame: &mut TrapFrame) {
    let nr  = frame.a7();
    let a0  = frame.a0();
    let a1  = frame.a1();
    let a2  = frame.a2();
    let a3  = frame.a3();
    let a4  = frame.a4();

    let ret: isize = match nr {
        SYS_EXIT | SYS_EXIT_GROUP => {
            // Linux exit: exit code in a0.  Ferrite exit_current reads a2.
            frame.x[12] = a0;
            crate::sched::exit_current(frame);
            return; // exit_current never returns
        }

        SYS_WRITE => sys_write(a0, a1, a2),

        SYS_READ  => sys_read(a0, a1, a2),

        SYS_WRITEV => sys_writev(a0, a1, a2),

        SYS_BRK    => sys_brk(a0),

        SYS_MMAP => {
            // mmap(addr, length, prot, flags, fd, offset)
            let length = a1;
            let flags  = a3;
            let fd_arg = a4 as isize;
            const MAP_ANON: usize = 0x20;
            if flags & MAP_ANON != 0 || fd_arg == -1 {
                sys_mmap_anon(a0, length)
            } else {
                ENOMEM // file-backed mmap not yet implemented
            }
        }

        SYS_MUNMAP   => 0, // stub: no physical page reclaim yet
        SYS_MPROTECT => 0, // stub

        SYS_GETPID => current_pid() as isize,
        SYS_GETTID => current_pid() as isize,
        SYS_GETPPID => {
            let cur_pa = sched::current_pa();
            if cur_pa == 0 { 0 } else {
                let tcb = unsafe { &*(cur_pa as *const Tcb) };
                if tcb.parent_pa == 0 { 0 } else {
                    unsafe { (*(tcb.parent_pa as *const Tcb)).pid as isize }
                }
            }
        }
        SYS_GETUID | SYS_GETEUID | SYS_GETGID | SYS_GETEGID => 0,

        SYS_UNAME => {
            let ptr = a0 as *mut Utsname;
            if ptr.is_null() {
                frame.set_a0(EFAULT as usize);
                return;
            }
            let u = unsafe { &mut *ptr };
            fill_str(&mut u.sysname,    b"Ferrite");
            fill_str(&mut u.nodename,   b"ferrite");
            fill_str(&mut u.release,    b"0.1.0");
            fill_str(&mut u.version,    b"PhaseA5");
            fill_str(&mut u.machine,    b"riscv64");
            fill_str(&mut u.domainname, b"");
            0
        }

        SYS_CLOCK_GETTIME => {
            if a1 != 0 {
                unsafe {
                    *((a1    ) as *mut u64) = 0; // tv_sec
                    *((a1 + 8) as *mut u64) = 0; // tv_nsec
                }
            }
            0
        }

        SYS_IOCTL => sys_ioctl(a0, a1, a2),

        SYS_SCHED_YIELD => {
            sched::yield_current(frame);
            return;
        }

        SYS_RT_SIGACTION | SYS_RT_SIGPROCMASK
        | SYS_SET_ROBUST_LIST | SYS_TKILL | SYS_TGKILL | SYS_KILL => 0,

        SYS_SET_TID_ADDR => current_pid() as isize,

        SYS_FUTEX    => 0,
        SYS_PRLIMIT64 => 0,
        SYS_UMASK    => 0o022,
        SYS_FCNTL    => 0,
        SYS_PPOLL    => 0,

        // ── Phase A3: file I/O ────────────────────────────────────────────────
        SYS_OPENAT   => sys_openat(a0, a1, a2),
        SYS_CLOSE    => sys_close(a0),
        SYS_LSEEK    => sys_lseek(a0, a1 as isize, a2),
        SYS_DUP      => sys_dup(a0, None),
        SYS_DUP3     => sys_dup(a0, Some(a1)),
        SYS_FSTAT    => sys_fstat(a0, a1),
        SYS_NEWFSTATAT => sys_newfstatat(a0, a1, a2),
        SYS_GETDENTS64 => sys_getdents64(a0, a1, a2),
        SYS_GETCWD   => sys_getcwd(a0, a1),
        SYS_CHDIR    => sys_chdir(a0),
        SYS_FACCESSAT => sys_faccessat(a0, a1),
        SYS_MKDIRAT  => sys_mkdirat(a0, a1),
        SYS_READLINKAT => EINVAL, // ramfs has no symlinks
        SYS_UNLINKAT | SYS_PIPE2 => ENOSYS,

        // ── Phase A4: process lifecycle ───────────────────────────────────────
        SYS_CLONE    => sys_clone(a0, frame),
        SYS_EXECVE   => return sys_execve(a0, a1, frame),
        SYS_WAIT4    => return sys_wait4(a0 as isize, a1, frame),

        _ => {
            uart::putchar(b'[');
            print_u64(nr as u64);
            uart::putchar(b'?');
            uart::putchar(b']');
            ENOSYS
        }
    };

    frame.set_a0(ret as usize);
}

// ── Current-thread helpers ────────────────────────────────────────────────────

fn current_tcb() -> Option<&'static mut Tcb> {
    let pa = sched::current_pa();
    if pa == 0 { None } else { Some(unsafe { &mut *(pa as *mut Tcb) }) }
}

fn current_pid() -> usize {
    match current_tcb() { Some(t) => t.pid, None => 0 }
}

// ── sys_write ─────────────────────────────────────────────────────────────────

fn sys_write(fd: usize, ptr: usize, len: usize) -> isize {
    if fd == 1 || fd == 2 {
        for i in 0..len {
            let b = unsafe { *((ptr + i) as *const u8) };
            uart::putchar(b);
        }
        return len as isize;
    }
    let Some((tbl, fd_entry)) = get_fd(fd) else { return EBADF; };
    // O_APPEND: always write at the end of the file.
    let offset = if fd_entry.flags as usize & O_APPEND != 0 {
        crate::fs::ramfs::inode_size(fd_entry.inode_pa)
    } else {
        fd_entry.offset
    };
    let buf = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
    match crate::fs::ramfs::fs_write(fd_entry.inode_pa, offset, buf) {
        Ok(n)  => {
            crate::fs::ramfs::fd_seek(tbl, fd, offset + n);
            n as isize
        }
        Err(_) => EBADF,
    }
}

// ── sys_read ──────────────────────────────────────────────────────────────────

fn sys_read(fd: usize, ptr: usize, len: usize) -> isize {
    if fd == 0 {
        if len == 0 { return 0; }
        let b = uart::getchar_blocking();
        unsafe { *(ptr as *mut u8) = b; }
        return 1;
    }
    let Some((tbl, fd_entry)) = get_fd(fd) else { return EBADF; };
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len) };
    let n = crate::fs::ramfs::fs_read(fd_entry.inode_pa, fd_entry.offset, buf);
    crate::fs::ramfs::fd_advance(tbl, fd, n);
    n as isize
}

// ── sys_writev ────────────────────────────────────────────────────────────────

fn sys_writev(fd: usize, iov_ptr: usize, iov_cnt: usize) -> isize {
    let mut total = 0isize;
    for i in 0..iov_cnt {
        let base_addr = iov_ptr + i * 16;
        let base = unsafe { *(base_addr as *const usize) };
        let ilen = unsafe { *((base_addr + 8) as *const usize) };
        total += sys_write(fd, base, ilen);
    }
    total
}

// ── Path handling ─────────────────────────────────────────────────────────────

/// Read a null-terminated path from user memory and resolve it against the
/// process cwd into a normalized absolute path. Returns the length.
fn resolve_path(path_va: usize, out: &mut [u8; MAX_PATH]) -> Result<usize, isize> {
    let mut raw = [0u8; MAX_PATH];
    let raw_len = read_cstr(path_va, &mut raw).ok_or(ENOENT)?;
    let raw = &raw[..raw_len];

    // Resolve against cwd for relative paths.
    let mut joined = [0u8; MAX_PATH];
    let mut jlen: usize;
    if raw.first() == Some(&b'/') {
        joined[0] = b'/';
        jlen = 1;
    } else {
        let cur_pa = sched::current_pa();
        let cwd_len = if cur_pa != 0 {
            let tcb = unsafe { &*(cur_pa as *const Tcb) };
            if tcb.fd_table_pa != 0 {
                crate::fs::ramfs::fd_cwd(tcb.fd_table_pa, &mut joined)
            } else { 0 }
        } else { 0 };
        if cwd_len == 0 {
            joined[0] = b'/';
            jlen = 1;
        } else {
            jlen = cwd_len;
        }
    }
    for &b in raw {
        if jlen >= MAX_PATH { return Err(ENOENT); }
        joined[jlen] = b;
        jlen += 1;
    }
    let joined = &joined[..jlen];

    // Normalize: split into components, handling "." and "..".
    let mut out_len = 0usize;
    for comp in joined.split(|&b| b == b'/') {
        match comp {
            b"" | b"." => continue,
            b".." => {
                // Pop the last component (walk back to the previous '/').
                while out_len > 1 {
                    out_len -= 1;
                    if out[out_len] == b'/' { break; }
                }
            }
            _ => {
                if out_len == 0 || out[out_len - 1] != b'/' {
                    out[out_len] = b'/';
                    out_len += 1;
                }
                if out_len + comp.len() > MAX_PATH { return Err(ENOENT); }
                out[out_len..out_len + comp.len()].copy_from_slice(comp);
                out_len += comp.len();
            }
        }
    }
    if out_len == 0 {
        out[0] = b'/';
        out_len = 1;
    }
    Ok(out_len)
}

/// Read a null-terminated string from user memory (bounded by `buf` size).
fn read_cstr(va: usize, buf: &mut [u8]) -> Option<usize> {
    let src = va as *const u8;
    for i in 0..buf.len() {
        let b = unsafe { src.add(i).read_volatile() };
        if b == 0 { return Some(i); }
        buf[i] = b;
    }
    None // not null-terminated within the limit
}

// ── sys_openat ────────────────────────────────────────────────────────────────
//
// openat(dirfd, path, flags, mode) — dirfd must be AT_FDCWD (a process cwd is
// honoured via resolve_path; per-fd directory relative opens are unsupported).

fn sys_openat(dirfd: usize, path_va: usize, flags: usize) -> isize {
    if dirfd as isize != AT_FDCWD { return ENOTDIR; }
    let mut path = [0u8; MAX_PATH];
    let len = match resolve_path(path_va, &mut path) {
        Ok(l)  => l,
        Err(e) => return e,
    };
    let path = &path[..len];

    let inode_pa = match crate::fs::ramfs::fs_open(path) {
        Some(pa) => {
            if flags & O_TRUNC != 0 {
                let _ = crate::fs::ramfs::fs_truncate(pa);
            }
            pa
        }
        None => {
            if flags & O_CREAT == 0 { return ENOENT; }
            match crate::fs::ramfs::fs_create(path) {
                Ok(pa) => pa,
                Err(crate::fs::ramfs::FsError::Exists) => return EEXIST,
                Err(_) => return ENOENT,
            }
        }
    };

    let Some(tcb) = current_tcb() else { return ENOENT; };
    if tcb.fd_table_pa == 0 {
        match crate::fs::ramfs::alloc_fd_table_stdio() {
            Some(t) => tcb.fd_table_pa = t,
            None    => return ENOMEM,
        }
    }
    match crate::fs::ramfs::fd_alloc(tcb.fd_table_pa, inode_pa, flags as u32) {
        Some(fd) => fd as isize,
        None     => ENOMEM,
    }
}

// ── sys_close ─────────────────────────────────────────────────────────────────

fn sys_close(fd: usize) -> isize {
    let Some(tcb) = current_tcb() else { return EBADF; };
    if tcb.fd_table_pa == 0 { return EBADF; }
    crate::fs::ramfs::fd_close(tcb.fd_table_pa, fd);
    0
}

// ── sys_lseek ─────────────────────────────────────────────────────────────────

fn sys_lseek(fd: usize, offset: isize, whence: usize) -> isize {
    const SEEK_SET: usize = 0;
    const SEEK_CUR: usize = 1;
    const SEEK_END: usize = 2;
    let Some((tbl, entry)) = get_fd(fd) else { return EBADF; };
    let base = match whence {
        SEEK_SET => 0usize,
        SEEK_CUR => entry.offset,
        SEEK_END => crate::fs::ramfs::inode_size(entry.inode_pa),
        _        => return EINVAL,
    };
    let new = base as isize + offset;
    if new < 0 { return EINVAL; }
    match crate::fs::ramfs::fd_seek(tbl, fd, new as usize) {
        Some(v) => v as isize,
        None    => EBADF,
    }
}

// ── sys_dup / sys_dup3 ────────────────────────────────────────────────────────

fn sys_dup(old_fd: usize, new_fd: Option<usize>) -> isize {
    let Some(tcb) = current_tcb() else { return EBADF; };
    if tcb.fd_table_pa == 0 { return EBADF; }
    let tbl = tcb.fd_table_pa;
    match new_fd {
        Some(dst) => {
            if dst >= crate::fs::ramfs::MAX_FDS { return EBADF; }
            crate::fs::ramfs::fd_close(tbl, dst);
            match crate::fs::ramfs::fd_dup(tbl, old_fd, dst) {
                Some(()) => dst as isize,
                None     => EBADF,
            }
        }
        None => {
            let Some(entry) = crate::fs::ramfs::fd_get(tbl, old_fd) else { return EBADF; };
            match crate::fs::ramfs::fd_alloc(tbl, entry.inode_pa, entry.flags) {
                Some(fd) => {
                    crate::fs::ramfs::fd_seek(tbl, fd, entry.offset);
                    fd as isize
                }
                None => ENOMEM,
            }
        }
    }
}

// ── struct stat (asm-generic layout, 128 bytes) ───────────────────────────────

fn write_stat(buf_va: usize, inode_pa: usize) -> isize {
    if buf_va == 0 { return EFAULT; }
    let kind = crate::fs::ramfs::inode_kind(inode_pa);
    let size = crate::fs::ramfs::inode_size(inode_pa);
    let mode = match kind {
        crate::fs::ramfs::InodeKind::Dir  => S_IFDIR | 0o755,
        crate::fs::ramfs::InodeKind::File => S_IFREG | 0o644,
    };
    let dst = buf_va as *mut u8;
    unsafe {
        core::ptr::write_bytes(dst, 0, 128);
        *((buf_va + 8)  as *mut u64) = (inode_pa >> 12) as u64;      // st_ino
        *((buf_va + 16) as *mut u32) = mode;                          // st_mode
        *((buf_va + 20) as *mut u32) = 1;                             // st_nlink
        *((buf_va + 48) as *mut i64) = size as i64;                   // st_size
        *((buf_va + 56) as *mut i32) = 4096;                          // st_blksize
        *((buf_va + 64) as *mut i64) = ((size + 511) / 512) as i64;   // st_blocks
    }
    0
}

fn sys_fstat(fd: usize, buf_va: usize) -> isize {
    if fd <= 2 {
        if buf_va == 0 { return EFAULT; }
        unsafe {
            core::ptr::write_bytes(buf_va as *mut u8, 0, 128);
            *((buf_va + 16) as *mut u32) = 0o020600; // S_IFCHR | 0600
        }
        return 0;
    }
    let Some((_, entry)) = get_fd(fd) else { return EBADF; };
    write_stat(buf_va, entry.inode_pa)
}

fn sys_newfstatat(dirfd: usize, path_va: usize, buf_va: usize) -> isize {
    if dirfd as isize != AT_FDCWD { return ENOTDIR; }
    let mut path = [0u8; MAX_PATH];
    let len = match resolve_path(path_va, &mut path) {
        Ok(l)  => l,
        Err(e) => return e,
    };
    match crate::fs::ramfs::fs_open(&path[..len]) {
        Some(pa) => write_stat(buf_va, pa),
        None     => ENOENT,
    }
}

// ── getdents64 ────────────────────────────────────────────────────────────────
//
// linux_dirent64: { u64 d_ino; s64 d_off; u16 d_reclen; u8 d_type; char d_name[]; }
// Records are 8-byte aligned; d_off carries the index of the NEXT entry.

fn sys_getdents64(fd: usize, buf_va: usize, buf_len: usize) -> isize {
    let Some((tbl, entry)) = get_fd(fd) else { return EBADF; };
    if crate::fs::ramfs::inode_kind(entry.inode_pa) != crate::fs::ramfs::InodeKind::Dir {
        return ENOTDIR;
    }
    let mut written = 0usize;
    let mut idx = entry.offset;
    let mut name = [0u8; crate::fs::ramfs::MAX_NAME];
    loop {
        let Some((name_len, kind, child_pa)) =
            crate::fs::ramfs::fs_readdir_ex(entry.inode_pa, idx, &mut name)
        else { break };
        let reclen = (19 + name_len + 1 + 7) & !7;
        if written + reclen > buf_len {
            if written == 0 { return EINVAL; } // buffer too small for one record
            break;
        }
        let base = buf_va + written;
        unsafe {
            *(base as *mut u64)        = (child_pa >> 12) as u64; // d_ino
            *((base + 8) as *mut i64)  = (idx + 1) as i64;        // d_off
            *((base + 16) as *mut u16) = reclen as u16;           // d_reclen
            *((base + 18) as *mut u8)  = match kind {             // d_type
                crate::fs::ramfs::InodeKind::Dir  => DT_DIR,
                crate::fs::ramfs::InodeKind::File => DT_REG,
            };
            core::ptr::copy_nonoverlapping(name.as_ptr(), (base + 19) as *mut u8, name_len);
            *((base + 19 + name_len) as *mut u8) = 0;
        }
        written += reclen;
        idx += 1;
    }
    crate::fs::ramfs::fd_seek(tbl, fd, idx);
    written as isize
}

// ── getcwd / chdir / faccessat / mkdirat ──────────────────────────────────────

fn sys_getcwd(buf_va: usize, size: usize) -> isize {
    if buf_va == 0 { return EFAULT; }
    let mut cwd = [0u8; crate::fs::ramfs::MAX_CWD];
    let len = match current_tcb() {
        Some(t) if t.fd_table_pa != 0 => crate::fs::ramfs::fd_cwd(t.fd_table_pa, &mut cwd),
        _ => { cwd[0] = b'/'; 1 }
    };
    if size < len + 1 { return ERANGE; }
    unsafe {
        core::ptr::copy_nonoverlapping(cwd.as_ptr(), buf_va as *mut u8, len);
        *((buf_va + len) as *mut u8) = 0;
    }
    (len + 1) as isize
}

fn sys_chdir(path_va: usize) -> isize {
    let mut path = [0u8; MAX_PATH];
    let len = match resolve_path(path_va, &mut path) {
        Ok(l)  => l,
        Err(e) => return e,
    };
    let path = &path[..len];
    match crate::fs::ramfs::fs_open(path) {
        Some(pa) => {
            if crate::fs::ramfs::inode_kind(pa) != crate::fs::ramfs::InodeKind::Dir {
                return ENOTDIR;
            }
        }
        None => return ENOENT,
    }
    let Some(tcb) = current_tcb() else { return ENOENT; };
    if tcb.fd_table_pa == 0 {
        match crate::fs::ramfs::alloc_fd_table_stdio() {
            Some(t) => tcb.fd_table_pa = t,
            None    => return ENOMEM,
        }
    }
    if crate::fs::ramfs::fd_set_cwd(tcb.fd_table_pa, path) { 0 } else { ENAMETOOLONG }
}

const ENAMETOOLONG: isize = -36;

fn sys_faccessat(dirfd: usize, path_va: usize) -> isize {
    if dirfd as isize != AT_FDCWD { return ENOTDIR; }
    let mut path = [0u8; MAX_PATH];
    let len = match resolve_path(path_va, &mut path) {
        Ok(l)  => l,
        Err(e) => return e,
    };
    match crate::fs::ramfs::fs_open(&path[..len]) {
        Some(_) => 0,
        None    => ENOENT,
    }
}

fn sys_mkdirat(dirfd: usize, path_va: usize) -> isize {
    if dirfd as isize != AT_FDCWD { return ENOTDIR; }
    let mut path = [0u8; MAX_PATH];
    let len = match resolve_path(path_va, &mut path) {
        Ok(l)  => l,
        Err(e) => return e,
    };
    match crate::fs::ramfs::fs_mkdir(&path[..len]) {
        Ok(()) => 0,
        Err(crate::fs::ramfs::FsError::Exists) => EEXIST,
        Err(crate::fs::ramfs::FsError::NotFound) => ENOENT,
        Err(_) => EINVAL,
    }
}

// ── sys_brk ───────────────────────────────────────────────────────────────────
//
// brk(0) → current brk. brk(addr) → extend heap up to addr, return new brk.

fn sys_brk(addr: usize) -> isize {
    let Some(tcb) = current_tcb() else { return ENOMEM; };

    if addr == 0 || addr <= tcb.brk_base {
        return tcb.brk_next as isize;
    }

    let map_up_to = (addr + 4095) & !4095;
    let pgd_pa    = vspace::satp_to_pgd_pa(tcb.satp);
    let flags     = vspace::PTE_R | vspace::PTE_W | vspace::PTE_U;

    let mut mapped = tcb.brk_mapped;
    while mapped < map_up_to {
        let Some(page) = mm::alloc_page() else { break; };
        unsafe { core::ptr::write_bytes(page as *mut u8, 0, 4096); }
        if vspace::map_page(pgd_pa, mapped, page, flags).is_err() { break; }
        mapped += 4096;
    }

    tcb.brk_mapped = mapped;
    tcb.brk_next   = addr.min(mapped);
    tcb.brk_next as isize
}

// ── sys_mmap_anon ─────────────────────────────────────────────────────────────
//
// Simple bump-pointer anonymous mmap: VAs start at 0x4000_0000 and grow up.

fn sys_mmap_anon(hint: usize, length: usize) -> isize {
    if length == 0 { return EINVAL; }
    let pages = (length + 4095) / 4096;

    let Some(tcb) = current_tcb() else { return ENOMEM; };

    if tcb.mmap_bump == 0 { tcb.mmap_bump = 0x4000_0000; }
    let va = if hint != 0 { (hint + 4095) & !4095 } else { tcb.mmap_bump };

    let pgd_pa = vspace::satp_to_pgd_pa(tcb.satp);
    let flags  = vspace::PTE_R | vspace::PTE_W | vspace::PTE_U;

    let mut mapped_va = va;
    for _ in 0..pages {
        let Some(page) = mm::alloc_page() else { return ENOMEM; };
        unsafe { core::ptr::write_bytes(page as *mut u8, 0, 4096); }
        if vspace::map_page(pgd_pa, mapped_va, page, flags).is_err() {
            return ENOMEM;
        }
        mapped_va += 4096;
    }

    if hint == 0 { tcb.mmap_bump = mapped_va; }
    va as isize
}

// ── sys_clone (fork) ──────────────────────────────────────────────────────────
//
// Only fork-style clones are supported (CLONE_VM → ENOSYS). The child gets a
// full copy of every PTE_U page in the parent's PGD[0] subtree (ELF segments,
// brk heap, anonymous mmaps); kernel-only pages (UART) are shared by mapping
// the same physical page. The parent's kernel stack (which is also the user
// stack, via the shared user mirror) is copied into a fresh stack, and any
// word that looks like a pointer into the parent's stack is rebased to the
// child's — this keeps sp/fp chains valid so fork+execve works.

fn sys_clone(flags: usize, frame: &mut TrapFrame) -> isize {
    if flags & CLONE_VM != 0 { return ENOSYS; }

    let Some(parent) = current_tcb() else { return ENOMEM; };
    let parent_pa     = sched::current_pa();
    let parent_pgd    = vspace::satp_to_pgd_pa(parent.satp);
    let parent_kstack = parent.kstack_pa;
    let parent_satp   = parent.satp;

    // Fresh VSpace: kernel superpage + shared user mirror already installed.
    let child_pgd = match unsafe { vspace::create_elf_vspace() } {
        Some(p) => p,
        None    => return ENOMEM,
    };
    if copy_user_pages(parent_pgd, child_pgd).is_err() { return ENOMEM; }

    let child_satp = vspace::pgd_to_satp(child_pgd);
    let child_pa = match crate::thread::create_linux_thread(0, child_satp, parent_pa) {
        Some(p) => p,
        None    => return ENOMEM,
    };

    let child = unsafe { &mut *(child_pa as *mut Tcb) };

    // Inherit address-space and fd state.
    child.brk_base   = parent.brk_base;
    child.brk_next   = parent.brk_next;
    child.brk_mapped = parent.brk_mapped;
    child.mmap_bump  = parent.mmap_bump;
    child.cspace_pa  = parent.cspace_pa;
    child.cspace_sb  = parent.cspace_sb;
    let child_kstack = child.kstack_pa;
    let child_pid    = child.pid;

    // Copy the fd table (shares inodes; offsets and cwd preserved).
    if parent.fd_table_pa != 0 {
        if let Some(tbl) = crate::fs::ramfs::alloc_fd_table() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    parent.fd_table_pa as *const u8,
                    tbl as *mut u8,
                    4096,
                );
            }
            child.fd_table_pa = tbl;
        }
    }

    // Copy the kernel stack, then rebase any word pointing into the parent's
    // stack to the equivalent offset in the child's.
    use crate::arch::riscv64::mmu::USER_MIRROR_OFFSET;
    unsafe {
        core::ptr::copy_nonoverlapping(
            parent_kstack as *const u8,
            child_kstack as *mut u8,
            crate::thread::KSTACK_SIZE,
        );
    }
    let p_lo = parent_kstack + USER_MIRROR_OFFSET;
    let p_hi = p_lo + crate::thread::KSTACK_SIZE;
    let delta = child_kstack.wrapping_sub(parent_kstack);
    for i in 0..(crate::thread::KSTACK_SIZE / 8) {
        let slot = unsafe { &mut *((child_kstack + i * 8) as *mut usize) };
        if *slot >= p_lo && *slot < p_hi {
            *slot = slot.wrapping_add(delta);
        }
    }

    // The child resumes from the same instruction (post-ecall) with a0 = 0.
    child.frame = *frame;
    child.frame.set_a0(0);
    // Point sp at the same stack offset, but in the child's stack.
    child.frame.x[2] = frame.x[2].wrapping_add(delta);
    child.satp = child_satp;
    let _ = parent_satp;

    sched::enqueue(child_pa, 0);
    child_pid as isize
}

/// Copy every user page of the PGD[0] subtree (VA < 2^39) into a fresh VSpace.
/// PTE_U pages are deep-copied; kernel-only leaves (e.g. the UART page) are
/// re-mapped to the same physical page.
fn copy_user_pages(src_pgd: usize, dst_pgd: usize) -> Result<(), ()> {
    let src_pgd_e = unsafe { (src_pgd as *const u64).read_volatile() };
    if src_pgd_e & vspace::PTE_V == 0 { return Ok(()); } // empty user subtree
    let src_pud = ((src_pgd_e >> 10) << 12) as usize;

    for i in 0..512usize {
        let pud_e = unsafe { ((src_pud + i * 8) as *const u64).read_volatile() };
        if pud_e & vspace::PTE_V == 0 { continue; }
        if pud_e & (vspace::PTE_R | vspace::PTE_W | vspace::PTE_X) != 0 {
            continue; // 1 GiB superpage: kernel RAM — already shared in dst
        }
        let src_pmd = ((pud_e >> 10) << 12) as usize;
        for j in 0..512usize {
            let pmd_e = unsafe { ((src_pmd + j * 8) as *const u64).read_volatile() };
            if pmd_e & vspace::PTE_V == 0 { continue; }
            if pmd_e & (vspace::PTE_R | vspace::PTE_W | vspace::PTE_X) != 0 {
                continue; // 2 MiB superpage: not produced by our loaders
            }
            let src_pt = ((pmd_e >> 10) << 12) as usize;
            for k in 0..512usize {
                let pte = unsafe { ((src_pt + k * 8) as *const u64).read_volatile() };
                if pte & vspace::PTE_V == 0 { continue; }
                if pte & (vspace::PTE_R | vspace::PTE_W | vspace::PTE_X) == 0 { continue; }
                let src_pa = ((pte >> 10) << 12) as usize;
                let va = (i << 30) | (j << 21) | (k << 12);
                let flags = pte & 0x3ff; // preserve R/W/X/U/A/D
                if pte & vspace::PTE_U != 0 {
                    // User page: deep copy.
                    let new_pa = mm::alloc_page().ok_or(())?;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            src_pa as *const u8, new_pa as *mut u8, 4096);
                    }
                    vspace::map_page(dst_pgd, va, new_pa, flags)?;
                } else {
                    // Kernel-only page (UART MMIO): share the physical page.
                    vspace::map_page(dst_pgd, va, src_pa, flags)?;
                }
            }
        }
    }
    Ok(())
}

// ── sys_execve ────────────────────────────────────────────────────────────────
//
// execve(path, argv, envp) — envp is ignored. The ELF is looked up first in
// the embedded process registry (proc::find_elf, by basename), then as a file
// in ramfs (single-page files only). A fresh kernel stack is allocated and the
// Linux entry frame (argc, argv pointers, NULL terminators, empty auxv) is
// written at its top; the running thread's satp is swapped on sret.

/// Spawn a Linux-ABI process from an embedded/ramfs ELF. Used by execve and
/// by the kernel's Phase A bootstrap. Returns the new TCB PA.
pub fn spawn_linux_process(
    elf_bytes: &[u8],
    args: &[&[u8]],
    parent_pa: usize,
) -> Option<usize> {
    let pgd = unsafe { vspace::create_elf_vspace() }?;
    // UART page (kernel-only) so the trap handler's putchar works mid-syscall.
    vspace::map_page(pgd, 0x1000_0000, 0x1000_0000, vspace::PTE_R | vspace::PTE_W).ok()?;
    let (entry, seg_end) = crate::elf::load_with_end(elf_bytes, pgd).ok()?;
    let satp = vspace::pgd_to_satp(pgd);
    let tcb_pa = crate::thread::create_linux_thread(entry, satp, parent_pa)?;
    {
        let tcb = unsafe { &mut *(tcb_pa as *mut Tcb) };
        tcb.brk_base   = seg_end;
        tcb.brk_next   = seg_end;
        tcb.brk_mapped = seg_end;
        // fds 0–2 reserved for stdin/stdout/stderr, matching Linux convention.
        tcb.fd_table_pa = crate::fs::ramfs::alloc_fd_table_stdio().unwrap_or(0);
    }
    // Copy the (possibly short) &str args into fixed-size NUL-padded buffers.
    let mut arg_bufs = [[0u8; MAX_ARG_LEN]; MAX_ARGS];
    if args.len() > MAX_ARGS { return None; }
    for (i, a) in args.iter().enumerate() {
        let l = a.len().min(MAX_ARG_LEN - 1);
        arg_bufs[i][..l].copy_from_slice(&a[..l]);
    }
    if !setup_entry_stack(tcb_pa, &arg_bufs[..args.len()]) { return None; }
    Some(tcb_pa)
}

/// Write the Linux initial stack frame (argc/argv/NULL/auxv) at the top of the
/// thread's kernel stack and point the thread's sp at it. String bytes and the
/// pointer table live in the same physical page the thread will read through
/// the user mirror, so the argv pointers are user-mirror VAs.
fn setup_entry_stack(tcb_pa: usize, args: &[[u8; MAX_ARG_LEN]]) -> bool {
    use crate::arch::riscv64::mmu::USER_MIRROR_OFFSET;
    let tcb = unsafe { &mut *(tcb_pa as *mut Tcb) };
    let ks = tcb.kstack_pa;

    // Copy argument strings, top of stack growing down.
    let mut sp_off = crate::thread::KSTACK_SIZE;
    let mut arg_ptrs = [0usize; MAX_ARGS];
    for (i, arg) in args.iter().enumerate() {
        let len = arg.iter().position(|&b| b == 0).unwrap_or(MAX_ARG_LEN).min(MAX_ARG_LEN - 1);
        sp_off -= len + 1;
        unsafe {
            core::ptr::copy_nonoverlapping(arg.as_ptr(), (ks + sp_off) as *mut u8, len);
            *((ks + sp_off + len) as *mut u8) = 0;
        }
        arg_ptrs[i] = ks + USER_MIRROR_OFFSET + sp_off; // user VA of the string
    }

    // Pointer table: argc, argv[], NULL, empty envp (NULL), empty auxv (0,0).
    let table_words = 1 + args.len() + 1 + 1 + 2;
    sp_off = (sp_off - table_words * 8) & !0xf; // 16-byte align
    let base = ks + sp_off;
    unsafe {
        *(base as *mut usize) = args.len();
        for (i, p) in arg_ptrs.iter().enumerate().take(args.len()) {
            *((base + 8 * (1 + i)) as *mut usize) = *p;
        }
        *((base + 8 * (1 + args.len())) as *mut usize) = 0; // argv NULL
        *((base + 8 * (2 + args.len())) as *mut usize) = 0; // envp NULL
        *((base + 8 * (3 + args.len())) as *mut usize) = 0; // auxv AT_NULL key
        *((base + 8 * (4 + args.len())) as *mut usize) = 0; // auxv value
    }
    tcb.frame.x[2] = ks + USER_MIRROR_OFFSET + sp_off;
    true
}

/// On success the trap frame is replaced wholesale — sret enters the new
/// image and the old program never resumes. On failure a0 carries the errno.
fn sys_execve(path_va: usize, argv_va: usize, frame: &mut TrapFrame) {
    if let Err(e) = execve_inner(path_va, argv_va, frame) {
        frame.set_a0(e as usize);
    }
}

fn execve_inner(path_va: usize, argv_va: usize, frame: &mut TrapFrame) -> Result<(), isize> {
    let mut path = [0u8; MAX_PATH];
    let path_len = read_cstr(path_va, &mut path).ok_or(ENOENT)?;
    let path = &path[..path_len];
    let basename = match path.iter().rposition(|&b| b == b'/') {
        Some(i) => &path[i + 1..],
        None    => path,
    };

    // Registry first (embedded ELFs), then ramfs (single data page).
    let mut file_buf = [0u8; 4096];
    let elf_bytes: &[u8] = match crate::proc::find_elf(basename) {
        Some(b) => b,
        None => {
            let inode = crate::fs::ramfs::fs_open(path).ok_or(ENOENT)?;
            if crate::fs::ramfs::inode_kind(inode) != crate::fs::ramfs::InodeKind::File {
                return Err(ENOENT);
            }
            let size = crate::fs::ramfs::inode_size(inode).min(4096);
            let n = crate::fs::ramfs::fs_read(inode, 0, &mut file_buf[..size]);
            if n < 64 { return Err(EINVAL); }
            // Leak the page so the slice outlives the stack frame.
            let backing = mm::alloc_page().ok_or(ENOMEM)?;
            unsafe {
                core::ptr::copy_nonoverlapping(file_buf.as_ptr(), backing as *mut u8, n);
                core::slice::from_raw_parts(backing as *const u8, n)
            }
        }
    };

    // Copy argv strings out of the (current) address space before replacing it.
    let mut arg_bufs = [[0u8; MAX_ARG_LEN]; MAX_ARGS];
    let mut arg_count = 0usize;
    if argv_va != 0 {
        for i in 0..MAX_ARGS {
            let p = unsafe { *((argv_va + i * 8) as *const usize) };
            if p == 0 { break; }
            match read_cstr(p, &mut arg_bufs[i]) {
                Some(_) => arg_count += 1,
                None    => break,
            }
        }
    }

    // Build the replacement address space + thread state on a FRESH kernel
    // stack (the current one still holds the live trap frame).
    let pgd = unsafe { vspace::create_elf_vspace() }.ok_or(ENOMEM)?;
    vspace::map_page(pgd, 0x1000_0000, 0x1000_0000, vspace::PTE_R | vspace::PTE_W)
        .map_err(|_| ENOMEM)?;
    let (entry, seg_end) = crate::elf::load_with_end(elf_bytes, pgd).map_err(|_| EINVAL)?;
    let new_satp = vspace::pgd_to_satp(pgd);

    let new_kstack = mm::alloc_pages(2).ok_or(ENOMEM)?; // 16 KiB, same as KSTACK
    unsafe { core::ptr::write_bytes(new_kstack as *mut u8, 0, crate::thread::KSTACK_SIZE); }

    let cur_pa = sched::current_pa();
    let tcb = unsafe { &mut *(cur_pa as *mut Tcb) };

    tcb.satp       = new_satp;
    tcb.kstack_pa  = new_kstack;
    tcb.brk_base   = seg_end;
    tcb.brk_next   = seg_end;
    tcb.brk_mapped = seg_end;
    tcb.mmap_bump  = 0;

    // Reset the trap frame: full register clear, then enter at ELF entry.
    let sstatus = frame.sstatus;
    *frame = TrapFrame::ZERO;
    frame.sstatus = sstatus;
    frame.sepc    = entry;

    if !setup_entry_stack(cur_pa, &arg_bufs[..arg_count]) {
        return Err(ENOMEM);
    }
    // setup_entry_stack wrote the new sp into the TCB's saved frame, but the
    // LIVE frame is what sret uses — copy the sp across.
    frame.x[2] = tcb.frame.x[2];

    // Switch to the new address space on sret. The trap frame itself lives on
    // the user-mirror stack, which is mapped in every VSpace, so the trap.S
    // epilogue can still pop it after the satp write.
    sched::set_current_satp(new_satp);
    Ok(())
}


// ── sys_wait4 ─────────────────────────────────────────────────────────────────
//
// wait4(pid, wstatus, options, rusage) — rusage ignored; options must be 0.
// pid > 0 waits for that child; pid == -1 waits for any child. Reaped children
// stay in the Exited state (TCBs are not yet recycled).

fn sys_wait4(pid_arg: isize, wstatus_va: usize, frame: &mut TrapFrame) {
    let cur_pa = sched::current_pa();
    if cur_pa == 0 {
        frame.set_a0(ECHILD as usize);
        return;
    }

    // Scan the global TCB list for children of the current process. Prefer an
    // already-exited child; otherwise block on the first live one.
    let mut live_candidate = 0usize;
    let mut cursor = TCB_LIST_HEAD.load(core::sync::atomic::Ordering::Acquire);
    while cursor != 0 {
        let tcb = unsafe { &*(cursor as *const Tcb) };
        if tcb.parent_pa == cur_pa
            && (pid_arg == -1 || tcb.pid == pid_arg as usize)
            && tcb.state != TcbState::Inactive
        {
            if tcb.state == TcbState::Exited {
                let pid = tcb.pid;
                let code = tcb.exit_code;
                wait_reap(pid, code, wstatus_va, frame);
                return;
            }
            if live_candidate == 0 { live_candidate = cursor; }
        }
        cursor = tcb.global_next;
    }

    if live_candidate == 0 {
        frame.set_a0(ECHILD as usize);
        return;
    }

    // Block until the child exits; exit_current writes wstatus and the pid
    // into our frame (linux-aware wake path).
    let child = unsafe { &mut *(live_candidate as *mut Tcb) };
    child.waiter_pa = cur_pa;
    sched::block_current(frame);
    // Unreachable: frame is replaced by the next thread's context.
}

fn wait_reap(pid: usize, exit_code: usize, wstatus_va: usize, frame: &mut TrapFrame) {
    if wstatus_va != 0 {
        let cur_pa = sched::current_pa();
        if cur_pa != 0 {
            let tcb = unsafe { &*(cur_pa as *const Tcb) };
            let pgd = vspace::satp_to_pgd_pa(tcb.satp);
            if let Some(pa) = vspace::va_to_pa(pgd, wstatus_va) {
                unsafe { *(pa as *mut i32) = (exit_code as i32) << 8; }
            }
        }
    }
    frame.set_a0(pid);
}

// ── sys_ioctl ─────────────────────────────────────────────────────────────────

fn sys_ioctl(fd: usize, req: usize, arg: usize) -> isize {
    let _ = fd;
    const TIOCGWINSZ: usize = 0x5413;
    const TCGETS:     usize = 0x5401;
    const TCSETS:     usize = 0x5402;
    const TCSETSW:    usize = 0x5403;
    const TCSETSF:    usize = 0x5404;
    const TIOCGPGRP:  usize = 0x540F;
    const TIOCSPGRP:  usize = 0x5410;
    const FIONREAD:   usize = 0x541B;
    const FIOCLEX:    usize = 0x5451;

    match req {
        TIOCGWINSZ => {
            if arg != 0 {
                unsafe {
                    *((arg    ) as *mut u16) = 24;
                    *((arg + 2) as *mut u16) = 80;
                    *((arg + 4) as *mut u16) = 0;
                    *((arg + 6) as *mut u16) = 0;
                }
            }
            0
        }
        TCGETS | TCSETS | TCSETSW | TCSETSF => 0,
        TIOCGPGRP => { if arg != 0 { unsafe { *(arg as *mut u32) = 1; } } 0 }
        TIOCSPGRP => 0,
        FIONREAD  => { if arg != 0 { unsafe { *(arg as *mut u32) = 0; } } 0 }
        FIOCLEX   => 0,
        _         => EINVAL,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn get_fd(fd: usize) -> Option<(usize, crate::fs::ramfs::FdEntry)> {
    let cur_pa = sched::current_pa();
    if cur_pa == 0 { return None; }
    let tcb = unsafe { &*(cur_pa as *const Tcb) };
    if tcb.fd_table_pa == 0 { return None; }
    let entry = crate::fs::ramfs::fd_get(tcb.fd_table_pa, fd)?;
    if entry.inode_pa == crate::fs::ramfs::FD_STDIO_SENTINEL { return None; }
    Some((tcb.fd_table_pa, entry))
}

fn print_u64(mut v: u64) {
    if v == 0 { uart::putchar(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut n = 0usize;
    while v > 0 { buf[n] = b'0' + (v % 10) as u8; n += 1; v /= 10; }
    for i in (0..n).rev() { uart::putchar(buf[i]); }
}
