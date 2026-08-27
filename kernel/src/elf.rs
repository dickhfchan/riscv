// ELF64 loader for the init process (Phase 8).
//
// Parses a statically-linked RV64 LE ELF binary, maps each PT_LOAD segment
// into an existing per-process VSpace, and returns the entry-point VA.
//
// Only the fields needed for a static no_std binary are parsed — no dynamic
// linking, no relocations, no symbol table.

use crate::arch::riscv64::vspace::{self, PTE_R, PTE_W, PTE_X, PTE_U};
use crate::mm;

// ELF64 header field offsets
const E_IDENT_MAGIC:   usize = 0;
const E_IDENT_CLASS:   usize = 4;
const E_IDENT_DATA:    usize = 5;
const E_ENTRY:         usize = 24;
const E_PHOFF:         usize = 32;
const E_PHENTSIZE:     usize = 54;
const E_PHNUM:         usize = 56;

// ELF64 program header field offsets
const PH_TYPE:   usize = 0;
const PH_FLAGS:  usize = 4;
const PH_OFFSET: usize = 8;
const PH_VADDR:  usize = 16;
const PH_FILESZ: usize = 32;
const PH_MEMSZ:  usize = 40;

const PT_LOAD: u32 = 1;
const PF_X:    u32 = 1;
const PF_W:    u32 = 2;
const PF_R:    u32 = 4;

// ── Public interface ──────────────────────────────────────────────────────────

/// Parse `data` as an ELF64 binary, map each PT_LOAD segment into `vspace_pa`,
/// and return the entry-point virtual address.
///
/// Physical pages are allocated via `mm::alloc_page()`, zeroed, and populated
/// from the file image.  User-space segments receive `PTE_U`.
pub fn load(data: &[u8], vspace_pa: usize) -> Result<usize, &'static str> {
    load_with_end(data, vspace_pa).map(|(entry, _)| entry)
}

/// Like `load`, but also returns the page-aligned VA just past the end of the
/// highest PT_LOAD segment.  Linux processes use it as the initial `brk`.
pub fn load_with_end(data: &[u8], vspace_pa: usize) -> Result<(usize, usize), &'static str> {
    if data.len() < 64 {
        return Err("ELF too short");
    }
    if &data[E_IDENT_MAGIC..E_IDENT_MAGIC + 4] != b"\x7fELF" {
        return Err("bad ELF magic");
    }
    if data[E_IDENT_CLASS] != 2 { return Err("not ELF64"); }
    if data[E_IDENT_DATA]  != 1 { return Err("not little-endian"); }

    let e_entry     = read_u64(data, E_ENTRY) as usize;
    let e_phoff     = read_u64(data, E_PHOFF) as usize;
    let e_phentsize = read_u16(data, E_PHENTSIZE) as usize;
    let e_phnum     = read_u16(data, E_PHNUM) as usize;

    if e_phentsize < 56 || e_phnum == 0 {
        return Err("bad phdrs");
    }

    let mut max_end = 0usize; // page-aligned end of highest PT_LOAD segment

    for i in 0..e_phnum {
        let ph_start = e_phoff + i * e_phentsize;
        if ph_start + e_phentsize > data.len() {
            return Err("phdr out of bounds");
        }
        let ph = &data[ph_start..ph_start + e_phentsize];

        if read_u32(ph, PH_TYPE) != PT_LOAD { continue; }

        let p_flags  = read_u32(ph, PH_FLAGS);
        let p_offset = read_u64(ph, PH_OFFSET) as usize;
        let p_vaddr  = read_u64(ph, PH_VADDR)  as usize;
        let p_filesz = read_u64(ph, PH_FILESZ) as usize;
        let p_memsz  = read_u64(ph, PH_MEMSZ)  as usize;

        if p_memsz == 0 { continue; }
        if p_offset + p_filesz > data.len() {
            return Err("segment file data out of bounds");
        }

        let pte_flags = elf_flags_to_pte(p_flags);
        let page_start = p_vaddr & !0xfff;
        let page_end   = (p_vaddr + p_memsz + 0xfff) & !0xfff;
        if page_end > max_end { max_end = page_end; }
        let mut va = page_start;

        while va < page_end {
            let page_pa = mm::alloc_page().ok_or("out of memory")?;
            unsafe { core::ptr::write_bytes(page_pa as *mut u8, 0, 4096) };

            // Bytes from the file image that fall within this page:
            //   file covers VAs [p_vaddr, p_vaddr + p_filesz)
            let copy_va_lo = va.max(p_vaddr);
            let copy_va_hi = (va + 4096).min(p_vaddr + p_filesz);

            if copy_va_lo < copy_va_hi {
                let dst_off = copy_va_lo - va;           // offset into page
                let src_off = p_offset + (copy_va_lo - p_vaddr); // file offset
                let len     = copy_va_hi - copy_va_lo;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(src_off),
                        (page_pa + dst_off) as *mut u8,
                        len,
                    );
                }
            }

            vspace::map_page(vspace_pa, va, page_pa, pte_flags)
                .map_err(|_| "map_page conflict")?;

            va += 4096;
        }
    }

    Ok((e_entry, max_end))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn elf_flags_to_pte(flags: u32) -> u64 {
    let mut pte = PTE_U; // all user-space segments are user-accessible
    if flags & PF_R != 0 { pte |= PTE_R; }
    if flags & PF_W != 0 { pte |= PTE_W; }
    if flags & PF_X != 0 { pte |= PTE_X; }
    pte
}

fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}
