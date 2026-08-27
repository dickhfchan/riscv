// Per-process Sv48 address spaces — Phases 7 & 8.
//
// Phase 7: create_process_vspace() — user mirror + fresh PGD root, no granular user pages.
// Phase 8: create_elf_vspace() + map_page() — true per-process isolation with ELF-loaded
//          pages at arbitrary user VAs.
//
// Design invariant: every process VSpace includes PGD[1] → BOOT_PUD_USER (the user mirror).
// This ensures TrapFrames saved to user-mirror-VA stacks are accessible after any satp
// switch, without needing sscratch tricks in the trap entry path.

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::mm;

const SATP_SV48: usize = 9 << 60;

// ── PTE flag bits (public for use by elf.rs and main.rs) ─────────────────────

pub const PTE_V: u64 = 1 << 0;
pub const PTE_R: u64 = 1 << 1;
pub const PTE_W: u64 = 1 << 2;
pub const PTE_X: u64 = 1 << 3;
pub const PTE_U: u64 = 1 << 4;
pub const PTE_A: u64 = 1 << 6;
pub const PTE_D: u64 = 1 << 7;

// ── Boot satp cache ───────────────────────────────────────────────────────────

static BOOT_SATP: AtomicUsize = AtomicUsize::new(0);

/// Call once immediately after enable_paging() to cache the boot satp value.
pub fn save_boot_satp() {
    let satp: usize;
    unsafe { core::arch::asm!("csrr {}, satp", out(reg) satp, options(nostack, nomem)); }
    BOOT_SATP.store(satp, Ordering::Relaxed);
}

pub fn boot_satp() -> usize {
    BOOT_SATP.load(Ordering::Relaxed)
}

pub fn pgd_to_satp(pgd_pa: usize) -> usize {
    SATP_SV48 | (pgd_pa >> 12)
}

/// Extract PGD physical address from a satp value (Sv39/48/57 all use PPN in bits 43:0).
pub fn satp_to_pgd_pa(satp: usize) -> usize {
    (satp & ((1usize << 44) - 1)) << 12
}

/// Flush all TLB entries (sfence.vma x0, x0).
/// Required after modifying PTEs in a live page table.
pub fn flush_tlb_all() {
    unsafe { core::arch::asm!("sfence.vma x0, x0", options(nostack, nomem)); }
}

// ── Phase 7: process VSpace (user-mirror approach) ───────────────────────────

/// Create a fresh Sv48 VSpace for a user process (Phase 7 approach: user mirror stack).
///
/// PGD layout:
///   PGD[0] → new kernel PUD:
///     PUD[0] = 1 GiB MMIO superpage → PA 0x00000000  (kernel-only)
///     PUD[2] = 1 GiB kernel RAM superpage → PA 0x80000000  (kernel-only)
///   PGD[1] → BOOT_PUD_USER (shared user mirror: all kernel RAM at VA+2^39, PTE_U=1)
pub unsafe fn create_process_vspace() -> Option<usize> {
    let pgd_pa = mm::alloc_page()?;
    let pud_pa = mm::alloc_page()?;

    core::ptr::write_bytes(pgd_pa as *mut u8, 0, 4096);
    core::ptr::write_bytes(pud_pa as *mut u8, 0, 4096);

    let pgd = pgd_pa as *mut u64;
    let pud = pud_pa as *mut u64;

    pud.add(0).write_volatile(leaf_pte(0x0000_0000, PTE_R | PTE_W));                // MMIO
    pud.add(2).write_volatile(leaf_pte(0x8000_0000, PTE_R | PTE_W | PTE_X));        // kernel RAM

    pgd.add(0).write_volatile(table_pte(pud_pa as u64));
    pgd.add(1).write_volatile(super::mmu::boot_pgd_user_pte()); // user mirror

    Some(pgd_pa)
}

// ── Phase 8: ELF VSpace (granular user pages) ─────────────────────────────────

/// Create a fresh Sv48 VSpace for loading an ELF process (Phase 8).
///
/// PGD layout (initial — user pages added later via map_page):
///   PGD[0] → new PUD:
///     PUD[2] = 1 GiB superpage → PA 0x80000000  (kernel RAM, kernel-only)
///     PUD[0] → PMD → PT entries for PLIC pages  (kernel-only)
///   PGD[1] → BOOT_PUD_USER (shared user mirror for TrapFrame stack)
///
/// PLIC pages are pre-mapped so the kernel can handle external interrupts
/// (PLIC claim/complete) even while this satp is active.
///
/// Caller must then map:
///   - UART page at 0x10000000 (kernel-only, for trap handler putchar)
///   - ELF segments at their PT_LOAD VAs (user-accessible, from elf::load)
pub unsafe fn create_elf_vspace() -> Option<usize> {
    let pgd_pa = mm::alloc_page()?;
    let pud_pa = mm::alloc_page()?;

    core::ptr::write_bytes(pgd_pa as *mut u8, 0, 4096);
    core::ptr::write_bytes(pud_pa as *mut u8, 0, 4096);

    let pgd = pgd_pa as *mut u64;
    let pud = pud_pa as *mut u64;

    // 1 GiB kernel RAM superpage (code + data).
    pud.add(2).write_volatile(leaf_pte(0x8000_0000, PTE_R | PTE_W | PTE_X));

    pgd.add(0).write_volatile(table_pte(pud_pa as u64));
    pgd.add(1).write_volatile(super::mmu::boot_pgd_user_pte()); // user mirror for stack

    // PLIC pages: the kernel must be able to access the PLIC (claim/complete,
    // enable, priority) even when this ELF VSpace's satp is active during an
    // external interrupt.  boot_satp covers [0, 1 GiB) with a superpage, but
    // ELF VSpaces can't use a superpage there because ELF code also lives in
    // that range (typically at 0x10000+).  Map the three pages actually touched:
    //   0x0c000000 – priority registers
    //   0x0c002000 – enable registers (S-mode context, offset 0x2080 in this page)
    //   0x0c201000 – threshold + claim/complete (S-mode context)
    map_page(pgd_pa, 0x0c00_0000, 0x0c00_0000, PTE_R | PTE_W).ok()?;
    map_page(pgd_pa, 0x0c00_2000, 0x0c00_2000, PTE_R | PTE_W).ok()?;
    map_page(pgd_pa, 0x0c20_1000, 0x0c20_1000, PTE_R | PTE_W).ok()?;

    Some(pgd_pa)
}

// ── Granular page mapping ─────────────────────────────────────────────────────

/// Map a 4 KiB page: physical page `pa` at virtual address `va` in the VSpace
/// rooted at `pgd_pa`, with PTE permission flags `pte_flags`.
///
/// Allocates intermediate page tables as needed.
/// Returns Err if an intermediate level is already a superpage (leaf PTE).
pub fn map_page(pgd_pa: usize, va: usize, pa: usize, pte_flags: u64) -> Result<(), ()> {
    let vpn = [
        (va >> 12) & 0x1ff, // L0 — PT index
        (va >> 21) & 0x1ff, // L1 — PMD index
        (va >> 30) & 0x1ff, // L2 — PUD index
        (va >> 39) & 0x1ff, // L3 — PGD index
    ];

    let mut table = pgd_pa as *mut u64;

    // Walk levels 3 → 1, allocating intermediate tables on demand
    for level in (1..=3).rev() {
        let entry_ptr = unsafe { table.add(vpn[level]) };
        let entry = unsafe { entry_ptr.read_volatile() };

        if entry & PTE_V == 0 {
            // Entry is invalid — allocate a fresh page table
            let new_pa = mm::alloc_page().ok_or(())?;
            unsafe { core::ptr::write_bytes(new_pa as *mut u8, 0, 4096) };
            unsafe { entry_ptr.write_volatile(table_pte(new_pa as u64)) };
            table = new_pa as *mut u64;
        } else if entry & (PTE_R | PTE_W | PTE_X) != 0 {
            // Leaf PTE (superpage) — cannot insert a sub-page here.
            return Err(());
        } else {
            // Table entry — follow the pointer to the next level
            table = (((entry >> 10) << 12) as usize) as *mut u64;
        }
    }

    // Write the 4 KiB leaf PTE at level 0
    let entry_ptr = unsafe { table.add(vpn[0]) };
    unsafe { entry_ptr.write_volatile(leaf_pte(pa as u64, pte_flags)) };
    Ok(())
}

// ── User-pointer translation ──────────────────────────────────────────────────

/// Walk the Sv48 page table rooted at `pgd_pa` and return the physical address
/// of virtual address `va`, or None if any level is not mapped.
/// Handles 1 GiB superpages (L2 leaf) and 4 KiB pages (L0 leaf).
pub fn va_to_pa(pgd_pa: usize, va: usize) -> Option<usize> {
    let vpn = [
        (va >> 12) & 0x1FF, // L0
        (va >> 21) & 0x1FF, // L1
        (va >> 30) & 0x1FF, // L2
        (va >> 39) & 0x1FF, // L3
    ];
    let mut table = pgd_pa as *const u64;
    for level in (0..=3usize).rev() {
        let pte = unsafe { table.add(vpn[level]).read_volatile() };
        if pte & PTE_V == 0 { return None; }
        if pte & (PTE_R | PTE_W | PTE_X) != 0 {
            // Leaf PTE — may be a superpage at this level.
            let pa_base = ((pte as usize >> 10) << 12) as usize;
            let offset_mask = if level == 0 { 0xFFF } else { (1usize << (12 + level * 9)) - 1 };
            return Some(pa_base | (va & offset_mask));
        }
        if level == 0 { return None; }
        table = (((pte as usize >> 10) << 12)) as *const u64;
    }
    None
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn table_pte(pa: u64) -> u64 {
    ((pa >> 12) << 10) | PTE_V
}

fn leaf_pte(pa: u64, flags: u64) -> u64 {
    ((pa >> 12) << 10) | flags | PTE_V | PTE_A | PTE_D
}
