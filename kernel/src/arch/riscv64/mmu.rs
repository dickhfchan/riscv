/*
 * Sv48 page table initialisation — Phase 2.
 *
 * We set up a minimal boot-time mapping before proper VM infrastructure
 * exists.  Two static page tables are used (no allocator needed):
 *
 *  BOOT_PGD[0]    → BOOT_PUD_LOW
 *  BOOT_PUD_LOW[2] → 1 GiB superpage: VA 0x80000000 → PA 0x80000000
 *
 * This identity-maps the region [0x80000000, 0xC000_0000) — which contains
 * the kernel image, BSS, boot stack, and the FDT — so code keeps running
 * with VA == PA after satp is written.
 *
 * Phase 3 will add the proper high-VA direct-map and relocate the kernel.
 */

use core::ptr::addr_of;

// ── PTE flag bits ───────────────────────────────────────────────────────────
const PTE_V: u64 = 1 << 0; // valid
const PTE_R: u64 = 1 << 1; // readable
const PTE_W: u64 = 1 << 2; // writable
const PTE_X: u64 = 1 << 3; // executable
const PTE_U: u64 = 1 << 4; // user-accessible (Phase 5: allow U-mode thread access)
const PTE_G: u64 = 1 << 5; // global (no ASID flush needed)
const PTE_A: u64 = 1 << 6; // accessed (hardware or software)
const PTE_D: u64 = 1 << 7; // dirty   (hardware or software)

// ── satp register ──────────────────────────────────────────────────────────
const SATP_SV48: u64 = 9u64 << 60; // MODE = Sv48

const ENTRIES: usize = 512;

/// 4 KiB page table (must be page-aligned).
#[repr(C, align(4096))]
struct PageTable([u64; ENTRIES]);

// Statically allocated page tables: kernel identity map + user mirror.
static mut BOOT_PGD:      PageTable = PageTable([0; ENTRIES]);
static mut BOOT_PUD_LOW:  PageTable = PageTable([0; ENTRIES]); // VA[47:39] = 0
static mut BOOT_PUD_USER: PageTable = PageTable([0; ENTRIES]); // VA[47:39] = 1 (user mirror)

/// Enable Sv48 paging with identity maps for MMIO and kernel RAM, plus a
/// user-mode mirror of kernel RAM with PTE_U=1.
///
/// After this returns:
///  - VA [0x00000000, 0x40000000) → PA same (MMIO, no PTE_U)
///  - VA [0x80000000, 0xC0000000) → PA same (kernel RAM, no PTE_U, kernel executes here)
///  - VA [USER_MIRROR, USER_MIRROR+1GiB) → PA [0x80000000, 0xC0000000) (PTE_U=1,
///      U-mode threads run here; S-mode trap handler reaches it via SUM=1)
///
/// # Safety
/// Must be called exactly once, before any other virtual-memory use.
pub unsafe fn enable_paging() {
    // ── PGD[0] → BOOT_PUD_LOW ────────────────────────────────────────────────
    let pud_pa = addr_of!(BOOT_PUD_LOW) as u64;
    BOOT_PGD.0[0] = table_pte(pud_pa);

    // BOOT_PUD_LOW[0] → 1 GiB superpage PA 0x00000000 (UART/PLIC/CLINT) no PTE_U
    BOOT_PUD_LOW.0[0] = leaf_pte(0x0000_0000u64, PTE_R | PTE_W);

    // BOOT_PUD_LOW[2] → 1 GiB superpage PA 0x80000000 (kernel RAM) no PTE_U.
    // S-mode executes here; PTE_U=0 is required (S-mode can never execute U pages).
    BOOT_PUD_LOW.0[2] = leaf_pte(0x8000_0000u64, PTE_R | PTE_W | PTE_X);

    // ── PGD[1] → BOOT_PUD_USER  (VA[47:39] = 1, base = 0x8000000000) ────────
    // BOOT_PUD_USER[2] mirrors kernel RAM at VA [0x8080000000, 0x80C0000000)
    // with PTE_U=1 so U-mode threads can execute and access their stack there.
    let pud_user_pa = addr_of!(BOOT_PUD_USER) as u64;
    BOOT_PGD.0[1] = table_pte(pud_user_pa);
    BOOT_PUD_USER.0[2] = leaf_pte(0x8000_0000u64, PTE_R | PTE_W | PTE_X | PTE_U);

    // ── Activate paging ──────────────────────────────────────────────────────
    let pgd_pa = addr_of!(BOOT_PGD) as u64;
    let satp   = SATP_SV48 | (pgd_pa >> 12);

    // Set SUM (bit 18) in sstatus BEFORE writing satp.
    // SUM lets S-mode load/store to PTE_U pages — needed so the trap handler
    // can push/pop the user stack (at a user-mirror VA) when a U-mode thread traps.
    // Note: SUM does NOT affect instruction fetches, so the kernel still cannot
    // execute from PTE_U pages; only loads/stores are permitted with SUM=1.
    core::arch::asm!(
        "sfence.vma zero, zero",
        "csrs sstatus, {sum}",
        "csrw satp, {satp}",
        "sfence.vma zero, zero",
        sum  = in(reg) (1usize << 18),
        satp = in(reg) satp,
        options(nostack),
    );
}

/// VA offset applied to U-mode thread entry points and stacks.
/// VA[47:39] = 1 → 0x8000000000; BOOT_PUD_USER[2] maps this range to RAM.
pub const USER_MIRROR_OFFSET: usize = 1 << 39; // 0x8_0000_0000

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Build a non-leaf (pointer) PTE: valid, no R/W/X.
#[inline]
fn table_pte(pa: u64) -> u64 {
    (pa >> 12 << 10) | PTE_V
}

/// Build a leaf PTE with the given permission flags.
#[inline]
fn leaf_pte(pa: u64, flags: u64) -> u64 {
    (pa >> 12 << 10) | PTE_V | PTE_A | PTE_D | PTE_G | flags
}

/// Return the raw PTE stored in BOOT_PGD[1] (the user-mirror table pointer).
/// Used by vspace.rs to share BOOT_PUD_USER across all process VSpaces.
pub fn boot_pgd_user_pte() -> u64 {
    unsafe { BOOT_PGD.0[1] }
}

/// Verify paging is on by reading `satp` and checking MODE == Sv48.
pub fn assert_sv48_active() {
    let satp: u64;
    unsafe { core::arch::asm!("csrr {}, satp", out(reg) satp, options(nostack, nomem)) };
    assert_eq!(satp >> 60, 9, "satp MODE is not Sv48");
}
