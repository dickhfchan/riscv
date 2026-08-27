// RISC-V PLIC driver — QEMU virt machine.
//
// Single-HART machine: HART 0 S-mode interrupt context = 1.
// PLIC base: 0x0c00_0000, within the MMIO identity map [0, 1 GiB).
//
// Register layout (SiFive PLIC spec):
//   priority[N]          : base + N*4                  (N = 1..127)
//   pending[word]        : base + 0x1000 + word*4
//   enable[ctx][word]    : base + 0x2000 + ctx*0x80 + word*4
//   threshold[ctx]       : base + 0x200000 + ctx*0x1000
//   claim_complete[ctx]  : base + 0x200004 + ctx*0x1000

const PLIC_BASE: usize = 0x0c00_0000;
const CTX: usize = 1; // HART 0, S-mode

#[inline]
fn mmio32(off: usize) -> *mut u32 {
    (PLIC_BASE + off) as *mut u32
}

/// Set the interrupt priority for IRQ source N (0 = disabled).
pub fn set_priority(irq: usize, priority: u32) {
    unsafe { mmio32(irq * 4).write_volatile(priority) };
}

/// Enable or disable IRQ source N for the S-mode context.
pub fn set_enable(irq: usize, enabled: bool) {
    let word = irq / 32;
    let bit  = irq % 32;
    let ptr  = mmio32(0x2000 + CTX * 0x80 + word * 4);
    let old  = unsafe { ptr.read_volatile() };
    let new  = if enabled { old | (1 << bit) } else { old & !(1 << bit) };
    unsafe { ptr.write_volatile(new) };
}

/// Set the minimum interrupt priority threshold for the S-mode context.
/// Interrupts with priority ≤ threshold are suppressed.
pub fn set_threshold(threshold: u32) {
    unsafe { mmio32(0x20_0000 + CTX * 0x1000).write_volatile(threshold) };
}

/// Claim the highest-priority pending interrupt for the S-mode context.
/// Returns 0 if no interrupt is pending.
pub fn claim() -> usize {
    unsafe { mmio32(0x20_0004 + CTX * 0x1000).read_volatile() as usize }
}

/// Signal that IRQ N has been fully handled (re-enables PLIC delivery if source
/// is still asserted and the IRQ is enabled for this context).
pub fn complete(irq: usize) {
    unsafe { mmio32(0x20_0004 + CTX * 0x1000).write_volatile(irq as u32) };
}

/// Initialise the PLIC for HART 0 S-mode: threshold = 0 and enable SEIE in sie.
pub fn init() {
    set_threshold(0); // all sources with priority ≥ 1 can fire
    unsafe {
        core::arch::asm!(
            "csrs sie, {seie}",
            seie = in(reg) (1usize << 9), // bit 9 = SEIE
            options(nostack, nomem),
        );
    }
}
