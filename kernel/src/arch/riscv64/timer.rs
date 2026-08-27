// Sstc supervisor-mode timer (RVA23 mandatory).
// S-mode reads `time` CSR directly and writes `stimecmp` CSR (0x14D).

/// QEMU virt machine timebase = 10 MHz → 100 000 ticks per 10 ms.
pub const TIMEBASE_HZ:    u64 = 10_000_000;
const TICK_MS:            u64 = 10;
pub const TICKS_PER_TICK: u64 = TIMEBASE_HZ / (1_000 / TICK_MS); // 100 000

pub fn read_time() -> u64 {
    let t: u64;
    unsafe { core::arch::asm!("csrr {}, time", out(reg) t, options(nostack, nomem)); }
    t
}

/// Arm the timer to fire `after` ticks from now.
pub fn arm(after: u64) {
    let target = read_time() + after;
    unsafe {
        core::arch::asm!(
            "csrw stimecmp, {}",
            in(reg) target,
            options(nostack, nomem),
        );
    }
}

/// Enable supervisor timer interrupt (set sie.STIE, bit 5).
pub fn enable() {
    unsafe {
        core::arch::asm!(
            "csrs sie, {}",
            in(reg) 0x20usize,
            options(nostack, nomem),
        );
    }
}

/// Arm for one tick and enable the interrupt.
pub fn init() {
    arm(TICKS_PER_TICK);
    enable();
}
