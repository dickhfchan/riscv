// SMP hart management — Phase 21.
// Uses SBI HSM extension to start secondary harts in S-mode.

const SBI_EXT_HSM:        usize = 0x48534D;
const SBI_HSM_HART_START: usize = 0;

fn sbi_call(ext: usize, fid: usize, a0: usize, a1: usize, a2: usize) -> isize {
    let error: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a7") ext  => _,
            inlateout("a6") fid  => _,
            inlateout("a0") a0   => error,
            inlateout("a1") a1   => _,
            inlateout("a2") a2   => _,
            lateout("a3") _, lateout("a4") _, lateout("a5") _,
            options(nostack),
        );
    }
    error
}

/// Start secondary hart `hartid` at physical address `start_addr` in S-mode.
/// Returns true if SBI accepted the request.
pub fn start_hart(hartid: usize, start_addr: usize) -> bool {
    sbi_call(SBI_EXT_HSM, SBI_HSM_HART_START, hartid, start_addr, 0) == 0
}
