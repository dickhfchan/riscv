//! Ferrite OS cspace_b — Phase 13: per-process CSpace.
//! Slot 1 in this process's private CSpace is null (no UntypedMemory was granted).
//! Retype from it → expect INVALID_CAPABILITY → demonstrates isolation.

#![no_std]
#![no_main]

use core::arch::asm;

const SLOT_PRIV_UT:     usize = 1;  // null in B's CSpace (isolation check)
const SLOT_NEW_EP:      usize = 2;  // destination (unreachable — retype will fail)

const UNTYPED_RETYPE:   usize = 1;
const CAPTYPE_ENDPOINT: usize = 5;
const DEBUG_PUTCHAR:    usize = 10_000;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    // Attempt RETYPE from slot 1 (null in B's CSpace) — must fail.
    let (rc, _, _, _) = ecall(SLOT_PRIV_UT, UNTYPED_RETYPE,
                               CAPTYPE_ENDPOINT, 0, SLOT_NEW_EP, 1);
    if rc != 0 {
        print(b"[B] retype: DENIED (slot 1 is null in B CSpace)\n");
    } else {
        print(b"[B] retype: UNEXPECTED SUCCESS\n");
    }
    exit();
}

fn exit() -> ! {
    unsafe {
        asm!(
            "li a0, 0",
            "li a1, 30",
            "ecall",
            options(noreturn, nostack, nomem),
        );
    }
}

fn print(msg: &[u8]) {
    for &b in msg { putchar(b); }
}

fn putchar(byte: u8) {
    unsafe {
        asm!(
            "ecall",
            in("a0") 0usize,
            in("a1") DEBUG_PUTCHAR,
            in("a2") byte as usize,
            lateout("a0") _, lateout("a1") _, lateout("a2") _, lateout("a3") _,
            lateout("a4") _, lateout("a5") _, lateout("a6") _, lateout("a7") _,
            options(nostack),
        );
    }
}

unsafe fn ecall(
    a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize,
) -> (usize, usize, usize, usize) {
    let (r0, r1, r2, r3): (usize, usize, usize, usize);
    asm!(
        "ecall",
        inlateout("a0") a0 => r0,
        inlateout("a1") a1 => r1,
        inlateout("a2") a2 => r2,
        inlateout("a3") a3 => r3,
        inlateout("a4") a4 => _,
        inlateout("a5") a5 => _,
        lateout("a6") _,
        lateout("a7") _,
        options(nostack),
    );
    (r0, r1, r2, r3)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop { unsafe { asm!("wfi", options(nostack, nomem)); } }
}
