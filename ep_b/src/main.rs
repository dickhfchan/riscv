//! Ferrite OS ep_b — Phase 12: userspace Endpoint creation (client side).
//!
//! Protocol:
//!   1. ENDPOINT_RECV on the pre-existing ep1 (slot 11) — block until ep_a
//!      signals that its dynamically created Endpoint is ready.
//!      The badge field carries the slot number of the new Endpoint.
//!   2. ENDPOINT_CALL on the new endpoint (slot number from badge).
//!   3. Print the reply.

#![no_std]
#![no_main]

use core::arch::asm;

const SLOT_EP1:      usize = 11;

const ENDPOINT_RECV: usize = 41;
const ENDPOINT_CALL: usize = 42;
const DEBUG_PUTCHAR: usize = 10_000;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    // Wait for ep_a to create ep2 and tell us its slot number.
    let (_, ep2_slot, _, _) = ecall(SLOT_EP1, ENDPOINT_RECV, 0, 0, 0, 0);

    print(b"[B] ep2 ready at slot ");
    print_num(ep2_slot);
    print(b", calling...\n");

    // Call the dynamically created endpoint with msg=100.
    let (_, _, reply, _) = ecall(ep2_slot, ENDPOINT_CALL, 0 /*badge*/, 100 /*msg0*/, 0, 0);

    print(b"[B] ep2 reply=");
    print_num(reply);
    print(b"\n");

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

fn print_num(mut n: usize) {
    if n == 0 { putchar(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    while n > 0 { buf[i] = (n % 10) as u8 + b'0'; n /= 10; i += 1; }
    while i > 0 { i -= 1; putchar(buf[i]); }
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
