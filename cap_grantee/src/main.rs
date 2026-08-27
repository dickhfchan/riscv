//! Ferrite OS cap_grantee — Phase 14: IPC capability transfer.
//!
//! CSpace: slot 0=cnode, slot 1=ep_shared (rendezvous), slot 2=null initially.
//!
//! Protocol:
//!   1. ENDPOINT_RECV on ep_shared with a6=2 (receive transferred cap at slot 2).
//!      After the recv completes, ep_private is now at slot 2.
//!   2. ENDPOINT_CALL on ep_private (slot 2) with msg=77.
//!   3. Print the reply (expected: 154).

#![no_std]
#![no_main]

use core::arch::asm;

const SLOT_EP_SHARED: usize = 1;  // shared rendezvous endpoint
const SLOT_EP_PRIV:   usize = 2;  // filled in by IPC cap transfer

const ENDPOINT_RECV:  usize = 41;
const ENDPOINT_CALL:  usize = 42;
const DEBUG_PUTCHAR:  usize = 10_000;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    // Block on ep_shared; a6=SLOT_EP_PRIV tells kernel to place received cap at slot 2.
    ecall7(SLOT_EP_SHARED, ENDPOINT_RECV, 0, 0, 0, 0, SLOT_EP_PRIV);
    print(b"[grantee] received ep_private at slot 2, calling...\n");

    // Invoke the just-received ep_private with msg=77.
    let (_, _, reply, _) = ecall(SLOT_EP_PRIV, ENDPOINT_CALL, 0, 77, 0, 0);
    print(b"[grantee] ep_private reply=");
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

unsafe fn ecall7(
    a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize,
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
        inlateout("a6") a6 => _,
        lateout("a7") _,
        options(nostack),
    );
    (r0, r1, r2, r3)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop { unsafe { asm!("wfi", options(nostack, nomem)); } }
}
