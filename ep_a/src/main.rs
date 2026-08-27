//! Ferrite OS ep_a — Phase 12: userspace Endpoint creation.
//!
//! Protocol:
//!   1. Call UNTYPED_RETYPE to carve a new Endpoint out of the UntypedMemory
//!      capability at slot 1 and install it at slot SLOT_EP2.
//!   2. ENDPOINT_SEND on the pre-existing ep1 (slot 11) — fire-and-forget
//!      delivery to ep_b, which is already blocking on RECV(11).
//!      The badge encodes the newly created slot number.
//!   3. ENDPOINT_RECV on the new ep2 (slot 16) — act as server.
//!   4. ENDPOINT_REPLY with msg * 2.

#![no_std]
#![no_main]

use core::arch::asm;

const SLOT_UNTYPED:     usize = 1;
const SLOT_EP1:         usize = 11; // pre-existing setup channel
const SLOT_EP2:         usize = 16; // slot where the new Endpoint will live

const UNTYPED_RETYPE:   usize = 1;
const ENDPOINT_SEND:    usize = 40;
const ENDPOINT_RECV:    usize = 41;
const ENDPOINT_REPLY:   usize = 43;
const CAPTYPE_ENDPOINT: usize = 5;  // CapType::Endpoint
const DEBUG_PUTCHAR:    usize = 10_000;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    // Dynamically create a new Endpoint at SLOT_EP2.
    // UNTYPED_RETYPE: a0=slot_untyped, a1=label, a2=cap_type, a3=size_bits,
    //                 a4=dst_slot, a5=count
    let (rc, _, _, _) = ecall(SLOT_UNTYPED, UNTYPED_RETYPE,
                               CAPTYPE_ENDPOINT, 0, SLOT_EP2, 1);
    if rc != 0 { exit(); } // retype failed — should not happen

    print(b"[A] created ep2 at slot 16, notifying B...\n");

    // Non-blocking send to ep1: ep_b is already blocking on RECV(11).
    // badge = SLOT_EP2 so ep_b learns which slot to invoke.
    ecall(SLOT_EP1, ENDPOINT_SEND, SLOT_EP2 /*badge*/, 0, 0, 0);

    // Block on the new endpoint waiting for ep_b's call.
    let (_, _, msg, _) = ecall(SLOT_EP2, ENDPOINT_RECV, 0, 0, 0, 0);

    print(b"[A] ep2 msg=");
    print_num(msg);
    print(b", replying with ");
    print_num(msg * 2);
    print(b"\n");

    ecall(0, ENDPOINT_REPLY, msg * 2, 0, 0, 0);

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
    for &b in msg {
        putchar(b);
    }
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
