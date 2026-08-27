//! Ferrite OS init_icaps — Phase 20: InitCaps handoff verification.
//!
//! The kernel gives this process a pre-populated CSpace:
//!   Slot 0: CNode self
//!   Slot 1: UntypedMemory (private 32 KiB pool)
//!   Slot 2: IRQControl
//!   Slot 3: Frame (UART @ 0x10000000)
//!
//! Verifies each cap type via CAP_IDENTIFY, then retypes an Endpoint from
//! the private UntypedMemory to prove the allocator is usable from userspace.

#![no_std]
#![no_main]

use core::arch::asm;

const DEBUG_PUTCHAR: usize = 10_000;
const THREAD_EXIT:   usize = 30;
const CAP_IDENTIFY:  usize = 9;
const UNTYPED_RETYPE: usize = 1;
const OK: usize = 0;

// CapType ordinals (must match kernel cap/mod.rs).
const CAP_CNODE:      usize = 2;
const CAP_UNTYPED:    usize = 1;
const CAP_IRQCONTROL: usize = 9;
const CAP_FRAME:      usize = 7;
const CAP_ENDPOINT:   usize = 5;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    print(b"[icaps] verifying InitCaps...\n");

    // Slot 0: CNode self
    let (rc, kind) = identify(0);
    assert_cap(rc, kind, CAP_CNODE, b"slot0=CNode");

    // Slot 1: UntypedMemory
    let (rc, kind) = identify(1);
    assert_cap(rc, kind, CAP_UNTYPED, b"slot1=Untyped");

    // Slot 2: IRQControl
    let (rc, kind) = identify(2);
    assert_cap(rc, kind, CAP_IRQCONTROL, b"slot2=IRQControl");

    // Slot 3: UART Frame
    let (rc, kind) = identify(3);
    assert_cap(rc, kind, CAP_FRAME, b"slot3=Frame");

    // Use slot 1 (UntypedMemory) to retype an Endpoint into slot 4.
    let rc = retype_endpoint(1, 4);
    if rc != OK {
        print(b"[icaps] FAIL: retype rc=");
        print_u(rc);
        print(b"\n");
        exit(1);
    }
    let (rc, kind) = identify(4);
    assert_cap(rc, kind, CAP_ENDPOINT, b"slot4=Endpoint(retyped)");

    print(b"[OK] Phase 20: InitCaps handoff verified\n");
    exit(0);
}

fn identify(slot: usize) -> (usize, usize) {
    let rc; let kind;
    unsafe {
        asm!("ecall",
            inlateout("a0") slot      => rc,
            inlateout("a1") CAP_IDENTIFY => kind,
            lateout("a2") _, lateout("a3") _, lateout("a4") _,
            lateout("a5") _, lateout("a6") _, lateout("a7") _,
            options(nostack));
    }
    (rc, kind)
}

fn retype_endpoint(ut_slot: usize, dst_slot: usize) -> usize {
    // a0=ut_slot, a1=UNTYPED_RETYPE, a2=CAP_ENDPOINT, a3=0(size_bits), a4=dst_slot, a5=1(count)
    let rc;
    unsafe {
        asm!("ecall",
            inlateout("a0") ut_slot          => rc,
            inlateout("a1") UNTYPED_RETYPE   => _,
            inlateout("a2") CAP_ENDPOINT     => _,
            inlateout("a3") 0usize           => _,
            inlateout("a4") dst_slot         => _,
            inlateout("a5") 1usize           => _,
            lateout("a6") _, lateout("a7") _,
            options(nostack));
    }
    rc
}

fn assert_cap(rc: usize, kind: usize, expected: usize, label: &[u8]) {
    if rc != OK || kind != expected {
        print(b"[icaps] FAIL: ");
        print(label);
        print(b" rc="); print_u(rc);
        print(b" kind="); print_u(kind);
        print(b" expected="); print_u(expected);
        print(b"\n");
        exit(1);
    }
    print(b"[icaps] OK: ");
    print(label);
    print(b"\n");
}

fn exit(code: usize) -> ! {
    unsafe {
        asm!("ecall",
            in("a0") 0usize,
            in("a1") THREAD_EXIT,
            in("a2") code,
            options(noreturn, nostack, nomem));
    }
}

fn putchar(b: u8) {
    unsafe {
        asm!("ecall",
            in("a0") 0usize, in("a1") DEBUG_PUTCHAR, in("a2") b as usize,
            lateout("a0") _, lateout("a1") _, lateout("a2") _,
            lateout("a3") _, lateout("a4") _, lateout("a5") _,
            lateout("a6") _, lateout("a7") _, options(nostack));
    }
}

fn print(msg: &[u8]) { for &b in msg { putchar(b); } }

fn print_u(v: usize) {
    if v == 0 { putchar(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut n = 0usize;
    let mut x = v;
    while x > 0 { buf[n] = b'0' + (x % 10) as u8; n += 1; x /= 10; }
    for i in (0..n).rev() { putchar(buf[i]); }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop { unsafe { asm!("wfi", options(nostack, nomem)); } }
}
