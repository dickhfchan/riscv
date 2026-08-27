//! Ferrite OS shared-memory writer — Phase 11.
//!
//! Protocol:
//!   1. Block on ENDPOINT_RECV (slot 11) — wait for reader to trigger.
//!   2. FRAME_MAP (slot 15) at FRAME_VA — establish RW mapping of the shared frame.
//!   3. Write a message into the frame.
//!   4. ENDPOINT_REPLY — wake the reader; data is ready.

#![no_std]
#![no_main]

use core::arch::asm;

const SLOT_ENDPOINT: usize = 11;
const SLOT_FRAME:    usize = 15;
const FRAME_VA:      usize = 0x30000; // page beyond ELF text; same in both processes

const ENDPOINT_RECV: usize = 41;
const ENDPOINT_REPLY: usize = 43;
const FRAME_MAP:     usize = 70;
const DEBUG_PUTCHAR: usize = 10_000;

const PTE_R: usize = 1 << 1;
const PTE_W: usize = 1 << 2;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    // Block until reader triggers via ENDPOINT_CALL.
    ecall(SLOT_ENDPOINT, ENDPOINT_RECV, 0, 0, 0, 0);

    // Map the shared frame read-write at FRAME_VA.
    let r = ecall(SLOT_FRAME, FRAME_MAP, FRAME_VA, PTE_R | PTE_W, 0, 0);
    if r.0 != 0 { exit(); } // map failed

    // Write the shared message.
    let msg = b"Phase 11: shared memory!\0";
    let dst = FRAME_VA as *mut u8;
    for (i, &b) in msg.iter().enumerate() {
        dst.add(i).write_volatile(b);
    }

    print(b"[sv] wrote to shared frame\n");

    // Reply to reader: data is ready.
    ecall(0, ENDPOINT_REPLY, 0, 0, 0, 0);

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

fn putchar(byte: u8) {
    unsafe {
        asm!(
            "ecall",
            in("a0") 0usize,
            in("a1") DEBUG_PUTCHAR,
            in("a2") byte as usize,
            lateout("a0") _,
            lateout("a1") _,
            lateout("a2") _,
            lateout("a3") _,
            lateout("a4") _,
            lateout("a5") _,
            lateout("a6") _,
            lateout("a7") _,
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
    loop {
        unsafe { asm!("wfi", options(nostack, nomem)); }
    }
}
