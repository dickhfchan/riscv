//! Ferrite OS shared-memory reader — Phase 11.
//!
//! Protocol:
//!   1. FRAME_MAP (slot 15) at FRAME_VA — establish R mapping of the shared frame.
//!   2. ENDPOINT_CALL (slot 11) — signal writer to fill the frame, then block.
//!   3. On reply: read and print bytes from FRAME_VA until the null terminator.

#![no_std]
#![no_main]

use core::arch::asm;

const SLOT_ENDPOINT: usize = 11;
const SLOT_FRAME:    usize = 15;
const FRAME_VA:      usize = 0x30000;

const ENDPOINT_CALL: usize = 42;
const FRAME_MAP:     usize = 70;
const DEBUG_PUTCHAR: usize = 10_000;

const PTE_R: usize = 1 << 1;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    // Map the shared frame read-only.  The writer hasn't written yet, but the
    // mapping is established so reads after the CALL return are valid.
    ecall(SLOT_FRAME, FRAME_MAP, FRAME_VA, PTE_R, 0, 0);

    print(b"[cl] mapped shared frame, calling writer...\n");

    // ENDPOINT_CALL blocks until writer replies (data is ready).
    ecall(SLOT_ENDPOINT, ENDPOINT_CALL, 0, 0, 0, 0);

    // Read the null-terminated message from shared memory and print it.
    print(b"[cl] shared data: ");
    let src = FRAME_VA as *const u8;
    let mut i = 0;
    loop {
        let b = src.add(i).read_volatile();
        if b == 0 { break; }
        putchar(b);
        i += 1;
    }
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
