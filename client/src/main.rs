//! Ferrite OS IPC client process — Phase 9.
//!
//! Ecall convention:
//!   a0 = cap slot, a1 = label, a2 = badge/arg0, a3 = msg[0], ...
//!   Returns: a0 = error, a1 = badge, a2 = msg[0], ...
//!
//! Slot 11 = Endpoint (minted in Phase 5, reused here).

#![no_std]
#![no_main]

use core::arch::asm;

const SLOT_ENDPOINT: usize = 11;
const ENDPOINT_CALL: usize = 42;
const DEBUG_PUTCHAR: usize = 10_000;
const THREAD_EXIT:   usize = 30;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    print(b"[cl] calling\n");

    // ENDPOINT_CALL: badge=0xBE, msg[0]=42.  Blocks until server replies.
    // Returns: a0=error, a1=0, a2=reply (server's msg[0]*2 = 84).
    let (_err, _badge, reply, _) = ecall(SLOT_ENDPOINT, ENDPOINT_CALL, 0xBE, 42, 0, 0);

    print(b"[cl] reply=");
    print_num(reply);
    print(b"\n");

    exit();
}

fn exit() -> ! {
    unsafe {
        asm!(
            "li a0, 0",
            "li a1, 30", // THREAD_EXIT
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
    if n == 0 {
        putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    while n > 0 {
        buf[i] = (n % 10) as u8 + b'0';
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        putchar(buf[i]);
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
