//! Ferrite OS tty_test — Phase 15: Console TTY.
//!
//! Reads a line via CONSOLE_GETCHAR (blocking), then echoes it back.
//! For automated testing the kernel seeds "hello\n" into the RX buffer
//! before this process starts; for interactive use, type at the keyboard.

#![no_std]
#![no_main]

use core::arch::asm;

const DEBUG_PUTCHAR:   usize = 10_000;
const CONSOLE_GETCHAR: usize = 10_001;
const THREAD_EXIT:     usize = 30;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    print(b"[tty] tty> ");

    let mut line = [0u8; 80];
    let mut n = 0usize;
    loop {
        let ch = getchar() as u8;
        if ch == b'\n' || ch == b'\r' { break; }
        if n < 79 { line[n] = ch; n += 1; }
    }

    print(b"[tty] echo: ");
    for i in 0..n { putchar(line[i]); }
    print(b"\n");
    print(b"[OK] Phase 15: TTY input/output working\n");

    exit();
}

fn getchar() -> usize {
    let (_, ch): (usize, usize);
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") 0usize => _,
            inlateout("a1") CONSOLE_GETCHAR => ch,
            lateout("a2") _, lateout("a3") _,
            lateout("a4") _, lateout("a5") _,
            lateout("a6") _, lateout("a7") _,
            options(nostack),
        );
    }
    ch
}

fn putchar(b: u8) {
    unsafe {
        asm!(
            "ecall",
            in("a0") 0usize,
            in("a1") DEBUG_PUTCHAR,
            in("a2") b as usize,
            lateout("a0") _, lateout("a1") _, lateout("a2") _, lateout("a3") _,
            lateout("a4") _, lateout("a5") _, lateout("a6") _, lateout("a7") _,
            options(nostack),
        );
    }
}

fn print(msg: &[u8]) { for &b in msg { putchar(b); } }

fn exit() -> ! {
    unsafe {
        asm!(
            "li a0, 0", "li a1, 30", "ecall",
            options(noreturn, nostack, nomem),
        );
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop { unsafe { asm!("wfi", options(nostack, nomem)); } }
}
