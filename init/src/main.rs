//! Ferrite OS init process — Phase 8.
//!
//! Compiled as a statically-linked RV64 ELF, loaded into its own VSpace by
//! the kernel ELF loader.  Communicates with the kernel only via ecall.
//!
//! Ecall convention (mirrors kernel syscall.rs):
//!   a0 = cap slot (0 = CNode self, always valid for DEBUG_PUTCHAR)
//!   a1 = label
//!   a2 = arg0
//!
//! label::DEBUG_PUTCHAR = 10_000  — write one byte to serial
//! label::THREAD_EXIT   = 30     — terminate calling thread

#![no_std]
#![no_main]

use core::arch::asm;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    print(b"[init] Hello from ELF process!\n");
    exit();
}

fn print(msg: &[u8]) {
    for &byte in msg {
        putchar(byte);
    }
}

fn putchar(byte: u8) {
    unsafe {
        asm!(
            "ecall",
            in("a0") 0usize,       // cap slot 0
            in("a1") 10000usize,   // DEBUG_PUTCHAR
            in("a2") byte as usize,
            // The kernel's set_reply zeroes a0-a7 in the TrapFrame.
            // Declare all as clobbered so the compiler doesn't keep live
            // values in these registers across the ecall.
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

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { asm!("wfi", options(nostack, nomem)); }
    }
}
