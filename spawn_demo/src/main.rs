//! Ferrite OS spawn_demo — Phase 17: PROC_SPAWN + PROC_WAIT.
//!
//! Demonstrates dynamic process creation from userspace:
//!   1. Call PROC_SPAWN("init") → kernel creates init process, returns Thread cap.
//!   2. Call PROC_WAIT(thread_slot) → block until init exits, collect exit code.
//!   3. Print result and exit.

#![no_std]
#![no_main]

use core::arch::asm;

const DEBUG_PUTCHAR: usize = 10_000;
const THREAD_EXIT:   usize = 30;
const PROC_SPAWN:    usize = 300;
const PROC_WAIT:     usize = 301;
const OK:            usize = 0;

// Slot in our CSpace where PROC_SPAWN deposits the child's Thread cap.
const CHILD_SLOT: usize = 1;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    print(b"[spawn] spawning 'init'...\n");

    let rc = proc_spawn(b"init", CHILD_SLOT);
    if rc != OK {
        print(b"[spawn] PROC_SPAWN failed rc=");
        print_u(rc);
        print(b"\n");
        exit(1);
    }
    print(b"[spawn] init spawned, waiting...\n");

    let (rc, exit_code) = proc_wait(CHILD_SLOT);
    if rc != OK {
        print(b"[spawn] PROC_WAIT failed rc=");
        print_u(rc);
        print(b"\n");
        exit(1);
    }

    print(b"[spawn] init exited with code ");
    print_u(exit_code);
    print(b"\n");
    print(b"[OK] Phase 17: PROC_SPAWN + PROC_WAIT working\n");
    exit(0);
}

// ── Syscall wrappers ─────────────────────────────────────────────────────────

fn proc_spawn(name: &[u8], dest_slot: usize) -> usize {
    // a0=0, a1=PROC_SPAWN, a2=name_va, a3=name_len, a4=dest_slot → a0=OK
    let rc;
    unsafe {
        asm!("ecall",
            inlateout("a0") 0usize => rc,
            inlateout("a1") PROC_SPAWN => _,
            inlateout("a2") name.as_ptr() as usize => _,
            inlateout("a3") name.len() => _,
            inlateout("a4") dest_slot => _,
            lateout("a5") _, lateout("a6") _, lateout("a7") _,
            options(nostack));
    }
    rc
}

fn proc_wait(thread_slot: usize) -> (usize, usize) {
    // a0=thread_cap_slot, a1=PROC_WAIT → a0=OK, a1=exit_code
    let rc;
    let exit_code;
    unsafe {
        asm!("ecall",
            inlateout("a0") thread_slot => rc,
            inlateout("a1") PROC_WAIT => exit_code,
            lateout("a2") _, lateout("a3") _, lateout("a4") _,
            lateout("a5") _, lateout("a6") _, lateout("a7") _,
            options(nostack));
    }
    (rc, exit_code)
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

// ── Utilities ────────────────────────────────────────────────────────────────

fn putchar(b: u8) {
    unsafe {
        asm!("ecall",
            in("a0") 0usize, in("a1") DEBUG_PUTCHAR, in("a2") b as usize,
            lateout("a0") _, lateout("a1") _, lateout("a2") _,
            lateout("a3") _, lateout("a4") _, lateout("a5") _,
            lateout("a6") _, lateout("a7") _,
            options(nostack));
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
