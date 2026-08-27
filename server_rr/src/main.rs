//! Ferrite OS ReplyRecv server — Phase 10.
//!
//! Handles exactly 3 clients using the ReplyRecv fastpath:
//!   recv()                        ← block for first client
//!   reply_recv(reply) × (N-1)    ← atomically reply + recv next
//!   reply(reply)                  ← deliver last reply, then exit
//!
//! This demonstrates the seL4 server-loop pattern where a server never
//! returns to userspace between handling consecutive requests.

#![no_std]
#![no_main]

use core::arch::asm;

const SLOT_ENDPOINT:        usize = 11;
const ENDPOINT_RECV:        usize = 41;
const ENDPOINT_REPLY:       usize = 43;
const ENDPOINT_REPLY_RECV:  usize = 44;
const DEBUG_PUTCHAR:        usize = 10_000;

const N_CLIENTS: usize = 3;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    // First recv: block until client 1 sends.
    let (_, _, msg, _) = ecall(SLOT_ENDPOINT, ENDPOINT_RECV, 0, 0, 0, 0);
    print(b"[sv] #1 msg=");
    print_num(msg);
    print(b"\n");
    let mut cur_msg = msg;

    // Middle clients: ReplyRecv replies to previous caller and immediately
    // recvs the next.  If a sender is already queued the transfer is
    // instantaneous (no scheduling round-trip).
    let mut i = 2usize;
    while i < N_CLIENTS {
        let (_, _, next_msg, _) = ecall(SLOT_ENDPOINT, ENDPOINT_REPLY_RECV, cur_msg * 2, 0, 0, 0);
        print(b"[sv] #");
        print_num(i);
        print(b" msg=");
        print_num(next_msg);
        print(b"\n");
        cur_msg = next_msg;
        i += 1;
    }

    // Final client (the last reply_recv already received it, or this is a
    // plain reply for N_CLIENTS == 1).
    // Deliver last ReplyRecv's received message then exit.
    let (_, _, last_msg, _) = ecall(SLOT_ENDPOINT, ENDPOINT_REPLY_RECV, cur_msg * 2, 0, 0, 0);
    print(b"[sv] #");
    print_num(N_CLIENTS);
    print(b" msg=");
    print_num(last_msg);
    print(b"\n");

    // Plain reply for the last client.
    ecall(0, ENDPOINT_REPLY, last_msg * 2, 0, 0, 0);

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
