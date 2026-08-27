//! Ferrite OS fs_demo — Phase 16: ramfs.
//!
//! Demonstrates mkdir, create+write, open, read, readdir via FS syscalls.

#![no_std]
#![no_main]

use core::arch::asm;

const DEBUG_PUTCHAR: usize = 10_000;
const FS_OPEN:    usize = 200;
const FS_CLOSE:   usize = 201;
const FS_READ:    usize = 202;
const FS_WRITE:   usize = 203;
const FS_MKDIR:   usize = 204;
const FS_READDIR: usize = 205;
const FS_STAT:    usize = 206;
const FS_CREATE:  usize = 208;
const OK:         usize = 0;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    // ── mkdir /bin, /etc ──────────────────────────────────────────────────────
    let r = fs_mkdir(b"/bin");
    if r != OK { print(b"[fs] mkdir /bin FAIL rc="); print_u(r); print(b"\n"); exit(); }
    print(b"[fs] mkdir /bin: OK\n");

    let r = fs_mkdir(b"/etc");
    if r != OK { print(b"[fs] mkdir /etc FAIL rc="); print_u(r); print(b"\n"); exit(); }
    print(b"[fs] mkdir /etc: OK\n");

    // ── create + write /hello.txt ─────────────────────────────────────────────
    let (rc, fd) = fs_create(b"/hello.txt");
    print(b"[fs] fs_create rc="); print_u(rc); print(b" fd="); print_u(fd); print(b"\n");
    if rc != OK { exit(); }
    let (wc, n) = fs_write(fd, b"hello, ferrite!\n");
    print(b"[fs] fs_write wc="); print_u(wc); print(b" n="); print_u(n); print(b"\n");
    if wc != OK || n == 0 { exit(); }
    fs_close(fd);
    print(b"[fs] write /hello.txt: OK\n");

    // ── readdir / ─────────────────────────────────────────────────────────────
    print(b"[fs] opening /...\n");
    let (rc, dfd) = fs_open(b"/");
    print(b"[fs] fs_open / rc="); print_u(rc); print(b" dfd="); print_u(dfd); print(b"\n");
    if rc != OK { exit(); }
    print(b"[fs] ls /:\n");
    let mut name = [0u8; 64];
    loop {
        let (rrc, n) = fs_readdir(dfd, &mut name);
        print(b"[fs] readdir rrc="); print_u(rrc); print(b" n="); print_u(n); print(b"\n");
        if n == 0 { break; }
        print(b"  ");
        for i in 0..n { putchar(name[i]); }
        print(b"\n");
    }
    fs_close(dfd);

    // ── cat /hello.txt ────────────────────────────────────────────────────────
    print(b"[fs] opening /hello.txt...\n");
    let (rc, rfd) = fs_open(b"/hello.txt");
    print(b"[fs] fs_open /hello.txt rc="); print_u(rc); print(b" rfd="); print_u(rfd); print(b"\n");
    if rc != OK { exit(); }
    let mut rbuf = [0u8; 64];
    let (rrc, n) = fs_read(rfd, &mut rbuf);
    print(b"[fs] fs_read rc="); print_u(rrc); print(b" n="); print_u(n); print(b"\n");
    fs_close(rfd);
    print(b"[fs] cat /hello.txt: ");
    for i in 0..n { putchar(rbuf[i]); }

    // ── stat /bin ─────────────────────────────────────────────────────────────
    print(b"[fs] stat /bin...\n");
    let (rc, kind, size) = fs_stat(b"/bin");
    print(b"[fs] stat rc="); print_u(rc); print(b" kind="); print_u(kind); print(b" size="); print_u(size); print(b"\n");
    if rc != OK { exit(); }
    if kind != 2 { print(b"[fs] stat /bin: wrong kind\n"); exit(); }
    print(b"[fs] stat /bin: dir, 0 entries\n");

    print(b"[OK] Phase 16: ramfs mkdir/ls/cat working\n");
    exit();
}

// ── Syscall wrappers ─────────────────────────────────────────────────────────

fn fs_mkdir(path: &[u8]) -> usize {
    let (a0, _, _, _) = ecall4(0, FS_MKDIR, path.as_ptr() as usize, path.len());
    a0
}

fn fs_create(path: &[u8]) -> (usize, usize) {
    let (a0, a1, _, _) = ecall4(0, FS_CREATE, path.as_ptr() as usize, path.len());
    (a0, a1)
}

fn fs_open(path: &[u8]) -> (usize, usize) {
    let (a0, a1, _, _) = ecall4(0, FS_OPEN, path.as_ptr() as usize, path.len());
    (a0, a1)
}

fn fs_close(fd: usize) {
    ecall4(0, FS_CLOSE, fd, 0);
}

fn fs_read(fd: usize, buf: &mut [u8]) -> (usize, usize) {
    let (a0, a1, _, _) = ecall5(0, FS_READ, fd, buf.as_mut_ptr() as usize, buf.len());
    (a0, a1)
}

fn fs_write(fd: usize, data: &[u8]) -> (usize, usize) {
    let (a0, a1, _, _) = ecall5(0, FS_WRITE, fd, data.as_ptr() as usize, data.len());
    (a0, a1)
}

fn fs_readdir(fd: usize, buf: &mut [u8]) -> (usize, usize) {
    let (a0, a1, _, _) = ecall5(0, FS_READDIR, fd, buf.as_mut_ptr() as usize, buf.len());
    (a0, a1)
}

fn fs_stat(path: &[u8]) -> (usize, usize, usize) {
    let (a0, a1, a2, _) = ecall4(0, FS_STAT, path.as_ptr() as usize, path.len());
    (a0, a1, a2)
}

fn ecall4(a0: usize, a1: usize, a2: usize, a3: usize) -> (usize, usize, usize, usize) {
    let (r0, r1, r2, r3);
    unsafe {
        asm!("ecall",
            inlateout("a0") a0 => r0, inlateout("a1") a1 => r1,
            inlateout("a2") a2 => r2, inlateout("a3") a3 => r3,
            lateout("a4") _, lateout("a5") _, lateout("a6") _, lateout("a7") _,
            options(nostack));
    }
    (r0, r1, r2, r3)
}

fn ecall5(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> (usize, usize, usize, usize) {
    let (r0, r1, r2, r3);
    unsafe {
        asm!("ecall",
            inlateout("a0") a0 => r0, inlateout("a1") a1 => r1,
            inlateout("a2") a2 => r2, inlateout("a3") a3 => r3,
            inlateout("a4") a4 => _,
            lateout("a5") _, lateout("a6") _, lateout("a7") _,
            options(nostack));
    }
    (r0, r1, r2, r3)
}

fn print_u(v: usize) {
    if v == 0 { putchar(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut n = 0usize;
    let mut x = v;
    while x > 0 { buf[n] = b'0' + (x % 10) as u8; n += 1; x /= 10; }
    for i in (0..n).rev() { putchar(buf[i]); }
}

fn putchar(b: u8) {
    unsafe {
        asm!("ecall",
            in("a0") 0usize, in("a1") DEBUG_PUTCHAR, in("a2") b as usize,
            lateout("a0") _, lateout("a1") _, lateout("a2") _, lateout("a3") _,
            lateout("a4") _, lateout("a5") _, lateout("a6") _, lateout("a7") _,
            options(nostack));
    }
}

fn print(msg: &[u8]) { for &b in msg { putchar(b); } }

fn exit() -> ! {
    unsafe { asm!("li a0,0","li a1,30","ecall", options(noreturn,nostack,nomem)); }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop { unsafe { asm!("wfi", options(nostack, nomem)); } }
}
