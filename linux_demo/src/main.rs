//! Ferrite OS linux_demo — Phase A3/A4: Linux ABI compatibility self-test.
//!
//! Speaks the Linux RISC-V syscall ABI (number in a7, args in a0-a5) instead
//! of Ferrite capability invocations. The kernel routes ecalls from this
//! process through linux_compat::dispatch.
//!
//! Coverage:
//!   A2: brk, mmap
//!   A3: openat(O_CREAT)/write/close, openat read, lseek, fstat, newfstatat,
//!       getdents64, getcwd, chdir, faccessat, mkdirat
//!   A4: getpid, clone (fork), execve (argv handoff), wait4 (wstatus)
//!
//! On entry: argc==1 → parent test run. argc==2 ("child") → execve'd child:
//! proves the kernel's argv stack setup, then exits with code 42.

#![no_std]
#![no_main]

use core::arch::asm;

// ── Linux RISC-V syscall numbers ──────────────────────────────────────────────
const SYS_GETCWD:      usize = 17;
const SYS_MKDIRAT:     usize = 34;
const SYS_FACCESSAT:   usize = 48;
const SYS_CHDIR:       usize = 49;
const SYS_OPENAT:      usize = 56;
const SYS_CLOSE:       usize = 57;
const SYS_GETDENTS64:  usize = 61;
const SYS_LSEEK:       usize = 62;
const SYS_READ:        usize = 63;
const SYS_WRITE:       usize = 64;
const SYS_NEWFSTATAT:  usize = 79;
const SYS_FSTAT:       usize = 80;
const SYS_EXIT:        usize = 93;
const SYS_UNAME:       usize = 160;
const SYS_GETPID:      usize = 172;
const SYS_BRK:         usize = 214;
const SYS_CLONE:       usize = 220;
const SYS_EXECVE:      usize = 221;
const SYS_MMAP:        usize = 222;
const SYS_WAIT4:       usize = 260;

const AT_FDCWD:  isize  = -100;
const O_CREAT:   usize  = 0o100;
const O_TRUNC:   usize  = 0o1000;
const O_RDWR:    usize  = 0o002;
const O_APPEND:  usize  = 0o2000;
const SEEK_SET:  usize  = 0;
const SEEK_END:  usize  = 2;
const PROT_RW:   usize  = 0x3;        // PROT_READ | PROT_WRITE
const MAP_ANON_PRIV: usize = 0x22;    // MAP_PRIVATE | MAP_ANONYMOUS

static mut CHECKS_FAILED: usize = 0;

// ── Entry point ───────────────────────────────────────────────────────────────
//
// Per the Linux ABI, sp points at: [argc][argv[0]]…[argv[argc-1]][NULL]…

// Pure-asm entry: capture the kernel-provided sp into a0 BEFORE any compiler
// prologue, then tail-call the Rust body with (sp) as its argument. Using a
// naked global_asm stub guarantees the compiler cannot insert a prologue that
// would clobber the incoming stack pointer.
core::arch::global_asm!(
    r#"
    .section .text.entry
    .global _start
    .type _start, @function
_start:
    mv   a0, sp
    j    _start_rust
"#
);

#[no_mangle]
pub unsafe extern "C" fn _start_rust(sp: usize) -> ! {
    let argc = *(sp as *const usize);
    let argv = (sp + 8) as *const usize;

    if argc >= 2 {
        let arg1 = *argv.add(1) as *const u8;
        if arg1.read_volatile() == b'c' {
            // execve'd child: argv made it across → success.
            print(b"[lx] child: execve OK, argv[1]=");
            print_cstr(arg1);
            print(b"\n");
            exit(42);
        }
        print(b"[lx] FAIL: unexpected argv[1]\n");
        exit(43);
    }

    main_tests();
    exit(0);
}

fn main_tests() {
    print(b"[lx] linux_demo: Linux ABI self-test\n");

    // ── A4 basics: getpid, uname ─────────────────────────────────────────────
    let pid = unsafe { syscall0(SYS_GETPID) };
    check(pid > 0, b"getpid");
    print(b"[lx] pid=");
    print_num(pid as usize);
    print(b"\n");

    let mut uts = [0u8; 390];
    let rc = unsafe { syscall1(SYS_UNAME, uts.as_mut_ptr() as usize) };
    check(rc == 0, b"uname");
    print(b"[lx] uname: ");
    print_cstr(uts.as_ptr());           // sysname
    print(b" ");
    print_cstr(unsafe { uts.as_ptr().add(65 * 3) }); // version
    print(b"\n");

    // ── A2: brk / mmap ───────────────────────────────────────────────────────
    let brk0 = unsafe { syscall1(SYS_BRK, 0) };
    check(brk0 > 0, b"brk query");
    let brk1 = unsafe { syscall1(SYS_BRK, (brk0 + 8192) as usize) };
    check(brk1 == brk0 + 8192, b"brk extend");
    unsafe {
        let p = brk0 as *mut u8;
        for i in 0..4096 { p.add(i).write_volatile(0xAB); }
        check(p.add(4095).read_volatile() == 0xAB, b"brk rw");
    }

    let mva = unsafe { syscall6(SYS_MMAP, 0, 4096, PROT_RW, MAP_ANON_PRIV, usize::MAX, 0) };
    check(mva as isize > 0, b"mmap anon");
    unsafe {
        let p = mva as *mut u8;
        p.write_volatile(0x5A);
        check(p.read_volatile() == 0x5A, b"mmap rw");
    }

    // ── A3: file I/O ─────────────────────────────────────────────────────────
    // Create + write (fs_demo from Phase 16 already populated /bin, /etc).
    let fd = unsafe {
        syscall4(SYS_OPENAT, AT_FDCWD as usize, b"/lxtest.txt\0".as_ptr() as usize,
                 O_CREAT | O_RDWR | O_TRUNC, 0o644)
    };
    check(fd as isize >= 0, b"openat O_CREAT");
    let n = unsafe { syscall3(SYS_WRITE, fd as usize, b"hello".as_ptr() as usize, 5) };
    check(n == 5, b"write");
    check(unsafe { syscall1(SYS_CLOSE, fd as usize) } == 0, b"close");

    // O_APPEND via a second fd.
    let fda = unsafe {
        syscall4(SYS_OPENAT, AT_FDCWD as usize, b"/lxtest.txt\0".as_ptr() as usize,
                 O_RDWR | O_APPEND, 0)
    };
    check(fda as isize >= 0, b"openat O_APPEND");
    let n = unsafe { syscall3(SYS_WRITE, fda as usize, b"+++".as_ptr() as usize, 3) };
    check(n == 3, b"write append");
    check(unsafe { syscall1(SYS_CLOSE, fda as usize) } == 0, b"close 2");

    // Read back and verify.
    let fd2 = unsafe {
        syscall4(SYS_OPENAT, AT_FDCWD as usize, b"/lxtest.txt\0".as_ptr() as usize, O_RDWR, 0)
    };
    check(fd2 as isize >= 0, b"openat read");
    let mut buf = [0u8; 16];
    let n = unsafe { syscall3(SYS_READ, fd2 as usize, buf.as_mut_ptr() as usize, 16) };
    check(n == 8, b"read len");
    check(&buf[..8] == b"hello+++", b"read content");

    // lseek SEEK_END → 8; SEEK_SET 0 → overwrite "hello" → "HELLO".
    let end = unsafe { syscall3(SYS_LSEEK, fd2 as usize, 0, SEEK_END) };
    check(end == 8, b"lseek SEEK_END");
    let zero = unsafe { syscall3(SYS_LSEEK, fd2 as usize, 0, SEEK_SET) };
    check(zero == 0, b"lseek SEEK_SET");
    let n = unsafe { syscall3(SYS_WRITE, fd2 as usize, b"HELLO".as_ptr() as usize, 5) };
    check(n == 5, b"write overwrite");
    check(unsafe { syscall1(SYS_CLOSE, fd2 as usize) } == 0, b"close 3");

    // fstat on the open fd / newfstatat on the path.
    let fd3 = unsafe {
        syscall4(SYS_OPENAT, AT_FDCWD as usize, b"/lxtest.txt\0".as_ptr() as usize, O_RDWR, 0)
    };
    let mut stat = [0u8; 128];
    check(unsafe { syscall2(SYS_FSTAT, fd3 as usize, stat.as_mut_ptr() as usize) } == 0,
          b"fstat");
    let st_size = unsafe { *((stat.as_ptr().add(48)) as *const i64) };
    check(st_size == 8, b"fstat size");
    check(unsafe { syscall1(SYS_CLOSE, fd3 as usize) } == 0, b"close 4");

    let mut stat2 = [0u8; 128];
    check(unsafe {
        syscall3(SYS_NEWFSTATAT, AT_FDCWD as usize, b"/lxtest.txt\0".as_ptr() as usize,
                 stat2.as_mut_ptr() as usize)
    } == 0, b"newfstatat");
    let mode = unsafe { *((stat2.as_ptr().add(16)) as *const u32) };
    check(mode & 0o170000 == 0o100000, b"newfstatat S_IFREG");

    // getdents64 on /
    let dfd = unsafe {
        syscall4(SYS_OPENAT, AT_FDCWD as usize, b"/\0".as_ptr() as usize, 0, 0)
    };
    check(dfd as isize >= 3, b"openat /");
    let mut dbuf = [0u8; 1024];
    let n = unsafe { syscall3(SYS_GETDENTS64, dfd as usize, dbuf.as_mut_ptr() as usize, 1024) };
    check(n > 0, b"getdents64");
    print(b"[lx] ls /:");
    let mut off = 0usize;
    while off < n as usize {
        let reclen = unsafe { *((dbuf.as_ptr().add(off + 16)) as *const u16) } as usize;
        let dtype  = unsafe { *(dbuf.as_ptr().add(off + 18)) };
        let name   = unsafe { dbuf.as_ptr().add(off + 19) };
        print(b" ");
        print_cstr(name);
        if dtype == 4 { print(b"/"); }
        if reclen == 0 { break; }
        off += reclen;
    }
    print(b"\n");
    check(unsafe { syscall1(SYS_CLOSE, dfd as usize) } == 0, b"close dir");
    print(b"[lx] step: cwd tests\n");

    // getcwd / chdir / faccessat / mkdirat
    let mut cwd = [0u8; 128];
    let n = unsafe { syscall2(SYS_GETCWD, cwd.as_mut_ptr() as usize, 128) };
    check(n == 2 && cwd[0] == b'/' && cwd[1] == 0, b"getcwd /");
    print(b"[lx] step: chdir /etc\n");
    check(unsafe { syscall1(SYS_CHDIR, b"/etc\0".as_ptr() as usize) } == 0, b"chdir /etc");
    print(b"[lx] step: getcwd /etc\n");
    let n = unsafe { syscall2(SYS_GETCWD, cwd.as_mut_ptr() as usize, 128) };
    check(n == 5 && &cwd[..4] == b"/etc", b"getcwd /etc");
    print(b"[lx] step: openat relative\n");
    // Relative open resolves against the cwd.
    check(unsafe {
        syscall4(SYS_OPENAT, AT_FDCWD as usize, b"rc.conf\0".as_ptr() as usize,
                 O_CREAT | O_RDWR, 0)
    } as isize >= 0, b"openat relative");
    print(b"[lx] step: stat relative\n");
    check(unsafe {
        syscall3(SYS_NEWFSTATAT, AT_FDCWD as usize, b"rc.conf\0".as_ptr() as usize,
                 stat2.as_mut_ptr() as usize)
    } == 0, b"stat relative");
    check(unsafe { syscall1(SYS_CHDIR, b"/\0".as_ptr() as usize) } == 0, b"chdir /");
    print(b"[lx] step: mkdirat\n");
    let mkdirat_rc = unsafe { syscall3(SYS_MKDIRAT, AT_FDCWD as usize, b"/tmp\0".as_ptr() as usize, 0o755) };
    check(mkdirat_rc == 0 || mkdirat_rc == -17 /* EEXIST */, b"mkdirat /tmp");
    print(b"[lx] step: clone\n");
    check(unsafe { syscall2(SYS_FACCESSAT, AT_FDCWD as usize, b"/hello.txt\0".as_ptr() as usize) } == 0,
          b"faccessat exists");
    check(unsafe { syscall2(SYS_FACCESSAT, AT_FDCWD as usize, b"/nope\0".as_ptr() as usize) } == -2,
          b"faccessat ENOENT");

    // ── A4: clone + execve + wait4 ───────────────────────────────────────────
    let child = unsafe { syscall5(SYS_CLONE, 17, 0, 0, 0, 0) }; // SIGCHLD = 17
    print(b"[lx] step: clone returned\n");
    if child == 0 {
        print(b"[lx] child: alive after clone\n");
        // Child: replace this image with linux_demo running the "child" path.
        let argv: [usize; 3] = [
            b"linux_demo\0".as_ptr() as usize,
            b"child\0".as_ptr() as usize,
            0,
        ];
        unsafe {
            syscall3(SYS_EXECVE, b"linux_demo\0".as_ptr() as usize,
                     argv.as_ptr() as usize, 0);
        }
        // execve only returns on failure.
        print(b"[lx] FAIL: execve returned\n");
        exit(44);
    }
    check(child > 0, b"clone");
    print(b"[lx] forked child pid=");
    print_num(child as usize);
    print(b"\n");

    let mut wstatus: i32 = -1;
    let waited = unsafe {
        syscall4(SYS_WAIT4, child as usize, &mut wstatus as *mut i32 as usize, 0, 0)
    };
    check(waited == child, b"wait4 pid");
    check(wstatus == 42 << 8, b"wait4 wstatus");
    print(b"[lx] wait4: pid=");
    print_num(waited as usize);
    print(b" exit_code=");
    print_num((wstatus >> 8) as usize);
    print(b"\n");

    // ── Summary ──────────────────────────────────────────────────────────────
    let failed = unsafe { CHECKS_FAILED };
    if failed == 0 {
        print(b"[lx] ALL PASS\n");
    } else {
        print(b"[lx] FAILURES=");
        print_num(failed);
        print(b"\n");
    }
}

// ── Check helper ──────────────────────────────────────────────────────────────

fn check(ok: bool, name: &[u8]) {
    if !ok {
        unsafe { CHECKS_FAILED += 1; }
        print(b"[lx] FAIL: ");
        print(name);
        print(b"\n");
    }
}

// ── Printing (via Linux write syscall) ────────────────────────────────────────

fn print(s: &[u8]) {
    unsafe { syscall3(SYS_WRITE, 1, s.as_ptr() as usize, s.len()) };
}

fn print_cstr(p: *const u8) {
    let mut len = 0usize;
    unsafe {
        while p.add(len).read_volatile() != 0 { len += 1; }
        syscall3(SYS_WRITE, 1, p as usize, len);
    }
}

fn print_num(mut v: usize) {
    if v == 0 { print(b"0"); return; }
    let mut buf = [0u8; 20];
    let mut n = 0usize;
    while v > 0 { buf[n] = b'0' + (v % 10) as u8; n += 1; v /= 10; }
    for i in (0..n).rev() { print(&buf[i..i + 1]); }
}

// ── Raw Linux ecalls (a7 = number, a0-a5 = args, a0 = return) ─────────────────

unsafe fn syscall0(nr: usize) -> isize {
    let r: isize;
    asm!("ecall", inlateout("a0") 0usize => r, in("a7") nr,
         lateout("a1") _, lateout("a2") _, lateout("a3") _,
         lateout("a4") _, lateout("a5") _, lateout("a6") _,
         options(nostack));
    r
}

unsafe fn syscall1(nr: usize, a0: usize) -> isize {
    let r: isize;
    asm!("ecall", inlateout("a0") a0 => r, in("a7") nr,
         lateout("a1") _, lateout("a2") _, lateout("a3") _,
         lateout("a4") _, lateout("a5") _, lateout("a6") _,
         options(nostack));
    r
}

unsafe fn syscall2(nr: usize, a0: usize, a1: usize) -> isize {
    let r: isize;
    asm!("ecall", inlateout("a0") a0 => r, inlateout("a1") a1 => _, in("a7") nr,
         lateout("a2") _, lateout("a3") _, lateout("a4") _,
         lateout("a5") _, lateout("a6") _,
         options(nostack));
    r
}

unsafe fn syscall3(nr: usize, a0: usize, a1: usize, a2: usize) -> isize {
    let r: isize;
    asm!("ecall", inlateout("a0") a0 => r, inlateout("a1") a1 => _,
         inlateout("a2") a2 => _, in("a7") nr,
         lateout("a3") _, lateout("a4") _, lateout("a5") _, lateout("a6") _,
         options(nostack));
    r
}

unsafe fn syscall4(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let r: isize;
    asm!("ecall", inlateout("a0") a0 => r, inlateout("a1") a1 => _,
         inlateout("a2") a2 => _, inlateout("a3") a3 => _, in("a7") nr,
         lateout("a4") _, lateout("a5") _, lateout("a6") _,
         options(nostack));
    r
}

unsafe fn syscall5(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let r: isize;
    asm!("ecall", inlateout("a0") a0 => r, inlateout("a1") a1 => _,
         inlateout("a2") a2 => _, inlateout("a3") a3 => _, inlateout("a4") a4 => _,
         in("a7") nr, lateout("a5") _, lateout("a6") _,
         options(nostack));
    r
}

unsafe fn syscall6(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize,
                   a4: usize, a5: usize) -> isize {
    let r: isize;
    asm!("ecall", inlateout("a0") a0 => r, inlateout("a1") a1 => _,
         inlateout("a2") a2 => _, inlateout("a3") a3 => _, inlateout("a4") a4 => _,
         inlateout("a5") a5 => _, in("a7") nr, lateout("a6") _,
         options(nostack));
    r
}

fn exit(code: usize) -> ! {
    unsafe {
        asm!("ecall", in("a0") code, in("a7") SYS_EXIT,
             options(noreturn, nostack, nomem));
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    print(b"[lx] PANIC\n");
    exit(101);
}
