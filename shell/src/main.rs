//! Ferrite OS interactive shell.
//!
//! Supports: ls [path], cat <file>, write <file> <text>, mkdir <dir>,
//!           cd [path], pwd, stat <path>, rm <file>, mv <src> <dst>,
//!           cp <src> <dst>, help, exit
//!
//! Uses Ferrite FS syscalls (200–208) and CONSOLE_GETCHAR (10_001).
//! Characters are echoed by the kernel console as they are typed;
//! the shell only needs to maintain the line buffer.

#![no_std]
#![no_main]

use core::arch::asm;

const DEBUG_PUTCHAR:    usize = 10_000;
const CONSOLE_GETCHAR:  usize = 10_001;
const FS_OPEN:          usize = 200;
const FS_CLOSE:         usize = 201;
const FS_READ:          usize = 202;
const FS_WRITE:         usize = 203;
const FS_MKDIR:         usize = 204;
const FS_READDIR:       usize = 205;
const FS_STAT:          usize = 206;
const FS_CREATE:        usize = 208;
const FS_UNLINK:        usize = 209;
const FS_RENAME:        usize = 210;
const CNODE_DELETE:     usize = 13;
const PROC_SPAWN:       usize = 300;
const PROC_WAIT:        usize = 301;
const PROC_LINUX_SPAWN: usize = 310;
const CHILD_SLOT:       usize = 1;
const OK:               usize = 0;

#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    let mut cwd = [0u8; 128];
    cwd[0] = b'/';
    let mut cwd_len = 1usize;

    print(b"\r\nFerrite OS shell ready. Type 'help' for commands.\r\n");

    loop {
        // Prompt: "ferrite:/path$ "
        print(b"ferrite:");
        for i in 0..cwd_len { putchar(cwd[i]); }
        print(b"$ ");

        // Read a line; kernel console echoes each char as it arrives.
        // Backspace (127 or 8): the console already emitted \b \b to erase
        // the previous char on screen, so we just shrink the buffer.
        let mut line = [0u8; 128];
        let mut n = 0usize;
        loop {
            let ch = getchar() as u8;
            match ch {
                b'\n' | b'\r' => { print(b"\r\n"); break; }
                127 | 8       => { if n > 0 { n -= 1; } }
                b' '..=b'~'  => { if n < 127 { line[n] = ch; n += 1; } }
                _             => {}
            }
        }
        if n == 0 { continue; }

        // Trim leading spaces
        let mut start = 0;
        while start < n && line[start] == b' ' { start += 1; }
        if start == n { continue; }

        // Split into cmd and arg
        let mut cmd_end = start;
        while cmd_end < n && line[cmd_end] != b' ' { cmd_end += 1; }
        let cmd = &line[start..cmd_end];

        let mut arg_start = cmd_end;
        while arg_start < n && line[arg_start] == b' ' { arg_start += 1; }
        let arg = &line[arg_start..n];

        if cmd == b"ls" {
            do_ls(if arg.is_empty() { &cwd[..cwd_len] } else { arg }, &cwd[..cwd_len]);
        } else if cmd == b"cat" {
            if arg.is_empty() { print(b"usage: cat <file>\r\n"); }
            else { do_cat(arg, &cwd[..cwd_len]); }
        } else if cmd == b"write" {
            do_write(arg, &cwd[..cwd_len]);
        } else if cmd == b"mkdir" {
            if arg.is_empty() { print(b"usage: mkdir <dir>\r\n"); }
            else { do_mkdir(arg, &cwd[..cwd_len]); }
        } else if cmd == b"touch" {
            if arg.is_empty() { print(b"usage: touch <file>\r\n"); }
            else { do_touch(arg, &cwd[..cwd_len]); }
        } else if cmd == b"rm" {
            if arg.is_empty() { print(b"usage: rm <file>\r\n"); }
            else { do_rm(arg, &cwd[..cwd_len]); }
        } else if cmd == b"mv" {
            do_mv_or_cp(arg, &cwd[..cwd_len], false);
        } else if cmd == b"cp" {
            do_mv_or_cp(arg, &cwd[..cwd_len], true);
        } else if cmd == b"cd" {
            do_cd(if arg.is_empty() { b"/" } else { arg }, &mut cwd, &mut cwd_len);
        } else if cmd == b"pwd" {
            for i in 0..cwd_len { putchar(cwd[i]); }
            print(b"\r\n");
        } else if cmd == b"stat" {
            if arg.is_empty() { print(b"usage: stat <path>\r\n"); }
            else { do_stat(arg, &cwd[..cwd_len]); }
        } else if cmd == b"help" {
            print(b"Commands:\r\n");
            print(b"  ls [path]           list directory contents\r\n");
            print(b"  cat <file>          print file to screen\r\n");
            print(b"  write <file> <text> write text to file (creates if needed)\r\n");
            print(b"  mkdir <dir>         create directory\r\n");
            print(b"  touch <file>        create file if it does not exist\r\n");
            print(b"  rm <file>           remove file or empty directory\r\n");
            print(b"  mv <src> <dst>      move/rename a file or directory\r\n");
            print(b"  cp <src> <dst>      copy a file\r\n");
            print(b"  cd [path]           change directory (default /)\r\n");
            print(b"  pwd                 print working directory\r\n");
            print(b"  stat <path>         show type and size\r\n");
            print(b"  run <name>          spawn Ferrite-native process and wait\r\n");
            print(b"  lrun <name>         spawn Linux-ABI process and wait\r\n");
            print(b"  echo [text]         print text to screen\r\n");
            print(b"  help                show this help\r\n");
            print(b"  exit                exit shell\r\n");
            print(b"Programs (run): init, spawn_demo\r\n");
            print(b"Programs (lrun): linux_demo\r\n");
        } else if cmd == b"run" {
            if arg.is_empty() { print(b"usage: run <name>\r\n"); }
            else { do_run(arg, false); }
        } else if cmd == b"lrun" {
            if arg.is_empty() { print(b"usage: lrun <name>\r\n"); }
            else { do_run(arg, true); }
        } else if cmd == b"echo" {
            print_bytes(arg);
            print(b"\r\n");
        } else if cmd == b"exit" {
            print(b"Goodbye!\r\n");
            exit();
        } else {
            print(b"Unknown command: ");
            for i in 0..(cmd_end - start) { putchar(line[start + i]); }
            print(b"\r\n");
        }
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

fn do_ls(path: &[u8], cwd: &[u8]) {
    let mut rpath = [0u8; 128];
    let rlen = resolve(cwd, path, &mut rpath);

    let (rc, fd) = fs_open(&rpath[..rlen]);
    if rc != OK {
        print(b"ls: no such file or directory: ");
        print_bytes(path);
        print(b"\r\n");
        return;
    }

    let mut name = [0u8; 64];
    let mut count = 0usize;
    loop {
        let (_, n) = fs_readdir(fd, &mut name);
        if n == 0 { break; }
        print_bytes(&name[..n]);
        print(b"\r\n");
        count += 1;
    }
    if count == 0 { print(b"(empty)\r\n"); }
    fs_close(fd);
}

fn do_cat(path: &[u8], cwd: &[u8]) {
    let mut rpath = [0u8; 128];
    let rlen = resolve(cwd, path, &mut rpath);

    let (rc, fd) = fs_open(&rpath[..rlen]);
    if rc != OK {
        print(b"cat: ");
        print_bytes(path);
        print(b": no such file\r\n");
        return;
    }

    let mut buf = [0u8; 256];
    loop {
        let (_, n) = fs_read(fd, &mut buf);
        if n == 0 { break; }
        print_bytes(&buf[..n]);
    }
    print(b"\r\n");
    fs_close(fd);
}

fn do_write(args: &[u8], cwd: &[u8]) {
    // Split: first token = file, rest = content
    let mut i = 0;
    while i < args.len() && args[i] != b' ' { i += 1; }
    if i == 0 || i >= args.len() {
        print(b"usage: write <file> <text>\r\n");
        return;
    }
    let file = &args[..i];
    while i < args.len() && args[i] == b' ' { i += 1; }
    let content = &args[i..];

    let mut rpath = [0u8; 128];
    let rlen = resolve(cwd, file, &mut rpath);

    // Open existing or create new
    let fd = {
        let (rc, fd) = fs_open(&rpath[..rlen]);
        if rc == OK { fd } else {
            let (rc2, fd2) = fs_create(&rpath[..rlen]);
            if rc2 != OK { print(b"write: cannot create file\r\n"); return; }
            fd2
        }
    };

    let (wc, bytes) = fs_write(fd, content);
    fs_close(fd);
    if wc == OK {
        print_u(bytes);
        print(b" bytes written\r\n");
    } else {
        print(b"write: failed\r\n");
    }
}

fn do_mkdir(path: &[u8], cwd: &[u8]) {
    let mut rpath = [0u8; 128];
    let rlen = resolve(cwd, path, &mut rpath);

    let rc = fs_mkdir(&rpath[..rlen]);
    if rc == OK {
        print_bytes(&rpath[..rlen]);
        print(b"\r\n");
    } else {
        print(b"mkdir: failed (already exists?)\r\n");
    }
}

fn do_touch(path: &[u8], cwd: &[u8]) {
    let mut rpath = [0u8; 128];
    let rlen = resolve(cwd, path, &mut rpath);
    let (rc, fd) = fs_open(&rpath[..rlen]);
    if rc == OK { fs_close(fd); return; }
    let (rc2, fd2) = fs_create(&rpath[..rlen]);
    if rc2 != OK { print(b"touch: failed\r\n"); return; }
    fs_close(fd2);
}

fn do_rm(path: &[u8], cwd: &[u8]) {
    let mut rpath = [0u8; 128];
    let rlen = resolve(cwd, path, &mut rpath);
    let rc = fs_unlink(&rpath[..rlen]);
    if rc != OK {
        print(b"rm: ");
        print_bytes(path);
        if rc == 2 { print(b": not empty\r\n"); }
        else       { print(b": failed\r\n"); }
    }
}

/// Shared impl for `mv` (copy=false) and `cp` (copy=true).
fn do_mv_or_cp(args: &[u8], cwd: &[u8], copy: bool) {
    // Split into two tokens.
    let mut i = 0;
    while i < args.len() && args[i] != b' ' { i += 1; }
    if i == 0 || i >= args.len() {
        if copy { print(b"usage: cp <src> <dst>\r\n"); }
        else    { print(b"usage: mv <src> <dst>\r\n"); }
        return;
    }
    let src_arg = &args[..i];
    while i < args.len() && args[i] == b' ' { i += 1; }
    let dst_arg = &args[i..];
    if dst_arg.is_empty() {
        if copy { print(b"usage: cp <src> <dst>\r\n"); }
        else    { print(b"usage: mv <src> <dst>\r\n"); }
        return;
    }

    let mut src = [0u8; 128];
    let mut dst = [0u8; 128];
    let slen = resolve(cwd, src_arg, &mut src);
    let dlen = resolve(cwd, dst_arg, &mut dst);

    if copy {
        // Open source, create dest, copy data.
        let (rc, src_fd) = fs_open(&src[..slen]);
        if rc != OK {
            print(b"cp: ");
            print_bytes(src_arg);
            print(b": no such file\r\n");
            return;
        }
        let (rc2, dst_fd) = fs_create(&dst[..dlen]);
        if rc2 != OK {
            print(b"cp: cannot create destination\r\n");
            fs_close(src_fd);
            return;
        }
        let mut buf = [0u8; 256];
        loop {
            let (_, n) = fs_read(src_fd, &mut buf);
            if n == 0 { break; }
            fs_write(dst_fd, &buf[..n]);
        }
        fs_close(src_fd);
        fs_close(dst_fd);
    } else {
        let rc = fs_rename(&src[..slen], &dst[..dlen]);
        if rc != OK {
            print(b"mv: failed\r\n");
        }
    }
}

fn do_cd(path: &[u8], cwd: &mut [u8; 128], cwd_len: &mut usize) {
    let mut rpath = [0u8; 128];
    let rlen = resolve(&cwd[..*cwd_len], path, &mut rpath);

    let (rc, kind, _) = fs_stat(&rpath[..rlen]);
    if rc != OK {
        print(b"cd: no such directory: ");
        print_bytes(path);
        print(b"\r\n");
    } else if kind != 2 {
        print(b"cd: not a directory\r\n");
    } else {
        cwd[..rlen].copy_from_slice(&rpath[..rlen]);
        *cwd_len = rlen;
    }
}

fn do_stat(path: &[u8], cwd: &[u8]) {
    let mut rpath = [0u8; 128];
    let rlen = resolve(cwd, path, &mut rpath);

    let (rc, kind, size) = fs_stat(&rpath[..rlen]);
    if rc != OK {
        print(b"stat: not found: ");
        print_bytes(path);
        print(b"\r\n");
        return;
    }
    print_bytes(&rpath[..rlen]);
    if kind == 2 {
        print(b"  [directory, ");
        print_u(size);
        print(b" entries]\r\n");
    } else {
        print(b"  [file, ");
        print_u(size);
        print(b" bytes]\r\n");
    }
}

fn do_run(name: &[u8], linux: bool) {
    let rc = if linux {
        proc_linux_spawn(name, CHILD_SLOT)
    } else {
        proc_spawn(name, CHILD_SLOT)
    };
    if rc != OK {
        print(b"run: spawn failed (rc=");
        print_u(rc);
        print(b") - is '");
        print_bytes(name);
        print(b"' registered?\r\n");
        return;
    }
    let (rc, exit_code) = proc_wait(CHILD_SLOT);
    cnode_delete(CHILD_SLOT);
    if rc != OK {
        print(b"run: wait failed (rc=");
        print_u(rc);
        print(b")\r\n");
        return;
    }
    print(b"[exited ");
    print_u(exit_code);
    print(b"]\r\n");
}

// ── Path helpers ──────────────────────────────────────────────────────────────

fn resolve(cwd: &[u8], path: &[u8], out: &mut [u8; 128]) -> usize {
    // Build raw absolute path into a temp buffer, then normalize.
    let mut raw = [0u8; 128];
    let raw_len;
    if path.is_empty() {
        let n = cwd.len().min(128);
        raw[..n].copy_from_slice(&cwd[..n]);
        raw_len = n;
    } else if path[0] == b'/' {
        let n = path.len().min(128);
        raw[..n].copy_from_slice(&path[..n]);
        raw_len = n;
    } else if cwd.len() == 1 {
        raw[0] = b'/';
        let n = path.len().min(127);
        raw[1..1 + n].copy_from_slice(&path[..n]);
        raw_len = 1 + n;
    } else {
        let cn = cwd.len().min(126);
        raw[..cn].copy_from_slice(&cwd[..cn]);
        raw[cn] = b'/';
        let n = path.len().min(127 - cn);
        raw[cn + 1..cn + 1 + n].copy_from_slice(&path[..n]);
        raw_len = cn + 1 + n;
    }
    path_normalize(&raw[..raw_len], out)
}

/// Resolve `.` and `..` components in an absolute path, writing the result
/// into `out`.  Returns the length of the normalized path.
fn path_normalize(input: &[u8], out: &mut [u8; 128]) -> usize {
    out[0] = b'/';
    let mut len = 1usize;
    let mut depth = 0usize;
    let mut seg = [0usize; 16]; // seg[i] = value of `len` before segment i

    let src = if !input.is_empty() && input[0] == b'/' { &input[1..] } else { input };
    let mut i = 0;
    while i < src.len() {
        while i < src.len() && src[i] == b'/' { i += 1; }
        let s = i;
        while i < src.len() && src[i] != b'/' { i += 1; }
        let comp = &src[s..i];
        if comp.is_empty() || comp == b"." {
            // skip
        } else if comp == b".." {
            if depth > 0 { depth -= 1; len = seg[depth]; }
        } else if depth < 16 {
            seg[depth] = len;
            depth += 1;
            if len > 1 && len < 128 { out[len] = b'/'; len += 1; }
            let cl = comp.len().min(128 - len);
            out[len..len + cl].copy_from_slice(&comp[..cl]);
            len += cl;
        }
    }
    len
}

// ── Syscall wrappers ──────────────────────────────────────────────────────────

fn proc_spawn(name: &[u8], dest_slot: usize) -> usize {
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

fn proc_linux_spawn(name: &[u8], dest_slot: usize) -> usize {
    let rc;
    unsafe {
        asm!("ecall",
            inlateout("a0") 0usize => rc,
            inlateout("a1") PROC_LINUX_SPAWN => _,
            inlateout("a2") name.as_ptr() as usize => _,
            inlateout("a3") name.len() => _,
            inlateout("a4") dest_slot => _,
            lateout("a5") _, lateout("a6") _, lateout("a7") _,
            options(nostack));
    }
    rc
}

fn proc_wait(thread_slot: usize) -> (usize, usize) {
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

fn cnode_delete(slot: usize) {
    unsafe {
        asm!("ecall",
            in("a0") 0usize,
            in("a1") CNODE_DELETE,
            in("a2") slot,
            lateout("a0") _, lateout("a1") _, lateout("a2") _,
            lateout("a3") _, lateout("a4") _, lateout("a5") _,
            lateout("a6") _, lateout("a7") _,
            options(nostack));
    }
}

fn getchar() -> usize {
    let (_, ch): (usize, usize);
    unsafe {
        asm!("ecall",
            inlateout("a0") 0usize => _,
            inlateout("a1") CONSOLE_GETCHAR => ch,
            lateout("a2") _, lateout("a3") _, lateout("a4") _,
            lateout("a5") _, lateout("a6") _, lateout("a7") _,
            options(nostack));
    }
    ch
}

fn fs_open(path: &[u8]) -> (usize, usize) {
    let (a0, a1, _, _) = e4(0, FS_OPEN, path.as_ptr() as usize, path.len());
    (a0, a1)
}

fn fs_close(fd: usize) { e4(0, FS_CLOSE, fd, 0); }

fn fs_read(fd: usize, buf: &mut [u8]) -> (usize, usize) {
    let (a0, a1, _, _) = e5(0, FS_READ, fd, buf.as_mut_ptr() as usize, buf.len());
    (a0, a1)
}

fn fs_write(fd: usize, data: &[u8]) -> (usize, usize) {
    let (a0, a1, _, _) = e5(0, FS_WRITE, fd, data.as_ptr() as usize, data.len());
    (a0, a1)
}

fn fs_mkdir(path: &[u8]) -> usize {
    let (a0, _, _, _) = e4(0, FS_MKDIR, path.as_ptr() as usize, path.len());
    a0
}

fn fs_readdir(fd: usize, buf: &mut [u8]) -> (usize, usize) {
    let (a0, a1, _, _) = e5(0, FS_READDIR, fd, buf.as_mut_ptr() as usize, buf.len());
    (a0, a1)
}

fn fs_stat(path: &[u8]) -> (usize, usize, usize) {
    let (a0, a1, a2, _) = e4(0, FS_STAT, path.as_ptr() as usize, path.len());
    (a0, a1, a2)
}

fn fs_create(path: &[u8]) -> (usize, usize) {
    let (a0, a1, _, _) = e4(0, FS_CREATE, path.as_ptr() as usize, path.len());
    (a0, a1)
}

fn fs_unlink(path: &[u8]) -> usize {
    let (a0, _, _, _) = e4(0, FS_UNLINK, path.as_ptr() as usize, path.len());
    a0
}

fn fs_rename(old: &[u8], new: &[u8]) -> usize {
    let (a0, _, _, _) = e6(0, FS_RENAME,
        old.as_ptr() as usize, old.len(),
        new.as_ptr() as usize, new.len());
    a0
}

fn e4(a0: usize, a1: usize, a2: usize, a3: usize) -> (usize, usize, usize, usize) {
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

fn e6(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> (usize, usize, usize, usize) {
    let (r0, r1, r2, r3);
    unsafe {
        asm!("ecall",
            inlateout("a0") a0 => r0, inlateout("a1") a1 => r1,
            inlateout("a2") a2 => r2, inlateout("a3") a3 => r3,
            inlateout("a4") a4 => _, inlateout("a5") a5 => _,
            lateout("a6") _, lateout("a7") _,
            options(nostack));
    }
    (r0, r1, r2, r3)
}

fn e5(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> (usize, usize, usize, usize) {
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

// ── I/O helpers ───────────────────────────────────────────────────────────────

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
fn print_bytes(b: &[u8]) { for &c in b { putchar(c); } }

fn print_u(mut v: usize) {
    if v == 0 { putchar(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut n = 0usize;
    while v > 0 { buf[n] = b'0' + (v % 10) as u8; n += 1; v /= 10; }
    for i in (0..n).rev() { putchar(buf[i]); }
}

fn exit() -> ! {
    unsafe { asm!("li a0,0", "li a1,30", "ecall", options(noreturn, nostack, nomem)); }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    print(b"[shell] PANIC\r\n");
    loop { unsafe { asm!("wfi", options(nostack, nomem)); } }
}
