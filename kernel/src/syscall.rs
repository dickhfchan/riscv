/*
 * Syscall dispatcher — Phase 5.
 *
 * `dispatch(&mut TrapFrame)` is called from the trap handler for every ecall.
 * It reads arguments from the frame, performs the operation, and writes results
 * back into the frame (a0-a7).  For blocking IPC calls the frame may be
 * overwritten with a different thread's context before returning.
 *
 * Register convention:
 *   a0 = capability slot index
 *   a1 = invocation label
 *   a2-a7 = message words 0-5
 * Reply written to a0-a7.
 */

use crate::arch::riscv64::trap::TrapFrame;
use crate::cap::{Cap, CapType, Rights, root_cspace};
use crate::cap::{cnode, endpoint::Endpoint, notification::Notification, untyped};

// ── Invocation labels ─────────────────────────────────────────────────────────

pub mod label {
    // UntypedMemory
    pub const UNTYPED_RETYPE:   usize = 1;
    // CNode
    pub const CNODE_COPY:       usize = 10;
    pub const CNODE_MOVE:       usize = 11;
    pub const CNODE_MINT:       usize = 12;
    pub const CNODE_DELETE:     usize = 13;
    pub const CNODE_REVOKE:     usize = 14;
    // Thread (Phase 4)
    pub const THREAD_RESUME:    usize = 20;
    pub const THREAD_SUSPEND:   usize = 21;
    pub const THREAD_CONFIGURE: usize = 22;
    pub const THREAD_EXIT:      usize = 30; // terminate calling thread
    // Endpoint IPC (Phase 5)
    pub const ENDPOINT_SEND:       usize = 40;
    pub const ENDPOINT_RECV:       usize = 41;
    pub const ENDPOINT_CALL:       usize = 42;
    pub const ENDPOINT_REPLY:      usize = 43; // reply to Call; no cap slot needed
    pub const ENDPOINT_REPLY_RECV: usize = 44; // atomic reply + recv (server loop fastpath)
    // Notification (Phase 5)
    pub const NOTIF_SIGNAL:     usize = 50;
    pub const NOTIF_WAIT:       usize = 51;
    // IRQ (Phase 6)
    pub const IRQ_ISSUE_HANDLER: usize = 60; // IRQControl → mint IRQHandler cap
    pub const IRQ_ACK:           usize = 61; // IRQHandler → re-enable in PLIC
    // Frame (Phase 11)
    pub const FRAME_MAP:        usize = 70; // map frame into current thread's VSpace
    // Generic
    pub const CAP_IDENTIFY:     usize = 9;
    pub const DEBUG_PUTCHAR:    usize = 10_000;
    pub const CONSOLE_GETCHAR:  usize = 10_001; // blocking single-char read (Phase 15)
    // Filesystem (Phase 16) — no cap slot required
    pub const FS_OPEN:    usize = 200; // a2=path_va a3=path_len → a1=fd
    pub const FS_CLOSE:   usize = 201; // a2=fd
    pub const FS_READ:    usize = 202; // a2=fd a3=buf_va a4=buf_len → a1=n
    pub const FS_WRITE:   usize = 203; // a2=fd a3=buf_va a4=buf_len → a1=n
    pub const FS_MKDIR:   usize = 204; // a2=path_va a3=path_len
    pub const FS_READDIR: usize = 205; // a2=fd a3=buf_va a4=buf_len → a1=name_len (0=end)
    pub const FS_STAT:    usize = 206; // a2=path_va a3=path_len → a1=kind a2=size
    pub const FS_CREATE:  usize = 208; // a2=path_va a3=path_len → a1=fd (create+open)
    // Process lifecycle (Phase 17) — no cap slot required for SPAWN
    pub const PROC_SPAWN:       usize = 300; // a2=name_va a3=name_len a4=dest_slot → Thread cap at dest_slot
    pub const PROC_WAIT:        usize = 301; // a0=thread_cap_slot → a0=OK a1=exit_code (blocks until child exits)
    // Phase B: Linux-mode spawn from Ferrite-native callers
    pub const PROC_LINUX_SPAWN: usize = 310; // a2=name_va a3=name_len a4=dest_slot → Thread cap (Linux-ABI child)
}

// ── Error codes ───────────────────────────────────────────────────────────────

pub mod error {
    pub const OK:                 usize = 0;
    pub const INVALID_CAPABILITY: usize = 1;
    pub const ILLEGAL_OPERATION:  usize = 2;
    pub const INVALID_ARGUMENT:   usize = 3;
    pub const FAILED_LOOKUP:      usize = 4;
    pub const NOT_ENOUGH_MEMORY:  usize = 5;
}

// ── Main entry ────────────────────────────────────────────────────────────────

/// Dispatch an ecall.  Reads args from `frame`, writes reply into `frame`.
/// For blocking IPC the frame may be replaced by a different thread's context.
pub fn dispatch(frame: &mut TrapFrame) {
    let a0 = frame.a0();
    let a1 = frame.a1();
    let a2 = frame.a2();
    let a3 = frame.a3();
    let a4 = frame.a4();
    let a5 = frame.a5();
    let a6 = frame.a6();

    // ── No-cap operations ─────────────────────────────────────────────────────

    if a1 == label::CONSOLE_GETCHAR {
        crate::console::getchar(frame);
        return;
    }

    // ── Filesystem syscalls (Phase 16) ────────────────────────────────────────
    if a1 >= 200 && a1 <= 208 {
        dispatch_fs(frame, a1, a2, a3, a4, a5);
        return;
    }

    // ── Process spawn (Phase 17) — no cap slot required ───────────────────────
    if a1 == label::PROC_SPAWN {
        dispatch_proc_spawn(frame, a2, a3, a4);
        return;
    }

    // ── Linux-mode spawn (Phase B) ────────────────────────────────────────────
    if a1 == label::PROC_LINUX_SPAWN {
        dispatch_proc_linux_spawn(frame, a2, a3, a4);
        return;
    }

    if a1 == label::THREAD_EXIT {
        crate::sched::exit_current(frame);
        return;
    }

    if a1 == label::ENDPOINT_REPLY {
        let cur_pa = crate::sched::current_pa();
        if cur_pa != 0 {
            let cur   = unsafe { &mut *(cur_pa as *mut crate::thread::Tcb) };
            let rpa   = cur.reply_pa;
            cur.reply_pa = 0;
            if rpa != 0 {
                crate::sched::unblock(rpa, [error::OK, 0, a2, a3, a4, a5, a6, 0]);
            }
        }
        frame.set_reply(err(error::OK));
        return;
    }

    // ── Cap lookup ────────────────────────────────────────────────────────────

    let (root_pa, root_sb) = {
        let cur_pa = crate::sched::current_pa();
        if cur_pa != 0 {
            let tcb = unsafe { &*(cur_pa as *const crate::thread::Tcb) };
            if tcb.cspace_pa != 0 { (tcb.cspace_pa, tcb.cspace_sb) } else { root_cspace() }
        } else {
            root_cspace()
        }
    };
    if root_pa == 0 { frame.set_reply(err(error::FAILED_LOOKUP)); return; }

    let cap = match cnode::lookup(root_pa, root_sb, a0) {
        Ok(c) if !c.is_null() => c,
        _ => { frame.set_reply(err(error::INVALID_CAPABILITY)); return; }
    };

    match (cap.cap_type, a1) {

        // ── Identify ─────────────────────────────────────────────────────────
        (_, label::CAP_IDENTIFY) => {
            frame.set_reply([error::OK, cap.cap_type as usize, cap.ptr, cap.extra,
                             cap.rights.bits() as usize, 0, 0, 0]);
        }

        // ── UntypedMemory::Retype ─────────────────────────────────────────
        (CapType::UntypedMemory, label::UNTYPED_RETYPE) => {
            let cap_type = match CapType::from_u8(a2 as u8) {
                Some(t) => t,
                None    => { frame.set_reply(err(error::INVALID_ARGUMENT)); return; }
            };
            let rc = untyped::retype(&cap, cap_type, a3, root_pa, root_sb, a4, a5.max(1));
            frame.set_reply(err(rc));
        }

        // ── CNode ops ─────────────────────────────────────────────────────────
        (CapType::CNode, label::CNODE_COPY) => {
            let rights = Rights::from_bits_truncate(a4 as u8);
            let rc = match cnode::copy(cap.ptr, cap.extra, a2, a3, rights) {
                Ok(()) => error::OK, Err(_) => error::ILLEGAL_OPERATION,
            };
            frame.set_reply(err(rc));
        }
        (CapType::CNode, label::CNODE_MOVE) => {
            let rc = match cnode::move_cap(cap.ptr, cap.extra, a2, a3) {
                Ok(()) => error::OK, Err(_) => error::ILLEGAL_OPERATION,
            };
            frame.set_reply(err(rc));
        }
        (CapType::CNode, label::CNODE_MINT) => {
            let rights = Rights::from_bits_truncate(a4 as u8);
            let rc = match cnode::mint(cap.ptr, cap.extra, a2, a3, rights) {
                Ok(()) => error::OK, Err(_) => error::ILLEGAL_OPERATION,
            };
            frame.set_reply(err(rc));
        }
        (CapType::CNode, label::CNODE_DELETE) => {
            let rc = match cnode::delete(cap.ptr, cap.extra, a2) {
                Ok(_)  => error::OK, Err(_) => error::ILLEGAL_OPERATION,
            };
            frame.set_reply(err(rc));
        }
        (CapType::CNode, label::CNODE_REVOKE) => {
            let rc = match cnode::revoke(cap.ptr, cap.extra, a2) {
                Ok(()) => error::OK,
                Err(_) => error::ILLEGAL_OPERATION,
            };
            frame.set_reply(err(rc));
        }

        // ── Thread ops ────────────────────────────────────────────────────────
        (CapType::Thread, label::PROC_WAIT) => {
            let child_tcb_pa = cap.ptr;
            let cur_pa = crate::sched::current_pa();
            if cur_pa == 0 { frame.set_reply(err(error::ILLEGAL_OPERATION)); return; }
            let child = unsafe { &mut *(child_tcb_pa as *mut crate::thread::Tcb) };
            if child.state == crate::thread::TcbState::Exited {
                // Child already done — return exit code immediately.
                let mut r = err(error::OK);
                r[1] = child.exit_code;
                frame.set_reply(r);
            } else {
                // Block caller until child exits; exit_current will wake us.
                child.waiter_pa = cur_pa;
                crate::sched::block_current(frame);
                // frame now contains the next thread's context; sret enters it.
            }
        }
        (CapType::Thread, label::THREAD_RESUME) => {
            let tcb = unsafe { &*(cap.ptr as *const crate::thread::Tcb) };
            crate::sched::enqueue(cap.ptr, tcb.priority as usize);
            frame.set_reply(err(error::OK));
        }
        (CapType::Thread, label::THREAD_SUSPEND) => {
            let tcb = unsafe { &mut *(cap.ptr as *mut crate::thread::Tcb) };
            tcb.state = crate::thread::TcbState::Suspended;
            frame.set_reply(err(error::OK));
        }

        // ── Endpoint IPC ──────────────────────────────────────────────────────
        (CapType::Endpoint, label::ENDPOINT_SEND) => {
            let ep  = unsafe { &mut *(cap.ptr as *mut Endpoint) };
            let msg = [a3, a4, a5, a6];
            ep.send(frame, a2, msg, false);
        }
        (CapType::Endpoint, label::ENDPOINT_RECV) => {
            let ep = unsafe { &mut *(cap.ptr as *mut Endpoint) };
            ep.recv(frame);
        }
        (CapType::Endpoint, label::ENDPOINT_CALL) => {
            let ep  = unsafe { &mut *(cap.ptr as *mut Endpoint) };
            let msg = [a3, a4, a5, a6];
            ep.send(frame, a2, msg, true);
        }
        (CapType::Endpoint, label::ENDPOINT_REPLY_RECV) => {
            let ep = unsafe { &mut *(cap.ptr as *mut Endpoint) };
            ep.reply_recv(frame);
        }

        // ── Notification ──────────────────────────────────────────────────────
        (CapType::Notification, label::NOTIF_SIGNAL) => {
            let n = unsafe { &mut *(cap.ptr as *mut Notification) };
            n.signal(a2, frame);
        }
        (CapType::Notification, label::NOTIF_WAIT) => {
            let n = unsafe { &mut *(cap.ptr as *mut Notification) };
            n.wait(frame);
        }

        // ── IRQControl ────────────────────────────────────────────────────────
        (CapType::IRQControl, label::IRQ_ISSUE_HANDLER) => {
            // a2 = irq_num, a3 = dst_slot in root CNode
            let new_cap = Cap::new(CapType::IRQHandler, a2, 0, Rights::ALL);
            let rc = cnode::insert(root_pa, root_sb, a3, new_cap);
            frame.set_reply(err(if rc.is_ok() { error::OK } else { error::ILLEGAL_OPERATION }));
        }

        // ── IRQHandler ────────────────────────────────────────────────────────
        (CapType::IRQHandler, label::IRQ_ACK) => {
            // Re-enable the IRQ in PLIC after the interrupt source has been cleared.
            crate::cap::irq::unmask_irq(cap.ptr); // cap.ptr = irq number
            frame.set_reply(err(error::OK));
        }

        // ── Frame map ─────────────────────────────────────────────────────────
        // a0 = frame slot, a1 = FRAME_MAP, a2 = target VA, a3 = PTE flags (R/W/X)
        (CapType::Frame, label::FRAME_MAP) => {
            let frame_pa  = cap.ptr;
            let va        = a2;
            let pte_flags = (a3 as u64) | crate::arch::riscv64::vspace::PTE_U;
            let cur_pa    = crate::sched::current_pa();
            if cur_pa == 0 { frame.set_reply(err(error::ILLEGAL_OPERATION)); return; }
            let tcb    = unsafe { &*(cur_pa as *const crate::thread::Tcb) };
            let pgd_pa = crate::arch::riscv64::vspace::satp_to_pgd_pa(tcb.satp);
            match crate::arch::riscv64::vspace::map_page(pgd_pa, va, frame_pa, pte_flags) {
                Ok(()) => {
                    crate::arch::riscv64::vspace::flush_tlb_all();
                    frame.set_reply(err(error::OK));
                }
                Err(()) => { frame.set_reply(err(error::ILLEGAL_OPERATION)); }
            }
        }

        // ── Debug putchar ─────────────────────────────────────────────────────
        (_, label::DEBUG_PUTCHAR) => {
            crate::arch::riscv64::uart::putchar(a2 as u8);
            frame.set_reply(err(error::OK));
        }

        _ => { frame.set_reply(err(error::ILLEGAL_OPERATION)); }
    }
}

// ── Filesystem dispatch (Phase 16) ────────────────────────────────────────────

fn dispatch_fs(frame: &mut TrapFrame, label: usize, a2: usize, a3: usize, a4: usize, _a5: usize) {
    use crate::fs::ramfs;
    use crate::arch::riscv64::vspace;

    // Helper: translate a user VA to a kernel-accessible slice reference.
    // Reads up to `len` bytes from user memory starting at `va`.
    // Returns a raw byte slice backed by the physical page.
    // Safety: single-page paths only; we return early if not mapped.
    let cur_tcb_pa = crate::sched::current_pa();
    let pgd_pa = if cur_tcb_pa != 0 {
        let tcb = unsafe { &*(cur_tcb_pa as *const crate::thread::Tcb) };
        vspace::satp_to_pgd_pa(tcb.satp)
    } else {
        vspace::satp_to_pgd_pa(vspace::boot_satp())
    };

    // Translate user VA → kernel PA slice.  Handles at most one page (4096 B).
    let user_slice = |va: usize, len: usize| -> Option<&'static [u8]> {
        let pa = vspace::va_to_pa(pgd_pa, va)?;
        Some(unsafe { core::slice::from_raw_parts(pa as *const u8, len) })
    };
    let user_slice_mut = |va: usize, len: usize| -> Option<&'static mut [u8]> {
        let pa = vspace::va_to_pa(pgd_pa, va)?;
        Some(unsafe { core::slice::from_raw_parts_mut(pa as *mut u8, len) })
    };

    // Get (or lazily allocate) the per-process FdTable.
    let get_fd_table = || -> Option<usize> {
        if cur_tcb_pa == 0 { return None; }
        let tcb = unsafe { &mut *(cur_tcb_pa as *mut crate::thread::Tcb) };
        if tcb.fd_table_pa == 0 {
            tcb.fd_table_pa = ramfs::alloc_fd_table()?;
        }
        Some(tcb.fd_table_pa)
    };

    match label {
        // FS_OPEN: a2=path_va, a3=path_len → a0=OK, a1=fd
        label::FS_OPEN => {
            let path = match user_slice(a2, a3) { Some(p) => p, None => { frame.set_reply(err(error::FAILED_LOOKUP)); return; } };
            let inode_pa = match ramfs::fs_open(path) { Some(p) => p, None => { frame.set_reply(err(error::INVALID_CAPABILITY)); return; } };
            let tbl = match get_fd_table() { Some(t) => t, None => { frame.set_reply(err(error::NOT_ENOUGH_MEMORY)); return; } };
            let fd = match ramfs::fd_alloc(tbl, inode_pa, 0) { Some(f) => f, None => { frame.set_reply(err(error::ILLEGAL_OPERATION)); return; } };
            let mut r = err(error::OK); r[1] = fd; frame.set_reply(r);
        }
        // FS_CLOSE: a2=fd
        label::FS_CLOSE => {
            let tbl = match get_fd_table() { Some(t) => t, None => { frame.set_reply(err(error::OK)); return; } };
            ramfs::fd_close(tbl, a2);
            frame.set_reply(err(error::OK));
        }
        // FS_READ: a2=fd, a3=buf_va, a4=buf_len → a0=OK, a1=n
        label::FS_READ => {
            let tbl = match get_fd_table() { Some(t) => t, None => { frame.set_reply(err(error::INVALID_ARGUMENT)); return; } };
            let fd_entry = match ramfs::fd_get(tbl, a2) { Some(e) => e, None => { frame.set_reply(err(error::INVALID_ARGUMENT)); return; } };
            let buf = match user_slice_mut(a3, a4) { Some(b) => b, None => { frame.set_reply(err(error::FAILED_LOOKUP)); return; } };
            let n = ramfs::fs_read(fd_entry.inode_pa, fd_entry.offset, buf);
            ramfs::fd_advance(tbl, a2, n);
            let mut r = err(error::OK); r[1] = n; frame.set_reply(r);
        }
        // FS_WRITE: a2=fd, a3=buf_va, a4=buf_len → a0=OK, a1=n
        label::FS_WRITE => {
            let tbl = match get_fd_table() { Some(t) => t, None => { frame.set_reply(err(error::INVALID_ARGUMENT)); return; } };
            let fd_entry = match ramfs::fd_get(tbl, a2) { Some(e) => e, None => { frame.set_reply(err(error::INVALID_ARGUMENT)); return; } };
            let buf = match user_slice(a3, a4) { Some(b) => b, None => { frame.set_reply(err(error::FAILED_LOOKUP)); return; } };
            match ramfs::fs_write(fd_entry.inode_pa, fd_entry.offset, buf) {
                Ok(n)  => { ramfs::fd_advance(tbl, a2, n); let mut r = err(error::OK); r[1] = n; frame.set_reply(r); }
                Err(_) => { frame.set_reply(err(error::ILLEGAL_OPERATION)); }
            }
        }
        // FS_MKDIR: a2=path_va, a3=path_len
        label::FS_MKDIR => {
            let path = match user_slice(a2, a3) { Some(p) => p, None => { frame.set_reply(err(error::FAILED_LOOKUP)); return; } };
            match ramfs::fs_mkdir(path) {
                Ok(())  => { frame.set_reply(err(error::OK)); }
                Err(e)  => { frame.set_reply(err(fs_err(e))); }
            }
        }
        // FS_READDIR: a2=fd, a3=buf_va, a4=buf_len → a0=OK, a1=name_len (0=end)
        label::FS_READDIR => {
            let tbl = match get_fd_table() { Some(t) => t, None => { frame.set_reply(err(error::INVALID_ARGUMENT)); return; } };
            let fd_entry = match ramfs::fd_get(tbl, a2) { Some(e) => e, None => { frame.set_reply(err(error::INVALID_ARGUMENT)); return; } };
            let buf = match user_slice_mut(a3, a4) { Some(b) => b, None => { frame.set_reply(err(error::FAILED_LOOKUP)); return; } };
            let n = ramfs::fs_readdir(fd_entry.inode_pa, fd_entry.offset, buf);
            if n > 0 { ramfs::fd_advance(tbl, a2, 1); }
            let mut r = err(error::OK); r[1] = n; frame.set_reply(r);
        }
        // FS_STAT: a2=path_va, a3=path_len → a0=OK, a1=kind, a2=size
        label::FS_STAT => {
            let path = match user_slice(a2, a3) { Some(p) => p, None => { frame.set_reply(err(error::FAILED_LOOKUP)); return; } };
            match ramfs::lookup_path(path) {
                Some(pa) => {
                    let mut r = err(error::OK);
                    r[1] = ramfs::inode_kind(pa) as usize;
                    r[2] = ramfs::inode_size(pa);
                    frame.set_reply(r);
                }
                None => { frame.set_reply(err(error::INVALID_CAPABILITY)); }
            }
        }
        // FS_CREATE: a2=path_va, a3=path_len → a0=OK, a1=fd
        label::FS_CREATE => {
            let path = match user_slice(a2, a3) { Some(p) => p, None => { frame.set_reply(err(error::FAILED_LOOKUP)); return; } };
            let inode_pa = match ramfs::fs_create(path) {
                Ok(pa)  => pa,
                Err(e)  => { frame.set_reply(err(fs_err(e))); return; }
            };
            let tbl = match get_fd_table() { Some(t) => t, None => { frame.set_reply(err(error::NOT_ENOUGH_MEMORY)); return; } };
            let fd = match ramfs::fd_alloc(tbl, inode_pa, 0) { Some(f) => f, None => { frame.set_reply(err(error::ILLEGAL_OPERATION)); return; } };
            let mut r = err(error::OK); r[1] = fd; frame.set_reply(r);
        }
        _ => { frame.set_reply(err(error::ILLEGAL_OPERATION)); }
    }
}

// ── Process spawn dispatch (Phase 17) ────────────────────────────────────────

fn dispatch_proc_spawn(frame: &mut TrapFrame, name_va: usize, name_len: usize, dest_slot: usize) {
    use crate::arch::riscv64::vspace;
    use crate::cap::{Cap, CapType, Rights};

    // Translate user name pointer → kernel slice.
    let cur_tcb_pa = crate::sched::current_pa();
    let pgd_pa = if cur_tcb_pa != 0 {
        let tcb = unsafe { &*(cur_tcb_pa as *const crate::thread::Tcb) };
        vspace::satp_to_pgd_pa(tcb.satp)
    } else {
        vspace::satp_to_pgd_pa(vspace::boot_satp())
    };
    let name_pa = match vspace::va_to_pa(pgd_pa, name_va) {
        Some(pa) => pa,
        None     => { frame.set_reply(err(error::FAILED_LOOKUP)); return; }
    };
    let name = unsafe { core::slice::from_raw_parts(name_pa as *const u8, name_len) };

    // Look up ELF by name.
    let elf_bytes = match crate::proc::find_elf(name) {
        Some(b) => b,
        None    => { frame.set_reply(err(error::INVALID_ARGUMENT)); return; }
    };

    // Create per-process VSpace, map UART (kernel-only), load ELF.
    let child_vspace = match unsafe { vspace::create_elf_vspace() } {
        Some(v) => v,
        None    => { frame.set_reply(err(error::NOT_ENOUGH_MEMORY)); return; }
    };
    if vspace::map_page(child_vspace, 0x1000_0000, 0x1000_0000,
                        vspace::PTE_R | vspace::PTE_W).is_err() {
        frame.set_reply(err(error::NOT_ENOUGH_MEMORY));
        return;
    }
    let entry_va = match crate::elf::load(elf_bytes, child_vspace) {
        Ok(e)  => e,
        Err(_) => { frame.set_reply(err(error::ILLEGAL_OPERATION)); return; }
    };
    let child_satp = vspace::pgd_to_satp(child_vspace);
    let child_tcb_pa = match crate::thread::create_elf_thread(entry_va, child_satp) {
        Some(p) => p,
        None    => { frame.set_reply(err(error::NOT_ENOUGH_MEMORY)); return; }
    };

    // Install Thread cap in caller's CSpace at dest_slot.
    let (caller_cs_pa, caller_cs_sb) = if cur_tcb_pa != 0 {
        let tcb = unsafe { &*(cur_tcb_pa as *const crate::thread::Tcb) };
        if tcb.cspace_pa != 0 { (tcb.cspace_pa, tcb.cspace_sb) } else { crate::cap::root_cspace() }
    } else {
        crate::cap::root_cspace()
    };
    let thread_cap = Cap::new(CapType::Thread, child_tcb_pa, 0, Rights::ALL);
    if cnode::insert(caller_cs_pa, caller_cs_sb, dest_slot, thread_cap).is_err() {
        frame.set_reply(err(error::ILLEGAL_OPERATION));
        return;
    }

    // Enqueue the child — it will run on the next scheduler tick.
    crate::sched::enqueue(child_tcb_pa, 0);

    frame.set_reply(err(error::OK));
}

// ── Linux-mode spawn (Phase B) ────────────────────────────────────────────────
//
// Like PROC_SPAWN but creates a Linux-ABI process (TCB.linux_compat = true).
// The ELF is looked up by name in the proc registry (same as PROC_SPAWN).

fn dispatch_proc_linux_spawn(frame: &mut TrapFrame, name_va: usize, name_len: usize, dest_slot: usize) {
    use crate::arch::riscv64::vspace;
    use crate::cap::{Cap, CapType, Rights};

    let cur_tcb_pa = crate::sched::current_pa();
    let pgd_pa = if cur_tcb_pa != 0 {
        let tcb = unsafe { &*(cur_tcb_pa as *const crate::thread::Tcb) };
        vspace::satp_to_pgd_pa(tcb.satp)
    } else {
        vspace::satp_to_pgd_pa(vspace::boot_satp())
    };
    let name_pa = match vspace::va_to_pa(pgd_pa, name_va) {
        Some(pa) => pa,
        None     => { frame.set_reply(err(error::FAILED_LOOKUP)); return; }
    };
    let name = unsafe { core::slice::from_raw_parts(name_pa as *const u8, name_len) };

    let elf_bytes = match crate::proc::find_elf(name) {
        Some(b) => b,
        None    => { frame.set_reply(err(error::INVALID_ARGUMENT)); return; }
    };

    let args: [&[u8]; 1] = [name];
    let child_tcb_pa = match crate::linux_compat::spawn_linux_process(elf_bytes, &args, cur_tcb_pa) {
        Some(p) => p,
        None    => { frame.set_reply(err(error::NOT_ENOUGH_MEMORY)); return; }
    };

    let (caller_cs_pa, caller_cs_sb) = if cur_tcb_pa != 0 {
        let tcb = unsafe { &*(cur_tcb_pa as *const crate::thread::Tcb) };
        if tcb.cspace_pa != 0 { (tcb.cspace_pa, tcb.cspace_sb) } else { crate::cap::root_cspace() }
    } else {
        crate::cap::root_cspace()
    };
    let thread_cap = Cap::new(CapType::Thread, child_tcb_pa, 0, Rights::ALL);
    if cnode::insert(caller_cs_pa, caller_cs_sb, dest_slot, thread_cap).is_err() {
        frame.set_reply(err(error::ILLEGAL_OPERATION));
        return;
    }

    crate::sched::enqueue(child_tcb_pa, 0);
    frame.set_reply(err(error::OK));
}

fn fs_err(e: crate::fs::ramfs::FsError) -> usize {
    use crate::fs::ramfs::FsError::*;
    match e {
        NotFound | InvalidPath => error::INVALID_CAPABILITY,
        Exists                 => error::ILLEGAL_OPERATION,
        NoMemory               => error::NOT_ENOUGH_MEMORY,
        _                      => error::INVALID_ARGUMENT,
    }
}

#[inline]
fn err(code: usize) -> [usize; 8] {
    let mut r = [0usize; 8];
    r[0] = code;
    r
}
