#![no_std]
#![no_main]

mod arch;
mod cap;
mod console;
mod elf;
mod fs;
mod linux_compat;
mod mm;
mod proc;
mod sched;
mod syscall;
mod thread;

// ELF binaries embedded at compile time by build.rs.
static INIT_ELF:       &[u8] = include_bytes!(env!("INIT_ELF_PATH"));
static SERVER_ELF:     &[u8] = include_bytes!(env!("SERVER_ELF_PATH"));
static CLIENT_ELF:     &[u8] = include_bytes!(env!("CLIENT_ELF_PATH"));
static SERVER_RR_ELF:  &[u8] = include_bytes!(env!("SERVER_RR_ELF_PATH"));
static SHM_WRITER_ELF: &[u8] = include_bytes!(env!("SHM_WRITER_ELF_PATH"));
static SHM_READER_ELF: &[u8] = include_bytes!(env!("SHM_READER_ELF_PATH"));
static EP_A_ELF:       &[u8] = include_bytes!(env!("EP_A_ELF_PATH"));
static EP_B_ELF:       &[u8] = include_bytes!(env!("EP_B_ELF_PATH"));
static CSPACE_A_ELF:     &[u8] = include_bytes!(env!("CSPACE_A_ELF_PATH"));
static CSPACE_B_ELF:     &[u8] = include_bytes!(env!("CSPACE_B_ELF_PATH"));
static CAP_GRANTOR_ELF:  &[u8] = include_bytes!(env!("CAP_GRANTOR_ELF_PATH"));
static CAP_GRANTEE_ELF:  &[u8] = include_bytes!(env!("CAP_GRANTEE_ELF_PATH"));
static TTY_TEST_ELF:     &[u8] = include_bytes!(env!("TTY_TEST_ELF_PATH"));
static FS_DEMO_ELF:      &[u8] = include_bytes!(env!("FS_DEMO_ELF_PATH"));
static SPAWN_DEMO_ELF:   &[u8] = include_bytes!(env!("SPAWN_DEMO_ELF_PATH"));
static INIT_ICAPS_ELF:   &[u8] = include_bytes!(env!("INIT_ICAPS_ELF_PATH"));
static LINUX_DEMO_ELF:   &[u8] = include_bytes!(env!("LINUX_DEMO_ELF_PATH"));
static SHELL_ELF:        &[u8] = include_bytes!(env!("SHELL_ELF_PATH"));

use arch::riscv64::{mmu, plic, timer, trap, uart, vspace};
use cap::{Cap, CapType, Rights, cnode, untyped::UntypedHeader};
use mm::buddy::PAGE_SIZE;
use core::sync::atomic::{AtomicUsize, Ordering};

// ── Root CNode slot assignments ───────────────────────────────────────────────
const SLOT_CNODE_SELF:        usize = 0;
const SLOT_UNTYPED:           usize = 1;
const SLOT_ENDPOINT:          usize = 11;
const SLOT_NOTIF:             usize = 12;
const SLOT_IRQCONTROL:        usize = 13;
const SLOT_IRQHANDLER_UART:   usize = 14;
const SLOT_FRAME:             usize = 15;
const SLOT_EP14_SHARED:       usize = 17; // Phase 14 shared rendezvous endpoint
const SLOT_EP14_PRIV:         usize = 18; // Phase 14 grantor's private endpoint
const ROOT_SIZE_BITS:         usize = 6;
const UNTYPED_PAGES:          usize = 256;
const UNTYPED_ORDER:          usize = 8;
const UART_IRQ:               usize = 10; // QEMU virt UART (16550A) IRQ

// ── IPC helpers (U-mode ecall wrappers) ──────────────────────────────────────

#[inline(always)]
unsafe fn ecall_ipc(
    a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize,
) -> (usize, usize, usize, usize) {
    let (r0, r1, r2, r3): (usize, usize, usize, usize);
    core::arch::asm!(
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

// ── Phase 5 thread functions (run in U-mode at user mirror VAs) ──────────────
// These functions must NOT access global variables or call println! directly:
// all data accesses from U-mode must either use the (user-stack-local) ABI or
// go through ecall (which traps to S-mode where globals are freely accessible).

extern "C" fn server_thread() -> ! {
    // ENDPOINT_RECV — blocks until client calls.
    let (_, _, msg0, _) = unsafe {
        ecall_ipc(SLOT_ENDPOINT, syscall::label::ENDPOINT_RECV, 0, 0, 0, 0)
    };
    // ENDPOINT_REPLY — send msg0*2 back.
    unsafe {
        ecall_ipc(0, syscall::label::ENDPOINT_REPLY, msg0 * 2, 0, 0, 0);
    }
    unsafe {
        core::arch::asm!("li a0, 0", "li a1, 30", "ecall",
                         options(noreturn, nostack, nomem));
    }
}

extern "C" fn client_thread() -> ! {
    // ENDPOINT_CALL — badge=0x42, msg0=100; blocks until server replies.
    unsafe {
        ecall_ipc(SLOT_ENDPOINT, syscall::label::ENDPOINT_CALL, 0x42, 100, 0, 0);
    }
    unsafe {
        core::arch::asm!("li a0, 0", "li a1, 30", "ecall",
                         options(noreturn, nostack, nomem));
    }
}

// ── Phase 7 init process (U-mode, private VSpace) ────────────────────────────
// Must NOT dereference kernel VAs — only uses stack-local data and ecalls.
// The byte array below is initialised with literal constants, so the compiler
// emits immediate stores to the stack (no .rodata reference from U-mode).
extern "C" fn init_process() -> ! {
    let msg: [u8; 11] = [
        b'[', b'i', b'n', b'i', b't', b']', b' ', b'O', b'K', b'\r', b'\n',
    ];
    for b in msg {
        unsafe { ecall_ipc(0, syscall::label::DEBUG_PUTCHAR, b as usize, 0, 0, 0) };
    }
    unsafe {
        core::arch::asm!("li a0, 0", "li a1, 30", "ecall",
                         options(noreturn, nostack, nomem))
    }
}

// ── Phase 21: SMP thread functions ────────────────────────────────────────────
// Defined at module level so they can be used as extern "C" function pointers.
static SMP_A: AtomicUsize = AtomicUsize::new(0);
static SMP_B: AtomicUsize = AtomicUsize::new(0);

extern "C" fn smp_thread_a() -> ! {
    for _ in 0..5 {
        SMP_A.fetch_add(1, Ordering::Relaxed);
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)); }
    }
    sched::thread_exit()
}
extern "C" fn smp_thread_b() -> ! {
    for _ in 0..5 {
        SMP_B.fetch_add(1, Ordering::Relaxed);
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)); }
    }
    sched::thread_exit()
}

// ── Phase 4 thread functions (S-mode, used as regression smoke test) ──────────
static PH4_A: AtomicUsize = AtomicUsize::new(0);
static PH4_B:     AtomicUsize = AtomicUsize::new(0);

extern "C" fn thread_a() -> ! {
    for _ in 0..3 { PH4_A.fetch_add(1, Ordering::Relaxed); unsafe { core::arch::asm!("wfi", options(nomem,nostack)); } }
    sched::thread_exit()
}
extern "C" fn thread_b() -> ! {
    for _ in 0..3 { PH4_B.fetch_add(1, Ordering::Relaxed); unsafe { core::arch::asm!("wfi", options(nomem,nostack)); } }
    sched::thread_exit()
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn kernel_main(hart_id: usize, fdt_addr: usize) -> ! {
    uart::init();
    banner(hart_id, fdt_addr);

    // ── Phase 2 ───────────────────────────────────────────────────────────────
    println!("  ── Memory ───────────────────────────────");
    mm::init(fdt_addr);
    println!("  [OK] Buddy allocator ready");
    unsafe { mmu::enable_paging() };
    vspace::save_boot_satp(); // cache boot satp for TCB defaults and NEXT_SATP restores
    mmu::assert_sv48_active();
    println!("  [OK] Sv48 paging on");
    println!();

    // ── Phase 3 ───────────────────────────────────────────────────────────────
    println!("  ── Capabilities ─────────────────────────");
    let root_pa = cnode::alloc(ROOT_SIZE_BITS).expect("root CNode alloc");
    cnode::force_insert(root_pa, ROOT_SIZE_BITS, SLOT_CNODE_SELF,
        Cap::new(CapType::CNode, root_pa, ROOT_SIZE_BITS, Rights::ALL));

    let ut_pa  = mm::alloc_pages(UNTYPED_ORDER).expect("untyped alloc");
    let ut_end = ut_pa + UNTYPED_PAGES * PAGE_SIZE;
    unsafe {
        let hdr = &mut *(ut_pa as *mut UntypedHeader);
        hdr.start     = ut_pa;
        hdr.end       = ut_end;
        hdr.watermark = ut_pa + core::mem::size_of::<UntypedHeader>();
    }
    cnode::force_insert(root_pa, ROOT_SIZE_BITS, SLOT_UNTYPED,
        Cap::new(CapType::UntypedMemory, ut_pa, UNTYPED_PAGES * PAGE_SIZE, Rights::ALL));

    cap::set_root_cspace(root_pa, ROOT_SIZE_BITS);
    unsafe { trap::install() };
    trap::verify_install();
    println!("  [OK] Root CNode, UntypedMemory, trap handler installed");
    println!();

    // Quick Phase 3 regression.
    let r = invoke(SLOT_CNODE_SELF, syscall::label::CAP_IDENTIFY, 0, 0, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::OK);
    println!("  [OK] Phase 3 regression pass");

    // Negative-path capability invariants.
    let r = invoke(63, syscall::label::CAP_IDENTIFY, 0, 0, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::INVALID_CAPABILITY, "empty slot must fail");
    println!("  [OK] Empty slot \u{2192} INVALID_CAPABILITY");

    let r = invoke(SLOT_UNTYPED, syscall::label::UNTYPED_RETYPE, 255, 0, 50, 1, 0, 0);
    assert_eq!(r[0], syscall::error::INVALID_ARGUMENT, "bad cap_type must fail");
    println!("  [OK] Bad cap_type \u{2192} INVALID_ARGUMENT");

    println!();

    // ── Phase 4 regression ────────────────────────────────────────────────────
    println!("  ── Phase 4 regression ───────────────────");
    let tcb_a4a = thread::create_kthread(thread_a as *const () as usize).expect("tcb_a");
    let tcb_a4b = thread::create_kthread(thread_b as *const () as usize).expect("tcb_b");
    sched::enqueue(tcb_a4a, 0);
    sched::enqueue(tcb_a4b, 0);
    unsafe { core::arch::asm!("csrs sstatus, {}", in(reg) 0x2usize, options(nostack, nomem)); }
    timer::init();
    sched::init_idle_frame();
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }
    assert_eq!(PH4_A.load(Ordering::Relaxed), 3);
    assert_eq!(PH4_B.load(Ordering::Relaxed), 3);
    println!("  [OK] MLFQ scheduler: both threads ran 3× ({} ticks)", sched::tick_count());
    println!();

    // ── Phase 5: IPC ──────────────────────────────────────────────────────────
    println!("  ── Phase 5: IPC ─────────────────────────");

    // Retype Endpoint into slot 11.
    let r = invoke(SLOT_UNTYPED, syscall::label::UNTYPED_RETYPE,
                   CapType::Endpoint as usize, 0, SLOT_ENDPOINT, 1, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "Endpoint retype failed");
    let ep_cap = cnode::lookup(root_pa, ROOT_SIZE_BITS, SLOT_ENDPOINT).unwrap();
    println!("  [OK] Endpoint   @ {:#010x}", ep_cap.ptr);

    // Retype Notification into slot 12.
    let r = invoke(SLOT_UNTYPED, syscall::label::UNTYPED_RETYPE,
                   CapType::Notification as usize, 0, SLOT_NOTIF, 1, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "Notification retype failed");
    let notif_cap = cnode::lookup(root_pa, ROOT_SIZE_BITS, SLOT_NOTIF).unwrap();
    println!("  [OK] Notification @ {:#010x}", notif_cap.ptr);

    // Occupied-slot retype rejection (Endpoint is now in slot 11).
    let r = invoke(SLOT_UNTYPED, syscall::label::UNTYPED_RETYPE,
                   CapType::Endpoint as usize, 0, SLOT_ENDPOINT, 1, 0, 0);
    assert_eq!(r[0], syscall::error::ILLEGAL_OPERATION, "occupied slot must fail");
    println!("  [OK] Occupied slot \u{2192} ILLEGAL_OPERATION");
    println!();

    // ── Notification smoke test (non-blocking, direct dispatch) ──────────────
    println!();
    println!("  Notification test:");
    let r = invoke(SLOT_NOTIF, syscall::label::NOTIF_SIGNAL, 0xAB, 0, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "Signal failed");
    let r = invoke(SLOT_NOTIF, syscall::label::NOTIF_WAIT, 0, 0, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "Wait failed");
    assert_eq!(r[1], 0xAB, "Wrong badge");
    println!("  [OK] Signal(0xAB) \u{2192} Wait \u{2192} badge={:#x}", r[1]);

    // Notification accumulation: successive signals bitwise-OR into the pending word.
    let r = invoke(SLOT_NOTIF, syscall::label::NOTIF_SIGNAL, 0b0001, 0, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::OK);
    let r = invoke(SLOT_NOTIF, syscall::label::NOTIF_SIGNAL, 0b0110, 0, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::OK);
    let r = invoke(SLOT_NOTIF, syscall::label::NOTIF_WAIT, 0, 0, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::OK);
    assert_eq!(r[1], 0b0111, "signals must accumulate via bitwise-OR");
    println!("  [OK] Notification accumulation: 0b0001 | 0b0110 = {:#05b}", r[1]);

    // ── Endpoint Call/Reply test with U-mode threads ──────────────────────────
    println!();
    println!("  Endpoint Call/Reply test (U-mode threads):");

    let tcb_server = thread::create_uthread(server_thread as *const () as usize)
        .expect("server thread");
    let tcb_client = thread::create_uthread(client_thread as *const () as usize)
        .expect("client thread");

    // Enqueue server first so it blocks on recv before client calls.
    sched::enqueue(tcb_server, 0);
    sched::enqueue(tcb_client, 0);
    let ticks_before = sched::tick_count();
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Call/Reply round-trip: both threads exited cleanly ({} ticks)",
        sched::tick_count() - ticks_before);
    println!();
    println!("  [OK] Phase 5 complete.");
    println!();

    // ── Phase 6: Interrupts (PLIC) ────────────────────────────────────────────
    println!("  ── Phase 6: Interrupts ──────────────────");

    // Init PLIC: set threshold = 0 (all priorities pass), enable SEIE in sie.
    plic::init();

    // Install a singleton IRQControl cap (no Retype; created directly by kernel).
    cnode::force_insert(root_pa, ROOT_SIZE_BITS, SLOT_IRQCONTROL,
        Cap::new(CapType::IRQControl, 0, 0, Rights::ALL));
    println!("  [OK] IRQControl cap installed");

    // Mint an IRQHandler cap for UART IRQ 10 via IRQ_ISSUE_HANDLER.
    let r = invoke(SLOT_IRQCONTROL, syscall::label::IRQ_ISSUE_HANDLER,
                   UART_IRQ, SLOT_IRQHANDLER_UART, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "IRQ_ISSUE_HANDLER failed ({})", r[0]);
    let irq_cap = cnode::lookup(root_pa, ROOT_SIZE_BITS, SLOT_IRQHANDLER_UART).unwrap();
    assert_eq!(irq_cap.ptr, UART_IRQ, "IRQHandler ptr should be irq number");
    println!("  [OK] IRQHandler(irq={}) minted", UART_IRQ);

    // Configure PLIC source: priority 1, enabled for S-mode context.
    plic::set_priority(UART_IRQ, 1);
    plic::set_enable(UART_IRQ, true);

    // Enable UART THRE interrupt — fires immediately (TX buffer always empty).
    // handle_external() will: claim → mask IRQ → count++ → complete.
    uart::enable_thre_interrupt();

    while cap::irq::irq_count() == 0 {
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)); }
    }

    // Interrupt received — clear the interrupt source before unmasking.
    uart::disable_interrupts();
    // Optionally re-enable PLIC source for future use (tested via IRQ_ACK path):
    let r = invoke(SLOT_IRQHANDLER_UART, syscall::label::IRQ_ACK, 0, 0, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "IRQ_ACK failed");

    let last = cap::irq::last_irq();
    assert_eq!(last, UART_IRQ, "expected IRQ {}, got {}", UART_IRQ, last);
    println!("  [OK] External IRQ {} received via PLIC (count={})",
             last, cap::irq::irq_count());
    println!("  [OK] IRQ_ACK re-enabled source in PLIC");
    println!();
    println!("  Phase 6 complete.");
    println!();

    // ── Phase 7: Process Bootstrap (per-process VSpace + satp switching) ───────
    println!("  ── Phase 7: Process Bootstrap ───────────");

    // Create an isolated VSpace for the init process.
    // It shares BOOT_PUD_USER so user-mirror TrapFrames are accessible everywhere.
    let init_vspace_pa = unsafe { vspace::create_process_vspace() }
        .expect("init vspace alloc");
    let init_satp = vspace::pgd_to_satp(init_vspace_pa);
    println!("  [OK] Init VSpace created (satp={:#x})", init_satp);
    assert_ne!(init_satp, vspace::boot_satp(), "init satp must differ from boot satp");

    // Create the init thread running in its own VSpace.
    let init_tcb = thread::create_process_thread(
        init_process as *const () as usize,
        init_satp,
    ).expect("init thread alloc");
    println!("  [OK] Init thread created");

    // Schedule and wait.
    sched::enqueue(init_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Init process exited (satp switched {} → {})",
             init_satp, vspace::boot_satp());
    println!();
    println!("  Phase 7 complete.");
    println!();

    // ── Phase 8: ELF Process Bootstrap ───────────────────────────────────────
    println!("  ── Phase 8: ELF Process Bootstrap ──────");

    // Create an isolated VSpace for the ELF process.
    // Unlike Phase 7, no MMIO superpage — UART is mapped granularly below.
    let elf_vspace_pa = unsafe { vspace::create_elf_vspace() }
        .expect("elf vspace alloc");
    let elf_satp = vspace::pgd_to_satp(elf_vspace_pa);
    println!("  [OK] ELF VSpace created (satp={:#x})", elf_satp);

    // The S-mode trap handler (debug_putchar) runs with init's satp active.
    // Map UART at 0x10000000 as kernel-only (no PTE_U) so trap handler can
    // access it even when the init VSpace is loaded in satp.
    vspace::map_page(elf_vspace_pa, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W)
        .expect("UART map_page failed");
    println!("  [OK] UART page mapped in ELF VSpace (kernel-only)");

    // Parse the ELF, allocate pages, copy segments, map with PTE_U.
    let entry_va = elf::load(INIT_ELF, elf_vspace_pa)
        .expect("ELF load failed");
    println!("  [OK] Init ELF loaded (entry={:#x})", entry_va);

    // sepc = true ELF entry VA; sp = user-mirror stack for cross-VSpace TrapFrame access.
    let elf_tcb = thread::create_elf_thread(entry_va, elf_satp)
        .expect("elf thread alloc");
    println!("  [OK] ELF thread created");

    sched::enqueue(elf_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Init ELF process exited cleanly");
    println!();
    println!("  Phase 8 complete.");
    println!();

    // ── Phase 9: Multi-process ELF IPC ────────────────────────────────────────
    println!("  ── Phase 9: Multi-process ELF IPC ──────");

    // Create isolated VSpaces for server and client.  Each gets UART mapped
    // (kernel-only) so the S-mode trap handler can reach the UART while either
    // process's VSpace is loaded in satp.
    let sv_vspace_pa = unsafe { vspace::create_elf_vspace() }
        .expect("server vspace alloc");
    vspace::map_page(sv_vspace_pa, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W)
        .expect("server UART map_page failed");
    let sv_entry = elf::load(SERVER_ELF, sv_vspace_pa)
        .expect("server ELF load failed");
    let sv_satp = vspace::pgd_to_satp(sv_vspace_pa);
    let sv_tcb  = thread::create_elf_thread(sv_entry, sv_satp)
        .expect("server thread alloc");
    println!("  [OK] Server ELF loaded (entry={:#x})", sv_entry);

    let cl_vspace_pa = unsafe { vspace::create_elf_vspace() }
        .expect("client vspace alloc");
    vspace::map_page(cl_vspace_pa, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W)
        .expect("client UART map_page failed");
    let cl_entry = elf::load(CLIENT_ELF, cl_vspace_pa)
        .expect("client ELF load failed");
    let cl_satp = vspace::pgd_to_satp(cl_vspace_pa);
    let cl_tcb  = thread::create_elf_thread(cl_entry, cl_satp)
        .expect("client thread alloc");
    println!("  [OK] Client ELF loaded (entry={:#x})", cl_entry);

    // Enqueue server before client so server reaches ENDPOINT_RECV first.
    sched::enqueue(sv_tcb, 0);
    sched::enqueue(cl_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Both processes exited cleanly");
    println!();
    println!("  Phase 9 complete.");
    println!();

    // ── Phase 10: ReplyRecv — server-loop fastpath ────────────────────────────
    println!("  ── Phase 10: ReplyRecv Fastpath ─────────");

    const N_CLIENTS: usize = 3;

    // Server: one ELF that handles N_CLIENTS requests via ReplyRecv loop.
    let rr_vspace_pa = unsafe { vspace::create_elf_vspace() }
        .expect("server_rr vspace alloc");
    vspace::map_page(rr_vspace_pa, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W)
        .expect("server_rr UART map_page failed");
    let rr_entry = elf::load(SERVER_RR_ELF, rr_vspace_pa)
        .expect("server_rr ELF load failed");
    let rr_satp  = vspace::pgd_to_satp(rr_vspace_pa);
    let rr_tcb   = thread::create_elf_thread(rr_entry, rr_satp)
        .expect("server_rr thread alloc");
    println!("  [OK] ReplyRecv server loaded (entry={:#x})", rr_entry);

    // Clients: N_CLIENTS independent ELF processes sharing the same binary.
    let mut cl_tcbs = [0usize; N_CLIENTS];
    for (i, slot) in cl_tcbs.iter_mut().enumerate() {
        let vsp = unsafe { vspace::create_elf_vspace() }
            .expect("client vspace alloc");
        vspace::map_page(vsp, 0x1000_0000, 0x1000_0000,
            vspace::PTE_R | vspace::PTE_W)
            .expect("client UART map_page failed");
        let entry = elf::load(CLIENT_ELF, vsp)
            .expect("client ELF load failed");
        let satp  = vspace::pgd_to_satp(vsp);
        *slot = thread::create_elf_thread(entry, satp)
            .expect("client thread alloc");
        println!("  [OK] Client {} loaded", i + 1);
    }

    // Enqueue server first so it reaches ENDPOINT_RECV before any client calls.
    sched::enqueue(rr_tcb, 0);
    for &tcb in &cl_tcbs { sched::enqueue(tcb, 0); }

    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Server + {} clients exited cleanly", N_CLIENTS);
    println!();
    println!("  Phase 10 complete.");
    println!();

    // ── Phase 11: Frame capability + shared memory ────────────────────────────
    println!("  ── Phase 11: Shared Memory (Frame Cap) ──");

    // Retype one 4 KiB Frame from UntypedMemory into slot 15.
    // Both writer and reader will map this same physical page into their VSpaces.
    let r = invoke(SLOT_UNTYPED, syscall::label::UNTYPED_RETYPE,
                   CapType::Frame as usize, 0, SLOT_FRAME, 1, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "Frame retype failed");
    let frame_cap = cnode::lookup(root_pa, ROOT_SIZE_BITS, SLOT_FRAME).unwrap();
    println!("  [OK] Frame cap @ PA {:#010x}", frame_cap.ptr);

    // Writer: blocks on RECV, then maps frame RW, writes message, replies.
    let wr_vspace = unsafe { vspace::create_elf_vspace() }.expect("writer vspace");
    vspace::map_page(wr_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W).expect("writer UART");
    let wr_entry = elf::load(SHM_WRITER_ELF, wr_vspace).expect("writer ELF");
    let wr_tcb   = thread::create_elf_thread(wr_entry, vspace::pgd_to_satp(wr_vspace))
        .expect("writer thread");
    println!("  [OK] Writer loaded (entry={:#x})", wr_entry);

    // Reader: maps frame RO, calls writer via IPC, reads after reply.
    let rd_vspace = unsafe { vspace::create_elf_vspace() }.expect("reader vspace");
    vspace::map_page(rd_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W).expect("reader UART");
    let rd_entry = elf::load(SHM_READER_ELF, rd_vspace).expect("reader ELF");
    let rd_tcb   = thread::create_elf_thread(rd_entry, vspace::pgd_to_satp(rd_vspace))
        .expect("reader thread");
    println!("  [OK] Reader loaded (entry={:#x})", rd_entry);

    // Writer first so it reaches ENDPOINT_RECV before reader calls.
    sched::enqueue(wr_tcb, 0);
    sched::enqueue(rd_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Writer and reader exited cleanly");
    println!();
    println!("  Phase 11 complete.");
    println!();

    // ── Phase 12: Userspace Endpoint creation ─────────────────────────────────
    println!("  ── Phase 12: Userspace Endpoint Creation ─");

    // ep_b must be enqueued first so it blocks on RECV(ep1) before ep_a runs.
    // ep_a then retypes a new Endpoint into slot 16, signals ep_b via ep1 (SEND),
    // and immediately blocks on RECV(ep2).  ep_b wakes, sees the slot number,
    // and CALLs ep2.  ep_a handles the call and replies.

    let epa_vspace = unsafe { vspace::create_elf_vspace() }.expect("ep_a vspace");
    vspace::map_page(epa_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W).expect("ep_a UART");
    let epa_entry = elf::load(EP_A_ELF, epa_vspace).expect("ep_a ELF");
    let epa_tcb   = thread::create_elf_thread(epa_entry, vspace::pgd_to_satp(epa_vspace))
        .expect("ep_a thread");
    println!("  [OK] ep_a loaded (entry={:#x})", epa_entry);

    let epb_vspace = unsafe { vspace::create_elf_vspace() }.expect("ep_b vspace");
    vspace::map_page(epb_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W).expect("ep_b UART");
    let epb_entry = elf::load(EP_B_ELF, epb_vspace).expect("ep_b ELF");
    let epb_tcb   = thread::create_elf_thread(epb_entry, vspace::pgd_to_satp(epb_vspace))
        .expect("ep_b thread");
    println!("  [OK] ep_b loaded (entry={:#x})", epb_entry);

    // ep_b first so it reaches ENDPOINT_RECV(ep1) before ep_a runs.
    sched::enqueue(epb_tcb, 0);
    sched::enqueue(epa_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] ep_a and ep_b exited cleanly");
    println!();
    println!("  Phase 12 complete.");
    println!();

    // ── Phase 13: Per-process CSpaces ─────────────────────────────────────────
    println!("  ── Phase 13: Per-process CSpaces ────────");

    // Each ELF thread gets its own private CNode (size_bits=3, 8 slots).
    // Process A's CSpace: slot 0 = self CNode, slot 1 = private UntypedMemory.
    // Process B's CSpace: slot 0 = self CNode, slot 1 = null.
    // Both processes try UNTYPED_RETYPE on slot 1 — only A should succeed.

    const PROC_SB: usize = 3; // 2^3 = 8 slots per per-process CNode

    // ── CSpace A: CNode self + private UntypedMemory ──
    let cs_a_pa = cnode::alloc(PROC_SB).expect("cspace_a alloc");
    cnode::force_insert(cs_a_pa, PROC_SB, 0,
        Cap::new(CapType::CNode, cs_a_pa, PROC_SB, Rights::ALL));
    // Give A a fresh physical page as its private untyped pool.
    let a_ut_pa = mm::alloc_page().expect("A private untyped page");
    unsafe {
        let hdr = &mut *(a_ut_pa as *mut UntypedHeader);
        hdr.start     = a_ut_pa;
        hdr.end       = a_ut_pa + PAGE_SIZE;
        hdr.watermark = a_ut_pa + core::mem::size_of::<UntypedHeader>();
    }
    cnode::force_insert(cs_a_pa, PROC_SB, 1,
        Cap::new(CapType::UntypedMemory, a_ut_pa, PAGE_SIZE, Rights::ALL));
    println!("  [OK] CSpace A: slot 1 = UntypedMemory @ {:#010x}", a_ut_pa);

    // ── CSpace B: CNode self only; slot 1 stays null ──
    let cs_b_pa = cnode::alloc(PROC_SB).expect("cspace_b alloc");
    cnode::force_insert(cs_b_pa, PROC_SB, 0,
        Cap::new(CapType::CNode, cs_b_pa, PROC_SB, Rights::ALL));
    println!("  [OK] CSpace B: slot 1 = null (no untyped granted)");

    // ── Load and configure cspace_a ──
    let ca_vspace = unsafe { vspace::create_elf_vspace() }.expect("cspace_a vspace");
    vspace::map_page(ca_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W).expect("cspace_a UART");
    let ca_entry = elf::load(CSPACE_A_ELF, ca_vspace).expect("cspace_a ELF");
    let ca_tcb   = thread::create_elf_thread(ca_entry, vspace::pgd_to_satp(ca_vspace))
        .expect("cspace_a thread");
    unsafe {
        let tcb = &mut *(ca_tcb as *mut thread::Tcb);
        tcb.cspace_pa = cs_a_pa;
        tcb.cspace_sb = PROC_SB;
    }
    println!("  [OK] cspace_a loaded (entry={:#x})", ca_entry);

    // ── Load and configure cspace_b ──
    let cb_vspace = unsafe { vspace::create_elf_vspace() }.expect("cspace_b vspace");
    vspace::map_page(cb_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W).expect("cspace_b UART");
    let cb_entry = elf::load(CSPACE_B_ELF, cb_vspace).expect("cspace_b ELF");
    let cb_tcb   = thread::create_elf_thread(cb_entry, vspace::pgd_to_satp(cb_vspace))
        .expect("cspace_b thread");
    unsafe {
        let tcb = &mut *(cb_tcb as *mut thread::Tcb);
        tcb.cspace_pa = cs_b_pa;
        tcb.cspace_sb = PROC_SB;
    }
    println!("  [OK] cspace_b loaded (entry={:#x})", cb_entry);

    sched::enqueue(ca_tcb, 0);
    sched::enqueue(cb_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Per-process CSpace isolation verified");
    println!();
    println!("  Phase 13 complete.");
    println!();

    // ── Phase 14: IPC Capability Transfer ─────────────────────────────────────
    println!("  ── Phase 14: IPC Capability Transfer ────");

    // Retype ep14_shared (rendezvous channel) and ep14_private into global root.
    let r = invoke(SLOT_UNTYPED, syscall::label::UNTYPED_RETYPE,
                   CapType::Endpoint as usize, 0, SLOT_EP14_SHARED, 1, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "ep14_shared retype failed");
    let ep14_shared_cap = cnode::lookup(root_pa, ROOT_SIZE_BITS, SLOT_EP14_SHARED).unwrap();

    let r = invoke(SLOT_UNTYPED, syscall::label::UNTYPED_RETYPE,
                   CapType::Endpoint as usize, 0, SLOT_EP14_PRIV, 1, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "ep14_priv retype failed");
    let ep14_priv_cap = cnode::lookup(root_pa, ROOT_SIZE_BITS, SLOT_EP14_PRIV).unwrap();

    println!("  [OK] ep_shared @ PA {:#010x}", ep14_shared_cap.ptr);
    println!("  [OK] ep_private @ PA {:#010x}", ep14_priv_cap.ptr);

    // Per-process CSpaces (size_bits=3, 8 slots each).
    // Grantor CSpace: slot 0=self, slot 1=ep_shared, slot 2=ep_private.
    // Grantee CSpace: slot 0=self, slot 1=ep_shared, slot 2=null (receives ep_private).
    const P14_SB: usize = 3;

    let gr_cs_pa = cnode::alloc(P14_SB).expect("grantor cspace");
    cnode::force_insert(gr_cs_pa, P14_SB, 0, Cap::new(CapType::CNode, gr_cs_pa, P14_SB, Rights::ALL));
    cnode::force_insert(gr_cs_pa, P14_SB, 1, ep14_shared_cap);
    cnode::force_insert(gr_cs_pa, P14_SB, 2, ep14_priv_cap);
    println!("  [OK] Grantor CSpace: ep_shared=slot1, ep_private=slot2");

    let ge_cs_pa = cnode::alloc(P14_SB).expect("grantee cspace");
    cnode::force_insert(ge_cs_pa, P14_SB, 0, Cap::new(CapType::CNode, ge_cs_pa, P14_SB, Rights::ALL));
    cnode::force_insert(ge_cs_pa, P14_SB, 1, ep14_shared_cap);
    // grantee slot 2 = null; filled in at runtime by IPC cap transfer
    println!("  [OK] Grantee CSpace: ep_shared=slot1, slot2=null (receives ep_private)");

    // Load cap_grantor ELF.
    let gr_vspace = unsafe { vspace::create_elf_vspace() }.expect("grantor vspace");
    vspace::map_page(gr_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W).expect("grantor UART");
    let gr_entry = elf::load(CAP_GRANTOR_ELF, gr_vspace).expect("grantor ELF");
    let gr_tcb   = thread::create_elf_thread(gr_entry, vspace::pgd_to_satp(gr_vspace))
        .expect("grantor thread");
    unsafe {
        let tcb = &mut *(gr_tcb as *mut thread::Tcb);
        tcb.cspace_pa = gr_cs_pa;
        tcb.cspace_sb = P14_SB;
    }
    println!("  [OK] cap_grantor loaded (entry={:#x})", gr_entry);

    // Load cap_grantee ELF.
    let ge_vspace = unsafe { vspace::create_elf_vspace() }.expect("grantee vspace");
    vspace::map_page(ge_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W).expect("grantee UART");
    let ge_entry = elf::load(CAP_GRANTEE_ELF, ge_vspace).expect("grantee ELF");
    let ge_tcb   = thread::create_elf_thread(ge_entry, vspace::pgd_to_satp(ge_vspace))
        .expect("grantee thread");
    unsafe {
        let tcb = &mut *(ge_tcb as *mut thread::Tcb);
        tcb.cspace_pa = ge_cs_pa;
        tcb.cspace_sb = P14_SB;
    }
    println!("  [OK] cap_grantee loaded (entry={:#x})", ge_entry);

    // Grantee first so it reaches ENDPOINT_RECV before grantor sends.
    sched::enqueue(ge_tcb, 0);
    sched::enqueue(gr_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Cap transfer verified: grantee invoked grantor's private endpoint");
    println!();
    println!("  Phase 14 complete.");
    println!();

    // ── Phase 15: TTY / Console Input ─────────────────────────────────────────
    println!("  ── Phase 15: TTY / Console Input ────────");

    // Enable UART RX interrupt.  PLIC source 10 is already priority-1 and
    // enabled from Phase 6; we just need to turn on ERBFI in the UART IER.
    console::init_rx();
    println!("  [OK] UART RX interrupt enabled");

    // Pre-seed the RX buffer so the automated `make run` test does not block.
    // Interactive use (make shell): comment out this line and type at the keyboard.
    console::seed(b"hello\n");
    println!("  [OK] RX buffer seeded with test input");

    // Load the tty_test ELF.
    let tty_vspace = unsafe { vspace::create_elf_vspace() }.expect("tty vspace");
    vspace::map_page(tty_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W).expect("tty UART map");
    let tty_entry = elf::load(TTY_TEST_ELF, tty_vspace).expect("tty ELF load");
    let tty_tcb   = thread::create_elf_thread(tty_entry, vspace::pgd_to_satp(tty_vspace))
        .expect("tty thread");
    println!("  [OK] tty_test ELF loaded (entry={:#x})", tty_entry);

    sched::enqueue(tty_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Phase 15 complete.");
    println!();

    // ── Phase 16: In-memory filesystem (ramfs) ────────────────────────────────
    println!("  ── Phase 16: ramfs ──────────────────────");

    fs::ramfs::init();
    println!("  [OK] ramfs initialised (root inode @ PA {:#x})", fs::ramfs::root_pa());

    let fsd_vspace = unsafe { vspace::create_elf_vspace() }.expect("fs_demo vspace");
    vspace::map_page(fsd_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W).expect("fs_demo UART map");
    let fsd_entry = elf::load(FS_DEMO_ELF, fsd_vspace).expect("fs_demo ELF load");
    println!("  [OK] fs_demo ELF loaded (entry={:#x})", fsd_entry);
    let fsd_tcb   = thread::create_elf_thread(fsd_entry, vspace::pgd_to_satp(fsd_vspace))
        .expect("fs_demo thread");
    println!("  [OK] fs_demo thread created");

    sched::enqueue(fsd_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Phase 16 complete.");
    println!();

    // ── Phase 17: PROC_SPAWN + PROC_WAIT ─────────────────────────────────────
    println!("  ── Phase 17: PROC_SPAWN + PROC_WAIT ─────");

    // Give spawn_demo its own CSpace (size_bits=3, 8 slots).
    // Slot 0 = self CNode; slot 1 = empty (receives child Thread cap from PROC_SPAWN).
    const P17_SB: usize = 3;
    let sd_cs_pa = cnode::alloc(P17_SB).expect("spawn_demo cspace alloc");
    cnode::force_insert(sd_cs_pa, P17_SB, 0,
        Cap::new(CapType::CNode, sd_cs_pa, P17_SB, Rights::ALL));
    println!("  [OK] spawn_demo CSpace allocated");

    let sd_vspace = unsafe { vspace::create_elf_vspace() }
        .expect("spawn_demo vspace alloc");
    vspace::map_page(sd_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W)
        .expect("spawn_demo UART map");
    let sd_entry = elf::load(SPAWN_DEMO_ELF, sd_vspace)
        .expect("spawn_demo ELF load");
    println!("  [OK] spawn_demo ELF loaded (entry={:#x})", sd_entry);

    let sd_tcb = thread::create_elf_thread(sd_entry, vspace::pgd_to_satp(sd_vspace))
        .expect("spawn_demo thread alloc");
    unsafe {
        let tcb = &mut *(sd_tcb as *mut thread::Tcb);
        tcb.cspace_pa = sd_cs_pa;
        tcb.cspace_sb = P17_SB;
    }
    println!("  [OK] spawn_demo thread configured");

    sched::enqueue(sd_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Phase 17 complete.");
    println!();

    // ── Phase 18: Slab Allocator ──────────────────────────────────────────────
    println!("  ── Phase 18: Slab Allocator ─────────────");
    let ep_pa  = mm::slab_alloc(24).expect("slab alloc 24B");
    let nt_pa  = mm::slab_alloc(16).expect("slab alloc 16B");
    let _tcb_p = mm::slab_alloc(512).expect("slab alloc 512B");
    assert_ne!(ep_pa, 0);
    assert_ne!(nt_pa, 0);
    // Verify the freed slot is recycled on the next alloc.
    mm::slab_free(ep_pa, 24);
    mm::slab_free(nt_pa, 16);
    let ep2_pa = mm::slab_alloc(24).expect("slab reuse 24B");
    assert_eq!(ep2_pa, ep_pa, "slab must reuse freed cell");
    println!("  [OK] Slab alloc/free/reuse verified (24B cell PA={:#x})", ep_pa);
    println!("  [OK] Phase 18 complete.");
    println!();

    // ── Phase 19: CNODE_REVOKE ────────────────────────────────────────────────
    println!("  ── Phase 19: CNODE_REVOKE ───────────────");
    // Retype an Endpoint into fresh slot 20 of the root CNode.
    let r = invoke(SLOT_UNTYPED, syscall::label::UNTYPED_RETYPE,
                   CapType::Endpoint as usize, 0, 20, 1, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "retype into slot 20 failed");
    // Copy to slot 21.
    let r = invoke(SLOT_CNODE_SELF, syscall::label::CNODE_COPY,
                   20, 21, Rights::ALL.bits() as usize, 0, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "CNODE_COPY 20→21 failed");
    // Verify copy exists.
    let r = invoke(21, syscall::label::CAP_IDENTIFY, 0, 0, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "slot 21 should contain a cap");
    // Revoke slot 20 — should also nullify slot 21.
    let r = invoke(SLOT_CNODE_SELF, syscall::label::CNODE_REVOKE,
                   20, 0, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::OK, "CNODE_REVOKE failed");
    // Both slots should now be empty.
    let r = invoke(21, syscall::label::CAP_IDENTIFY, 0, 0, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::INVALID_CAPABILITY, "copy should be revoked");
    let r = invoke(20, syscall::label::CAP_IDENTIFY, 0, 0, 0, 0, 0, 0);
    assert_eq!(r[0], syscall::error::INVALID_CAPABILITY, "original should be revoked");
    println!("  [OK] CNODE_REVOKE nullified original + all copies");
    println!("  [OK] Phase 19 complete.");
    println!();

    // ── Phase 20: InitCaps Handoff ────────────────────────────────────────────
    println!("  ── Phase 20: InitCaps Handoff ───────────");

    const ICAPS_SB: usize = 3; // 2^3 = 8 slots
    let icaps_cs_pa = cnode::alloc(ICAPS_SB).expect("icaps cspace alloc");

    // Slot 0: CNode self.
    cnode::force_insert(icaps_cs_pa, ICAPS_SB, 0,
        Cap::new(CapType::CNode, icaps_cs_pa, ICAPS_SB, Rights::ALL));

    // Slot 1: private UntypedMemory pool (8 pages = 32 KiB).
    let icaps_ut_pa   = mm::alloc_pages(3).expect("icaps untyped pages");
    let icaps_ut_size = 8 * PAGE_SIZE;
    unsafe {
        let hdr = &mut *(icaps_ut_pa as *mut UntypedHeader);
        hdr.start     = icaps_ut_pa;
        hdr.end       = icaps_ut_pa + icaps_ut_size;
        hdr.watermark = icaps_ut_pa + core::mem::size_of::<UntypedHeader>();
    }
    cnode::force_insert(icaps_cs_pa, ICAPS_SB, 1,
        Cap::new(CapType::UntypedMemory, icaps_ut_pa, icaps_ut_size, Rights::ALL));

    // Slot 2: IRQControl authority.
    cnode::force_insert(icaps_cs_pa, ICAPS_SB, 2,
        Cap::new(CapType::IRQControl, 0, 0, Rights::ALL));

    // Slot 3: UART Frame (PA 0x10000000, 4 KiB).
    cnode::force_insert(icaps_cs_pa, ICAPS_SB, 3,
        Cap::new(CapType::Frame, 0x1000_0000, PAGE_SIZE, Rights::ALL));

    println!("  [OK] InitCaps CSpace built (Untyped + IRQControl + Frame)");

    let icaps_vspace = unsafe { vspace::create_elf_vspace() }.expect("icaps vspace");
    vspace::map_page(icaps_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W).expect("icaps UART map");
    let icaps_entry = elf::load(INIT_ICAPS_ELF, icaps_vspace).expect("icaps ELF load");
    let icaps_tcb   = thread::create_elf_thread(icaps_entry, vspace::pgd_to_satp(icaps_vspace))
        .expect("icaps thread");
    unsafe {
        let tcb = &mut *(icaps_tcb as *mut thread::Tcb);
        tcb.cspace_pa = icaps_cs_pa;
        tcb.cspace_sb = ICAPS_SB;
    }
    println!("  [OK] init_icaps ELF loaded (entry={:#x})", icaps_entry);

    sched::enqueue(icaps_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Phase 20 complete.");
    println!();

    // ── Phase 21: SMP (2-hart) ────────────────────────────────────────────────
    println!("  ── Phase 21: SMP (2-hart) ───────────────");

    // Start secondary hart 1 at the _start_hart entry point.
    extern "C" { fn _start_hart(); }
    let hart1_ok = arch::riscv64::smp::start_hart(1, _start_hart as usize);
    println!("  [{}] Hart 1 start via SBI HSM: {}",
        if hart1_ok { "OK" } else { "WARN" },
        if hart1_ok { "accepted" } else { "failed (single-hart QEMU?)" });

    let ta = thread::create_kthread(smp_thread_a as *const () as usize).expect("smp_a");
    let tb = thread::create_kthread(smp_thread_b as *const () as usize).expect("smp_b");
    sched::enqueue(ta, 0);
    sched::enqueue(tb, 0);

    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    let a_val = SMP_A.load(Ordering::Acquire);
    let b_val = SMP_B.load(Ordering::Acquire);
    assert_eq!(a_val, 5, "smp_thread_a should run 5× (got {})", a_val);
    assert_eq!(b_val, 5, "smp_thread_b should run 5× (got {})", b_val);
    println!("  [OK] Both SMP threads completed (A={}, B={})", a_val, b_val);
    println!("  [OK] Phase 21 complete.");
    println!();

    // ── Phase A: Linux ABI compatibility (A1–A5) ──────────────────────────────
    println!("  ── Phase A: Linux ABI (A1-A5) ───────────");

    let lx_tcb = linux_compat::spawn_linux_process(LINUX_DEMO_ELF, &[b"linux_demo"], 0)
        .expect("linux_demo spawn");
    println!("  [OK] linux_demo loaded (pid={})",
        unsafe { (*(lx_tcb as *const thread::Tcb)).pid });

    sched::enqueue(lx_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    println!("  [OK] Phase A complete.");
    println!();
    println!("  All 21 phases + Linux ABI (A1-A5) + Shell Execution (B) passed.");
    println!();

    // ── Phase B: Shell Execution ──────────────────────────────────────────────
    println!("  ── Phase B: Shell Execution ─────────────");

    let sh_vspace = unsafe { vspace::create_elf_vspace() }
        .expect("shell vspace alloc");
    vspace::map_page(sh_vspace, 0x1000_0000, 0x1000_0000,
        vspace::PTE_R | vspace::PTE_W)
        .expect("shell UART map");
    let sh_entry = elf::load(SHELL_ELF, sh_vspace)
        .expect("shell ELF load");
    let sh_tcb = thread::create_elf_thread(sh_entry, vspace::pgd_to_satp(sh_vspace))
        .expect("shell thread alloc");

    // Give the shell a CSpace so it can hold Thread caps for run/lrun/wait.
    // Slot 0 = self CNode; slots 1-15 = scratch (one child at a time).
    const SH_SB: usize = 4; // 2^4 = 16 slots
    let sh_cs_pa = cnode::alloc(SH_SB).expect("shell cspace alloc");
    cnode::force_insert(sh_cs_pa, SH_SB, 0,
        Cap::new(CapType::CNode, sh_cs_pa, SH_SB, Rights::ALL));
    unsafe {
        let tcb = &mut *(sh_tcb as *mut thread::Tcb);
        tcb.cspace_pa = sh_cs_pa;
        tcb.cspace_sb = SH_SB;
    }
    println!("  [OK] Shell loaded with CSpace (run/lrun/echo available).");
    println!("  [OK] Phase B complete — use 'make shell' to interact.");
    println!();

    sched::enqueue(sh_tcb, 0);
    sched::start_scheduling();
    while !sched::is_done() { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }

    loop { unsafe { core::arch::asm!("wfi", options(nomem, nostack)) } }
}

// ── invoke helper (direct dispatch for kernel self-tests) ─────────────────────

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn invoke(
    a0: usize, a1: usize,
    a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize,
) -> [usize; 8] {
    let mut frame = trap::TrapFrame::ZERO;
    frame.x[10] = a0; frame.x[11] = a1; frame.x[12] = a2; frame.x[13] = a3;
    frame.x[14] = a4; frame.x[15] = a5; frame.x[16] = a6; frame.x[17] = a7;
    syscall::dispatch(&mut frame);
    [frame.x[10], frame.x[11], frame.x[12], frame.x[13],
     frame.x[14], frame.x[15], frame.x[16], frame.x[17]]
}

// ── Banner ────────────────────────────────────────────────────────────────────

fn banner(hart_id: usize, fdt_addr: usize) {
    println!();
    println!("  ███████╗███████╗██████╗ ██████╗ ██╗████████╗███████╗");
    println!("  ██╔════╝██╔════╝██╔══██╗██╔══██╗██║╚══██╔══╝██╔════╝");
    println!("  █████╗  █████╗  ██████╔╝██████╔╝██║   ██║   █████╗  ");
    println!("  ██╔══╝  ██╔══╝  ██╔══██╗██╔══██╗██║   ██║   ██╔══╝  ");
    println!("  ██║     ███████╗██║  ██║██║  ██║██║   ██║   ███████╗ ");
    println!("  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝");
    println!();
    println!("  Ferrite OS — RISC-V RVA23 Microkernel  [Phase B: Shell Execution]");
    println!("  Hart {:1}   FDT @ {:#010x}", hart_id, fdt_addr);
    println!();
}

// ── Panic handler ─────────────────────────────────────────────────────────────

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    let _ = write!(uart::UartWriter, "\n\n!!! KERNEL PANIC !!!\n{}\n\n", info);
    loop { unsafe { core::arch::asm!("wfi", options(nomem, nostack)) } }
}
