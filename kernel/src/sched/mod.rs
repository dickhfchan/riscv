// MLFQ (Multi-Level Feedback Queue) scheduler — Phase 4 / Phase 21 SMP.
//
// Single shared run-queue (protected by QUEUE_LOCK) across all harts.
// Per-hart state: CURRENT[hart], NEXT_SATP[hart], BOOT_FRAME[hart],
// BOOT_FRAME_VALID[hart].
//
// Hart 0 signals scheduling completion (SCHEDULING_ACTIVE → false) once
// LIVE_THREADS reaches 0 and the boot frame for hart 0 is available.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::arch::riscv64::{timer, trap::TrapFrame};
use crate::thread::{Tcb, TcbState, MLFQ_LEVELS, ticks_for_level};

const MAX_HARTS: usize = 4;

// ── Per-hart statics ──────────────────────────────────────────────────────────

/// PA of the currently running TCB on each hart (0 = idle / boot frame).
static CURRENT: [AtomicUsize; MAX_HARTS] = [
    AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0),
];

/// Next satp value for each hart.  Written here, read by trap.S (indexed by
/// sscratch = hart_id) before sret to switch page-table roots without sscratch
/// tricks.  0 = no switch.
#[no_mangle]
static NEXT_SATP: [AtomicUsize; MAX_HARTS] = [
    AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0),
];

struct SyncFrame(UnsafeCell<TrapFrame>);
unsafe impl Sync for SyncFrame {}

/// Saved frame from the first timer interrupt while the hart is idle.
/// Restored when the hart's run-queue is empty so sret returns to the boot WFI.
static BOOT_FRAME: [SyncFrame; MAX_HARTS] = [
    SyncFrame(UnsafeCell::new(TrapFrame::ZERO)),
    SyncFrame(UnsafeCell::new(TrapFrame::ZERO)),
    SyncFrame(UnsafeCell::new(TrapFrame::ZERO)),
    SyncFrame(UnsafeCell::new(TrapFrame::ZERO)),
];
static BOOT_FRAME_VALID: [AtomicBool; MAX_HARTS] = [
    AtomicBool::new(false), AtomicBool::new(false),
    AtomicBool::new(false), AtomicBool::new(false),
];

/// Permanent idle frame: sepc = _kernel_idle, sstatus = SPP=1/SPIE=1.
/// Used as fallback when BOOT_FRAME is not yet valid, to prevent trap.S from
/// sret-ing back into user-mode with a user VSpace still in NEXT_SATP.
static IDLE_FRAME: SyncFrame = SyncFrame(UnsafeCell::new(TrapFrame::ZERO));
static IDLE_FRAME_READY: AtomicBool = AtomicBool::new(false);

// ── Shared run-queue ──────────────────────────────────────────────────────────

/// MLFQ run-queue heads and tails (PA; 0 = empty).
static QUEUE_HEAD: [AtomicUsize; MLFQ_LEVELS] = [
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
];
static QUEUE_TAIL: [AtomicUsize; MLFQ_LEVELS] = [
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
];

/// Spinlock protecting the MLFQ queue for multi-hart access.
struct SpinLock(AtomicBool);
impl SpinLock {
    const fn new() -> Self { Self(AtomicBool::new(false)) }
    fn lock(&self) {
        while self.0.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
    }
    fn unlock(&self) { self.0.store(false, Ordering::Release); }
}
static QUEUE_LOCK: SpinLock = SpinLock::new();

// ── Global counters ───────────────────────────────────────────────────────────

static TICK_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Threads currently alive (Runnable + Running + Blocked; not Exited/Suspended).
/// is_done() only fires on hart 0 when this reaches 0.
static LIVE_THREADS: AtomicUsize = AtomicUsize::new(0);

/// I/O waiters: threads blocked on external I/O (console, device).
static IO_WAITERS: AtomicUsize = AtomicUsize::new(0);

/// True while the scheduler should context-switch on timer interrupts.
static SCHEDULING_ACTIVE: AtomicBool = AtomicBool::new(false);

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read the current hart ID from sscratch (set in boot.S / _start_hart).
fn current_hart() -> usize {
    let h: usize;
    unsafe { core::arch::asm!("csrr {}, sscratch", out(reg) h, options(nomem, nostack)); }
    h
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn tick_count() -> usize { TICK_COUNT.load(Ordering::Relaxed) }
pub fn current_pa() -> usize { CURRENT[current_hart()].load(Ordering::Relaxed) }
pub fn add_io_waiter()    { IO_WAITERS.fetch_add(1, Ordering::Relaxed); }
pub fn remove_io_waiter() { IO_WAITERS.fetch_sub(1, Ordering::Relaxed); }

/// Schedule a satp switch for the current hart on the next sret (Phase A4
/// execve: the running thread replaces its own address space).
pub fn set_current_satp(satp: usize) {
    NEXT_SATP[current_hart()].store(satp, Ordering::Relaxed);
}

/// Wake a blocked thread, writing `reply` into its saved frame, enqueue at priority 0.
pub fn unblock(tcb_pa: usize, reply: [usize; 8]) {
    let tcb = unsafe { &mut *(tcb_pa as *mut Tcb) };
    tcb.frame.set_reply(reply);
    wake(tcb_pa);
}

/// Wake a blocked thread from an IRQ handler, switching the trap frame immediately.
pub fn wake_from_irq(tcb_pa: usize, reply: [usize; 8], frame: &mut TrapFrame) {
    let hart = current_hart();
    let tcb = unsafe { &mut *(tcb_pa as *mut Tcb) };
    tcb.frame.set_reply(reply);
    tcb.state     = TcbState::Running;
    tcb.priority  = 0;
    tcb.ticks_rem = ticks_for_level(0);
    tcb.next_pa   = 0;
    CURRENT[hart].store(tcb_pa, Ordering::Relaxed);
    NEXT_SATP[hart].store(tcb.satp, Ordering::Relaxed);
    *frame = tcb.frame;
    check_frame_sp("wake_from_irq", frame);
}

/// Re-enqueue a thread (reply already written to its frame).
pub fn wake(tcb_pa: usize) {
    let tcb = unsafe { &mut *(tcb_pa as *mut Tcb) };
    tcb.state     = TcbState::Runnable;
    tcb.priority  = 0;
    tcb.ticks_rem = ticks_for_level(0);
    tcb.next_pa   = 0;
    link(tcb_pa, 0);
}

/// Save current thread's frame (marking it Blocked), switch to the next thread.
/// Returns the blocked thread's PA.  Caller must add it to an IPC wait queue.
pub fn block_current(frame: &mut TrapFrame) -> usize {
    block_with_state(frame, TcbState::Blocked)
}

/// Mark current thread Exited and switch to next.
/// Wakes any PROC_WAIT waiter before switching.
pub fn exit_current(frame: &mut TrapFrame) {
    let hart = current_hart();
    let cur_pa = CURRENT[hart].load(Ordering::Relaxed);
    if cur_pa == 0 { return; }

    let cur = unsafe { &mut *(cur_pa as *mut Tcb) };
    cur.frame     = *frame;
    cur.state     = TcbState::Exited;
    cur.exit_code = frame.a2();
    LIVE_THREADS.fetch_sub(1, Ordering::AcqRel);

    // Wake any waiter BEFORE switch_to_next so it lands in the run queue first.
    let waiter_pa = cur.waiter_pa;
    if waiter_pa != 0 {
        cur.waiter_pa = 0;
        let waiter = unsafe { &*(waiter_pa as *const Tcb) };
        if waiter.linux_compat {
            // Linux wait4: a0 = child pid, *wstatus = exit_code << 8.
            // The wstatus user pointer is the waiter's saved a1; translate it
            // through the WAITER's page table (we run under the child's satp).
            let wstatus_va = waiter.frame.x[11];
            if wstatus_va != 0 {
                let waiter_pgd = crate::arch::riscv64::vspace::satp_to_pgd_pa(waiter.satp);
                if let Some(pa) = crate::arch::riscv64::vspace::va_to_pa(waiter_pgd, wstatus_va) {
                    unsafe { *(pa as *mut i32) = (cur.exit_code as i32) << 8; }
                }
            }
            unblock(waiter_pa, [cur.pid, 0, 0, 0, 0, 0, 0, 0]);
        } else {
            unblock(waiter_pa, [0, cur.exit_code, 0, 0, 0, 0, 0, 0]);
        }
    }

    CURRENT[hart].store(0, Ordering::Relaxed);
    switch_to_next(frame);
}

fn block_with_state(frame: &mut TrapFrame, state: TcbState) -> usize {
    let hart = current_hart();
    let cur_pa = CURRENT[hart].load(Ordering::Relaxed);
    if cur_pa == 0 { return 0; }

    let cur = unsafe { &mut *(cur_pa as *mut Tcb) };
    cur.frame = *frame;
    cur.state = state;
    CURRENT[hart].store(0, Ordering::Relaxed);
    switch_to_next(frame);
    cur_pa
}

fn check_frame_sp(label: &str, f: &TrapFrame) {
    let sp = f.x[2];
    // Kernel boot stack: [0x80800000, 0x80CB2000)
    // User-mirror: VA = PA + 0x8000000000; PA in [0x80000000, 0xBFFFFFFF]
    //   → VA in [0x8080000000, 0x80C0000000)
    const USER_MIRROR_BASE: usize = 0x80_8000_0000;  // = 0x8080000000
    const USER_MIRROR_TOP:  usize = 0x80_C000_0000;  // = 0x80C0000000
    const KSTACK_BASE: usize = 0x8080_0000;
    const KSTACK_TOP:  usize = 0x80CB_2000;
    let kernel_stack_ok = sp >= KSTACK_BASE && sp <= KSTACK_TOP;
    let user_mirror_ok  = sp >= USER_MIRROR_BASE && sp < USER_MIRROR_TOP;
    let zero_ok = sp == 0;
    if !kernel_stack_ok && !user_mirror_ok && !zero_ok {
        crate::println!("  [SCHED] {} bad frame.x[2]={:#018x} sepc={:#018x}",
            label, sp, f.sepc);
    }
}

fn switch_to_next(frame: &mut TrapFrame) {
    let hart = current_hart();
    let next_pa = dequeue_locked();
    if next_pa != 0 {
        let next = unsafe { &mut *(next_pa as *mut Tcb) };
        next.state = TcbState::Running;
        CURRENT[hart].store(next_pa, Ordering::Relaxed);
        NEXT_SATP[hart].store(next.satp, Ordering::Relaxed);
        *frame = next.frame;
        check_frame_sp("switch_to_next(thread)", frame);
    } else if BOOT_FRAME_VALID[hart].load(Ordering::Relaxed) {
        unsafe { *frame = *BOOT_FRAME[hart].0.get(); }
        NEXT_SATP[hart].store(crate::arch::riscv64::vspace::boot_satp(), Ordering::Relaxed);
        BOOT_FRAME_VALID[hart].store(false, Ordering::Relaxed);
        check_frame_sp("switch_to_next(boot)", frame);
        // Only hart 0 signals scheduling completion.
        if hart == 0 && IO_WAITERS.load(Ordering::Relaxed) == 0
           && LIVE_THREADS.load(Ordering::Acquire) == 0 {
            SCHEDULING_ACTIVE.store(false, Ordering::Relaxed);
        }
    } else if IDLE_FRAME_READY.load(Ordering::Relaxed) {
        // BOOT_FRAME not yet valid (consumed when first scheduling a thread,
        // not yet regenerated by a timer).  Use the permanent idle frame so
        // trap.S srets to S-mode _kernel_idle WFI instead of leaving NEXT_SATP
        // pointing at the user VSpace — which would cause ghost user-mode
        // execution followed by an instruction page fault when the timer fires.
        unsafe { *frame = *IDLE_FRAME.0.get(); }
        NEXT_SATP[hart].store(crate::arch::riscv64::vspace::boot_satp(), Ordering::Relaxed);
        check_frame_sp("switch_to_next(idle)", frame);
        if hart == 0 && IO_WAITERS.load(Ordering::Relaxed) == 0
           && LIVE_THREADS.load(Ordering::Acquire) == 0 {
            SCHEDULING_ACTIVE.store(false, Ordering::Relaxed);
        }
    }
    // else: init_idle_frame not yet called — frame unchanged (pre-scheduler init).
}

/// Enable the scheduler.  Must be called before enqueueing threads.
pub fn start_scheduling() {
    SCHEDULING_ACTIVE.store(true, Ordering::Relaxed);
}

/// Pre-populate the permanent idle frame.  Call once after paging is enabled,
/// before start_scheduling().  The idle frame has sepc = _kernel_idle (a known
/// S-mode WFI loop in boot.S) and sstatus with SPP=1/SPIE=1 so that sret
/// returns to S-mode with interrupts enabled rather than back to user space.
pub fn init_idle_frame() {
    extern "C" { fn _kernel_idle(); }
    let sp: usize;
    unsafe { core::arch::asm!("mv {}, sp", out(reg) sp, options(nomem, nostack)); }
    let frame = unsafe { &mut *IDLE_FRAME.0.get() };
    *frame = TrapFrame::ZERO;
    frame.sepc    = _kernel_idle as *const () as usize;
    frame.sstatus = (1 << 8) | (1 << 5) | (1 << 18); // SPP=1 (S-mode), SPIE=1, SUM=1
    frame.x[2]    = sp;                   // boot kernel stack pointer
    IDLE_FRAME_READY.store(true, Ordering::Relaxed);
}

/// True once all threads have exited and BOOT_FRAME[0] was restored.
pub fn is_done() -> bool { !SCHEDULING_ACTIVE.load(Ordering::Relaxed) }

/// Enqueue `tcb_pa` at the given `priority` level and count it as a live thread.
pub fn enqueue(tcb_pa: usize, priority: usize) {
    let tcb = unsafe { &mut *(tcb_pa as *mut Tcb) };
    tcb.priority  = priority as u8;
    tcb.state     = TcbState::Runnable;
    tcb.ticks_rem = ticks_for_level(priority as u8);
    tcb.next_pa   = 0;
    LIVE_THREADS.fetch_add(1, Ordering::Relaxed);
    link(tcb_pa, priority);
}

/// Yield the CPU — re-enqueue the current thread at priority 0 and switch away.
pub fn yield_current(frame: &mut TrapFrame) {
    let hart = current_hart();
    let cur_pa = CURRENT[hart].load(Ordering::Relaxed);
    if cur_pa == 0 { return; }
    let cur = unsafe { &mut *(cur_pa as *mut Tcb) };
    cur.frame = *frame;
    cur.state = TcbState::Runnable;
    CURRENT[hart].store(0, Ordering::Relaxed);
    link(cur_pa, 0);
    switch_to_next(frame);
}

/// Mark the current thread suspended and spin in WFI.  Never returns.
pub fn thread_exit() -> ! {
    let hart = current_hart();
    let cur_pa = CURRENT[hart].load(Ordering::Relaxed);
    if cur_pa != 0 {
        let tcb = unsafe { &mut *(cur_pa as *mut Tcb) };
        tcb.state = TcbState::Suspended;
        LIVE_THREADS.fetch_sub(1, Ordering::AcqRel);
    }
    loop { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }
}

// ── Timer interrupt handler ───────────────────────────────────────────────────

/// Called from `trap_handler` on every supervisor timer interrupt.
pub fn on_timer(frame: &mut TrapFrame) {
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    timer::arm(timer::TICKS_PER_TICK);

    if !SCHEDULING_ACTIVE.load(Ordering::Relaxed) {
        return;
    }

    let hart = current_hart();
    let cur_pa = CURRENT[hart].load(Ordering::Relaxed);

    if cur_pa == 0 {
        // Interrupted idle.  Only save as BOOT_FRAME if we came from S-mode
        // (sstatus.SPP = 1, bit 8).  A U-mode frame here means a ghost thread
        // is running due to a bug — never let that corrupt the boot frame.
        if !BOOT_FRAME_VALID[hart].load(Ordering::Relaxed)
            && frame.sstatus & (1 << 8) != 0
        {
            unsafe { *BOOT_FRAME[hart].0.get() = *frame; }
            BOOT_FRAME_VALID[hart].store(true, Ordering::Relaxed);
        }
    } else {
        let cur = unsafe { &mut *(cur_pa as *mut Tcb) };
        cur.frame = *frame;

        if cur.state == TcbState::Running { cur.state = TcbState::Runnable; }

        if cur.state == TcbState::Runnable {
            if cur.ticks_rem > 0 { cur.ticks_rem -= 1; }
            if cur.ticks_rem == 0 {
                let new_prio = (cur.priority as usize + 1).min(MLFQ_LEVELS - 1);
                cur.priority  = new_prio as u8;
                cur.ticks_rem = ticks_for_level(new_prio as u8);
            }
            link(cur_pa, cur.priority as usize);
        }
        // Suspended / Blocked / Exited threads are not re-linked.
        CURRENT[hart].store(0, Ordering::Relaxed);
    }

    let next_pa = dequeue_locked();

    if next_pa != 0 {
        let next = unsafe { &mut *(next_pa as *mut Tcb) };
        next.state = TcbState::Running;
        CURRENT[hart].store(next_pa, Ordering::Relaxed);
        NEXT_SATP[hart].store(next.satp, Ordering::Relaxed);
        *frame = next.frame;
    } else if BOOT_FRAME_VALID[hart].load(Ordering::Relaxed) {
        unsafe { *frame = *BOOT_FRAME[hart].0.get(); }
        NEXT_SATP[hart].store(crate::arch::riscv64::vspace::boot_satp(), Ordering::Relaxed);
        BOOT_FRAME_VALID[hart].store(false, Ordering::Relaxed);
        if hart == 0 && IO_WAITERS.load(Ordering::Relaxed) == 0
           && LIVE_THREADS.load(Ordering::Acquire) == 0 {
            SCHEDULING_ACTIVE.store(false, Ordering::Relaxed);
        }
    } else if IDLE_FRAME_READY.load(Ordering::Relaxed) {
        unsafe { *frame = *IDLE_FRAME.0.get(); }
        NEXT_SATP[hart].store(crate::arch::riscv64::vspace::boot_satp(), Ordering::Relaxed);
        if hart == 0 && IO_WAITERS.load(Ordering::Relaxed) == 0
           && LIVE_THREADS.load(Ordering::Acquire) == 0 {
            SCHEDULING_ACTIVE.store(false, Ordering::Relaxed);
        }
    }
}

// ── Secondary hart entry point ────────────────────────────────────────────────

/// Called from `_start_hart` assembly for each secondary hart.
/// Enables interrupts and arms the timer, then spins in WFI.
/// The scheduler's on_timer handler picks up runnable threads from the shared queue.
#[no_mangle]
pub extern "C" fn secondary_main(_hart_id: usize) -> ! {
    extern "C" { fn _trap_entry(); }
    unsafe {
        // Install the trap vector for this hart.
        core::arch::asm!("csrw stvec, {}", in(reg) _trap_entry as usize,
                         options(nostack, nomem));
        // Enable supervisor interrupts.
        core::arch::asm!("csrs sstatus, {}", in(reg) 0x2usize, options(nostack, nomem));
    }
    crate::arch::riscv64::timer::init();
    loop { unsafe { core::arch::asm!("wfi", options(nomem, nostack)); } }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Append `tcb_pa` to the tail of `QUEUE[level]` (acquires/releases QUEUE_LOCK).
fn link(tcb_pa: usize, level: usize) {
    unsafe { (*(tcb_pa as *mut Tcb)).next_pa = 0; }
    QUEUE_LOCK.lock();
    let tail_pa = QUEUE_TAIL[level].swap(tcb_pa, Ordering::Relaxed);
    if tail_pa == 0 {
        QUEUE_HEAD[level].store(tcb_pa, Ordering::Relaxed);
    } else {
        unsafe { (*(tail_pa as *mut Tcb)).next_pa = tcb_pa; }
    }
    QUEUE_LOCK.unlock();
}

/// Dequeue while holding QUEUE_LOCK.
fn dequeue_locked() -> usize {
    QUEUE_LOCK.lock();
    let result = dequeue();
    QUEUE_LOCK.unlock();
    result
}

/// Remove and return the head of the highest-priority non-empty level.
/// Must be called under QUEUE_LOCK.
fn dequeue() -> usize {
    for level in 0..MLFQ_LEVELS {
        let head_pa = QUEUE_HEAD[level].load(Ordering::Relaxed);
        if head_pa != 0 {
            let next = unsafe { (*(head_pa as *mut Tcb)).next_pa };
            QUEUE_HEAD[level].store(next, Ordering::Relaxed);
            if next == 0 { QUEUE_TAIL[level].store(0, Ordering::Relaxed); }
            unsafe { (*(head_pa as *mut Tcb)).next_pa = 0; }
            return head_pa;
        }
    }
    0
}
