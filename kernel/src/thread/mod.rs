// Thread Control Block (TCB) — Phase 4.

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::arch::riscv64::trap::TrapFrame;
use crate::mm;

/// Intrusive global TCB list head (PA; 0 = empty).
/// Used by CNODE_REVOKE to scan all per-process CSpaces.
pub static TCB_LIST_HEAD: AtomicUsize = AtomicUsize::new(0);

/// Linux PID allocator (Phase A4). Assigned to every thread; only
/// Linux-compat processes expose it via getpid/clone/wait4.
static NEXT_PID: AtomicUsize = AtomicUsize::new(1);

pub fn next_pid() -> usize { NEXT_PID.fetch_add(1, Ordering::Relaxed) }

pub const KSTACK_SIZE:  usize = 4 * 4096; // 16 KiB — debug-mode call chains can exceed 4 KiB
const    KSTACK_ORDER: usize = 2;          // alloc_pages(2) = 4 contiguous pages
pub const MLFQ_LEVELS:  usize = 3;

/// Ticks before a thread at this MLFQ level is demoted.
pub const fn ticks_for_level(level: u8) -> u16 {
    match level {
        0 => 1,
        1 => 2,
        _ => 4,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcbState {
    Inactive  = 0,
    Runnable  = 1,
    Running   = 2,
    Blocked   = 3,
    Suspended = 4,
    Exited    = 5, // terminated via THREAD_EXIT; exit_code is valid
}

/// S-mode sstatus for a kernel thread: SPP=1, SPIE=1.
const SSTATUS_KTHREAD: usize = (1 << 8) | (1 << 5);
/// U-mode sstatus: SPP=0, SPIE=1, SUM=1.
/// SUM=1 ensures that when a timer/ecall trap fires from U-mode, the S-mode trap
/// handler can read/write the user stack (which resides in a PTE_U page).
const SSTATUS_UTHREAD: usize = (1 << 5) | (1 << 18);

/// Thread Control Block.
///
/// `frame` is at offset 0 so asm helpers can address it without arithmetic.
/// One page (4 KiB) is allocated per TCB from the buddy allocator; the struct
/// occupies only the first ~300 bytes but the page must not be shared.
#[repr(C)]
pub struct Tcb {
    pub frame:      TrapFrame, // 272 bytes — saved CPU context
    pub state:      TcbState,
    pub priority:   u8,        // current MLFQ level (0 = highest)
    pub ticks_rem:  u16,       // ticks remaining before demotion
    pub ipc_is_call: bool,     // true if thread blocked via Call (awaiting Reply)
    _pad:           [u8; 3],
    pub next_pa:    usize,     // intrusive list: scheduler queue or IPC wait queue
    pub kstack_pa:  usize,     // PA of kernel stack page
    pub reply_pa:   usize,     // PA of Tcb that Called this thread (0 = none)
    pub satp:       usize,     // VSpace: satp CSR value for this thread (Phase 7)
    pub cspace_pa:     usize,  // per-process CNode PA (0 = use global root CSpace)
    pub cspace_sb:     usize,  // per-process CNode size_bits
    pub cap_recv_slot: usize,  // cap dest slot in receiver's CSpace (saved at RECV time, 0 = none)
    pub fd_table_pa:   usize,  // PA of FdTable page (0 = none; lazily allocated on first open)
    pub waiter_pa:     usize,  // TCB PA of thread blocked in PROC_WAIT on this thread (0 = none)
    pub exit_code:     usize,  // exit code set on THREAD_EXIT (valid when state == Exited)
    pub global_next:   usize,  // intrusive global TCB list link (PA; 0 = end)
    pub linux_compat:  bool,   // Phase A1: routes ecalls through Linux ABI dispatcher
    _pad2:             [u8; 7],
    pub brk_base:      usize,  // Phase A2: heap start VA (set when Linux ELF is loaded)
    pub brk_next:      usize,  // Phase A2: current program break VA
    pub brk_mapped:    usize,  // Phase A2: page-aligned VA high-water mark for brk
    pub mmap_bump:     usize,  // Phase A2: anonymous mmap VA bump pointer (0 → init 0x4000_0000)
    pub pid:           usize,  // Phase A4: Linux process ID (allocated for every thread)
    pub parent_pa:     usize,  // Phase A4: TCB PA of parent process (0 = kernel-spawned)
}

fn alloc_tcb(entry: usize, sstatus: usize) -> Option<usize> {
    let kstack_pa = mm::alloc_pages(KSTACK_ORDER)?;
    // Use the slab allocator for TCBs — 8× more efficient than one page per TCB.
    let tcb_pa = mm::slab_alloc(core::mem::size_of::<Tcb>())?;

    // slab_alloc already zeroes tcb_pa; kstack still needs explicit zero.
    unsafe { core::ptr::write_bytes(kstack_pa as *mut u8, 0, KSTACK_SIZE); }

    let tcb = unsafe { &mut *(tcb_pa as *mut Tcb) };
    tcb.frame.sepc    = entry;
    tcb.frame.sstatus = sstatus;
    tcb.frame.x[2]    = kstack_pa + KSTACK_SIZE;
    tcb.state         = TcbState::Runnable;
    tcb.priority      = 0;
    tcb.ticks_rem     = ticks_for_level(0);
    tcb.kstack_pa     = kstack_pa;
    tcb.satp          = crate::arch::riscv64::vspace::boot_satp();
    tcb.pid           = next_pid();

    // Prepend to the global TCB list for CNODE_REVOKE scanning (Phase 19).
    // global_next is written before the TCB is made visible in the list.
    let old_head = TCB_LIST_HEAD.load(Ordering::Acquire);
    tcb.global_next = old_head;
    TCB_LIST_HEAD.store(tcb_pa, Ordering::Release);

    Some(tcb_pa)
}

/// Kernel thread (S-mode): entry and stack use kernel VAs directly.
pub fn create_kthread(entry: usize) -> Option<usize> {
    alloc_tcb(entry, SSTATUS_KTHREAD)
}

/// User thread (U-mode): entry and stack are mapped to the user mirror
/// (VA = kernel_PA + USER_MIRROR_OFFSET) where PTE_U=1, so ecall works.
/// PC-relative code and data on the user stack work correctly because the
/// mirror offset cancels in any PC-relative address calculation.
pub fn create_uthread(entry: usize) -> Option<usize> {
    use crate::arch::riscv64::mmu::USER_MIRROR_OFFSET;
    let tcb_pa = alloc_tcb(entry, SSTATUS_UTHREAD)?;
    let tcb = unsafe { &mut *(tcb_pa as *mut Tcb) };
    tcb.frame.sepc = entry + USER_MIRROR_OFFSET;
    tcb.frame.x[2] = tcb.kstack_pa + KSTACK_SIZE + USER_MIRROR_OFFSET;
    // satp stays as boot_satp (user mirror is in boot PGD)
    Some(tcb_pa)
}

/// Process thread (U-mode, separate VSpace): like create_uthread but uses
/// the supplied `satp` value so the process runs in its own page table root.
/// The process VSpace must share BOOT_PUD_USER (see vspace::create_process_vspace)
/// so that user-mirror-VA stacks are accessible in any VSpace.
pub fn create_process_thread(entry: usize, vspace_satp: usize) -> Option<usize> {
    use crate::arch::riscv64::mmu::USER_MIRROR_OFFSET;
    let tcb_pa = alloc_tcb(entry, SSTATUS_UTHREAD)?;
    let tcb = unsafe { &mut *(tcb_pa as *mut Tcb) };
    tcb.frame.sepc = entry + USER_MIRROR_OFFSET; // run from user mirror VA
    tcb.frame.x[2] = tcb.kstack_pa + KSTACK_SIZE + USER_MIRROR_OFFSET; // user mirror stack
    tcb.satp = vspace_satp; // isolated VSpace
    Some(tcb_pa)
}

/// ELF process thread (U-mode, separate VSpace, true ELF VAs).
///
/// Unlike create_process_thread, sepc is the raw ELF entry VA (e.g., 0x10000) —
/// the binary runs from pages explicitly mapped by the ELF loader, not from the
/// user mirror.  The stack pointer still uses the user mirror so that TrapFrames
/// remain accessible in any VSpace after a satp switch.
pub fn create_elf_thread(entry_va: usize, satp: usize) -> Option<usize> {
    use crate::arch::riscv64::mmu::USER_MIRROR_OFFSET;
    let tcb_pa = alloc_tcb(entry_va, SSTATUS_UTHREAD)?; // sepc = entry_va already
    let tcb = unsafe { &mut *(tcb_pa as *mut Tcb) };
    tcb.frame.x[2] = tcb.kstack_pa + KSTACK_SIZE + USER_MIRROR_OFFSET; // user mirror stack
    tcb.satp = satp;
    Some(tcb_pa)
}

/// Linux-ABI process thread (Phase A4): like create_elf_thread, but ecalls
/// route through the Linux syscall dispatcher. The caller adjusts
/// `frame.x[2]` after writing the argv block into the kernel stack page —
/// the stack must stay at a user-mirror VA so trap frames remain reachable
/// from any VSpace during context switches.
pub fn create_linux_thread(entry_va: usize, satp: usize, parent_pa: usize) -> Option<usize> {
    let tcb_pa = create_elf_thread(entry_va, satp)?;
    let tcb = unsafe { &mut *(tcb_pa as *mut Tcb) };
    tcb.linux_compat = true;
    tcb.parent_pa    = parent_pa;
    Some(tcb_pa)
}
