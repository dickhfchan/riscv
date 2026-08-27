/*
 * Trap handler — S-mode exception and interrupt dispatcher.
 *
 * All traps land at `_trap_entry` (trap.S), which saves the TrapFrame on the
 * kernel stack and calls `trap_handler` here.  We dispatch on scause, then
 * restore the frame (including modified a0-a7 for ecall returns).
 */

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::println;

/* Include the assembly entry via global_asm so it lands in .text.trap. */
core::arch::global_asm!(include_str!("trap.S"));

// ── TrapFrame ────────────────────────────────────────────────────────────────

/// Mirrors the stack layout in trap.S exactly (34 × usize).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TrapFrame {
    pub x:       [usize; 32], // x[0] = dummy zero; x[i] = register xi
    pub sepc:    usize,       // at offset 32*8 = 256
    pub sstatus: usize,       // at offset 33*8 = 264
}

impl TrapFrame {
    pub const ZERO: Self = Self { x: [0; 32], sepc: 0, sstatus: 0 };
}

impl TrapFrame {
    #[inline] pub fn a0(&self) -> usize { self.x[10] }
    #[inline] pub fn a1(&self) -> usize { self.x[11] }
    #[inline] pub fn a2(&self) -> usize { self.x[12] }
    #[inline] pub fn a3(&self) -> usize { self.x[13] }
    #[inline] pub fn a4(&self) -> usize { self.x[14] }
    #[inline] pub fn a5(&self) -> usize { self.x[15] }
    #[inline] pub fn a6(&self) -> usize { self.x[16] }
    #[inline] pub fn a7(&self) -> usize { self.x[17] }

    pub fn set_reply(&mut self, reply: [usize; 8]) {
        self.x[10] = reply[0];
        self.x[11] = reply[1];
        self.x[12] = reply[2];
        self.x[13] = reply[3];
        self.x[14] = reply[4];
        self.x[15] = reply[5];
        self.x[16] = reply[6];
        self.x[17] = reply[7];
    }

    #[inline]
    pub fn set_a0(&mut self, v: usize) { self.x[10] = v; }

    #[inline]
    pub fn pc(&self) -> usize { self.sepc }

    #[inline]
    pub fn set_pc(&mut self, v: usize) { self.sepc = v; }
}

// ── Exception causes ─────────────────────────────────────────────────────────

const CAUSE_MISALIGNED_FETCH:  usize = 0;
const CAUSE_ILLEGAL_INSTR:     usize = 2;
const CAUSE_BREAKPOINT:        usize = 3;
const CAUSE_LOAD_FAULT:        usize = 5;
const CAUSE_STORE_FAULT:       usize = 7;
const CAUSE_ECALL_U:           usize = 8;
const CAUSE_ECALL_S:           usize = 9;
const CAUSE_LOAD_PAGE_FAULT:   usize = 13;
const CAUSE_STORE_PAGE_FAULT:  usize = 15;

const INTERRUPT_BIT:                 usize = 1 << 63;
const INTERRUPT_SUPERVISOR_TIMER:    usize = INTERRUPT_BIT | 5;
const INTERRUPT_SUPERVISOR_EXTERNAL: usize = INTERRUPT_BIT | 9;

// ── Trap counter (for diagnostics) ──────────────────────────────────────────

static TRAP_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn trap_count() -> usize { TRAP_COUNT.load(Ordering::Relaxed) }

// ── Install ───────────────────────────────────────────────────────────────────

/// Point `stvec` at `_trap_entry` in direct mode (bits[1:0] = 0).
pub unsafe fn install() {
    extern "C" { fn _trap_entry(); }
    let addr = _trap_entry as *const () as usize;
    core::arch::asm!(
        "csrw stvec, {addr}",
        addr = in(reg) addr,
        options(nostack, nomem),
    );
}

/// Read back stvec and verify it points to _trap_entry.
pub fn verify_install() {
    extern "C" { fn _trap_entry(); }
    let expected = _trap_entry as *const () as usize;
    let actual: usize;
    unsafe {
        core::arch::asm!("csrr {}, stvec", out(reg) actual, options(nostack, nomem));
    }
    // bits[1:0] = mode (0 = direct), ignore them in comparison
    assert_eq!(actual & !0x3, expected & !0x3, "stvec install mismatch");
}

// ── Main Rust handler (called from trap.S) ────────────────────────────────────

#[no_mangle]
pub extern "C" fn trap_handler(frame: &mut TrapFrame) {
    TRAP_COUNT.fetch_add(1, Ordering::Relaxed);

    let scause: usize;
    let stval:  usize;
    unsafe {
        core::arch::asm!("csrr {}, scause", out(reg) scause, options(nostack, nomem));
        core::arch::asm!("csrr {}, stval",  out(reg) stval,  options(nostack, nomem));
    }

    if scause & INTERRUPT_BIT != 0 {
        match scause {
            INTERRUPT_SUPERVISOR_TIMER    => crate::sched::on_timer(frame),
            INTERRUPT_SUPERVISOR_EXTERNAL => crate::cap::irq::handle_external(frame),
            irq => println!("  [IRQ] cause={} (unhandled)", irq & !INTERRUPT_BIT),
        }
        return;
    }

    match scause {
        // ecall from U-mode or S-mode
        CAUSE_ECALL_U | CAUSE_ECALL_S => {
            frame.sepc += 4; // advance past the ecall instruction
            // If the current thread is running in Linux ABI mode, route to the
            // Linux syscall dispatcher instead of the Ferrite capability handler.
            let cur_pa = crate::sched::current_pa();
            if cur_pa != 0 {
                let linux = unsafe {
                    (*(cur_pa as *const crate::thread::Tcb)).linux_compat
                };
                if linux {
                    crate::linux_compat::dispatch(frame);
                    return;
                }
            }
            crate::syscall::dispatch(frame); // writes reply (or new thread ctx) to frame
        }

        CAUSE_BREAKPOINT => {
            // c.ebreak (0x9002, 2-byte compressed) or ebreak (4-byte). Check
            // bits[1:0] of the instruction word: 0b11 → 32-bit, else 16-bit.
            let instr = unsafe { (frame.sepc as *const u16).read_volatile() };
            frame.sepc += if instr & 0x3 == 0x3 { 4 } else { 2 };
        }

        _ => {
            // Unexpected exception — panic with diagnostic
            println!();
            println!("  !!! UNHANDLED EXCEPTION !!!");
            println!("  scause  = {:#018x}", scause);
            println!("  sepc    = {:#018x}", frame.sepc);
            println!("  stval   = {:#018x}", stval);
            println!("  sstatus = {:#018x}", frame.sstatus);
            println!("  a0      = {:#018x}", frame.a0());
            println!("  frame.x2= {:#018x}  (inner sp)", frame.x[2]);
            println!("  old_sp  = {:#018x}  (outer sp = inner sp + 272)", frame.x[2].wrapping_add(272));
            panic!("unhandled exception scause={:#x}", scause);
        }
    }
}
