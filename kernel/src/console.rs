/*
 * Console — kernel-wide print!/println! macros + UART RX ring buffer.
 *
 * Phase 1–14: TX only (putchar via polling).
 * Phase 15: adds RX ring buffer, blocking CONSOLE_GETCHAR syscall, and UART RX
 * IRQ handling.  A waiting TCB is stored in the waiter queue (linked via next_pa)
 * and woken directly from the external-IRQ handler so the sret enters the woken
 * thread without waiting for the next timer tick.
 */

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::arch::riscv64::uart::UartWriter;
use crate::arch::riscv64::trap::TrapFrame;

// ── TX (print macros) ─────────────────────────────────────────────────────────

pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    UartWriter.write_fmt(args).ok();
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::console::_print(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! println {
    ()            => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::print!("{}\n", format_args!($($arg)*)) };
}

// ── RX ring buffer ────────────────────────────────────────────────────────────

/// PLIC IRQ number for the QEMU virt UART (ns16550a).
pub const CONSOLE_IRQ: usize = 10;

const BUF_CAP: usize = 4096;

struct RxBuf {
    data: [u8; BUF_CAP],
    head: usize, // read index
    tail: usize, // write index
}

impl RxBuf {
    const fn new() -> Self { Self { data: [0; BUF_CAP], head: 0, tail: 0 } }
    fn is_empty(&self) -> bool { self.head == self.tail }
    fn push(&mut self, b: u8) {
        let next = (self.tail + 1) % BUF_CAP;
        if next != self.head { self.data[self.tail] = b; self.tail = next; }
    }
    fn pop(&mut self) -> Option<u8> {
        if self.is_empty() { return None; }
        let b = self.data[self.head];
        self.head = (self.head + 1) % BUF_CAP;
        Some(b)
    }
}

static mut RX_BUF: RxBuf = RxBuf::new();

// ── Waiter queue (TCB PAs linked via next_pa) ─────────────────────────────────

static WAITER_HEAD: AtomicUsize = AtomicUsize::new(0);
static WAITER_TAIL: AtomicUsize = AtomicUsize::new(0);

fn enqueue_waiter(tcb_pa: usize) {
    let tcb = unsafe { &mut *(tcb_pa as *mut crate::thread::Tcb) };
    tcb.next_pa = 0;
    let old_tail = WAITER_TAIL.swap(tcb_pa, Ordering::Relaxed);
    if old_tail == 0 {
        WAITER_HEAD.store(tcb_pa, Ordering::Relaxed);
    } else {
        unsafe { (*(old_tail as *mut crate::thread::Tcb)).next_pa = tcb_pa; }
    }
}

fn dequeue_waiter() -> usize {
    let head = WAITER_HEAD.load(Ordering::Relaxed);
    if head == 0 { return 0; }
    let next = unsafe { (*(head as *mut crate::thread::Tcb)).next_pa };
    WAITER_HEAD.store(next, Ordering::Relaxed);
    if next == 0 { WAITER_TAIL.store(0, Ordering::Relaxed); }
    head
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Enable UART RX interrupt and register the PLIC source.
/// Call after plic::init() and plic::set_enable(CONSOLE_IRQ, true).
pub fn init_rx() {
    crate::arch::riscv64::uart::enable_rx_interrupt();
}

/// Pre-load bytes into the ring buffer for automated testing.
pub fn seed(data: &[u8]) {
    for &b in data {
        #[allow(static_mut_refs)]
        unsafe { RX_BUF.push(b); }
    }
}

/// CONSOLE_GETCHAR syscall handler.
/// If a char is available, returns it immediately in a1.
/// Otherwise blocks the calling thread; it will be woken by rx_irq() when a char arrives.
pub fn getchar(frame: &mut TrapFrame) {
    #[allow(static_mut_refs)]
    if let Some(b) = unsafe { RX_BUF.pop() } {
        frame.set_reply([0, b as usize, 0, 0, 0, 0, 0, 0]);
        return;
    }
    // No char available — block current thread and add to waiter queue.
    crate::sched::add_io_waiter();
    let tcb_pa = crate::sched::block_current(frame);
    if tcb_pa != 0 {
        enqueue_waiter(tcb_pa);
    }
}

/// Called from the external-IRQ handler when IRQ == CONSOLE_IRQ and data_ready().
/// Reads one byte from UART, echoes it, and either wakes a waiter or buffers the byte.
pub fn rx_irq(frame: &mut TrapFrame) {
    let raw = crate::arch::riscv64::uart::read_byte();
    // Translate CR → LF for terminal compat; echo visually.
    let byte = if raw == b'\r' {
        crate::arch::riscv64::uart::putchar(b'\r');
        crate::arch::riscv64::uart::putchar(b'\n');
        b'\n'
    } else if raw == 127 || raw == 8 {
        // Backspace/DEL: erase the previous character on the terminal.
        crate::arch::riscv64::uart::putchar(8);    // BS: move left
        crate::arch::riscv64::uart::putchar(b' '); // overwrite with space
        crate::arch::riscv64::uart::putchar(8);    // BS: move left again
        raw
    } else {
        crate::arch::riscv64::uart::putchar(raw);
        raw
    };

    let waiter = dequeue_waiter();
    if waiter != 0 {
        crate::sched::remove_io_waiter();
        // Wake directly into the current trap frame so sret enters the woken thread.
        crate::sched::wake_from_irq(waiter, [0, byte as usize, 0, 0, 0, 0, 0, 0], frame);
    } else {
        #[allow(static_mut_refs)]
        unsafe { RX_BUF.push(byte); }
    }
}
