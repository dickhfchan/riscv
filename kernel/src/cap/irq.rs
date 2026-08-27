// IRQ capability dispatch layer.
//
// IRQControl cap (ptr=0): authority to mint IRQHandler caps via IRQ_ISSUE_HANDLER.
// IRQHandler cap (ptr=irq_num): represents one PLIC interrupt source.
//
// handle_external() is called from the S-mode external-interrupt path in
// trap_handler.  It claims the PLIC, checks whether the IRQ is the console
// (UART RX), and dispatches accordingly.  For the console IRQ, the byte is
// read and any waiting thread is woken directly into the current trap frame so
// sret enters it immediately.  For all other IRQs the source is masked and the
// caller re-enables it via IRQ_ACK + unmask_irq().

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::arch::riscv64::{plic, uart};
use crate::arch::riscv64::trap::TrapFrame;

static IRQ_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_IRQ:  AtomicUsize = AtomicUsize::new(0);

/// Called by the trap handler on every INTERRUPT_SUPERVISOR_EXTERNAL.
pub fn handle_external(frame: &mut TrapFrame) {
    let irq = plic::claim();
    if irq == 0 { return; } // spurious

    // Console (UART RX): read byte, echo, wake any blocked getchar caller.
    if irq == crate::console::CONSOLE_IRQ && uart::data_ready() {
        crate::console::rx_irq(frame);
        plic::set_enable(irq, true); // keep RX enabled for next byte
        plic::complete(irq);
        return;
    }

    // Generic IRQ: mask the source BEFORE completing so the PLIC cannot re-assert
    // SEIP while the interrupt condition (e.g., UART THRE) is still active.
    plic::set_enable(irq, false);
    IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
    LAST_IRQ.store(irq, Ordering::Relaxed);
    plic::complete(irq);
}

pub fn irq_count() -> usize { IRQ_COUNT.load(Ordering::Relaxed) }
pub fn last_irq()  -> usize { LAST_IRQ.load(Ordering::Relaxed) }

/// Re-enable IRQ source N in the PLIC after the interrupt condition is cleared.
pub fn unmask_irq(irq: usize) { plic::set_enable(irq, true); }
