// Async Notification — badge-OR signaling.
//
// A Notification holds an accumulated badge word.  Signal ORs bits in;
// Wait returns the word immediately (clearing it) or blocks if zero.

use crate::arch::riscv64::trap::TrapFrame;
use crate::sched;
use crate::syscall::error;

#[repr(C)]
pub struct Notification {
    pub badge:  usize,   // accumulated signal bits (0 = no pending signals)
    pub waiter: usize,   // PA of blocked receiver (0 = none)
}

impl Notification {
    /// Signal: OR `badge` into the word; wake any blocked waiter.
    pub fn signal(&mut self, badge: usize, frame: &mut TrapFrame) {
        self.badge |= badge;
        if self.waiter != 0 {
            let waiter_pa = self.waiter;
            self.waiter   = 0;
            let b         = self.badge;
            self.badge    = 0;
            sched::unblock(waiter_pa, [error::OK, b, 0, 0, 0, 0, 0, 0]);
        }
        frame.set_reply([error::OK, 0, 0, 0, 0, 0, 0, 0]);
    }

    /// Wait: return badge immediately if non-zero, else block.
    pub fn wait(&mut self, frame: &mut TrapFrame) {
        if self.badge != 0 {
            let b      = self.badge;
            self.badge = 0;
            frame.set_reply([error::OK, b, 0, 0, 0, 0, 0, 0]);
        } else {
            let blocked_pa = sched::block_current(frame);
            self.waiter    = blocked_pa;
        }
    }
}
