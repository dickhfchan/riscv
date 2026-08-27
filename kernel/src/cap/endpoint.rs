// Synchronous IPC Endpoint — seL4-style rendezvous.
//
// An Endpoint holds either a queue of waiting senders (SendBlocked) or a queue
// of waiting receivers (RecvBlocked), never both.  Direct transfer occurs when
// the matching party arrives; the other path blocks the caller.

use crate::arch::riscv64::trap::TrapFrame;
use crate::thread::{Tcb, TcbState};
use crate::sched;
use crate::syscall::error;

// ── Capability transfer helper ────────────────────────────────────────────────
//
// On IPC rendezvous, if the sender includes a6=src_slot and the receiver
// saved a6=dst_slot (in cap_recv_slot), the kernel copies the capability from
// the sender's CSpace into the receiver's CSpace.  a6=0 on either side means
// no transfer.

fn cspace_of(tcb: &Tcb) -> (usize, usize) {
    if tcb.cspace_pa != 0 { (tcb.cspace_pa, tcb.cspace_sb) } else { super::root_cspace() }
}

fn transfer_cap(sender: &Tcb, recv: &mut Tcb, src_slot: usize) {
    let dst_slot = recv.cap_recv_slot;
    if src_slot == 0 || dst_slot == 0 { return; }
    recv.cap_recv_slot = 0;
    let (s_pa, s_sb) = cspace_of(sender);
    let (r_pa, r_sb) = cspace_of(recv);
    if let Ok(cap) = super::cnode::lookup(s_pa, s_sb, src_slot) {
        if !cap.is_null() {
            let _ = super::cnode::insert(r_pa, r_sb, dst_slot, cap);
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EpState { Idle = 0, SendBlocked = 1, RecvBlocked = 2 }

#[repr(C)]
pub struct Endpoint {
    pub state:      EpState,
    _pad:           [u8; 7],
    pub queue_head: usize,  // PA of first waiting Tcb
    pub queue_tail: usize,  // PA of last  waiting Tcb
}

impl Endpoint {
    /// Handle ENDPOINT_SEND or ENDPOINT_CALL.
    /// `msg[0..4]` = a3..a6, `badge` = a2, `is_call` = whether to block for reply.
    pub fn send(&mut self, frame: &mut TrapFrame, badge: usize, msg: [usize; 4], is_call: bool) {
        if self.state == EpState::RecvBlocked {
            // Receiver already waiting: direct transfer.
            let recv_pa = self.ep_dequeue();
            let recv    = unsafe { &mut *(recv_pa as *mut Tcb) };

            recv.frame.set_reply([error::OK, badge, msg[0], msg[1], msg[2], msg[3], 0, 0]);

            // Cap transfer: a6 of sender = source cap slot; receiver's cap_recv_slot = dest.
            let src_slot = frame.x[16]; // a6
            if src_slot != 0 {
                let cur_pa = sched::current_pa();
                if cur_pa != 0 {
                    let sender = unsafe { &*(cur_pa as *const Tcb) };
                    transfer_cap(sender, recv, src_slot);
                }
            }

            if is_call {
                // Wake receiver BEFORE blocking caller so switch_to_next finds it
                // in the MLFQ.  (Ordering matters: block_current calls switch_to_next
                // immediately, and it must see a runnable receiver to avoid prematurely
                // restoring the BOOT_FRAME.)
                recv.reply_pa = sched::current_pa();
                sched::wake(recv_pa);
                let _blocked = sched::block_current(frame);
            } else {
                frame.set_reply([error::OK, 0, 0, 0, 0, 0, 0, 0]);
                sched::wake(recv_pa);
            }
            if self.queue_head == 0 { self.state = EpState::Idle; }
        } else {
            // No receiver: block sender.
            self.state = EpState::SendBlocked;
            let cur = unsafe { &mut *(sched::current_pa() as *mut Tcb) };
            cur.ipc_is_call = is_call;
            // Badge (a2) and msg words (a3-a6) are already in frame.x[12..17].
            let blocked_pa = sched::block_current(frame);
            self.ep_enqueue(blocked_pa);
        }
    }

    /// Handle ENDPOINT_RECV.
    pub fn recv(&mut self, frame: &mut TrapFrame) {
        // Save the receiver's cap destination slot (a6) before potentially blocking.
        let cur_pa = sched::current_pa();
        if cur_pa != 0 {
            unsafe { (*(cur_pa as *mut Tcb)).cap_recv_slot = frame.x[16]; } // a6
        }

        if self.state == EpState::SendBlocked {
            // Sender already waiting: direct transfer.
            let send_pa = self.ep_dequeue();
            let send    = unsafe { &mut *(send_pa as *mut Tcb) };

            let badge = send.frame.x[12]; // a2 = badge sent
            let msg   = [send.frame.x[13], send.frame.x[14], send.frame.x[15], 0];

            frame.set_reply([error::OK, badge, msg[0], msg[1], msg[2], 0, 0, 0]);

            // Cap transfer: sender's a6 = source slot; receiver's cap_recv_slot = dest.
            let src_slot = send.frame.x[16]; // a6 of sender's saved frame
            if src_slot != 0 && cur_pa != 0 {
                let recv = unsafe { &mut *(cur_pa as *mut Tcb) };
                transfer_cap(send, recv, src_slot);
            } else if cur_pa != 0 {
                // No transfer — still reset cap_recv_slot.
                unsafe { (*(cur_pa as *mut Tcb)).cap_recv_slot = 0; }
            }

            if send.ipc_is_call {
                // Sender called: receiver holds the reply cap.
                if cur_pa != 0 {
                    unsafe { (*(cur_pa as *mut Tcb)).reply_pa = send_pa; }
                }
                // Sender stays Blocked waiting for Reply — do not wake it.
            } else {
                sched::unblock(send_pa, [error::OK, 0, 0, 0, 0, 0, 0, 0]);
            }
            if self.queue_head == 0 { self.state = EpState::Idle; }
        } else {
            // No sender: block receiver (cap_recv_slot already saved above).
            self.state = EpState::RecvBlocked;
            let blocked_pa = sched::block_current(frame);
            self.ep_enqueue(blocked_pa);
        }
    }

    /// Handle ENDPOINT_REPLY_RECV — seL4-style server-loop fastpath.
    ///
    /// Atomically delivers the reply to the current caller (using the saved
    /// `reply_pa` in the current TCB) and then performs a RECV on this endpoint.
    /// If a sender is already queued the transfer is immediate (no scheduling
    /// round-trip); otherwise the server blocks until a client calls.
    ///
    /// `frame.x[12]` (a2) is the reply value forwarded to the caller.
    pub fn reply_recv(&mut self, frame: &mut TrapFrame) {
        // Deliver reply to saved caller, identical to ENDPOINT_REPLY.
        let cur_pa = sched::current_pa();
        if cur_pa != 0 {
            let cur = unsafe { &mut *(cur_pa as *mut Tcb) };
            let rpa = cur.reply_pa;
            cur.reply_pa = 0;
            if rpa != 0 {
                let reply_val = frame.x[12]; // a2
                sched::unblock(rpa, [error::OK, 0, reply_val, 0, 0, 0, 0, 0]);
            }
        }
        // Then block on the next recv (or direct-transfer if a sender is queued).
        self.recv(frame);
    }

    fn ep_enqueue(&mut self, tcb_pa: usize) {
        unsafe { (*(tcb_pa as *mut Tcb)).next_pa = 0; }
        if self.queue_head == 0 {
            self.queue_head = tcb_pa;
            self.queue_tail = tcb_pa;
        } else {
            unsafe { (*(self.queue_tail as *mut Tcb)).next_pa = tcb_pa; }
            self.queue_tail = tcb_pa;
        }
    }

    fn ep_dequeue(&mut self) -> usize {
        let head = self.queue_head;
        if head != 0 {
            let next = unsafe { (*(head as *const Tcb)).next_pa };
            self.queue_head = next;
            if next == 0 { self.queue_tail = 0; }
            unsafe { (*(head as *mut Tcb)).next_pa = 0; }
        }
        head
    }
}
