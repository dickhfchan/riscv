/*
 * Ferrite OS — RISC-V64 trap entry (S-mode, direct mode).
 *
 * TrapFrame layout (272 bytes = 34 × 8):
 *   sp + i*8   = xi  (i = 0-31, x0 slot left zero)
 *   sp + 32*8  = sepc
 *   sp + 33*8  = sstatus
 *
 * Calling convention: trap_handler(&mut TrapFrame) via extern "C"
 * (first arg in a0 = x10 per RISC-V ABI).
 */

    .section .text.trap
    .global  _trap_entry
    .type    _trap_entry, @function
    .align   2          /* stvec direct mode: 4-byte aligned */

_trap_entry:
    /* ── Allocate TrapFrame (34 × 8 = 272 bytes) ─────────────────────── */
    addi sp, sp, -272

    /* ── Save the original sp using t0 as scratch ────────────────────── */
    sd   t0,  40(sp)        /* save t0 first so we can use it          */
    addi t0,  sp, 272       /* t0 = original (pre-trap) sp             */
    sd   t0,  16(sp)        /* frame[x2] = original sp                 */
    ld   t0,  40(sp)        /* restore t0 from frame                   */

    /* ── Save all GPRs except x0 (always 0) and x2 (done above) ─────── */
    sd   x1,   8(sp)
    /* x2 saved above */
    sd   x3,  24(sp)
    sd   x4,  32(sp)
    sd   x5,  40(sp)        /* t0 — correct value since we restored it */
    sd   x6,  48(sp)
    sd   x7,  56(sp)
    sd   x8,  64(sp)
    sd   x9,  72(sp)
    sd  x10,  80(sp)
    sd  x11,  88(sp)
    sd  x12,  96(sp)
    sd  x13, 104(sp)
    sd  x14, 112(sp)
    sd  x15, 120(sp)
    sd  x16, 128(sp)
    sd  x17, 136(sp)
    sd  x18, 144(sp)
    sd  x19, 152(sp)
    sd  x20, 160(sp)
    sd  x21, 168(sp)
    sd  x22, 176(sp)
    sd  x23, 184(sp)
    sd  x24, 192(sp)
    sd  x25, 200(sp)
    sd  x26, 208(sp)
    sd  x27, 216(sp)
    sd  x28, 224(sp)
    sd  x29, 232(sp)
    sd  x30, 240(sp)
    sd  x31, 248(sp)

    /* ── Save sepc and sstatus ────────────────────────────────────────── */
    csrr t0, sepc
    sd   t0, 256(sp)
    csrr t0, sstatus
    sd   t0, 264(sp)

    /* ── Call Rust handler: trap_handler(*mut TrapFrame) ─────────────── */
    mv   a0, sp
    call trap_handler

    /* ── Restore sepc and sstatus from (possibly modified) frame ──────── */
    ld   t0, 256(sp)
    csrw sepc, t0
    ld   t0, 264(sp)
    csrw sstatus, t0

    /* ── Switch VSpace if the scheduler changed NEXT_SATP ─────────────── */
    /* NEXT_SATP is a #[no_mangle] static array indexed by hart ID.        */
    /* sscratch holds the hart ID (set in boot.S and _start_hart).         */
    /* Each AtomicUsize element is 8 bytes, offset = hart_id * 8.          */
    csrr t1, sscratch
    la   t2, NEXT_SATP
    slli t1, t1, 3
    add  t2, t2, t1
    ld   t0, 0(t2)
    beqz t0, .Lno_satp_switch
    csrw satp, t0
    sfence.vma zero, zero
.Lno_satp_switch:

    /* ── Restore GPRs (a0-a7 carry syscall return values) ────────────── */
    ld   x1,   8(sp)
    /* x2 (sp) restored last */
    ld   x3,  24(sp)
    ld   x4,  32(sp)
    ld   x5,  40(sp)
    ld   x6,  48(sp)
    ld   x7,  56(sp)
    ld   x8,  64(sp)
    ld   x9,  72(sp)
    ld  x10,  80(sp)    /* a0 = syscall error code or return value    */
    ld  x11,  88(sp)
    ld  x12,  96(sp)
    ld  x13, 104(sp)
    ld  x14, 112(sp)
    ld  x15, 120(sp)
    ld  x16, 128(sp)
    ld  x17, 136(sp)
    ld  x18, 144(sp)
    ld  x19, 152(sp)
    ld  x20, 160(sp)
    ld  x21, 168(sp)
    ld  x22, 176(sp)
    ld  x23, 184(sp)
    ld  x24, 192(sp)
    ld  x25, 200(sp)
    ld  x26, 208(sp)
    ld  x27, 216(sp)
    ld  x28, 224(sp)
    ld  x29, 232(sp)
    ld  x30, 240(sp)
    ld  x31, 248(sp)

    /* ── Restore sp last (pops the TrapFrame) ─────────────────────────── */
    ld   sp,  16(sp)

    sret
