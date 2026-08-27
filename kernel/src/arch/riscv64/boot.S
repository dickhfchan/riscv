/*
 * Ferrite OS — RISC-V64 boot entry
 *
 * OpenSBI calls us in S-mode with:
 *   a0 = hart ID
 *   a1 = FDT physical address
 *
 * Only hart 0 proceeds to kernel_main; all others spin in WFI until
 * SBI HSM wakes them via _start_hart.
 */

    /* Explicitly request the M extension: the integrated assembler does not
     * always infer it from the target when global_asm! is compiled. */
    .attribute arch, "rv64gc"
    .section .text.entry
    .global  _start
    .type    _start, @function

_start:
    /* Park all harts except hart 0. */
    bnez a0, .Lhart_park

    /* Store hart 0's hart ID in sscratch for current_hart() queries. */
    csrw sscratch, zero

    /* Set up the boot stack for hart 0. */
    la   sp, __boot_stack_top

    /*
     * Install a minimal direct-mode trap vector before touching anything.
     * All exceptions/interrupts land here until the kernel sets stvec
     * properly in Phase 4.
     */
    la   t0, .Ltrap_stub
    csrw stvec, t0

    /* Disable S-mode interrupts — we are not ready for them yet. */
    csrw sie, zero

    /* Zero the BSS section (Rust relies on this). */
    la   t0, __bss_start
    la   t1, __bss_end
    bgeu t0, t1, .Lbss_done
.Lbss_loop:
    sd   zero, (t0)
    addi t0,   t0, 8
    bltu t0,   t1, .Lbss_loop
.Lbss_done:

    /*
     * Call kernel_main(hart_id: usize, fdt_addr: usize).
     * a0 and a1 still hold the values OpenSBI placed there.
     */
    call kernel_main

    /* kernel_main must never return; halt if it does. */
.Lhalt:
    wfi
    j    .Lhalt

.Lhart_park:
    wfi
    j    .Lhart_park

    /*
     * Minimal trap stub — direct mode (stvec[1:0] = 0).
     * Must be 4-byte aligned.  Just spins; the UART is not yet
     * initialised at the point this could fire.
     */
    .align 2
.Ltrap_stub:
    wfi
    j    .Ltrap_stub

/*
 * Secondary hart entry point — called by SBI HSM HART_START.
 *   a0 = hart ID
 *   a1 = opaque (unused; we pass 0)
 *
 * Sets up a per-hart stack and calls secondary_main(hart_id).
 */
    .global  _start_hart
    .type    _start_hart, @function
_start_hart:
    /* Store hart ID in sscratch so current_hart() works from trap context. */
    csrw sscratch, a0

    /* Per-hart kernel stack: __hart_stacks_top - hart_id * 16384. */
    la   sp, __hart_stacks_top
    li   t0, 16384
    mul  t0, a0, t0
    sub  sp, sp, t0

    /* Minimal trap stub until secondary_main installs the real stvec. */
    la   t1, .Ltrap_stub
    csrw stvec, t1

    /* Disable interrupts until secondary_main enables them. */
    csrw sie, zero

    /* call secondary_main(hart_id); a0 still holds hart ID. */
    call secondary_main

.Lhalt_secondary:
    wfi
    j    .Lhalt_secondary

/*
 * Permanent kernel idle loop — used as the fallback sret target when
 * switch_to_next has no runnable thread and no saved boot frame.
 * Must be in S-mode (SPP=1 in the idle TrapFrame) so sret returns here
 * instead of back to user space.
 */
    .global _kernel_idle
_kernel_idle:
.Lki_wfi:
    wfi
    j .Lki_wfi
