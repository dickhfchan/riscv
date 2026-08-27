/*
 * Ferrite OS kernel linker script — RV64 (Sv48)
 *
 * OpenSBI (M-mode) loads us at 0x80200000 and jumps here in S-mode.
 * a0 = hart ID, a1 = FDT physical address.
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

BASE_ADDRESS = 0x80200000;

SECTIONS
{
    . = BASE_ADDRESS;

    /* ---- text ---- */
    .text : ALIGN(4) {
        /* _start must be the very first instruction */
        *(.text.entry)
        *(.text .text.*)
    }

    . = ALIGN(4096);

    /* ---- read-only data ---- */
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }

    . = ALIGN(4096);

    /* ---- data ---- */
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    . = ALIGN(4096);

    /* ---- zero-initialised data ---- */
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        . = ALIGN(8);
        __bss_end = .;
    }

    . = ALIGN(4096);

    /* ---- boot stack: 64 KiB ---- */
    .boot_stack (NOLOAD) : {
        . += 64K;
        __boot_stack_top = .;
    }

    /* ---- secondary-hart stacks: 16 KiB each × 3 harts (harts 1-3) ---- */
    .hart_stacks (NOLOAD) : {
        __hart_stacks_base = .;
        . += 16K * 3;
        __hart_stacks_top = .;
    }

    /* ---- kernel end marker ---- */
    __kernel_end = .;

    /* Discard DWARF exception tables; we use panic=abort */
    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
    }
}
