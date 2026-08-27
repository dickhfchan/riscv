/* Ferrite OS — server process linker script (Phase 9). */

OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS {
    . = 0x10000;

    .text : ALIGN(4) {
        KEEP(*(.text.entry))
        *(.text .text.*)
    }

    . = ALIGN(4096);

    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }

    . = ALIGN(4096);

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    . = ALIGN(4096);

    .bss (NOLOAD) : {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
    }

    /DISCARD/ : { *(.eh_frame) *(.eh_frame_hdr) }
}
