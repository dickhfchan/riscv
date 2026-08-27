/* Ferrite OS — init_icaps process linker script.
 * Loaded into a fresh per-process VSpace by the kernel ELF loader.
 * Base at 0x10000 to leave the zero page unmapped (NULL-pointer protection). */

OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS {
    . = 0x10000;

    .text : ALIGN(4) {
        KEEP(*(.text.entry))   /* _start must be first */
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
