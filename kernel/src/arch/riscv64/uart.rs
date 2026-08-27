/*
 * NS16550A UART driver — MMIO, polling (no interrupts in Phase 1).
 *
 * QEMU virt machine places the first UART at 0x10000000.
 * Real hardware: override UART_BASE from the FDT in Phase 2.
 */

use core::fmt;

const UART_BASE: usize = 0x1000_0000;

/* 16550A register offsets (each register is 1 byte wide) */
const THR: usize = 0; /* Transmit Holding Register     (W, DLAB=0) */
const IER: usize = 1; /* Interrupt Enable Register      (RW)        */
const FCR: usize = 2; /* FIFO Control Register          (W)         */
const LCR: usize = 3; /* Line Control Register           (RW)        */
const MCR: usize = 4; /* Modem Control Register          (RW)        */
const LSR: usize = 5; /* Line Status Register            (R)         */
const DLL: usize = 0; /* Divisor Latch LSB (DLAB=1)                 */
const DLH: usize = 1; /* Divisor Latch MSB (DLAB=1)                 */

/* LSR bits */
const LSR_THR_EMPTY: u8 = 1 << 5; /* TX holding register empty — safe to write */
const LSR_DATA_READY: u8 = 1 << 0; /* RX data available in RHR */

#[inline(always)]
fn write_reg(reg: usize, val: u8) {
    unsafe { ((UART_BASE + reg) as *mut u8).write_volatile(val) }
}

#[inline(always)]
fn read_reg(reg: usize) -> u8 {
    unsafe { ((UART_BASE + reg) as *const u8).read_volatile() }
}

/// Initialise the 16550A for 115200 8N1.
///
/// QEMU ignores the baud divisor (no real serial link), but setting it
/// correctly makes the driver portable to real SiFive/StarFive hardware
/// that uses a 1,843,200 Hz reference clock:
///   divisor = 1,843,200 / (16 × 115200) = 1
pub fn init() {
    write_reg(IER, 0x00); /* disable all interrupts             */
    write_reg(LCR, 0x80); /* set DLAB to access divisor latches */
    write_reg(DLL, 0x01); /* divisor LSB (115200 @ 1.8432 MHz)  */
    write_reg(DLH, 0x00); /* divisor MSB                         */
    write_reg(LCR, 0x03); /* 8 data bits, 1 stop, no parity; clear DLAB */
    write_reg(FCR, 0x07); /* enable + reset TX/RX FIFOs, 1-byte trigger */
    write_reg(MCR, 0x03); /* assert DTR and RTS                  */
    write_reg(IER, 0x00); /* keep interrupts disabled            */
}

/// True if a received byte is waiting in the RHR.
pub fn data_ready() -> bool {
    read_reg(LSR) & LSR_DATA_READY != 0
}

/// Read one byte from the Receive Holding Register (caller must check data_ready first).
pub fn read_byte() -> u8 {
    read_reg(0) // RHR is at offset 0 (same as THR, selected by direction)
}

/// Enable the Received Data Available interrupt (ERBFI = IER bit 0).
pub fn enable_rx_interrupt() {
    write_reg(IER, 0x01); // ERBFI only; THRE stays off
}

/// Enable the Transmitter Holding Register Empty (THRE) interrupt.
/// The UART asserts this interrupt (and IRQ 10 on QEMU virt) whenever the
/// transmit holding register is empty — which is almost immediately.
pub fn enable_thre_interrupt() {
    write_reg(IER, 0x02); // ETBEI bit
}

/// Disable all UART interrupts (safe to call from S-mode at any time).
pub fn disable_interrupts() {
    write_reg(IER, 0x00);
}

/// Write one byte, polling until the TX holding register is free.
pub fn putchar(byte: u8) {
    while read_reg(LSR) & LSR_THR_EMPTY == 0 {
        core::hint::spin_loop();
    }
    write_reg(THR, byte);
}

/// Block until a byte arrives in the RHR, then return it.
pub fn getchar_blocking() -> u8 {
    loop {
        if read_reg(LSR) & LSR_DATA_READY != 0 {
            return read_reg(0); // RHR at offset 0
        }
        core::hint::spin_loop();
    }
}

/// Zero-size writer that routes `core::fmt::Write` to the UART.
pub struct UartWriter;

impl fmt::Write for UartWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &byte in s.as_bytes() {
            if byte == b'\n' {
                putchar(b'\r'); /* CR+LF for terminal compatibility */
            }
            putchar(byte);
        }
        Ok(())
    }
}
