KERNEL_ELF  := target/riscv64gc-unknown-none-elf/debug/ferrite-kernel
KERNEL_BIN  := target/riscv64gc-unknown-none-elf/debug/ferrite-kernel.bin

QEMU        := qemu-system-riscv64
QEMU_ARGS   := -machine virt \
               -cpu rv64 \
               -m 256M \
               -nographic \
               -bios default \
               -kernel $(KERNEL_ELF)

GDB_PORT    := 1234

.PHONY: build run shell debug clean

build:
	~/.cargo/bin/cargo build

run: build
	$(QEMU) $(QEMU_ARGS)

# Interactive shell: same as run but stdin is connected so you can type.
# The kernel seeds the RX buffer for `make run`; for `make shell` type your own input.
shell: build
	$(QEMU) $(QEMU_ARGS)

# Launch QEMU paused, waiting for GDB on port 1234.
debug: build
	$(QEMU) $(QEMU_ARGS) -S -gdb tcp::$(GDB_PORT) &
	riscv64-unknown-elf-gdb -ex "target remote :$(GDB_PORT)" $(KERNEL_ELF)

# Strip to raw binary (useful for some bootloaders).
bin: build
	llvm-objcopy -O binary $(KERNEL_ELF) $(KERNEL_BIN)

clean:
	cd kernel && cargo clean
