# Ferrite OS — RISC-V RVA23 Microkernel Specification

> A capability-based microkernel written in Rust, targeting the RISC-V RVA23 profile,
> with BSD-equivalent services running as isolated userspace servers.

---

## 1. Project Identity

| Field        | Value                          |
|-------------|-------------------------------|
| Name         | Ferrite                        |
| Kernel type  | Microkernel (L4-style)         |
| Language     | Rust (no_std, nightly)         |
| ISA target   | `riscv64gc` — RVA23 profile    |
| License      | BSD 2-Clause                   |
| Inspiration  | FreeBSD, seL4, Redox OS        |

---

## 2. Target Architecture: RISC-V RVA23 Profile

### 2.1 Mandatory ISA Extensions (RVA23U64 + RVA23S64)

| Group          | Extensions |
|----------------|------------|
| Base           | RV64I      |
| Arithmetic     | M (mul/div), F (float32), D (float64), Zfhmin (float16 min) |
| Atomics        | A, Zacas (cmp-and-swap), Zawrs (wait-on-reservation), Ziccamoa |
| Compressed     | C, Zca, Zcb, Zcd |
| Bit manip      | Zba, Zbb, Zbs |
| CSR / hints    | Zicsr, Zicntr, Zihpm, Zihintpause, Zicclsm |
| Vector         | V (VLEN≥128), Zvfhmin, Zvkn (crypto) |
| Supervisor     | Sstc (supervisor timer), Sscofpmf, Svnapot, Svpbmt, Svinval, Svadu |
| Hypervisor     | H (optional, for Type-1 VM hosting) |
| Security       | Smstateen / Ssstateen / Shstateen |

### 2.2 Privilege Levels Used

```
M-mode  — OpenSBI firmware (not Ferrite)
S-mode  — Ferrite kernel
U-mode  — All servers and applications
```

### 2.3 Paging

- Sv48 (4-level, 48-bit VA) as default; Sv57 optional via boot flag
- Huge pages: 4 KB, 2 MB, 1 GB, 512 GB
- Svpbmt: I/O and non-cacheable mappings
- Svnapot: natural-aligned power-of-two pages for device MMIO
- Svinval: fine-grained TLB shootdown (SINVAL.VMA / SFENCE.W.INVAL)

### 2.4 Boot Environment

- OpenSBI (>= 1.5) provides M-mode runtime; kernel enters at S-mode
- Boot protocol: RISC-V SBI + Devicetree (FDT) passed in `a1`
- Multiprocessor: SBI HSM extension for hart lifecycle

---

## 3. Microkernel Architecture

### 3.1 Core Principle

The kernel provides **four primitives only**:

1. **Address Spaces** — virtual memory regions
2. **Threads** — units of execution
3. **IPC Endpoints** — synchronous message-passing channels
4. **Capabilities** — unforgeable tokens authorising operations on any object

Everything else (filesystems, networking, device drivers, POSIX emulation) lives in
**userspace servers** communicating via IPC.

### 3.2 Kernel Object Taxonomy

```
KObject
├── Thread          — hart-scheduled execution unit
├── AddressSpace    — page-table root + region list
├── Endpoint        — IPC rendezvous point (sync)
├── Notification    — async signal word (like seL4 Notification)
├── CNode           — capability table (tree node)
├── UntypedMemory   — raw physical memory capability
├── Frame           — 4KB–1GB physical frame
├── PageTable       — intermediate PT node
├── IRQControl      — authority to claim hardware interrupts
├── IRQHandler      — per-interrupt capability
└── IOPort          — MMIO region capability (future)
```

### 3.3 Capability System

- Capabilities stored in **CNodes** (radix trees, fan-out configurable)
- Operations: `Invoke`, `Copy`, `Move`, `Mint` (derive with fewer rights), `Delete`, `Revoke`
- Rights bits per capability: `Read | Write | Grant | GrantReply | Call`
- No ambient authority — root task bootstraps from `InitCaps` passed at load

---

## 4. Kernel Subsystems

### 4.1 Memory Manager

| Component           | Detail |
|--------------------|--------|
| Physical allocator  | Buddy allocator (order 0–18, i.e. 4 KB – 1 GB) |
| Kernel heap         | Slab allocator for fixed KObject sizes; `linked_list_allocator` fallback |
| Virtual kernel map  | Direct-map of all RAM at `0xFFFF_FFC0_0000_0000` (top 512 GB) |
| User-space VM       | Each AddressSpace holds a `BTreeMap<VAddr, Region>` |
| CoW                 | Copy-on-write fork via page fault + frame refcount |
| Demand paging       | Faults forwarded to the owning pager server via IPC |

### 4.2 Scheduler

| Property          | Value |
|------------------|-------|
| Algorithm         | Multi-level feedback queue (MLFQ), 32 priority bands |
| Quantum           | Configurable per-thread, default 1 ms |
| SMP               | Per-hart run queues + work-stealing |
| Real-time         | Fixed-priority preemptive band (bands 0–7) |
| Timer source      | Sstc — `stimecmp` CSR, no SBI_TIME needed |
| Idle              | `WFI` + Zawrs `wrs.sto` |

### 4.3 IPC

| Mechanism         | Detail |
|------------------|--------|
| Synchronous call  | `seL4`-style fastpath: register transfer, 0-copy for ≤8 words |
| Shared memory     | Grant `Frame` capabilities into remote AddressSpace |
| Async signals     | `Notification` objects; `Signal` / `Wait` syscalls |
| Large transfers   | Capability-passed shared frames (zero-copy bulk) |
| Max message size  | 64 words (512 bytes) in registers + unlimited via shared frames |

### 4.4 Interrupt Handling

- Kernel claims PLIC / APLIC (AIA) at boot via devicetree
- Per-interrupt `IRQHandler` capability issued to driver servers
- Driver ACKs interrupt via `IRQHandler.Ack` syscall after servicing
- MSI/MSI-X supported via AIA IMSIC (one IMSIC per hart)

---

## 5. Syscall Interface

### 5.1 Encoding

```
a0  = capability index (CNode slot)
a1  = invocation label (operation)
a2–a7 = message words 0–5
```

Return: `a0 = error code`, `a1–a7 = reply words`.

### 5.2 Syscall Table

| Number | Name           | Description |
|--------|---------------|-------------|
| 0      | `Call`         | Send + recv on endpoint (blocking) |
| 1      | `Send`         | Send only (non-blocking if possible) |
| 2      | `Recv`         | Receive on endpoint |
| 3      | `Reply`        | Reply to saved caller |
| 4      | `ReplyRecv`    | Atomic reply + next recv |
| 5      | `Yield`        | Voluntary scheduler yield |
| 6      | `Wait`         | Block on Notification |
| 7      | `Signal`       | Signal a Notification |
| 8      | `CapOp`        | Copy / Move / Mint / Delete / Revoke cap |
| 9      | `Identify`     | Debug: return object type for cap slot |
| 10     | `DebugPutChar` | (debug build only) UART output |

---

## 6. Userspace Servers (BSD-equivalent services)

Each server is a standalone Rust binary linked against `libferrite` (the IPC runtime).

### 6.1 Process Manager (`init` / `proc_server`)

Responsibilities mirror BSD `kern/kern_proc.c`:
- `fork`, `exec`, `exit`, `wait4`
- Process group / session / controlling terminal
- Signal delivery (POSIX signals via IPC notification)
- `getpid`, `getppid`, `getuid`, `setuid`, credentials
- Resource limits (`rlimit`)

### 6.2 Virtual Memory Server (`vm_server`)

Mirrors BSD `vm/` subsystem:
- `mmap`, `munmap`, `mprotect`, `madvise`, `mincore`
- Anonymous and file-backed mappings
- `brk` / `sbrk` heap management
- Page fault handler (pager protocol with kernel)
- `shm_open`, `shm_unlink` POSIX shared memory

### 6.3 Virtual Filesystem Server (`vfs_server`)

Mirrors BSD `vfs/`:
- VFS layer: vnode operations, mount table
- Namei / path resolution
- File descriptors, `open`, `read`, `write`, `close`, `ioctl`, `fcntl`
- `stat`, `fstat`, `lstat`, `chmod`, `chown`
- Pluggable filesystem backends (each a sub-server)

#### 6.3.1 Filesystem Sub-Servers

| Server        | Equivalent      | Formats |
|--------------|----------------|---------|
| `tmpfs`       | BSD `tmpfs`     | RAM-backed |
| `ffs_server`  | BSD UFS/FFS     | UFS2 on-disk |
| `ext4_server` | ext2/3/4        | Linux compat |
| `fat_server`  | MSDOSFS         | FAT12/16/32/exFAT |
| `devfs`       | BSD `devfs`     | Device namespace |
| `procfs`      | BSD `procfs`    | `/proc` |
| `nfs_client`  | BSD NFS v3/v4   | Network |

### 6.4 Network Stack (`net_server`)

Mirrors BSD `netinet/`, `netinet6/`, `net/`:
- Ethernet, ARP, IP v4/v6
- TCP (CUBIC congestion control), UDP, ICMP
- BSD socket API: `socket`, `bind`, `connect`, `listen`, `accept`, `send*`, `recv*`
- `select` / `poll` / `kqueue` (via Notification objects)
- PF firewall (ported from OpenBSD PF)
- `route`, `arp` management

### 6.5 Device Servers

| Server         | Devices                         | Protocol |
|---------------|---------------------------------|---------|
| `uart_server`  | 16550 / SiFive UART             | IRQHandler cap |
| `virtio_server`| virtio-blk, virtio-net, virtio-rng | MMIO cap |
| `pcie_server`  | PCIe root complex, ECAM         | MMIO cap + MSI |
| `usb_server`   | XHCI                            | MMIO cap + MSI |
| `gpio_server`  | SoC GPIO banks                  | MMIO cap |
| `i2c_server`   | I²C buses                       | MMIO cap |
| `spi_server`   | SPI buses                       | MMIO cap |
| `rtc_server`   | RTC / CLOCK_REALTIME            | MMIO cap |
| `dma_server`   | IOMMU / SMMU coordination       | MMIO cap |

### 6.6 Security Server (`sec_server`)

- MAC framework (mirrors BSD `security/mac/`)
- Jails: namespace isolation (UID map, filesystem root, network namespace)
- Capsicum: capability-mode `cap_enter()`, capability rights on fd
- Pledge-style syscall restriction layer on top of IPC filtering

### 6.7 Audit Server (`audit_server`)

- BSM audit trail (mirrors BSD `security/audit/`)
- Audit records sent via IPC to server; written to `audit.log`
- `auditctl`, `auditon` compatible interface

### 6.8 POSIX Compatibility Library (`libposix`)

- Thin shim library linked into every application
- Translates libc calls → IPC messages to appropriate servers
- Provides `errno`, POSIX thread primitives (pthreads over kernel threads)
- Compatible with FreeBSD 14 ABI (goal: run unmodified BSD binaries with relink)

---

## 7. Boot Sequence

```
1. OpenSBI (M-mode)
   └─ loads kernel ELF into RAM, jumps to S-mode entry

2. Ferrite entry (_start.S)
   ├─ set up satp (Sv48), enable paging
   ├─ set up kernel stack per hart
   ├─ parse FDT → memory map, PLIC base, UART base
   └─ call kernel_main()

3. kernel_main()
   ├─ initialise buddy allocator
   ├─ initialise slab allocator
   ├─ initialise CNode tree (root CNode)
   ├─ initialise scheduler
   ├─ initialise PLIC / AIA
   ├─ load init_server ELF (embedded in kernel image)
   └─ transfer control to init_server in U-mode

4. init_server
   ├─ spawns proc_server, vm_server, vfs_server, net_server
   ├─ mounts tmpfs on /
   ├─ mounts devfs on /dev
   ├─ starts uart_server, virtio_server
   ├─ mounts ffs_server on /usr (from virtio-blk)
   └─ exec /sbin/init (BSD-compatible init)
```

---

## 8. Memory Layout (64-bit VA)

```
0x0000_0000_0000_0000  –  0x0000_007F_FFFF_FFFF   User space (128 GB per process)
0xFFFF_FF00_0000_0000  –  0xFFFF_FF7F_FFFF_FFFF   Kernel direct-map (all RAM)
0xFFFF_FF80_0000_0000  –  0xFFFF_FFBF_FFFF_FFFF   Kernel heap / vmalloc
0xFFFF_FFC0_0000_0000  –  0xFFFF_FFDF_FFFF_FFFF   Kernel code + data (linked here)
0xFFFF_FFE0_0000_0000  –  0xFFFF_FFFF_FFFF_FFFF   Per-hart stacks + guard pages
```

---

## 9. Source Tree Layout

```
ferrite/
├── kernel/                  # S-mode microkernel (no_std)
│   ├── src/
│   │   ├── main.rs          # kernel_main entry
│   │   ├── arch/riscv64/    # arch-specific code
│   │   │   ├── boot.S       # _start, trap vector
│   │   │   ├── csr.rs       # CSR wrappers
│   │   │   ├── mmu.rs       # Sv48 page table
│   │   │   ├── trap.rs      # exception / interrupt dispatch
│   │   │   ├── sbi.rs       # SBI call wrappers
│   │   │   └── timer.rs     # Sstc stimecmp
│   │   ├── mm/
│   │   │   ├── buddy.rs     # physical allocator
│   │   │   ├── slab.rs      # kernel object allocator
│   │   │   └── vm.rs        # address space management
│   │   ├── cap/
│   │   │   ├── cnode.rs     # capability table
│   │   │   ├── rights.rs    # rights bits
│   │   │   └── invoke.rs    # cap dispatch
│   │   ├── sched/
│   │   │   ├── mlfq.rs      # MLFQ scheduler
│   │   │   └── smp.rs       # per-hart queues
│   │   ├── ipc/
│   │   │   ├── endpoint.rs  # sync IPC
│   │   │   └── notification.rs
│   │   └── irq/
│   │       ├── plic.rs
│   │       └── aia.rs
│   ├── Cargo.toml
│   └── linker.ld
│
├── servers/                 # Userspace servers (std-ish, uses libferrite)
│   ├── init/
│   ├── proc_server/
│   ├── vm_server/
│   ├── vfs_server/
│   │   └── backends/
│   │       ├── tmpfs/
│   │       ├── ffs/
│   │       └── devfs/
│   ├── net_server/
│   ├── uart_server/
│   └── virtio_server/
│
├── libs/
│   ├── libferrite/          # IPC runtime + syscall wrappers
│   ├── libposix/            # POSIX shim over IPC
│   └── libdtb/              # FDT / devicetree parser
│
├── tools/
│   ├── mkimage/             # pack kernel + servers into boot image
│   └── capvis/              # capability graph visualiser
│
├── xtask/                   # cargo xtask build automation
│   └── src/main.rs
│
├── Cargo.toml               # workspace root
└── .cargo/config.toml       # riscv64gc target, linker flags
```

---

## 10. Toolchain & Build Requirements

| Tool                   | Version / Notes |
|-----------------------|----------------|
| Rust (nightly)         | `nightly-2025-07` or later; `riscv64gc-unknown-none-elf` target |
| LLVM / clang           | ≥ 18 (for assembly in kernel) |
| OpenSBI                | ≥ 1.5 (M-mode firmware) |
| QEMU                   | ≥ 9.0 (`-machine virt`, `-cpu rv64,v=true,h=true`) |
| cargo-binutils         | `objcopy`, `objdump` for ELF manipulation |
| dtc                    | Devicetree compiler (DTB generation) |
| gdb-multiarch          | Debugging via QEMU GDB stub |

### Cargo targets

```toml
# .cargo/config.toml
[build]
target = "riscv64gc-unknown-none-elf"

[target.riscv64gc-unknown-none-elf]
rustflags = [
  "-C", "target-feature=+m,+a,+f,+d,+c,+v,+zba,+zbb,+zbs,+zicsr,+zifencei",
  "-C", "relocation-model=static",
  "-C", "code-model=medium",
]
```

---

## 11. Key Rust Crates

| Crate               | Purpose |
|--------------------|---------|
| `riscv` (0.11+)     | CSR access macros |
| `fdt` (0.1+)        | FDT parser (no_std) |
| `linked_list_allocator` | Fallback heap |
| `spin`              | Spinlocks / once cells |
| `bitflags`          | Capability rights, page flags |
| `zerocopy`          | Safe transmutation for IPC messages |
| `smoltcp`           | TCP/IP stack base for net_server |
| `async-executor`    | Cooperative async in servers |
| `virtio-drivers`    | VirtIO device abstractions |

---

## 12. Development Phases

### Phase 1 — Bare Metal Boot (Milestone: UART output in S-mode)
- [ ] Workspace + `.cargo/config.toml` setup
- [ ] `boot.S`: enter S-mode, set `mtvec`, set `satp=0`
- [ ] UART 16550 driver (direct MMIO, no_std)
- [ ] Basic `println!` macro over UART
- [ ] Rust panic handler

### Phase 2 — Memory Management
- [ ] FDT parser → extract memory regions
- [ ] Buddy physical allocator
- [ ] Sv48 page table builder
- [ ] Enable paging, set up kernel direct-map
- [ ] Slab allocator for fixed-size kernel objects

### Phase 3 — Capability System
- [ ] CNode data structure (radix tree)
- [ ] `UntypedMemory` → retype to other objects
- [ ] Rights bits, `Mint` / `Copy` / `Delete` / `Revoke`
- [ ] Syscall dispatch via `ecall` trap handler

### Phase 4 — Threads & Scheduler
- [ ] Thread object: register save/restore, stack allocation
- [ ] MLFQ scheduler (single hart)
- [ ] `stimecmp` (Sstc) timer interrupt for preemption
- [ ] SMP: per-hart run queues + IPI-based wake (SBI IPI)

### Phase 5 — IPC
- [ ] Endpoint: synchronous Call / Send / Recv fastpath
- [ ] Notification: Signal / Wait
- [ ] Capability transfer in IPC messages
- [ ] Reply capability pattern

### Phase 6 — Interrupt Delegation
- [ ] PLIC initialisation from FDT
- [ ] `IRQControl` / `IRQHandler` capability objects
- [ ] AIA / APLIC + IMSIC for MSI (optional)

### Phase 7 — init Server & Process Bootstrap
- [ ] ELF loader in kernel (loads init)
- [ ] `InitCaps` passed to init (UntypedMemory pool, IRQControl, UART frame)
- [ ] `init` spawns child servers via `proc_server`

### Phase 8 — Userspace Servers (BSD Services)
- [ ] `proc_server`: fork/exec/exit/wait
- [ ] `vm_server`: mmap/munmap/pager protocol
- [ ] `vfs_server` + `tmpfs` + `devfs`
- [ ] `uart_server` (terminal, `/dev/ttyS0`)
- [ ] `virtio_server` (blk + net)
- [ ] `net_server` (smoltcp-based, BSD socket API)
- [ ] `ffs_server` (UFS2 read-write)

### Phase 9 — POSIX Compatibility
- [ ] `libposix`: map libc → IPC calls
- [ ] `libpthread`: POSIX threads over kernel threads
- [ ] `kqueue` / `poll` / `select` via Notification
- [ ] Run `/bin/sh` (statically linked)

### Phase 10 — Security & Hardening
- [ ] `sec_server`: Jails + Capsicum
- [ ] MAC framework hooks in VFS / net
- [ ] KASLR (randomise kernel load address)
- [ ] Stack canaries + shadow stack (Zicfiss, when available)
- [ ] W^X enforcement on all mappings

---

## 13. Testing Strategy

| Layer          | Tool / Method |
|---------------|---------------|
| Unit tests     | `cargo test` (host, miri for unsafe) |
| Kernel tests   | QEMU + custom test harness, serial output parsed |
| IPC fuzzing    | `libAFL` target injecting malformed IPC messages |
| SMP stress     | QEMU `-smp 4`, lock-order checker |
| POSIX conformance | LTP (Linux Test Project) subset on `libposix` |
| Performance    | `lmbench`, `sysbench` under QEMU |

---

## 14. Conformance Goals

| Standard              | Target                              |
|----------------------|-------------------------------------|
| RISC-V RVA23         | Full mandatory profile compliance   |
| POSIX.1-2017         | Core subset via libposix            |
| FreeBSD 14 syscall ABI | Binary compat with relink         |
| SBI v2               | Full (base + TIME + IPI + HSM + SRST + PMU) |
| OpenSBI 1.5+         | Firmware interface                  |

---

## 15. Non-Goals (Explicit Exclusions)

- x86, ARM, or other ISA support (RISC-V RVA23 only)
- Monolithic kernel mode
- Linux ABI / syscall compatibility
- GUI / graphics (no DRM/KMS in scope)
- Cryptographic library (delegate to userspace `libcrypto`)
