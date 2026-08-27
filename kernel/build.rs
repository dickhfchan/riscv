use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // ── Kernel linker script ──────────────────────────────────────────────────
    println!("cargo:rustc-link-arg=-T{manifest_dir}/linker.ld");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=src/arch/riscv64/boot.S");
    println!("cargo:rerun-if-changed=src/arch/riscv64/trap.S");

    let workspace_dir = Path::new(&manifest_dir).parent().unwrap();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());

    // ── Build the init process (Phase 8) ─────────────────────────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "init");

    // ── Build the IPC server and client (Phase 9) ─────────────────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "server");
    build_elf(&rustc, workspace_dir, &out_dir, "client");

    // ── Build the ReplyRecv server (Phase 10) ─────────────────────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "server_rr");

    // ── Build the shared-memory writer and reader (Phase 11) ──────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "shm_writer");
    build_elf(&rustc, workspace_dir, &out_dir, "shm_reader");

    // ── Build the userspace endpoint-creation demo (Phase 12) ─────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "ep_a");
    build_elf(&rustc, workspace_dir, &out_dir, "ep_b");

    // ── Build the per-process CSpace probes (Phase 13) ────────────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "cspace_a");
    build_elf(&rustc, workspace_dir, &out_dir, "cspace_b");

    // ── Build the IPC cap-transfer demo (Phase 14) ────────────────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "cap_grantor");
    build_elf(&rustc, workspace_dir, &out_dir, "cap_grantee");

    // ── Build the TTY test process (Phase 15) ─────────────────────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "tty_test");

    // ── Build the ramfs demo (Phase 16) ───────────────────────────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "fs_demo");

    // ── Build the process spawn demo (Phase 17) ────────────────────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "spawn_demo");

    // ── Build the InitCaps verification binary (Phase 20) ─────────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "init_icaps");

    // ── Build the Linux ABI self-test (Phases A1–A5) ──────────────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "linux_demo");

    // ── Build the interactive shell ───────────────────────────────────────────
    build_elf(&rustc, workspace_dir, &out_dir, "shell");
}

fn build_elf(rustc: &str, workspace_dir: &Path, out_dir: &Path, name: &str) {
    let dir    = workspace_dir.join(name);
    let elf    = out_dir.join(format!("{name}.elf"));
    let linker = dir.join("linker.ld");
    let src    = dir.join("src/main.rs");

    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", linker.display());

    let status = Command::new(rustc)
        .args([
            "--edition", "2021",
            "--target", "riscv64gc-unknown-none-elf",
            "-C", "relocation-model=static",
            "-C", "code-model=medium",
            "-C", &format!("link-arg=-T{}", linker.display()),
            "-C", "target-feature=+zba,+zbb,+zbs",
            "-C", "opt-level=2",
            "-C", "panic=abort",
            "--crate-type", "bin",
            "--crate-name", name,
            "-o", elf.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .status()
        .unwrap_or_else(|_| panic!("failed to invoke rustc for {name}"));

    assert!(status.success(), "{name} build failed");

    // Export the ELF path so kernel/src/main.rs can include_bytes! it.
    let env_key = format!("{}_ELF_PATH", name.to_uppercase());
    println!("cargo:rustc-env={env_key}={}", elf.display());
}
