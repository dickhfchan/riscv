// Process ELF registry — Phase 17.
//
// Maps process names to their embedded ELF byte slices so PROC_SPAWN can
// load any registered process by name from a userspace ecall.

static INIT_BYTES:       &[u8] = include_bytes!(env!("INIT_ELF_PATH"));
static SPAWN_DEMO_BYTES: &[u8] = include_bytes!(env!("SPAWN_DEMO_ELF_PATH"));
static LINUX_DEMO_BYTES: &[u8] = include_bytes!(env!("LINUX_DEMO_ELF_PATH"));

pub fn find_elf(name: &[u8]) -> Option<&'static [u8]> {
    match name {
        b"init"       => Some(INIT_BYTES),
        b"spawn_demo" => Some(SPAWN_DEMO_BYTES),
        b"linux_demo" => Some(LINUX_DEMO_BYTES),
        _ => None,
    }
}
