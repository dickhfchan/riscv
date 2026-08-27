/*
 * Memory management subsystem — Phase 2.
 *
 * Initialises the buddy allocator from the FDT memory map, excluding
 * the kernel image, OpenSBI firmware, and the FDT blob itself.
 */

pub mod buddy;
pub mod slab;

use buddy::{BuddyAllocator, PAGE_SIZE};
use crate::println;

// Global buddy allocator — single-hart, no locks in Phase 2.
static mut BUDDY: BuddyAllocator = BuddyAllocator::new();

extern "C" {
    // End of the kernel image (from linker script).
    static __kernel_end: u8;
}

/// Initialise physical memory management.
///
/// `fdt_addr` — physical address of the FDT blob (from OpenSBI / boot.S).
pub fn init(fdt_addr: usize) {
    let kernel_end = core::ptr::addr_of!(__kernel_end) as usize;
    let kernel_end_page = align_up(kernel_end, PAGE_SIZE);

    // Parse the FDT for memory regions.
    let fdt = unsafe {
        fdt::Fdt::from_ptr(fdt_addr as *const u8)
    }
    .expect("invalid FDT");

    println!("  [MM] Physical memory map:");
    for region in fdt.memory().regions() {
        let start = region.starting_address as usize;
        let size  = match region.size { Some(s) if s > 0 => s, _ => continue };
        let end   = start + size;

        println!("       [{:#010x} – {:#010x}]  {} MiB",
            start, end - 1, size >> 20);

        // Free region: skip anything below kernel_end (kernel + OpenSBI).
        let free_start = kernel_end_page.max(start);
        // Skip the FDT region (keep a 4 MiB buffer around it).
        let fdt_guard_start = align_down(fdt_addr, 4 << 20);
        let free_end        = end.min(fdt_guard_start);

        println!("  [MM] fdt_addr   : {:#010x}  guard: {:#010x}  free_end: {:#010x}",
            fdt_addr, fdt_guard_start, free_end);

        if free_start < free_end {
            // Safety: single-hart boot, no concurrent access.
            unsafe { (&raw mut BUDDY).as_mut().unwrap().add_region(free_start, free_end) };
        }
    }

    let buddy = unsafe { (&raw const BUDDY).as_ref().unwrap() };
    println!("  [MM] Kernel end : {:#010x}", kernel_end);
    println!("  [MM] Free pages : {} ({} MiB)",
        buddy.free_pages, buddy.free_pages * PAGE_SIZE >> 20);
    println!("  [MM] Total pages: {} ({} MiB)",
        buddy.total_pages, buddy.total_pages * PAGE_SIZE >> 20);
}

fn buddy_mut() -> &'static mut BuddyAllocator {
    // Safety: called only from single-hart boot context.
    unsafe { (&raw mut BUDDY).as_mut().unwrap() }
}

/// Allocate one 4 KiB page. Returns physical address.
pub fn alloc_page() -> Option<usize> {
    buddy_mut().alloc(0)
}

/// Free one 4 KiB page at physical address `pa`.
pub fn free_page(pa: usize) { buddy_mut().free(pa, 0) }

/// Allocate 2^order pages. Returns physical address.
pub fn alloc_pages(order: usize) -> Option<usize> { buddy_mut().alloc(order) }

/// Free 2^order pages at physical address `pa`.
pub fn free_pages(pa: usize, order: usize) { buddy_mut().free(pa, order) }

/// Slab-allocate a zeroed cell large enough for `size` bytes. Returns PA.
pub fn slab_alloc(size: usize) -> Option<usize> { slab::alloc(size) }

/// Return a slab cell to its cache. `size` must match the original alloc.
pub fn slab_free(pa: usize, size: usize) { slab::free(pa, size) }

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}
