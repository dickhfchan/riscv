// Slab allocator — Phase 18.
//
// Three fixed size-classes: 16 B (Notification), 32 B (Endpoint), 512 B (TCB).
// Each slab is one 4 KiB buddy page divided into equal cells.
// Free cells form an intrusive singly-linked list: the first 8 bytes of every
// free cell hold the PA of the next free cell (0 = end of list).
//
// No lock needed: SIE=0 while we are in the trap / syscall path.

use crate::mm;

const CLASSES: [usize; 3] = [16, 32, 512];

struct SlabCache {
    free_head: usize,
    cell_size: usize,
}

impl SlabCache {
    const fn new(cell_size: usize) -> Self {
        Self { free_head: 0, cell_size }
    }

    fn alloc(&mut self) -> Option<usize> {
        if self.free_head == 0 { self.grow()?; }
        let cell = self.free_head;
        self.free_head = unsafe { *(cell as *const usize) };
        // Zero the cell before handing it out.
        unsafe { core::ptr::write_bytes(cell as *mut u8, 0, self.cell_size); }
        Some(cell)
    }

    fn free(&mut self, pa: usize) {
        unsafe { *(pa as *mut usize) = self.free_head; }
        self.free_head = pa;
    }

    fn grow(&mut self) -> Option<()> {
        let page_pa = mm::alloc_page()?;
        let n = 4096 / self.cell_size;
        // Build free list in reverse order so the head ends up at the lowest PA.
        let mut prev = 0usize;
        for i in (0..n).rev() {
            let cell = page_pa + i * self.cell_size;
            unsafe { *(cell as *mut usize) = prev; }
            prev = cell;
        }
        self.free_head = prev;
        Some(())
    }
}

static mut CACHES: [SlabCache; 3] = [
    SlabCache::new(16),
    SlabCache::new(32),
    SlabCache::new(512),
];

fn class_index(size: usize) -> Option<usize> {
    CLASSES.iter().position(|&s| size <= s)
}

/// Allocate a zeroed cell large enough for `size` bytes. Returns PA or None.
pub fn alloc(size: usize) -> Option<usize> {
    let idx = class_index(size)?;
    unsafe {
        let c = &mut *core::ptr::addr_of_mut!(CACHES);
        c[idx].alloc()
    }
}

/// Return a previously allocated cell to its slab cache.
/// `size` must be the same value passed to `alloc`.
pub fn free(pa: usize, size: usize) {
    if let Some(idx) = class_index(size) {
        unsafe {
            let c = &mut *core::ptr::addr_of_mut!(CACHES);
            c[idx].free(pa);
        }
    }
}
