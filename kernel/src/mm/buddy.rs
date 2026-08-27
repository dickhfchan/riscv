/*
 * Buddy physical-page allocator.
 *
 * Manages a region of physical RAM as 4 KiB pages organised into
 * power-of-two orders (0 = 4 KiB, MAX_ORDER = 4 KiB × 2^MAX_ORDER).
 *
 * Free lists are intrusive: the first 8 bytes of each free block hold
 * the physical address of the next free block in the same order (0 = end).
 *
 * Safety contract (Phase 2): single-hart, no interrupts — no locking needed.
 */

pub const PAGE_SIZE: usize = 4096;
pub const _PAGE_SHIFT: usize = 12;
pub const MAX_ORDER: usize = 11; // largest block = 4 KiB × 2^11 = 8 MiB

#[inline]
fn read_next(pa: usize) -> usize {
    unsafe { (pa as *const usize).read_volatile() }
}

#[inline]
fn write_next(pa: usize, next: usize) {
    unsafe { (pa as *mut usize).write_volatile(next) }
}

pub struct BuddyAllocator {
    free_lists: [usize; MAX_ORDER + 1], // physical addr of head, 0 = empty
    pub free_pages: usize,
    pub total_pages: usize,
}

impl BuddyAllocator {
    pub const fn new() -> Self {
        Self { free_lists: [0; MAX_ORDER + 1], free_pages: 0, total_pages: 0 }
    }

    /// Add the region [start, end) — both page-aligned — to the allocator.
    pub fn add_region(&mut self, mut start: usize, end: usize) {
        debug_assert!(start % PAGE_SIZE == 0);
        debug_assert!(end % PAGE_SIZE == 0);
        while start < end {
            let remaining_pages = (end - start) / PAGE_SIZE;
            if remaining_pages == 0 { break; }
            let page_index = start / PAGE_SIZE;
            let align_order = page_index.trailing_zeros() as usize;
            let size_order = usize::BITS as usize - 1 - remaining_pages.leading_zeros() as usize;
            let order = align_order.min(size_order).min(MAX_ORDER);
            self.push_free(start, order);
            let pages = 1usize << order;
            self.total_pages += pages;
            self.free_pages += pages;
            start += pages * PAGE_SIZE;
        }
    }

    fn push_free(&mut self, pa: usize, order: usize) {
        write_next(pa, self.free_lists[order]);
        self.free_lists[order] = pa;
    }

    fn pop_free(&mut self, order: usize) -> Option<usize> {
        let pa = self.free_lists[order];
        if pa == 0 { return None; }
        self.free_lists[order] = read_next(pa);
        Some(pa)
    }

    /// Allocate 2^order contiguous pages. Returns physical address.
    pub fn alloc(&mut self, order: usize) -> Option<usize> {
        assert!(order <= MAX_ORDER);
        let found = (order..=MAX_ORDER).find(|&o| self.free_lists[o] != 0)?;
        let pa = self.pop_free(found).unwrap();
        // Split higher-order block down to requested size.
        for split in (order..found).rev() {
            let buddy = pa + (PAGE_SIZE << split);
            self.push_free(buddy, split);
        }
        self.free_pages -= 1 << order;
        Some(pa)
    }

    /// Free 2^order pages at physical address pa, coalescing buddies.
    pub fn free(&mut self, mut pa: usize, mut order: usize) {
        assert!(order <= MAX_ORDER);
        self.free_pages += 1 << order;
        while order < MAX_ORDER {
            let buddy = pa ^ (PAGE_SIZE << order);
            if self.remove_from_list(buddy, order) {
                pa = pa.min(buddy);
                order += 1;
            } else {
                break;
            }
        }
        self.push_free(pa, order);
    }

    /// Remove a specific physical address from free_lists[order].
    /// Returns true if found and removed.
    fn remove_from_list(&mut self, target: usize, order: usize) -> bool {
        // `slot` is a raw pointer to the value we'd need to update
        // (either free_lists[order] itself, or a block's next-word).
        let mut slot = &mut self.free_lists[order] as *mut usize;
        let mut cur = unsafe { *slot };
        while cur != 0 {
            if cur == target {
                let next = read_next(cur);
                unsafe { *slot = next; }
                return true;
            }
            slot = cur as *mut usize;
            cur = read_next(cur);
        }
        false
    }
}
