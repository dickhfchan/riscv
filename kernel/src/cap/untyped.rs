/*
 * UntypedMemory — raw physical memory that can be retyped into kernel objects.
 *
 * An UntypedMemory capability gives authority over a contiguous physical region.
 * A header structure is stored at the very beginning of that region; it holds a
 * bump pointer so successive Retype invocations carve out non-overlapping areas.
 *
 *  PA: [ UntypedHeader | ... objects allocated by Retype ... | end ]
 */

use super::{Cap, CapType, Rights};
use crate::mm::buddy::PAGE_SIZE;

// ── Header stored in-band at the start of the physical region ─────────────────

#[repr(C)]
pub struct UntypedHeader {
    pub start:     usize,
    pub end:       usize,
    pub watermark: usize, // next free byte
}

impl UntypedHeader {
    /// Allocate `size` bytes with `align`-byte alignment.
    pub fn bump(&mut self, size: usize, align: usize) -> Option<usize> {
        let aligned = (self.watermark + align - 1) & !(align - 1);
        if aligned + size > self.end { return None; }
        self.watermark = aligned + size;
        Some(aligned)
    }

    pub fn free_bytes(&self) -> usize {
        self.end.saturating_sub(self.watermark)
    }
}

// ── Object size + alignment tables ────────────────────────────────────────────

/// Bytes required to store one instance of `cap_type` with parameter `size_bits`.
pub fn object_size(cap_type: CapType, size_bits: usize) -> usize {
    match cap_type {
        CapType::CNode        => core::mem::size_of::<Cap>() << size_bits,
        CapType::Frame        => PAGE_SIZE << size_bits,
        CapType::Thread       => 2 * PAGE_SIZE, // TCB page + kernel-stack page
        CapType::PageTable    => PAGE_SIZE,
        CapType::Endpoint     => core::mem::size_of::<super::endpoint::Endpoint>(),
        CapType::Notification => core::mem::size_of::<super::notification::Notification>(),
        _                     => 0,
    }
}

/// Required alignment for one object of `cap_type` with `size_bits`.
pub fn object_align(cap_type: CapType, size_bits: usize) -> usize {
    let sz = object_size(cap_type, size_bits);
    if sz == 0 { return 8; }
    sz.next_power_of_two()
}

// ── Retype ────────────────────────────────────────────────────────────────────

/// Carve `count` objects of (`cap_type`, `size_bits`) out of the untyped region,
/// inserting new capabilities at CNode slots [dst_slot, dst_slot + count).
///
/// Returns an error code (0 = OK) matching `crate::syscall::error::*`.
pub fn retype(
    untyped: &Cap,
    cap_type: CapType,
    size_bits: usize,
    dst_cnode_pa: usize,
    dst_cnode_size_bits: usize,
    dst_slot: usize,
    count: usize,
) -> usize {
    use crate::syscall::error;
    use crate::cap::cnode;

    let obj_sz  = object_size(cap_type, size_bits);
    let obj_aln = object_align(cap_type, size_bits);
    if obj_sz == 0 { return error::INVALID_ARGUMENT; }

    let hdr = unsafe { &mut *(untyped.ptr as *mut UntypedHeader) };

    for i in 0..count {
        let pa = match hdr.bump(obj_sz, obj_aln) {
            Some(p) => p,
            None    => return error::NOT_ENOUGH_MEMORY,
        };
        // Zero the newly allocated region.
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, obj_sz) };

        let new_cap = Cap::new(cap_type, pa, size_bits, Rights::ALL);
        if cnode::insert(dst_cnode_pa, dst_cnode_size_bits, dst_slot + i, new_cap).is_err() {
            return error::ILLEGAL_OPERATION;
        }
    }
    error::OK
}
