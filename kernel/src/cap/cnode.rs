/*
 * CNode — capability table operations.
 *
 * A CNode object is a physically-contiguous, page-aligned array of Cap slots.
 * The slot count is 2^size_bits.  The CNode's own metadata (size_bits) lives
 * in the *capability* that refers to it, not in the CNode itself.
 */

use core::sync::atomic::Ordering;
use super::{Cap, Rights};
use crate::mm::{self, buddy::PAGE_SIZE};

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    OutOfRange,
    SlotOccupied,
    SlotEmpty,
    InsufficientRights,
    InvalidArgument,
}

// ── Internal helpers ──────────────────────────────────────────────────────────

#[inline]
fn slots(cnode_pa: usize) -> *mut Cap {
    cnode_pa as *mut Cap
}

#[inline]
fn check_index(size_bits: usize, index: usize) -> Result<(), Error> {
    if index < (1 << size_bits) { Ok(()) } else { Err(Error::OutOfRange) }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Read the capability in slot `index`.
pub fn lookup(cnode_pa: usize, size_bits: usize, index: usize) -> Result<Cap, Error> {
    check_index(size_bits, index)?;
    Ok(unsafe { slots(cnode_pa).add(index).read() })
}

/// Write `cap` into slot `index`; slot must currently be Null.
pub fn insert(
    cnode_pa: usize, size_bits: usize,
    index: usize, cap: Cap,
) -> Result<(), Error> {
    check_index(size_bits, index)?;
    let ptr = unsafe { slots(cnode_pa).add(index) };
    let existing = unsafe { ptr.read() };
    if !existing.is_null() { return Err(Error::SlotOccupied); }
    unsafe { ptr.write(cap) };
    Ok(())
}

/// Overwrite slot `index` unconditionally (for bootstrap only).
pub fn force_insert(cnode_pa: usize, _size_bits: usize, index: usize, cap: Cap) {
    unsafe { slots(cnode_pa).add(index).write(cap) };
}

/// Copy `src` to `dst`, intersecting rights with `mask`.  `dst` must be Null.
pub fn copy(
    cnode_pa: usize, size_bits: usize,
    src: usize, dst: usize,
    mask: Rights,
) -> Result<(), Error> {
    let src_cap = lookup(cnode_pa, size_bits, src)?;
    if src_cap.is_null() { return Err(Error::SlotEmpty); }
    let mut new_cap = src_cap;
    new_cap.rights = new_cap.rights & mask;
    insert(cnode_pa, size_bits, dst, new_cap)
}

/// Move `src` to `dst` (dst must be Null), clearing src.
pub fn move_cap(
    cnode_pa: usize, size_bits: usize,
    src: usize, dst: usize,
) -> Result<(), Error> {
    let src_cap = lookup(cnode_pa, size_bits, src)?;
    if src_cap.is_null() { return Err(Error::SlotEmpty); }
    insert(cnode_pa, size_bits, dst, src_cap)?;
    force_insert(cnode_pa, size_bits, src, Cap::NULL);
    Ok(())
}

/// Mint: copy with a specific (reduced) rights set.
pub fn mint(
    cnode_pa: usize, size_bits: usize,
    src: usize, dst: usize,
    new_rights: Rights,
) -> Result<(), Error> {
    let src_cap = lookup(cnode_pa, size_bits, src)?;
    if src_cap.is_null() { return Err(Error::SlotEmpty); }
    if !src_cap.rights.contains(new_rights) { return Err(Error::InsufficientRights); }
    let mut new_cap = src_cap;
    new_cap.rights = new_rights;
    insert(cnode_pa, size_bits, dst, new_cap)
}

/// Delete (clear) slot `index`, returning the old capability.
pub fn delete(cnode_pa: usize, size_bits: usize, index: usize) -> Result<Cap, Error> {
    check_index(size_bits, index)?;
    let ptr = unsafe { slots(cnode_pa).add(index) };
    let old = unsafe { ptr.read() };
    if old.is_null() { return Err(Error::SlotEmpty); }
    unsafe { ptr.write(Cap::NULL) };
    Ok(old)
}

// ── Revoke ────────────────────────────────────────────────────────────────────

/// Revoke: nullify every copy of the capability at `(cnode_pa, index)` —
/// scanning the root CSpace and every per-process CSpace — then delete the
/// target slot itself.
pub fn revoke(cnode_pa: usize, size_bits: usize, index: usize) -> Result<(), Error> {
    let target = lookup(cnode_pa, size_bits, index)?;
    if target.is_null() { return Err(Error::SlotEmpty); }

    // Scan one CSpace and nullify all slots that are copies of `target`.
    let nullify = |cs_pa: usize, cs_sb: usize| {
        let n = 1usize << cs_sb;
        for i in 0..n {
            if cs_pa == cnode_pa && i == index { continue; } // skip the revocation target
            let ptr = unsafe { slots(cs_pa).add(i) };
            let cap = unsafe { ptr.read() };
            if !cap.is_null() && cap.cap_type == target.cap_type && cap.ptr == target.ptr {
                unsafe { ptr.write(Cap::NULL); }
            }
        }
    };

    // Root CSpace.
    let (root_pa, root_sb) = super::root_cspace();
    nullify(root_pa, root_sb);

    // All per-process CSpaces reachable via the global TCB list.
    let mut tcb_pa = crate::thread::TCB_LIST_HEAD.load(Ordering::Acquire);
    while tcb_pa != 0 {
        let tcb = unsafe { &*(tcb_pa as *const crate::thread::Tcb) };
        if tcb.cspace_pa != 0 && tcb.cspace_pa != root_pa {
            nullify(tcb.cspace_pa, tcb.cspace_sb);
        }
        tcb_pa = tcb.global_next;
    }

    // Finally, delete the target slot itself.
    force_insert(cnode_pa, size_bits, index, Cap::NULL);
    Ok(())
}

// ── Allocation ────────────────────────────────────────────────────────────────

/// Allocate a new CNode from the buddy allocator.
/// Returns the physical address of the zeroed slot array.
pub fn alloc(size_bits: usize) -> Option<usize> {
    let total_bytes = (1usize << size_bits) * core::mem::size_of::<Cap>();
    let pages  = (total_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    let order  = usize::BITS as usize - 1 - pages.leading_zeros() as usize;
    let order  = if pages.is_power_of_two() { order } else { order + 1 };
    let pa     = mm::alloc_pages(order)?;
    // Zero all slots (Cap::NULL is all-zero bytes).
    unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE << order) };
    Some(pa)
}
