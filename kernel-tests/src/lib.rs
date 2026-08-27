//! Host-native unit tests for Ferrite OS pure-logic kernel modules.
//! Run with: cargo test -p kernel-tests

// ── BuddyAllocator (copied from kernel/src/mm/buddy.rs) ──────────────────────

pub const PAGE_SIZE: usize = 4096;
const MAX_ORDER: usize = 11;

fn read_next(pa: usize) -> usize {
    unsafe { (pa as *const usize).read_volatile() }
}

fn write_next(pa: usize, next: usize) {
    unsafe { (pa as *mut usize).write_volatile(next) }
}

pub struct BuddyAllocator {
    free_lists: [usize; MAX_ORDER + 1],
    pub free_pages: usize,
    pub total_pages: usize,
}

impl BuddyAllocator {
    pub const fn new() -> Self {
        Self { free_lists: [0; MAX_ORDER + 1], free_pages: 0, total_pages: 0 }
    }

    pub fn add_region(&mut self, mut start: usize, end: usize) {
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

    pub fn alloc(&mut self, order: usize) -> Option<usize> {
        let found = (order..=MAX_ORDER).find(|&o| self.free_lists[o] != 0)?;
        let pa = self.pop_free(found).unwrap();
        for split in (order..found).rev() {
            let buddy = pa + (PAGE_SIZE << split);
            self.push_free(buddy, split);
        }
        self.free_pages -= 1 << order;
        Some(pa)
    }

    pub fn free(&mut self, mut pa: usize, mut order: usize) {
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

    fn remove_from_list(&mut self, target: usize, order: usize) -> bool {
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

// ── Cap types (copied from kernel/src/cap/mod.rs) ────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CapType {
    #[default] Null = 0,
    UntypedMemory = 1,
    CNode         = 2,
    Thread        = 3,
    AddressSpace  = 4,
    Endpoint      = 5,
    Notification  = 6,
    Frame         = 7,
    PageTable     = 8,
    IRQControl    = 9,
    IRQHandler    = 10,
}

impl CapType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0  => Self::Null,
            1  => Self::UntypedMemory,
            2  => Self::CNode,
            3  => Self::Thread,
            4  => Self::AddressSpace,
            5  => Self::Endpoint,
            6  => Self::Notification,
            7  => Self::Frame,
            8  => Self::PageTable,
            9  => Self::IRQControl,
            10 => Self::IRQHandler,
            _  => return None,
        })
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Rights(u8);

impl Rights {
    pub const READ:  Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const GRANT: Self = Self(1 << 2);
    pub const ALL:   Self = Self(0x1F);
    pub const NONE:  Self = Self(0x00);

    pub fn bits(self) -> u8 { self.0 }
    pub fn from_bits_truncate(v: u8) -> Self { Self(v & 0x1F) }
    pub fn contains(self, other: Self) -> bool { (self.0 & other.0) == other.0 }
}

impl std::ops::BitAnd for Rights {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self { Self(self.0 & rhs.0) }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Cap {
    pub cap_type: CapType,
    pub rights:   Rights,
    _pad:         [u8; 6],
    pub ptr:      usize,
    pub extra:    usize,
}

impl Cap {
    pub const NULL: Self = Self {
        cap_type: CapType::Null,
        rights:   Rights::NONE,
        _pad:     [0; 6],
        ptr:      0,
        extra:    0,
    };

    pub const fn new(cap_type: CapType, ptr: usize, extra: usize, rights: Rights) -> Self {
        Self { cap_type, rights, _pad: [0; 6], ptr, extra }
    }

    pub fn is_null(self) -> bool { matches!(self.cap_type, CapType::Null) }
}

// ── CNode operations (copied from kernel/src/cap/cnode.rs) ───────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CnodeError { OutOfRange, SlotOccupied, SlotEmpty, InsufficientRights }

fn slots(cnode_pa: usize) -> *mut Cap { cnode_pa as *mut Cap }

fn check_index(size_bits: usize, index: usize) -> Result<(), CnodeError> {
    if index < (1 << size_bits) { Ok(()) } else { Err(CnodeError::OutOfRange) }
}

pub fn cnode_lookup(pa: usize, sb: usize, index: usize) -> Result<Cap, CnodeError> {
    check_index(sb, index)?;
    Ok(unsafe { slots(pa).add(index).read() })
}

pub fn cnode_insert(pa: usize, sb: usize, index: usize, cap: Cap) -> Result<(), CnodeError> {
    check_index(sb, index)?;
    let ptr = unsafe { slots(pa).add(index) };
    let existing = unsafe { ptr.read() };
    if !existing.is_null() { return Err(CnodeError::SlotOccupied); }
    unsafe { ptr.write(cap) };
    Ok(())
}

pub fn cnode_force_insert(pa: usize, index: usize, cap: Cap) {
    unsafe { slots(pa).add(index).write(cap) };
}

pub fn cnode_delete(pa: usize, sb: usize, index: usize) -> Result<Cap, CnodeError> {
    check_index(sb, index)?;
    let ptr = unsafe { slots(pa).add(index) };
    let old = unsafe { ptr.read() };
    if old.is_null() { return Err(CnodeError::SlotEmpty); }
    unsafe { ptr.write(Cap::NULL) };
    Ok(old)
}

pub fn cnode_mint(pa: usize, sb: usize, src: usize, dst: usize, new_rights: Rights) -> Result<(), CnodeError> {
    let src_cap = cnode_lookup(pa, sb, src)?;
    if src_cap.is_null() { return Err(CnodeError::SlotEmpty); }
    if !src_cap.rights.contains(new_rights) { return Err(CnodeError::InsufficientRights); }
    let mut new_cap = src_cap;
    new_cap.rights = new_rights;
    cnode_insert(pa, sb, dst, new_cap)
}

// ── UntypedHeader (copied from kernel/src/cap/untyped.rs) ────────────────────

#[repr(C)]
pub struct UntypedHeader {
    pub start:     usize,
    pub end:       usize,
    pub watermark: usize,
}

impl UntypedHeader {
    pub fn bump(&mut self, size: usize, align: usize) -> Option<usize> {
        let aligned = (self.watermark + align - 1) & !(align - 1);
        if aligned + size > self.end { return None; }
        self.watermark = aligned + size;
        Some(aligned)
    }
}

pub fn object_size(cap_type: CapType, size_bits: usize) -> usize {
    match cap_type {
        CapType::CNode        => std::mem::size_of::<Cap>() << size_bits,
        CapType::Frame        => PAGE_SIZE << size_bits,
        CapType::PageTable    => PAGE_SIZE,
        CapType::Endpoint     => 64,
        CapType::Notification => 32,
        _                     => 0,
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod buddy_tests {
    use super::*;
    use std::alloc::{alloc, dealloc, Layout};

    fn alloc_arena(pages: usize) -> (*mut u8, usize) {
        let size = pages * PAGE_SIZE;
        let layout = Layout::from_size_align(size, PAGE_SIZE).unwrap();
        let ptr = unsafe { alloc(layout) };
        assert!(!ptr.is_null(), "arena alloc failed");
        unsafe { ptr.write_bytes(0, size) };
        (ptr, size)
    }

    unsafe fn free_arena(ptr: *mut u8, pages: usize) {
        let layout = Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap();
        dealloc(ptr, layout);
    }

    #[test]
    fn alloc_order0_aligned() {
        let (ptr, _) = alloc_arena(4);
        let base = ptr as usize;
        let mut b = BuddyAllocator::new();
        b.add_region(base, base + 4 * PAGE_SIZE);
        let pa = b.alloc(0).expect("alloc failed");
        assert_eq!(pa % PAGE_SIZE, 0, "page must be page-aligned");
        unsafe { free_arena(ptr, 4) };
    }

    #[test]
    fn alloc_orderN_aligned() {
        let (ptr, _) = alloc_arena(8);
        let base = ptr as usize;
        let mut b = BuddyAllocator::new();
        b.add_region(base, base + 8 * PAGE_SIZE);
        let pa = b.alloc(2).expect("alloc(2) failed");
        assert_eq!(pa % (PAGE_SIZE * 4), 0, "order-2 alloc must be 4-page aligned");
        unsafe { free_arena(ptr, 8) };
    }

    #[test]
    fn alloc_returns_different_pages() {
        let (ptr, _) = alloc_arena(4);
        let base = ptr as usize;
        let mut b = BuddyAllocator::new();
        b.add_region(base, base + 4 * PAGE_SIZE);
        let a = b.alloc(0).unwrap();
        let b2 = b.alloc(0).unwrap();
        assert_ne!(a, b2, "two allocs must return different addresses");
        unsafe { free_arena(ptr, 4) };
    }

    #[test]
    fn alloc_exhaustion_returns_none() {
        let (ptr, _) = alloc_arena(2);
        let base = ptr as usize;
        let mut b = BuddyAllocator::new();
        b.add_region(base, base + 2 * PAGE_SIZE);
        b.alloc(0).unwrap();
        b.alloc(0).unwrap();
        assert!(b.alloc(0).is_none(), "exhausted allocator must return None");
        unsafe { free_arena(ptr, 2) };
    }

    #[test]
    fn free_then_alloc_succeeds() {
        let (ptr, _) = alloc_arena(2);
        let base = ptr as usize;
        let mut b = BuddyAllocator::new();
        b.add_region(base, base + 2 * PAGE_SIZE);
        let pa = b.alloc(0).unwrap();
        b.free(pa, 0);
        let pa2 = b.alloc(0).expect("alloc after free must succeed");
        assert_eq!(pa, pa2, "freed page should be reused");
        unsafe { free_arena(ptr, 2) };
    }

    #[test]
    fn free_coalesces_buddies() {
        let (ptr, _) = alloc_arena(4);
        let base = ptr as usize;
        let mut b = BuddyAllocator::new();
        b.add_region(base, base + 4 * PAGE_SIZE);
        let a = b.alloc(0).unwrap();
        let b2 = b.alloc(0).unwrap();
        b.free(a, 0);
        b.free(b2, 0);
        let large = b.alloc(1).expect("coalesced order-1 alloc must succeed");
        assert_eq!(large % (PAGE_SIZE * 2), 0);
        unsafe { free_arena(ptr, 4) };
    }

    #[test]
    fn free_page_count_tracks() {
        let (ptr, _) = alloc_arena(4);
        let base = ptr as usize;
        let mut b = BuddyAllocator::new();
        b.add_region(base, base + 4 * PAGE_SIZE);
        assert_eq!(b.free_pages, 4);
        b.alloc(0).unwrap();
        assert_eq!(b.free_pages, 3);
        let pa = b.alloc(0).unwrap();
        assert_eq!(b.free_pages, 2);
        b.free(pa, 0);
        assert_eq!(b.free_pages, 3);
        unsafe { free_arena(ptr, 4) };
    }

    #[test]
    fn total_pages_matches_region() {
        let (ptr, _) = alloc_arena(8);
        let base = ptr as usize;
        let mut b = BuddyAllocator::new();
        b.add_region(base, base + 8 * PAGE_SIZE);
        assert_eq!(b.total_pages, 8);
        unsafe { free_arena(ptr, 8) };
    }
}

#[cfg(test)]
mod cap_tests {
    use super::*;

    #[test]
    fn cap_null_is_all_zeros() {
        let cap = Cap::NULL;
        let bytes: [u8; std::mem::size_of::<Cap>()] = unsafe { std::mem::transmute(cap) };
        assert!(bytes.iter().all(|&b| b == 0), "Cap::NULL must be all-zero bytes");
    }

    #[test]
    fn cap_size_is_24() {
        assert_eq!(std::mem::size_of::<Cap>(), 24, "Cap must be exactly 24 bytes");
    }

    #[test]
    fn captype_from_u8_roundtrip() {
        for v in 0u8..=10 {
            let ct = CapType::from_u8(v).expect("valid variant");
            assert_eq!(ct as u8, v, "from_u8({v}) round-trip failed");
        }
        assert!(CapType::from_u8(11).is_none(), "out-of-range must return None");
        assert!(CapType::from_u8(255).is_none(), "out-of-range must return None");
    }

    #[test]
    fn rights_contains() {
        assert!(Rights::ALL.contains(Rights::READ));
        assert!(Rights::ALL.contains(Rights::WRITE));
        assert!(!Rights::NONE.contains(Rights::READ));
        assert!(!Rights::READ.contains(Rights::WRITE));
    }

    #[test]
    fn rights_bitand() {
        assert_eq!(Rights::ALL & Rights::READ, Rights::READ);
        assert_eq!(Rights::READ & Rights::WRITE, Rights::NONE);
    }

    #[test]
    fn rights_from_bits_truncate() {
        let r = Rights::from_bits_truncate(0xFF);
        assert_eq!(r.bits(), 0x1F, "must mask to 5 bits");
    }

    #[test]
    fn cap_is_null() {
        assert!(Cap::NULL.is_null());
        let cap = Cap::new(CapType::Endpoint, 0x1000, 0, Rights::ALL);
        assert!(!cap.is_null());
    }

    #[test]
    fn cap_new_fields() {
        let cap = Cap::new(CapType::CNode, 0xDEAD_0000, 6, Rights::READ);
        assert_eq!(cap.cap_type, CapType::CNode);
        assert_eq!(cap.ptr, 0xDEAD_0000);
        assert_eq!(cap.extra, 6);
        assert_eq!(cap.rights, Rights::READ);
    }
}

#[cfg(test)]
mod cnode_tests {
    use super::*;

    fn alloc_cnode_mem(size_bits: usize) -> Vec<u8> {
        let slots = 1usize << size_bits;
        let bytes = slots * std::mem::size_of::<Cap>();
        vec![0u8; bytes]
    }

    #[test]
    fn lookup_empty_slot_returns_null() {
        let mem = alloc_cnode_mem(3);
        let pa = mem.as_ptr() as usize;
        let cap = cnode_lookup(pa, 3, 0).unwrap();
        assert!(cap.is_null());
    }

    #[test]
    fn lookup_out_of_range() {
        let mem = alloc_cnode_mem(2);
        let pa = mem.as_ptr() as usize;
        assert_eq!(cnode_lookup(pa, 2, 4), Err(CnodeError::OutOfRange));
        assert_eq!(cnode_lookup(pa, 2, 100), Err(CnodeError::OutOfRange));
    }

    #[test]
    fn insert_then_lookup_roundtrip() {
        let mut mem = alloc_cnode_mem(3);
        let pa = mem.as_mut_ptr() as usize;
        let cap = Cap::new(CapType::Endpoint, 0x8000_1000, 0, Rights::ALL);
        cnode_insert(pa, 3, 2, cap).unwrap();
        let got = cnode_lookup(pa, 3, 2).unwrap();
        assert_eq!(got.cap_type, CapType::Endpoint);
        assert_eq!(got.ptr, 0x8000_1000);
    }

    #[test]
    fn insert_occupied_fails() {
        let mut mem = alloc_cnode_mem(3);
        let pa = mem.as_mut_ptr() as usize;
        let cap = Cap::new(CapType::Endpoint, 0x1000, 0, Rights::ALL);
        cnode_insert(pa, 3, 0, cap).unwrap();
        assert_eq!(
            cnode_insert(pa, 3, 0, cap),
            Err(CnodeError::SlotOccupied),
            "inserting into occupied slot must fail"
        );
    }

    #[test]
    fn delete_clears_slot() {
        let mut mem = alloc_cnode_mem(3);
        let pa = mem.as_mut_ptr() as usize;
        let cap = Cap::new(CapType::Frame, 0x2000, 0, Rights::ALL);
        cnode_insert(pa, 3, 1, cap).unwrap();
        let old = cnode_delete(pa, 3, 1).unwrap();
        assert_eq!(old.cap_type, CapType::Frame);
        let after = cnode_lookup(pa, 3, 1).unwrap();
        assert!(after.is_null(), "slot must be null after delete");
    }

    #[test]
    fn delete_empty_fails() {
        let mem = alloc_cnode_mem(3);
        let pa = mem.as_ptr() as usize;
        assert_eq!(cnode_delete(pa, 3, 0), Err(CnodeError::SlotEmpty));
    }

    #[test]
    fn mint_reduces_rights() {
        let mut mem = alloc_cnode_mem(3);
        let pa = mem.as_mut_ptr() as usize;
        let cap = Cap::new(CapType::Endpoint, 0x1000, 0, Rights::ALL);
        cnode_insert(pa, 3, 0, cap).unwrap();
        cnode_mint(pa, 3, 0, 1, Rights::READ).unwrap();
        let minted = cnode_lookup(pa, 3, 1).unwrap();
        assert_eq!(minted.rights, Rights::READ);
    }

    #[test]
    fn mint_escalation_rejected() {
        let mut mem = alloc_cnode_mem(3);
        let pa = mem.as_mut_ptr() as usize;
        let cap = Cap::new(CapType::Endpoint, 0x1000, 0, Rights::READ);
        cnode_insert(pa, 3, 0, cap).unwrap();
        assert_eq!(
            cnode_mint(pa, 3, 0, 1, Rights::WRITE),
            Err(CnodeError::InsufficientRights),
            "cannot escalate rights via mint"
        );
    }

    #[test]
    fn fresh_cnode_all_null() {
        let mem = alloc_cnode_mem(3);
        let pa = mem.as_ptr() as usize;
        for i in 0..8 {
            assert!(cnode_lookup(pa, 3, i).unwrap().is_null(), "slot {i} should be null");
        }
    }

    #[test]
    fn force_insert_overwrites() {
        let mut mem = alloc_cnode_mem(3);
        let pa = mem.as_mut_ptr() as usize;
        let cap1 = Cap::new(CapType::Endpoint, 0x1000, 0, Rights::ALL);
        let cap2 = Cap::new(CapType::Frame, 0x2000, 0, Rights::ALL);
        cnode_insert(pa, 3, 0, cap1).unwrap();
        cnode_force_insert(pa, 0, cap2);
        let got = cnode_lookup(pa, 3, 0).unwrap();
        assert_eq!(got.cap_type, CapType::Frame);
        assert_eq!(got.ptr, 0x2000);
    }
}

#[cfg(test)]
mod untyped_tests {
    use super::*;

    #[test]
    fn bump_basic() {
        let mut hdr = UntypedHeader { start: 0x1000, end: 0x2000, watermark: 0x1010 };
        let pa = hdr.bump(64, 8).expect("bump should succeed");
        assert!(pa >= 0x1010, "must be at or after watermark");
        assert!(pa % 8 == 0, "must be 8-aligned");
        assert_eq!(hdr.watermark, pa + 64);
    }

    #[test]
    fn bump_alignment() {
        let mut hdr = UntypedHeader { start: 0x1000, end: 0x5000, watermark: 0x1001 };
        let pa = hdr.bump(16, 64).expect("bump with alignment");
        assert_eq!(pa % 64, 0, "result must be 64-aligned");
    }

    #[test]
    fn bump_exhaustion() {
        let mut hdr = UntypedHeader { start: 0x1000, end: 0x1100, watermark: 0x10F0 };
        let pa = hdr.bump(16, 1).expect("exactly fits");
        assert_eq!(pa, 0x10F0);
        assert!(hdr.bump(1, 1).is_none(), "exhausted: must return None");
    }

    #[test]
    fn object_size_frame_order0() {
        assert_eq!(object_size(CapType::Frame, 0), PAGE_SIZE);
    }

    #[test]
    fn object_size_frame_order2() {
        assert_eq!(object_size(CapType::Frame, 2), PAGE_SIZE * 4);
    }

    #[test]
    fn object_size_cnode_sb3() {
        assert_eq!(object_size(CapType::CNode, 3), 192);
    }

    #[test]
    fn object_size_null_is_zero() {
        assert_eq!(object_size(CapType::Null, 0), 0);
    }

    #[test]
    fn object_size_endpoint_nonzero() {
        assert!(object_size(CapType::Endpoint, 0) > 0);
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn cap_size_exactly_24() {
        assert_eq!(std::mem::size_of::<Cap>(), 24);
    }

    #[test]
    fn cap_align_is_8() {
        assert_eq!(std::mem::align_of::<Cap>(), 8);
    }

    #[test]
    fn rights_size_is_1() {
        assert_eq!(std::mem::size_of::<Rights>(), 1);
    }

    #[test]
    fn captype_size_is_1() {
        assert_eq!(std::mem::size_of::<CapType>(), 1);
    }

    #[test]
    fn page_size_is_4096() {
        assert_eq!(PAGE_SIZE, 4096);
    }
}
