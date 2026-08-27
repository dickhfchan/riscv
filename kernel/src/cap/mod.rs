/*
 * Capability model — core types.
 *
 * A Cap is a 24-byte unforgeable token that authorises operations on one
 * kernel object.  Capabilities are stored in CNodes (power-of-two arrays of
 * Cap slots), which are themselves kernel objects described by capabilities.
 */

pub mod cnode;
pub mod endpoint;
pub mod irq;
pub mod notification;
pub mod untyped;

use core::sync::atomic::{AtomicUsize, Ordering};

// ── Rights bit-flags ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Rights(u8);

impl Rights {
    pub const READ:        Self = Self(1 << 0);
    pub const WRITE:       Self = Self(1 << 1);
    pub const GRANT:       Self = Self(1 << 2);
    pub const GRANT_REPLY: Self = Self(1 << 3);
    pub const CALL:        Self = Self(1 << 4);
    pub const ALL:         Self = Self(0x1F);
    pub const NONE:        Self = Self(0x00);

    pub fn bits(self) -> u8 { self.0 }
    pub fn from_bits_truncate(v: u8) -> Self { Self(v & 0x1F) }
    pub fn contains(self, other: Self) -> bool { (self.0 & other.0) == other.0 }
}

impl core::ops::BitAnd for Rights {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self { Self(self.0 & rhs.0) }
}
impl core::ops::BitAndAssign for Rights {
    fn bitand_assign(&mut self, rhs: Self) { self.0 &= rhs.0; }
}
impl core::ops::BitOr for Rights {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}

// ── Object types ─────────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CapType {
    #[default]
    Null = 0,
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

// ── Capability slot ───────────────────────────────────────────────────────────

/// 24-byte capability slot stored in CNode arrays.
///
/// `ptr`   — physical address of the kernel object.
/// `extra` — type-specific metadata:
///           CNode         → size_bits (number of slots = 2^size_bits)
///           UntypedMemory → not used (header is at ptr)
///           Frame         → size in bytes
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Cap {
    pub cap_type: CapType,
    pub rights:   Rights,
    _pad:         [u8; 6],
    pub ptr:      usize,
    pub extra:    usize,
}
// sizeof: 1+1+6+8+8 = 24 bytes.

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

// ── Bootstrap CSpace globals ──────────────────────────────────────────────────
//
// The "root CSpace" is the initial capability namespace created by kernel_main
// and consulted by the trap handler for all ecall invocations.

static ROOT_PA:        AtomicUsize = AtomicUsize::new(0);
static ROOT_SIZE_BITS: AtomicUsize = AtomicUsize::new(0);

pub fn set_root_cspace(pa: usize, size_bits: usize) {
    ROOT_PA.store(pa, Ordering::Release);
    ROOT_SIZE_BITS.store(size_bits, Ordering::Release);
}

pub fn root_cspace() -> (usize, usize) {
    (ROOT_PA.load(Ordering::Acquire), ROOT_SIZE_BITS.load(Ordering::Acquire))
}
