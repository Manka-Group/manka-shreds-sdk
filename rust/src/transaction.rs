//! The transaction message: a fully decoded transaction laid out for zero-copy reading.
//!
//! # Layout
//!
//! A fixed 104-byte header followed by sections in a fixed order, each starting 8-byte aligned:
//!
//! ```text
//!   0  u64  slot                 64  u32  fec_set_index
//!   8  u64  parent_slot          68  u32  entry_index
//!  16  u64  rx_ts_ns             72  u32  tx_index
//!  24  u64  emit_ts_ns           76  u32  instruction_bytes_len
//!  32  [32] leader               80  u32  lookup_bytes_len
//!                                84  u32  raw_tx_len
//!                                88  u16  source_id
//!                                90  u16  flags
//!                                92  u16  account_count
//!                                94  u16  instruction_count
//!                                96  u8   signature_count
//!                                97  u8   message_version   (0xff = legacy)
//!                                98  u8   lookup_count
//!                                99  u8   required_signatures
//!                               100  u8   readonly_signed
//!                               101  u8   readonly_unsigned
//!                               102  u16  reserved
//! 104     signatures         signature_count * 64
//!         account_keys       account_count * 32
//!         recent_blockhash   32
//!         instruction_table  instruction_count * 16
//!         instruction_bytes  padded to 8
//!         lookup_table       lookup_count * 40
//!         lookup_bytes       padded to 8
//!         raw_tx             raw_tx_len, only when the flag is set
//! ```
//!
//! Fixed offsets and alignment are what make reading free: account keys and signatures are read by
//! pointing at a slice, never by walking length prefixes, and nothing is decoded until it is asked
//! for.

use crate::{
    error::{Error, Result},
    protocol::Verification,
};

/// Bytes in the fixed header.
pub const TX_HEADER_LEN: usize = 104;
/// Bytes in one instruction table entry.
pub const INSTRUCTION_ENTRY_LEN: usize = 16;
/// Bytes in one address lookup table entry.
pub const LOOKUP_ENTRY_LEN: usize = 40;
/// Marks a legacy (pre-versioned) message.
pub const MESSAGE_VERSION_LEGACY: u8 = 0xff;

const IS_VOTE: u16 = 1 << 0;
const VERIFIED: u16 = 1 << 1;
const HAS_RAW_TX: u16 = 1 << 2;
const RECOVERED: u16 = 1 << 3;
const HAS_LEADER: u16 = 1 << 4;
const REASON_SHIFT: u16 = 5;
const REASON_MASK: u16 = 0b11;

/// Rounds up to a multiple of 8.
const fn align8(len: usize) -> usize {
    len.next_multiple_of(8)
}

/// One instruction, pointing into the message's shared byte region.
#[derive(Clone, Copy, Debug)]
pub struct Instruction<'a> {
    /// Index into the account keys of the program being invoked.
    pub program_id_index: u8,
    /// Indices into the account keys, in the order the program expects them.
    pub accounts: &'a [u8],
    /// Opaque instruction data.
    pub data: &'a [u8],
}

/// One address lookup table reference, carried unresolved.
///
/// Resolving these needs the lookup tables' account state, which a shred pipeline does not have.
#[derive(Clone, Copy, Debug)]
pub struct AddressLookup<'a> {
    /// The lookup table account.
    pub account_key: &'a [u8; 32],
    /// Indices loaded as writable.
    pub writable_indexes: &'a [u8],
    /// Indices loaded as readonly.
    pub readonly_indexes: &'a [u8],
}

/// A decoded transaction, borrowing the bytes it was read from.
#[derive(Clone, Copy, Debug)]
pub struct Transaction<'a> {
    bytes: &'a [u8],
    signatures_at: usize,
    account_keys_at: usize,
    blockhash_at: usize,
    instruction_table_at: usize,
    instruction_bytes_at: usize,
    lookup_table_at: usize,
    lookup_bytes_at: usize,
    raw_tx_at: usize,
}

impl<'a> Transaction<'a> {
    /// Reads a transaction, validating that every section is present and every offset in range.
    pub fn read(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < TX_HEADER_LEN {
            return Err(Error::Truncated {
                what: "transaction header",
                need: TX_HEADER_LEN,
                have: bytes.len(),
            });
        }
        let u16_at = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]) as usize;
        let u32_at =
            |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("in range")) as usize;

        let instruction_bytes_len = u32_at(76);
        let lookup_bytes_len = u32_at(80);
        let account_count = u16_at(92);
        let instruction_count = u16_at(94);
        let signature_count = bytes[96] as usize;
        let lookup_count = bytes[98] as usize;

        let mut at = TX_HEADER_LEN;
        let mut take = |len: usize| -> Result<usize> {
            let start = at;
            at = at.checked_add(len).ok_or(Error::Truncated {
                what: "transaction",
                need: usize::MAX,
                have: bytes.len(),
            })?;
            if at > bytes.len() {
                return Err(Error::Truncated {
                    what: "transaction",
                    need: at,
                    have: bytes.len(),
                });
            }
            Ok(start)
        };

        let signatures_at = take(signature_count * 64)?;
        let account_keys_at = take(account_count * 32)?;
        let blockhash_at = take(32)?;
        let instruction_table_at = take(instruction_count * INSTRUCTION_ENTRY_LEN)?;
        let instruction_bytes_at = take(align8(instruction_bytes_len))?;
        let lookup_table_at = take(lookup_count * LOOKUP_ENTRY_LEN)?;
        let lookup_bytes_at = take(align8(lookup_bytes_len))?;
        let raw_tx_at = take(u32_at(84))?;

        // Table entries are offsets into their own byte region, so they are checked once here and
        // every accessor below can slice without a bounds test.
        for index in 0..instruction_count {
            let entry = instruction_table_at + index * INSTRUCTION_ENTRY_LEN;
            let accounts_end = u16_at(entry + 2) + u16_at(entry + 4);
            let data_end = u32_at(entry + 8) + u32_at(entry + 12);
            if accounts_end > instruction_bytes_len || data_end > instruction_bytes_len {
                return Err(Error::BadOffset {
                    what: "instruction",
                    index,
                });
            }
        }
        for index in 0..lookup_count {
            let entry = lookup_table_at + index * LOOKUP_ENTRY_LEN;
            let writable_end = u16_at(entry + 32) + u16_at(entry + 34);
            let readonly_end = u16_at(entry + 36) + u16_at(entry + 38);
            if writable_end > lookup_bytes_len || readonly_end > lookup_bytes_len {
                return Err(Error::BadOffset {
                    what: "lookup",
                    index,
                });
            }
        }

        Ok(Self {
            bytes,
            signatures_at,
            account_keys_at,
            blockhash_at,
            instruction_table_at,
            instruction_bytes_at,
            lookup_table_at,
            lookup_bytes_at,
            raw_tx_at,
        })
    }

    /// The bytes this transaction was read from.
    #[inline]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[inline]
    fn u16_at(&self, at: usize) -> u16 {
        u16::from_le_bytes([self.bytes[at], self.bytes[at + 1]])
    }

    #[inline]
    fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.bytes[at..at + 4].try_into().expect("in range"))
    }

    #[inline]
    fn u64_at(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.bytes[at..at + 8].try_into().expect("in range"))
    }

    /// Slot the transaction landed in.
    #[inline]
    pub fn slot(&self) -> u64 {
        self.u64_at(0)
    }

    /// The slot this one builds on.
    #[inline]
    pub fn parent_slot(&self) -> u64 {
        self.u64_at(8)
    }

    /// When the first shred of the FEC set arrived, on the server's monotonic clock.
    #[inline]
    pub fn rx_ts_ns(&self) -> u64 {
        self.u64_at(16)
    }

    /// When the server finished encoding this message, on the same clock as [`Self::rx_ts_ns`].
    #[inline]
    pub fn emit_ts_ns(&self) -> u64 {
        self.u64_at(24)
    }

    /// How long the server took from first shred to encoded message.
    ///
    /// Both stamps come from one monotonic clock, so this is meaningful; neither can be compared
    /// against a local wall clock.
    #[inline]
    pub fn pipeline_ns(&self) -> u64 {
        self.emit_ts_ns().saturating_sub(self.rx_ts_ns())
    }

    /// Leader assigned to the slot, when the schedule knew one.
    #[inline]
    pub fn leader(&self) -> Option<&'a [u8; 32]> {
        self.has(HAS_LEADER)
            .then(|| self.bytes[32..64].try_into().expect("in range"))
    }

    /// Erasure set this transaction was carried in.
    #[inline]
    pub fn fec_set_index(&self) -> u32 {
        self.u32_at(64)
    }

    /// Index of the entry within the slot.
    #[inline]
    pub fn entry_index(&self) -> u32 {
        self.u32_at(68)
    }

    /// Index of the transaction within its entry.
    #[inline]
    pub fn tx_index(&self) -> u32 {
        self.u32_at(72)
    }

    /// Which ingress source delivered the shreds.
    #[inline]
    pub fn source_id(&self) -> u16 {
        self.u16_at(88)
    }

    /// Raw header flags. Prefer the named accessors.
    #[inline]
    pub fn flags(&self) -> u16 {
        self.u16_at(90)
    }

    #[inline]
    fn has(&self, bits: u16) -> bool {
        self.flags() & bits == bits
    }

    /// Whether this is a simple vote transaction.
    #[inline]
    pub fn is_vote(&self) -> bool {
        self.has(IS_VOTE)
    }

    /// Whether the FEC set had to be reconstructed from parity shreds.
    #[inline]
    pub fn recovered(&self) -> bool {
        self.has(RECOVERED)
    }

    /// How much the server could vouch for this transaction.
    pub fn verification(&self) -> Verification {
        if self.has(VERIFIED) {
            return Verification::Verified;
        }
        match (self.flags() >> REASON_SHIFT) & REASON_MASK {
            1 => Verification::UnknownLeader,
            2 => Verification::StaleSchedule,
            _ => Verification::Disabled,
        }
    }

    /// Number of account keys carried in the message.
    #[inline]
    pub fn account_count(&self) -> usize {
        self.u16_at(92) as usize
    }

    /// Number of instructions.
    #[inline]
    pub fn instruction_count(&self) -> usize {
        self.u16_at(94) as usize
    }

    /// Number of signatures.
    #[inline]
    pub fn signature_count(&self) -> usize {
        self.bytes[96] as usize
    }

    /// Message version, or [`MESSAGE_VERSION_LEGACY`] for a legacy message.
    #[inline]
    pub fn message_version(&self) -> u8 {
        self.bytes[97]
    }

    /// Number of address lookup table references.
    #[inline]
    pub fn lookup_count(&self) -> usize {
        self.bytes[98] as usize
    }

    /// Signatures the message requires.
    #[inline]
    pub fn required_signatures(&self) -> u8 {
        self.bytes[99]
    }

    /// Signed accounts that are readonly.
    #[inline]
    pub fn readonly_signed(&self) -> u8 {
        self.bytes[100]
    }

    /// Unsigned accounts that are readonly.
    #[inline]
    pub fn readonly_unsigned(&self) -> u8 {
        self.bytes[101]
    }

    /// The transaction's first signature — its id.
    #[inline]
    pub fn signature(&self) -> Option<&'a [u8; 64]> {
        (self.signature_count() > 0)
            .then(|| self.bytes[self.signatures_at..self.signatures_at + 64].try_into())
            .and_then(std::result::Result::ok)
    }

    /// Every signature, in order.
    pub fn signatures(&self) -> impl ExactSizeIterator<Item = &'a [u8; 64]> {
        let bytes = self.bytes;
        let at = self.signatures_at;
        (0..self.signature_count())
            .map(move |i| bytes[at + i * 64..at + i * 64 + 64].try_into().expect("in range"))
    }

    /// One account key, by index.
    pub fn account_key(&self, index: usize) -> Option<&'a [u8; 32]> {
        if index >= self.account_count() {
            return None;
        }
        let at = self.account_keys_at + index * 32;
        self.bytes[at..at + 32].try_into().ok()
    }

    /// Every account key, in the order the message declared them.
    pub fn account_keys(&self) -> impl ExactSizeIterator<Item = &'a [u8; 32]> {
        let bytes = self.bytes;
        let at = self.account_keys_at;
        (0..self.account_count())
            .map(move |i| bytes[at + i * 32..at + i * 32 + 32].try_into().expect("in range"))
    }

    /// The blockhash the transaction was signed against.
    #[inline]
    pub fn recent_blockhash(&self) -> &'a [u8; 32] {
        self.bytes[self.blockhash_at..self.blockhash_at + 32]
            .try_into()
            .expect("in range")
    }

    /// One instruction, by index.
    pub fn instruction(&self, index: usize) -> Option<Instruction<'a>> {
        if index >= self.instruction_count() {
            return None;
        }
        let entry = self.instruction_table_at + index * INSTRUCTION_ENTRY_LEN;
        let base = self.instruction_bytes_at;
        let accounts_at = base + self.u16_at(entry + 2) as usize;
        let accounts_len = self.u16_at(entry + 4) as usize;
        let data_at = base + self.u32_at(entry + 8) as usize;
        let data_len = self.u32_at(entry + 12) as usize;
        Some(Instruction {
            program_id_index: self.bytes[entry],
            accounts: &self.bytes[accounts_at..accounts_at + accounts_len],
            data: &self.bytes[data_at..data_at + data_len],
        })
    }

    /// Every instruction, in execution order.
    pub fn instructions(&self) -> impl ExactSizeIterator<Item = Instruction<'a>> {
        let this = *self;
        (0..self.instruction_count()).map(move |i| this.instruction(i).expect("index in range"))
    }

    /// Every address lookup table reference, unresolved.
    pub fn lookups(&self) -> impl ExactSizeIterator<Item = AddressLookup<'a>> {
        let this = *self;
        (0..self.lookup_count()).map(move |i| {
            let entry = this.lookup_table_at + i * LOOKUP_ENTRY_LEN;
            let base = this.lookup_bytes_at;
            let writable_at = base + this.u16_at(entry + 32) as usize;
            let writable_len = this.u16_at(entry + 34) as usize;
            let readonly_at = base + this.u16_at(entry + 36) as usize;
            let readonly_len = this.u16_at(entry + 38) as usize;
            AddressLookup {
                account_key: this.bytes[entry..entry + 32].try_into().expect("in range"),
                writable_indexes: &this.bytes[writable_at..writable_at + writable_len],
                readonly_indexes: &this.bytes[readonly_at..readonly_at + readonly_len],
            }
        })
    }

    /// The original transaction bytes, when the server was asked to include them.
    ///
    /// Off by default: the decoded form carries the same information, and repeating the bytes
    /// roughly doubles the stream's bandwidth.
    pub fn raw_tx(&self) -> Option<&'a [u8]> {
        self.has(HAS_RAW_TX)
            .then(|| &self.bytes[self.raw_tx_at..self.raw_tx_at + self.u32_at(84) as usize])
    }
}
