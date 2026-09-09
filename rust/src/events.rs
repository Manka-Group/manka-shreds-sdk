//! Frames other than transactions: slot boundaries, entries and equivocation reports.
//!
//! Each is a fixed-size little-endian record with no variable tail, so reading one is a bounds
//! check and a handful of loads.
//!
//! # Why entries carry no transaction bytes
//!
//! An entry's transactions already travel on the transaction stream, each carrying the
//! `entry_index` that puts it back in its entry. Repeating the bytes here would double the
//! bandwidth of a subscriber taking both streams to say nothing new. What the entry frame adds is
//! the structure around them: the PoH hash, the hash count, and how many transactions the entry
//! claimed — which is what lets a subscriber notice one is missing.

use crate::{
    error::{Error, Result},
    protocol::Verification,
};

fn require(bytes: &[u8], need: usize, what: &'static str) -> Result<()> {
    if bytes.len() < need {
        return Err(Error::Truncated {
            what,
            need,
            have: bytes.len(),
        });
    }
    Ok(())
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounds checked"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("bounds checked"))
}

/// The first shred of a slot arrived.
#[derive(Clone, Copy, Debug)]
pub struct SlotStart<'a> {
    /// Slot that just appeared.
    pub slot: u64,
    /// Present once a shred declaring the parent has arrived.
    pub parent_slot: Option<u64>,
    /// The slot's leader, when the schedule knew one.
    pub leader: Option<&'a [u8; 32]>,
    /// When the first shred arrived, on the server's monotonic clock.
    pub rx_ts_ns: u64,
    /// Which ingress source delivered it.
    pub source: u16,
    /// Shred version carried by the first shred.
    pub shred_version: u16,
}

impl<'a> SlotStart<'a> {
    /// Bytes in the encoded frame.
    pub const LEN: usize = 64;

    /// Reads a slot start.
    pub fn read(bytes: &'a [u8]) -> Result<Self> {
        require(bytes, Self::LEN, "slot start")?;
        let flags = bytes[60];
        Ok(Self {
            slot: u64_at(bytes, 0),
            parent_slot: (flags & 1 != 0).then(|| u64_at(bytes, 8)),
            leader: (flags & 2 != 0).then(|| bytes[16..48].try_into().expect("bounds checked")),
            rx_ts_ns: u64_at(bytes, 48),
            source: u16_at(bytes, 56),
            shred_version: u16_at(bytes, 58),
        })
    }
}

/// A slot finished, either completed or given up on.
#[derive(Clone, Copy, Debug)]
pub struct SlotEnd {
    /// Slot that finished.
    pub slot: u64,
    /// Parent of `slot`.
    pub parent_slot: u64,
    /// Data shreds observed or recovered.
    pub data_shreds: u32,
    /// FEC sets that completed.
    pub fec_sets: u32,
    /// Sets that had to be reconstructed from parity.
    pub recovered_sets: u32,
    /// Shreds never obtained, so their entries were never emitted.
    pub missing_shreds: u32,
    /// When the slot was retired, on the server's monotonic clock.
    pub end_ts_ns: u64,
    /// Whether the slot was seen whole. False means shreds were lost.
    pub complete: bool,
}

impl SlotEnd {
    /// Bytes in the encoded frame.
    pub const LEN: usize = 48;

    /// Reads a slot end.
    pub fn read(bytes: &[u8]) -> Result<Self> {
        require(bytes, Self::LEN, "slot end")?;
        Ok(Self {
            slot: u64_at(bytes, 0),
            parent_slot: u64_at(bytes, 8),
            data_shreds: u32_at(bytes, 16),
            fec_sets: u32_at(bytes, 20),
            recovered_sets: u32_at(bytes, 24),
            missing_shreds: u32_at(bytes, 28),
            end_ts_ns: u64_at(bytes, 32),
            complete: bytes[40] & 1 != 0,
        })
    }
}

/// One proof-of-history entry.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    /// Slot the entry was produced in.
    pub slot: u64,
    /// Parent of `slot`.
    pub parent_slot: u64,
    /// When the FEC set's first shred arrived, on the server's monotonic clock.
    pub rx_ts_ns: u64,
    /// PoH hashes since the previous entry. Zero means this is not a tick boundary.
    pub num_hashes: u64,
    /// Transactions the entry claims — compare against what arrived.
    pub tx_count: u64,
    /// The entry's PoH hash.
    pub hash: &'a [u8; 32],
    /// FEC set the entry came from.
    pub fec_set_index: u32,
    /// Index of the entry within its batch.
    pub entry_index: u32,
    /// Signature status of the FEC set.
    pub verification: Verification,
}

impl<'a> Entry<'a> {
    /// Bytes in the encoded frame.
    pub const LEN: usize = 88;

    /// Reads an entry.
    pub fn read(bytes: &'a [u8]) -> Result<Self> {
        require(bytes, Self::LEN, "entry")?;
        Ok(Self {
            slot: u64_at(bytes, 0),
            parent_slot: u64_at(bytes, 8),
            rx_ts_ns: u64_at(bytes, 16),
            num_hashes: u64_at(bytes, 24),
            tx_count: u64_at(bytes, 32),
            hash: bytes[40..72].try_into().expect("bounds checked"),
            fec_set_index: u32_at(bytes, 72),
            entry_index: u32_at(bytes, 76),
            verification: Verification::from_byte(bytes[80]),
        })
    }
}

/// Two different shreds arrived for one slot and index — the leader equivocated.
///
/// Both signatures are carried so the report can be checked independently; which fork survives is
/// not knowable at this layer, and a subscriber may care about the conflict itself.
#[derive(Clone, Copy, Debug)]
pub struct Duplicate<'a> {
    /// Slot both shreds claim.
    pub slot: u64,
    /// Index both shreds claim.
    pub index: u32,
    /// Source that delivered the version that arrived first.
    pub first_source: u16,
    /// Source that delivered the conflicting version.
    pub second_source: u16,
    /// When the conflict was noticed, on the server's monotonic clock.
    pub detected_ns: u64,
    /// Whether the conflicting shreds were data shreds rather than parity.
    pub is_data: bool,
    /// Signature of the version that arrived first.
    pub first_signature: &'a [u8; 64],
    /// Signature of the conflicting version.
    pub second_signature: &'a [u8; 64],
}

impl<'a> Duplicate<'a> {
    /// Bytes in the encoded frame.
    pub const LEN: usize = 160;

    /// Reads a duplicate report.
    pub fn read(bytes: &'a [u8]) -> Result<Self> {
        require(bytes, Self::LEN, "duplicate")?;
        Ok(Self {
            slot: u64_at(bytes, 0),
            index: u32_at(bytes, 8),
            first_source: u16_at(bytes, 12),
            second_source: u16_at(bytes, 14),
            detected_ns: u64_at(bytes, 16),
            is_data: bytes[24] != 0,
            first_signature: bytes[32..96].try_into().expect("bounds checked"),
            second_signature: bytes[96..160].try_into().expect("bounds checked"),
        })
    }
}

/// A shred republished exactly as it arrived.
///
/// # What this stream is
///
/// Every other event is a *conclusion* the node reached — a transaction it decoded, a slot it
/// judged finished. This is the evidence those were drawn from, handed to you at the moment the
/// node received it, before it verified or decoded anything.
///
/// **Nothing here is claimed to be leader-signed.** A shred is republished as soon as it survives
/// deduplication; the signature check happens later, on the FEC set as a whole. If you need the
/// guarantee, take `transactions`, which carries it. If you need the latency and run your own
/// pipeline, this is for you.
///
/// Two things it deliberately is not. **Not recovered**: a shred rebuilt from parity is not
/// republished, so a gap here is a real loss rather than an artefact, and your own count matches the
/// network's. **Not filtered**: a shred is a fragment of an erasure set, not yet anything a filter
/// can match on.
///
/// It is the highest-rate stream a node publishes — a multiple of `transactions`, since most
/// fragments carry votes. Take it only if you are consuming it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawShred<'a> {
    /// Slot the shred belongs to.
    pub slot: u64,
    /// Index within the slot, scoped by [`Self::is_data`].
    ///
    /// A data shred and a coding shred may share an index. Key on the pair, not on the index alone.
    pub index: u32,
    /// Index of the first data shred of the FEC set this belongs to.
    pub fec_set_index: u32,
    /// When the node received it, on the server's monotonic clock.
    pub rx_ts_ns: u64,
    /// Which configured source delivered it first.
    pub source: u16,
    /// Whether this is a data shred rather than parity.
    pub is_data: bool,
    /// The shred exactly as it arrived, ready for a parser that expects one.
    pub bytes: &'a [u8],
}

impl<'a> RawShred<'a> {
    /// Bytes before the payload.
    pub const HEADER_LEN: usize = 32;

    /// Reads the frame, borrowing the payload rather than copying it.
    pub fn read(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(Error::Truncated {
                what: "raw shred",
                need: Self::HEADER_LEN,
                have: bytes.len(),
            });
        }
        Ok(Self {
            slot: u64::from_le_bytes(bytes[0..8].try_into().expect("in range")),
            index: u32::from_le_bytes(bytes[8..12].try_into().expect("in range")),
            fec_set_index: u32::from_le_bytes(bytes[12..16].try_into().expect("in range")),
            rx_ts_ns: u64::from_le_bytes(bytes[16..24].try_into().expect("in range")),
            source: u16::from_le_bytes(bytes[24..26].try_into().expect("in range")),
            // Anything other than the parity marker is data: a kind byte this build does not know
            // is a newer node, and refusing the frame would break you over a field you do not use.
            is_data: bytes[26] != 1,
            bytes: &bytes[Self::HEADER_LEN..],
        })
    }
}
