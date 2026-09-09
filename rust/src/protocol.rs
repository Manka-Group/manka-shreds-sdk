//! The manka-shreds wire protocol: frames and control messages.
//!
//! Everything here is byte layout, kept separate from the client so a consumer driving the protocol
//! some other way — a different transport, a proxy, a replay tool — can use the parsing without the
//! socket handling.

use crate::{
    error::{Error, Result},
    handshake::{KeyRef, Proof},
};

/// Protocol version this implementation speaks.
pub const PROTOCOL_VERSION: u16 = 1;

/// Bytes in a frame header.
pub const FRAME_HEADER_LEN: usize = 16;

/// Largest payload a frame may carry.
pub const MAX_FRAME_PAYLOAD: usize = 16 << 20;

/// What a frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// A kind this build does not recognise. Never sent; produced when reading.
    Unknown = 0,
    /// A decoded transaction.
    Transaction = 1,
    /// A proof-of-history entry.
    Entry = 2,
    /// The first shred of a slot arrived.
    SlotStart = 3,
    /// A slot finished.
    SlotEnd = 4,
    /// A leader equivocated.
    Duplicate = 5,
    /// A shred republished verbatim.
    RawShred = 6,
    /// Frames this connection missed.
    Lag = 7,
    /// Ingress source statistics.
    SourceStats = 8,
    /// A client's greeting.
    Hello = 9,
    /// The server's reply to a greeting.
    HelloAck = 10,
    /// The server's verdict on a filter.
    FilterAck = 11,
    /// The server refused or closed.
    Error = 12,
    /// A liveness probe.
    Ping = 13,
    /// The answer to a probe.
    Pong = 14,
    /// A filter submission.
    SetFilter = 15,
    /// The server's nonce and its proof that it holds the key.
    Challenge = 16,
    /// The client's proof that it holds the key.
    Prove = 17,
    /// The compression dictionary the server wants this connection to use.
    Dictionary = 18,
}

impl FrameKind {
    /// Reads a kind byte, mapping anything unrecognised to [`FrameKind::Unknown`].
    ///
    /// An unrecognised kind is not an error: a client built before a frame type existed must skip
    /// it, not drop the connection, or adding one would break every deployed subscriber.
    #[inline]
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Transaction,
            2 => Self::Entry,
            3 => Self::SlotStart,
            4 => Self::SlotEnd,
            5 => Self::Duplicate,
            6 => Self::RawShred,
            7 => Self::Lag,
            8 => Self::SourceStats,
            9 => Self::Hello,
            10 => Self::HelloAck,
            11 => Self::FilterAck,
            12 => Self::Error,
            13 => Self::Ping,
            14 => Self::Pong,
            15 => Self::SetFilter,
            16 => Self::Challenge,
            17 => Self::Prove,
            18 => Self::Dictionary,
            _ => Self::Unknown,
        }
    }
}

/// What this client can accept beyond the streams it subscribes to.
///
/// A bitmask in the greeting, in a byte that was previously padding. Absent bits mean "no", which is
/// what a client built before this existed should be taken to have said.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Capabilities(pub u8);

impl Capabilities {
    /// This client will accept the server's compression dictionary on this connection.
    ///
    /// Without it the server never sends one. With it, a client holding no dictionary — or a
    /// different one — is brought up to the server's during the handshake and streams at the full
    /// ratio from its first message, rather than paying roughly three times the bandwidth until
    /// somebody notices it was never given one.
    pub const ACCEPTS_DICTIONARY: u8 = 1 << 0;

    /// Whether every bit in `bits` is set.
    ///
    /// "All of these", not "any of these": a future bit must never imply a present one.
    #[inline]
    pub const fn has(self, bits: u8) -> bool {
        self.0 & bits == bits
    }
}

/// Largest dictionary this client will accept from a server.
///
/// The one thing a server hands a client that is neither fixed-width nor bounded by something the
/// client asked for, so it needs a bound of its own — otherwise a hostile or compromised node
/// streams as much "dictionary" as this side will allocate. Far past any dictionary worth training:
/// the ratio stops improving well below it.
pub const MAX_DICTIONARY_BYTES: usize = 8 << 20;

/// Largest control message this client will read while the handshake is in progress.
///
/// A challenge is sixty-four bytes and an acknowledgement is smaller; the only variable one is an
/// error, whose detail is a sentence. It needs a bound because the length is the *server's* to
/// choose and it is what this side allocates against — and at this point in the exchange the server
/// has proved nothing. Judged by [`MAX_FRAME_PAYLOAD`] instead, any address you dial could cost you
/// sixteen megabytes for the price of a header.
pub const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;

/// The compression dictionary a connection will use, sent by the server.
///
/// Arrives once, after the acknowledgement and before the first data frame, and only when this
/// client asked for one and does not already hold the one the server is using.
///
/// The id travels beside the bytes so the message is self-describing: check it against what the
/// acknowledgement announced rather than trusting the pairing to have survived the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dictionary {
    /// Identifier of these bytes, matching what the acknowledgement announced.
    pub id: u32,
    /// The dictionary itself.
    pub bytes: Vec<u8>,
}

impl Dictionary {
    /// Bytes before the payload.
    pub const HEADER_LEN: usize = 8;

    /// Reads the message, refusing one larger than [`MAX_DICTIONARY_BYTES`].
    ///
    /// The declared length is checked *before* the body is taken, so a number a peer invented
    /// cannot decide how much this side allocates.
    pub fn read(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(Error::Truncated {
                what: "dictionary",
                need: Self::HEADER_LEN,
                have: bytes.len(),
            });
        }
        let id = u32::from_le_bytes(bytes[0..4].try_into().expect("bounds checked"));
        let len = u32::from_le_bytes(bytes[4..8].try_into().expect("bounds checked")) as usize;
        if len > MAX_DICTIONARY_BYTES {
            return Err(Error::Handshake(format!(
                "the server sent a {len}-byte dictionary; the limit is {MAX_DICTIONARY_BYTES}"
            )));
        }
        let body = bytes
            .get(Self::HEADER_LEN..Self::HEADER_LEN + len)
            .ok_or(Error::Truncated {
                what: "dictionary",
                need: Self::HEADER_LEN + len,
                have: bytes.len(),
            })?;
        Ok(Self {
            id,
            bytes: body.to_vec(),
        })
    }

    /// Appends the encoded message to `out`.
    ///
    /// A client never sends one. This exists so a test can build what a server would.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&(self.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.bytes);
    }
}

/// Streams a subscriber may ask for.
///
/// A key grants a subset; the server grants the intersection of what was asked and what the key
/// permits, so asking for more than the key allows is not an error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct StreamMask(pub u32);

impl StreamMask {
    /// Decoded transactions.
    pub const TRANSACTIONS: u32 = 1 << 0;
    /// Proof-of-history entries.
    pub const ENTRIES: u32 = 1 << 1;
    /// Slot starts and ends.
    pub const SLOT_EVENTS: u32 = 1 << 2;
    /// Equivocation reports.
    pub const DUPLICATES: u32 = 1 << 3;
    /// Every shred verbatim, before the node verifies or decodes anything.
    ///
    /// The highest-rate stream published — a multiple of [`Self::TRANSACTIONS`], since a shred is a
    /// fragment and most fragments carry votes. Nothing on it is claimed to be leader-signed.
    pub const RAW_SHREDS: u32 = 1 << 4;
    /// Reserved on the wire; no producer exists.
    pub const SOURCE_STATS: u32 = 1 << 5;
    /// Vote transactions, which are excluded from [`Self::TRANSACTIONS`] unless this is set.
    pub const VOTES: u32 = 1 << 6;

    /// Every stream that is actually published.
    pub const ALL: Self = Self(
        Self::TRANSACTIONS
            | Self::ENTRIES
            | Self::SLOT_EVENTS
            | Self::DUPLICATES
            | Self::RAW_SHREDS
            | Self::VOTES,
    );

    /// Whether every stream in `other` is present.
    #[inline]
    pub const fn contains(self, other: u32) -> bool {
        self.0 & other == other
    }
}

/// Compression codecs. The value is what travels in the frame flags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Codec {
    /// The payload is not compressed.
    #[default]
    None = 0,
    /// lz4, which this SDK never negotiates.
    Lz4 = 1,
    /// zstd, optionally with a negotiated dictionary.
    Zstd = 2,
}

impl Codec {
    /// Reads a codec byte.
    #[inline]
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Lz4,
            2 => Self::Zstd,
            _ => Self::None,
        }
    }
}

/// Bit offered in a handshake for [`Codec::Zstd`].
pub const CODEC_BIT_ZSTD: u8 = 1 << 2;

/// Why the server refused or closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    /// The key or secret was not accepted.
    Unauthorized = 1,
    /// The key does not permit what was asked.
    Forbidden = 2,
    /// The subscriber fell too far behind and was disconnected.
    TooSlow = 3,
    /// Too many requests.
    RateLimited = 4,
    /// The request was malformed, or violated a server policy such as required compression.
    BadRequest = 5,
    /// The server is going away.
    Shutdown = 6,
    /// The server does not speak this protocol version.
    UnsupportedVersion = 7,
    /// A code this build does not recognise.
    Unknown = 0,
}

impl ErrorCode {
    /// Reads a code, mapping anything unrecognised to [`ErrorCode::Unknown`].
    #[inline]
    pub const fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::Unauthorized,
            2 => Self::Forbidden,
            3 => Self::TooSlow,
            4 => Self::RateLimited,
            5 => Self::BadRequest,
            6 => Self::Shutdown,
            7 => Self::UnsupportedVersion,
            _ => Self::Unknown,
        }
    }
}

/// How much the server could vouch for a transaction or entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    /// The leader's signature over the FEC set's merkle root checked out.
    Verified,
    /// The node runs with signature verification switched off.
    Disabled,
    /// No leader is known for the slot.
    UnknownLeader,
    /// The leader schedule is behind.
    StaleSchedule,
}

impl Verification {
    /// Reads the one-byte encoding used by entry frames.
    #[inline]
    pub(crate) const fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Verified,
            2 => Self::UnknownLeader,
            3 => Self::StaleSchedule,
            _ => Self::Disabled,
        }
    }
}

/// A decoded frame header.
#[derive(Clone, Copy, Debug)]
pub struct FrameHeader {
    /// Payload bytes following the header.
    pub len: usize,
    /// What the payload is, as far as this build recognises it.
    pub kind: FrameKind,
    /// The kind byte exactly as it arrived, so an unknown frame keeps its identity.
    pub raw_kind: u8,
    /// Whether the payload is compressed.
    pub compressed: bool,
    /// The codec the payload was compressed with.
    pub codec: Codec,
    /// Which of this connection's named filters the frame matched.
    ///
    /// Empty when the connection named none. Sixteen filters fit, in two bytes the header already
    /// carried as padding — widening it would add eight bytes to every frame to serve a case
    /// nobody has asked for, and network is what this spends most of.
    pub matched: FilterMask,
    /// Per-connection sequence number. A gap is exactly what was dropped.
    pub seq: u64,
}

/// Which named filters a frame matched.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct FilterMask(pub u16);

impl FilterMask {
    /// Named filters one connection may hold.
    pub const CAPACITY: usize = 16;

    /// Nothing matched, or nothing was named.
    pub const NONE: Self = Self(0);

    /// Whether the filter at `index` matched.
    #[inline]
    pub const fn has(self, index: u8) -> bool {
        self.0 & (1u16 << index) != 0
    }

    /// Whether nothing matched.
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Indices of the filters that matched.
    pub fn iter(self) -> impl Iterator<Item = u8> {
        (0..Self::CAPACITY as u8).filter(move |index| self.has(*index))
    }
}

/// Reads a frame header.
pub fn read_frame_header(bytes: &[u8]) -> Result<FrameHeader> {
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(Error::Truncated {
            what: "frame header",
            need: FRAME_HEADER_LEN,
            have: bytes.len(),
        });
    }
    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len > MAX_FRAME_PAYLOAD {
        return Err(Error::FrameTooLarge { len });
    }
    let flags = bytes[5];
    Ok(FrameHeader {
        len,
        kind: FrameKind::from_byte(bytes[4]),
        raw_kind: bytes[4],
        compressed: flags & 0b100 != 0,
        codec: Codec::from_byte(flags & 0b11),
        matched: FilterMask(u16::from_le_bytes([bytes[6], bytes[7]])),
        seq: u64::from_le_bytes(bytes[8..16].try_into().expect("bounds checked")),
    })
}

/// Appends a frame carrying `payload` to `out`.
pub fn write_frame(out: &mut Vec<u8>, kind: FrameKind, seq: u64, payload: &[u8]) {
    out.reserve(FRAME_HEADER_LEN + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.push(kind as u8);
    out.push(0);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(payload);
}

/// What a client offers when it connects.
///
/// **Carries no credential.** Your key is named by [`KeyRef`], a one-way function of it, and
/// possession is proved afterwards — see [`crate::handshake`]. A captured greeting is worth nothing.
#[derive(Clone, Debug)]
pub struct Hello {
    /// Streams to subscribe to.
    pub streams: StreamMask,
    /// Codecs this client can decode.
    pub codecs: u8,
    /// Which key is claimed, without disclosing it.
    pub key_ref: KeyRef,
    /// Fresh per connection, so a captured server proof cannot be replayed at this client.
    pub client_nonce: [u8; 32],
    /// What this client can be sent beyond the streams themselves.
    ///
    /// Occupies a byte the greeting has always written as zero and never read, so a client built
    /// before this existed reads as advertising nothing — the correct answer for it.
    pub capabilities: Capabilities,
    /// Content hash of the dictionary this client holds, or zero for none.
    pub dictionary_id: u32,
    /// A filter document to install before the stream starts, if any.
    pub filter: Option<String>,
}

impl Hello {
    /// Appends the encoded greeting to `out`.
    ///
    /// The reference and the nonce are fixed width, so the greeting has no variable-length
    /// credential fields — there is no credential in it to be variable. The dictionary id trails
    /// them so a peer that stops reading there still parses: a missing id simply means no
    /// dictionary. The filter trails that in turn, on the same principle.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        out.extend_from_slice(&self.streams.0.to_le_bytes());
        out.push(self.codecs);
        out.push(self.capabilities.0);
        out.extend_from_slice(&self.key_ref.0);
        out.extend_from_slice(&self.client_nonce);
        out.extend_from_slice(&self.dictionary_id.to_le_bytes());
        if let Some(filter) = &self.filter {
            out.extend_from_slice(&(filter.len() as u32).to_le_bytes());
            out.extend_from_slice(filter.as_bytes());
        }
    }
}

/// The server's nonce and its proof that it holds your key.
///
/// Sent before you have proved anything. Checking it is what tells you the peer is the node rather
/// than something sitting in front of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// Chosen by the server.
    pub server_nonce: [u8; 32],
    /// `HMAC(key, "server" ‖ transcript)`.
    pub proof: Proof,
}

impl Challenge {
    /// Bytes in the encoded message.
    pub const LEN: usize = 64;

    /// Reads the message.
    pub fn read(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::LEN {
            return Err(Error::Truncated {
                what: "challenge",
                need: Self::LEN,
                have: bytes.len(),
            });
        }
        let mut server_nonce = [0u8; 32];
        server_nonce.copy_from_slice(&bytes[0..32]);
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&bytes[32..64]);
        Ok(Self {
            server_nonce,
            proof: Proof(proof),
        })
    }
}

/// Your proof that you hold the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prove {
    /// `HMAC(key, "client" ‖ transcript)`.
    pub proof: Proof,
}

impl Prove {
    /// Bytes in the encoded message.
    pub const LEN: usize = 32;

    /// Appends the encoded message to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.proof.0);
    }
}

/// What the server settled.
#[derive(Clone, Copy, Debug)]
pub struct HelloAck {
    /// Version the server speaks.
    pub protocol_version: u16,
    /// Streams actually granted.
    pub granted: StreamMask,
    /// This connection's server-assigned id, which the operator's logs are keyed by.
    pub session_id: u64,
    /// The negotiated codec.
    pub codec: Codec,
    /// How often the server pings an idle connection.
    pub keepalive_ms: u16,
    /// Non-zero only when the server holds the same dictionary this client offered.
    pub dictionary_id: u32,
}

impl HelloAck {
    /// Bytes in the encoded message.
    pub const LEN: usize = 22;

    /// Reads an acknowledgement.
    pub fn read(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::LEN {
            return Err(Error::Truncated {
                what: "hello ack",
                need: Self::LEN,
                have: bytes.len(),
            });
        }
        Ok(Self {
            protocol_version: u16::from_le_bytes([bytes[0], bytes[1]]),
            granted: StreamMask(u32::from_le_bytes(
                bytes[2..6].try_into().expect("bounds checked"),
            )),
            session_id: u64::from_le_bytes(bytes[6..14].try_into().expect("bounds checked")),
            codec: Codec::from_byte(bytes[14]),
            keepalive_ms: u16::from_le_bytes([bytes[16], bytes[17]]),
            dictionary_id: u32::from_le_bytes(bytes[18..22].try_into().expect("bounds checked")),
        })
    }
}

/// The server refused, or is closing the connection.
#[derive(Clone, Debug)]
pub struct ErrorMessage {
    /// Why.
    pub code: ErrorCode,
    /// A human-readable explanation.
    pub detail: String,
}

impl ErrorMessage {
    /// Reads an error message.
    pub fn read(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(Error::Truncated {
                what: "error",
                need: 4,
                have: bytes.len(),
            });
        }
        let len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let end = (4 + len).min(bytes.len());
        Ok(Self {
            code: ErrorCode::from_u16(u16::from_le_bytes([bytes[0], bytes[1]])),
            detail: String::from_utf8_lossy(&bytes[4..end]).into_owned(),
        })
    }
}

/// Frames this client missed, and where the stream resumes.
#[derive(Clone, Copy, Debug)]
pub struct Lag {
    /// How many frames were dropped.
    pub dropped: u64,
    /// The sequence number the stream continues from.
    pub resume_seq: u64,
}

impl Lag {
    /// Bytes in the encoded message.
    pub const LEN: usize = 16;

    /// Reads a lag report.
    pub fn read(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::LEN {
            return Err(Error::Truncated {
                what: "lag",
                need: Self::LEN,
                have: bytes.len(),
            });
        }
        Ok(Self {
            dropped: u64::from_le_bytes(bytes[0..8].try_into().expect("bounds checked")),
            resume_seq: u64::from_le_bytes(bytes[8..16].try_into().expect("bounds checked")),
        })
    }
}

/// The server's verdict on a submitted filter.
#[derive(Clone, Debug)]
pub struct FilterAck {
    /// Whether the filter is now in force.
    pub accepted: bool,
    /// Measured cost, whether or not it was accepted.
    pub cost: u32,
    /// Why it was refused, when it was.
    pub detail: String,
}

impl FilterAck {
    /// Reads a filter acknowledgement.
    pub fn read(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::Truncated {
                what: "filter ack",
                need: 8,
                have: bytes.len(),
            });
        }
        let len = u16::from_le_bytes([bytes[6], bytes[7]]) as usize;
        let end = (8 + len).min(bytes.len());
        Ok(Self {
            accepted: bytes[0] != 0,
            cost: u32::from_le_bytes(bytes[2..6].try_into().expect("bounds checked")),
            detail: String::from_utf8_lossy(&bytes[8..end]).into_owned(),
        })
    }
}

/// The content hash a dictionary is identified by.
///
/// FNV-1a folded to 32 bits, matching the server exactly. Two peers agree on a dictionary by
/// agreeing on this number, so it must be computed the same way on both sides or the dictionary is
/// silently never used. Not cryptographic: this detects a mismatch, it does not defend against one
/// being forged — and a forged id only produces a decode failure.
pub fn dictionary_id(dictionary: &[u8]) -> u32 {
    if dictionary.is_empty() {
        return 0;
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in dictionary {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let folded = ((hash >> 32) ^ hash) as u32;
    // Zero is reserved for "none", so a dictionary that happens to hash to it is nudged.
    if folded == 0 { 1 } else { folded }
}
