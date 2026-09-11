"""The manka-shreds wire protocol: frames, control messages and message layouts.

Everything here is byte layout. It is kept separate from the client so that a consumer wanting to
drive the protocol some other way — a different transport, a proxy, a replay tool — can use the
parsing without the socket handling.

Offsets are fixed and every section is 8-byte aligned, which is why fields are read by pointing at
them rather than by walking length prefixes.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from enum import IntEnum, StrEnum

__all__ = [
    "ALL_STREAMS",
    "Capability",
    "Challenge",
    "Codec",
    "CodecBit",
    "DICTIONARY_HEADER_LEN",
    "Dictionary",
    "ErrorCode",
    "FRAME_HEADER_LEN",
    "FilterAck",
    "FrameHeader",
    "FrameKind",
    "HELLO_ACK_LEN",
    "Hello",
    "HelloAck",
    "Lag",
    "MAX_DICTIONARY_BYTES",
    "MAX_FRAME_PAYLOAD",
    "MAX_HANDSHAKE_BYTES",
    "NamedFilter",
    "PROTOCOL_VERSION",
    "ProtocolError",
    "ServerError",
    "Stream",
    "Verification",
    "dictionary_id",
    "read_challenge",
    "read_dictionary",
    "read_error",
    "read_filter_ack",
    "read_frame_header",
    "read_hello_ack",
    "read_lag",
    "write_dictionary",
    "write_frame",
    "write_hello",
    "write_prove",
    "write_set_filter",
]

#: Protocol version this implementation speaks.
PROTOCOL_VERSION = 1

#: Bytes in a frame header.
FRAME_HEADER_LEN = 16

#: Largest payload a frame may carry.
MAX_FRAME_PAYLOAD = 16 << 20


class FrameKind(IntEnum):
    """What a frame carries."""

    #: A kind this build does not recognise. Never sent; produced when reading.
    UNKNOWN = 0
    TRANSACTION = 1
    ENTRY = 2
    SLOT_START = 3
    SLOT_END = 4
    DUPLICATE = 5
    RAW_SHRED = 6
    LAG = 7
    SOURCE_STATS = 8
    HELLO = 9
    HELLO_ACK = 10
    FILTER_ACK = 11
    ERROR = 12
    PING = 13
    PONG = 14
    SET_FILTER = 15
    #: The server's nonce and its proof that it holds the key.
    CHALLENGE = 16
    #: The client's proof that it holds the key.
    PROVE = 17
    #: The compression dictionary the server wants this connection to use.
    DICTIONARY = 18


class Stream(IntEnum):
    """Streams a subscriber may ask for.

    A key grants a subset; the server grants the intersection.
    """

    TRANSACTIONS = 1 << 0
    ENTRIES = 1 << 1
    SLOT_EVENTS = 1 << 2
    DUPLICATES = 1 << 3
    #: Every shred verbatim, before the node verifies or decodes anything.
    #:
    #: The highest-rate stream published — a multiple of :attr:`TRANSACTIONS`, since a shred is a
    #: fragment and most fragments carry votes. Nothing on it is claimed to be leader-signed.
    RAW_SHREDS = 1 << 4
    #: Reserved on the wire; no producer exists and the name is refused at key load.
    SOURCE_STATS = 1 << 5
    VOTES = 1 << 6


#: Every stream that is actually published.
ALL_STREAMS = (
    Stream.TRANSACTIONS
    | Stream.ENTRIES
    | Stream.SLOT_EVENTS
    | Stream.DUPLICATES
    | Stream.RAW_SHREDS
    | Stream.VOTES
)


class Codec(IntEnum):
    """Compression codecs. The value is what travels in the frame flags."""

    NONE = 0
    LZ4 = 1
    ZSTD = 2


class CodecBit(IntEnum):
    """Bits offered in a handshake, one per codec this client can decode."""

    NONE = 1 << 0
    LZ4 = 1 << 1
    ZSTD = 1 << 2


class Capability(IntEnum):
    """What a client can accept beyond the streams it subscribes to.

    A bitmask in the greeting, in a byte that was previously padding. Absent bits mean "no", which
    is what a client built before this existed should be taken to have said.
    """

    #: This client will accept the server's compression dictionary on this connection.
    #:
    #: Without it the server never sends one. With it, a client holding no dictionary — or a
    #: different one — is brought up to the server's during the handshake and streams at the full
    #: ratio from its first message, rather than paying roughly three times the bandwidth until
    #: somebody notices it was never given one.
    ACCEPTS_DICTIONARY = 1 << 0


#: Largest dictionary this client will accept from a server.
#:
#: The one thing a server hands a client that is neither fixed-width nor bounded by something the
#: client asked for, so it needs a bound of its own — otherwise a hostile or compromised node
#: streams as much "dictionary" as this side will allocate.
MAX_DICTIONARY_BYTES = 8 << 20

#: Largest control message this client will read while the handshake is in progress.
#:
#: A challenge is sixty-four bytes and an acknowledgement is smaller; the only variable one is an
#: error, whose detail is a sentence. It needs a bound because the length is the *server's* to
#: choose and it is what this side buffers against — and at this point in the exchange the server
#: has proved nothing.
MAX_HANDSHAKE_BYTES = 64 * 1024


class ProtocolError(Exception):
    """Anything the protocol could not be read as."""


class ServerError(Exception):
    """The server refused the connection, or closed it."""

    def __init__(self, code: int, detail: str) -> None:
        try:
            name = ErrorCode(code).name
        except ValueError:
            name = str(code)
        super().__init__(f"server error {name}: {detail}")
        self.code = code
        self.detail = detail


class ErrorCode(IntEnum):
    """Why the server refused or closed."""

    UNAUTHORIZED = 1
    FORBIDDEN = 2
    TOO_SLOW = 3
    RATE_LIMITED = 4
    BAD_REQUEST = 5
    SHUTDOWN = 6
    UNSUPPORTED_VERSION = 7


class Verification(StrEnum):
    """How much a transaction's FEC set could be vouched for."""

    #: The leader's signature over the set's merkle root checked out.
    VERIFIED = "verified"
    #: The node runs with verification switched off.
    DISABLED = "disabled"
    #: No leader is known for the slot.
    UNKNOWN_LEADER = "unknown-leader"
    #: The leader schedule is behind.
    STALE_SCHEDULE = "stale-schedule"


@dataclass(frozen=True, slots=True)
class Dictionary:
    """The compression dictionary a connection will use, as the server sends it."""

    #: Identifier of these bytes, matching what the acknowledgement announced.
    id: int
    #: The dictionary itself.
    bytes: bytes


#: Bytes before a dictionary's payload.
DICTIONARY_HEADER_LEN = 8


def read_dictionary(buf: bytes) -> Dictionary:
    """Read a dictionary message, refusing one larger than :data:`MAX_DICTIONARY_BYTES`.

    The declared length is checked *before* the body is taken, so a number a peer invented cannot
    decide how much this side allocates.
    """
    if len(buf) < DICTIONARY_HEADER_LEN:
        raise ProtocolError(f"dictionary needs {DICTIONARY_HEADER_LEN} bytes, have {len(buf)}")
    ident, length = struct.unpack_from("<II", buf, 0)
    if length > MAX_DICTIONARY_BYTES:
        raise ProtocolError(
            f"the server sent a {length}-byte dictionary; the limit is {MAX_DICTIONARY_BYTES}"
        )
    if len(buf) < DICTIONARY_HEADER_LEN + length:
        raise ProtocolError(
            f"dictionary needs {DICTIONARY_HEADER_LEN + length} bytes, have {len(buf)}"
        )
    return Dictionary(
        id=ident,
        bytes=bytes(buf[DICTIONARY_HEADER_LEN : DICTIONARY_HEADER_LEN + length]),
    )


def write_dictionary(dictionary: Dictionary) -> bytes:
    """Encode a dictionary message.

    A client never sends one. This exists so a test can build what a server would.
    """
    return struct.pack("<II", dictionary.id, len(dictionary.bytes)) + dictionary.bytes


@dataclass(frozen=True, slots=True)
class FrameHeader:
    """A decoded frame header."""

    #: Payload bytes following the header.
    len: int
    #: What the payload is, as far as this build recognises it.
    kind: FrameKind
    #: The kind byte exactly as it arrived, so an unknown frame keeps its identity.
    raw_kind: int
    #: Whether the payload is compressed.
    compressed: bool
    #: Codec the payload was compressed with.
    codec: Codec
    #: Which of this connection's named filters the frame matched, as a bitmask.
    #:
    #: Zero when the connection named no filters. Bit ``i`` is the filter at index ``i`` in the set
    #: that was submitted; one transaction can match several and is delivered once with every match
    #: recorded, rather than once per filter.
    matched: int
    #: Per-connection sequence number. A gap is exactly what was dropped.
    seq: int


def read_frame_header(buf: bytes, at: int = 0) -> FrameHeader:
    """Read a frame header.

    An unrecognised kind is not an error: a client built before a frame type existed must skip it,
    not drop the connection, or adding one would break every deployed subscriber.
    """
    if len(buf) - at < FRAME_HEADER_LEN:
        raise ProtocolError(f"frame header needs {FRAME_HEADER_LEN} bytes, have {len(buf) - at}")
    length, raw_kind, flags, matched, seq = struct.unpack_from("<IBBHQ", buf, at)
    if length > MAX_FRAME_PAYLOAD:
        raise ProtocolError(f"frame declares {length} payload bytes, limit is {MAX_FRAME_PAYLOAD}")
    try:
        kind = FrameKind(raw_kind)
    except ValueError:
        kind = FrameKind.UNKNOWN
    return FrameHeader(
        len=length,
        kind=kind,
        raw_kind=raw_kind,
        compressed=(flags & 0b100) != 0,
        codec=Codec(flags & 0b11),
        matched=matched,
        seq=seq,
    )


def write_frame(kind: FrameKind, seq: int, payload: bytes, matched: int = 0) -> bytes:
    """Write a frame with ``payload`` as its body."""
    return struct.pack("<IBBHQ", len(payload), int(kind), 0, matched, seq) + payload


# -------------------------------------------------------------------------------------------------
# Handshake
# -------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Hello:
    """What a client offers when it connects.

    **Carries no credential.** Your key is named by a one-way reference and proved afterwards — see
    :mod:`manka_shreds_sdk.handshake`. A captured greeting is worth nothing.
    """

    streams: int
    codecs: int
    #: Which key is claimed, without disclosing it. 32 bytes.
    key_ref: bytes
    #: Fresh per connection, so a captured server proof cannot be replayed at this client. 32 bytes.
    client_nonce: bytes
    #: What this client can be sent beyond the streams themselves — see :class:`Capability`.
    capabilities: int = 0
    #: Content hash of the dictionary this client holds, or zero for none.
    dictionary_id: int = 0
    #: A filter document to install before the stream starts, if any.
    filter: str | None = None


def write_hello(hello: Hello) -> bytes:
    """Encode a greeting.

    The reference and the nonce are fixed width, so the greeting has no variable-length credential
    fields — there is no credential in it to be variable. The dictionary id trails them so a peer
    that stops reading there still parses: a missing id simply means no dictionary. The filter
    trails that in turn, length-prefixed with a ``u32`` because a filter naming two thousand
    accounts is far past 64 KiB.
    """
    out = bytearray(76)
    struct.pack_into("<HIBB", out, 0, PROTOCOL_VERSION, hello.streams, hello.codecs, hello.capabilities)
    out[8:40] = hello.key_ref
    out[40:72] = hello.client_nonce
    struct.pack_into("<I", out, 72, hello.dictionary_id)
    if hello.filter is not None:
        # Byte length, not character count: a filter is base58 today but the field is UTF-8.
        encoded = hello.filter.encode("utf-8")
        out += struct.pack("<I", len(encoded)) + encoded
    return bytes(out)


@dataclass(frozen=True, slots=True)
class Challenge:
    """The server's nonce and its proof that it holds your key.

    Sent before you have proved anything. Checking it is what tells you the peer is the node rather
    than something sitting in front of it.
    """

    server_nonce: bytes
    proof: bytes


def read_challenge(buf: bytes) -> Challenge:
    """Decode a challenge."""
    if len(buf) < 64:
        raise ProtocolError("challenge truncated")
    return Challenge(server_nonce=bytes(buf[0:32]), proof=bytes(buf[32:64]))


def write_prove(proof: bytes) -> bytes:
    """Encode your proof that you hold the key."""
    return bytes(proof)


@dataclass(frozen=True, slots=True)
class HelloAck:
    """What the server settled."""

    protocol_version: int
    session_id: int
    #: Streams actually granted — the intersection of what was asked and what the key permits.
    granted: int
    codec: Codec
    #: How often the server pings an idle connection.
    keepalive_ms: int
    #: Non-zero only when the server holds the same dictionary this client offered.
    dictionary_id: int


#: Bytes in an encoded acknowledgement.
HELLO_ACK_LEN = 22


def read_hello_ack(buf: bytes) -> HelloAck:
    """Decode an acknowledgement."""
    if len(buf) < HELLO_ACK_LEN:
        raise ProtocolError(f"hello ack needs {HELLO_ACK_LEN} bytes, have {len(buf)}")
    version, granted, session, codec = struct.unpack_from("<HIQB", buf, 0)
    # Byte 15 is reserved.
    keepalive, dictionary_id = struct.unpack_from("<HI", buf, 16)
    return HelloAck(
        protocol_version=version,
        granted=granted,
        session_id=session,
        codec=Codec(codec),
        keepalive_ms=keepalive,
        dictionary_id=dictionary_id,
    )


def read_error(buf: bytes) -> ServerError:
    """Decode an error message."""
    if len(buf) < 4:
        raise ProtocolError("error message truncated")
    code, length = struct.unpack_from("<HH", buf, 0)
    detail = bytes(buf[4 : 4 + length]).decode("utf-8", errors="replace")
    return ServerError(code, detail)


@dataclass(frozen=True, slots=True)
class Lag:
    """Frames this client missed, and where the stream resumes."""

    dropped: int
    resume_seq: int


def read_lag(buf: bytes) -> Lag:
    """Decode a lag report."""
    if len(buf) < 16:
        raise ProtocolError("lag message truncated")
    dropped, resume = struct.unpack_from("<QQ", buf, 0)
    return Lag(dropped=dropped, resume_seq=resume)


@dataclass(frozen=True, slots=True)
class FilterAck:
    """The server's verdict on a submitted filter."""

    accepted: bool
    cost: int
    detail: str


def read_filter_ack(buf: bytes) -> FilterAck:
    """Decode a filter acknowledgement."""
    if len(buf) < 8:
        raise ProtocolError("filter ack truncated")
    accepted = buf[0] != 0
    # Byte 1 is reserved.
    (cost,) = struct.unpack_from("<I", buf, 2)
    (length,) = struct.unpack_from("<H", buf, 6)
    detail = bytes(buf[8 : 8 + length]).decode("utf-8", errors="replace")
    return FilterAck(accepted=accepted, cost=cost, detail=detail)


@dataclass(frozen=True, slots=True)
class NamedFilter:
    """One filter, with the name the subscriber chose for it."""

    #: The filter itself.
    spec: dict
    #: What you call it. Comes back in a refusal so you know which one was at fault.
    name: str | None = None


def write_set_filter(filters: list[NamedFilter]) -> bytes:
    """Encode a filter submission. The frame length delimits it, so the JSON needs no prefix.

    The whole set replaces whatever the connection carried, and is accepted or refused together — a
    connection is never left holding part of what was asked for.
    """
    body = {
        "filters": [
            {"name": f.name, "spec": f.spec} if f.name is not None else {"spec": f.spec}
            for f in filters
        ]
    }
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def dictionary_id(dictionary: bytes) -> int:
    """The content hash a dictionary is identified by.

    FNV-1a folded to 32 bits, matching the server exactly. Two peers agree on a dictionary by
    agreeing on this number, so it must be computed the same way on both sides or the dictionary is
    silently never used.
    """
    if not dictionary:
        return 0
    hash_ = 0xCBF29CE484222325
    prime = 0x100000001B3
    mask = 0xFFFFFFFFFFFFFFFF
    for byte in dictionary:
        hash_ = ((hash_ ^ byte) * prime) & mask
    folded = (hash_ ^ (hash_ >> 32)) & 0xFFFFFFFF
    # Zero means "no dictionary", so a hash that lands there is nudged rather than misread.
    return 1 if folded == 0 else folded
