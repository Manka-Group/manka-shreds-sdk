"""The transaction message.

A fixed 104-byte header followed by sections in a fixed order, each 8-byte aligned::

      0  u64  slot                 64  u32  fec_set_index
      8  u64  parent_slot          68  u32  entry_index
     16  u64  rx_ts_ns             72  u32  tx_index
     24  u64  emit_ts_ns           76  u32  instruction_bytes_len
     32  [32] leader               80  u32  lookup_bytes_len
                                   84  u32  raw_tx_len
                                   88  u16  source_id
                                   90  u16  flags
                                   92  u16  account_count
                                   94  u16  instruction_count
                                   96  u8   signature_count
                                   97  u8   message_version   (0xff = legacy)
                                   98  u8   lookup_count
                                   99  u8   required_signatures
                                  100  u8   readonly_signed
                                  101  u8   readonly_unsigned
                                  102  u16  reserved
    104     signatures         signature_count * 64
            account_keys       account_count * 32
            recent_blockhash   32
            instruction_table  instruction_count * 16
            instruction_bytes  padded to 8
            lookup_table       lookup_count * 40
            lookup_bytes       padded to 8
            raw_tx             raw_tx_len, only when the flag is set

The fixed offsets are what make reading cheap: every field is a load at a known position and every
byte string is a ``memoryview`` slice, never a copy. Nothing is decoded until it is asked for, so a
subscriber that only looks at, say, the first account key never pays for the rest.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntFlag

from .protocol import ProtocolError, Verification

__all__ = [
    "INSTRUCTION_ENTRY_LEN",
    "LOOKUP_ENTRY_LEN",
    "MESSAGE_VERSION_LEGACY",
    "TX_HEADER_LEN",
    "AddressLookup",
    "Instruction",
    "Transaction",
    "TxFlag",
]

#: Bytes in the fixed header.
TX_HEADER_LEN = 104
#: Bytes in one instruction table entry.
INSTRUCTION_ENTRY_LEN = 16
#: Bytes in one address lookup table entry.
LOOKUP_ENTRY_LEN = 40


class TxFlag(IntFlag):
    """Bits in the transaction header's flag field."""

    #: The transaction is a simple vote.
    IS_VOTE = 1 << 0
    #: The FEC set's leader signature verified.
    VERIFIED = 1 << 1
    #: The raw transaction bytes are appended.
    HAS_RAW_TX = 1 << 2
    #: The FEC set had to be reconstructed from parity.
    RECOVERED = 1 << 3
    #: The leader was known and named in the header.
    HAS_LEADER = 1 << 4


_REASON_SHIFT = 5
_REASON_MASK = 0b11

#: Marks a legacy (pre-versioned) message.
MESSAGE_VERSION_LEGACY = 0xFF


@dataclass(frozen=True, slots=True)
class Instruction:
    """One instruction, pointing into the message's shared byte region."""

    #: Index into ``account_keys`` of the program being invoked.
    program_id_index: int
    #: Indices into ``account_keys``, in the order the program expects them.
    accounts: bytes
    #: Opaque instruction data.
    data: bytes


@dataclass(frozen=True, slots=True)
class AddressLookup:
    """One address lookup table reference, carried unresolved."""

    #: The lookup table account.
    account_key: bytes
    #: Indices loaded as writable.
    writable_indexes: bytes
    #: Indices loaded as readonly.
    readonly_indexes: bytes


def _align8(length: int) -> int:
    """Round up to a multiple of 8."""
    return (length + 7) & ~7


class Transaction:
    """A decoded transaction.

    Backed directly by the received buffer. Accessors return ``bytes`` slices of it.
    """

    __slots__ = (
        "_account_keys_at",
        "_blockhash_at",
        "_instruction_bytes_at",
        "_instruction_table_at",
        "_lookup_bytes_at",
        "_lookup_table_at",
        "_raw_tx_at",
        "_signatures_at",
        "bytes",
    )

    def __init__(self, data: bytes) -> None:
        self.bytes = data
        at = TX_HEADER_LEN

        def take(length: int) -> int:
            nonlocal at
            start = at
            at += length
            if at > len(data):
                raise ProtocolError(f"transaction needs {at} bytes, have {len(data)}")
            return start

        self._signatures_at = take(self.signature_count * 64)
        self._account_keys_at = take(self.account_count * 32)
        self._blockhash_at = take(32)
        self._instruction_table_at = take(self.instruction_count * INSTRUCTION_ENTRY_LEN)
        (instruction_bytes_len,) = struct.unpack_from("<I", data, 76)
        self._instruction_bytes_at = take(_align8(instruction_bytes_len))
        self._lookup_table_at = take(self.lookup_count * LOOKUP_ENTRY_LEN)
        (lookup_bytes_len,) = struct.unpack_from("<I", data, 80)
        self._lookup_bytes_at = take(_align8(lookup_bytes_len))
        (raw_tx_len,) = struct.unpack_from("<I", data, 84)
        self._raw_tx_at = take(raw_tx_len)

        # Table entries are offsets into their own byte region. Checking them once here is what
        # lets every accessor below slice without a bounds test.
        for i in range(self.instruction_count):
            entry = self._instruction_table_at + i * INSTRUCTION_ENTRY_LEN
            accounts_off, accounts_len = struct.unpack_from("<HH", data, entry + 2)
            data_off, data_len = struct.unpack_from("<II", data, entry + 8)
            if accounts_off + accounts_len > instruction_bytes_len or (
                data_off + data_len > instruction_bytes_len
            ):
                raise ProtocolError(f"instruction {i} points outside its byte region")
        for i in range(self.lookup_count):
            entry = self._lookup_table_at + i * LOOKUP_ENTRY_LEN
            w_off, w_len, r_off, r_len = struct.unpack_from("<HHHH", data, entry + 32)
            if w_off + w_len > lookup_bytes_len or r_off + r_len > lookup_bytes_len:
                raise ProtocolError(f"lookup {i} points outside its byte region")

    @staticmethod
    def read(data: bytes) -> Transaction:
        """Read a transaction, validating that every section is present."""
        if len(data) < TX_HEADER_LEN:
            raise ProtocolError(
                f"transaction header needs {TX_HEADER_LEN} bytes, have {len(data)}"
            )
        return Transaction(data)

    def _u64(self, at: int) -> int:
        return struct.unpack_from("<Q", self.bytes, at)[0]

    def _u32(self, at: int) -> int:
        return struct.unpack_from("<I", self.bytes, at)[0]

    def _u16(self, at: int) -> int:
        return struct.unpack_from("<H", self.bytes, at)[0]

    # -- header ------------------------------------------------------------------------------

    @property
    def slot(self) -> int:
        """Slot the transaction landed in."""
        return self._u64(0)

    @property
    def parent_slot(self) -> int:
        """The slot this one builds on."""
        return self._u64(8)

    @property
    def rx_ts_ns(self) -> int:
        """When the first shred of the FEC set arrived, on the server's monotonic clock."""
        return self._u64(16)

    @property
    def emit_ts_ns(self) -> int:
        """When the server finished encoding this message, on the same clock as ``rx_ts_ns``."""
        return self._u64(24)

    @property
    def pipeline_ns(self) -> int:
        """How long the server took from first shred to encoded message.

        Both stamps come from one monotonic clock, so this is meaningful; neither can be compared
        against a local wall clock.
        """
        return self.emit_ts_ns - self.rx_ts_ns

    @property
    def leader(self) -> bytes | None:
        """Leader assigned to the slot, when the schedule knew one."""
        return bytes(self.bytes[32:64]) if self._has(TxFlag.HAS_LEADER) else None

    @property
    def fec_set_index(self) -> int:
        """Erasure set this transaction was carried in."""
        return self._u32(64)

    @property
    def entry_index(self) -> int:
        """Index of the entry within the slot."""
        return self._u32(68)

    @property
    def tx_index(self) -> int:
        """Index of the transaction within its entry."""
        return self._u32(72)

    @property
    def source_id(self) -> int:
        """Which ingress source delivered the shreds."""
        return self._u16(88)

    @property
    def flags(self) -> int:
        """Raw header flags. Prefer the named accessors."""
        return self._u16(90)

    def _has(self, bits: int) -> bool:
        return (self.flags & bits) == bits

    @property
    def is_vote(self) -> bool:
        """Whether this is a simple vote transaction."""
        return self._has(TxFlag.IS_VOTE)

    @property
    def recovered(self) -> bool:
        """Whether the FEC set had to be reconstructed from parity shreds."""
        return self._has(TxFlag.RECOVERED)

    @property
    def verification(self) -> Verification:
        """How much the server could vouch for this transaction."""
        if self._has(TxFlag.VERIFIED):
            return Verification.VERIFIED
        match (self.flags >> _REASON_SHIFT) & _REASON_MASK:
            case 1:
                return Verification.UNKNOWN_LEADER
            case 2:
                return Verification.STALE_SCHEDULE
            case _:
                return Verification.DISABLED

    @property
    def account_count(self) -> int:
        """Number of account keys carried in the message."""
        return self._u16(92)

    @property
    def instruction_count(self) -> int:
        """Number of instructions."""
        return self._u16(94)

    @property
    def signature_count(self) -> int:
        """Number of signatures."""
        return self.bytes[96]

    @property
    def message_version(self) -> int:
        """Message version, or :data:`MESSAGE_VERSION_LEGACY` for a legacy message."""
        return self.bytes[97]

    @property
    def lookup_count(self) -> int:
        """Number of address lookup table references."""
        return self.bytes[98]

    @property
    def required_signatures(self) -> int:
        """Signatures the message requires."""
        return self.bytes[99]

    @property
    def readonly_signed(self) -> int:
        """Signed accounts that are readonly."""
        return self.bytes[100]

    @property
    def readonly_unsigned(self) -> int:
        """Unsigned accounts that are readonly."""
        return self.bytes[101]

    # -- sections ----------------------------------------------------------------------------

    @property
    def signature(self) -> bytes | None:
        """The transaction's first signature — its id. ``None`` if it carries none.

        Every real transaction is signed, so this is ``None`` only for something a leader should
        never have put in a block. It is nullable rather than raising because the node is a relay,
        not a validator: it forwards what the leader signed into the shred, and refusing the frame
        or raising from an accessor would let a leader knock subscribers off the stream.
        """
        if self.signature_count == 0:
            return None
        return bytes(self.bytes[self._signatures_at : self._signatures_at + 64])

    def signatures(self) -> list[bytes]:
        """Every signature, in order."""
        return [
            bytes(self.bytes[self._signatures_at + i * 64 : self._signatures_at + i * 64 + 64])
            for i in range(self.signature_count)
        ]

    def account_key(self, index: int) -> bytes | None:
        """One account key, by index. ``None`` if the index is past the end.

        Nullable because the index usually is not the caller's: ``instruction.program_id_index``
        comes off the wire, and a transaction naming an index past its own account list is
        something a leader can produce.
        """
        if index < 0 or index >= self.account_count:
            return None
        at = self._account_keys_at + index * 32
        return bytes(self.bytes[at : at + 32])

    def account_keys(self) -> list[bytes]:
        """Every account key, in the order the message declared them."""
        return [
            bytes(self.bytes[self._account_keys_at + i * 32 : self._account_keys_at + i * 32 + 32])
            for i in range(self.account_count)
        ]

    @property
    def recent_blockhash(self) -> bytes:
        """The blockhash the transaction was signed against."""
        return bytes(self.bytes[self._blockhash_at : self._blockhash_at + 32])

    def instruction(self, index: int) -> Instruction | None:
        """One instruction, by index. ``None`` if the index is past the end."""
        if index < 0 or index >= self.instruction_count:
            return None
        entry = self._instruction_table_at + index * INSTRUCTION_ENTRY_LEN
        base = self._instruction_bytes_at
        accounts_off, accounts_len = struct.unpack_from("<HH", self.bytes, entry + 2)
        data_off, data_len = struct.unpack_from("<II", self.bytes, entry + 8)
        return Instruction(
            program_id_index=self.bytes[entry],
            accounts=bytes(self.bytes[base + accounts_off : base + accounts_off + accounts_len]),
            data=bytes(self.bytes[base + data_off : base + data_off + data_len]),
        )

    def instructions(self) -> list[Instruction]:
        """Every instruction, in execution order."""
        out: list[Instruction] = []
        for i in range(self.instruction_count):
            # In range by construction, so the ``None`` case cannot arise here.
            found = self.instruction(i)
            if found is not None:
                out.append(found)
        return out

    def lookups(self) -> list[AddressLookup]:
        """Every address lookup table reference, unresolved.

        Resolving these needs the lookup tables' account state, which a shred pipeline does not
        have. A consumer that needs the resolved keys must fetch the tables itself.
        """
        out: list[AddressLookup] = []
        for i in range(self.lookup_count):
            entry = self._lookup_table_at + i * LOOKUP_ENTRY_LEN
            base = self._lookup_bytes_at
            w_off, w_len, r_off, r_len = struct.unpack_from("<HHHH", self.bytes, entry + 32)
            out.append(
                AddressLookup(
                    account_key=bytes(self.bytes[entry : entry + 32]),
                    writable_indexes=bytes(self.bytes[base + w_off : base + w_off + w_len]),
                    readonly_indexes=bytes(self.bytes[base + r_off : base + r_off + r_len]),
                )
            )
        return out

    @property
    def raw_tx(self) -> bytes | None:
        """The original transaction bytes, when the server was asked to include them.

        Off by default: the decoded form above carries the same information, and repeating the
        bytes roughly doubles the stream's bandwidth.
        """
        if not self._has(TxFlag.HAS_RAW_TX):
            return None
        length = self._u32(84)
        return bytes(self.bytes[self._raw_tx_at : self._raw_tx_at + length])

    def __repr__(self) -> str:
        sig = self.signature
        return (
            f"Transaction(slot={self.slot}, "
            f"signature={sig.hex()[:16] + '...' if sig else None}, "
            f"instructions={self.instruction_count}, vote={self.is_vote})"
        )
