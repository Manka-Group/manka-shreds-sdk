"""The subscriber client: connect, prove possession of your key, then read events.

The whole exchange is::

    you  -> node   greeting: streams, codecs, a one-way reference to your key, your nonce
    node -> you    its nonce and HMAC(key, "server" | transcript)
    you            check it — a peer that cannot produce this does not hold your key
    you  -> node   HMAC(key, "client" | transcript)
    node -> you    what it granted, and the dictionary if you do not hold it
    node -> you    frames, until one side stops

Your key never crosses the wire. See :mod:`manka_shreds_sdk.handshake`.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from compression import zstd
from dataclasses import dataclass
from typing import Union

from .dictcache import DictionaryCache
from .events import (
    Duplicate,
    Entry,
    RawShred,
    SlotEnd,
    SlotStart,
    read_duplicate,
    read_entry,
    read_raw_shred,
    read_slot_end,
    read_slot_start,
)
from .handshake import Transcript, client_proof, fresh_nonce, key_ref, verify_server
from .protocol import (
    ALL_STREAMS,
    FRAME_HEADER_LEN,
    MAX_FRAME_PAYLOAD,
    MAX_HANDSHAKE_BYTES,
    Capability,
    Codec,
    CodecBit,
    FilterAck,
    FrameKind,
    Hello,
    Lag,
    NamedFilter,
    ProtocolError,
    ServerError,
    dictionary_id,
    read_challenge,
    read_dictionary,
    read_error,
    read_filter_ack,
    read_frame_header,
    read_hello_ack,
    read_lag,
    write_frame,
    write_hello,
    write_prove,
    write_set_filter,
)
from .transport import ServerVerification, Transport, TransportError, Wire, connect_quic, connect_tcp

__all__ = [
    "Client",
    "DuplicateEvent",
    "EntryEvent",
    "Event",
    "FilterAckEvent",
    "LagEvent",
    "PingEvent",
    "PongEvent",
    "RawShredEvent",
    "SlotEndEvent",
    "SlotStartEvent",
    "TransactionEvent",
    "UnknownEvent",
]

from .transaction import Transaction

DEFAULT_CONNECT_TIMEOUT = 10.0


# -------------------------------------------------------------------------------------------------
# Events
# -------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TransactionEvent:
    """A decoded transaction."""

    seq: int
    transaction: Transaction
    #: Which of this connection's named filters this transaction matched, as a bitmask.
    #:
    #: Zero when the connection named none. One transaction matching several filters arrives once,
    #: with every match recorded.
    matched: int
    type: str = "transaction"


@dataclass(frozen=True, slots=True)
class EntryEvent:
    seq: int
    entry: Entry
    type: str = "entry"


@dataclass(frozen=True, slots=True)
class SlotStartEvent:
    seq: int
    slot: SlotStart
    type: str = "slot-start"


@dataclass(frozen=True, slots=True)
class SlotEndEvent:
    seq: int
    slot: SlotEnd
    type: str = "slot-end"


@dataclass(frozen=True, slots=True)
class DuplicateEvent:
    seq: int
    duplicate: Duplicate
    type: str = "duplicate"


@dataclass(frozen=True, slots=True)
class RawShredEvent:
    """A shred republished exactly as it arrived. Needs the ``RAW_SHREDS`` stream.

    Delivered before the node verified or decoded anything, so nothing on it is claimed to be
    leader-signed — see :class:`~manka_shreds_sdk.events.RawShred`.
    """

    seq: int
    shred: RawShred
    type: str = "raw-shred"


@dataclass(frozen=True, slots=True)
class LagEvent:
    seq: int
    lag: Lag
    type: str = "lag"


@dataclass(frozen=True, slots=True)
class FilterAckEvent:
    seq: int
    ack: FilterAck
    type: str = "filter-ack"


@dataclass(frozen=True, slots=True)
class PingEvent:
    seq: int
    type: str = "ping"


@dataclass(frozen=True, slots=True)
class PongEvent:
    seq: int
    type: str = "pong"


@dataclass(frozen=True, slots=True)
class UnknownEvent:
    """A frame kind this build does not know.

    Carried rather than dropped so a newer server does not break an older subscriber.
    """

    seq: int
    kind: int
    payload: bytes
    type: str = "unknown"


Event = Union[
    TransactionEvent,
    EntryEvent,
    SlotStartEvent,
    SlotEndEvent,
    DuplicateEvent,
    RawShredEvent,
    LagEvent,
    FilterAckEvent,
    PingEvent,
    PongEvent,
    UnknownEvent,
]


# -------------------------------------------------------------------------------------------------
# Client
# -------------------------------------------------------------------------------------------------


class Client:
    """A live subscription to a node.

    Construct with :meth:`connect`, then iterate::

        client = await Client.connect(host="node.example.com", port=9000, secret=secret)
        async for event in client:
            if event.type == "transaction":
                print(event.transaction.slot, event.transaction.signature.hex())
    """

    __slots__ = (
        "_buffer",
        "_closed",
        "_closer",
        "_decompressor",
        "_dictionary",
        "_max_message_bytes",
        "_wire",
        "dictionary_was_sent",
        "granted",
        "keepalive_ms",
        "message_bytes",
        "session_id",
        "wire_bytes",
    )

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._closed = False
        self._closer = None
        self._dictionary: bytes | None = None
        self._decompressor = None
        self._max_message_bytes = MAX_FRAME_PAYLOAD
        self._wire: Wire | None = None
        #: Whether the dictionary came over the wire rather than out of the cache.
        self.dictionary_was_sent = False
        #: Streams actually granted — the intersection of what was asked and what the key permits.
        self.granted = 0
        self.keepalive_ms = 0
        self.session_id = 0
        #: Bytes read from the transport, before decompression.
        self.wire_bytes = 0
        #: Bytes after decompression. Against :attr:`wire_bytes`, this is the achieved ratio.
        self.message_bytes = 0

    # -- connecting --------------------------------------------------------------------------

    @staticmethod
    async def connect(
        *,
        host: str,
        port: int,
        secret: str | bytes,
        streams: int = ALL_STREAMS,
        transport: Transport = "quic",
        verification: ServerVerification | None = None,
        dictionary: bytes | None = None,
        dictionary_cache: str | None | object = ...,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        max_message_bytes: int = MAX_FRAME_PAYLOAD,
        filters: list[NamedFilter] | None = None,
    ) -> Client:
        """Open a subscription.

        ``host`` and ``port`` are the node's address — public, and the only thing besides your
        secret that you need. There is no certificate to pin and no dictionary to install.
        """
        if not host or port == 0:
            raise ProtocolError(
                "no node endpoint was given. Pass host and port; this SDK compiles none in, so "
                "one build serves every node"
            )

        key = secret.encode() if isinstance(secret, str) else bytes(secret)

        # Where received dictionaries live. ``None`` means keep none, which is correct for a
        # read-only deployment and no worse than plain zstd — the node simply sends it again.
        if dictionary_cache is ...:
            cache = DictionaryCache.default_location()
        elif dictionary_cache is None:
            cache = None
        else:
            cache = DictionaryCache(dictionary_cache)  # type: ignore[arg-type]

        held = dictionary
        if held is None and cache is not None:
            newest = cache.newest()
            held = newest[1] if newest else None

        self = Client()
        self._max_message_bytes = max_message_bytes

        if transport == "tcp":
            wire = await connect_tcp(host, port, connect_timeout)
            closer = None
        else:
            wire, closer = await connect_quic(host, port, verification, connect_timeout)
        self._wire = wire
        self._closer = closer

        try:
            await self._handshake(key, streams, held, cache, filters, connect_timeout)
        except BaseException:
            await self.close()
            raise
        return self

    async def _handshake(
        self,
        key: bytes,
        streams: int,
        held: bytes | None,
        cache: DictionaryCache | None,
        filters: list[NamedFilter] | None,
        timeout: float,
    ) -> None:
        assert self._wire is not None
        wire = self._wire
        reference = key_ref(key)
        client_nonce = fresh_nonce()

        greeting = Hello(
            streams=streams,
            codecs=CodecBit.ZSTD,
            key_ref=reference,
            client_nonce=client_nonce,
            capabilities=Capability.ACCEPTS_DICTIONARY,
            dictionary_id=dictionary_id(held) if held else 0,
            filter=(
                write_set_filter(filters).decode() if filters else None
            ),
        )
        await wire.write(write_frame(FrameKind.HELLO, 0, write_hello(greeting)))

        proved = False
        ack = None
        pushed: bytes | None = None

        async def next_frame() -> tuple[int, int, bytes]:
            header = await self._read_frame_header(handshake=True)
            payload = await self._read_exactly(header.len)
            return header.kind, header.raw_kind, payload

        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TransportError("the handshake did not complete in time")
            kind, raw_kind, payload = await asyncio.wait_for(next_frame(), remaining)

            if kind == FrameKind.ERROR:
                raise read_error(payload)

            if ack is not None:
                # The node named a dictionary this side does not hold, so it is sending it — once,
                # before the first data frame. Reading it here rather than in the event loop is
                # what makes "the dictionary does not change during a run" true by construction.
                if kind != FrameKind.DICTIONARY:
                    raise ProtocolError(
                        f"the server announced dictionary {ack.dictionary_id} and then sent frame "
                        f"kind {raw_kind}"
                    )
                offered = read_dictionary(payload)
                # Checked against what the acknowledgement named. Accepting bytes that do not match
                # would leave this side decompressing against something other than what the node
                # compresses with, and every frame after it unreadable for a reason nothing on the
                # wire would explain.
                actual = dictionary_id(offered.bytes)
                if offered.id != ack.dictionary_id or actual != ack.dictionary_id:
                    raise ProtocolError(
                        "the server sent a dictionary that is not the one it announced: "
                        f"acknowledged {ack.dictionary_id}, frame said {offered.id}, bytes hash "
                        f"to {actual}"
                    )
                pushed = offered.bytes
                break

            if kind != FrameKind.CHALLENGE:
                # Anything other than a challenge here means the peer skipped proving it holds the
                # key. Accepting it would make the whole exchange optional — a server that simply
                # never challenged would be trusted, which is precisely what this replaces.
                if not proved:
                    raise ProtocolError(
                        "the server answered without proving it holds this key; a peer that skips "
                        "the proof is not one this client will talk to"
                    )
                if kind == FrameKind.HELLO_ACK:
                    parsed = read_hello_ack(payload)
                    holds_it = (
                        held is not None
                        and parsed.dictionary_id != 0
                        and dictionary_id(held) == parsed.dictionary_id
                    )
                    ack = parsed
                    if not holds_it and parsed.dictionary_id != 0:
                        continue  # one more frame is on its way
                    break
                raise ProtocolError(f"expected HelloAck, got frame kind {raw_kind}")

            challenge = read_challenge(payload)
            transcript = Transcript(
                key_ref=reference,
                client_nonce=client_nonce,
                server_nonce=challenge.server_nonce,
                binding=wire.channel_binding(),
            )
            if not verify_server(transcript, key, challenge.proof):
                # Either the peer does not hold this key, or something is sitting between the two
                # ends presenting a certificate of its own. Both mean the connection must not
                # continue, and nothing has been revealed: no proof of ours has been sent yet.
                raise ProtocolError(
                    "the server did not prove it holds this key; the connection is not to the "
                    "node it claims to be, or is being relayed"
                )
            proved = True
            await wire.write(
                write_frame(FrameKind.PROVE, 0, write_prove(client_proof(transcript, key)))
            )

        if ack is None:
            raise ProtocolError("the handshake ended without an acknowledgement")
        if ack.codec != Codec.ZSTD:
            raise ProtocolError(
                f"server negotiated {Codec(ack.codec).name} but this client requires zstd; the "
                "server has zstd disabled"
            )

        self.session_id = ack.session_id
        self.granted = ack.granted
        self.keepalive_ms = ack.keepalive_ms

        if pushed is not None:
            self._dictionary = pushed
            self.dictionary_was_sent = True
            if cache is not None:
                cache.store(ack.dictionary_id, pushed)
        elif held is not None and ack.dictionary_id != 0:
            self._dictionary = held
        if self._dictionary is not None:
            self._decompressor = zstd.ZstdDict(self._dictionary)

    # -- reading -----------------------------------------------------------------------------

    async def _fill(self, need: int) -> None:
        assert self._wire is not None
        while len(self._buffer) < need:
            chunk = await self._wire.read(65536)
            if not chunk:
                raise TransportError("the node closed the connection")
            self.wire_bytes += len(chunk)
            self._buffer.extend(chunk)

    async def _read_exactly(self, count: int) -> bytes:
        if count == 0:
            return b""
        await self._fill(count)
        out = bytes(self._buffer[:count])
        del self._buffer[:count]
        return out

    async def _read_frame_header(self, *, handshake: bool = False):
        await self._fill(FRAME_HEADER_LEN)
        header = read_frame_header(bytes(self._buffer[:FRAME_HEADER_LEN]))
        limit = MAX_HANDSHAKE_BYTES if handshake and header.kind != FrameKind.DICTIONARY else (
            self._max_message_bytes
        )
        if header.len > limit:
            raise ProtocolError(
                f"the server declared a {header.len}-byte frame; this connection's limit is {limit}"
            )
        del self._buffer[:FRAME_HEADER_LEN]
        return header

    def _decompress(self, payload: bytes, codec: Codec) -> bytes:
        if codec != Codec.ZSTD:
            raise ProtocolError(f"the server compressed with {Codec(codec).name}, which this client cannot decode")
        try:
            if self._decompressor is not None:
                return zstd.decompress(payload, zstd_dict=self._decompressor)
            return zstd.decompress(payload)
        except zstd.ZstdError as exc:
            raise ProtocolError(f"the frame did not decompress: {exc}") from exc

    async def next_event(self) -> Event:
        """Read one event, waiting for it if necessary."""
        assert self._wire is not None
        while True:
            header = await self._read_frame_header()
            payload = await self._read_exactly(header.len)
            body = self._decompress(payload, header.codec) if header.compressed else payload
            self.message_bytes += len(body)
            seq = header.seq

            match header.kind:
                case FrameKind.TRANSACTION:
                    return TransactionEvent(
                        seq=seq, transaction=Transaction.read(body), matched=header.matched
                    )
                case FrameKind.ENTRY:
                    return EntryEvent(seq=seq, entry=read_entry(body))
                case FrameKind.SLOT_START:
                    return SlotStartEvent(seq=seq, slot=read_slot_start(body))
                case FrameKind.SLOT_END:
                    return SlotEndEvent(seq=seq, slot=read_slot_end(body))
                case FrameKind.DUPLICATE:
                    return DuplicateEvent(seq=seq, duplicate=read_duplicate(body))
                case FrameKind.RAW_SHRED:
                    return RawShredEvent(seq=seq, shred=read_raw_shred(body))
                case FrameKind.LAG:
                    return LagEvent(seq=seq, lag=read_lag(body))
                case FrameKind.FILTER_ACK:
                    return FilterAckEvent(seq=seq, ack=read_filter_ack(body))
                case FrameKind.PING:
                    await self._wire.write(write_frame(FrameKind.PONG, 0, b""))
                    return PingEvent(seq=seq)
                case FrameKind.PONG:
                    return PongEvent(seq=seq)
                case FrameKind.ERROR:
                    raise read_error(body)
                case FrameKind.DICTIONARY:
                    # Settled during the handshake; a second one mid-stream would mean frames
                    # before and after it decode against different dictionaries.
                    raise ProtocolError(
                        "the server sent a dictionary mid-stream; it is settled at connect time"
                    )
                case _:
                    return UnknownEvent(seq=seq, kind=header.raw_kind, payload=body)

    def __aiter__(self) -> AsyncIterator[Event]:
        return self._iterate()

    async def _iterate(self) -> AsyncIterator[Event]:
        try:
            while not self._closed:
                yield await self.next_event()
        except (TransportError, ServerError):
            if not self._closed:
                raise

    # -- control -----------------------------------------------------------------------------

    async def set_filters(self, filters: list[NamedFilter]) -> None:
        """Replace this connection's filter set.

        The whole set replaces whatever the connection carried, and is accepted or refused
        together — a connection is never left holding part of what was asked for. The verdict
        arrives as a :class:`FilterAckEvent`.
        """
        assert self._wire is not None
        await self._wire.write(write_frame(FrameKind.SET_FILTER, 0, write_set_filter(filters)))

    async def ping(self) -> None:
        """Ask the node to answer, so a silent connection can be told from a dead one."""
        assert self._wire is not None
        await self._wire.write(write_frame(FrameKind.PING, 0, b""))

    async def close(self) -> None:
        """Close the connection. Idempotent."""
        if self._closed:
            return
        self._closed = True
        if self._wire is not None:
            await self._wire.close()
        if self._closer is not None:
            try:
                await self._closer()
            except Exception:
                pass

    async def __aenter__(self) -> Client:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    @property
    def server_fingerprint(self) -> str | None:
        """SHA-256 of the certificate the session completed against, or ``None`` over TCP.

        Nothing verified it; the node proved itself with your key. Read it if you want to pin
        it on a later connection with :class:`~manka_shreds_sdk.Fingerprint`.
        """
        getter = getattr(self._wire, "server_fingerprint", None)
        return getter() if getter is not None else None

    @property
    def dictionary(self) -> bytes | None:
        """The compression dictionary this connection settled on, if any."""
        return self._dictionary
