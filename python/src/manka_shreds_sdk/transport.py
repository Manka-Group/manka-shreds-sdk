"""Getting bytes to and from a node, over QUIC or TCP.

A node serves both on the same address — QUIC is UDP, so the port number is shared and you need one
address either way.

# Why QUIC by default

Over a WAN one lost packet stalls a TCP stream until it is retransmitted, holding back every message
behind it, *including messages that already arrived intact*. For a stream whose whole value is
arriving early, that is the wrong failure mode: the data you are paying for is held hostage by a
packet you already have the successor to. QUIC does not head-of-line block the same way, establishes
in one round trip, and survives your address changing.

TCP is still here and is a reasonable choice for a colocated subscriber, or one behind a network
that blocks UDP.

# Why nothing verifies the certificate

QUIC is always TLS, so the node presents one. Nothing here checks it against a trust store, because
it is not what authenticates the node — your key is, during the handshake. The certificate's hash
goes into that transcript and that is its only job. See :mod:`manka_shreds_sdk.handshake`.
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from dataclasses import dataclass
from typing import Literal, Protocol

from .handshake import NO_BINDING

__all__ = [
    "ALPN",
    "ServerVerification",
    "Transport",
    "TransportError",
    "Unchecked",
    "Wire",
    "connect_tcp",
    "connect_quic",
    "fingerprint_of",
]

#: Which transport to use.
Transport = Literal["quic", "tcp"]

#: Application-layer protocol negotiation identifier.
#:
#: Pins the QUIC connection to this protocol, so a server speaking something else is refused at the
#: TLS handshake rather than after it has been given a session.
ALPN = "manka-shreds/1"


class TransportError(Exception):
    """The connection could not be established, or failed while open."""


@dataclass(frozen=True, slots=True)
class Unchecked:
    """Accept whatever certificate the node presents.

    The default, and correct against a manka-shreds node: the node proves it holds your key before
    you send any proof of your own, and that proof is bound to the TLS session it arrived on — so a
    substituted certificate is caught by the exchange rather than by a fingerprint you had to be
    given.
    """


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """Require the node's certificate to have this SHA-256 fingerprint.

    For a deployment that pins one. Hex, with or without colons.
    """

    value: str


#: How the server's certificate should be treated.
ServerVerification = Unchecked | Fingerprint


def fingerprint_of(der: bytes) -> str:
    """The SHA-256 fingerprint of a DER certificate, lowercase hex."""
    return hashlib.sha256(der).hexdigest()


def _normalise_fingerprint(value: str) -> str:
    return value.replace(":", "").replace(" ", "").lower()


class Wire(Protocol):
    """A byte pipe to a node.

    Deliberately small: the client does all framing, so a consumer wanting a transport this package
    does not ship — a proxy, a replay file, a test double — implements these four methods.
    """

    async def read(self, limit: int = 65536) -> bytes:
        """Return up to ``limit`` bytes, or ``b""`` once the peer is done."""
        ...

    async def write(self, data: bytes) -> None:
        """Write bytes."""
        ...

    async def close(self) -> None:
        """Close the connection."""
        ...

    def channel_binding(self) -> bytes:
        """What a proof of key possession is bound to on this connection.

        The hash of whatever certificate the TLS session completed against — nothing verified it,
        and nothing needed to. Its only job is to differ between two TLS sessions, so that anything
        terminating yours and reconnecting onwards produces a transcript neither end agrees with.

        All zeroes over TCP, which presents no certificate: the key still never crosses the wire,
        but an interposed relay stops being detectable.
        """
        ...


class _TcpWire:
    """A plain TCP connection. No certificate, and therefore no channel binding."""

    __slots__ = ("_reader", "_writer")

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    async def read(self, limit: int = 65536) -> bytes:
        return await self._reader.read(limit)

    async def write(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def close(self) -> None:
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except (OSError, asyncio.CancelledError):
            pass

    def channel_binding(self) -> bytes:
        return NO_BINDING


async def connect_tcp(host: str, port: int, timeout: float = 10.0) -> Wire:
    """Open a TCP connection to a node."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except TimeoutError as exc:
        raise TransportError(f"connecting to {host}:{port} over TCP timed out") from exc
    except OSError as exc:
        raise TransportError(f"connecting to {host}:{port} over TCP failed: {exc}") from exc
    return _TcpWire(reader, writer)


class _QuicWire:
    """One bidirectional QUIC stream, carrying exactly the framing TCP does."""

    __slots__ = ("_binding", "_client", "_reader", "_stream_id", "_writer")

    def __init__(self, client, reader, writer, stream_id: int, binding: bytes) -> None:
        self._client = client
        self._reader = reader
        self._writer = writer
        self._stream_id = stream_id
        self._binding = binding

    async def read(self, limit: int = 65536) -> bytes:
        return await self._reader.read(limit)

    async def write(self, data: bytes) -> None:
        self._writer.write(data)
        # aioquic's stream writer has no drain of its own; the connection flushes on write.

    async def close(self) -> None:
        try:
            self._writer.close()
        except Exception:
            pass

    def channel_binding(self) -> bytes:
        return self._binding


async def connect_quic(
    host: str,
    port: int,
    verification: ServerVerification | None = None,
    timeout: float = 10.0,
):
    """Open a QUIC connection to a node, returning ``(wire, closer)``.

    QUIC needs a native implementation, which is the one thing this package does not carry itself.
    Install it with ``pip install 'manka-shreds-sdk[quic]'``.
    """
    try:
        from aioquic.asyncio.client import connect as _aioquic_connect
        from aioquic.quic.configuration import QuicConfiguration
    except ImportError as exc:  # pragma: no cover - exercised by deployment, not by tests
        raise TransportError(
            "QUIC needs the optional aioquic dependency: pip install 'manka-shreds-sdk[quic]'. "
            "Pass transport='tcp' to use the built-in TCP transport instead."
        ) from exc

    verification = verification or Unchecked()
    config = QuicConfiguration(is_client=True, alpn_protocols=[ALPN])
    # Nothing verifies the certificate; the node authenticates itself with your key. See the module
    # docstring, and handshake.py for why this is not the weakening it looks like.
    config.verify_mode = ssl.CERT_NONE

    context = _aioquic_connect(host, port, configuration=config)
    client = await asyncio.wait_for(context.__aenter__(), timeout)

    der = b""
    tls = getattr(client._quic, "tls", None)
    certificate = getattr(tls, "_peer_certificate", None) if tls is not None else None
    if certificate is not None:
        try:
            from cryptography.hazmat.primitives.serialization import Encoding

            der = certificate.public_bytes(Encoding.DER)
        except Exception:
            der = b""

    if isinstance(verification, Fingerprint):
        want = _normalise_fingerprint(verification.value)
        got = fingerprint_of(der)
        if not der or got != want:
            await context.__aexit__(None, None, None)
            raise TransportError(
                f"the node's certificate fingerprint is {got or 'unavailable'}, expected {want}"
            )

    reader, writer = await client.create_stream()
    binding = hashlib.sha256(der).digest() if der else NO_BINDING
    wire = _QuicWire(client, reader, writer, writer.get_extra_info("stream_id", 0), binding)

    async def closer() -> None:
        await context.__aexit__(None, None, None)

    return wire, closer
