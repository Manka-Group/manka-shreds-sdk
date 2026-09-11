"""Proving possession of your key without ever sending it.

# What this replaces

A password-style handshake sends the credential to authenticate. Your key is a single value that is
both name and secret, so sending it puts a fully usable credential on the wire on every connect —
recoverable by anyone who can capture the traffic or terminate the TLS in front of it.

Nothing here sends it. Both ends prove they hold it instead::

    you  -> node   key reference, your nonce
    node -> you    its nonce, HMAC(key, "server" | transcript)
    you            check it — a peer that cannot produce this does not hold your key
    you  -> node   HMAC(key, "client" | transcript)

# Why there is no fingerprint to configure

QUIC is always TLS, so the node presents a certificate. **Nothing verifies it**, nobody distributes
it, and the node may mint a fresh one on every restart. It is not what authenticates the node — your
key is.

Its hash goes into the transcript, and that is all it is for. Anything that terminates your TLS and
reconnects onwards must present a certificate of its own, so the transcript it shares with you
differs from the one it shares with the node. It cannot compute either proof without your key, and
it cannot pass a proof between the two sessions, because each is bound to a different certificate.

That is why this SDK needs no fingerprint, no certificate authority, and no domain name — and why a
node rotating its certificate does not break you.

Over plain TCP there is no certificate and therefore no binding. Your key still never crosses the
wire, but an interposed relay is no longer detectable, which is why TCP is for a subscriber that is
not crossing a network it does not control.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

__all__ = [
    "DIGEST_LEN",
    "NO_BINDING",
    "Transcript",
    "binding_of",
    "client_proof",
    "fresh_nonce",
    "key_ref",
    "server_proof",
    "short_ref",
    "verify_server",
]

_REF_DOMAIN = b"manka-shreds/key-ref/v1"
_SERVER_DOMAIN = b"manka-shreds/server-proof/v1"
_CLIENT_DOMAIN = b"manka-shreds/client-proof/v1"

#: Bytes in a key reference, a nonce, a binding and a proof — all SHA-256 sized.
DIGEST_LEN = 32

#: What ties a proof to one TLS session when there is none: all zeroes, for plain TCP.
NO_BINDING = bytes(DIGEST_LEN)


def key_ref(key: bytes) -> bytes:
    """A public, stable reference to an API key.

    SHA-256 of the key under a domain separator. This is what travels in the greeting, and what
    belongs in a log or a support ticket: it identifies your key without being it.
    """
    return hashlib.sha256(_REF_DOMAIN + key).digest()


def short_ref(reference: bytes) -> str:
    """A key reference rendered for a log — the first sixteen hex characters."""
    return reference.hex()[:16]


def binding_of(certificate_der: bytes) -> bytes:
    """The binding for a server presenting ``certificate_der``."""
    return hashlib.sha256(certificate_der).digest()


@dataclass(frozen=True, slots=True)
class Transcript:
    """Everything both ends must agree on for a proof to mean anything."""

    #: Which key is claimed.
    key_ref: bytes
    #: Chosen by the client.
    client_nonce: bytes
    #: Chosen by the server.
    server_nonce: bytes
    #: The TLS session this belongs to.
    binding: bytes


def _proof(transcript: Transcript, key: bytes, domain: bytes) -> bytes:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(domain)
    mac.update(transcript.key_ref)
    mac.update(transcript.client_nonce)
    mac.update(transcript.server_nonce)
    mac.update(transcript.binding)
    return mac.digest()


def server_proof(transcript: Transcript, key: bytes) -> bytes:
    """The proof the server sends, which authenticates the node to you."""
    return _proof(transcript, key, _SERVER_DOMAIN)


def client_proof(transcript: Transcript, key: bytes) -> bytes:
    """The proof you send, which authenticates you to the node."""
    return _proof(transcript, key, _CLIENT_DOMAIN)


def verify_server(transcript: Transcript, key: bytes, presented: bytes) -> bool:
    """Whether ``presented`` is the proof the server should have sent.

    Compared in constant time: returning early on the first differing byte would tell a forger how
    much of a guess was right, which is the one piece of feedback it needs.
    """
    expected = server_proof(transcript, key)
    # compare_digest is constant time and tolerates a length mismatch, which a peer can cause.
    return hmac.compare_digest(expected, presented)


def fresh_nonce() -> bytes:
    """A nonce for one handshake.

    From the operating system's generator: it must be unpredictable, not merely unique. A nonce an
    attacker can anticipate lets it collect a proof over a transcript you are about to produce.
    """
    return os.urandom(DIGEST_LEN)
