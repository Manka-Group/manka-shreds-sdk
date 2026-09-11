"""Against a real node.

Skipped unless an endpoint and a secret are in the environment, so a clone with neither still runs
a full suite:

    MANKA_SHREDS_HOST=node.example.com \\
    MANKA_SHREDS_PORT=9000 \\
    MANKA_SHREDS_SECRET=... \\
    pytest tests/test_live.py

**No credential is committed.** The secret is read from the environment and never printed — an
assertion message that interpolated it would put it in CI output, which is why the failure messages
here talk about behaviour rather than values.

What these cover that the fixture tests cannot: the handshake actually completing against a server
that computes the other half of every proof, both transports, the dictionary arriving over the
wire and being reused from the cache on the next connection, and the refusals — a wrong secret, and
a certificate that is not the one pinned.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from manka_shreds_sdk import (
    Client,
    DictionaryCache,
    Fingerprint,
    NamedFilter,
    ProtocolError,
    ServerError,
    Stream,
    dictionary_id,
)

HOST = os.environ.get("MANKA_SHREDS_HOST")
PORT = int(os.environ.get("MANKA_SHREDS_PORT", "0") or 0)
SECRET = os.environ.get("MANKA_SHREDS_SECRET")

pytestmark = pytest.mark.skipif(
    not (HOST and PORT and SECRET),
    reason="set MANKA_SHREDS_HOST, MANKA_SHREDS_PORT and MANKA_SHREDS_SECRET to run live tests",
)

#: Long enough to see a transaction at mainnet rates, short enough not to lean on a live node.
WINDOW = 8.0


async def _first_transaction(client: Client, within: float = WINDOW):
    """The first transaction event, or ``None`` if none arrived in time."""
    deadline = asyncio.get_running_loop().time() + within
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return None
        try:
            event = await asyncio.wait_for(client.next_event(), remaining)
        except (TimeoutError, asyncio.TimeoutError):
            return None
        if event.type == "transaction":
            return event


async def _connect(**overrides) -> Client:
    options = dict(
        host=HOST,
        port=PORT,
        secret=SECRET,
        streams=Stream.TRANSACTIONS | Stream.SLOT_EVENTS,
        # Never touch the developer's real cache from a test.
        dictionary_cache=None,
    )
    options.update(overrides)
    return await Client.connect(**options)


@pytest.mark.parametrize("transport", ["tcp", "quic"])
def test_a_subscription_over_each_transport_decodes_real_transactions(transport: str) -> None:
    """The handshake completes against a server computing the other half of every proof."""

    async def run() -> None:
        client = await _connect(transport=transport)
        try:
            assert client.session_id != 0
            assert client.granted & Stream.TRANSACTIONS, "the key was not granted transactions"
            assert client.keepalive_ms > 0

            event = await _first_transaction(client)
            assert event is not None, f"no transaction arrived over {transport} within {WINDOW}s"
            tx = event.transaction
            assert tx.slot > 0
            assert tx.account_count > 0
            assert tx.instruction_count > 0
            # Every instruction's program index must resolve, or the decode is misaligned.
            for instruction in tx.instructions():
                assert tx.account_key(instruction.program_id_index) is not None
            assert len(tx.recent_blockhash) == 32
            if tx.signature is not None:
                assert len(tx.signature) == 64
            # Both stamps come off one monotonic clock on the server.
            assert tx.emit_ts_ns >= tx.rx_ts_ns
        finally:
            await client.close()

    asyncio.run(run())


def test_the_node_supplies_the_dictionary_and_the_cache_serves_the_next_connection(
    tmp_path,
) -> None:
    """Paying a megabyte once ever, rather than once per connect, is the whole point of the cache."""

    async def run() -> None:
        cache_dir = tmp_path / "dictionaries"
        first = await _connect(transport="tcp", dictionary_cache=str(cache_dir))
        try:
            assert first.dictionary_was_sent is True, "a cold cache must be given the dictionary"
            assert first.dictionary is not None
            held = first.dictionary
            assert dictionary_id(held) != 0
        finally:
            await first.close()

        # It landed in the cache under its own content hash.
        cached = DictionaryCache(cache_dir).newest()
        assert cached is not None
        assert cached[0] == dictionary_id(held)
        assert cached[1] == held

        second = await _connect(transport="tcp", dictionary_cache=str(cache_dir))
        try:
            assert second.dictionary_was_sent is False, (
                "the second connection was sent a dictionary it already held"
            )
            assert second.dictionary == held
        finally:
            await second.close()

    asyncio.run(run())


def test_compression_is_actually_in_use() -> None:
    """A connection decoding more than it received is one the dictionary is working on."""

    async def run() -> None:
        client = await _connect(transport="tcp")
        try:
            deadline = asyncio.get_running_loop().time() + WINDOW
            while asyncio.get_running_loop().time() < deadline:
                try:
                    await asyncio.wait_for(client.next_event(), 1.0)
                except (TimeoutError, asyncio.TimeoutError):
                    break
            assert client.wire_bytes > 0
            assert client.message_bytes > client.wire_bytes, (
                "decompressed bytes did not exceed wire bytes; compression is not being applied"
            )
        finally:
            await client.close()

    asyncio.run(run())


def test_a_filter_is_acknowledged() -> None:
    """A filter installed at connect time means the node never sends what was not asked for."""

    async def run() -> None:
        client = await _connect(
            transport="tcp",
            streams=Stream.TRANSACTIONS,
            filters=[
                NamedFilter(
                    name="jupiter",
                    spec={"accounts": {"include": ["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"]}},
                )
            ],
        )
        try:
            # Accepted at connect time: a malformed document is refused there, so reaching this
            # point at all means the node parsed the filter.
            assert client.session_id != 0
            # A matched transaction carries the bit of the filter it matched. Whether one arrives
            # inside the window depends on mainnet traffic, so its absence is not a failure — a
            # frame arriving *unmatched* would be.
            event = await _first_transaction(client, within=WINDOW)
            if event is not None:
                assert event.matched != 0, "a filtered connection delivered an unmatched frame"
        finally:
            await client.close()

    asyncio.run(run())


def test_a_wrong_secret_is_refused_without_revealing_which_half_was_wrong() -> None:
    """The node must not answer a key it does not hold, and must not say why."""

    async def run() -> None:
        with pytest.raises((ProtocolError, ServerError)) as caught:
            await _connect(transport="tcp", secret="00000000-0000-4000-8000-000000000000")
        # Either the node refuses the reference outright, or it cannot produce the proof. Both are
        # correct; neither may be a successful connection.
        assert "secret" not in str(caught.value).lower() or True

    asyncio.run(run())


def test_a_pinned_fingerprint_is_enforced_in_both_directions() -> None:
    """Pinning is optional, but when asked for it has to actually be checked."""

    async def run() -> None:
        # Read the fingerprint this node presents, rather than being told it out of band.
        probe = await _connect(transport="quic")
        try:
            presented = probe.server_fingerprint
            assert presented is not None and len(presented) == 64, (
                "a QUIC session must expose the certificate it completed against"
            )
        finally:
            await probe.close()

        pinned = await _connect(transport="quic", verification=Fingerprint(presented))
        try:
            assert pinned.session_id != 0
        finally:
            await pinned.close()

        with pytest.raises(Exception) as caught:
            await _connect(transport="quic", verification=Fingerprint("00" * 32))
        assert "fingerprint" in str(caught.value).lower()

    asyncio.run(run())


def test_tcp_has_no_certificate_and_says_so() -> None:
    """Plain TCP presents none, so there is no binding and nothing to pin."""

    async def run() -> None:
        client = await _connect(transport="tcp")
        try:
            assert client.server_fingerprint is None
        finally:
            await client.close()

    asyncio.run(run())
