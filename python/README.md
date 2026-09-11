# manka-shreds — Python SDK

A subscriber client for the manka-shreds shred stream.

The protocol itself — framing, streams, filters, timestamps, the transaction layout — is documented
once in the [repository README](../README.md). This document is about using the package.

Setting up for the first time? [SETUP.md](../SETUP.md) is the five-minute version.

This package is not on PyPI yet. Install it from the repository:

```fish
pip install "manka-shreds-sdk @ git+https://github.com/Manka-Group/manka-shreds-sdk#subdirectory=python"
```

Or from a local checkout, which is the shape to use when you are reading the source alongside your
own code:

```fish
pip install -e /path/to/manka-shreds-sdk/python
```

Once it is published this becomes `pip install manka-shreds-sdk`, and nothing else about your code
changes.

**Requires Python 3.14 or newer**, where `compression.zstd` entered the standard library — so
decompression, including with a server-supplied dictionary, needs no third-party package. A TCP
subscriber therefore has **no dependencies at all**. QUIC needs a native implementation and is an
extra:

```fish
pip install "manka-shreds-sdk[quic]"
```

---

## Connecting

```python
import asyncio, os
from manka_shreds_sdk import Client, Stream

async def main():
    client = await Client.connect(
        host="node.example.com",
        port=9000,
        secret=os.environ["MANKA_SHREDS_SECRET"],
        streams=Stream.TRANSACTIONS,
    )
    async for event in client:
        if event.type == "transaction":
            tx = event.transaction
            print(tx.slot, tx.signature.hex() if tx.signature else None)

asyncio.run(main())
```

**Two things reach a node: its address and your secret.** The address is public; the secret is the
only credential, and it never crosses the wire — the greeting carries `SHA-256(domain ‖ secret)` and
both ends prove they hold the key. There is no certificate to pin and no dictionary to install.

`Client` is also an async context manager, which closes the connection on the way out:

```python
async with await Client.connect(host=host, port=port, secret=secret) as client:
    async for event in client:
        ...
```

### Options

| Argument | Default | Meaning |
|---|---|---|
| `host`, `port` | required | The node's address. One port serves both transports |
| `secret` | required | Your key, as `str` or `bytes` |
| `streams` | `ALL_STREAMS` | Which streams to ask for. The server grants the intersection with your key's |
| `transport` | `"quic"` | `"quic"` or `"tcp"` |
| `verification` | `Unchecked()` | Certificate handling. `Fingerprint(hex)` to pin one |
| `dictionary` | `None` | A dictionary you already hold, instead of the cache's |
| `dictionary_cache` | platform default | A directory, or `None` to keep none |
| `connect_timeout` | `10.0` | Seconds for the whole handshake |
| `max_message_bytes` | 16 MiB | Largest frame this connection will accept |
| `filters` | `None` | Filters to install before the stream starts |

---

## Events

Every event carries `type` and `seq`. A gap in `seq` is exactly what was dropped.

| `type` | Attribute | Needs |
|---|---|---|
| `transaction` | `.transaction`, `.matched` | `Stream.TRANSACTIONS` |
| `entry` | `.entry` | `Stream.ENTRIES` |
| `slot-start` | `.slot` | `Stream.SLOT_EVENTS` |
| `slot-end` | `.slot` | `Stream.SLOT_EVENTS` |
| `duplicate` | `.duplicate` | `Stream.DUPLICATES` |
| `raw-shred` | `.shred` | `Stream.RAW_SHREDS` |
| `lag` | `.lag` | always |
| `filter-ack` | `.ack` | always |
| `ping` / `pong` | — | always |
| `unknown` | `.kind`, `.payload` | a frame this build does not know, carried rather than dropped |

`next_event()` reads one event if you would rather not iterate.

---

## Transactions

Decoded lazily from the received buffer — nothing is parsed until it is asked for:

```python
tx = event.transaction
tx.slot, tx.parent_slot, tx.entry_index, tx.tx_index
tx.signature          # first signature, the transaction's id; None if unsigned
tx.signatures()       # all of them
tx.account_keys()     # every account key, in declared order
tx.recent_blockhash
tx.is_vote, tx.recovered, tx.verification
tx.pipeline_ns        # first shred -> encoded message, on the node's monotonic clock

for ix in tx.instructions():
    program = tx.account_key(ix.program_id_index)   # None if the index is out of range
    ix.accounts, ix.data

tx.lookups()          # address lookup tables, unresolved
tx.raw_tx             # original bytes, only when the node was asked to include them
```

`tx.signature` and `tx.account_key(i)` return `None` rather than raising. A leader can sign a
transaction with no signatures, or one naming a program index past its own account list; the node
relays what the leader signed, and raising from an accessor would let a leader knock every
subscriber off the stream.

---

## Filters

A filter installed at connect time means the node never sends what you did not ask for:

```python
from manka_shreds_sdk import NamedFilter

client = await Client.connect(
    host=host, port=port, secret=secret,
    filters=[NamedFilter(name="jup", spec={"account": "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"})],
)
```

`event.matched` is a bitmask of which of your filters the transaction matched — bit `i` is the
filter at index `i`. One transaction matching several arrives once, with every match recorded.

`await client.set_filters([...])` replaces the set mid-stream. The whole set is accepted or refused
together, and the verdict arrives as a `filter-ack` event.

---

## Compression

**Not optional.** The node compresses with zstd and a trained dictionary, and this client requires
it — a server with zstd disabled is refused at connect rather than silently costing three times the
bandwidth.

There is nothing to install. The node hands over the dictionary it is using during the handshake
whenever this client does not already hold it, and the SDK caches it under its own content hash:

```
$MANKA_SHREDS_DICTIONARY_CACHE   explicit, or "off"/"none" to disable
$XDG_CACHE_HOME/manka-shreds
~/.cache/manka-shreds
```

Every cache operation degrades to "no cache" rather than failing the connection — a read-only
filesystem or a container with no home directory is a normal deployment. `client.dictionary_was_sent`
is `True` when the dictionary came over the wire rather than out of the cache; seeing that on *every*
connection means the cache is not working, which is worth knowing and otherwise invisible.

`client.wire_bytes` against `client.message_bytes` is the ratio you are actually getting.

---

## Transport

QUIC by default. Over a WAN one lost packet stalls a TCP stream until it is retransmitted, holding
back every message behind it including ones that already arrived — the wrong failure mode for a
stream whose value is arriving early.

```python
await Client.connect(host=host, port=port, secret=secret, transport="tcp")
```

TCP is a reasonable choice for a colocated subscriber, or one behind a network that blocks UDP, and
needs no extra dependency. Note that plain TCP presents no certificate and therefore no channel
binding: your key still never crosses the wire, but an interposed relay stops being detectable.

---

## Testing

```fish
cd python
uv run --with pytest python -m pytest
```

The fixture tests decode golden bytes produced by the server's own encoders, committed under
`fixtures/`. They are what stops this SDK and the node drifting apart, since the SDK vendors its own
decoders rather than depending on the server crates.
