# @manka-shreds/sdk (TypeScript)

Subscriber client for the [manka-shreds](https://github.com/Manka-Group/manka-shreds) Solana
shred stream.

The protocol itself — framing, streams, filters, timestamps, the transaction layout — is documented
once in the [repository README](../README.md). This document is about using the package.

Setting up for the first time? [SETUP.md](../SETUP.md) is the five-minute version.

This package is not on npm yet. Clone the repository, build it once, then install it by path:

```fish
git clone https://github.com/Manka-Group/manka-shreds-sdk
cd manka-shreds-sdk/typescript
npm install          # dev dependencies, for the build
npm run build        # emits dist/, which is what the package exports

cd /path/to/your/project
npm install /path/to/manka-shreds-sdk/typescript
```

The build step is not optional: the package points at `dist/`, and the repository holds sources only
— committing build output would mean you were running something you could not check against the
source beside it.

Once it is published this becomes `npm install @manka-shreds/sdk`, and nothing else about your code
changes.

**Requires Node 22.15 or newer**, where `node:zlib` gained zstd — so decompression, including with a
dictionary, uses nothing but Node itself.

QUIC does not: Node has no QUIC (`node:quic` does not exist in Node 22 LTS, and is experimental and
flag-gated where it does), so it comes from **`@matrixai/quic`**, a native addon with prebuilt
per-platform binaries. It is loaded lazily, so a consumer that passes `transport: 'tcp'` never
touches it and never fails on a platform it has no binary for.

---

## Connecting

You supply the address and your secret — see
[What you supply, and what you do not](../README.md#what-you-supply-and-what-you-do-not). Nothing
else: there is no certificate to pin, and the compression dictionary arrives from the node when you
connect:

```ts
import { MankaShredsClient, Stream } from '@manka-shreds/sdk';

const client = await MankaShredsClient.connect({
  host: 'node.example.com',
  port: 9000,
  secret: process.env.MANKA_SHREDS_SECRET!,
  streams: Stream.TRANSACTIONS | Stream.SLOT_EVENTS,
});

console.log(`session ${client.sessionId} granted ${client.granted}`);

for await (const event of client) {
  switch (event.type) {
    case 'transaction':
      console.log(event.transaction.slot, event.transaction.pipelineNs);
      break;
    case 'slot-start':
      console.log('slot started', event.slot.slot);
      break;
    case 'lag':
      console.error(`dropped ${event.lag.dropped} frames`);
      break;
  }
}
```

Omitting `streams` subscribes to every published stream. See the
[stream table](../README.md#streams). **Votes are opt-in**; votes are about half of mainnet
traffic, so adding `Stream.VOTES` roughly doubles your frame rate.

`host`, `port` and `verification` are all optional and default to the node this
package was issued for. Pass any of them to override that one. Reaching a different node needs only
`host` and `port` — nothing about the default node's certificate is baked in, so there is nothing
to override alongside them.

`secret` is sent as its **UTF-8 bytes, exactly as written** — it is never decoded as hex or base64,
even when it looks like either. Secrets are usually a run of hex digits, and the server compares
against the literal characters in its key file, so guessing at an encoding would silently send the
wrong bytes. Pass a `Buffer` if your secret is genuinely binary. This matches the Rust SDK and the
`manka-shreds-cli` exactly.

## Transport

QUIC unless you say otherwise. The rationale is in the [repository
README](../README.md#transport-quic-by-default); the API is:

```ts
// QUIC (default). The node authenticates itself with your key during the handshake, so its
// certificate is not checked against anything — there is nothing to configure.
const quic = {};

// TCP, for a colocated subscriber or one behind a network that blocks UDP.
const overTcp = { transport: 'tcp' as const };
```

**There is no fingerprint to supply.** The node proves it holds your key before you send any proof
of your own, and that proof is bound to the certificate the session actually presented, so a relay
substituting its own is caught by the exchange. The node may rotate its certificate whenever it
likes without breaking you. See [the handshake](../README.md#the-handshake).

For a deployment that is not a manka-shreds node in its default configuration:

```ts
// Verify against the platform root store, as an HTTPS client would. Only meaningful when the
// node has a CA-signed certificate for a name it is reachable by; it will refuse the
// self-signed certificate a node generates by default.
const webpki = { verification: { webpki: true } as const };

// Belt and braces: additionally require this exact certificate. Adds nothing over the default
// against a manka-shreds node, and brings back a value that must be reissued on every rotation.
const pinned = { verification: { fingerprint: '828221a0e060de4b' } };

// When the certificate names something other than the host you dial.
const named = { verification: { webpki: true } as const, serverName: 'node.internal' };
```

A fingerprint may be written with or without colons, in any case. The node prints it at startup:

```text
quic listener ready (primary transport) bind=0.0.0.0:9100 self_signed=true fingerprint=828221a0…
```

`fingerprintOf(der)` computes the same value from a certificate you already hold.

## Events

Iterating yields a discriminated union — narrow on `event.type`:

| `type` | Field | Carries |
|---|---|---|
| `transaction` | `transaction`, `matched` | a decoded transaction, and which named filters it matched |
| `entry` | `entry` | a proof-of-history entry |
| `slot-start` | `slot` | the first shred of a slot arrived |
| `slot-end` | `slot` | a slot finished, with shred and recovery counts |
| `duplicate` | `duplicate` | a leader equivocated; both signatures included |
| `lag` | `lag` | frames you missed, and where the stream resumes |
| `filter-ack` | `ack` | the verdict on a filter you submitted |
| `ping` / `pong` | — | liveness; pings are answered for you |
| `other` | `kind`, `payload` | a frame kind this build does not know |

Every event also carries `seq`, its per-connection sequence number.

The iterator ends when the connection closes, and rejects if the server sends an error or the socket
fails. Breaking out of the `for await` closes the connection.

### Reading until something happens, then carrying on

`break` closing the connection is right for "I am done" and wrong for "I am done *waiting*". When
you need to read until a specific event and then keep streaming — waiting for a `filter-ack` before
trusting a new filter, say — use `next()` instead:

```ts
import type { MankaShredsEvent } from '@manka-shreds/sdk';

client.setFilter({ is_vote: { value: false } });

let event: MankaShredsEvent | null;
while ((event = await client.next()) !== null) {
  if (event.type === 'filter-ack') {
    if (!event.ack.accepted) throw new Error(event.ack.detail);
    break;   // leaves the connection open
  }
}

// Still connected; carry on reading.
for await (const event of client) { /* ... */ }
```

`next()` resolves to `null` once the connection has closed and rejects if it failed. It is the
direct equivalent of the Rust SDK's `next_event()`.

### Buffers are views, not copies

Every byte accessor returns a `subarray` of the receive buffer, which is what keeps decoding cheap.
Those views are valid **only during the current iteration**. To keep one, copy it:

```ts
if (event.type === 'transaction' && event.transaction.signature !== null) {
  const signature = Buffer.from(event.transaction.signature);   // safe to keep
  const borrowed = event.transaction.signature;                 // invalid after the next iteration
}
```

The exception is `event.payload` on an `other` event, which is already copied.

## Reading a transaction

```ts
import { MESSAGE_VERSION_LEGACY } from '@manka-shreds/sdk';

if (event.type === 'transaction') {
  const tx = event.transaction;

  tx.slot;               // bigint
  tx.parentSlot;
  tx.signature;          // Buffer(64) | null — the transaction id
  tx.isVote;
  tx.recovered;          // reconstructed from parity rather than received directly
  tx.verification;       // 'verified' | 'disabled' | 'unknown-leader' | 'stale-schedule'
  tx.pipelineNs;         // server-internal latency, monotonic

  for (const key of tx.accountKeys()) {
    // Buffer(32)
  }

  for (const ix of tx.instructions()) {
    const program = tx.accountKey(ix.programIdIndex);   // Buffer(32) | null
    // ix.accounts: Buffer of indices, ix.data: Buffer
  }

  for (const lookup of tx.lookups()) {
    // Unresolved: lookup.accountKey, lookup.writableIndexes, lookup.readonlyIndexes
  }

  if (tx.messageVersion === MESSAGE_VERSION_LEGACY) {
    // Pre-versioned message.
  }
}
```

Slots and timestamps are `bigint` because they exceed `Number.MAX_SAFE_INTEGER` in the nanosecond
range — silently losing precision there would be worse than requiring the suffix. Counts and indices
are plain numbers.

Keys and signatures are raw `Buffer`s, not base58. This package has no dependencies, so encoding is
left to you (`bs58`, `@solana/web3.js`, or your own).

### Why `signature` and `accountKey` can be `null`

Every real transaction is signed, and its instructions name account indices that exist. But the node
is a **relay, not a validator**: it forwards what a leader signed into the shred, and it does not
re-check that the transactions inside are well formed. A leader can therefore produce a transaction
with no signature, or one whose `programIdIndex` points past its own account list.

Those accessors return `null` rather than throwing, because throwing would be worse in both
directions. It would fire from a property read or from inside a `for` loop — well outside whatever
`try` guarded the decode — and a leader could use it to knock every subscriber off the stream. Same
reason the decoder relays such a transaction instead of refusing the frame: refusing would hand the
same lever to the same party. `null` is something you can skip.

This matches the Rust SDK, which returns `Option` from both.

## Compression

This client offers only zstd and refuses a stream the server would send uncompressed; see
[Compression is mandatory](../README.md#compression-is-mandatory) for why. A server with zstd
disabled rejects the promise from `connect` with a message mentioning `requires zstd`.

The dictionary needs nothing from you. The node sends whichever one it is using during the
handshake, this package checks it against the id the acknowledgement announced, caches it under its
own hash, and uses it from the first message:

```ts
const client = await MankaShredsClient.connect({ host, port, secret });

client.dictionaryActive;   // false only if the node has no dictionary at all
client.dictionaryWasSent;  // true when it arrived over the wire rather than from the cache
```

`dictionaryWasSent` is expected the first time you connect to a node, and again after its operator
changes the dictionary. True on *every* connection means the cache is not being written.

The cache lives at `$XDG_CACHE_HOME/manka-shreds`, else `~/.cache/manka-shreds`. `MANKA_SHREDS_DICTIONARY_CACHE`
moves it, or `off` disables it; `dictionaryCache: '/some/path'` and `dictionaryCache: null` do the
same in code. A cache that cannot be written is not an error — the dictionary still arrives and the
stream still runs at the full ratio, it is simply fetched again next time.

To seed a client that already holds the bytes and skip even the first transfer:

```ts
import { readFileSync } from 'node:fs';

const client = await MankaShredsClient.connect({
  host, port, secret,
  dictionary: readFileSync('/etc/manka-shreds/dictionary.bin'),
});
```

One that does not match the node's is not an error: the node sends its own, and yours is superseded
for that connection.

Watch the achieved ratio with `client.wireBytes` and `client.decodedBytes`.

## Filters

One filter:

```ts
client.setFilter({ programs: { include: ['JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4'] } });
```

Or up to sixteen named ones on the same connection, which is what lets one connection serve several
interests:

```ts
import type { MankaShredsEvent } from '@manka-shreds/sdk';

client.setFilters([
  { name: 'jupiter', spec: { programs: { include: ['JUP6Lk...'] } } },
  { name: 'my-desk', spec: { accounts: { include: ['So111...'], exclude: ['...'] } } },
]);

// Neither is in force yet. `next()` rather than `for await`, so the connection stays open.
let event: MankaShredsEvent | null;
while ((event = await client.next()) !== null) {
  if (event.type === 'filter-ack') {
    if (!event.ack.accepted) {
      console.error(`refused (cost ${event.ack.cost}): ${event.ack.detail}`);
    }
    break;
  }
}
```

Every transaction then reports which of them it matched, as a bitmask:

```ts
if (event.type === 'transaction') {
  for (let index = 0; index < 16; index += 1) {
    if ((event.matched & (1 << index)) !== 0) {
      console.log(`slot ${event.transaction.slot} matched filter ${index}`);
    }
  }
}
```

A transaction matching several filters arrives **once** with every match recorded, not once per
filter. The set is accepted or refused together, so the connection never carries part of what was
asked for.

Both calls return immediately — **the filters are not in force yet**, and frames already in flight
still arrive under the previous ones. The language, including `include`/`exclude`/`required` key
clauses and the two budgets, is documented [here](../README.md#filters).

### Filtering from the first frame

That round trip is not free: until the ack arrives you are unfiltered, and everything you subscribed
to is being sent to you and billed. Pass the filters to `connect` instead and the window does not
exist — the server installs them before the first frame:

```ts
const client = await MankaShredsClient.connect({
  host, port, secret,
  filters: [{ name: 'my-desk', spec: { accounts: { include: ['So111...'] } } }],
});
```

There is no `filter-ack` to wait for: the filter is in force before anything is sent, and `connect`
resolving is the acknowledgement. A filter that does not compile, or that exceeds your key's
budgets, **rejects the promise** rather than connecting you unfiltered — the fallback would bill you
for exactly the traffic you were avoiding. `setFilters` still works afterwards, replacing it.

## Errors

| Thrown | Meaning |
|---|---|
| `ServerError` | the server refused or closed; `.code` and `.detail` — see the [error table](../README.md#errors) |
| `ProtocolError` | a malformed message, or a codec this client never offered |
| `Error` | socket failure or timeout |

There is no automatic reconnect: reconnect policy belongs to the caller, and a client that silently
reconnects hides a `TooSlow` that you need to know about.

```ts
import { ErrorCode, ServerError } from '@manka-shreds/sdk';

while (true) {
  try {
    const client = await MankaShredsClient.connect(options);
    for await (const event of client) {
      handle(event);
    }
  } catch (err) {
    if (err instanceof ServerError && (err.code === ErrorCode.Unauthorized || err.code === ErrorCode.Forbidden)) {
      throw err;   // needs a key change, not a retry
    }
    console.error('disconnected:', err);
  }
  await new Promise((r) => setTimeout(r, 1_000));
}
```

Back off on `RateLimited`.

## Health

| Property | Use |
|---|---|
| `sessionId` | quote it to your operator when reporting a problem |
| `granted` | what you actually got, which may be less than you asked for |
| `gaps` | frames dropped because you were not reading fast enough — should stay 0n |
| `wireBytes` / `decodedBytes` | achieved compression ratio |
| `dictionaryActive` | whether a dictionary is in use; false only if the node has none |
| `dictionaryWasSent` | whether it arrived over the wire rather than from the cache |

A rising `gaps` is the signal to narrow your filter or move work off the receive path. The
`for await` loop is the receive path: anything slow inside it is time not spent reading, and a slow
reader is eventually disconnected with `TooSlow`. Push work onto a queue rather than awaiting it
inline.

### Falling behind is bounded, not buffered

Events you have not asked for accumulate, but only up to a few thousand. Past that the client stops
reading the socket until you catch up, which pushes back through the transport to the server.

That is deliberate, and it is what makes the numbers above mean anything. Buffering without bound
would trade a memory leak for a lie: your process grows until it dies, and until then the server
sees a subscriber keeping up perfectly, so it never drops a frame, never sends a `lag`, and `gaps`
stays at `0n` while you fall further behind. With the bound, a consumer that cannot keep up is told
so — by the server, in the terms the protocol defines.

The practical consequence: a slow `for await` body slows the stream rather than silently queueing it,
and a consumer that stops entirely resumes from wherever the server's own queue got to, having been
told what it lost. Neither is a reason to do heavy work inline — you will still be disconnected with
`TooSlow` eventually — but the failure is visible rather than invisible.

## Using the protocol directly

`protocol`, `transaction` and `events` are exported and free of any socket handling, so you can
decode frames from a capture, a replay, or your own transport:

```ts
import { FRAME_HEADER_LEN, readFrameHeader, Transaction } from '@manka-shreds/sdk';

const header = readFrameHeader(bytes);
const payload = bytes.subarray(FRAME_HEADER_LEN, FRAME_HEADER_LEN + header.len);
const tx = Transaction.read(payload);
```

## Testing

```fish
npm test
```

`test/fixtures.test.ts` decodes the golden bytes in [`../fixtures`](../fixtures) — including a frame
the Rust server compressed with a dictionary, proving Node's built-in zstd is wire-compatible.
`test/client.test.ts` runs the client against a stub server speaking the real wire format, covering
the compression refusal, dictionary negotiation, sequence gaps, unknown frames, byte-at-a-time
delivery, mid-stream errors, and the backpressure above in both directions — that a consumer which
stops reading stops the socket, and that one which starts again is not left wedged.
