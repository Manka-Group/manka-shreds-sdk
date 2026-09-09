# manka-shreds SDKs

Client libraries for the [manka-shreds](https://github.com/Manka-Group/manka-shreds) Solana shred stream, in
Rust and TypeScript.

manka-shreds ingests raw shreds directly from the cluster, deduplicates them across sources, recovers what
the network lost from parity, decodes them to transactions, and streams the result to authenticated
subscribers. You see a transaction when the shreds carrying it arrive — before any block is
assembled, and well before RPC.

| SDK | Path | Runtime | Dependencies |
|---|---|---|---|
| Rust | [`rust/`](rust) | tokio | `tokio`, `quinn`, `rustls`, `zstd`, `thiserror`, `sha2` |
| TypeScript | [`typescript/`](typescript) | Node 22.15+ | `@matrixai/quic` (native) |

**New here? Start with [SETUP.md](SETUP.md)** — clone to a transaction on screen, in five minutes,
in either language.

This file covers what the two SDKs share: the protocol itself. Language detail lives in
**[Rust](rust/README.md)** · **[TypeScript](typescript/README.md)**.

**Not yet on crates.io or npm.** The Rust crate installs as a git dependency and the TypeScript
package is built from this repository — see the install section of whichever usage document you
need. Nothing else about your code changes when they are published to the registries.

**You need two things: the node's address, and your secret.** The address is public; the secret is
the only credential, and there is no key id to go with it — the greeting names your key by a hash of
the secret, so that is what the server looks it up by. There is nothing else to configure — see
[What you supply, and what you do not](#what-you-supply-and-what-you-do-not). No certificate to pin:
the node proves it holds your key during the handshake, so it may rotate its certificate without
breaking you. No compression dictionary to install either: the node hands you its own when you
connect.

---

## Quick start

**Rust**

```rust
use manka_shreds_sdk::Event;

let mut client = manka_shreds_sdk::connect(
    "node.example.com:9000",
    std::env::var("MANKA_SHREDS_SECRET")?,
).await?;

loop {
    if let Event::Transaction { tx, matched } = client.next_event().await? {
        println!("slot {} tx {:?} filters {:?}", tx.slot(), tx.signature(), matched);
    }
}
```

**TypeScript**

```ts
import { MankaShredsClient } from '@manka-shreds/sdk';

const client = await MankaShredsClient.connect({
  host: 'node.example.com',
  port: 9000,
  secret: process.env.MANKA_SHREDS_SECRET!,
});

for await (const event of client) {
  if (event.type === 'transaction') {
    console.log(event.transaction.slot, event.matched);
  }
}
```

---

## Your key is never sent

The one thing worth knowing about this protocol: **your API key does not go on the wire.** Not in
the greeting, not encrypted, not at all.

Instead both ends prove they hold it:

```text
you  → node   a one-way reference to your key, and a nonce
node → you    its nonce, and HMAC(key, "server" ‖ transcript)
you           check it — a peer that cannot produce this does not hold your key
you  → node   HMAC(key, "client" ‖ transcript)
```

A packet capture of an entire handshake is worth nothing to whoever took it. The reference is a
SHA-256 of your key, so it identifies which key you are using without being usable as one — which
also makes it the right thing to quote in a support ticket.

### Why there is no certificate to configure

QUIC is always TLS, so the node presents a certificate. **Nothing verifies it, nobody distributes
it, and the node may mint a fresh one on every restart.** It is not what authenticates the node —
your key is.

Its hash goes into the transcript above, and that is its only job. Anything that terminates your TLS
and reconnects onwards must present a certificate of its own, so the transcript it shares with you
differs from the one it shares with the node. It cannot compute either proof without your key, and
it cannot pass a proof between the two sessions.

So there is no fingerprint to paste, no certificate authority, no domain name, and nothing that
breaks when the node rotates its certificate. The node proves itself *before* you send your own
proof, so a peer that is not the node learns nothing from trying.

**Over plain TCP there is no certificate and therefore no binding.** Your key still never crosses
the wire, but an interposed relay stops being detectable — which is why TCP is for a subscriber that
is not crossing a network it does not control.

---

## What you supply, and what you do not

Two things: **the address, and your secret.** Nothing else, and nothing is compiled into this
repository.

| Not your problem | Why |
|---|---|
| **Certificate** | the node authenticates itself with your key during the handshake, bound to the certificate the session presented. There is nothing to pin, and an operator may rotate it whenever they like |
| **Compression dictionary** | the node hands its own over while connecting, and the SDK caches it under its own hash — see [Compression](#compression-is-not-optional) |

**Your key is never in this repository**: the same build serves every subscriber, and works against
every node. Earlier builds compiled an endpoint in; that meant a reissue every
time a node moved, and a subscriber pointed at one that had gone away saw a failure that read like a
credential error. Passing it is one argument and it cannot go stale.

```ts
const client = await MankaShredsClient.connect({
  host: 'node.example.com',
  port: 9000,
  secret: process.env.MANKA_SHREDS_SECRET!,
});
```

```rust
let mut client = manka_shreds_sdk::connect(
    "node.example.com:9000",
    std::env::var("MANKA_SHREDS_SECRET")?,
).await?;
```

The same port serves both transports — QUIC over UDP, TCP over TCP.

---

## Transport: QUIC by default

**Both SDKs connect over QUIC unless told otherwise.** A node serves QUIC and TCP on the same
address — QUIC is UDP, so the port number is shared and you need one address either way.

Over a WAN one lost packet stalls a TCP stream until it is retransmitted, holding back every
message behind it, *including messages that already arrived intact*. For a stream whose whole value
is arriving early, that is the wrong failure mode: the data you are paying for is held hostage by a
packet you already have the successor to. QUIC does not head-of-line block the same way, establishes
in one round trip, and survives your address changing.

TCP is still there and is a reasonable choice for a colocated subscriber, or one behind a network
that blocks UDP — `Config::tcp()` in Rust, `transport: 'tcp'` in TypeScript.

### Verifying the server

**You do not have to.** The node proves it holds your key before you send any proof of your own,
and that proof is bound to the TLS session it arrives on — so a substituted certificate is caught
by the exchange, not by a fingerprint you had to be given. See
[Why there is no certificate to configure](#why-there-is-no-certificate-to-configure) above.

The default is therefore `Unchecked`: the connection is encrypted as always, and what is skipped is
checking the certificate against a trust store, which proves nothing a manka-shreds node needs proved.

Two other modes exist for deployments that are not a manka-shreds node in the default configuration:

| Mode | When |
|---|---|
| **`Unchecked`** (default) | against a manka-shreds node — the key authenticates it |
| **`WebPki`** | the node has a certificate signed by a public CA for a name it is reachable by |
| **`Pinned(fingerprint)`** | belt and braces; brings back a value that must be reissued on every certificate rotation |

Neither of the other two adds anything against a node that authenticates itself with your key, and
`WebPki` will **refuse** the self-signed certificate a node generates by default.

---

## Compression is mandatory

**Both SDKs offer only zstd, and refuse a connection the server would hand them uncompressed.**

A manka-shreds node streams several hundred megabits of transaction data per second uncompressed. Plain
zstd alone cuts that by about a ninth — transaction messages are small and per-message compression
cannot see how much they repeat across the stream. The dictionary the node hands you does see it,
and takes the same traffic to roughly a third of the wire. Compression is not a tuning knob here, it
is the difference between a feasible and an infeasible egress bill.

The enforcement is on both sides, because either alone is insufficient:

* **Server side.** A node run with `egress.require_compression = true` refuses any handshake that
  negotiates its way to an uncompressed stream, answering with `BadRequest` and the message
  `this server requires a compressed stream; offer zstd or lz4 in the handshake`. A client that
  offered only `none` never gets a stream at all.
* **Client side.** Both SDKs put only the zstd bit in the handshake's codec mask, and both abort the
  connection if the acknowledgement comes back with any other codec. So even against a permissive
  server, an SDK-built client cannot end up on an uncompressed stream by accident.

This means a server with zstd disabled entirely is unusable by these SDKs — by design. The failure
is loud (`Error::CompressionRequired` in Rust, a rejected promise mentioning `requires zstd` in
TypeScript) rather than a silently expensive stream.

### Dictionaries

A dictionary nearly triples zstd's ratio on transaction frames — 1.13x to 3.3x, measured on real
mainnet traffic the dictionary was not trained on. They are small and highly repetitive, which is
the exact case plain zstd handles worst: within a single small frame it has no history to work from,
and it never sees that the *next* frame repeats most of this one.

**There is nothing to do.** The node sends you the dictionary it is using, during the handshake,
whenever you do not already hold that one. Both SDKs ask for it, check it, cache it, and use it from
the first message. No file to install, nothing to reissue when the operator changes it, and
nothing that can quietly go stale.

The exchange is:

```text
you  → Hello        which dictionary you hold (if any), and that you will accept one
node → Challenge    and its own proof that it holds your key
you  → Prove
node → HelloAck     the dictionary it will compress with
node → Dictionary   the bytes — only when yours is not that one
```

Three properties are worth knowing, because each removes a way this used to go wrong:

* **It is settled before `connect` returns.** The dictionary a connection uses cannot change while
  that connection runs. A node sending another mid-stream is refused rather than ignored, because
  the alternative is every subsequent frame failing to decode for a reason nothing on the wire
  explains.
* **It comes after the proof, never before.** A megabyte is only ever sent to a peer that has proved
  it holds the key, so the handshake is not an amplifier.
* **The bytes are checked against the id the node announced.** Anything else is refused. Accepting
  mismatched bytes would leave you decompressing against something other than what the node
  compresses with.

Received dictionaries are cached on disk, addressed by their own hash, so the transfer happens once
ever rather than once per connection:

| | |
|---|---|
| Default location | `$XDG_CACHE_HOME/manka-shreds`, else `~/.cache/manka-shreds` |
| Move it | `MANKA_SHREDS_DICTIONARY_CACHE=/some/path` |
| Switch it off | `MANKA_SHREDS_DICTIONARY_CACHE=off`, or `without_dictionary_cache()` / `dictionaryCache: null` |

A cache that cannot be written is not an error: the connection still gets the dictionary and still
streams at the full ratio, it just pays the transfer again next time. Since neither SDK logs
anything, that fact is reported as state — `dictionary_was_sent()` / `dictionaryWasSent` is true
when the dictionary arrived over the wire rather than out of the cache. Seeing it true on *every*
connection means the cache is not working.

`dictionary_active()` / `dictionaryActive` tells you whether a dictionary is in use at all. It is
false only when the node has none.

To seed a client that already has the bytes, pass them at connect time and skip even the first
transfer. One that does not match the node's is not an error — the node sends its own and yours is
superseded for that connection.

The id is FNV-1a folded to 32 bits, computed identically in both SDKs and the server. There is no
ordering between ids: "outdated" only ever means "a different hash".

It is a coordination token, not a security one. It detects a mismatch; it does not defend against a
forged one, and a forged id produces a decode failure rather than plausible data. The cache is
addressed by the same 32-bit value, so a process that can write to your cache directory could plant
bytes that collide with an id you would otherwise fetch — but such a process can also edit the
binary that reads them, so the boundary is the filesystem. Point `MANKA_SHREDS_DICTIONARY_CACHE` somewhere
only your subscriber can write if that distinction matters to you.

---

## Protocol reference

### Transports

QUIC and TCP carry byte-for-byte identical framing, so everything below applies to both.

Over QUIC a session is one bidirectional stream, opened by the client, with ALPN `manka-shreds/1`. A peer
speaking anything else is refused during the TLS handshake rather than after being given a session.

### Framing

Every message is a 16-byte header followed by its payload:

| Offset | Type | Field |
|---|---|---|
| 0 | u32 | payload length |
| 4 | u8 | frame kind |
| 5 | u8 | flags — bits 0–1 codec, bit 2 "body is compressed" |
| 6 | u16 | matched named filters, as a bitmask |
| 8 | u64 | sequence number |

All integers are little-endian. The maximum payload is 16 MiB.

**The length is chosen by whoever is sending.** Check it before growing a buffer, not after.

| What | Limit |
|---|---|
| Any frame payload | 16 MiB |
| A filter document | 256 KiB |
| A dictionary | 8 MiB |
| A control message during the handshake | 64 KiB |

The last row is the one worth writing code for. A challenge or a refusal arrives from a peer that
has proved nothing yet, so a client that judged those by the 16 MiB ceiling would let any address it
dials cost it sixteen megabytes for the price of a header. Both SDKs enforce it; the node applies
the same rule to a greeting, for the same reason.

If your own client exposes a maximum message size, apply it to the frame as well as to what a
compressed body expands into. Applied only to the expansion it does nothing at all against an
uncompressed frame — which is exactly the case someone setting it is trying to bound.

The compressed flag and the codec are separate because a body that did not shrink is sent
uncompressed even on a compressed connection — read the flag, not the negotiated codec.

**Sequence numbers are per connection.** A gap means the server dropped frames for you because you
were not reading fast enough; a `Lag` frame states how many and where the stream resumes. Both SDKs
count gaps for you (`gaps()` / `gaps`).

For that to mean anything, a client that falls behind has to stop reading bytes rather than buffer
them: the server can only report what it can see, and a subscriber quietly queueing the firehose in
memory looks, from the server's side, exactly like one keeping up. Both SDKs do stop — Rust because
`next_event` reads the socket only when called, TypeScript by bounding its event backlog and pausing
the transport past it. Neither will hide a fall behind from you.

**Unknown frame kinds must be skipped, not treated as fatal.** Both SDKs surface them as
`Event::Other` / `{ type: 'other' }` with the raw kind byte and payload, so a server that starts
emitting a new frame type does not break older subscribers.

| Kind | Frame |
|---|---|
| 1 | Transaction |
| 2 | Entry |
| 3 | SlotStart |
| 4 | SlotEnd |
| 5 | Duplicate |
| 6 | RawShred |
| 7 | Lag |
| 9 | Hello |
| 10 | HelloAck |
| 11 | FilterAck |
| 12 | Error |
| 13 | Ping |
| 14 | Pong |
| 15 | SetFilter |
| 16 | Challenge |
| 17 | Prove |
| 18 | Dictionary |

Kind 6 carries the `raw_shreds` stream, which a key has to be granted before the node produces it
at all. Kind 8 (SourceStats) is reserved on the wire; no producer exists, and a key cannot be
granted it.

### Handshake

    client → Hello       kind 9
    server → Challenge   kind 16, and the server's own proof
    client → Prove       kind 17
    server → HelloAck    kind 10, or Error (kind 12) and close
    server → Dictionary  kind 18, only when the client needs one

`Hello`:

| Offset | Type | Field |
|---|---|---|
| 0 | u16 | protocol version (1) |
| 2 | u32 | requested stream mask |
| 6 | u8 | codec mask |
| 7 | u8 | capability mask — bit 0 asks to be sent the dictionary |
| 8 | 32 bytes | key reference, `SHA-256` of the key |
| 40 | 32 bytes | client nonce, fresh per connection |
| 72 | u32 | dictionary id held, or 0 |
| 76 | u32 | filter length, if a filter is sent |
| 80 | … | filter JSON |

**The greeting carries no credential.** The key is named by its reference and possession is proved
afterwards over the nonce exchange, so a captured greeting is worth nothing. Both fields before the
dictionary id are fixed width — there is no credential in the greeting to be variable.

The trailing fields are appended in order, so a peer that stops reading after the nonce still parses
the rest: an absent id simply means no dictionary, and an absent length means no filter.

A greeting that *declares* a filter length must deliver it. A short one is refused rather than read
as "no filter": the alternative is connecting a subscriber unfiltered when it asked to be narrowed,
which is a silent bandwidth bill rather than an error. See [filtering at connect](#filter-at-connect-not-after).

Byte 7 was padding until capabilities were added, and was always written as zero. A client built
before them therefore advertises nothing, which is the correct reading of its silence — and is why
adding the dictionary exchange needed no version bump.

`Dictionary` (kind 18), sent once after the acknowledgement and before the first data frame:

| Offset | Type | Field |
|---|---|---|
| 0 | u32 | dictionary id, matching what the acknowledgement announced |
| 4 | u32 | length |
| 8 | … | the dictionary |

At most 8 MiB, refused on the declared length before any body is read. Check that the bytes hash to
the announced id before using them.

`HelloAck`, 22 bytes:

| Offset | Type | Field |
|---|---|---|
| 0 | u16 | protocol version |
| 2 | u32 | granted stream mask |
| 6 | u64 | session id |
| 14 | u8 | negotiated codec |
| 15 | u8 | reserved |
| 16 | u16 | keepalive interval, ms |
| 18 | u32 | dictionary id in use, or 0 |

The **session id** is what the operator's logs are keyed by — quote it when reporting a problem.

Codec negotiation takes the intersection of the client's and server's masks and prefers zstd, then
lz4, then none. Since the SDKs offer only zstd, the result is zstd or a refused connection.

### Streams

A stream mask selects what you receive. Your key grants a subset; the server grants the
intersection, so asking for more than your key allows is not an error — read the granted mask back
from the acknowledgement.

| Bit | Stream | Contents |
|---|---|---|
| 0 | `TRANSACTIONS` | decoded transactions |
| 1 | `ENTRIES` | proof-of-history entries |
| 2 | `SLOT_EVENTS` | slot starts and ends |
| 3 | `DUPLICATES` | equivocation reports |
| 6 | `VOTES` | vote transactions |

**Votes are excluded from `TRANSACTIONS` unless `VOTES` is also set.** Votes are about half of
mainnet transactions by count and are rarely what a subscriber wants, so they are opt-in. Adding
them roughly doubles your frame rate.

### Timestamps

Every timestamp is nanoseconds on the **server's monotonic clock**. `rx_ts_ns` is when the FEC set's
first shred arrived; `emit_ts_ns` is when the server finished encoding the message. Their difference
is the server's internal pipeline latency and is meaningful.

Neither can be compared against your local wall clock — they are not the same clock domain and the
result is nonsense. To measure end-to-end latency, stamp your own arrival time and compare
successive arrivals, or compare against a slot's expected wall time from another source.

### Verification

Each transaction and entry carries how much the server could vouch for it:

| Value | Meaning |
|---|---|
| `verified` | the leader's signature over the FEC set's merkle root checked out |
| `disabled` | the node runs with signature verification switched off |
| `unknown-leader` | no leader is known for the slot |
| `stale-schedule` | the leader schedule is behind |

Anything other than `verified` means the bytes are structurally valid but not proven to come from
the slot's leader.

### Filters

Send a filter (kind 15) whose payload is the JSON below — no length prefix, the frame length
delimits it. The server applies it asynchronously and answers with `FilterAck` (kind 11) carrying
whether it was accepted, its measured cost, and why it was refused if it was.

**The filter is not in force when the call returns.** Frames already in flight still arrive under
the previous filter. If you need certainty, wait for the acknowledgement before treating the change
as applied.

#### Filter at connect, not after

That round trip is not free. Between the handshake completing and the `FilterAck` arriving your
connection is **unfiltered**, and everything you subscribed to is being sent to you — on a busy node
thousands of transactions you did not ask for and are billed for.

Carry the filter in the greeting instead and the window does not exist. The server compiles it
before the connection joins the fan-out, so there is no instant at which you are both connected and
unfiltered:

```rust
Config::new(key, secret).filters(&[NamedFilter { name: "mine", spec_json }])
```

```ts
MankaShredsClient.connect({ host, port, secret, filters: [{ name: 'mine', spec }] });
```

The document is byte-for-byte what `SetFilter` carries, so a filter means the same thing whichever
way it is sent, and the same sixteen-filter limit and budgets apply. There is no `FilterAck` — the
filter is in force before the first frame, and the connection succeeding is the acknowledgement.

**A filter that does not compile, or that exceeds your key's budgets, refuses the connection.** It
does not fall back to an unfiltered stream: that would bill you for precisely the traffic you were
avoiding, without saying so. The refusal is a `BadRequest` naming what was wrong. `SetFilter`
afterwards replaces it, acknowledged normally.

#### Named filters, one connection

A connection carries up to **sixteen named filters**, and every transaction reports which of them it
matched. That is what makes one connection enough for several interests — without attribution,
sixteen filters is the same thing as one filter that is their union, and you would have to re-run
your own filters on arrival to work out why you were sent something.

```jsonc
{"filters": [
  {"name": "jupiter", "spec": {"programs": {"include": ["JUP6Lk..."]}}},
  {"name": "my-desk", "spec": {"and": [
    {"is_vote": {"value": false}},
    {"accounts": {"include": ["So111..."], "exclude": ["..."]}}
  ]}}
]}
```

A submission replaces whatever the connection held, and is **accepted or refused together** — you
are never left carrying part of what you asked for. A transaction matching several filters arrives
**once** with every match recorded, not once per filter.

**An empty list means no filtering, which is the firehose** — the same state as a connection that
never submitted anything. To receive nothing, submit `"none"`.

The match set is a 16-bit mask in the frame header; bit `i` is the filter at index `i` in the set
you submitted. Both SDKs surface it as `matched`.

#### Key clauses

`accounts`, `programs` and `fee_payers` each take three independent sets. Any may be omitted, and an
omitted set is no constraint — so `exclude` alone is a useful filter.

| Set | Meaning |
|---|---|
| `include` | at least one of these is present |
| `exclude` | none of these is present |
| `required` | **every** one of these is present |

Keys and signatures are base58 strings.

```jsonc
"all"                                          // everything
"none"                                         // nothing
{"is_vote": {"value": false}}                  // non-vote transactions
{"verified": {"value": true}}                  // authenticated FEC sets only
{"accounts":   {"include": ["So111...", "..."]}}
{"accounts":   {"exclude": ["..."]}}           // everything except these
{"accounts":   {"required": ["...", "..."]}}   // must touch all of them
{"programs":   {"include": ["JUP6Lk..."]}}     // top-level programs invoked
{"fee_payers": {"include": ["..."]}}
{"signature": "5j7s6N..."}                     // one specific transaction
{"slot_range": {"from": 100, "to": null}}      // inclusive, either end optional
{"data_prefix": {"program": null, "prefix": [9, 8, 7]}}
{"and": [ ... ]}
{"or":  [ ... ]}
{"not": { ... }}
```

**Sets of a few thousand keys are expected and cost nothing per transaction.** The server inverts
every subscriber's keys into a single index, so its work depends on your transaction's account keys
rather than on how many keys you named — or on how many other subscribers are connected. Prefer one
large `include` set over an `or` of many small ones.

#### Budgets

Two, because a filter spends two different resources: **cost** bounds evaluation work (combinators,
and `data_prefix`, which walks each instruction), and **keys** bounds memory. They are separate
because a large account set is cheap to evaluate and expensive to hold. Both apply to the connection
as a whole, and a refusal reports the measured value so you learn by how much you were over.

#### What filters do not see

Accounts reached through an **address lookup table** are not matched — resolving them needs account
state a shred pipeline does not have. A filter naming an account will miss transactions that reach
it through a table. Ask your operator if that matters for what you are doing.

### Keepalive

The server pings an idle connection every `keepalive_ms`. **Both SDKs answer automatically**, from
inside the read path, so a consumer slow to poll is not disconnected for being idle. You will still
see the `Ping` event; you do not need to act on it.

### Errors

| Code | Meaning |
|---|---|
| 1 | `Unauthorized` — key or secret not accepted |
| 2 | `Forbidden` — the key does not permit what was asked |
| 3 | `TooSlow` — you fell too far behind and were disconnected |
| 4 | `RateLimited` |
| 5 | `BadRequest` — malformed, or a policy violation such as required compression |
| 6 | `Shutdown` — the server is going away |
| 7 | `UnsupportedVersion` |

`TooSlow` means the server's per-connection buffer overflowed. The fix is to do less work in the
receive path: hand messages to another thread or task, and narrow your filter so the server drops
what you do not want instead of sending it.

---

## Transaction layout

Transactions are delivered fully decoded, in a layout designed to be read without parsing: a fixed
104-byte header, then sections in a fixed order, each 8-byte aligned. Account keys and signatures
are read by pointing at a slice; nothing is decoded until you ask for it.

```text
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
```

Flags: `IS_VOTE` 1, `VERIFIED` 2, `HAS_RAW_TX` 4, `RECOVERED` 8, `HAS_LEADER` 16, with the
two-bit unverified reason at shift 5.

**Address lookup tables are carried unresolved.** Resolving them needs the lookup tables' account
state, which a shred pipeline does not have. You get the table key and the writable/readonly index
lists; resolving them to addresses is yours to do.

**Raw transaction bytes are off by default.** The decoded form carries the same information and
repeating the bytes roughly doubles the stream's bandwidth. Ask your operator if you need them.

**The node is a relay, not a validator.** It forwards what the leader signed into the shred, and it
does not re-check that the transactions inside are well formed. A leader can therefore produce a
transaction with no signature at all, or one whose `program_id_index` points past its own account
list, and it will reach you.

Both SDKs decode such a transaction rather than refusing the frame, and the affected accessors
answer instead of failing — `Option` in Rust, `null` in TypeScript:

| Accessor | Empty when |
|---|---|
| `signature()` / `signature` | the transaction carries no signature |
| `account_key(i)` / `accountKey(i)` | `i` is past the account list |

The alternatives are both worse, and both are levers a leader could pull against every subscriber at
once: refusing the frame drops your stream, and raising from an accessor fires wherever you happen
to touch the field, well away from whatever guarded the decode. Skipping a `null` is something you
can do. [`fixtures/tx_malformed.bin`](fixtures) is exactly this case, and both suites decode it.

---

## Fixtures

[`fixtures/`](fixtures) holds golden bytes produced by the server's own encoders, plus a
`manifest.json` of the expected decoded values. Both SDKs' test suites decode them and assert field
by field.

This matters because the SDKs vendor their own decoders rather than depending on the server crates —
nothing but these tests stops the two from drifting apart. If the server changes a layout, the
fixtures change and the SDK tests fail, rather than an SDK silently misreading a field.

Everything in `fixtures/` is synthetic: no captured mainnet traffic, no keys, no secrets. Regenerate
from the manka-shreds repository with:

```fish
cargo run --example fixtures -- ../manka-shreds-sdk/fixtures
```

Then run both suites:

```fish
cd rust; and cargo test
cd typescript; and npm test
```

---

## Getting access

Keys are issued by whoever runs the node. You need:

- a **secret**, which is the whole credential — there is no separate key id;
- the **host and port** (one port, serving QUIC over UDP and TCP over TCP).

No certificate fingerprint: there is nothing to distribute and nothing that breaks when the node
rotates its certificate. No dictionary either — the node sends you its own when you connect. An
This repository carries neither: the address is an argument, so one build
serves every node.

Nothing in this repository grants access to anything.

## License

MIT.
