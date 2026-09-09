# manka-shreds-sdk (Rust)

Subscriber client for the [manka-shreds](https://github.com/Manka-Group/manka-shreds) Solana shred stream.

The protocol itself — framing, streams, filters, timestamps, the transaction layout — is documented
once in the [repository README](../README.md). This document is about using the crate.

Setting up for the first time? [SETUP.md](../SETUP.md) is the five-minute version.

This crate is not on crates.io yet, so cargo takes it from git:

```toml
[dependencies]
manka-shreds-sdk = { git = "https://github.com/Manka-Group/manka-shreds-sdk" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Pin a `tag` or `rev` if you want a build that cannot move under you. A local checkout works too —
`path = "../manka-shreds-sdk/rust"` — which is the shape to use when you are reading the source
alongside your own code.

Once it is published the git reference becomes a version, and nothing else about your code changes.

Requires Rust 1.85 (edition 2024). Depends on `tokio`, `quinn`, `rustls`, `zstd`, `thiserror` and
`sha2`; it does not pull in any Solana crate.

---

## Connecting

You supply the address and your secret — see
[What you supply, and what you do not](../README.md#what-you-supply-and-what-you-do-not). Nothing
else: there is no certificate to pin, and the compression dictionary arrives from the node when you
connect. One call:

```rust
use manka_shreds_sdk::Event;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = manka_shreds_sdk::connect(
        "node.example.com:9000",
        std::env::var("MANKA_SHREDS_SECRET")?,
    ).await?;
    println!("session {} granted {:?}", client.session_id(), client.granted());

    loop {
        match client.next_event().await? {
            Event::Transaction { tx, .. } => {
                println!("slot {} pipeline {}µs", tx.slot(), tx.pipeline_ns() / 1_000);
            }
            Event::SlotStart(slot) => println!("slot {} started", slot.slot),
            Event::Lag(lag) => eprintln!("dropped {} frames", lag.dropped),
            _ => {}
        }
    }
}
```

That subscribes to every published stream. To narrow it, or to filter at connect, build a `Config`
and pass it to `Client::connect` with the address:

```rust
use manka_shreds_sdk::{Client, Config, StreamMask};

let config = Config::new(std::env::var("MANKA_SHREDS_SECRET")?)
    .streams(StreamMask(StreamMask::TRANSACTIONS | StreamMask::SLOT_EVENTS));
let mut client = Client::connect("node.example.com:9000", config).await?;
```

See the [stream table](../README.md#streams). **Votes are opt-in**; votes are about half of
mainnet traffic, so including `StreamMask::VOTES` roughly doubles your frame rate.

`Config::new` is the only constructor. It defaults to `ServerVerification::Unchecked`, which is
right against a manka-shreds node — the handshake authenticates it, so its certificate carries no trust.
Against something else, set the verification mode explicitly.

The secret may be raw bytes or any `Into<Vec<u8>>`. If yours is hex or base64, decode it yourself
before passing it in — it is sent as the bytes you provide, and the server compares against the
literal characters in its key file.

## Transport

QUIC unless you say otherwise. The rationale is in the [repository
README](../README.md#transport-quic-by-default); the API is:

```rust
// QUIC (default). The node authenticates itself with your key during the handshake,
// so its certificate is not checked against anything — there is nothing to configure.
Config::new(secret)

// TCP, for a colocated subscriber or one behind a network that blocks UDP.
Config::new(secret).tcp()
```

**There is no fingerprint to supply.** The node proves it holds your key before you send any proof
of your own, and that proof is bound to the certificate the session actually presented, so a relay
substituting its own is caught by the exchange. The node may rotate its certificate whenever it
likes without breaking you. See [the handshake](../README.md#the-handshake).

For a deployment that is not a manka-shreds node in its default configuration:

```rust
// Verify against the platform root store, as an HTTPS client would. Only meaningful when the
// node has a CA-signed certificate for a name it is reachable by; it will refuse the
// self-signed certificate a node generates by default.
Config::new(secret).verification(ServerVerification::WebPki)

// Belt and braces: additionally require this exact certificate. Adds nothing over the default
// against a manka-shreds node, and brings back a value that must be reissued on every rotation.
Config::new(secret).pinned("828221a0e060de4b…")

// When the certificate names something other than the host you dial.
Config::new(secret)
    .verification(ServerVerification::WebPki)
    .server_name("node.internal")
```

A fingerprint may be written with or without colons, in any case. The node prints it at startup:

```text
quic listener ready (primary transport) bind=0.0.0.0:9100 self_signed=true fingerprint=828221a0…
```

`fingerprint_of(der)` computes the same value from a certificate you already hold.

## Events

`next_event` returns one `Event` per frame:

| Variant | Carries |
|---|---|
| `Transaction { tx, matched }` | a decoded transaction, and which named filters it matched |
| `Entry(Entry)` | a proof-of-history entry |
| `SlotStart(SlotStart)` | the first shred of a slot arrived |
| `SlotEnd(SlotEnd)` | a slot finished, with its shred and recovery counts |
| `Duplicate(Duplicate)` | a leader equivocated; both signatures included |
| `Lag(Lag)` | frames you missed, and where the stream resumes |
| `FilterAck(FilterAck)` | the verdict on a filter you submitted |
| `Ping` / `Pong` | liveness; pings are answered for you |
| `Other { kind, payload }` | a frame kind this build does not know |

`Event` is `#[non_exhaustive]`: match with a `_` arm, or a future frame type will break your build.

### The borrow

`next_event` returns `Event<'_>` borrowing the client's internal frame buffer, which is what makes
decoding allocation-free. The borrow ends when the event is dropped, so this does not compile:

```rust,ignore
let a = client.next_event().await?;   // borrows client
let b = client.next_event().await?;   // error: still borrowed
```

Copy out what you need before looping again:

```rust
let signature = match client.next_event().await? {
    Event::Transaction { tx, .. } => tx.signature().copied(),
    _ => None,
};
```

If you want owned events on a channel, copy in the receive loop and send the copies. Keep that loop
cheap: work done there is time not spent reading, and a slow reader is disconnected with `TooSlow`.

## Reading a transaction

Every accessor is a load or a slice; nothing is decoded until asked for.

```rust
use manka_shreds_sdk::{Event, Verification};

if let Event::Transaction { tx, matched } = client.next_event().await? {
    tx.slot();
    matched;                      // which of your named filters this arrived for
    tx.parent_slot();
    tx.signature();               // Option<&[u8; 64]> — the transaction id
    tx.is_vote();
    tx.recovered();               // reconstructed from parity rather than received directly
    tx.verification();            // Verification::Verified, or why not
    tx.pipeline_ns();             // server-internal latency, monotonic

    for key in tx.account_keys() {
        // &[u8; 32]
    }

    for ix in tx.instructions() {
        let program = tx.account_key(ix.program_id_index as usize);
        let _ = (program, ix.accounts, ix.data);
    }

    for lookup in tx.lookups() {
        // Unresolved: the table key plus writable/readonly index lists.
        let _ = (lookup.account_key, lookup.writable_indexes, lookup.readonly_indexes);
    }

    if tx.message_version() == manka_shreds_sdk::transaction::MESSAGE_VERSION_LEGACY {
        // Pre-versioned message.
    }

    if tx.verification() != Verification::Verified {
        // Structurally valid, but not proven to come from the slot's leader.
    }
}
```

Keys and signatures are raw bytes, not base58 — this crate deliberately has no base58 dependency.
Use `bs58` or `solana-pubkey` if you need the string form.

## Compression

This client offers only zstd and refuses a stream the server would send uncompressed; see
[Compression is mandatory](../README.md#compression-is-mandatory) for why. A server with zstd
disabled produces `Error::CompressionRequired`.

The dictionary needs nothing from you. The node sends whichever one it is using during the
handshake, this crate checks it against the id the acknowledgement announced, caches it under its
own hash, and uses it from the first message:

```rust
let client = Client::connect(addr, Config::new(secret)).await?;

assert!(client.dictionary_active());       // false only if the node has no dictionary at all
if client.dictionary_was_sent() {
    // Arrived over the wire rather than from the cache. Expected the first time you connect to a
    // node, and again after its operator changes the dictionary. Every time means the cache is
    // not writable — see below.
}
```

The cache lives at `$XDG_CACHE_HOME/manka-shreds`, else `~/.cache/manka-shreds`. `MANKA_SHREDS_DICTIONARY_CACHE`
moves it, or `off` disables it; `Config::dictionary_cache(dir)` and
`Config::without_dictionary_cache()` do the same in code. A cache that cannot be written is not an
error — the dictionary still arrives and the stream still runs at the full ratio, it is simply
fetched again next time.

To seed a client that already holds the bytes and skip even the first transfer:

```rust
use std::sync::Arc;

let dictionary = Arc::new(std::fs::read("/etc/manka-shreds/dictionary.bin")?);
let config = Config::new(secret).dictionary(dictionary);
```

One that does not match the node's is not an error: the node sends its own, and yours is superseded
for that connection.

Watch the achieved ratio with `wire_bytes()` and `decoded_bytes()`.

## Filters

One filter:

```rust
client
    .set_filter(r#"{"programs":{"include":["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"]}}"#)
    .await?;
```

Or up to sixteen named ones on the same connection, which is what lets one connection serve several
interests:

```rust
use manka_shreds_sdk::NamedFilter;

client
    .set_filters(&[
        NamedFilter {
            name: "jupiter",
            spec_json: r#"{"programs":{"include":["JUP6Lk..."]}}"#,
        },
        NamedFilter {
            name: "my-desk",
            spec_json: r#"{"accounts":{"include":["So111..."],"exclude":["..."]}}"#,
        },
    ])
    .await?;

// The set is not in force yet. Wait for the acknowledgement if that matters.
loop {
    if let Event::FilterAck(ack) = client.next_event().await? {
        if !ack.accepted {
            eprintln!("refused (measured {}): {}", ack.cost, ack.detail);
        }
        break;
    }
}
```

Every transaction then reports which of them it matched:

```rust
if let Event::Transaction { tx, matched } = client.next_event().await? {
    for index in matched.iter() {
        println!("slot {} matched filter {index}", tx.slot());
    }
}
```

A transaction matching several filters arrives **once** with every match recorded, not once per
filter. The set is accepted or refused together, so the connection never carries part of what was
asked for.

The filter language — including `include`/`exclude`/`required` key clauses and the two budgets — is
documented [here](../README.md#filters). Frames already in flight still arrive under the previous
filter.

### Filtering from the first frame

That round trip is not free: until the ack arrives you are unfiltered, and everything you subscribed
to is being sent to you and billed. Name the filters on the config instead and the window does not
exist — the server installs them before the first frame:

```rust
let config = Config::new(secret).filters(&[NamedFilter {
    name: "my-desk",
    spec_json: r#"{"accounts":{"include":["So111..."]}}"#,
}]);
let mut client = Client::connect(addr, config).await?;
```

There is no `FilterAck` to wait for: the filter is in force before anything is sent, and `connect`
returning is the acknowledgement. A filter that does not compile, or that exceeds your key's
budgets, **fails the connection** rather than connecting you unfiltered — the fallback would bill
you for exactly the traffic you were avoiding. `set_filters` still works afterwards, replacing it.

`Config::filter` takes a single unnamed spec, for the common case.

## Errors

`Error` is `#[non_exhaustive]`. The ones worth handling distinctly:

| Variant | Meaning |
|---|---|
| `Server { code, detail }` | the server refused or closed — see the [error table](../README.md#errors) |
| `CompressionRequired(codec)` | the server would not give a zstd stream |
| `Version { server, client }` | protocol version mismatch |
| `Closed` | the connection ended |
| `Io(_)` | the socket failed |
| `Truncated { .. }` / `BadOffset { .. }` | a malformed message |

There is no automatic reconnect: reconnect policy belongs to the caller, and a client that silently
reconnects hides a `TooSlow` that you need to know about. A minimal loop:

```rust
loop {
    match run(&addr, config.clone()).await {
        Err(manka_shreds_sdk::Error::Server { code, detail }) => {
            eprintln!("disconnected: {code:?} {detail}");
        }
        Err(err) => eprintln!("disconnected: {err}"),
        Ok(()) => break,
    }
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}
```

Back off on `RateLimited`, and do not retry `Unauthorized` or `Forbidden` — those need a key change,
not a retry.

## Health

| Accessor | Use |
|---|---|
| `session_id()` | quote it to your operator when reporting a problem |
| `granted()` | what you actually got, which may be less than you asked for |
| `gaps()` | frames dropped because you were not reading fast enough — should stay 0 |
| `wire_bytes()` / `decoded_bytes()` | achieved compression ratio |
| `dictionary_active()` | whether a dictionary is in use; false only if the node has none |
| `dictionary_was_sent()` | whether it arrived over the wire rather than from the cache |
| `keepalive_ms()` | how often an idle connection is pinged |

A rising `gaps()` is the signal to narrow your filter or move work off the receive path.

## Using the protocol directly

The `protocol`, `transaction` and `events` modules are public and free of any socket handling, so
you can decode frames from a capture, a replay, or your own transport:

```rust
use manka_shreds_sdk::{Transaction, protocol::{FRAME_HEADER_LEN, read_frame_header}};

let header = read_frame_header(&bytes)?;
let payload = &bytes[FRAME_HEADER_LEN..FRAME_HEADER_LEN + header.len];
let tx = Transaction::read(payload)?;
```

## Testing

```fish
cargo test
cargo clippy --all-targets -- -D warnings
```

`tests/fixtures.rs` decodes the golden bytes in [`../fixtures`](../fixtures); `tests/client.rs`
runs the client against a stub server that speaks the real wire format, including the compression
refusal, dictionary negotiation, sequence gaps, unknown frames and byte-at-a-time delivery.
