# Setup

From cloning this repository to a transaction on your screen. Five minutes.

You need two things, and we give you one of them:

| | |
|---|---|
| **address** | `host:port` of the node. Public. The same port serves both transports |
| **secret** | from us. The only credential there is |

There is no key id. The greeting names your key by `SHA-256(domain ‖ secret)` and never carries the
secret itself, so the server finds it by that reference rather than by a name.

Nothing else. No certificate to pin, no dictionary to install — the node proves it holds your key
during the handshake, and hands you its compression dictionary while connecting.

---

## Rust

Requires Rust 1.85 (edition 2024).

**1. Add the dependency:**

```toml
[dependencies]
manka-shreds-sdk = { git = "https://github.com/Manka-Group/manka-shreds-sdk" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

**2. Connect and read:**

```rust
use manka_shreds_sdk::Event;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = manka_shreds_sdk::connect(
        "NODE_HOST:9000",
        std::env::var("MANKA_SHREDS_SECRET")?,
    ).await?;

    loop {
        if let Event::Transaction { tx, .. } = client.next_event().await? {
            println!("slot {} sig {:?}", tx.slot(), tx.signature());
        }
    }
}
```

**3. Run it:**

```fish
set -x MANKA_SHREDS_SECRET your-secret
cargo run
```

---

## TypeScript

Requires Node 22.15 or newer, where zstd is built in.

**1. Build the package once, then install it by path:**

```fish
git clone https://github.com/Manka-Group/manka-shreds-sdk
cd manka-shreds-sdk/typescript
npm install
npm run build

cd /path/to/your/project
npm install /path/to/manka-shreds-sdk/typescript
```

The build is not optional — the repository holds sources, and the package exports `dist/`.

**2. Connect and read:**

```ts
import { MankaShredsClient } from '@manka-shreds/sdk';

const client = await MankaShredsClient.connect({
  host: 'NODE_HOST',
  port: 9000,
  secret: process.env.MANKA_SHREDS_SECRET!,
});

for await (const event of client) {
  if (event.type === 'transaction') {
    console.log(event.transaction.slot, event.transaction.signature);
  }
}
```

**3. Run it:**

```fish
set -x MANKA_SHREDS_SECRET your-secret
node your-script.js
```

---

## It connected. Now what?

**You are getting everything.** That is every transaction on the cluster, votes included — votes are
about half of mainnet. Narrow it before you are billed for what you discard: see
[Streams](README.md#streams) to drop whole categories, and [Filters](README.md#filters) to match on
accounts or programs. A filter passed at connect is in force before the first frame arrives; setting
one afterwards leaves a window where the firehose is already flowing.

**Read `Lag` events.** There are no acknowledgements and nothing is retransmitted. If you cannot
keep up you lose the oldest frames and are told exactly what you missed. Ignoring it is how you end
up with a hole in your view and no idea it is there.

**Keep your receive loop cheap.** Time spent in it is time not spent reading, and a subscriber that
stays behind is disconnected.

---

## When it does not connect

| What you see | What it means |
|---|---|
| `Unauthorized` | The secret is wrong — or the key is not granted the stream you asked for. Both refusals look the same on purpose |
| `malformed hello`, or a complaint about a field length | The node predates the current handshake. It needs upgrading; nothing on your side will help |
| `Forbidden: no requested stream is permitted` | Your key authenticated but is granted none of the streams you asked for. Ask us to widen it |
| Connection refused, or a timeout | Wrong address or port, or the node is down. The port is the same for QUIC and TCP |
| Something about zstd | The node has compression disabled. These SDKs require it; see [Compression](README.md#compression-is-not-optional) |

Quote the **key reference** in a support ticket, not your key. It is a SHA-256 of your secret, so it
identifies which key you are using without being usable as one. Both SDKs log it on a failed
handshake.

---

Full protocol reference: **[README.md](README.md)**.
Language detail: **[Rust](rust/README.md)** · **[TypeScript](typescript/README.md)**.
