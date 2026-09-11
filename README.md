# manka-shreds SDK

Client libraries for the manka-shreds Solana shred stream, in Rust and TypeScript. A transaction
reaches you when the shreds carrying it arrive, before any block is assembled and well before RPC.

## Documentation

Full documentation is available at **[docs.manka.wtf](https://docs.manka.wtf)** — how to get access,
the endpoints, filters, streams, the wire protocol and the transaction layout.

## Installation

Rust, as a git dependency until the crate is published:

```toml
[dependencies]
manka-shreds-sdk = { git = "https://github.com/Manka-Group/manka-shreds-sdk" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

TypeScript, built from this repository until the package is published:

```bash
git clone https://github.com/Manka-Group/manka-shreds-sdk
npm install ./manka-shreds-sdk/typescript
```

## Getting started

Two things are needed and both come from us: the address of a node, and your secret. There is no
key id, and nothing else to configure.

```rust
use manka_shreds_sdk::Event;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = manka_shreds_sdk::connect(
        std::env::var("MANKA_SHREDS_ENDPOINT")?,
        std::env::var("MANKA_SHREDS_SECRET")?,
    )
    .await?;

    loop {
        if let Event::Transaction { tx, .. } = client.next_event().await? {
            println!("slot {} sig {:?}", tx.slot(), tx.signature());
        }
    }
}
```

```ts
import { MankaShredsClient } from '@manka-shreds/sdk';

const client = await MankaShredsClient.connect({
  host: process.env.MANKA_SHREDS_HOST!,
  port: Number(process.env.MANKA_SHREDS_PORT),
  secret: process.env.MANKA_SHREDS_SECRET!,
});

for await (const event of client) {
  if (event.type === 'transaction') {
    console.log(event.transaction.slot, event.transaction.signature);
  }
}
```

Both connect over QUIC, both require compression, and both fetch the compression dictionary from
the node while connecting. You are subscribed to everything by default, votes included — narrowing
that is the first thing to read about in the documentation.

## Requirements

Rust 1.85 or newer, edition 2024, on tokio.

Node 22.15 or newer, where zstd is built in.

## License

MIT. See [LICENSE](LICENSE).
