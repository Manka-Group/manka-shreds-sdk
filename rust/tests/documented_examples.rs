//! The Rust examples in the shipped documents, compiled.
//!
//! The TypeScript examples are type checked by `typescript/test/docs.test.ts`, which walks every
//! document and feeds each `ts` block to the compiler. It collects `rust` blocks too and then skips
//! them, so until this file existed the Rust examples in `SETUP.md` and the READMEs were checked by
//! nothing at all — and they are the first code a subscriber runs.
//!
//! That is not a hypothetical. `connect` gained a required address argument, and every documented
//! call to it changed shape on the same day; a stale example would have compiled in nobody's build
//! but the subscriber's.
//!
//! Nothing here runs — each example is a function that is compiled and never called, because
//! running them would need a live node. Compilation is the whole point: a signature that drifts
//! away from the documents fails the build rather than the customer.

#![allow(dead_code, unused_variables)]

use manka_shreds_sdk::{Client, Config, Event, StreamMask};

/// `SETUP.md`, and the Rust quick start in `README.md`.
async fn setup_guide_quick_start() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = manka_shreds_sdk::connect(
        "NODE_HOST:9000",
        std::env::var("MANKA_SHREDS_SECRET")?,
    )
    .await?;

    loop {
        if let Event::Transaction { tx, .. } = client.next_event().await? {
            println!("slot {} sig {:?}", tx.slot(), tx.signature());
        }
    }
}

/// `rust/README.md` — narrowing the streams, and filtering at connect.
async fn narrowing_the_streams() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new(std::env::var("MANKA_SHREDS_SECRET")?)
        .streams(StreamMask(StreamMask::TRANSACTIONS | StreamMask::SLOT_EVENTS));
    let client = Client::connect("node.example.com:9000", config).await?;
    let _ = client;
    Ok(())
}

/// `rust/README.md` — the transport and verification forms.
///
/// Every one of these is a mode a subscriber might reasonably reach for, and each is a distinct
/// call. A renamed builder would leave the document describing an API that no longer exists.
fn transport_and_verification() {
    let secret = "s3cret";

    let _quic = Config::new(secret);
    let _tcp = Config::new(secret).tcp();
    let _webpki =
        Config::new(secret).verification(manka_shreds_sdk::ServerVerification::WebPki);
    let _pinned = Config::new(secret).pinned("828221a0e060de4b");
    let _named = Config::new(secret)
        .verification(manka_shreds_sdk::ServerVerification::WebPki)
        .server_name("node.internal");
}

/// `README.md` — the address is supplied, never compiled in.
///
/// The archive used to carry an endpoint. Reintroducing one would not fail here, but a documented
/// call that stopped taking an address would.
async fn the_address_is_an_argument() -> Result<(), Box<dyn std::error::Error>> {
    let client = manka_shreds_sdk::connect(
        "node.example.com:9000",
        std::env::var("MANKA_SHREDS_SECRET")?,
    )
    .await?;
    let _ = client;
    Ok(())
}

/// The documents referencing these examples still exist, and still contain Rust to check.
///
/// A guard against this file quietly becoming decoration: if a document is renamed or its examples
/// removed, the pairing here should be revisited rather than left asserting nothing.
#[test]
fn the_documents_these_examples_come_from_still_carry_rust() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for doc in ["SETUP.md", "README.md", "rust/README.md"] {
        let path = root.join(doc);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
        assert!(
            text.contains("```rust"),
            "{doc} carries no Rust examples; the ones compiled in this file may be orphaned"
        );
    }
}
