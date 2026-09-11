//! The Rust examples in the README, compiled.
//!
//! The README is the only document this repository still carries; everything else lives on
//! docs.manka.wtf. That makes this file the single guard on the first code a subscriber runs:
//! a signature that drifts away from the example fails the build here rather than in their editor.
//!
//! Nothing here runs. Each example is a function that is compiled and never called, because
//! running one would need a live node and a secret. Compilation is the whole point.

#![allow(dead_code, unused_variables)]

use manka_shreds_sdk::Event;

/// `README.md` — Getting started.
///
/// Both arguments come from the environment on purpose: the address is never compiled in, and a
/// documented call that stopped taking one would fail to build here.
async fn getting_started() -> Result<(), Box<dyn std::error::Error>> {
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

/// A guard against this file quietly becoming decoration: if the README stops carrying Rust, the
/// example above is no longer mirroring anything and the pairing should be revisited.
#[test]
fn the_readme_still_carries_the_rust_example() {
    let readme = include_str!("../../README.md");
    assert!(
        readme.contains("```rust"),
        "README.md carries no Rust block — this file mirrors nothing"
    );
    assert!(
        readme.contains("manka_shreds_sdk::connect("),
        "README.md no longer shows connect() — update this file to match"
    );
}
