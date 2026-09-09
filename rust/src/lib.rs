//! Subscriber client for the manka-shreds Solana shred stream.
//!
//! manka-shreds ingests raw shreds from the cluster, recovers what the network lost, decodes them to
//! transactions, and streams the result to authenticated subscribers ahead of any RPC. This crate
//! is the client side of that stream.
//!
//! ```no_run
//! use manka_shreds_sdk::{Client, Config, Event, StreamMask};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::new(std::env::var("MANKA_SHREDS_SECRET")?)
//!     .streams(StreamMask(StreamMask::TRANSACTIONS));
//! let mut client = Client::connect("node.example.com:9100", config).await?;
//!
//! loop {
//!     match client.next_event().await? {
//!         Event::Transaction { tx, .. } => {
//!             println!("{} {:?}", tx.slot(), tx.signature());
//!         }
//!         Event::Lag(lag) => eprintln!("dropped {} frames", lag.dropped),
//!         _ => {}
//!     }
//! }
//! # }
//! ```
//!
//! # Compression is not optional
//!
//! This client offers only zstd, and refuses a connection the server would hand it uncompressed.
//! See [`Client`] for why.
//!
//! # What this crate does not do
//!
//! Nothing here talks to a validator, submits transactions, or resolves address lookup tables —
//! resolving those needs account state a shred pipeline does not have, so lookups are carried
//! unresolved and left to the consumer.

#![forbid(unsafe_code)]

pub mod client;
pub mod handshake;
pub mod dictcache;
pub mod error;
pub mod events;
pub mod protocol;
pub mod transaction;
pub mod transport;

pub use client::{Client, Config, Event, NamedFilter};

/// Connects to `addr` with your credentials and nothing else to decide.
///
/// The address is yours to supply: this build carries no endpoint, so one archive serves every
/// node and none of them can go stale when an operator moves or adds one. `addr` is `host:port`,
/// and the same port serves both transports — QUIC over UDP, TCP over TCP.
///
/// There is nothing else to configure, and no key id to go with the secret. The greeting names your
/// key by `SHA-256(domain ‖ secret)` and never carries the secret itself, so the server finds it by
/// that reference rather than by a name. The node authenticates itself with the same key during the
/// handshake, so there is no certificate to pin, and it hands over its compression dictionary while
/// connecting, so there is none to install.
///
/// ```no_run
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let mut client = manka_shreds_sdk::connect(
///     "node.example.com:9000",
///     std::env::var("MANKA_SHREDS_SECRET")?,
/// ).await?;
/// # Ok(())
/// # }
/// ```
///
/// To subscribe to a subset of streams or filter at connect, build a [`Config`] with
/// [`Config::new`] and call [`Client::connect`].
///
/// # Errors
///
/// Whatever [`Client::connect`] returns.
pub async fn connect(
    addr: impl tokio::net::ToSocketAddrs + std::fmt::Display + Clone,
    secret: impl Into<Vec<u8>>,
) -> Result<Client> {
    Client::connect(addr, Config::new(secret)).await
}
pub use error::{Error, Result};
pub use events::{Duplicate, Entry, RawShred, SlotEnd, SlotStart};
pub use dictcache::DictionaryCache;
pub use protocol::{
    Capabilities, Codec, Dictionary, ErrorCode, FrameHeader, FrameKind, MAX_DICTIONARY_BYTES,
    StreamMask, Verification, dictionary_id,
};
pub use transaction::{AddressLookup, Instruction, Transaction};
pub use transport::{ServerVerification, Transport, fingerprint_of};
