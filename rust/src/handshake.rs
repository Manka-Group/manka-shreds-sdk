//! Proving possession of your key without ever sending it.
//!
//! # What this replaces
//!
//! A password-style handshake sends the credential to authenticate. Your key is a single value that
//! is both name and secret, so sending it puts a fully usable credential on the wire on every
//! connect — recoverable by anyone who can capture the traffic or terminate the TLS in front of it.
//!
//! Nothing here sends it. Both ends prove they hold it instead.
//!
//! ```text
//! you    → node   key reference, your nonce
//! node   → you    its nonce, HMAC(key, "server" ‖ transcript)
//! you            check it — a peer that cannot produce this does not hold your key
//! you    → node   HMAC(key, "client" ‖ transcript)
//! ```
//!
//! # Why there is no fingerprint to configure
//!
//! QUIC is always TLS, so the node presents a certificate. **Nothing verifies it**, nobody
//! distributes it, and the node may mint a fresh one on every restart. It is not what authenticates
//! the node — your key is.
//!
//! Its hash goes into the transcript, and that is all it is for. Anything that terminates your TLS
//! and reconnects onwards must present a certificate of its own, so the transcript it shares with
//! you differs from the one it shares with the node. It cannot compute either proof without your
//! key, and it cannot pass a proof between the two sessions, because each is bound to a different
//! certificate.
//!
//! That is why this SDK needs no fingerprint, no certificate authority, and no domain name — and
//! why a node rotating its certificate does not break you.
//!
//! Over plain TCP there is no certificate and therefore no binding. Your key still never crosses
//! the wire, but an interposed relay is no longer detectable, which is why TCP is for a subscriber
//! that is not crossing a network it does not control.

use hmac::{Mac, digest::CtOutput};
use sha2::{Digest, Sha256};

const REF_DOMAIN: &[u8] = b"manka-shreds/key-ref/v1";
const SERVER_DOMAIN: &[u8] = b"manka-shreds/server-proof/v1";
const CLIENT_DOMAIN: &[u8] = b"manka-shreds/client-proof/v1";

type HmacSha256 = hmac::Hmac<Sha256>;

/// A public, stable reference to an API key.
///
/// `SHA-256` of the key under a domain separator. This is what travels in the greeting, and what
/// appears in a log or a support ticket: it identifies your key without being it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyRef(pub [u8; 32]);

impl KeyRef {
    /// Bytes on the wire.
    pub const LEN: usize = 32;

    /// Derives the reference for `key`.
    pub fn of(key: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(REF_DOMAIN);
        hasher.update(key);
        Self(hasher.finalize().into())
    }

    /// Lowercase hex, for a log line or a support ticket.
    pub fn to_hex(self) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// The first sixteen hex characters, enough to tell two keys apart at a glance.
    pub fn short(self) -> String {
        self.to_hex().chars().take(16).collect()
    }
}

impl std::fmt::Debug for KeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyRef({})", self.short())
    }
}

impl std::fmt::Display for KeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.short())
    }
}

/// What ties a proof to one TLS session: the hash of the certificate the server presented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelBinding(pub [u8; 32]);

impl ChannelBinding {
    /// For a transport that presents no certificate — plain TCP.
    pub const NONE: Self = Self([0u8; 32]);

    /// For a server presenting `certificate_der`.
    pub fn of_certificate(certificate_der: &[u8]) -> Self {
        Self(Sha256::digest(certificate_der).into())
    }

    /// Whether this binding says nothing about the session.
    #[inline]
    pub fn is_none(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

/// A proof of possession.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof(pub [u8; 32]);

impl Proof {
    /// Bytes on the wire.
    pub const LEN: usize = 32;
}

/// Everything both ends must agree on for a proof to mean anything.
#[derive(Clone, Copy, Debug)]
pub struct Transcript {
    /// Which key is claimed.
    pub key_ref: KeyRef,
    /// Chosen by the client.
    pub client_nonce: [u8; 32],
    /// Chosen by the server.
    pub server_nonce: [u8; 32],
    /// The TLS session this belongs to.
    pub binding: ChannelBinding,
}

impl Transcript {
    /// The proof the server sends, which authenticates the node to you.
    pub fn server_proof(&self, key: &[u8]) -> Proof {
        self.proof(key, SERVER_DOMAIN)
    }

    /// The proof you send, which authenticates you to the node.
    pub fn client_proof(&self, key: &[u8]) -> Proof {
        self.proof(key, CLIENT_DOMAIN)
    }

    fn proof(&self, key: &[u8], domain: &[u8]) -> Proof {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts a key of any length");
        mac.update(domain);
        mac.update(&self.key_ref.0);
        mac.update(&self.client_nonce);
        mac.update(&self.server_nonce);
        mac.update(&self.binding.0);
        Proof(mac.finalize().into_bytes().into())
    }

    /// Whether `presented` is the proof the server should have sent.
    ///
    /// Compared in constant time: returning early on the first differing byte would tell a forger
    /// how much of a guess was right.
    pub fn verify_server(&self, key: &[u8], presented: &Proof) -> bool {
        let wrap = |bytes: &[u8; 32]| -> CtOutput<HmacSha256> {
            CtOutput::new(hmac::digest::Output::<HmacSha256>::clone_from_slice(bytes))
        };
        wrap(&self.server_proof(key).0) == wrap(&presented.0)
    }
}

/// A nonce for one handshake.
///
/// From the operating system's generator: it must be unpredictable, not merely unique. A nonce an
/// attacker can anticipate lets it collect a proof over a transcript you are about to produce.
pub fn fresh_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut nonce)
        .expect("the operating system generator is available");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_reference_identifies_a_key_without_containing_it() {
        let key = b"3f2504e0-4f89-11d3-9a0c-0305e82c3301";
        let reference = KeyRef::of(key);
        assert_eq!(reference, KeyRef::of(key));
        assert_ne!(reference, KeyRef::of(b"another"));
        assert!(!reference.to_hex().contains("3f2504e0"));
    }

    #[test]
    fn the_two_directions_cannot_be_swapped() {
        let transcript = Transcript {
            key_ref: KeyRef::of(b"k"),
            client_nonce: [1u8; 32],
            server_nonce: [2u8; 32],
            binding: ChannelBinding::of_certificate(b"cert"),
        };
        assert!(transcript.verify_server(b"k", &transcript.server_proof(b"k")));
        assert!(
            !transcript.verify_server(b"k", &transcript.client_proof(b"k")),
            "a client proof authenticated a server"
        );
    }

    /// The scenario the binding exists for.
    #[test]
    fn a_relay_cannot_pass_a_proof_between_two_sessions() {
        let key = b"the-key";
        let base = Transcript {
            key_ref: KeyRef::of(key),
            client_nonce: [1u8; 32],
            server_nonce: [2u8; 32],
            binding: ChannelBinding::of_certificate(b"the relay's certificate"),
        };
        let real = Transcript {
            binding: ChannelBinding::of_certificate(b"the node's certificate"),
            ..base
        };
        assert!(
            !base.verify_server(key, &real.server_proof(key)),
            "a proof from the real node satisfied a session terminated by a relay"
        );
    }

    #[test]
    fn nonces_do_not_repeat() {
        assert_ne!(fresh_nonce(), fresh_nonce());
    }
}
