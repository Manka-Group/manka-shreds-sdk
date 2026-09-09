//! How the client reaches the server: QUIC, or TCP.
//!
//! # Why QUIC is the default
//!
//! Over a WAN one lost packet stalls a TCP stream until it is retransmitted, holding back every
//! message behind it — including messages that already arrived intact. For a latency product
//! carrying a firehose that is the wrong failure mode: the data you are paying to receive early is
//! held hostage by a packet you already have the successor to.
//!
//! QUIC does not head-of-line block the same way, establishes in one round trip, and survives the
//! client changing address. Inside a datacentre TCP is simpler and marginally faster, which is why
//! it remains available — but it is the exception, chosen deliberately, not the default.
//!
//! A node serves both on the same address: QUIC is UDP, so the port number is shared.
//!
//! # Verifying the server
//!
//! QUIC is always encrypted, so the client must decide what it trusts. See [`ServerVerification`].

use std::{net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::error::{Error, Result};

/// Application-layer protocol identifier, matched against the server's.
///
/// Pins the connection to this protocol, so a peer speaking something else is refused during the
/// TLS handshake rather than after it has been given a session.
pub const ALPN: &[u8] = b"manka-shreds/1";

/// Which transport to use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Transport {
    /// QUIC. The default, and what a node offers first.
    #[default]
    Quic,
    /// TCP. For a colocated subscriber, or one behind something that blocks UDP.
    Tcp,
}

/// What, if anything, the client checks the server's certificate against.
///
/// # The node is not authenticated by its certificate
///
/// It is authenticated by your key. During the handshake the node proves it holds that key, over a
/// transcript bound to the certificate the session completed against — so anything terminating your
/// TLS and reconnecting onwards produces a transcript that does not match, and cannot forge one.
/// See [`crate::handshake`].
///
/// That is why [`Self::Unchecked`] is the default and is *not* a downgrade: the certificate carries
/// no trust to begin with, and the node may rotate it whenever it likes without breaking you.
#[derive(Clone, Debug, Default)]
pub enum ServerVerification {
    /// Accept whatever certificate is presented, and rely on the key to authenticate the node.
    ///
    /// The default, and the right choice against a manka-shreds node. The connection is still encrypted;
    /// what is skipped is checking the certificate against a trust store, which would prove nothing
    /// a manka-shreds node needs proved. An interposed relay is caught by the proof exchange instead.
    #[default]
    Unchecked,
    /// Verify against the platform root store, as an ordinary HTTPS client would.
    ///
    /// Only meaningful when the node has a certificate signed by a public CA for a name it is
    /// reachable by. It adds nothing over [`Self::Unchecked`] against a node that authenticates
    /// itself with your key, and it will refuse the self-signed certificate a node generates by
    /// default.
    WebPki,
    /// Additionally require the leaf certificate to have this SHA-256 fingerprint, lowercase hex.
    ///
    /// Belt and braces. The proof exchange already detects a substituted certificate, so this is
    /// not needed — and it brings back the cost it was invented for: the value must be reissued
    /// every time the node's certificate changes.
    Pinned(String),
}

/// A connection to the server, whichever transport carries it.
///
/// The framing above this is identical either way, which is the point: one protocol implementation,
/// two ways of moving its bytes.
pub(crate) enum Wire {
    Tcp(TcpStream),
    Quic {
        // Held so the connection is not closed underneath the streams.
        _endpoint: quinn::Endpoint,
        _connection: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
}

impl Wire {
    /// What a proof of key possession is bound to on this connection.
    ///
    /// The hash of whatever certificate the TLS session actually completed against — nothing
    /// verified it, and nothing needed to. Its only job is to differ between two TLS sessions, so
    /// that anything terminating yours and reconnecting onwards produces a transcript neither end
    /// agrees with. See [`crate::handshake`].
    ///
    /// TCP presents no certificate, so there is nothing to bind to. The key still never crosses the
    /// wire; an interposed relay simply stops being detectable.
    pub(crate) fn channel_binding(&self) -> crate::handshake::ChannelBinding {
        match self {
            Self::Tcp(_) => crate::handshake::ChannelBinding::NONE,
            Self::Quic { _connection, .. } => _connection
                .peer_identity()
                .and_then(|identity| {
                    identity
                        .downcast::<Vec<rustls::pki_types::CertificateDer>>()
                        .ok()
                })
                .and_then(|chain| {
                    chain
                        .first()
                        .map(|leaf| crate::handshake::ChannelBinding::of_certificate(leaf))
                })
                .unwrap_or(crate::handshake::ChannelBinding::NONE),
        }
    }

    /// Appends whatever has arrived to `buf`, returning how much. Zero means the peer is done.
    pub(crate) async fn read_buf(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        match self {
            Self::Tcp(stream) => Ok(stream.read_buf(buf).await?),
            Self::Quic { recv, .. } => {
                // Read into the spare capacity the caller already reserved, so a frame larger than
                // one datagram does not reallocate per chunk.
                let at = buf.len();
                if buf.capacity() - at < 16 * 1024 {
                    buf.reserve(64 * 1024);
                }
                buf.resize(buf.capacity(), 0);
                let read = recv
                    .read(&mut buf[at..])
                    .await
                    .map_err(|error| Error::Handshake(format!("quic read: {error}")))?;
                let read = read.unwrap_or(0);
                buf.truncate(at + read);
                Ok(read)
            }
        }
    }

    /// Writes every byte.
    pub(crate) async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Tcp(stream) => Ok(stream.write_all(bytes).await?),
            Self::Quic { send, .. } => send
                .write_all(bytes)
                .await
                .map_err(|error| Error::Handshake(format!("quic write: {error}"))),
        }
    }
}

/// Opens a TCP connection with Nagle disabled.
pub(crate) async fn connect_tcp(addr: SocketAddr) -> Result<Wire> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    Ok(Wire::Tcp(stream))
}

/// Opens a QUIC connection and its session stream.
pub(crate) async fn connect_quic(
    addr: SocketAddr,
    server_name: &str,
    verification: &ServerVerification,
) -> Result<Wire> {
    let mut tls = match verification {
        ServerVerification::WebPki => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder()?.with_root_certificates(roots).with_no_client_auth()
        }
        ServerVerification::Pinned(fingerprint) => builder()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServer::new(fingerprint)?))
            .with_no_client_auth(),
        ServerVerification::Unchecked => builder()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServer::any()))
            .with_no_client_auth(),
    };
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| Error::Handshake(error.to_string()))?;
    let bind = if addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_tls)));

    let connection = endpoint
        .connect(addr, server_name)
        .map_err(|error| Error::Handshake(format!("quic connect to {addr}: {error}")))?
        .await
        .map_err(|error| Error::Handshake(format!("quic handshake with {addr}: {error}")))?;

    // The client opens the session stream, so the server does not have to guess when it is ready.
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|error| Error::Handshake(format!("opening the session stream: {error}")))?;

    Ok(Wire::Quic {
        _endpoint: endpoint,
        _connection: connection,
        send,
        recv,
    })
}

fn builder() -> Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>> {
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| Error::Handshake(error.to_string()))
}

/// A verifier that accepts exactly one certificate, by fingerprint.
///
/// With no fingerprint it accepts anything, which is what [`ServerVerification::Unchecked`] asks
/// for — and what is correct against a manka-shreds node, whose certificate carries no trust because the
/// handshake authenticates it with your key instead. Both live in one type so there is a single
/// place where certificate checking is relaxed, rather than two independent ways to end up
/// checking nothing.
#[derive(Debug)]
struct PinnedServer {
    expected: Option<[u8; 32]>,
}

impl PinnedServer {
    fn new(fingerprint: &str) -> Result<Self> {
        let cleaned: String = fingerprint
            .chars()
            .filter(|c| !matches!(c, ':' | ' ' | '-'))
            .collect();
        if cleaned.len() != 64 {
            return Err(Error::Handshake(format!(
                "a certificate fingerprint is 64 hex characters (32 bytes of SHA-256), got {}",
                cleaned.len()
            )));
        }
        let mut expected = [0u8; 32];
        for (index, byte) in expected.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&cleaned[index * 2..index * 2 + 2], 16).map_err(|_| {
                Error::Handshake("a certificate fingerprint must be hexadecimal".to_string())
            })?;
        }
        Ok(Self {
            expected: Some(expected),
        })
    }

    fn any() -> Self {
        Self { expected: None }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let Some(expected) = self.expected else {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        };
        use sha2::{Digest, Sha256};
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        // Constant time is not required — the fingerprint is public, and an attacker learning it
        // learns nothing they could not read off the certificate the server presents to anyone.
        if actual == expected {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "certificate fingerprint {} does not match the pinned {}",
                hex(&actual),
                hex(&expected)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // TLS 1.3 only, so this is unreachable; refusing is the safe answer if it ever is not.
        Err(rustls::Error::General("tls 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Lowercase hex, for a fingerprint in an error message.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The SHA-256 fingerprint of a DER certificate, lowercase hex.
///
/// The same value the node prints at startup, and the same one
/// `openssl x509 -fingerprint -sha256` gives minus the colons.
pub fn fingerprint_of(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(der))
}
