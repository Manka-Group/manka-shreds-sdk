//! Exercises the client against a stub server that speaks the real wire format.
//!
//! The frames it sends are the committed fixtures, so this tests framing, handshake and
//! decompression without asserting anything about layout that `fixtures.rs` does not already pin
//! down.

use std::{path::PathBuf, sync::Arc};

use manka_shreds_sdk::{
    Client, Codec, Config, ErrorCode, Error, Event, FrameKind, StreamMask, dictionary_id,
    handshake::{ChannelBinding, KeyRef, Transcript},
    protocol::{FRAME_HEADER_LEN, read_frame_header, write_frame},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn load(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("reading {name}: {err}"))
}

/// Encodes a hello ack the way the server does.
fn hello_ack(codec: Codec, granted: u32, dictionary_id: u32) -> Vec<u8> {
    let mut body = vec![0u8; 22];
    body[0..2].copy_from_slice(&1u16.to_le_bytes());
    body[2..6].copy_from_slice(&granted.to_le_bytes());
    body[6..14].copy_from_slice(&99u64.to_le_bytes());
    body[14] = codec as u8;
    body[16..18].copy_from_slice(&15_000u16.to_le_bytes());
    body[18..22].copy_from_slice(&dictionary_id.to_le_bytes());
    let mut frame = Vec::new();
    write_frame(&mut frame, FrameKind::HelloAck, 0, &body);
    frame
}

/// Encodes an error the way the server does.
fn error_frame(code: ErrorCode, detail: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(code as u16).to_le_bytes());
    body.extend_from_slice(&(detail.len() as u16).to_le_bytes());
    body.extend_from_slice(detail.as_bytes());
    let mut frame = Vec::new();
    write_frame(&mut frame, FrameKind::Error, 0, &body);
    frame
}

/// Reads the client's greeting off `socket`.
async fn read_hello(socket: &mut TcpStream) -> Vec<u8> {
    let mut buffer = Vec::new();
    loop {
        let read = socket.read_buf(&mut buffer).await.expect("read");
        assert_ne!(read, 0, "client closed before greeting");
        if buffer.len() < FRAME_HEADER_LEN {
            continue;
        }
        let header = read_frame_header(&buffer).expect("header");
        if buffer.len() >= FRAME_HEADER_LEN + header.len {
            assert_eq!(header.kind, FrameKind::Hello);
            return buffer[FRAME_HEADER_LEN..FRAME_HEADER_LEN + header.len].to_vec();
        }
    }
}

/// The secret every stub authenticates against, and every test connects with.
const SECRET: &[u8] = b"secret";

/// Completes the proof exchange as a node does, then hands the socket to `respond`.
///
/// Every test goes through this rather than a shortcut, so the exchange is exercised on each one:
/// a client that stopped proving, or proved the wrong thing, would fail the whole file rather than
/// one test written to notice.
async fn prove(socket: &mut TcpStream, hello: &[u8], key: &[u8]) {
    // The greeting names the key by reference and carries the client's nonce; neither is a secret.
    let mut key_ref = [0u8; 32];
    key_ref.copy_from_slice(&hello[8..40]);
    let mut client_nonce = [0u8; 32];
    client_nonce.copy_from_slice(&hello[40..72]);
    assert_eq!(
        KeyRef(key_ref),
        KeyRef::of(key),
        "the greeting named a different key"
    );

    let transcript = Transcript {
        key_ref: KeyRef(key_ref),
        client_nonce,
        server_nonce: [42u8; 32],
        // TCP, so nothing binds the exchange to a session.
        binding: ChannelBinding::NONE,
    };
    let mut body = Vec::new();
    body.extend_from_slice(&transcript.server_nonce);
    body.extend_from_slice(&transcript.server_proof(key).0);
    let mut frame = Vec::new();
    write_frame(&mut frame, FrameKind::Challenge, 0, &body);
    socket.write_all(&frame).await.expect("challenge");

    // And the client's proof comes back.
    let mut buffer = Vec::new();
    loop {
        let read = socket.read_buf(&mut buffer).await.expect("read");
        assert_ne!(read, 0, "client closed before proving");
        if buffer.len() < FRAME_HEADER_LEN {
            continue;
        }
        let header = read_frame_header(&buffer).expect("header");
        if buffer.len() >= FRAME_HEADER_LEN + header.len {
            assert_eq!(header.kind, FrameKind::Prove);
            let mut proof = [0u8; 32];
            proof.copy_from_slice(&buffer[FRAME_HEADER_LEN..FRAME_HEADER_LEN + 32]);
            assert_eq!(
                proof,
                transcript.client_proof(key).0,
                "the client proved possession of something other than its key"
            );
            return;
        }
    }
}

/// Starts a server that runs `respond` once the client has proved its key.
async fn stub<F, Fut>(respond: F) -> std::net::SocketAddr
where
    F: FnOnce(TcpStream, Vec<u8>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let hello = read_hello(&mut socket).await;
        prove(&mut socket, &hello, SECRET).await;
        respond(socket, hello).await;
    });
    addr
}

/// Starts a server that answers the greeting directly, without proving anything.
///
/// For the cases where the server refuses before the exchange gets that far.
async fn stub_refusing<F, Fut>(respond: F) -> std::net::SocketAddr
where
    F: FnOnce(TcpStream, Vec<u8>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let hello = read_hello(&mut socket).await;
        respond(socket, hello).await;
    });
    addr
}

/// A configuration pointed at a stub, over TCP.
///
/// These stubs are TCP servers, so the transport is named rather than defaulted. QUIC — the actual
/// default — is exercised against a real node in the integration suite, where there is a real
/// certificate to verify and a real endpoint to negotiate with; a QUIC stub here would test this
/// SDK against another mock rather than against the server.
///
/// The dictionary cache is off. It defaults to the user's cache directory, which is right for a
/// subscriber and wrong for a test suite: these would leave megabytes in a developer's home and,
/// worse, read one another's, since they run in parallel against a shared path. The tests that
/// exercise the cache point it at a scratch directory of their own.
fn config() -> Config {
    Config::new(SECRET.to_vec())
        .tcp()
        .without_dictionary_cache()
}

/// A scratch cache directory that removes itself.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "manka-shreds-sdk-dictpush-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Encodes a dictionary frame the way the server does.
fn dictionary_frame(id: u32, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    manka_shreds_sdk::Dictionary {
        id,
        bytes: bytes.to_vec(),
    }
    .write(&mut body);
    let mut frame = Vec::new();
    write_frame(&mut frame, FrameKind::Dictionary, 0, &body);
    frame
}

#[tokio::test]
async fn the_client_only_ever_offers_zstd() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let addr = stub(|mut socket, hello| async move {
        socket
            .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 0))
            .await
            .expect("write");
        let _ = tx.send(hello);
        // Held open so the client does not see a close before it is done.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    let client = Client::connect(addr, config()).await.expect("connects");
    assert_eq!(client.granted().0, StreamMask::TRANSACTIONS);
    assert_eq!(client.session_id(), 99);

    // Byte 6 is the codec mask. Only the zstd bit may be set: offering `none` is exactly how a
    // client would quietly negotiate its way out of compression.
    let hello = rx.await.expect("greeting");
    assert_eq!(hello[6], 1 << 2);
}

#[tokio::test]
async fn a_server_that_negotiates_no_compression_is_refused_by_the_client() {
    let addr = stub(|mut socket, _| async move {
        socket
            .write_all(&hello_ack(Codec::None, StreamMask::TRANSACTIONS, 0))
            .await
            .expect("write");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    let err = Client::connect(addr, config()).await.expect_err("refused");
    assert!(
        matches!(err, Error::CompressionRequired(Codec::None)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_server_rejecting_an_uncompressed_client_surfaces_as_a_server_error() {
    let detail = "this server requires a compressed stream; offer zstd or lz4 in the handshake";
    // Refused on the greeting, before any challenge — which is where a real node refuses, since it
    // decides on the codec before it proves anything.
    let addr = stub_refusing(move |mut socket, _| async move {
        socket
            .write_all(&error_frame(ErrorCode::BadRequest, detail))
            .await
            .expect("write");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    match Client::connect(addr, config()).await {
        Err(Error::Server { code, detail: got }) => {
            assert_eq!(code, ErrorCode::BadRequest);
            assert_eq!(got, detail);
        }
        other => panic!("expected a server error, got {other:?}"),
    }
}

#[tokio::test]
async fn transactions_arrive_decoded_decompressed_and_in_order() {
    let addr = stub(|mut socket, _| async move {
        socket
            .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 0))
            .await
            .expect("write");
        let tx = load("tx_simple.bin");
        for seq in 0..3u64 {
            let body = zstd::bulk::compress(&tx, 3).expect("compress");
            let mut frame = Vec::new();
            write_frame(&mut frame, FrameKind::Transaction, seq, &body);
            // Set the compressed flag, which `write_frame` leaves clear.
            frame[5] = 0b100 | Codec::Zstd as u8;
            socket.write_all(&frame).await.expect("write");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    let mut client = Client::connect(addr, config()).await.expect("connects");
    assert!(!client.dictionary_active());
    for expected in 0..3u64 {
        match client.next_event().await.expect("event") {
            Event::Transaction { tx, .. } => {
                assert_eq!(tx.slot(), 250_000_001);
                assert_eq!(tx.account_count(), 3);
                let _ = expected;
            }
            other => panic!("expected a transaction, got {other:?}"),
        }
    }
    assert!(
        client.decoded_bytes() > client.wire_bytes(),
        "compression should shrink the stream: {} decoded vs {} on the wire",
        client.decoded_bytes(),
        client.wire_bytes()
    );
}

#[tokio::test]
async fn the_negotiated_dictionary_is_used() {
    let dictionary = Arc::new(load("dictionary.bin"));
    let id = dictionary_id(&dictionary);
    let addr = stub(move |mut socket, hello| async move {
        // The offered id trails the fixed-width reference and nonce. Both are fixed width because
        // the greeting carries no credential to be variable.
        let at = 8 + 32 + 32;
        let offered = u32::from_le_bytes(hello[at..at + 4].try_into().expect("in range"));
        assert_eq!(offered, id, "the client should offer the dictionary it holds");

        socket
            .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, id))
            .await
            .expect("write");
        socket
            .write_all(&load("frame_zstd_dictionary.bin"))
            .await
            .expect("write");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    let mut client = Client::connect(addr, config().dictionary(Arc::new(load("dictionary.bin"))))
        .await
        .expect("connects");
    assert!(client.dictionary_active());
    match client.next_event().await.expect("event") {
        Event::Transaction { tx, .. } => assert_eq!(tx.slot(), 250_000_001),
        other => panic!("expected a transaction, got {other:?}"),
    }
}

/// A server holding no dictionary announces none, and the connection works without one.
#[tokio::test]
async fn a_server_without_a_dictionary_leaves_the_client_without_one() {
    let addr = stub(|mut socket, _| async move {
        socket
            .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 0))
            .await
            .expect("write");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    let client = Client::connect(addr, config()).await.expect("connects");
    assert!(!client.dictionary_active());
    assert!(!client.dictionary_was_sent());
}

/// A client that holds nothing is given the dictionary and uses it on this connection.
///
/// The whole point: no file to ship, no configuration, and the full ratio from the first message
/// rather than after somebody notices it was missing.
#[tokio::test]
async fn a_client_holding_nothing_is_given_the_dictionary() {
    let dictionary = load("dictionary.bin");
    let id = dictionary_id(&dictionary);
    let addr = stub(move |mut socket, hello| async move {
        // The client asked for it: the capability byte follows version, streams and codecs.
        assert_eq!(
            hello[7] & 1,
            1,
            "the client did not ask to be sent a dictionary"
        );
        // And offered nothing, since it holds nothing.
        let at = 8 + 32 + 32;
        let offered = u32::from_le_bytes(hello[at..at + 4].try_into().expect("in range"));
        assert_eq!(offered, 0);

        socket
            .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, id))
            .await
            .expect("write");
        socket
            .write_all(&dictionary_frame(id, &dictionary))
            .await
            .expect("write");
        socket
            .write_all(&load("frame_zstd_dictionary.bin"))
            .await
            .expect("write");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    let mut client = Client::connect(addr, config()).await.expect("connects");
    assert!(client.dictionary_active(), "the pushed dictionary was not applied");
    assert!(client.dictionary_was_sent());

    // And it decodes the body the server compressed with it, which is what the id stands for.
    match client.next_event().await.expect("event") {
        Event::Transaction { tx, .. } => assert_eq!(tx.slot(), 250_000_001),
        other => panic!("expected a transaction, got {other:?}"),
    }
}

/// A received dictionary is cached, and the next connection offers it instead of being sent it.
#[tokio::test]
async fn a_received_dictionary_is_cached_and_offered_next_time() {
    let dir = Dir::new("cached");
    let dictionary = load("dictionary.bin");
    let id = dictionary_id(&dictionary);

    // First connection: holds nothing, is sent it.
    let pushing = {
        let dictionary = dictionary.clone();
        stub(move |mut socket, _| async move {
            socket
                .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, id))
                .await
                .expect("write");
            socket
                .write_all(&dictionary_frame(id, &dictionary))
                .await
                .expect("write");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await
    };
    let first = Client::connect(pushing, config().dictionary_cache(dir.0.clone()))
        .await
        .expect("connects");
    assert!(first.dictionary_active() && first.dictionary_was_sent());
    drop(first);

    // Second connection: offers what it cached, and is sent nothing.
    let reusing = stub(move |mut socket, hello| async move {
        let at = 8 + 32 + 32;
        let offered = u32::from_le_bytes(hello[at..at + 4].try_into().expect("in range"));
        assert_eq!(offered, id, "the cached dictionary was not offered");
        socket
            .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, id))
            .await
            .expect("write");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;
    let second = Client::connect(reusing, config().dictionary_cache(dir.0.clone()))
        .await
        .expect("connects");
    assert!(second.dictionary_active(), "the cached dictionary was not applied");
    assert!(
        !second.dictionary_was_sent(),
        "the dictionary was fetched again despite being cached"
    );
}

/// A client whose dictionary is the wrong one is brought up to date.
///
/// "Outdated" is only ever "a different hash" — there is no ordering between dictionary ids — so
/// this is the same path as holding none, and has to work the same way.
#[tokio::test]
async fn a_client_holding_a_different_dictionary_is_brought_up_to_date() {
    let dictionary = load("dictionary.bin");
    let id = dictionary_id(&dictionary);
    let stale: Vec<u8> = load("dictionary.bin").into_iter().rev().collect();
    let stale_id = dictionary_id(&stale);
    assert_ne!(id, stale_id);

    let addr = {
        let dictionary = dictionary.clone();
        stub(move |mut socket, hello| async move {
            let at = 8 + 32 + 32;
            let offered = u32::from_le_bytes(hello[at..at + 4].try_into().expect("in range"));
            assert_eq!(offered, stale_id, "the client did not offer what it held");
            socket
                .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, id))
                .await
                .expect("write");
            socket
                .write_all(&dictionary_frame(id, &dictionary))
                .await
                .expect("write");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await
    };

    let client = Client::connect(addr, config().dictionary(Arc::new(stale)))
        .await
        .expect("connects");
    assert!(client.dictionary_active(), "a stale holder was left on plain zstd");
    assert!(client.dictionary_was_sent());
}

#[tokio::test]
async fn a_ping_is_answered_without_the_consumer_doing_anything() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let addr = stub(|mut socket, _| async move {
        socket
            .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 0))
            .await
            .expect("write");
        let mut ping = Vec::new();
        write_frame(&mut ping, FrameKind::Ping, 1, &[]);
        socket.write_all(&ping).await.expect("write");

        let mut buffer = vec![0u8; FRAME_HEADER_LEN];
        socket.read_exact(&mut buffer).await.expect("read pong");
        let _ = tx.send(read_frame_header(&buffer).expect("header").kind);
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    let mut client = Client::connect(addr, config()).await.expect("connects");
    assert!(matches!(client.next_event().await.expect("event"), Event::Ping));
    assert_eq!(rx.await.expect("pong"), FrameKind::Pong);
}

#[tokio::test]
async fn a_lag_report_is_counted_as_a_gap_and_resets_the_expected_sequence() {
    let addr = stub(|mut socket, _| async move {
        socket
            .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 0))
            .await
            .expect("write");
        let mut body = Vec::new();
        body.extend_from_slice(&500u64.to_le_bytes());
        body.extend_from_slice(&1_000u64.to_le_bytes());
        let mut frame = Vec::new();
        write_frame(&mut frame, FrameKind::Lag, 3, &body);
        socket.write_all(&frame).await.expect("write");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    let mut client = Client::connect(addr, config()).await.expect("connects");
    match client.next_event().await.expect("event") {
        Event::Lag(lag) => {
            assert_eq!(lag.dropped, 500);
            assert_eq!(lag.resume_seq, 1_000);
        }
        other => panic!("expected a lag report, got {other:?}"),
    }
    assert_eq!(client.gaps(), 500);
}

#[tokio::test]
async fn an_unknown_frame_kind_is_delivered_rather_than_killing_the_connection() {
    let addr = stub(|mut socket, _| async move {
        socket
            .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 0))
            .await
            .expect("write");
        let mut frame = Vec::new();
        // A kind no build recognises, written by hand because the enum cannot express it.
        frame.extend_from_slice(&3u32.to_le_bytes());
        frame.push(200);
        frame.push(0);
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&1u64.to_le_bytes());
        frame.extend_from_slice(&[1, 2, 3]);
        socket.write_all(&frame).await.expect("write");

        let mut pong = Vec::new();
        write_frame(&mut pong, FrameKind::Pong, 2, &[]);
        socket.write_all(&pong).await.expect("write");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    let mut client = Client::connect(addr, config()).await.expect("connects");
    match client.next_event().await.expect("event") {
        Event::Other { kind, payload } => {
            assert_eq!(kind, 200);
            assert_eq!(payload, &[1, 2, 3]);
        }
        other => panic!("expected an unknown frame, got {other:?}"),
    }
    assert!(matches!(client.next_event().await.expect("event"), Event::Pong));
}

#[tokio::test]
async fn a_frame_split_across_reads_is_reassembled() {
    let addr = stub(|mut socket, _| async move {
        socket
            .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 0))
            .await
            .expect("write");
        let mut frame = Vec::new();
        write_frame(&mut frame, FrameKind::Transaction, 0, &load("tx_simple.bin"));
        // One byte at a time is the worst case a stream socket can produce.
        for byte in frame {
            socket.write_all(&[byte]).await.expect("write");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    let mut client = Client::connect(addr, config()).await.expect("connects");
    match client.next_event().await.expect("event") {
        Event::Transaction { tx, .. } => assert_eq!(tx.slot(), 250_000_001),
        other => panic!("expected a transaction, got {other:?}"),
    }
}

#[tokio::test]
async fn a_server_error_mid_stream_surfaces_from_the_event_loop() {
    let addr = stub(|mut socket, _| async move {
        socket
            .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 0))
            .await
            .expect("write");
        socket
            .write_all(&error_frame(ErrorCode::TooSlow, "subscriber fell too far behind"))
            .await
            .expect("write");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    let mut client = Client::connect(addr, config()).await.expect("connects");
    match client.next_event().await {
        Err(Error::Server { code, .. }) => assert_eq!(code, ErrorCode::TooSlow),
        other => panic!("expected a server error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_closed_connection_is_reported_rather_than_hanging() {
    let addr = stub(|mut socket, _| async move {
        socket
            .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 0))
            .await
            .expect("write");
        drop(socket);
    })
    .await;

    let mut client = Client::connect(addr, config()).await.expect("connects");
    assert!(matches!(client.next_event().await, Err(Error::Closed)));
}

/// A peer that cannot prove it holds the key is abandoned, and nothing is sent to it.
///
/// This is what replaces certificate pinning. Anything that terminates the TLS in front of a node —
/// or simply is not the node — cannot produce the server proof, because it does not have the key.
/// The client stops there, before sending a proof of its own, so the impostor learns nothing it
/// could relay onwards.
#[tokio::test]
async fn a_server_that_cannot_prove_the_key_is_refused() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let addr = stub_refusing(move |mut socket, hello| async move {
        let mut key_ref = [0u8; 32];
        key_ref.copy_from_slice(&hello[8..40]);
        let mut client_nonce = [0u8; 32];
        client_nonce.copy_from_slice(&hello[40..72]);
        let transcript = Transcript {
            key_ref: KeyRef(key_ref),
            client_nonce,
            server_nonce: [42u8; 32],
            binding: ChannelBinding::NONE,
        };

        // A proof over the right transcript, made with the wrong key — exactly what an impostor
        // that watched a previous connection could produce.
        let mut body = Vec::new();
        body.extend_from_slice(&transcript.server_nonce);
        body.extend_from_slice(&transcript.server_proof(b"not the key").0);
        let mut frame = Vec::new();
        write_frame(&mut frame, FrameKind::Challenge, 0, &body);
        socket.write_all(&frame).await.expect("challenge");

        // Whatever the client does next, record it. It must not be a proof.
        let mut buffer = Vec::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            socket.read_buf(&mut buffer),
        )
        .await;
        let _ = tx.send(matches!(read, Ok(Ok(n)) if n > 0));
    })
    .await;

    let error = Client::connect(addr, config())
        .await
        .expect_err("a server that cannot prove the key must be refused");
    assert!(
        matches!(&error, Error::Handshake(message) if message.contains("did not prove")),
        "{error:?}"
    );
    assert!(
        !rx.await.expect("the stub reported"),
        "the client sent something after an unprovable challenge; it must reveal nothing"
    );
}

/// A proof from one exchange is worthless in another.
///
/// The nonces are what make that true. Without them a single captured handshake would let anyone
/// impersonate the node to that client forever.
#[tokio::test]
async fn a_replayed_server_proof_is_refused() {
    let addr = stub_refusing(move |mut socket, hello| async move {
        let mut key_ref = [0u8; 32];
        key_ref.copy_from_slice(&hello[8..40]);
        // A proof over *this* client's key and reference, but somebody else's nonces — what a
        // recording of an earlier connection would give an attacker.
        let stale = Transcript {
            key_ref: KeyRef(key_ref),
            client_nonce: [0xAAu8; 32],
            server_nonce: [0xBBu8; 32],
            binding: ChannelBinding::NONE,
        };
        let mut body = Vec::new();
        body.extend_from_slice(&[0xBBu8; 32]);
        body.extend_from_slice(&stale.server_proof(SECRET).0);
        let mut frame = Vec::new();
        write_frame(&mut frame, FrameKind::Challenge, 0, &body);
        socket.write_all(&frame).await.expect("challenge");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    })
    .await;

    let error = Client::connect(addr, config())
        .await
        .expect_err("a replayed proof must be refused");
    assert!(
        matches!(&error, Error::Handshake(message) if message.contains("did not prove")),
        "{error:?}"
    );
}

/// What a server that is wrong, rather than merely absent, does after the acknowledgement.
///
/// The checks around the pushed dictionary all guard against a peer that lies — a compromised node,
/// a proxy rewriting frames, a build whose dictionary and id came apart. The stub here proves the
/// key honestly, so what these establish is that this client keeps checking *after* the peer is
/// authenticated: possession of the key buys the right to stream, not the right to be believed
/// about what it is sending.
mod hostile_dictionary {
    use super::*;

    /// Connects and returns what went wrong.
    async fn expect_failure(addr: std::net::SocketAddr) -> manka_shreds_sdk::Error {
        Client::connect(addr, config())
            .await
            .expect_err("this client accepted something it should have refused")
    }

    /// A server that announces a dictionary and never sends it does not hang the client.
    ///
    /// Silence is the failure mode a timeout exists for. Without one this client would sit in
    /// `connect` indefinitely, which from the outside looks like a slow network rather than a peer
    /// that will never answer.
    #[tokio::test]
    async fn an_announced_dictionary_that_never_arrives_times_out() {
        let addr = stub(|mut socket, _| async move {
            socket
                .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 12_345))
                .await
                .expect("write");
            // Held open, saying nothing.
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        })
        .await;

        let mut config = config();
        config.connect_timeout = std::time::Duration::from_secs(2);
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            Client::connect(addr, config),
        )
        .await
        .expect("the client waited past its own handshake timeout")
        .expect_err("a silent server was accepted");
        assert!(
            format!("{error}").contains("did not send it"),
            "unhelpful error: {error}"
        );
    }

    /// Bytes that do not hash to the announced id are refused.
    ///
    /// The check that matters most. Accepting them would leave this client decompressing against
    /// something other than what the node compresses with, and every frame afterwards would fail
    /// for a reason nothing on the wire explains.
    #[tokio::test]
    async fn a_dictionary_whose_bytes_do_not_match_is_refused() {
        let addr = stub(|mut socket, _| async move {
            socket
                .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 12_345))
                .await
                .expect("write");
            socket
                .write_all(&dictionary_frame(12_345, b"not the dictionary"))
                .await
                .expect("write");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await;

        let error = expect_failure(addr).await;
        assert!(
            format!("{error}").contains("not the one it announced"),
            "unhelpful error: {error}"
        );
    }

    /// So is one whose frame names a different id than the acknowledgement did.
    #[tokio::test]
    async fn a_dictionary_under_a_different_id_is_refused() {
        let dictionary = load("dictionary.bin");
        let id = dictionary_id(&dictionary);
        let addr = stub(move |mut socket, _| async move {
            socket
                .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, id))
                .await
                .expect("write");
            // The right bytes, under a label that is not what the ack promised.
            socket
                .write_all(&dictionary_frame(id.wrapping_add(1), &dictionary))
                .await
                .expect("write");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await;

        let error = expect_failure(addr).await;
        assert!(
            format!("{error}").contains("not the one it announced"),
            "unhelpful error: {error}"
        );
    }

    /// A frame that is not a dictionary, where the dictionary belongs, ends the handshake.
    #[tokio::test]
    async fn something_other_than_a_dictionary_ends_the_handshake() {
        let addr = stub(|mut socket, _| async move {
            socket
                .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 12_345))
                .await
                .expect("write");
            let mut pong = Vec::new();
            write_frame(&mut pong, FrameKind::Pong, 0, &[]);
            socket.write_all(&pong).await.expect("write");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await;

        let error = expect_failure(addr).await;
        assert!(
            format!("{error}").contains("announced dictionary"),
            "unhelpful error: {error}"
        );
    }

    /// A refusal arriving where the dictionary should be is reported as the server's, not as noise.
    ///
    /// A node can decide to close between the acknowledgement and the dictionary — a key revoked in
    /// that instant, a connection limit reached. The subscriber should be told what the server said,
    /// not "expected a dictionary".
    #[tokio::test]
    async fn an_error_instead_of_the_dictionary_is_reported_as_the_servers() {
        let addr = stub(|mut socket, _| async move {
            socket
                .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 12_345))
                .await
                .expect("write");
            socket
                .write_all(&error_frame(ErrorCode::Forbidden, "key revoked"))
                .await
                .expect("write");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await;

        match expect_failure(addr).await {
            manka_shreds_sdk::Error::Server { code, detail } => {
                assert_eq!(code, ErrorCode::Forbidden);
                assert_eq!(detail, "key revoked");
            }
            other => panic!("the server's own refusal was reported as {other}"),
        }
    }

    /// A dictionary larger than this client accepts is refused on its declared length.
    ///
    /// Refused before the body is taken, so the number a peer invented never decides how much this
    /// side allocates. Otherwise a twelve-byte message would be an instruction to reserve as much
    /// memory as the length field can express.
    #[tokio::test]
    async fn a_dictionary_past_the_limit_is_refused_on_its_length() {
        let addr = stub(|mut socket, _| async move {
            socket
                .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 12_345))
                .await
                .expect("write");
            // A declared length past the limit, with no body behind it.
            let mut body = Vec::new();
            body.extend_from_slice(&12_345u32.to_le_bytes());
            body.extend_from_slice(
                &((manka_shreds_sdk::MAX_DICTIONARY_BYTES + 1) as u32).to_le_bytes(),
            );
            let mut frame = Vec::new();
            write_frame(&mut frame, FrameKind::Dictionary, 0, &body);
            socket.write_all(&frame).await.expect("write");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await;

        let error = expect_failure(addr).await;
        assert!(
            format!("{error}").contains("limit"),
            "unhelpful error: {error}"
        );
    }

    /// An empty dictionary is refused rather than installed as one.
    ///
    /// Zero-length bytes hash to the "no dictionary" id, so they can never match a non-zero
    /// announcement. Worth pinning: a decoder built from an empty dictionary is not an error at
    /// construction, so the failure would otherwise surface at the first frame.
    #[tokio::test]
    async fn an_empty_dictionary_is_refused() {
        let addr = stub(|mut socket, _| async move {
            socket
                .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, 12_345))
                .await
                .expect("write");
            socket
                .write_all(&dictionary_frame(12_345, b""))
                .await
                .expect("write");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await;

        let error = expect_failure(addr).await;
        assert!(
            format!("{error}").contains("not the one it announced"),
            "unhelpful error: {error}"
        );
    }

    /// A dictionary is never accepted before the server has proved it holds the key.
    ///
    /// Otherwise anyone able to answer a TCP connect could hand this client a megabyte, and the
    /// handshake would be an amplifier: a greeting in, a megabyte out, at whatever rate an attacker
    /// chooses. `stub_refusing` never proves anything, so nothing it sends may be believed.
    #[tokio::test]
    async fn a_dictionary_before_the_proof_is_not_accepted() {
        let dictionary = load("dictionary.bin");
        let id = dictionary_id(&dictionary);
        let addr = stub_refusing(move |mut socket, _| async move {
            // Straight to the ack and the dictionary, skipping the challenge entirely.
            socket
                .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, id))
                .await
                .expect("write");
            socket
                .write_all(&dictionary_frame(id, &dictionary))
                .await
                .expect("write");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await;

        let error = expect_failure(addr).await;
        let text = format!("{error}");
        assert!(
            !text.contains("dictionary"),
            "the client got as far as the dictionary with an unproved peer: {text}"
        );
    }

    /// A second dictionary, once the stream is running, is refused rather than ignored.
    ///
    /// "The dictionary does not change during a run" is what a subscriber relies on to decode
    /// anything at all. A server sending another means the next frame is compressed with something
    /// this side is not decoding with — so it is named here, rather than surfacing as corruption
    /// several frames later with nothing pointing at the cause.
    #[tokio::test]
    async fn a_second_dictionary_mid_stream_is_refused() {
        let dictionary = load("dictionary.bin");
        let id = dictionary_id(&dictionary);
        let addr = stub(move |mut socket, _| async move {
            socket
                .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, id))
                .await
                .expect("write");
            socket
                .write_all(&dictionary_frame(id, &dictionary))
                .await
                .expect("write");
            // And again, once the connection is up.
            socket
                .write_all(&dictionary_frame(id, &dictionary))
                .await
                .expect("write");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await;

        let mut client = Client::connect(addr, config()).await.expect("connects");
        assert!(client.dictionary_active());

        let error = loop {
            match client.next_event().await {
                Ok(_) => continue,
                Err(error) => break error,
            }
        };
        assert!(
            format!("{error}").contains("mid-stream"),
            "a second dictionary was tolerated: {error}"
        );
    }
}

/// Edge cases around how the dictionary actually reaches this client.
///
/// A real dictionary is about a megabyte, so it is the one control message that *always* spans many
/// reads. Everything else in the handshake fits in a single packet, which means the reassembly path
/// is exercised here or nowhere.
mod dictionary_delivery {
    use super::*;

    /// A dictionary split across many small writes is reassembled.
    ///
    /// Byte-at-a-time is the strongest form of the fragmentation a megabyte guarantees: if any part
    /// of the reader assumed a whole frame per read, this is where it shows.
    #[tokio::test]
    async fn a_dictionary_split_across_many_reads_is_reassembled() {
        let dictionary = load("dictionary.bin");
        let id = dictionary_id(&dictionary);
        let addr = stub(move |mut socket, _| async move {
            let mut bytes = hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, id);
            bytes.extend_from_slice(&dictionary_frame(id, &dictionary));
            bytes.extend_from_slice(&load("frame_zstd_dictionary.bin"));

            // Small, uneven chunks, including ones that split the length prefix itself.
            let mut at = 0usize;
            while at < bytes.len() {
                let size = (at % 7) + 1;
                let end = (at + size).min(bytes.len());
                if socket.write_all(&bytes[at..end]).await.is_err() {
                    return;
                }
                at = end;
                tokio::task::yield_now().await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await;

        let mut client = Client::connect(addr, config()).await.expect("connects");
        assert!(
            client.dictionary_active(),
            "a fragmented dictionary was not reassembled"
        );
        match client.next_event().await.expect("event") {
            Event::Transaction { tx, .. } => assert_eq!(tx.slot(), 250_000_001),
            other => panic!("expected a transaction, got {other:?}"),
        }
    }

    /// And when the acknowledgement, the dictionary and the first data frame arrive together.
    ///
    /// The opposite fragmentation, and the one that catches a reader which waits for another read
    /// that never comes, or which discards what rode in behind the dictionary. A dropped data frame
    /// here would look like a stalled stream rather than a parsing fault.
    #[tokio::test]
    async fn an_acknowledgement_dictionary_and_data_frame_in_one_write_all_land() {
        let dictionary = load("dictionary.bin");
        let id = dictionary_id(&dictionary);
        let addr = stub(move |mut socket, _| async move {
            let mut bytes = hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, id);
            bytes.extend_from_slice(&dictionary_frame(id, &dictionary));
            bytes.extend_from_slice(&load("frame_zstd_dictionary.bin"));
            let _ = socket.write_all(&bytes).await;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await;

        let mut client = Client::connect(addr, config()).await.expect("connects");
        assert!(client.dictionary_active());
        // The data frame rode in behind the dictionary and must not have been dropped with it.
        match client.next_event().await.expect("event") {
            Event::Transaction { tx, .. } => assert_eq!(tx.slot(), 250_000_001),
            other => panic!("expected a transaction, got {other:?}"),
        }
    }

    /// A dictionary id with the high bit set is handled as unsigned throughout.
    ///
    /// Half of all possible ids exceed 2^31. Anything that compared or formatted one through a
    /// signed path would work for half the dictionaries in existence and fail for the other half —
    /// the kind of defect that passes every test written against a single fixture.
    #[tokio::test]
    async fn a_dictionary_id_with_the_high_bit_set_is_unsigned() {
        let high = 0xdead_beefu32;
        assert!(high > 0x7fff_ffff, "the fixture must exercise the high bit");

        let addr = stub(move |mut socket, _| async move {
            socket
                .write_all(&hello_ack(Codec::Zstd, StreamMask::TRANSACTIONS, high))
                .await
                .expect("write");
            socket
                .write_all(&dictionary_frame(high, b"not the dictionary"))
                .await
                .expect("write");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await;

        let error = Client::connect(addr, config())
            .await
            .expect_err("bytes that do not match were accepted");
        let text = format!("{error}");
        assert!(text.contains("not the one it announced"), "{text}");
        assert!(
            text.contains("0xdeadbeef"),
            "the id was not reported as the unsigned value it is: {text}"
        );
    }

    /// A hostile node cannot fill the disk by handing out endless dictionaries.
    ///
    /// Every distinct dictionary a node sends is cached, so without a bound a node could write as
    /// much as it liked into a subscriber's filesystem — a megabyte per connection, for as long as
    /// the subscriber kept reconnecting.
    #[test]
    fn the_cache_stays_bounded_against_a_node_that_keeps_changing_its_dictionary() {
        let dir = Dir::new("flood");
        let cache = manka_shreds_sdk::DictionaryCache::new(dir.0.clone());
        let base = load("dictionary.bin");
        for round in 0..24u8 {
            // A distinct dictionary each time, as a node changing its own would produce.
            let mut bytes = base.clone();
            bytes.push(round);
            assert!(cache.store(dictionary_id(&bytes), &bytes));
        }
        let held = std::fs::read_dir(&dir.0)
            .expect("the cache directory")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".dict"))
            .count();
        assert!(held <= 8, "the cache holds {held} dictionaries, past its own bound");
    }

    /// A cache entry planted by another local process is used, and that is the trust boundary.
    ///
    /// The cache is content-addressed by a 32-bit hash, so bytes crafted to collide with an id this
    /// client would otherwise fetch are indistinguishable from the real thing. Anyone who can write
    /// there can do that — and can also edit the binary, so the boundary is the filesystem, not this
    /// check.
    ///
    /// What the check *does* buy is that an entry which does not hash to its own name is refused,
    /// which is the accident — a truncated write, a half-copied file, a stale name — rather than the
    /// attack. This pins that behaviour so the boundary stays where it is documented to be.
    #[test]
    fn a_cache_entry_that_does_not_hash_to_its_name_is_never_offered() {
        let dir = Dir::new("planted");
        std::fs::create_dir_all(&dir.0).expect("the directory");
        let cache = manka_shreds_sdk::DictionaryCache::new(dir.0.clone());

        // A file named for one dictionary, holding another's bytes.
        let real = load("dictionary.bin");
        let claimed = dictionary_id(&real);
        std::fs::write(
            dir.0.join(format!("{claimed:08x}.dict")),
            b"bytes that are not that dictionary",
        )
        .expect("planting");

        assert!(cache.load(claimed).is_none(), "a planted entry was offered");
        assert!(cache.newest().is_none());
        assert!(
            !dir.0.join(format!("{claimed:08x}.dict")).exists(),
            "the planted entry was left to be found again next run"
        );
    }
}

/// What a peer can make this client hold before it has proved anything.
///
/// The `len` in every frame header belongs to the sender, and it is what this side reserves
/// against. During the handshake the sender is an address the caller typed and nothing more: it has
/// produced no proof, and a challenge or a refusal is the first thing it says. Bounded only by what
/// a frame may be, either of them costs sixteen megabytes for the price of a header.
///
/// Each of these sends a header and no body on purpose. A client that refuses on the number never
/// waits; one that refuses after reading would sit here until the handshake timeout, which is what
/// the deadline around every connect below is there to catch.
mod handshake_ceiling {
    use super::*;

    /// Sends `frame` as a bare header declaring `len` bytes that will never follow.
    async fn announcing(kind: FrameKind, len: u32) -> std::net::SocketAddr {
        stub_refusing(move |mut socket, _| async move {
            let mut header = Vec::new();
            write_frame(&mut header, kind, 0, &[]);
            header.truncate(FRAME_HEADER_LEN);
            header[0..4].copy_from_slice(&len.to_le_bytes());
            let _ = socket.write_all(&header).await;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        })
        .await
    }

    #[tokio::test]
    async fn a_refusal_cannot_cost_a_frames_worth_of_memory() {
        let addr = announcing(FrameKind::Error, manka_shreds_sdk::protocol::MAX_FRAME_PAYLOAD as u32).await;
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            Client::connect(addr, config()),
        )
        .await
        .expect("the client waited for bytes that were never coming")
        .expect_err("an enormous refusal was accepted");
        assert!(
            error
                .to_string()
                .contains(&manka_shreds_sdk::protocol::MAX_HANDSHAKE_BYTES.to_string()),
            "the error does not say what the limit was: {error}"
        );
    }

    #[tokio::test]
    async fn a_challenge_cannot_cost_a_frames_worth_of_memory() {
        let addr = announcing(FrameKind::Challenge, manka_shreds_sdk::protocol::MAX_FRAME_PAYLOAD as u32).await;
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            Client::connect(addr, config()),
        )
        .await
        .expect("the client waited for bytes that were never coming")
        .expect_err("an enormous challenge was accepted");
        assert!(
            error.to_string().contains("Challenge"),
            "the error does not name the frame: {error}"
        );
    }

    /// The dictionary is the exception, and has to be: it arrives during the handshake and is
    /// legitimately megabytes. It is also the one frame here that comes after the server has proved
    /// itself, which is why a larger allowance is affordable at all.
    #[tokio::test]
    async fn a_dictionary_is_allowed_to_be_larger_than_a_control_message() {
        let bytes = vec![0x5au8; manka_shreds_sdk::protocol::MAX_HANDSHAKE_BYTES * 2];
        let id = dictionary_id(&bytes);
        let addr = stub(move |mut socket, _| async move {
            let mut out = hello_ack(Codec::Zstd, StreamMask::ALL.0, id);
            out.extend_from_slice(&dictionary_frame(id, &bytes));
            let _ = socket.write_all(&out).await;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        })
        .await;

        let client = Client::connect(addr, config())
            .await
            .expect("a dictionary above the control-message ceiling was refused");
        assert!(client.dictionary_active());
        assert!(client.dictionary_was_sent());
    }

    /// After the handshake the ceiling is the subscriber's own, and it applies to the frame rather
    /// than only to what a compressed body expands into — otherwise the setting does nothing at all
    /// against one that arrives uncompressed, which is the case someone lowering it is bounding.
    #[tokio::test]
    async fn a_frame_past_the_configured_size_is_refused_before_it_is_read() {
        let addr = stub(|mut socket, _| async move {
            let mut out = hello_ack(Codec::Zstd, StreamMask::ALL.0, 0);
            let mut header = Vec::new();
            write_frame(&mut header, FrameKind::Transaction, 0, &[]);
            header.truncate(FRAME_HEADER_LEN);
            header[0..4].copy_from_slice(&(manka_shreds_sdk::protocol::MAX_FRAME_PAYLOAD as u32).to_le_bytes());
            out.extend_from_slice(&header);
            let _ = socket.write_all(&out).await;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        })
        .await;

        let mut client = Client::connect(
            addr,
            Config {
                max_message_bytes: 64 << 10,
                ..config()
            },
        )
        .await
        .expect("the handshake itself was honest");

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.next_event(),
        )
        .await
        .expect("the client waited for a body that was never coming")
        .expect_err("an oversized frame was accepted");
        assert!(
            error.to_string().contains(&(64 * 1024).to_string()),
            "the error does not say what the limit was: {error}"
        );
    }
}
