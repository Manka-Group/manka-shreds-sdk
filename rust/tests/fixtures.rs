//! Decodes the golden fixtures produced by the server's own encoders.
//!
//! This SDK vendors its own decoders rather than depending on the server crates, so nothing but
//! this file stops the two from drifting apart. Every assertion here is a byte layout the server
//! actually produced; if a layout changes, these fail rather than the SDK silently misreading a
//! field.
//!
//! Regenerate with `cargo run --example fixtures -- ../manka-shreds-sdk/fixtures` in the manka-shreds
//! repository.

use std::{path::PathBuf, sync::Arc};

use manka_shreds_sdk::{
    Capabilities, Dictionary, Duplicate, Entry, ErrorCode, FrameKind, MAX_DICTIONARY_BYTES,
    SlotEnd, SlotStart, StreamMask, Transaction, Verification, dictionary_id,
    protocol::{
        CODEC_BIT_ZSTD, Codec, ErrorMessage, FRAME_HEADER_LEN, FilterAck, Hello, HelloAck, Lag,
        PROTOCOL_VERSION, read_frame_header,
    },
    handshake::KeyRef,
    transaction::MESSAGE_VERSION_LEGACY,
};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures")
}

fn load(name: &str) -> Vec<u8> {
    std::fs::read(dir().join(name)).unwrap_or_else(|err| panic!("reading {name}: {err}"))
}

#[test]
fn a_hello_encodes_to_exactly_the_bytes_the_server_expects() {
    let mut actual = Vec::new();
    Hello {
        streams: StreamMask(StreamMask::TRANSACTIONS | StreamMask::SLOT_EVENTS),
        codecs: CODEC_BIT_ZSTD,
        key_ref: KeyRef::of(b"fixture-key"),
        client_nonce: [0u8; 32],
        capabilities: Capabilities(Capabilities::ACCEPTS_DICTIONARY),
        filter: None,
        dictionary_id: 0x1234_5678,
    }
    .write(&mut actual);
    assert_eq!(actual, load("hello.bin"));
}

#[test]
fn a_hello_ack_decodes() {
    let ack = HelloAck::read(&load("hello_ack.bin")).expect("decodes");
    assert_eq!(ack.protocol_version, PROTOCOL_VERSION);
    assert_eq!(ack.granted.0, StreamMask::TRANSACTIONS);
    assert_eq!(ack.session_id, 0x0102_0304_0506_0708);
    assert_eq!(ack.codec, Codec::Zstd);
    assert_eq!(ack.keepalive_ms, 15_000);
    assert_eq!(ack.dictionary_id, 0x1234_5678);
}

#[test]
fn an_error_decodes_including_the_compression_refusal() {
    let error = ErrorMessage::read(&load("error.bin")).expect("decodes");
    assert_eq!(error.code, ErrorCode::BadRequest);
    assert_eq!(
        error.detail,
        "this server requires a compressed stream; offer zstd or lz4 in the handshake"
    );
}

#[test]
fn a_lag_report_decodes() {
    let lag = Lag::read(&load("lag.bin")).expect("decodes");
    assert_eq!(lag.dropped, 4_096);
    assert_eq!(lag.resume_seq, 1_000_000);
}

#[test]
fn a_filter_ack_decodes() {
    let ack = FilterAck::read(&load("filter_ack.bin")).expect("decodes");
    assert!(!ack.accepted);
    assert_eq!(ack.cost, 4_321);
    assert_eq!(ack.detail, "filter exceeds the per-connection cost budget");
}

#[test]
fn a_slot_start_decodes_with_and_without_its_optional_fields() {
    let bytes = load("slot_start.bin");
    let start = SlotStart::read(&bytes).expect("decodes");
    assert_eq!(start.slot, 250_000_001);
    assert_eq!(start.parent_slot, Some(250_000_000));
    assert_eq!(start.leader.map(|key| key[0]), Some(0x77));
    assert_eq!(start.rx_ts_ns, 1_700_000_000_000);
    assert_eq!(start.source, 3);
    assert_eq!(start.shred_version, 50_093);

    let bare_bytes = load("slot_start_bare.bin");
    let bare = SlotStart::read(&bare_bytes).expect("decodes");
    assert_eq!(bare.slot, 250_000_002);
    assert_eq!(bare.parent_slot, None);
    assert!(bare.leader.is_none());
}

#[test]
fn a_slot_end_decodes() {
    let end = SlotEnd::read(&load("slot_end.bin")).expect("decodes");
    assert_eq!(end.slot, 250_000_001);
    assert_eq!(end.parent_slot, 250_000_000);
    assert_eq!(end.data_shreds, 1_337);
    assert_eq!(end.fec_sets, 42);
    assert_eq!(end.recovered_sets, 7);
    assert_eq!(end.missing_shreds, 2);
    assert_eq!(end.end_ts_ns, 1_700_000_400_000);
    assert!(end.complete);
}

#[test]
fn an_entry_decodes_including_its_verification_verdict() {
    let bytes = load("entry.bin");
    let entry = Entry::read(&bytes).expect("decodes");
    assert_eq!(entry.slot, 250_000_001);
    assert_eq!(entry.parent_slot, 250_000_000);
    assert_eq!(entry.rx_ts_ns, 1_700_000_000_500);
    assert_eq!(entry.num_hashes, 64);
    assert_eq!(entry.tx_count, 5);
    assert_eq!(entry.hash[0], 0x99);
    assert_eq!(entry.fec_set_index, 96);
    assert_eq!(entry.entry_index, 12);
    assert_eq!(entry.verification, Verification::StaleSchedule);
}

#[test]
fn a_duplicate_report_decodes_both_conflicting_signatures() {
    let bytes = load("duplicate.bin");
    let dup = Duplicate::read(&bytes).expect("decodes");
    assert_eq!(dup.slot, 250_000_003);
    assert_eq!(dup.index, 17);
    assert_eq!(dup.first_source, 1);
    assert_eq!(dup.second_source, 2);
    assert_eq!(dup.detected_ns, 1_700_000_000_900);
    assert!(dup.is_data);
    assert_eq!(dup.first_signature[0], 0xaa);
    assert_eq!(dup.second_signature[0], 0xbb);
}

#[test]
fn a_transaction_decodes_every_header_field_and_section() {
    let bytes = load("tx_simple.bin");
    let tx = Transaction::read(&bytes).expect("decodes");
    assert_eq!(tx.slot(), 250_000_001);
    assert_eq!(tx.parent_slot(), 250_000_000);
    assert_eq!(tx.rx_ts_ns(), 1_700_000_000_000);
    assert_eq!(tx.emit_ts_ns(), 1_700_000_003_500);
    assert_eq!(tx.pipeline_ns(), 3_500);
    assert_eq!(tx.leader().map(|key| key[0]), Some(0x77));
    assert_eq!(tx.fec_set_index(), 96);
    assert_eq!(tx.entry_index(), 12);
    assert_eq!(tx.tx_index(), 3);
    assert_eq!(tx.source_id(), 3);
    assert!(!tx.is_vote());
    assert!(!tx.recovered());
    assert_eq!(tx.verification(), Verification::Verified);
    assert_eq!(tx.account_count(), 3);
    assert_eq!(tx.instruction_count(), 1);
    assert_eq!(tx.signature_count(), 1);
    assert_eq!(tx.message_version(), 0);
    assert_eq!(tx.lookup_count(), 0);
    assert_eq!(tx.required_signatures(), 1);
    assert_eq!(tx.readonly_signed(), 0);
    assert_eq!(tx.readonly_unsigned(), 1);

    assert_eq!(tx.signature().map(|sig| sig[0]), Some(0x11));
    assert_eq!(tx.signatures().len(), 1);
    assert_eq!(tx.recent_blockhash()[0], 0x22);

    // Account key `i` was filled with byte `i`, so this proves both the section offset and the
    // per-key stride.
    assert_eq!(tx.account_keys().len(), 3);
    for (index, key) in tx.account_keys().enumerate() {
        assert_eq!(key[0], index as u8, "account key {index}");
    }

    let ix = tx.instruction(0).expect("one instruction");
    assert_eq!(ix.program_id_index, 0);
    assert_eq!(ix.accounts, &[0, 1]);
    assert_eq!(ix.data, &[1, 2, 3, 4]);
    assert!(tx.raw_tx().is_none());
    assert_eq!(tx.lookups().len(), 0);
}

#[test]
fn a_transaction_with_every_optional_section_decodes() {
    let bytes = load("tx_full.bin");
    let tx = Transaction::read(&bytes).expect("decodes");
    assert_eq!(tx.account_count(), 6);
    assert!(tx.is_vote());
    assert!(tx.recovered());
    assert_eq!(tx.lookup_count(), 2);
    assert_eq!(tx.instruction(0).expect("instruction").data.len(), 40);

    let lookups: Vec<_> = tx.lookups().collect();
    assert_eq!(lookups.len(), 2);
    assert_eq!(lookups[0].account_key[0], 0xa0);
    assert_eq!(lookups[1].account_key[0], 0xa1);
    assert_eq!(lookups[0].writable_indexes, &[1]);
    assert_eq!(lookups[0].readonly_indexes, &[2]);

    let raw = tx.raw_tx().expect("raw bytes were requested");
    assert_eq!(raw.len(), 413);
}

#[test]
fn a_legacy_message_decodes_with_the_sentinel_version() {
    let bytes = load("tx_legacy.bin");
    let tx = Transaction::read(&bytes).expect("decodes");
    assert_eq!(tx.message_version(), MESSAGE_VERSION_LEGACY);
    assert_eq!(tx.account_count(), 2);
    assert!(tx.leader().is_none());
    assert_eq!(tx.verification(), Verification::UnknownLeader);
    let ix = tx.instruction(0).expect("one instruction");
    assert_eq!(ix.program_id_index, 1);
    assert_eq!(ix.data, &[9, 8, 7]);
}

#[test]
fn a_plain_frame_decodes_and_carries_a_whole_transaction() {
    let frame = load("frame_plain.bin");
    let header = read_frame_header(&frame).expect("header");
    assert_eq!(header.kind, FrameKind::Transaction);
    assert_eq!(header.seq, 7);
    assert!(!header.compressed);
    let tx = Transaction::read(&frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + header.len])
        .expect("decodes");
    assert_eq!(tx.slot(), 250_000_001);
}

#[test]
fn a_zstd_frame_decompresses() {
    let frame = load("frame_zstd.bin");
    let header = read_frame_header(&frame).expect("header");
    assert!(header.compressed);
    assert_eq!(header.codec, Codec::Zstd);
    let body = zstd::bulk::decompress(
        &frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + header.len],
        1 << 20,
    )
    .expect("decompresses");
    assert_eq!(body, load("tx_simple.bin"));
}

#[test]
fn a_dictionary_frame_decompresses_and_the_id_matches_the_server_hash() {
    let dictionary = load("dictionary.bin");
    assert_eq!(dictionary_id(&dictionary), 3_044_610_556);

    let frame = load("frame_zstd_dictionary.bin");
    let header = read_frame_header(&frame).expect("header");
    let prepared = zstd::dict::DecoderDictionary::copy(&dictionary);
    let body = zstd::bulk::Decompressor::with_prepared_dictionary(&prepared)
        .and_then(|mut d| {
            d.decompress(
                &frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + header.len],
                1 << 20,
            )
        })
        .expect("decompresses");
    assert_eq!(body, load("tx_simple.bin"));

    // The dictionary is what makes the stream affordable, so its benefit is asserted rather than
    // assumed: without it the same message costs materially more on the wire.
    let without = read_frame_header(&load("frame_zstd.bin")).expect("header").len;
    assert!(
        header.len < without,
        "dictionary frame {} should beat plain zstd {without}",
        header.len
    );
}

#[test]
fn decompressing_against_the_wrong_dictionary_fails_rather_than_returning_garbage() {
    let frame = load("frame_zstd_dictionary.bin");
    let header = read_frame_header(&frame).expect("header");
    let result = zstd::bulk::decompress(
        &frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + header.len],
        1 << 20,
    );
    assert!(result.is_err(), "a missing dictionary must not silently decode");
}

#[test]
fn an_unknown_frame_kind_is_readable_and_skippable() {
    let mut frame = vec![0u8; FRAME_HEADER_LEN + 4];
    frame[0..4].copy_from_slice(&4u32.to_le_bytes());
    frame[4] = 200;
    frame[8..16].copy_from_slice(&42u64.to_le_bytes());
    let header = read_frame_header(&frame).expect("header");
    assert_eq!(header.kind, FrameKind::Unknown);
    assert_eq!(header.raw_kind, 200);
    assert_eq!(header.len, 4);
}

#[test]
fn a_truncated_message_is_rejected_rather_than_misread() {
    let tx = load("tx_simple.bin");
    assert!(Transaction::read(&tx[..tx.len() - 1]).is_err());
    assert!(Transaction::read(&tx[..50]).is_err());
    assert!(Entry::read(&load("entry.bin")[..87]).is_err());
    assert!(SlotEnd::read(&load("slot_end.bin")[..47]).is_err());
}

/// The two SDKs must agree with each other, not merely each with the server.
#[test]
fn the_dictionary_id_matches_what_the_typescript_sdk_computes() {
    let dictionary = Arc::new(load("dictionary.bin"));
    assert_eq!(dictionary_id(&dictionary), 3_044_610_556);
    assert_eq!(dictionary_id(&[]), 0);
}

/// A frame carries which named filters it matched.
///
/// The mask sits in two bytes the header formerly padded, so what matters is that it reads back
/// intact *and* that the fields either side of it are undisturbed.
#[test]
fn a_frame_carries_which_named_filters_it_matched() {
    let frame = load("frame_matched.bin");
    let header = read_frame_header(&frame).expect("header");

    assert_eq!(header.matched.0, 9);
    assert!(header.matched.has(0));
    assert!(header.matched.has(3));
    assert!(!header.matched.has(1));
    assert_eq!(header.matched.iter().collect::<Vec<_>>(), vec![0, 3]);

    assert_eq!(header.seq, 11);
    assert_eq!(header.kind, FrameKind::Transaction);
    assert!(!header.compressed);

    let tx = Transaction::read(&frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + header.len])
        .expect("decodes");
    assert_eq!(tx.slot(), 250_000_001);
}

/// A connection that named no filters attributes nothing.
#[test]
fn an_unfiltered_frame_reports_no_match() {
    let header = read_frame_header(&load("frame_plain.bin")).expect("header");
    assert!(header.matched.is_empty());
}

/// A greeting carrying a filter has to be byte-identical to the server's own encoding.
///
/// This is the field that decides whether a subscriber is ever sent the firehose. Getting its
/// length prefix or its position wrong does not fail loudly — the server would read a truncated or
/// absent filter and connect the subscriber unfiltered, which looks like working software right up
/// until the bandwidth bill.
#[test]
fn a_greeting_with_a_filter_encodes_to_exactly_the_bytes_the_server_expects() {
    let filter = r#"{"filters":[{"name":"mine","spec":{"is_vote":{"value":false}}}]}"#;
    let mut actual = Vec::new();
    Hello {
        streams: StreamMask(StreamMask::TRANSACTIONS | StreamMask::SLOT_EVENTS),
        codecs: CODEC_BIT_ZSTD,
        key_ref: KeyRef::of(b"fixture-key"),
        client_nonce: [0u8; 32],
        capabilities: Capabilities(Capabilities::ACCEPTS_DICTIONARY),
        dictionary_id: 0x1234_5678,
        filter: Some(filter.to_string()),
    }
    .write(&mut actual);
    assert_eq!(actual, load("hello_filtered.bin"));

    // And it is exactly the unfiltered greeting plus a length-prefixed document, so the fields
    // before it are undisturbed.
    let plain = load("hello.bin");
    assert_eq!(actual.len(), plain.len() + 4 + filter.len());
    assert_eq!(&actual[..plain.len()], &plain[..]);
}

/// A transaction the node relays but a validator would reject, decoded by both SDKs alike.
///
/// The node is a relay, not a validator: it forwards what the leader signed into the shred without
/// re-checking that the transactions inside are well formed. So an unsigned transaction, or one
/// naming a program index past its own account list, does reach a subscriber.
///
/// Both SDKs must decode it without failing, and must agree on what they see. The alternatives are
/// both worse and both remotely triggerable by a leader: refusing the frame drops the subscriber's
/// stream, and throwing from an accessor fires wherever the consumer happens to touch the field —
/// well outside whatever guarded the decode. This pins the tolerant behaviour so it cannot quietly
/// revert. The TypeScript suite asserts the same thing against the same bytes.
#[test]
fn a_relayed_but_malformed_transaction_decodes_without_failing() {
    let bytes = load("tx_malformed.bin");
    let tx = Transaction::read(&bytes).expect("the relay's own output must decode");

    assert_eq!(tx.signature_count(), 0);
    assert_eq!(
        tx.signature(),
        None,
        "an unsigned transaction has no id, and asking for one must answer rather than fail"
    );
    assert_eq!(tx.signatures().count(), 0);
    assert_eq!(tx.account_count(), 2);

    let instructions: Vec<_> = tx.instructions().collect();
    assert_eq!(instructions.len(), 1);
    let program_index = instructions[0].program_id_index as usize;
    assert_eq!(program_index, 9, "the fixture names an index past the end");
    assert_eq!(
        tx.account_key(program_index),
        None,
        "an out-of-range program index must answer `None`, not panic"
    );

    // The keys it does have are whole, so nothing was clamped into a short read.
    for key in tx.account_keys() {
        assert_eq!(key.len(), 32);
    }
}

/// The proofs, against the vector the server publishes.
///
/// Every other handshake test in this SDK checks it against itself: both sides of each assertion
/// use the same derivation, so a changed domain string or a reordered transcript field keeps them
/// all green and refuses every real connection. This is the only test that would catch that, and it
/// is why the vector is generated by the server rather than written here.
#[test]
fn the_handshake_derivation_matches_the_servers() {
    use manka_shreds_sdk::handshake::{ChannelBinding, Transcript};

    let manifest = std::fs::read_to_string(dir().join("manifest.json")).expect("manifest");
    let field = |name: &str| -> String {
        let needle = format!("\"{name}\": \"");
        let at = manifest
            .find(&needle)
            .unwrap_or_else(|| panic!("{name} is absent from the manifest"))
            + needle.len();
        manifest[at..]
            .split('"')
            .next()
            .expect("a closing quote")
            .to_string()
    };
    let hex = |bytes: &[u8; 32]| -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    };

    const KEY: &[u8] = b"fixture-key";
    let transcript = Transcript {
        key_ref: KeyRef::of(KEY),
        client_nonce: [0x11; 32],
        server_nonce: [0x22; 32],
        binding: ChannelBinding::of_certificate(b"fixture-certificate"),
    };

    assert_eq!(hex(&transcript.key_ref.0), field("key_ref_hex"));
    assert_eq!(hex(&transcript.binding.0), field("binding_hex"));
    assert_eq!(
        hex(&transcript.server_proof(KEY).0),
        field("server_proof_hex")
    );
    assert_eq!(
        hex(&transcript.client_proof(KEY).0),
        field("client_proof_hex")
    );

    // Over TCP there is no certificate, so the binding is absent rather than improvised.
    assert_eq!(
        hex(&Transcript {
            binding: ChannelBinding::NONE,
            ..transcript
        }
        .server_proof(KEY)
        .0),
        field("tcp_binding_server_proof_hex")
    );

    // And the server's own proof verifies through this SDK's checker, which is what a client
    // actually runs at connect time.
    assert!(transcript.verify_server(
        KEY,
        &manka_shreds_sdk::handshake::Proof(
            hex_to_32(&field("server_proof_hex")).expect("32 bytes of hex")
        )
    ));
}

/// Parses 64 hex characters.
fn hex_to_32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// The dictionary frame decodes to the bytes the server sent, under the id it named.
///
/// This is the one frame a client must parse *during* the handshake, and getting it wrong does not
/// degrade: the connection comes up and every body afterwards is undecodable, for a reason nothing
/// on the wire explains. Pinned against the server's own bytes rather than against this SDK's idea
/// of them.
#[test]
fn a_dictionary_frame_decodes_to_what_the_server_sent() {
    let frame = load("dictionary_frame.bin");
    let header = read_frame_header(&frame).expect("a well-formed header");
    assert_eq!(header.kind, FrameKind::Dictionary);
    assert_eq!(header.seq, 0, "the dictionary is not part of the stream's ordering");

    let body = &frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + header.len];
    let dictionary = Dictionary::read(body).expect("decodes");

    // The bytes are the dictionary the other fixtures were compressed with.
    let expected = load("dictionary.bin");
    assert_eq!(dictionary.bytes, expected);
    // And the id it travels under is the hash of those bytes, so the pairing is self-checking.
    assert_eq!(dictionary.id, dictionary_id(&expected));
}

/// A dictionary frame is not compressed.
///
/// It cannot be: it is what the connection needs in order to decompress anything. A build that
/// treated it like a data frame would try to decompress it against the dictionary it is carrying.
#[test]
fn a_dictionary_frame_is_never_compressed() {
    let frame = load("dictionary_frame.bin");
    let header = read_frame_header(&frame).expect("a well-formed header");
    assert!(!header.compressed, "the dictionary arrived compressed");
}

/// The greeting asks for a dictionary, and says so in the byte the server reads.
///
/// A client that stopped setting this would still connect, still work, and silently stream at
/// roughly a third the compression — the exact failure this whole exchange exists to remove, and
/// one nothing else would catch.
#[test]
fn the_greeting_asks_to_be_sent_a_dictionary() {
    let hello = load("hello.bin");
    // Version, streams, codecs, then capabilities.
    assert_eq!(
        hello[7] & Capabilities::ACCEPTS_DICTIONARY,
        Capabilities::ACCEPTS_DICTIONARY,
        "the greeting does not ask for a dictionary"
    );
}

/// This SDK's limit is the server's limit.
///
/// Two independent constants for one protocol rule. If this client's were lower, a dictionary the
/// server is willing to send would be refused and every connection would fail; if it were higher,
/// this client would allocate for something the server would never produce.
#[test]
fn the_dictionary_limit_matches_the_servers() {
    let manifest = std::fs::read_to_string(dir().join("manifest.json")).expect("the manifest");
    let marker = "\"max_dictionary_bytes\": ";
    let at = manifest.find(marker).expect("the server publishes its limit") + marker.len();
    let rest = &manifest[at..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    let server: usize = rest[..end].parse().expect("a number");
    assert_eq!(
        MAX_DICTIONARY_BYTES, server,
        "this client and the server disagree about how large a dictionary may be"
    );
}
