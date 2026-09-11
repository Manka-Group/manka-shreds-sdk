"""Decodes the golden fixtures produced by the server's own encoders.

This SDK vendors its own decoders rather than depending on the server crates, so nothing but this
file stops the two from drifting apart. Every assertion here is a byte layout the server actually
produced; if a layout changes, these fail rather than the SDK silently misreading a field.

Regenerate with ``cargo run --example fixtures -- ../manka-shreds-sdk/fixtures`` in the manka-shreds
repository.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from manka_shreds_sdk.events import (
    read_duplicate,
    read_entry,
    read_raw_shred,
    read_slot_end,
    read_slot_start,
)
from manka_shreds_sdk.handshake import (
    NO_BINDING,
    Transcript,
    binding_of,
    client_proof,
    fresh_nonce,
    key_ref,
    server_proof,
    verify_server,
)
from manka_shreds_sdk.protocol import (
    FRAME_HEADER_LEN,
    MAX_DICTIONARY_BYTES,
    PROTOCOL_VERSION,
    Capability,
    Codec,
    ErrorCode,
    FrameKind,
    Hello,
    ProtocolError,
    Stream,
    Verification,
    dictionary_id,
    read_dictionary,
    read_error,
    read_filter_ack,
    read_frame_header,
    read_hello_ack,
    read_lag,
    write_dictionary,
    write_hello,
)
from manka_shreds_sdk.protocol import Dictionary as Dict_
from manka_shreds_sdk.transaction import MESSAGE_VERSION_LEGACY, Transaction

FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "fixtures"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_the_fixture_set_matches_the_protocol_version_this_sdk_speaks() -> None:
    assert MANIFEST["protocol_version"] == PROTOCOL_VERSION


# -------------------------------------------------------------------------------------------------
# Handshake
# -------------------------------------------------------------------------------------------------


def _transcript() -> tuple[Transcript, bytes]:
    hs = MANIFEST["handshake"]
    key = hs["key_material_utf8"].encode()
    return (
        Transcript(
            key_ref=key_ref(key),
            client_nonce=bytes([hs["client_nonce_byte"]]) * 32,
            server_nonce=bytes([hs["server_nonce_byte"]]) * 32,
            binding=binding_of(hs["certificate_der_utf8"].encode()),
        ),
        key,
    )


def test_the_derivation_matches_the_vector_every_sdk_is_pinned_to() -> None:
    """The one test that catches a protocol rename before it reaches a deployment.

    Both sides of every other assertion move together if a domain separator changes. These are
    fixed numbers the server publishes, so they do not.
    """
    hs = MANIFEST["handshake"]
    transcript, key = _transcript()
    assert transcript.key_ref.hex() == hs["key_ref_hex"]
    assert transcript.binding.hex() == hs["binding_hex"]
    assert server_proof(transcript, key).hex() == hs["server_proof_hex"]
    assert client_proof(transcript, key).hex() == hs["client_proof_hex"]

    # The TCP case, where there is no certificate to bind to.
    tcp = Transcript(
        key_ref=transcript.key_ref,
        client_nonce=transcript.client_nonce,
        server_nonce=transcript.server_nonce,
        binding=NO_BINDING,
    )
    assert server_proof(tcp, key).hex() == hs["tcp_binding_server_proof_hex"]


def test_a_server_proof_verifies_and_a_wrong_one_does_not() -> None:
    transcript, key = _transcript()
    assert verify_server(transcript, key, server_proof(transcript, key))
    # The client's proof is over a different domain, so it must not pass as the server's.
    assert not verify_server(transcript, key, client_proof(transcript, key))
    # A short proof is something a peer can send; it must be refused, not raise.
    assert not verify_server(transcript, key, b"\x00" * 16)


def test_a_nonce_is_fresh_and_the_right_width() -> None:
    a, b = fresh_nonce(), fresh_nonce()
    assert len(a) == 32
    assert a != b


# -------------------------------------------------------------------------------------------------
# Control messages
# -------------------------------------------------------------------------------------------------


def test_a_hello_encodes_to_exactly_the_bytes_the_server_expects() -> None:
    hello = MANIFEST["hello"]
    actual = write_hello(
        Hello(
            streams=Stream.TRANSACTIONS | Stream.SLOT_EVENTS,
            codecs=1 << 2,
            key_ref=key_ref(hello["key_material_utf8"].encode()),
            client_nonce=bytes(32),
            capabilities=Capability.ACCEPTS_DICTIONARY,
            dictionary_id=hello["dictionary_id"],
        )
    )
    assert actual == load("hello.bin")


def test_a_hello_carrying_a_filter_encodes_to_exactly_the_bytes_the_server_expects() -> None:
    """The field that decides whether a subscriber is ever sent the firehose.

    Getting its length prefix or its position wrong does not fail loudly — the server reads a
    truncated or absent filter and connects the subscriber unfiltered, which looks like working
    software right up until the bandwidth bill.
    """
    filtered = MANIFEST["hello_filtered"]
    actual = write_hello(
        Hello(
            streams=Stream.TRANSACTIONS | Stream.SLOT_EVENTS,
            codecs=1 << 2,
            key_ref=key_ref(filtered["key_material_utf8"].encode()),
            client_nonce=bytes(32),
            capabilities=Capability.ACCEPTS_DICTIONARY,
            dictionary_id=filtered["dictionary_id"],
            filter=filtered["filter"],
        )
    )
    assert actual == load("hello_filtered.bin")

    # And it is the unfiltered greeting plus a length-prefixed document, so the fields before it
    # are undisturbed.
    plain = load("hello.bin")
    assert len(actual) == len(plain) + 4 + len(filtered["filter"].encode())
    assert actual[: len(plain)] == plain


def test_a_filter_is_length_prefixed_in_bytes_rather_than_characters() -> None:
    """A filter name is chosen by the subscriber, and the field is UTF-8.

    Counting characters rather than bytes would understate the length of a name with an emoji or an
    accent in it and truncate the document on the wire.
    """
    spec = '{"filters":[{"name":"café 🎯","spec":"all"}]}'
    encoded = write_hello(
        Hello(
            streams=Stream.TRANSACTIONS,
            codecs=1 << 2,
            key_ref=key_ref(b"k"),
            client_nonce=bytes(32),
            capabilities=Capability.ACCEPTS_DICTIONARY,
            dictionary_id=0,
            filter=spec,
        )
    )
    at = 8 + 32 + 32 + 4
    assert int.from_bytes(encoded[at : at + 4], "little") == len(spec.encode())
    assert len(spec.encode()) > len(spec), "the test string must be multi-byte"
    assert encoded[at + 4 :].decode() == spec


def test_a_hello_ack_decodes() -> None:
    ack = read_hello_ack(load("hello_ack.bin"))
    want = MANIFEST["hello_ack"]
    assert ack.protocol_version == want["protocol_version"]
    assert ack.granted == want["granted"]
    assert ack.session_id == int(want["session_id"])
    assert ack.codec == want["codec"]
    assert ack.codec is Codec.ZSTD
    assert ack.keepalive_ms == want["keepalive_ms"]
    assert ack.dictionary_id == want["dictionary_id"]


def test_an_error_decodes_including_the_compression_refusal() -> None:
    error = read_error(load("error.bin"))
    assert error.code == MANIFEST["error"]["code"]
    assert error.code == ErrorCode.BAD_REQUEST
    assert error.detail == MANIFEST["error"]["detail"]


def test_a_lag_report_decodes() -> None:
    lag = read_lag(load("lag.bin"))
    assert lag.dropped == int(MANIFEST["lag"]["dropped"])
    assert lag.resume_seq == int(MANIFEST["lag"]["resume_seq"])


def test_a_filter_ack_decodes() -> None:
    ack = read_filter_ack(load("filter_ack.bin"))
    assert ack.accepted == MANIFEST["filter_ack"]["accepted"]
    assert ack.cost == MANIFEST["filter_ack"]["cost"]
    assert ack.detail == MANIFEST["filter_ack"]["detail"]


# -------------------------------------------------------------------------------------------------
# Framing
# -------------------------------------------------------------------------------------------------


def test_a_frame_header_decodes() -> None:
    header = read_frame_header(load("frame_plain.bin"))
    want = MANIFEST["frame_plain"]
    assert header.kind == FrameKind.TRANSACTION
    assert header.kind == want["kind"]
    assert header.len == MANIFEST["tx_simple_len"]
    assert header.seq == int(want["seq"])
    assert header.compressed is False
    assert header.codec is Codec.NONE


def test_a_matched_frame_carries_its_filter_bitmask() -> None:
    header = read_frame_header(load("frame_matched.bin"))
    assert header.matched == MANIFEST["frame_matched"]["matched"]


def test_a_compressed_frame_announces_its_codec() -> None:
    header = read_frame_header(load("frame_zstd.bin"))
    assert header.compressed is True
    assert header.codec is Codec.ZSTD


def test_an_unknown_frame_kind_is_skipped_rather_than_fatal() -> None:
    """Adding a frame type must not break a subscriber built before it existed."""
    from manka_shreds_sdk.protocol import write_frame

    frame = bytearray(write_frame(FrameKind.TRANSACTION, 1, b"payload"))
    frame[4] = 200  # a kind no build knows
    header = read_frame_header(bytes(frame))
    assert header.kind is FrameKind.UNKNOWN
    assert header.raw_kind == 200
    assert header.len == len(b"payload")


# -------------------------------------------------------------------------------------------------
# Dictionary
# -------------------------------------------------------------------------------------------------


def test_a_dictionary_frame_decodes_and_its_id_is_the_content_hash() -> None:
    framed = load("dictionary_frame.bin")
    header = read_frame_header(framed)
    assert header.kind is FrameKind.DICTIONARY
    dictionary = read_dictionary(framed[FRAME_HEADER_LEN:])
    assert dictionary.bytes == load("dictionary.bin")
    assert dictionary.id == dictionary_id(dictionary.bytes)
    assert dictionary.id == MANIFEST["dictionary_frame"]["dictionary_id"]
    assert len(dictionary.bytes) == MANIFEST["dictionary_frame"]["dictionary_len"]


def test_a_dictionary_round_trips() -> None:
    body = load("dictionary.bin")
    encoded = write_dictionary(Dict_(id=dictionary_id(body), bytes=body))
    assert read_dictionary(encoded).bytes == body


def test_an_oversized_dictionary_is_refused_before_it_is_allocated() -> None:
    """The declared length is the server's to choose, so it is checked before the body is taken."""
    header = (MAX_DICTIONARY_BYTES + 1).to_bytes(4, "little")
    with pytest.raises(ProtocolError, match="limit is"):
        read_dictionary(b"\x01\x00\x00\x00" + header)


def test_an_empty_dictionary_has_no_id() -> None:
    assert dictionary_id(b"") == 0


# -------------------------------------------------------------------------------------------------
# Events
# -------------------------------------------------------------------------------------------------


def test_a_slot_start_decodes_with_and_without_an_optional_parent_and_leader() -> None:
    start = read_slot_start(load("slot_start.bin"))
    want = MANIFEST["slot_start"]
    assert start.slot == int(want["slot"])
    assert start.parent_slot == int(want["parent_slot"])
    assert start.leader is not None
    assert len(start.leader) == 32
    assert start.leader[0] == want["leader_byte"]
    assert start.rx_ts_ns == int(want["rx_ts_ns"])
    assert start.shred_version == want["shred_version"]
    assert start.source == want["source"]

    bare = read_slot_start(load("slot_start_bare.bin"))
    assert bare.slot == int(MANIFEST["slot_start_bare"]["slot"])
    assert bare.parent_slot is None
    assert bare.leader is None


def test_a_slot_end_decodes() -> None:
    end = read_slot_end(load("slot_end.bin"))
    want = MANIFEST["slot_end"]
    assert end.slot == int(want["slot"])
    assert end.parent_slot == int(want["parent_slot"])
    assert end.data_shreds == want["data_shreds"]
    assert end.fec_sets == want["fec_sets"]
    assert end.recovered_sets == want["recovered_sets"]
    assert end.missing_shreds == want["missing_shreds"]
    assert end.complete == want["complete"]


def test_an_entry_decodes() -> None:
    entry = read_entry(load("entry.bin"))
    want = MANIFEST["entry"]
    assert entry.slot == int(want["slot"])
    assert entry.num_hashes == int(want["num_hashes"])
    assert entry.tx_count == int(want["tx_count"])
    assert entry.fec_set_index == want["fec_set_index"]
    assert entry.entry_index == want["entry_index"]
    assert entry.verification == want["verification"]
    assert len(entry.hash) == 32


def test_a_duplicate_report_decodes_with_both_signatures() -> None:
    report = read_duplicate(load("duplicate.bin"))
    want = MANIFEST["duplicate"]
    assert report.slot == int(want["slot"])
    assert report.index == want["index"]
    assert report.first_source == want["first_source"]
    assert report.second_source == want["second_source"]
    assert report.is_data == want["is_data"]
    assert len(report.first_signature) == 64
    assert len(report.second_signature) == 64
    assert report.first_signature != report.second_signature


def test_a_truncated_event_is_refused_rather_than_misread() -> None:
    for reader in (read_slot_start, read_slot_end, read_entry, read_duplicate, read_raw_shred):
        with pytest.raises(ProtocolError):
            reader(b"\x00" * 4)


# -------------------------------------------------------------------------------------------------
# Transactions
# -------------------------------------------------------------------------------------------------


def test_a_simple_transaction_decodes_every_header_field() -> None:
    tx = Transaction.read(load("tx_simple.bin"))
    want = MANIFEST["tx_simple"]
    assert tx.slot == int(want["slot"])
    assert tx.parent_slot == int(want["parent_slot"])
    assert tx.rx_ts_ns == int(want["rx_ts_ns"])
    assert tx.emit_ts_ns == int(want["emit_ts_ns"])
    assert tx.pipeline_ns == int(want["emit_ts_ns"]) - int(want["rx_ts_ns"])
    assert tx.leader is not None
    assert tx.leader[0] == want["leader_byte"]
    assert tx.fec_set_index == want["fec_set_index"]
    assert tx.entry_index == want["entry_index"]
    assert tx.tx_index == want["tx_index"]
    assert tx.source_id == want["source_id"]
    assert tx.is_vote == want["is_vote"]
    assert tx.recovered == want["recovered"]
    assert tx.verification == want["verification"]
    assert tx.verification is Verification.VERIFIED
    assert tx.account_count == want["account_count"]
    assert tx.instruction_count == want["instruction_count"]
    assert tx.signature_count == want["signature_count"]
    assert len(tx.signatures()) == want["signature_count"]
    assert len(tx.account_keys()) == want["account_count"]
    assert len(tx.recent_blockhash) == 32
    assert tx.raw_tx is None


def test_a_full_transaction_carries_lookups_and_raw_bytes() -> None:
    tx = Transaction.read(load("tx_full.bin"))
    want = MANIFEST["tx_full"]
    assert tx.account_count == want["account_count"]
    assert tx.lookup_count == want["lookup_count"]
    assert tx.is_vote == want["is_vote"]
    assert tx.recovered == want["recovered"]
    assert tx.message_version == want["message_version"]

    raw = tx.raw_tx
    assert raw is not None
    assert len(raw) == want["raw_tx_len"]

    instruction = tx.instruction(0)
    assert instruction is not None
    assert len(instruction.data) == want["instruction_data_len"]

    lookups = tx.lookups()
    assert len(lookups) == want["lookup_count"]
    assert lookups[0].account_key[0] == want["lookup0_key_byte"]
    assert lookups[1].account_key[0] == want["lookup1_key_byte"]
    assert list(lookups[0].writable_indexes) == want["lookup_writable"]
    assert list(lookups[0].readonly_indexes) == want["lookup_readonly"]


def test_a_legacy_message_is_marked_and_still_decodes() -> None:
    tx = Transaction.read(load("tx_legacy.bin"))
    want = MANIFEST["tx_legacy"]
    assert tx.message_version == MESSAGE_VERSION_LEGACY
    assert tx.message_version == want["message_version"]
    assert tx.leader is None
    assert tx.verification == want["verification"]
    instruction = tx.instruction(0)
    assert instruction is not None
    assert list(instruction.data) == want["instruction_data"]
    assert instruction.program_id_index == want["program_id_index"]


def test_a_malformed_transaction_decodes_without_raising() -> None:
    """A leader can produce this, and the node relays what the leader signed.

    Raising from an accessor would let a leader knock every subscriber off the stream, so an
    unsigned transaction and an out-of-range program index both return ``None`` instead.
    """
    tx = Transaction.read(load("tx_malformed.bin"))
    want = MANIFEST["tx_malformed"]
    assert tx.signature_count == want["signature_count"]
    assert tx.signature is None
    assert tx.signatures() == []

    instruction = tx.instruction(0)
    assert instruction is not None
    assert instruction.program_id_index == want["program_id_index"]
    # The index is past the account list, which is exactly the case this fixture exists for.
    assert instruction.program_id_index >= tx.account_count
    assert tx.account_key(instruction.program_id_index) is None
    assert tx.account_key(-1) is None


def test_a_truncated_transaction_is_refused() -> None:
    with pytest.raises(ProtocolError, match="transaction header needs"):
        Transaction.read(b"\x00" * 16)
