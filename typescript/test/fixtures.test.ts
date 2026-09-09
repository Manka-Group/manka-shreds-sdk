/**
 * Decodes the golden fixtures produced by the server's own encoders.
 *
 * This SDK vendors its own decoders rather than depending on the server crates, so nothing but this
 * file stops the two from drifting apart. Every assertion here is a byte layout the server actually
 * produced; if a layout changes, these fail rather than the SDK silently misreading a field.
 *
 * Regenerate with `cargo run --example fixtures -- ../manka-shreds-sdk/fixtures` in the manka-shreds repository.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { zstdDecompressSync } from 'node:zlib';

import {
  Capability,
  Codec,
  DICTIONARY_HEADER_LEN,
  ErrorCode,
  FRAME_HEADER_LEN,
  FrameKind,
  MAX_DICTIONARY_BYTES,
  PROTOCOL_VERSION,
  Stream,
  Verification,
  dictionaryId,
  readDictionary,
  writeDictionary,
  readError,
  readFilterAck,
  readFrameHeader,
  readHelloAck,
  readLag,
  writeHello,
} from '../src/protocol.js';
import {
  NO_BINDING,
  bindingOf,
  clientProof,
  freshNonce,
  keyRef,
  serverProof,
  verifyServer,
} from '../src/handshake.js';
import { DictionaryCache, scratchDir } from '../src/dictcache.js';
import { readDuplicate, readEntry, readSlotEnd, readSlotStart } from '../src/events.js';
import { MESSAGE_VERSION_LEGACY, Transaction } from '../src/transaction.js';

const dir = fileURLToPath(new URL('../../../fixtures/', import.meta.url));
const load = (name: string): Buffer => readFileSync(dir + name);
const manifest = JSON.parse(readFileSync(dir + 'manifest.json', 'utf8'));

test('the fixture set matches the protocol version this SDK speaks', () => {
  assert.equal(manifest.protocol_version, PROTOCOL_VERSION);
});

test('a hello encodes to exactly the bytes the server expects', () => {
  const expected = load('hello.bin');
  const actual = writeHello({
    streams: Stream.TRANSACTIONS | Stream.SLOT_EVENTS,
    codecs: 1 << 2,
    keyRef: keyRef(Buffer.from(manifest.hello.key_material_utf8, 'utf8')),
    clientNonce: Buffer.alloc(32),
    capabilities: Capability.ACCEPTS_DICTIONARY,
    dictionaryId: manifest.hello.dictionary_id,
  });
  assert.deepEqual(actual, expected);
});

// This is the field that decides whether a subscriber is ever sent the firehose. Getting its
// length prefix or its position wrong does not fail loudly — the server reads a truncated or absent
// filter and connects the subscriber unfiltered, which looks like working software right up until
// the bandwidth bill.
test('a hello carrying a filter encodes to exactly the bytes the server expects', () => {
  const expected = load('hello_filtered.bin');
  const actual = writeHello({
    streams: Stream.TRANSACTIONS | Stream.SLOT_EVENTS,
    codecs: 1 << 2,
    keyRef: keyRef(Buffer.from(manifest.hello_filtered.key_material_utf8, 'utf8')),
    clientNonce: Buffer.alloc(32),
    capabilities: Capability.ACCEPTS_DICTIONARY,
    dictionaryId: manifest.hello_filtered.dictionary_id,
    filter: manifest.hello_filtered.filter,
  });
  assert.deepEqual(actual, expected);

  // And it is the unfiltered greeting plus a length-prefixed document, so the fields before it are
  // undisturbed.
  const plain = load('hello.bin');
  assert.equal(actual.length, plain.length + 4 + Buffer.byteLength(manifest.hello_filtered.filter));
  assert.deepEqual(actual.subarray(0, plain.length), plain);
});

// `string.length` counts UTF-16 units, not bytes. Every key in a filter is base58 today, so the two
// agree — but the field is UTF-8, and a filter name is chosen by the subscriber. A name with an
// emoji or an accent in it would understate the length and truncate the document on the wire.
test('a filter is length-prefixed in bytes rather than characters', () => {
  const filter = '{"filters":[{"name":"café 🎯","spec":"all"}]}';
  const encoded = writeHello({
    streams: Stream.TRANSACTIONS,
    codecs: 1 << 2,
    keyRef: keyRef(Buffer.from('k', 'utf8')),
    clientNonce: Buffer.alloc(32),
    capabilities: Capability.ACCEPTS_DICTIONARY,
    dictionaryId: 0,
    filter,
  });
  // Version, streams, codecs, pad, then the fixed-width reference and nonce, then the dictionary.
  const prefixAt = 8 + 32 + 32 + 4;
  assert.equal(encoded.readUInt32LE(prefixAt), Buffer.byteLength(filter, 'utf8'));
  assert.ok(Buffer.byteLength(filter, 'utf8') > filter.length, 'the test string must be multi-byte');
  assert.equal(encoded.subarray(prefixAt + 4).toString('utf8'), filter);
});

test('a hello ack decodes', () => {
  const ack = readHelloAck(load('hello_ack.bin'));
  const want = manifest.hello_ack;
  assert.equal(ack.protocolVersion, want.protocol_version);
  assert.equal(ack.granted, want.granted);
  assert.equal(ack.sessionId, BigInt(want.session_id));
  assert.equal(ack.codec, want.codec);
  assert.equal(ack.codec, Codec.Zstd);
  assert.equal(ack.keepaliveMs, want.keepalive_ms);
  assert.equal(ack.dictionaryId, want.dictionary_id);
});

test('an error decodes, including the compression refusal', () => {
  const error = readError(load('error.bin'));
  assert.equal(error.code, manifest.error.code);
  assert.equal(error.code, ErrorCode.BadRequest);
  assert.equal(error.detail, manifest.error.detail);
});

test('a lag report decodes', () => {
  const lag = readLag(load('lag.bin'));
  assert.equal(lag.dropped, BigInt(manifest.lag.dropped));
  assert.equal(lag.resumeSeq, BigInt(manifest.lag.resume_seq));
});

test('a filter ack decodes', () => {
  const ack = readFilterAck(load('filter_ack.bin'));
  assert.equal(ack.accepted, manifest.filter_ack.accepted);
  assert.equal(ack.cost, manifest.filter_ack.cost);
  assert.equal(ack.detail, manifest.filter_ack.detail);
});

test('a slot start decodes, with and without an optional parent and leader', () => {
  const start = readSlotStart(load('slot_start.bin'));
  const want = manifest.slot_start;
  assert.equal(start.slot, BigInt(want.slot));
  assert.equal(start.parentSlot, BigInt(want.parent_slot));
  assert.equal(start.leader?.length, 32);
  assert.equal(start.leader?.[0], want.leader_byte);
  assert.equal(start.rxTsNs, BigInt(want.rx_ts_ns));
  assert.equal(start.shredVersion, want.shred_version);
  assert.equal(start.source, want.source);

  const bare = readSlotStart(load('slot_start_bare.bin'));
  assert.equal(bare.slot, BigInt(manifest.slot_start_bare.slot));
  assert.equal(bare.parentSlot, null);
  assert.equal(bare.leader, null);
});

test('a slot end decodes', () => {
  const end = readSlotEnd(load('slot_end.bin'));
  const want = manifest.slot_end;
  assert.equal(end.slot, BigInt(want.slot));
  assert.equal(end.parentSlot, BigInt(want.parent_slot));
  assert.equal(end.dataShreds, want.data_shreds);
  assert.equal(end.fecSets, want.fec_sets);
  assert.equal(end.recoveredSets, want.recovered_sets);
  assert.equal(end.missingShreds, want.missing_shreds);
  assert.equal(end.endTsNs, BigInt(want.end_ts_ns));
  assert.equal(end.complete, want.complete);
});

test('an entry decodes, including its verification verdict', () => {
  const entry = readEntry(load('entry.bin'));
  const want = manifest.entry;
  assert.equal(entry.slot, BigInt(want.slot));
  assert.equal(entry.parentSlot, BigInt(want.parent_slot));
  assert.equal(entry.rxTsNs, BigInt(want.rx_ts_ns));
  assert.equal(entry.numHashes, BigInt(want.num_hashes));
  assert.equal(entry.txCount, BigInt(want.tx_count));
  assert.equal(entry.hash.length, 32);
  assert.equal(entry.hash[0], want.hash_byte);
  assert.equal(entry.fecSetIndex, want.fec_set_index);
  assert.equal(entry.entryIndex, want.entry_index);
  assert.equal(entry.verification, Verification.StaleSchedule);
  assert.equal(entry.verification, want.verification);
});

test('a duplicate report decodes both conflicting signatures', () => {
  const dup = readDuplicate(load('duplicate.bin'));
  const want = manifest.duplicate;
  assert.equal(dup.slot, BigInt(want.slot));
  assert.equal(dup.index, want.index);
  assert.equal(dup.firstSource, want.first_source);
  assert.equal(dup.secondSource, want.second_source);
  assert.equal(dup.detectedNs, BigInt(want.detected_ns));
  assert.equal(dup.isData, want.is_data);
  assert.equal(dup.firstSignature.length, 64);
  assert.equal(dup.firstSignature[0], want.first_signature_byte);
  assert.equal(dup.secondSignature[0], want.second_signature_byte);
});

test('a transaction decodes every header field and section', () => {
  const tx = Transaction.read(load('tx_simple.bin'));
  const want = manifest.tx_simple;
  assert.equal(tx.slot, BigInt(want.slot));
  assert.equal(tx.parentSlot, BigInt(want.parent_slot));
  assert.equal(tx.rxTsNs, BigInt(want.rx_ts_ns));
  assert.equal(tx.emitTsNs, BigInt(want.emit_ts_ns));
  assert.equal(tx.pipelineNs, BigInt(want.emit_ts_ns) - BigInt(want.rx_ts_ns));
  assert.equal(tx.leader?.[0], want.leader_byte);
  assert.equal(tx.fecSetIndex, want.fec_set_index);
  assert.equal(tx.entryIndex, want.entry_index);
  assert.equal(tx.txIndex, want.tx_index);
  assert.equal(tx.sourceId, want.source_id);
  assert.equal(tx.isVote, want.is_vote);
  assert.equal(tx.recovered, want.recovered);
  assert.equal(tx.verification, Verification.Verified);
  assert.equal(tx.accountCount, want.account_count);
  assert.equal(tx.instructionCount, want.instruction_count);
  assert.equal(tx.signatureCount, want.signature_count);
  assert.equal(tx.messageVersion, want.message_version);
  assert.equal(tx.lookupCount, want.lookup_count);
  assert.equal(tx.requiredSignatures, want.required_signatures);
  assert.equal(tx.readonlySigned, want.readonly_signed);
  assert.equal(tx.readonlyUnsigned, want.readonly_unsigned);

  const signature = tx.signature;
  assert.ok(signature !== null, "a fixture transaction must be signed");
  assert.equal(signature.length, 64);
  assert.equal(signature[0], want.signature_byte);
  assert.equal(tx.signatures().length, want.signature_count);
  assert.equal(tx.recentBlockhash.length, 32);
  assert.equal(tx.recentBlockhash[0], want.blockhash_byte);

  // Account keys were written as key `i` filled with byte `i`, so this proves both the section
  // offset and the per-key stride.
  assert.equal(tx.accountKeys().length, want.account_count);
  for (let i = 0; i < want.account_count; i += 1) {
    assert.equal(tx.accountKey(i)?.[0], i, `account key ${i}`);
  }

  const [ix] = tx.instructions();
  assert.ok(ix);
  assert.equal(ix.programIdIndex, want.program_id_index);
  assert.deepEqual([...ix.accounts], want.instruction_accounts);
  assert.deepEqual([...ix.data], want.instruction_data);
  assert.equal(tx.rawTx, null);
  assert.equal(tx.lookups().length, 0);
});

test('a transaction with every optional section decodes', () => {
  const tx = Transaction.read(load('tx_full.bin'));
  const want = manifest.tx_full;
  assert.equal(tx.accountCount, want.account_count);
  assert.equal(tx.isVote, want.is_vote);
  assert.equal(tx.recovered, want.recovered);
  assert.equal(tx.lookupCount, want.lookup_count);

  const [ix] = tx.instructions();
  assert.equal(ix?.data.length, want.instruction_data_len);

  const lookups = tx.lookups();
  assert.equal(lookups.length, want.lookup_count);
  assert.equal(lookups[0]?.accountKey.length, 32);
  assert.equal(lookups[0]?.accountKey[0], want.lookup0_key_byte);
  assert.equal(lookups[1]?.accountKey[0], want.lookup1_key_byte);
  assert.deepEqual([...(lookups[0]?.writableIndexes ?? [])], want.lookup_writable);
  assert.deepEqual([...(lookups[0]?.readonlyIndexes ?? [])], want.lookup_readonly);

  const raw = tx.rawTx;
  assert.ok(raw, 'raw bytes were requested');
  assert.equal(raw.length, want.raw_tx_len);
});

test('a legacy message decodes with the sentinel version', () => {
  const tx = Transaction.read(load('tx_legacy.bin'));
  const want = manifest.tx_legacy;
  assert.equal(tx.messageVersion, MESSAGE_VERSION_LEGACY);
  assert.equal(tx.messageVersion, want.message_version);
  assert.equal(tx.accountCount, want.account_count);
  assert.equal(tx.leader, null);
  assert.equal(tx.verification, Verification.UnknownLeader);
  const [ix] = tx.instructions();
  assert.equal(ix?.programIdIndex, want.program_id_index);
  assert.deepEqual([...(ix?.data ?? [])], want.instruction_data);
});

test('a plain frame decodes and carries a whole transaction', () => {
  const frame = load('frame_plain.bin');
  const header = readFrameHeader(frame);
  assert.equal(header.kind, FrameKind.Transaction);
  assert.equal(header.seq, BigInt(manifest.frame_plain.seq));
  assert.equal(header.compressed, false);
  assert.equal(header.len, manifest.tx_simple_len);
  const tx = Transaction.read(frame.subarray(FRAME_HEADER_LEN, FRAME_HEADER_LEN + header.len));
  assert.equal(tx.slot, BigInt(manifest.tx_simple.slot));
});

test("Node's built-in zstd decodes a frame the Rust server compressed", () => {
  const frame = load('frame_zstd.bin');
  const header = readFrameHeader(frame);
  assert.equal(header.compressed, true);
  assert.equal(header.codec, Codec.Zstd);
  const body = zstdDecompressSync(frame.subarray(FRAME_HEADER_LEN, FRAME_HEADER_LEN + header.len));
  assert.deepEqual(body, load('tx_simple.bin'));
});

test('a dictionary-compressed frame decodes, and the id matches the server hash', () => {
  const dictionary = load('dictionary.bin');
  assert.equal(dictionaryId(dictionary), manifest.frame_zstd_dictionary.dictionary_id);

  const frame = load('frame_zstd_dictionary.bin');
  const header = readFrameHeader(frame);
  const payload = frame.subarray(FRAME_HEADER_LEN, FRAME_HEADER_LEN + header.len);
  const body = zstdDecompressSync(payload, { dictionary });
  assert.deepEqual(body, load('tx_simple.bin'));

  // The dictionary is what makes the stream affordable, so its benefit is asserted rather than
  // assumed: without it the same message costs materially more on the wire.
  const withoutDictionary = readFrameHeader(load('frame_zstd.bin')).len;
  assert.ok(
    header.len < withoutDictionary,
    `dictionary frame ${header.len} should beat plain zstd ${withoutDictionary}`,
  );
});

test('decompressing against the wrong dictionary fails rather than returning garbage', () => {
  const frame = load('frame_zstd_dictionary.bin');
  const header = readFrameHeader(frame);
  const payload = frame.subarray(FRAME_HEADER_LEN, FRAME_HEADER_LEN + header.len);
  assert.throws(() => zstdDecompressSync(payload));
});

test('an unknown frame kind is readable and skippable', () => {
  const frame = Buffer.alloc(FRAME_HEADER_LEN + 4);
  frame.writeUInt32LE(4, 0);
  frame.writeUInt8(200, 4);
  frame.writeBigUInt64LE(42n, 8);
  const header = readFrameHeader(frame);
  assert.equal(header.kind, FrameKind.Unknown);
  assert.equal(header.rawKind, 200);
  assert.equal(header.len, 4);
});

test('a truncated message is rejected rather than misread', () => {
  const tx = load('tx_simple.bin');
  assert.throws(() => Transaction.read(tx.subarray(0, tx.length - 1)));
  assert.throws(() => Transaction.read(tx.subarray(0, 50)));
  assert.throws(() => readEntry(load('entry.bin').subarray(0, 87)));
  assert.throws(() => readSlotEnd(load('slot_end.bin').subarray(0, 47)));
});

test('a frame carries which named filters it matched', () => {
  const frame = load('frame_matched.bin');
  const header = readFrameHeader(frame);
  const want = manifest.frame_matched;

  assert.equal(header.matched, want.matched);
  assert.equal(header.seq, BigInt(want.seq));
  // The mask must not disturb the fields either side of it.
  assert.equal(header.kind, FrameKind.Transaction);
  assert.equal(header.compressed, false);

  const indices: number[] = [];
  for (let bit = 0; bit < 16; bit += 1) {
    if ((header.matched & (1 << bit)) !== 0) indices.push(bit);
  }
  assert.deepEqual(indices, want.matched_indices);

  // And the transaction beside it still decodes.
  const tx = Transaction.read(frame.subarray(FRAME_HEADER_LEN, FRAME_HEADER_LEN + header.len));
  assert.equal(tx.slot, BigInt(manifest.tx_simple.slot));
});

test('a frame with no named filters reports no match', () => {
  const header = readFrameHeader(load('frame_plain.bin'));
  assert.equal(header.matched, 0, 'an unfiltered connection attributes nothing');
});

// A transaction the node relays but a validator would reject: unsigned, and naming a program index
// past its own account list. The node is a relay, not a validator — it forwards what the leader
// signed into the shred — so this does reach a subscriber.
//
// Both SDKs must decode it without throwing and agree on what they see. The alternatives are both
// worse and both remotely triggerable by a leader: refusing the frame drops the subscriber's
// stream, and throwing from an accessor fires wherever the consumer touches the field, well outside
// whatever `try` guarded the decode. The Rust suite asserts the same thing against the same bytes.
test('a relayed but malformed transaction decodes without throwing', () => {
  const tx = Transaction.read(load('tx_malformed.bin'));

  assert.equal(tx.signatureCount, 0);
  assert.equal(
    tx.signature,
    null,
    'an unsigned transaction has no id, and asking for one must answer rather than throw',
  );
  assert.equal(tx.signatures().length, 0);
  assert.equal(tx.accountCount, 2);

  const instructions = tx.instructions();
  assert.equal(instructions.length, 1);
  const programIdIndex = instructions[0]!.programIdIndex;
  assert.equal(programIdIndex, 9, 'the fixture names an index past the end');
  assert.equal(
    tx.accountKey(programIdIndex),
    null,
    'an out-of-range program index must answer null, not throw',
  );

  // The keys it does have are whole, so `subarray` clamping did not hand back a short read.
  for (const key of tx.accountKeys()) assert.equal(key.length, 32);

  // And an index the caller invents is answered the same way.
  assert.equal(tx.accountKey(-1), null);
  assert.equal(tx.instruction(99), null);
});

/**
 * The proofs, against the vector the server publishes.
 *
 * Every other handshake test in this SDK checks it against itself: both sides of each assertion use
 * the same derivation, so a changed domain string or a reordered transcript field keeps them all
 * green and refuses every real connection. This is the only test that would catch that, and it is
 * why the vector is generated by the server rather than written here.
 */
test('the handshake derivation matches the server’s', () => {
  const vector = manifest.handshake;
  const key = Buffer.from(vector.key_material_utf8, 'utf8');
  const transcript = {
    keyRef: keyRef(key),
    clientNonce: Buffer.alloc(32, vector.client_nonce_byte),
    serverNonce: Buffer.alloc(32, vector.server_nonce_byte),
    binding: bindingOf(Buffer.from(vector.certificate_der_utf8, 'utf8')),
  };

  assert.equal(transcript.keyRef.toString('hex'), vector.key_ref_hex);
  assert.equal(transcript.binding.toString('hex'), vector.binding_hex);
  assert.equal(serverProof(transcript, key).toString('hex'), vector.server_proof_hex);
  assert.equal(clientProof(transcript, key).toString('hex'), vector.client_proof_hex);

  // Over TCP there is no certificate, so the binding is absent rather than improvised.
  assert.equal(
    serverProof({ ...transcript, binding: NO_BINDING }, key).toString('hex'),
    vector.tcp_binding_server_proof_hex,
  );

  // And the server's own proof passes this SDK's checker, which is what a client runs at connect.
  assert.ok(verifyServer(transcript, key, Buffer.from(vector.server_proof_hex, 'hex')));
});

/**
 * The Rust and TypeScript SDKs must produce the same reference for the same key.
 *
 * A subscriber that switches languages keeps its key. If the two derived different references the
 * node would report the same key as unknown from one SDK and admit it from the other.
 */
test('a key reference is the same value the Rust SDK derives', () => {
  assert.equal(
    keyRef(Buffer.from(manifest.hello.key_material_utf8, 'utf8')).toString('hex'),
    manifest.handshake.key_ref_hex,
  );
});

/** A short proof is refused rather than throwing out of the comparison. */
test('a malformed proof is refused rather than crashing the client', () => {
  const key = Buffer.from('k');
  const transcript = {
    keyRef: keyRef(key),
    clientNonce: Buffer.alloc(32, 1),
    serverNonce: Buffer.alloc(32, 2),
    binding: NO_BINDING,
  };
  for (const bad of [Buffer.alloc(0), Buffer.alloc(31), Buffer.alloc(33), Buffer.alloc(32)]) {
    assert.equal(verifyServer(transcript, key, bad), false);
  }
  assert.ok(verifyServer(transcript, key, serverProof(transcript, key)));
});

/** Nonces come from the operating system, so two are never the same. */
test('nonces are unpredictable and correctly sized', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 64; i += 1) {
    const nonce = freshNonce();
    assert.equal(nonce.length, 32);
    seen.add(nonce.toString('hex'));
  }
  assert.equal(seen.size, 64, 'a nonce repeated');
});

/**
 * This build ships no dictionary, and must not start shipping one again by accident.
 *
 * It used to carry a megabyte copy of the node's, which had to stay byte-identical to it across
 * every reissue. The node now sends its own during the handshake, so nothing reads a file here — a
 * copy reappearing beside the package would be dead weight in every archive.
 */
test('no dictionary is shipped beside this package', () => {
  for (const path of ['../../../typescript/dictionary.bin', '../../../rust/dictionary.bin']) {
    assert.ok(
      !existsSync(fileURLToPath(new URL(path, import.meta.url))),
      `${path} is back; the node sends its dictionary during the handshake and nothing reads it`,
    );
  }
});

/**
 * Neither SDK carries a node address.
 *
 * This used to compare the endpoint baked into each, because a provisioning step that filled in one
 * and missed the other shipped two SDKs that disagreed about which node they talked to. The address
 * is now an argument, so there is nothing to keep in step and nothing to reissue when an operator
 * moves a node — but only while it stays that way. A constant reappearing in one SDK and not the
 * other would bring the whole class of problem back, so it is caught here rather than discovered by
 * a subscriber dialling somewhere that no longer exists.
 */
test('neither SDK bakes in a node address', () => {
  for (const path of ['../../../rust/src/defaults.rs', '../src/defaults.ts']) {
    assert.ok(
      !existsSync(fileURLToPath(new URL(path, import.meta.url))),
      `${path} is back; the address is an argument to connect, not a build-time constant`,
    );
  }
});

/**
 * The dictionary frame decodes to the bytes the server sent, under the id it named.
 *
 * This is the one frame a client must parse *during* the handshake, and getting it wrong does not
 * degrade: the connection comes up and every body afterwards is undecodable, for a reason nothing
 * on the wire explains. Pinned against the server's own bytes rather than this SDK's idea of them.
 */
test('a dictionary frame decodes to what the server sent', () => {
  const frame = load('dictionary_frame.bin');
  const header = readFrameHeader(frame);
  assert.equal(header.kind, FrameKind.Dictionary);
  assert.equal(header.seq, 0n, 'the dictionary is not part of the stream ordering');
  assert.equal(header.compressed, false, 'the dictionary arrived compressed');

  const body = frame.subarray(FRAME_HEADER_LEN, FRAME_HEADER_LEN + header.len);
  const parsed = readDictionary(body);

  const expected = load('dictionary.bin');
  assert.deepEqual(parsed.bytes, expected);
  // And the id it travels under is the hash of those bytes, so the pairing is self-checking.
  assert.equal(parsed.id, dictionaryId(expected));
  assert.equal(parsed.id, manifest.dictionary_frame.dictionary_id);
  assert.equal(parsed.bytes.length, manifest.dictionary_frame.dictionary_len);
});

/**
 * The greeting asks to be sent a dictionary, in the byte the server reads.
 *
 * A client that stopped setting this would still connect, still work, and silently stream at
 * roughly a third the compression — the exact failure this exchange exists to remove, and one
 * nothing else would catch.
 */
test('the greeting asks to be sent a dictionary', () => {
  const hello = load('hello.bin');
  const capabilities = hello.readUInt8(7);
  assert.equal(
    capabilities & Capability.ACCEPTS_DICTIONARY,
    Capability.ACCEPTS_DICTIONARY,
    'the greeting does not ask for a dictionary',
  );
  assert.equal(capabilities, manifest.hello.capabilities);
});

/**
 * This SDK's dictionary limit is the server's limit.
 *
 * Two independent constants for one protocol rule. If this client's were lower, a dictionary the
 * server is willing to send would be refused and every connection would fail; if it were higher,
 * this client would allocate for something the server would never produce.
 */
test('the dictionary limit matches the server', () => {
  assert.equal(MAX_DICTIONARY_BYTES, manifest.max_dictionary_bytes);
});

/**
 * A dictionary past the limit is refused on its declared length, before any body is taken.
 *
 * Otherwise an eight-byte message would be an instruction to allocate as much memory as the length
 * field can express.
 */
test('a dictionary past the limit is refused on its length alone', () => {
  const header = Buffer.alloc(DICTIONARY_HEADER_LEN);
  header.writeUInt32LE(1, 0);
  header.writeUInt32LE(MAX_DICTIONARY_BYTES + 1, 4);
  assert.throws(() => readDictionary(header), /limit/);

  // And exactly at the limit the length itself is accepted; only the missing body is complained of.
  const atLimit = Buffer.alloc(DICTIONARY_HEADER_LEN);
  atLimit.writeUInt32LE(1, 0);
  atLimit.writeUInt32LE(MAX_DICTIONARY_BYTES, 4);
  assert.throws(() => readDictionary(atLimit), /needs/);
});

/** A dictionary message round-trips, and a truncated one is refused rather than read short. */
test('a dictionary message round-trips and refuses truncation', () => {
  const bytes = load('dictionary.bin');
  const encoded = writeDictionary({ id: dictionaryId(bytes), bytes });
  const parsed = readDictionary(encoded);
  assert.equal(parsed.id, dictionaryId(bytes));
  assert.deepEqual(parsed.bytes, bytes);

  // Trailing bytes are ignored, so a future field can be appended without breaking this build.
  const padded = Buffer.concat([encoded, Buffer.from('a field that does not exist yet')]);
  assert.deepEqual(readDictionary(padded).bytes, bytes);

  for (const len of [0, 1, DICTIONARY_HEADER_LEN - 1, encoded.length - 1]) {
    assert.throws(() => readDictionary(encoded.subarray(0, len)), /needs/, `${len} bytes accepted`);
  }
});

/**
 * The bytes the cache holds are the bytes that were stored, and a corrupt entry is discarded.
 *
 * The cache is content-addressed, so a file that does not hash to its own name is either corrupt or
 * was written by something else. Offering it would have the node compress with one dictionary while
 * this side decoded with another — every frame unreadable, and the cause a file on disk rather than
 * anything on the wire.
 */
test('the dictionary cache round-trips and rejects a corrupt entry', () => {
  const dir = scratchDir('fixtures');
  try {
    const cache = new DictionaryCache(dir);
    const bytes = load('dictionary.bin');
    const id = dictionaryId(bytes);

    assert.equal(cache.load(id), null, 'an empty cache held something');
    assert.ok(cache.store(id, bytes));
    assert.deepEqual(cache.load(id), bytes);
    assert.deepEqual(cache.newest()?.bytes, bytes);

    // Bytes that do not match the id they are offered under are never written.
    assert.equal(cache.store(id + 1, bytes), false);

    // And an entry corrupted on disk is discarded rather than offered.
    writeFileSync(join(dir, `${(id >>> 0).toString(16).padStart(8, '0')}.dict`), 'not it');
    assert.equal(cache.load(id), null);
    assert.equal(cache.newest(), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * A dictionary stored right after another was loaded is the newer of the two.
 *
 * Exactly the sequence a connection performs: offer what the cache holds, be handed a different
 * one, store it. With no wait anywhere, because the bug this guards against only appears when the
 * two happen close together — a file's timestamp comes from a coarse clock that can lag the one an
 * explicit touch reads, so a load could outrank a later store and this client would go on offering
 * the dictionary it had just replaced, paying a megabyte on every connection.
 */
test('a dictionary stored after a load is the one offered next', () => {
  const dir = scratchDir('clock');
  try {
    const cache = new DictionaryCache(dir);
    const older = load('dictionary.bin');
    const newer = Buffer.from(older).reverse();
    assert.notEqual(dictionaryId(older), dictionaryId(newer));

    assert.ok(cache.store(dictionaryId(older), older));
    assert.equal(cache.newest()?.id, dictionaryId(older));
    assert.ok(cache.store(dictionaryId(newer), newer));
    assert.equal(
      cache.newest()?.id,
      dictionaryId(newer),
      'the replaced dictionary is still the one offered',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
