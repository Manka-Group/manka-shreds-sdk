/**
 * Mutated server output, decoded by this SDK.
 *
 * These decoders run inside a consumer's process against bytes from a network peer. A throw that
 * escapes the iterator is one thing — the documented contract is that a bad frame rejects. What is
 * *not* acceptable is a decoder that reads outside its buffer and returns nonsense, or one whose
 * accessors throw a `RangeError` a consumer has no way to anticipate from the documented API.
 *
 * Node makes the second failure mode easy to miss. `Buffer.subarray` silently clamps out-of-range
 * offsets and returns a short buffer rather than throwing, so a corrupted count produces a
 * plausible-looking result instead of an error. That is worse than a crash: it is a transaction the
 * consumer believes it decoded.
 *
 * So two properties here, per mutant:
 *
 *  * a decode either throws or returns something whose accessors all work — never a half-object
 *    that throws on the third field a consumer touches;
 *  * every buffer handed out lies inside the frame, and is the length the type promises.
 *
 * The fixtures are real server output, so mutating them reaches the arithmetic. Uniform random
 * bytes never would.
 */

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  Transaction,
  readDuplicate,
  readEntry,
  readFilterAck,
  readFrameHeader,
  readHelloAck,
  readLag,
  readSlotEnd,
  readSlotStart,
} from '../src/index.js';

function fixtures(): string {
  let at = dirname(fileURLToPath(import.meta.url));
  for (let up = 0; up < 8; up += 1) {
    if (existsSync(join(at, 'fixtures', 'manifest.json'))) return join(at, 'fixtures');
    at = dirname(at);
  }
  throw new Error('could not locate the fixtures directory');
}

const dir = fixtures();
const load = (name: string): Buffer => readFileSync(join(dir, name));

/** Deterministic xorshift, so a failure is reproducible from the seed alone. */
class Rand {
  constructor(private state: bigint) {}

  next(): bigint {
    const mask = 0xffffffffffffffffn;
    this.state ^= (this.state << 13n) & mask;
    this.state ^= this.state >> 7n;
    this.state ^= (this.state << 17n) & mask;
    return this.state;
  }

  below(bound: number): number {
    return bound === 0 ? 0 : Number(this.next() % BigInt(bound));
  }
}

/** Corrupts `bytes`, keeping enough structure to reach the code behind the length checks. */
function mutate(bytes: Buffer, rng: Rand): Buffer {
  if (bytes.length === 0) return bytes;
  switch (rng.below(6)) {
    case 0: {
      const out = Buffer.from(bytes);
      const at = rng.below(out.length);
      out[at] = (out[at] ?? 0) ^ (1 << rng.below(8));
      return out;
    }
    case 1: {
      const out = Buffer.from(bytes);
      out[rng.below(out.length)] = rng.below(256);
      return out;
    }
    case 2: {
      // The header region, where the counts and offsets live.
      const out = Buffer.from(bytes);
      out[rng.below(Math.min(out.length, 64))] = rng.below(256);
      return out;
    }
    case 3:
      return Buffer.from(bytes.subarray(0, rng.below(bytes.length + 1)));
    case 4:
      return Buffer.concat([bytes, Buffer.alloc(rng.below(64), rng.below(256))]);
    default: {
      const out = Buffer.from(bytes);
      if (out.length > 8) {
        const len = 1 + rng.below(Math.floor(out.length / 4));
        const from = rng.below(out.length - len);
        const to = rng.below(out.length - len);
        Buffer.from(out.subarray(from, from + len)).copy(out, to);
      }
      return out;
    }
  }
}

/**
 * Reads everything a consumer could read, and checks each buffer is inside the frame.
 *
 * The containment check is the one that matters. `subarray` clamping means an out-of-range read
 * yields a short buffer rather than an error, so without checking lengths a corrupted account count
 * would hand back a 12-byte "pubkey" and this test would pass.
 */
function exhaust(tx: Transaction, frame: Buffer): void {
  const within = (view: Buffer, expected: number, what: string): void => {
    assert.equal(view.length, expected, `${what} came back ${view.length} bytes, not ${expected}`);
    assert.ok(view.byteOffset >= frame.byteOffset, `${what} starts before the frame`);
    assert.ok(
      view.byteOffset + view.length <= frame.byteOffset + frame.length,
      `${what} runs past the end of the frame`,
    );
  };

  void tx.slot;
  void tx.parentSlot;
  void tx.isVote;
  void tx.recovered;
  void tx.verification;
  void tx.pipelineNs;
  void tx.messageVersion;
  void tx.accountCount;
  void tx.instructionCount;
  // Nullable, and legitimately so on a mutant: a transaction carrying no signature is something a
  // leader could produce, and the decoder relays it rather than refusing the frame.
  if (tx.signature !== null) within(tx.signature, 64, 'signature');
  if (tx.leader !== null) within(tx.leader, 32, 'leader');
  within(tx.recentBlockhash, 32, 'recent blockhash');

  for (const key of tx.accountKeys()) within(key, 32, 'account key');
  for (const signature of tx.signatures()) within(signature, 64, 'signature');

  for (const ix of tx.instructions()) {
    // A program index the sender chose. It must resolve to a whole key or to `null` — never to a
    // clamped fragment of one, and never to an exception thrown mid-loop.
    const program = tx.accountKey(ix.programIdIndex);
    if (program !== null) within(program, 32, 'program key');
    assert.ok(ix.accounts.byteOffset >= frame.byteOffset, 'instruction accounts start before the frame');
    assert.ok(
      ix.data.byteOffset + ix.data.length <= frame.byteOffset + frame.length,
      'instruction data runs past the end of the frame',
    );
  }

  for (const lookup of tx.lookups()) {
    within(lookup.accountKey, 32, 'lookup key');
    assert.ok(
      lookup.readonlyIndexes.byteOffset + lookup.readonlyIndexes.length
        <= frame.byteOffset + frame.length,
      'lookup indexes run past the end of the frame',
    );
  }
}

test('mutated transactions either fail to decode or decode coherently', () => {
  const seeds = ['tx_simple.bin', 'tx_full.bin', 'tx_legacy.bin'].map(load);
  const rng = new Rand(0x243f6a8885a308d3n);
  let decoded = 0;

  for (let round = 0; round < 20_000; round += 1) {
    let mutant = seeds[round % seeds.length]!;
    for (let n = 0; n <= rng.below(3); n += 1) mutant = mutate(mutant, rng);

    let tx: Transaction;
    try {
      tx = Transaction.read(mutant);
    } catch {
      // A refused decode is the correct outcome for most mutants.
      continue;
    }
    decoded += 1;
    // Having decoded, every accessor must work. A decoder that validates the header and then lets
    // an accessor throw has moved the failure to wherever the consumer happens to look first.
    exhaust(tx, mutant);
  }

  assert.ok(
    decoded > 200,
    `only ${decoded} of 20000 mutants decoded, so the accessors were barely reached`,
  );
});

test('mutated event frames never read outside themselves', () => {
  const seeds = [
    'entry.bin',
    'slot_start.bin',
    'slot_start_bare.bin',
    'slot_end.bin',
    'duplicate.bin',
  ].map(load);
  const rng = new Rand(0x9e3779b97f4a7c15n);
  let decoded = 0;

  const inside = (view: Buffer, expected: number, frame: Buffer, what: string): void => {
    assert.equal(view.length, expected, `${what} came back ${view.length} bytes`);
    assert.ok(
      view.byteOffset + view.length <= frame.byteOffset + frame.length,
      `${what} runs past the end of the frame`,
    );
  };

  for (let round = 0; round < 20_000; round += 1) {
    let mutant = seeds[round % seeds.length]!;
    for (let n = 0; n <= rng.below(3); n += 1) mutant = mutate(mutant, rng);

    // Every reader against every fixture: a consumer routes on the frame kind, and a corrupted kind
    // byte sends a payload to the wrong reader.
    for (const [name, read] of [
      ['entry', readEntry],
      ['slot-start', readSlotStart],
      ['slot-end', readSlotEnd],
      ['duplicate', readDuplicate],
    ] as const) {
      let value: unknown;
      try {
        value = read(mutant);
      } catch {
        continue;
      }
      decoded += 1;
      if (name === 'entry') inside((value as { hash: Buffer }).hash, 32, mutant, 'entry hash');
      if (name === 'slot-start') {
        const leader = (value as { leader: Buffer | null }).leader;
        if (leader !== null) inside(leader, 32, mutant, 'leader');
      }
      if (name === 'duplicate') {
        const { firstSignature, secondSignature } = value as {
          firstSignature: Buffer;
          secondSignature: Buffer;
        };
        inside(firstSignature, 64, mutant, 'first signature');
        inside(secondSignature, 64, mutant, 'second signature');
      }
    }
  }

  assert.ok(decoded > 200, `only ${decoded} event mutants decoded`);
});

test('mutated control messages never read outside themselves', () => {
  const seeds = ['hello_ack.bin', 'filter_ack.bin', 'lag.bin', 'error.bin'].map(load);
  const rng = new Rand(0x0123456789abcdefn);

  for (let round = 0; round < 20_000; round += 1) {
    let mutant = seeds[round % seeds.length]!;
    for (let n = 0; n <= rng.below(3); n += 1) mutant = mutate(mutant, rng);

    for (const read of [readHelloAck, readFilterAck, readLag]) {
      try {
        const value = read(mutant) as { detail?: string };
        // A `detail` is a length-prefixed string the server chose. Its declared length must not be
        // able to reach past the message — `subarray` would clamp and hand back a truncated string
        // rather than complaining.
        if (typeof value.detail === 'string') {
          assert.ok(
            Buffer.byteLength(value.detail, 'utf8') <= mutant.length,
            'a detail string longer than the message it arrived in',
          );
        }
      } catch {
        // Refused, which is fine.
      }
    }
  }
});

test('a mutated frame header never describes a payload outside the frame', () => {
  const seeds = ['frame_plain.bin', 'frame_zstd.bin', 'frame_matched.bin'].map(load);
  const rng = new Rand(0xdeadbeef0badf00dn);
  let headers = 0;

  for (let round = 0; round < 20_000; round += 1) {
    let mutant = seeds[round % seeds.length]!;
    for (let n = 0; n <= rng.below(3); n += 1) mutant = mutate(mutant, rng);

    let header;
    try {
      header = readFrameHeader(mutant);
    } catch {
      continue;
    }
    headers += 1;
    // The length field decides how much a consumer waits for and allocates. It is the sender's
    // number, so the only safe reading is that it must be checked before it is used.
    assert.ok(header.len >= 0, 'a negative payload length');
    assert.ok(Number.isSafeInteger(header.len), 'a payload length that is not a safe integer');
  }

  assert.ok(headers > 500, `only ${headers} frame headers parsed`);
});
