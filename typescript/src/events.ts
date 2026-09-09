/**
 * Frames other than transactions: slot boundaries, entries and equivocation reports.
 *
 * Each is a fixed-size little-endian record with no variable tail, so reading one is a bounds check
 * and a handful of loads.
 *
 * # Why entries carry no transaction bytes
 *
 * An entry's transactions already travel on the transaction stream, each carrying the `entryIndex`
 * that puts it back in its entry. Repeating the bytes here would double the bandwidth of a
 * subscriber taking both streams to say nothing new. What the entry frame adds is the structure
 * around them: the PoH hash, the hash count, and how many transactions the entry claimed — which is
 * what lets a subscriber notice one is missing.
 */

import { ProtocolError, Verification } from './protocol.js';

function require_(bytes: Buffer, need: number, what: string): void {
  if (bytes.length < need) {
    throw new ProtocolError(`${what} needs ${need} bytes, have ${bytes.length}`);
  }
}

function decodeVerification(byte: number): Verification {
  switch (byte) {
    case 0:
      return Verification.Verified;
    case 2:
      return Verification.UnknownLeader;
    case 3:
      return Verification.StaleSchedule;
    default:
      return Verification.Disabled;
  }
}

/** Bytes in an encoded slot start. */
export const SLOT_START_LEN = 64;
/** Bytes in an encoded slot end. */
export const SLOT_END_LEN = 48;
/** Bytes in an encoded entry. */
export const ENTRY_LEN = 88;
/** Bytes in an encoded duplicate report. */
export const DUPLICATE_LEN = 160;

/** The first shred of a slot arrived. */
export interface SlotStart {
  slot: bigint;
  /** Present once a shred declaring the parent has arrived. */
  parentSlot: bigint | null;
  /** The slot's leader, when the schedule knew one. */
  leader: Buffer | null;
  /** When the first shred arrived, on the server's monotonic clock. */
  rxTsNs: bigint;
  source: number;
  shredVersion: number;
}

/** Reads a slot start. */
export function readSlotStart(bytes: Buffer): SlotStart {
  require_(bytes, SLOT_START_LEN, 'slot start');
  const flags = bytes.readUInt8(60);
  return {
    slot: bytes.readBigUInt64LE(0),
    parentSlot: (flags & 1) !== 0 ? bytes.readBigUInt64LE(8) : null,
    leader: (flags & 2) !== 0 ? bytes.subarray(16, 48) : null,
    rxTsNs: bytes.readBigUInt64LE(48),
    source: bytes.readUInt16LE(56),
    shredVersion: bytes.readUInt16LE(58),
  };
}

/** A slot finished, either completed or given up on. */
export interface SlotEnd {
  slot: bigint;
  parentSlot: bigint;
  dataShreds: number;
  fecSets: number;
  /** Sets that had to be reconstructed from parity. */
  recoveredSets: number;
  /** Shreds never seen and never recoverable. */
  missingShreds: number;
  /** When the slot was retired, on the server's monotonic clock. */
  endTsNs: bigint;
  /** Whether the slot was seen whole. False means shreds were lost. */
  complete: boolean;
}

/** Reads a slot end. */
export function readSlotEnd(bytes: Buffer): SlotEnd {
  require_(bytes, SLOT_END_LEN, 'slot end');
  return {
    slot: bytes.readBigUInt64LE(0),
    parentSlot: bytes.readBigUInt64LE(8),
    dataShreds: bytes.readUInt32LE(16),
    fecSets: bytes.readUInt32LE(20),
    recoveredSets: bytes.readUInt32LE(24),
    missingShreds: bytes.readUInt32LE(28),
    endTsNs: bytes.readBigUInt64LE(32),
    complete: (bytes.readUInt8(40) & 1) !== 0,
  };
}

/** One proof-of-history entry. */
export interface Entry {
  slot: bigint;
  parentSlot: bigint;
  rxTsNs: bigint;
  /** PoH hashes since the previous entry. Zero marks a tick-free entry. */
  numHashes: bigint;
  /** How many transactions the entry claimed — compare against what arrived. */
  txCount: bigint;
  /** The entry's PoH hash. */
  hash: Buffer;
  fecSetIndex: number;
  entryIndex: number;
  verification: Verification;
}

/** Reads an entry. */
export function readEntry(bytes: Buffer): Entry {
  require_(bytes, ENTRY_LEN, 'entry');
  return {
    slot: bytes.readBigUInt64LE(0),
    parentSlot: bytes.readBigUInt64LE(8),
    rxTsNs: bytes.readBigUInt64LE(16),
    numHashes: bytes.readBigUInt64LE(24),
    txCount: bytes.readBigUInt64LE(32),
    hash: bytes.subarray(40, 72),
    fecSetIndex: bytes.readUInt32LE(72),
    entryIndex: bytes.readUInt32LE(76),
    verification: decodeVerification(bytes.readUInt8(80)),
  };
}

/**
 * Two different shreds arrived for one slot and index — the leader equivocated.
 *
 * Both signatures are carried so the report can be checked independently.
 */
export interface Duplicate {
  slot: bigint;
  index: number;
  firstSource: number;
  secondSource: number;
  /** When the conflict was noticed, on the server's monotonic clock. */
  detectedNs: bigint;
  /** Whether the conflicting shreds were data shreds rather than parity. */
  isData: boolean;
  firstSignature: Buffer;
  secondSignature: Buffer;
}

/** Reads a duplicate report. */
export function readDuplicate(bytes: Buffer): Duplicate {
  require_(bytes, DUPLICATE_LEN, 'duplicate');
  return {
    slot: bytes.readBigUInt64LE(0),
    index: bytes.readUInt32LE(8),
    firstSource: bytes.readUInt16LE(12),
    secondSource: bytes.readUInt16LE(14),
    detectedNs: bytes.readBigUInt64LE(16),
    isData: bytes.readUInt8(24) !== 0,
    firstSignature: bytes.subarray(32, 96),
    secondSignature: bytes.subarray(96, 160),
  };
}

/**
 * A shred republished exactly as it arrived.
 *
 * # What this stream is
 *
 * Every other event is a *conclusion* the node reached — a transaction it decoded, a slot it judged
 * finished. This is the evidence those were drawn from, handed to you at the moment the node
 * received it, before it verified or decoded anything.
 *
 * **Nothing here is claimed to be leader-signed.** A shred is republished as soon as it survives
 * deduplication; the signature check happens later, on the FEC set as a whole. If you need the
 * guarantee, take `transactions`, which carries it. If you need the latency and run your own
 * pipeline, this is for you.
 *
 * Two things it deliberately is not. **Not recovered**: a shred rebuilt from parity is not
 * republished, so a gap here is a real loss rather than an artefact, and your own count matches the
 * network's. **Not filtered**: a shred is a fragment of an erasure set, not yet anything a filter
 * can match on.
 *
 * It is the highest-rate stream a node publishes. Take it only if you are consuming it.
 */
export interface RawShred {
  /** Slot the shred belongs to. */
  slot: bigint;
  /**
   * Index within the slot, scoped by `isData`.
   *
   * A data shred and a coding shred may share an index. Key on the pair, not on the index alone.
   */
  index: number;
  /** Index of the first data shred of the FEC set this belongs to. */
  fecSetIndex: number;
  /** When the node received it, on the server's monotonic clock. */
  rxTsNs: bigint;
  /** Which configured source delivered it first. */
  source: number;
  /** Whether this is a data shred rather than parity. */
  isData: boolean;
  /** The shred exactly as it arrived, ready for a parser that expects one. */
  bytes: Buffer;
}

/** Bytes before a raw shred's payload. */
export const RAW_SHRED_HEADER_LEN = 32;

/** Decodes a republished shred, borrowing the payload rather than copying it. */
export function readRawShred(bytes: Buffer): RawShred {
  require_(bytes, RAW_SHRED_HEADER_LEN, 'raw shred');
  return {
    slot: bytes.readBigUInt64LE(0),
    index: bytes.readUInt32LE(8),
    fecSetIndex: bytes.readUInt32LE(12),
    rxTsNs: bytes.readBigUInt64LE(16),
    source: bytes.readUInt16LE(24),
    // Anything other than the parity marker is data: a kind byte this build does not know is a
    // newer node, and refusing the frame would break you over a field you do not use.
    isData: bytes.readUInt8(26) !== 1,
    bytes: bytes.subarray(RAW_SHRED_HEADER_LEN),
  };
}
