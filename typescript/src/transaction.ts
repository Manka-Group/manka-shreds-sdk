/**
 * The transaction message.
 *
 * A fixed 104-byte header followed by sections in a fixed order, each 8-byte aligned:
 *
 * ```text
 *   0  u64  slot                 64  u32  fec_set_index
 *   8  u64  parent_slot          68  u32  entry_index
 *  16  u64  rx_ts_ns             72  u32  tx_index
 *  24  u64  emit_ts_ns           76  u32  instruction_bytes_len
 *  32  [32] leader               80  u32  lookup_bytes_len
 *                                84  u32  raw_tx_len
 *                                88  u16  source_id
 *                                90  u16  flags
 *                                92  u16  account_count
 *                                94  u16  instruction_count
 *                                96  u8   signature_count
 *                                97  u8   message_version   (0xff = legacy)
 *                                98  u8   lookup_count
 *                                99  u8   required_signatures
 *                               100  u8   readonly_signed
 *                               101  u8   readonly_unsigned
 *                               102  u16  reserved
 * 104     signatures         signature_count * 64
 *         account_keys       account_count * 32
 *         recent_blockhash   32
 *         instruction_table  instruction_count * 16
 *         instruction_bytes  padded to 8
 *         lookup_table       lookup_count * 40
 *         lookup_bytes       padded to 8
 *         raw_tx             raw_tx_len, only when the flag is set
 * ```
 *
 * The fixed offsets are what make reading cheap: every field is a load at a known position and
 * every byte string is a `subarray`, never a copy. Nothing is decoded until it is asked for, so a
 * subscriber that only looks at, say, the first account key never pays for the rest.
 */

import { ProtocolError, Verification } from './protocol.js';

/** Bytes in the fixed header. */
export const TX_HEADER_LEN = 104;
/** Bytes in one instruction table entry. */
export const INSTRUCTION_ENTRY_LEN = 16;
/** Bytes in one address lookup table entry. */
export const LOOKUP_ENTRY_LEN = 40;

/** Bits in the transaction header's flag field. */
export const TxFlag = {
  /** The transaction is a simple vote. */
  IS_VOTE: 1 << 0,
  /** The FEC set's leader signature verified. */
  VERIFIED: 1 << 1,
  /** The raw transaction bytes are appended. */
  HAS_RAW_TX: 1 << 2,
  /** The FEC set had to be reconstructed from parity. */
  RECOVERED: 1 << 3,
  /** The leader was known and named in the header. */
  HAS_LEADER: 1 << 4,
} as const;

const REASON_SHIFT = 5;
const REASON_MASK = 0b11;

/** Marks a legacy (pre-versioned) message. */
export const MESSAGE_VERSION_LEGACY = 0xff;

/** One instruction, pointing into the message's shared byte region. */
export interface Instruction {
  /** Index into `accountKeys` of the program being invoked. */
  programIdIndex: number;
  /** Indices into `accountKeys`, in the order the program expects them. */
  accounts: Buffer;
  /** Opaque instruction data. */
  data: Buffer;
}

/** One address lookup table reference, carried unresolved. */
export interface AddressLookup {
  /** The lookup table account. */
  accountKey: Buffer;
  /** Indices loaded as writable. */
  writableIndexes: Buffer;
  /** Indices loaded as readonly. */
  readonlyIndexes: Buffer;
}

/** Rounds up to a multiple of 8. */
function align8(len: number): number {
  return (len + 7) & ~7;
}

/**
 * A decoded transaction.
 *
 * Backed directly by the received buffer. Accessors return `subarray` views, which means they are
 * valid only as long as the underlying buffer is — copy anything kept past the callback with
 * `Buffer.from(...)`.
 */
export class Transaction {
  private readonly signaturesAt: number;
  private readonly accountKeysAt: number;
  private readonly blockhashAt: number;
  private readonly instructionTableAt: number;
  private readonly instructionBytesAt: number;
  private readonly lookupTableAt: number;
  private readonly lookupBytesAt: number;
  private readonly rawTxAt: number;

  private constructor(readonly bytes: Buffer) {
    const need = (end: number): never => {
      throw new ProtocolError(`transaction needs ${end} bytes, have ${bytes.length}`);
    };
    let at = TX_HEADER_LEN;
    const take = (len: number): number => {
      const start = at;
      at += len;
      if (at > bytes.length) need(at);
      return start;
    };

    this.signaturesAt = take(this.signatureCount * 64);
    this.accountKeysAt = take(this.accountCount * 32);
    this.blockhashAt = take(32);
    this.instructionTableAt = take(this.instructionCount * INSTRUCTION_ENTRY_LEN);
    const instructionBytesLen = this.bytes.readUInt32LE(76);
    this.instructionBytesAt = take(align8(instructionBytesLen));
    this.lookupTableAt = take(this.lookupCount * LOOKUP_ENTRY_LEN);
    const lookupBytesLen = this.bytes.readUInt32LE(80);
    this.lookupBytesAt = take(align8(lookupBytesLen));
    this.rawTxAt = take(this.bytes.readUInt32LE(84));

    // Table entries are offsets into their own byte region. Checking them once here is what lets
    // every accessor below slice without a bounds test.
    for (let i = 0; i < this.instructionCount; i += 1) {
      const entry = this.instructionTableAt + i * INSTRUCTION_ENTRY_LEN;
      const accountsEnd = bytes.readUInt16LE(entry + 2) + bytes.readUInt16LE(entry + 4);
      const dataEnd = bytes.readUInt32LE(entry + 8) + bytes.readUInt32LE(entry + 12);
      if (accountsEnd > instructionBytesLen || dataEnd > instructionBytesLen) {
        throw new ProtocolError(`instruction ${i} points outside its byte region`);
      }
    }
    for (let i = 0; i < this.lookupCount; i += 1) {
      const entry = this.lookupTableAt + i * LOOKUP_ENTRY_LEN;
      const writableEnd = bytes.readUInt16LE(entry + 32) + bytes.readUInt16LE(entry + 34);
      const readonlyEnd = bytes.readUInt16LE(entry + 36) + bytes.readUInt16LE(entry + 38);
      if (writableEnd > lookupBytesLen || readonlyEnd > lookupBytesLen) {
        throw new ProtocolError(`lookup ${i} points outside its byte region`);
      }
    }
  }

  /** Reads a transaction, validating that every section is present. */
  static read(bytes: Buffer): Transaction {
    if (bytes.length < TX_HEADER_LEN) {
      throw new ProtocolError(`transaction header needs ${TX_HEADER_LEN} bytes, have ${bytes.length}`);
    }
    return new Transaction(bytes);
  }

  /** Slot the transaction landed in. */
  get slot(): bigint {
    return this.bytes.readBigUInt64LE(0);
  }

  /** The slot this one builds on. */
  get parentSlot(): bigint {
    return this.bytes.readBigUInt64LE(8);
  }

  /** When the first shred of the FEC set arrived, on the server's monotonic clock. */
  get rxTsNs(): bigint {
    return this.bytes.readBigUInt64LE(16);
  }

  /** When the server finished encoding this message, on the same clock as `rxTsNs`. */
  get emitTsNs(): bigint {
    return this.bytes.readBigUInt64LE(24);
  }

  /**
   * How long the server took from first shred to encoded message.
   *
   * Both stamps come from one monotonic clock, so this is meaningful; neither can be compared
   * against a local wall clock.
   */
  get pipelineNs(): bigint {
    return this.emitTsNs - this.rxTsNs;
  }

  /** Leader assigned to the slot, when the schedule knew one. */
  get leader(): Buffer | null {
    return this.has(TxFlag.HAS_LEADER) ? this.bytes.subarray(32, 64) : null;
  }

  /** Erasure set this transaction was carried in. */
  get fecSetIndex(): number {
    return this.bytes.readUInt32LE(64);
  }

  /** Index of the entry within the slot. */
  get entryIndex(): number {
    return this.bytes.readUInt32LE(68);
  }

  /** Index of the transaction within its entry. */
  get txIndex(): number {
    return this.bytes.readUInt32LE(72);
  }

  /** Which ingress source delivered the shreds. */
  get sourceId(): number {
    return this.bytes.readUInt16LE(88);
  }

  /** Raw header flags. Prefer the named accessors. */
  get flags(): number {
    return this.bytes.readUInt16LE(90);
  }

  private has(bits: number): boolean {
    return (this.flags & bits) === bits;
  }

  /** Whether this is a simple vote transaction. */
  get isVote(): boolean {
    return this.has(TxFlag.IS_VOTE);
  }

  /** Whether the FEC set had to be reconstructed from parity shreds. */
  get recovered(): boolean {
    return this.has(TxFlag.RECOVERED);
  }

  /** How much the server could vouch for this transaction. */
  get verification(): Verification {
    if (this.has(TxFlag.VERIFIED)) return Verification.Verified;
    switch ((this.flags >> REASON_SHIFT) & REASON_MASK) {
      case 1:
        return Verification.UnknownLeader;
      case 2:
        return Verification.StaleSchedule;
      default:
        return Verification.Disabled;
    }
  }

  /** Number of account keys carried in the message. */
  get accountCount(): number {
    return this.bytes.readUInt16LE(92);
  }

  /** Number of instructions. */
  get instructionCount(): number {
    return this.bytes.readUInt16LE(94);
  }

  /** Number of signatures. */
  get signatureCount(): number {
    return this.bytes.readUInt8(96);
  }

  /** Message version, or {@link MESSAGE_VERSION_LEGACY} for a legacy message. */
  get messageVersion(): number {
    return this.bytes.readUInt8(97);
  }

  /** Number of address lookup table references. */
  get lookupCount(): number {
    return this.bytes.readUInt8(98);
  }

  /** Signatures the message requires. */
  get requiredSignatures(): number {
    return this.bytes.readUInt8(99);
  }

  /** Signed accounts that are readonly. */
  get readonlySigned(): number {
    return this.bytes.readUInt8(100);
  }

  /** Unsigned accounts that are readonly. */
  get readonlyUnsigned(): number {
    return this.bytes.readUInt8(101);
  }

  /**
   * The transaction's first signature — its id. `null` if it carries none.
   *
   * Every real transaction is signed, so this is `null` only for something a leader should never
   * have put in a block. It is nullable rather than throwing because the node is a relay, not a
   * validator: it forwards what the leader signed into the shred, and refusing the frame or
   * throwing from an accessor would let a leader knock subscribers off the stream. `null` is
   * something a consumer can skip; an exception from a property read, thrown well outside whatever
   * `try` guarded the decode, is not.
   */
  get signature(): Buffer | null {
    if (this.signatureCount === 0) return null;
    return this.bytes.subarray(this.signaturesAt, this.signaturesAt + 64);
  }

  /** Every signature, in order. */
  signatures(): Buffer[] {
    const out: Buffer[] = [];
    for (let i = 0; i < this.signatureCount; i += 1) {
      const at = this.signaturesAt + i * 64;
      out.push(this.bytes.subarray(at, at + 64));
    }
    return out;
  }

  /**
   * One account key, by index. `null` if the index is past the end.
   *
   * Nullable because the index usually is not the caller's: `instruction.programIdIndex` comes off
   * the wire, and a transaction naming an index past its own account list is something a leader can
   * produce. Throwing here would turn that into an exception in the middle of a `for` loop over
   * instructions — the pattern this package's own documentation shows.
   */
  accountKey(index: number): Buffer | null {
    if (index < 0 || index >= this.accountCount) return null;
    const at = this.accountKeysAt + index * 32;
    return this.bytes.subarray(at, at + 32);
  }

  /** Every account key, in the order the message declared them. */
  accountKeys(): Buffer[] {
    const out: Buffer[] = [];
    for (let i = 0; i < this.accountCount; i += 1) {
      const at = this.accountKeysAt + i * 32;
      out.push(this.bytes.subarray(at, at + 32));
    }
    return out;
  }

  /** The blockhash the transaction was signed against. */
  get recentBlockhash(): Buffer {
    return this.bytes.subarray(this.blockhashAt, this.blockhashAt + 32);
  }

  /** One instruction, by index. `null` if the index is past the end. */
  instruction(index: number): Instruction | null {
    if (index < 0 || index >= this.instructionCount) return null;
    const entry = this.instructionTableAt + index * INSTRUCTION_ENTRY_LEN;
    const base = this.instructionBytesAt;
    const accountsOff = base + this.bytes.readUInt16LE(entry + 2);
    const dataOff = base + this.bytes.readUInt32LE(entry + 8);
    return {
      programIdIndex: this.bytes.readUInt8(entry),
      accounts: this.bytes.subarray(accountsOff, accountsOff + this.bytes.readUInt16LE(entry + 4)),
      data: this.bytes.subarray(dataOff, dataOff + this.bytes.readUInt32LE(entry + 12)),
    };
  }

  /** Every instruction, in execution order. */
  instructions(): Instruction[] {
    const out: Instruction[] = [];
    for (let i = 0; i < this.instructionCount; i += 1) {
      // In range by construction, so the `null` case cannot arise here.
      const instruction = this.instruction(i);
      if (instruction !== null) out.push(instruction);
    }
    return out;
  }

  /**
   * Every address lookup table reference, unresolved.
   *
   * Resolving these needs the lookup tables' account state, which a shred pipeline does not have.
   * A consumer that needs the resolved keys must fetch the tables itself.
   */
  lookups(): AddressLookup[] {
    const out: AddressLookup[] = [];
    for (let i = 0; i < this.lookupCount; i += 1) {
      const entry = this.lookupTableAt + i * LOOKUP_ENTRY_LEN;
      const base = this.lookupBytesAt;
      const writableOff = base + this.bytes.readUInt16LE(entry + 32);
      const readonlyOff = base + this.bytes.readUInt16LE(entry + 36);
      out.push({
        accountKey: this.bytes.subarray(entry, entry + 32),
        writableIndexes: this.bytes.subarray(
          writableOff,
          writableOff + this.bytes.readUInt16LE(entry + 34),
        ),
        readonlyIndexes: this.bytes.subarray(
          readonlyOff,
          readonlyOff + this.bytes.readUInt16LE(entry + 38),
        ),
      });
    }
    return out;
  }

  /**
   * The original transaction bytes, when the server was asked to include them.
   *
   * Off by default: the decoded form above carries the same information, and repeating the bytes
   * roughly doubles the stream's bandwidth.
   */
  get rawTx(): Buffer | null {
    if (!this.has(TxFlag.HAS_RAW_TX)) return null;
    return this.bytes.subarray(this.rawTxAt, this.rawTxAt + this.bytes.readUInt32LE(84));
  }
}
