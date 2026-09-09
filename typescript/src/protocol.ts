/**
 * The manka-shreds wire protocol: frames, control messages and message layouts.
 *
 * Everything here is byte layout. It is kept separate from the client so that a consumer wanting
 * to drive the protocol some other way — a browser transport, a different runtime, a proxy — can
 * use the parsing without the socket handling.
 *
 * Offsets are fixed and every section is 8-byte aligned, which is why fields are read by pointing
 * at them rather than by walking length prefixes.
 */

/** Protocol version this implementation speaks. */
export const PROTOCOL_VERSION = 1;

/** Bytes in a frame header. */
export const FRAME_HEADER_LEN = 16;

/** Largest payload a frame may carry. */
export const MAX_FRAME_PAYLOAD = 16 << 20;

/** What a frame carries. */
export enum FrameKind {
  /** A kind this build does not recognise. Never sent; produced when reading. */
  Unknown = 0,
  Transaction = 1,
  Entry = 2,
  SlotStart = 3,
  SlotEnd = 4,
  Duplicate = 5,
  RawShred = 6,
  Lag = 7,
  SourceStats = 8,
  Hello = 9,
  HelloAck = 10,
  FilterAck = 11,
  Error = 12,
  Ping = 13,
  Pong = 14,
  SetFilter = 15,
  /** The server's nonce and its proof that it holds the key. */
  Challenge = 16,
  /** The client's proof that it holds the key. */
  Prove = 17,
  /** The compression dictionary the server wants this connection to use. */
  Dictionary = 18,
}

/** Streams a subscriber may ask for. A key grants a subset; the server grants the intersection. */
export const Stream = {
  TRANSACTIONS: 1 << 0,
  ENTRIES: 1 << 1,
  SLOT_EVENTS: 1 << 2,
  DUPLICATES: 1 << 3,
  /**
   * Every shred verbatim, before the node verifies or decodes anything.
   *
   * The highest-rate stream published — a multiple of `TRANSACTIONS`, since a shred is a fragment
   * and most fragments carry votes. Nothing on it is claimed to be leader-signed.
   */
  RAW_SHREDS: 1 << 4,
  /** Reserved on the wire; no producer exists and the name is refused at key load. */
  SOURCE_STATS: 1 << 5,
  VOTES: 1 << 6,
} as const;

/** Every stream that is actually published. */
export const ALL_STREAMS =
  Stream.TRANSACTIONS |
  Stream.ENTRIES |
  Stream.SLOT_EVENTS |
  Stream.DUPLICATES |
  Stream.RAW_SHREDS |
  Stream.VOTES;

/** Compression codecs. The value is what travels in the frame flags. */
export enum Codec {
  None = 0,
  Lz4 = 1,
  Zstd = 2,
}

/** Bits offered in a handshake, one per codec this client can decode. */
export const CodecBit = {
  NONE: 1 << 0,
  LZ4: 1 << 1,
  ZSTD: 1 << 2,
} as const;

/**
 * What a client can accept beyond the streams it subscribes to.
 *
 * A bitmask in the greeting, in a byte that was previously padding. Absent bits mean "no", which is
 * what a client built before this existed should be taken to have said.
 */
export const Capability = {
  /**
   * This client will accept the server's compression dictionary on this connection.
   *
   * Without it the server never sends one. With it, a client holding no dictionary — or a different
   * one — is brought up to the server's during the handshake and streams at the full ratio from its
   * first message, rather than paying roughly three times the bandwidth until somebody notices it
   * was never given one.
   */
  ACCEPTS_DICTIONARY: 1 << 0,
} as const;

/**
 * Largest dictionary this client will accept from a server.
 *
 * The one thing a server hands a client that is neither fixed-width nor bounded by something the
 * client asked for, so it needs a bound of its own — otherwise a hostile or compromised node
 * streams as much "dictionary" as this side will allocate. Far past any dictionary worth training:
 * the ratio stops improving well below it.
 */
export const MAX_DICTIONARY_BYTES = 8 << 20;

/**
 * Largest control message this client will read while the handshake is in progress.
 *
 * A challenge is sixty-four bytes and an acknowledgement is smaller; the only variable one is an
 * error, whose detail is a sentence. It needs a bound because the length is the *server's* to
 * choose and it is what this side buffers against — and at this point in the exchange the server
 * has proved nothing. Judged by {@link MAX_FRAME_PAYLOAD} instead, any address you dial could hold
 * sixteen megabytes of yours for the price of a header.
 *
 * The dictionary is the one handshake frame this does not apply to; it has
 * {@link MAX_DICTIONARY_BYTES} of its own, and it arrives only after the server has proved itself.
 */
export const MAX_HANDSHAKE_BYTES = 64 * 1024;

/** The compression dictionary a connection will use, as the server sends it. */
export interface Dictionary {
  /** Identifier of these bytes, matching what the acknowledgement announced. */
  id: number;
  /** The dictionary itself. */
  bytes: Buffer;
}

/** Bytes before a dictionary's payload. */
export const DICTIONARY_HEADER_LEN = 8;

/**
 * Reads a dictionary message, refusing one larger than {@link MAX_DICTIONARY_BYTES}.
 *
 * The declared length is checked *before* the body is taken, so a number a peer invented cannot
 * decide how much this side allocates.
 */
export function readDictionary(buf: Buffer): Dictionary {
  if (buf.length < DICTIONARY_HEADER_LEN) {
    throw new ProtocolError(
      `dictionary needs ${DICTIONARY_HEADER_LEN} bytes, have ${buf.length}`,
    );
  }
  const id = buf.readUInt32LE(0);
  const len = buf.readUInt32LE(4);
  if (len > MAX_DICTIONARY_BYTES) {
    throw new ProtocolError(
      `the server sent a ${len}-byte dictionary; the limit is ${MAX_DICTIONARY_BYTES}`,
    );
  }
  if (buf.length < DICTIONARY_HEADER_LEN + len) {
    throw new ProtocolError(
      `dictionary needs ${DICTIONARY_HEADER_LEN + len} bytes, have ${buf.length}`,
    );
  }
  return {
    id,
    // Copied rather than sliced: a subarray keeps the whole read buffer alive, and this one is
    // held for the life of the connection.
    bytes: Buffer.from(buf.subarray(DICTIONARY_HEADER_LEN, DICTIONARY_HEADER_LEN + len)),
  };
}

/**
 * Encodes a dictionary message.
 *
 * A client never sends one. This exists so a test can build what a server would.
 */
export function writeDictionary(dictionary: Dictionary): Buffer {
  const out = Buffer.allocUnsafe(DICTIONARY_HEADER_LEN + dictionary.bytes.length);
  out.writeUInt32LE(dictionary.id, 0);
  out.writeUInt32LE(dictionary.bytes.length, 4);
  dictionary.bytes.copy(out, DICTIONARY_HEADER_LEN);
  return out;
}

/** Why the server refused or closed. */
export enum ErrorCode {
  Unauthorized = 1,
  Forbidden = 2,
  TooSlow = 3,
  RateLimited = 4,
  BadRequest = 5,
  Shutdown = 6,
  UnsupportedVersion = 7,
}

/** How much a transaction's FEC set could be vouched for. */
export enum Verification {
  /** The leader's signature over the set's merkle root checked out. */
  Verified = 'verified',
  /** The node runs with verification switched off. */
  Disabled = 'disabled',
  /** No leader is known for the slot. */
  UnknownLeader = 'unknown-leader',
  /** The leader schedule is behind. */
  StaleSchedule = 'stale-schedule',
}

/** A decoded frame header. */
export interface FrameHeader {
  /** Payload bytes following the header. */
  len: number;
  /** What the payload is, as far as this build recognises it. */
  kind: FrameKind;
  /** The kind byte exactly as it arrived, so an unknown frame keeps its identity. */
  rawKind: number;
  /** Whether the payload is compressed. */
  compressed: boolean;
  /** Codec the payload was compressed with. */
  codec: Codec;
  /**
   * Which of this connection's named filters the frame matched, as a bitmask.
   *
   * Zero when the connection named no filters. Bit `i` is the filter at index `i` in the set that
   * was submitted; one transaction can match several and is delivered once with every match
   * recorded, rather than once per filter.
   */
  matched: number;
  /** Per-connection sequence number. A gap is exactly what was dropped. */
  seq: bigint;
}

/**
 * Reads a frame header.
 *
 * An unrecognised kind is not an error: a client built before a frame type existed must skip it,
 * not drop the connection, or adding one would break every deployed subscriber.
 */
export function readFrameHeader(buf: Buffer, at = 0): FrameHeader {
  if (buf.length - at < FRAME_HEADER_LEN) {
    throw new ProtocolError(`frame header needs ${FRAME_HEADER_LEN} bytes, have ${buf.length - at}`);
  }
  const len = buf.readUInt32LE(at);
  if (len > MAX_FRAME_PAYLOAD) {
    throw new ProtocolError(`frame declares ${len} payload bytes, limit is ${MAX_FRAME_PAYLOAD}`);
  }
  const rawKind = buf.readUInt8(at + 4);
  const flags = buf.readUInt8(at + 5);
  return {
    len,
    kind: rawKind in FrameKind ? (rawKind as FrameKind) : FrameKind.Unknown,
    rawKind,
    compressed: (flags & 0b100) !== 0,
    codec: (flags & 0b11) as Codec,
    matched: buf.readUInt16LE(at + 6),
    seq: buf.readBigUInt64LE(at + 8),
  };
}

/** Writes a frame with `payload` as its body. */
export function writeFrame(
  kind: FrameKind,
  seq: bigint,
  payload: Buffer,
  matched = 0,
): Buffer {
  const out = Buffer.allocUnsafe(FRAME_HEADER_LEN + payload.length);
  out.writeUInt32LE(payload.length, 0);
  out.writeUInt8(kind, 4);
  out.writeUInt8(0, 5);
  out.writeUInt16LE(matched, 6);
  out.writeBigUInt64LE(seq, 8);
  payload.copy(out, FRAME_HEADER_LEN);
  return out;
}

/** Anything the protocol could not be read as. */
export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}

/** The server refused the connection, or closed it. */
export class ServerError extends Error {
  constructor(
    readonly code: ErrorCode,
    readonly detail: string,
  ) {
    super(`server error ${ErrorCode[code] ?? code}: ${detail}`);
    this.name = 'ServerError';
  }
}

// ---------------------------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------------------------

/**
 * What a client offers when it connects.
 *
 * **Carries no credential.** Your key is named by a one-way reference and proved afterwards — see
 * `handshake`. A captured greeting is worth nothing.
 */
export interface Hello {
  streams: number;
  codecs: number;
  /** Which key is claimed, without disclosing it. 32 bytes. */
  keyRef: Buffer;
  /** Fresh per connection, so a captured server proof cannot be replayed at this client. 32 bytes. */
  clientNonce: Buffer;
  /**
   * What this client can be sent beyond the streams themselves — see {@link Capability}.
   *
   * Occupies a byte the greeting has always written as zero and never read, so a client built
   * before this existed advertises nothing, which is the correct reading of its silence.
   */
  capabilities: number;
  /** Content hash of the dictionary this client holds, or zero for none. */
  dictionaryId: number;
  /** A filter document to install before the stream starts, if any. */
  filter?: string;
}

/**
 * Encodes a greeting.
 *
 * The reference and the nonce are fixed width, so the greeting has no variable-length credential
 * fields — there is no credential in it to be variable. The dictionary id trails them so a peer that
 * stops reading there still parses: a missing id simply means no dictionary. The filter trails that
 * in turn, length-prefixed with a `u32` because a filter naming two thousand accounts is far past
 * 64 KiB.
 */
export function writeHello(hello: Hello): Buffer {
  const filter = hello.filter === undefined ? undefined : Buffer.from(hello.filter, 'utf8');
  const base = 8 + 32 + 32 + 4;
  const out = Buffer.allocUnsafe(base + (filter === undefined ? 0 : 4 + filter.length));
  out.writeUInt16LE(PROTOCOL_VERSION, 0);
  out.writeUInt32LE(hello.streams, 2);
  out.writeUInt8(hello.codecs, 6);
  out.writeUInt8(hello.capabilities, 7);
  hello.keyRef.copy(out, 8);
  hello.clientNonce.copy(out, 40);
  out.writeUInt32LE(hello.dictionaryId, 72);
  if (filter !== undefined) {
    // Byte length, not character count: a filter is base58 today but the field is UTF-8, and
    // `string.length` would understate any key that is not.
    out.writeUInt32LE(filter.length, base);
    filter.copy(out, base + 4);
  }
  return out;
}

/**
 * The server's nonce and its proof that it holds your key.
 *
 * Sent before you have proved anything. Checking it is what tells you the peer is the node rather
 * than something sitting in front of it.
 */
export interface Challenge {
  serverNonce: Buffer;
  proof: Buffer;
}

/** Decodes a challenge. */
export function readChallenge(buf: Buffer): Challenge {
  if (buf.length < 64) throw new ProtocolError('challenge truncated');
  return {
    serverNonce: Buffer.from(buf.subarray(0, 32)),
    proof: Buffer.from(buf.subarray(32, 64)),
  };
}

/** Encodes your proof that you hold the key. */
export function writeProve(proof: Buffer): Buffer {
  return Buffer.from(proof);
}

/** What the server settled. */
export interface HelloAck {
  protocolVersion: number;
  sessionId: bigint;
  /** Streams actually granted — the intersection of what was asked and what the key permits. */
  granted: number;
  codec: Codec;
  /** How often the server pings an idle connection. */
  keepaliveMs: number;
  /** Non-zero only when the server holds the same dictionary this client offered. */
  dictionaryId: number;
}

/** Bytes in an encoded acknowledgement. */
export const HELLO_ACK_LEN = 22;

/** Decodes an acknowledgement. */
export function readHelloAck(buf: Buffer): HelloAck {
  if (buf.length < HELLO_ACK_LEN) {
    throw new ProtocolError(`hello ack needs ${HELLO_ACK_LEN} bytes, have ${buf.length}`);
  }
  return {
    protocolVersion: buf.readUInt16LE(0),
    granted: buf.readUInt32LE(2),
    sessionId: buf.readBigUInt64LE(6),
    codec: buf.readUInt8(14) as Codec,
    // Byte 15 is reserved.
    keepaliveMs: buf.readUInt16LE(16),
    dictionaryId: buf.readUInt32LE(18),
  };
}

/** Decodes an error message. */
export function readError(buf: Buffer): ServerError {
  if (buf.length < 4) {
    throw new ProtocolError('error message truncated');
  }
  const code = buf.readUInt16LE(0);
  const len = buf.readUInt16LE(2);
  const detail = buf.subarray(4, 4 + len).toString('utf8');
  return new ServerError(code as ErrorCode, detail);
}

/** Frames this client missed, and where the stream resumes. */
export interface Lag {
  dropped: bigint;
  resumeSeq: bigint;
}

/** Decodes a lag report. */
export function readLag(buf: Buffer): Lag {
  if (buf.length < 16) throw new ProtocolError('lag message truncated');
  return { dropped: buf.readBigUInt64LE(0), resumeSeq: buf.readBigUInt64LE(8) };
}

/** The server's verdict on a submitted filter. */
export interface FilterAck {
  accepted: boolean;
  cost: number;
  detail: string;
}

/** Decodes a filter acknowledgement. */
export function readFilterAck(buf: Buffer): FilterAck {
  if (buf.length < 8) throw new ProtocolError('filter ack truncated');
  const len = buf.readUInt16LE(6);
  return {
    accepted: buf.readUInt8(0) !== 0,
    // Byte 1 is reserved.
    cost: buf.readUInt32LE(2),
    detail: buf.subarray(8, 8 + len).toString('utf8'),
  };
}

/** One filter, with the name the subscriber chose for it. */
export interface NamedFilter {
  /** What you call it. Comes back in a refusal so you know which one was at fault. */
  name?: string;
  /** The filter itself. */
  spec: object;
}

/**
 * Encodes a filter submission. The frame length delimits it, so the JSON needs no prefix.
 *
 * The whole set replaces whatever the connection carried, and is accepted or refused together — a
 * connection is never left holding part of what was asked for.
 */
export function writeSetFilter(filters: NamedFilter[]): Buffer {
  return Buffer.from(JSON.stringify({ filters }), 'utf8');
}

/**
 * The content hash a dictionary is identified by.
 *
 * FNV-1a folded to 32 bits, matching the server exactly. Two peers agree on a dictionary by
 * agreeing on this number, so it must be computed the same way on both sides or the dictionary is
 * silently never used.
 */
export function dictionaryId(dictionary: Buffer): number {
  if (dictionary.length === 0) return 0;
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const mask = 0xffffffffffffffffn;
  for (const byte of dictionary) {
    hash = ((hash ^ BigInt(byte)) * prime) & mask;
  }
  const folded = Number((hash ^ (hash >> 32n)) & 0xffffffffn);
  // Zero means "no dictionary", so a hash that lands there is nudged rather than misread.
  return folded === 0 ? 1 : folded;
}
