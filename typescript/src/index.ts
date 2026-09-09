/**
 * The manka-shreds TypeScript SDK: a zero-dependency subscriber client for the manka-shreds shred stream.
 *
 * See README.md for a walkthrough. The short version:
 *
 * ```ts
 * import { MankaShredsClient, Stream } from '@manka-shreds/sdk';
 *
 * const client = await MankaShredsClient.connect({
 *   host: 'node.example.com',
 *   port: 9100,
 *   secret: process.env.MANKA_SHREDS_SECRET!,
 *   streams: Stream.TRANSACTIONS,
 * });
 *
 * for await (const event of client) {
 *   if (event.type === 'transaction') {
 *     console.log(event.transaction.slot, event.transaction.signature.toString('hex'));
 *   }
 * }
 * ```
 */

export { MankaShredsClient, type ClientOptions, type MankaShredsEvent } from './client.js';
/**
 * Proving possession of your key without sending it.
 *
 * `connect` does all of this for you. It is exported for a consumer driving the protocol some other
 * way, and so the mechanism is inspectable rather than folded invisibly into the client.
 */
export * as handshake from './handshake.js';
export {
  ALPN,
  TransportError,
  fingerprintOf,
  type ServerVerification,
  type Transport,
  type Wire,
} from './transport.js';
export {
  Transaction,
  TxFlag,
  INSTRUCTION_ENTRY_LEN,
  LOOKUP_ENTRY_LEN,
  MESSAGE_VERSION_LEGACY,
  TX_HEADER_LEN,
  type AddressLookup,
  type Instruction,
} from './transaction.js';
export {
  DUPLICATE_LEN,
  ENTRY_LEN,
  SLOT_END_LEN,
  SLOT_START_LEN,
  readDuplicate,
  readEntry,
  readRawShred,
  readSlotEnd,
  readSlotStart,
  type Duplicate,
  type Entry,
  type RawShred,
  type SlotEnd,
  type SlotStart,
} from './events.js';
export { DictionaryCache, CACHE_ENV, defaultDir } from './dictcache.js';
export {
  ALL_STREAMS,
  Capability,
  Codec,
  CodecBit,
  DICTIONARY_HEADER_LEN,
  ErrorCode,
  FRAME_HEADER_LEN,
  FrameKind,
  HELLO_ACK_LEN,
  MAX_DICTIONARY_BYTES,
  MAX_FRAME_PAYLOAD,
  MAX_HANDSHAKE_BYTES,
  PROTOCOL_VERSION,
  ProtocolError,
  ServerError,
  Stream,
  Verification,
  dictionaryId,
  readDictionary,
  writeDictionary,
  type Dictionary,
  readError,
  readFilterAck,
  readFrameHeader,
  readHelloAck,
  readLag,
  writeFrame,
  writeHello,
  writeSetFilter,
  type FilterAck,
  type FrameHeader,
  type Hello,
  type HelloAck,
  type Lag,
  type NamedFilter,
} from './protocol.js';
