/**
 * The subscriber client.
 *
 * Connects, authenticates, and yields decoded events as they arrive.
 *
 * # Compression is not optional
 *
 * This client offers only zstd. A manka-shreds node streams several hundred megabits of transaction data
 * per second uncompressed, and a dictionary-compressed stream is roughly a third of that. Letting a
 * subscriber quietly negotiate its way to an uncompressed stream costs the operator bandwidth they
 * did not agree to, so a node can be configured to refuse it — and this client refuses it too,
 * rather than connecting and silently costing more than it should.
 *
 * The only requirement this places on a consumer is Node 22.15 or newer, where zstd is built in.
 */

import { zstdDecompressSync } from 'node:zlib';

import { clientProof, freshNonce, keyRef, verifyServer } from './handshake.js';

import {
  connectQuic,
  connectTcp,
  type ServerVerification,
  type Transport,
  type Wire,
} from './transport.js';

import { DictionaryCache } from './dictcache.js';

import {
  ALL_STREAMS,
  Capability,
  Codec,
  CodecBit,
  FrameKind,
  FRAME_HEADER_LEN,
  DICTIONARY_HEADER_LEN,
  MAX_DICTIONARY_BYTES,
  MAX_HANDSHAKE_BYTES,
  ProtocolError,
  ServerError,
  dictionaryId,
  readDictionary,
  readError,
  readFilterAck,
  readFrameHeader,
  readHelloAck,
  readLag,
  writeFrame,
  writeHello,
  writeProve,
  readChallenge,
  writeSetFilter,
  type FilterAck,
  type FrameHeader,
  type NamedFilter,
  type HelloAck,
  type Lag,
} from './protocol.js';
import {
  readDuplicate,
  readRawShred,
  readEntry,
  readSlotEnd,
  readSlotStart,
  type Duplicate,
  type RawShred,
  type Entry,
  type SlotEnd,
  type SlotStart,
} from './events.js';
import { Transaction } from './transaction.js';

/** How to connect. */
export interface ClientOptions {
  /**
   * Server host. Required.
   *
   * This build carries no endpoint, so one archive serves every node and none of them can go stale
   * when an operator moves or adds one. There is nothing to pin alongside it: the node
   * authenticates itself with your key during the handshake, so its certificate carries no trust.
   */
  host: string;
  /** Server port. Required. Both transports are served on it — QUIC over UDP, TCP over TCP. */
  port: number;
  /**
   * Which transport to use. QUIC by default.
   *
   * Over a WAN one lost packet stalls a TCP stream until it is retransmitted, holding back
   * messages that already arrived. QUIC does not head-of-line block the same way. Choose `'tcp'`
   * for a colocated subscriber, or one behind a network that blocks UDP.
   */
  transport?: Transport;
  /**
   * How to verify the server's certificate over QUIC. Ignored over TCP.
   *
   * Defaults to `{ unchecked: true }`, which is the right choice against a manka-shreds node: the
   * handshake proves the node holds your key before this side proves anything, and each proof is
   * bound to a hash of the certificate the session presented, so an interposed relay — which must
   * present its own — cannot compute either proof or carry one across. Checking the certificate
   * against a trust store proves nothing further, and requiring it would break every subscriber
   * the moment an operator rotated it.
   *
   * `{ webpki: true }` verifies against the platform roots, for a node holding a CA-signed
   * certificate for a name it is reachable by. `{ fingerprint }` additionally pins one exact
   * certificate — belt and braces, and it brings back the reissue-on-rotation cost.
   */
  verification?: ServerVerification;
  /**
   * Name presented for TLS, when it differs from `host`.
   *
   * Needed when dialling a bare address whose certificate names something else, which is the case
   * for a node's generated certificate.
   */
  serverName?: string;
  /**
   * The key issued to this subscriber, and the only credential there is.
   *
   * There is no key id to go with it. The greeting names your key by `SHA-256(domain ‖ secret)` and
   * never carries the secret itself, so the server finds it by that reference rather than by a
   * name. This package used to take a `keyId`, ignore it, and let a subscriber believe a wrong one
   * would be caught somewhere.
   *
   * A string is sent as its UTF-8 bytes, exactly as written — never decoded as hex or base64, even
   * when it looks like either. Pass a `Buffer` if your secret is genuinely binary.
   */
  secret: string | Buffer;
  /**
   * Streams to subscribe to. Defaults to everything the key permits.
   *
   * The server grants the intersection of this and what the key allows, so asking for more than
   * the key permits is not an error — check {@link MankaShredsClient.granted} for what was actually
   * given.
   */
  streams?: number;
  /**
   * A compression dictionary to offer, when you have one in hand.
   *
   * Almost never needed. The node hands over whichever dictionary it is using during the handshake,
   * so leaving this unset gets the full ratio on the first connection and every one after it. Set
   * it only to seed a client that already has the bytes and wants to skip even that first transfer.
   *
   * Transaction frames are small and highly repetitive, so per-message compression cannot exploit
   * the repetition and a dictionary can — roughly three times the ratio on live traffic. One that
   * does not match the node's is not an error: the node simply sends its own, and this one is
   * superseded for the life of the connection.
   */
  dictionary?: Buffer;
  /**
   * Where dictionaries received from a node are kept between runs.
   *
   * Unset uses the platform's cache directory, so the megabyte a node sends is paid once ever
   * rather than once per connection. `null` keeps none — the dictionary still arrives and this
   * session still streams at the full ratio, it is simply fetched again next time. Correct for a
   * read-only filesystem, or anywhere you would rather this package did not write.
   *
   * See `dictcache` for the default location and the environment variable that moves it.
   */
  dictionaryCache?: string | null;
  /** How long to wait for the handshake, in milliseconds. Defaults to 10 seconds. */
  connectTimeoutMs?: number;
  /**
   * Largest message to accept, compressed or not.
   *
   * Bounds both the frame taken off the socket and what a compressed one is expanded into, so
   * lowering it actually bounds what a node can make this process hold. A compressed body is
   * smaller than what it becomes, so nothing legitimate is lost by checking it in both places.
   * Handshake frames are bounded separately, by what each of them can be.
   */
  maxMessageBytes?: number;
  /**
   * Filters installed in the greeting, so the stream is narrowed before it starts.
   *
   * {@link MankaShredsClient.setFilters} leaves a window — a round trip at least — during which the
   * connection is unfiltered and everything subscribed to arrives. On a busy node that window is
   * thousands of transactions nobody asked for, and it is billed. Naming them here closes it: the
   * server installs them before the first frame is sent.
   *
   * A filter that does not compile, or that exceeds the key's budgets, rejects the promise from
   * `connect` rather than falling back to an unfiltered stream.
   */
  filters?: NamedFilter[];
}

/** Something the server sent. */
export type MankaShredsEvent =
  | {
      type: 'transaction';
      seq: bigint;
      transaction: Transaction;
      /**
       * Which of this connection's named filters this transaction matched, as a bitmask.
       *
       * Zero when the connection named none. One transaction matching several filters arrives
       * once, with every match recorded.
       */
      matched: number;
    }
  | { type: 'entry'; seq: bigint; entry: Entry }
  | { type: 'slot-start'; seq: bigint; slot: SlotStart }
  | { type: 'slot-end'; seq: bigint; slot: SlotEnd }
  | { type: 'duplicate'; seq: bigint; duplicate: Duplicate }
  /**
   * A shred republished exactly as it arrived. Needs the `RAW_SHREDS` stream.
   *
   * Delivered before the node verified or decoded anything, so nothing on it is claimed to be
   * leader-signed — see {@link RawShred}.
   */
  | { type: 'raw-shred'; seq: bigint; shred: RawShred }
  | { type: 'lag'; seq: bigint; lag: Lag }
  | { type: 'filter-ack'; seq: bigint; ack: FilterAck }
  | { type: 'ping'; seq: bigint }
  | { type: 'pong'; seq: bigint }
  /** A frame kind this build does not know. Carried rather than dropped so a newer server does
   *  not break an older subscriber. */
  | { type: 'other'; seq: bigint; kind: number; payload: Buffer };

const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_MESSAGE_BYTES = 16 << 20;

/**
 * Events buffered for a consumer that is not asking for them before the transport stops reading.
 *
 * Large enough that a consumer doing ordinary per-event work never touches it — a burst of a few
 * thousand frames is absorbed without a single pause — and small enough that a consumer which has
 * genuinely stopped is noticed by the server within its own queue rather than after this one has
 * eaten the heap.
 */
const MAX_BACKLOG = 4_096;

/**
 * Where reading restarts, well below {@link MAX_BACKLOG}.
 *
 * A gap between the two stops a consumer hovering at the bound from pausing and resuming the socket
 * on alternate events, which costs a syscall each way and achieves nothing.
 */
const RESUME_BACKLOG = 1_024;

/**
 * Turns a secret into the bytes the server compares against.
 *
 * A string is sent as its UTF-8 bytes, exactly as written. It is deliberately *not* decoded as hex
 * or base64 even when it looks like either: the server compares against the literal characters in
 * its key file, and a secret is usually a run of hex digits, so guessing at an encoding would
 * silently send the wrong bytes for the most common secret there is.
 */
function decodeSecret(secret: string | Buffer): Buffer {
  return Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8');
}

/**
 * A live subscription.
 *
 * Iterate it to receive events:
 *
 * ```ts
 * const client = await MankaShredsClient.connect({ ... });
 * for await (const event of client) {
 *   if (event.type === 'transaction') console.log(event.transaction.slot);
 * }
 * ```
 */
export class MankaShredsClient implements AsyncIterable<MankaShredsEvent> {
  private buffer: Buffer = Buffer.alloc(0);
  private pending: Array<(value: IteratorResult<MankaShredsEvent>) => void> = [];
  private failed: Array<(reason: unknown) => void> = [];
  private queue: MankaShredsEvent[] = [];
  private paused = false;
  private error: unknown = null;
  private done = false;
  private expectedSeq = 0n;
  private gapCount = 0n;
  private wire = 0n;
  private decoded = 0n;

  private constructor(
    private readonly socket: Wire,
    private readonly ack: HelloAck,
    private readonly dictionary: Buffer | null,
    private readonly pushedDictionary: boolean,
    private readonly maxMessageBytes: number,
    leftover: Buffer,
  ) {
    socket.onData((chunk) => this.onData(chunk));
    socket.onError((err) => this.fail(err));
    socket.onClose(() => this.finish());
    // Bytes that arrived alongside the handshake reply already belong to the stream.
    if (leftover.length > 0) this.onData(leftover);
    socket.resume();
  }

  /**
   * Connects, authenticates and negotiates compression.
   *
   * Uses QUIC unless `transport: 'tcp'` says otherwise.
   */
  static async connect(options: ClientOptions): Promise<MankaShredsClient> {
    const timeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    const transport = options.transport ?? 'quic';

    const { host, port } = options;
    // Where received dictionaries live. `null` means keep none, which is correct for a read-only
    // deployment and no worse than plain zstd — the node simply sends it again next time.
    const cache =
      options.dictionaryCache === undefined
        ? DictionaryCache.defaultLocation()
        : options.dictionaryCache === null
          ? null
          : new DictionaryCache(options.dictionaryCache);
    // What this client already holds: an explicit dictionary, or failing that whichever one the
    // cache used most recently. Offering it lets the node skip sending a megabyte this side has.
    const held = options.dictionary ?? cache?.newest()?.bytes ?? null;
    // The node authenticates itself with your key rather than with its certificate, so there is
    // nothing here to check and nothing to configure. See `handshake`.
    const verification: ServerVerification = options.verification ?? { unchecked: true };

    if (host === '' || port === 0) {
      throw new ProtocolError(
        'this build of the SDK was not provisioned with a node endpoint. Pass host and port, ' +
          'along with the certificate fingerprint your operator gave you',
      );
    }

    const wire =
      transport === 'quic'
        ? await connectQuic({
            host,
            port,
            serverName: options.serverName ?? defaultServerName(host),
            verification,
            timeoutMs,
          })
        : await connectTcp(host, port, timeoutMs);

    try {
      // Your key never leaves this process. It names itself by a one-way reference, and possession
      // is proved below over nonces bound to this TLS session.
      const key = decodeSecret(options.secret);
      const reference = keyRef(key);
      const clientNonce = freshNonce();
      // Set when the server proves itself. Nothing past the challenge is accepted without it.
      let proved = false;

      const hello = writeHello({
        streams: options.streams ?? ALL_STREAMS,
        // Only zstd: see the note at the top of this file.
        codecs: CodecBit.ZSTD,
        keyRef: reference,
        clientNonce,
        // Asking for the dictionary is what makes the ratio automatic. A node only sends one to a
        // client that said it would take it, so a client that cannot is never handed a megabyte it
        // would discard.
        capabilities: Capability.ACCEPTS_DICTIONARY,
        dictionaryId: held ? dictionaryId(held) : 0,
        // Encoded through the same function `setFilters` uses, so a filter means the same thing
        // whichever way it was sent.
        ...(options.filters === undefined
          ? {}
          : { filter: writeSetFilter(options.filters).toString('utf8') }),
      });

      // Filled in when the acknowledgement arrives, and again if the node pushes a dictionary.
      let ack: HelloAck | null = null;
      let pushed: Buffer | null = null;

      const { header, payload, rest } = await exchange(
        wire,
        writeFrame(FrameKind.Hello, 0n, hello),
        timeoutMs,
        (frame, body) => {
          if (frame.kind === FrameKind.Error) throw readError(body);

          // The node named a dictionary this side does not hold, so it is sending it — once,
          // before the first data frame. Reading it here rather than in the event loop is what
          // makes "the dictionary does not change during a run" true by construction: by the time
          // `connect` returns, the one this connection uses is settled.
          if (ack !== null) {
            if (frame.kind !== FrameKind.Dictionary) {
              throw new ProtocolError(
                `the server announced dictionary ${ack.dictionaryId} and then sent frame kind ` +
                  `${frame.rawKind}`,
              );
            }
            const offered = readDictionary(body);
            // Checked against what the acknowledgement named. Accepting bytes that do not match
            // would leave this side decompressing against something other than what the node
            // compresses with, and every frame after it unreadable for a reason nothing on the
            // wire would explain.
            const actual = dictionaryId(offered.bytes);
            if (offered.id !== ack.dictionaryId || actual !== ack.dictionaryId) {
              throw new ProtocolError(
                'the server sent a dictionary that is not the one it announced: acknowledged ' +
                  `${ack.dictionaryId}, frame said ${offered.id}, bytes hash to ${actual}`,
              );
            }
            pushed = offered.bytes;
            return null;
          }

          if (frame.kind !== FrameKind.Challenge) {
            // Anything other than a challenge here means the peer skipped proving it holds the
            // key. Accepting it would make the whole exchange optional — a server that simply
            // never challenged would be trusted, which is precisely what this replaces.
            if (!proved) {
              throw new ProtocolError(
                'the server answered without proving it holds this key; a peer that skips the ' +
                  'proof is not one this client will talk to',
              );
            }
            // The acknowledgement may promise a dictionary this side does not hold, in which case
            // one more frame is on its way and the handshake is not over.
            if (frame.kind === FrameKind.HelloAck) {
              const parsed = readHelloAck(body);
              const holdsIt =
                held !== null &&
                parsed.dictionaryId !== 0 &&
                dictionaryId(held) === parsed.dictionaryId;
              if (!holdsIt && parsed.dictionaryId !== 0) {
                ack = parsed;
                return KEEP_READING;
              }
            }
            return null;
          }

          const challenge = readChallenge(body);
          const transcript = {
            keyRef: reference,
            clientNonce,
            serverNonce: challenge.serverNonce,
            binding: wire.channelBinding(),
          };
          if (!verifyServer(transcript, key, challenge.proof)) {
            // Either the peer does not hold this key, or something is sitting between the two ends
            // presenting a certificate of its own. Both mean the connection must not continue, and
            // nothing has been revealed: no proof of ours has been sent yet.
            throw new ProtocolError(
              'the server did not prove it holds this key; the connection is not to the node it ' +
                'claims to be, or is being relayed',
            );
          }
          proved = true;
          return writeFrame(FrameKind.Prove, 0n, writeProve(clientProof(transcript, key)));
        },
      );
      if (header.kind === FrameKind.Error) throw readError(payload);
      // `ack` is already set when the exchange ran on to collect a pushed dictionary, in which case
      // the frame it resolved with is that dictionary rather than the acknowledgement.
      const settled: HelloAck =
        ack ??
        (header.kind === FrameKind.HelloAck
          ? readHelloAck(payload)
          : (() => {
              throw new ProtocolError(`expected HelloAck, got frame kind ${header.rawKind}`);
            })());
      if (settled.codec !== Codec.Zstd) {
        throw new ProtocolError(
          `server negotiated ${Codec[settled.codec] ?? settled.codec} but this client requires ` +
            'zstd; the server has zstd disabled',
        );
      }

      let agreed: Buffer | null = null;
      if (pushed !== null) {
        agreed = pushed;
        // Kept for next time, so the megabyte is paid once ever rather than once per connection.
        // A failure here changes nothing about this session.
        cache?.store(settled.dictionaryId, pushed);
      } else if (
        held !== null &&
        settled.dictionaryId !== 0 &&
        dictionaryId(held) === settled.dictionaryId
      ) {
        // What this side already held, kept only because the server said it is using that one.
        agreed = held;
      }

      return new MankaShredsClient(
        wire,
        settled,
        agreed,
        pushed !== null,
        options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES,
        rest,
      );
    } catch (err) {
      wire.close();
      throw err;
    }
  }

  /** Streams the server actually granted — the intersection of what was asked and what the key allows. */
  get granted(): number {
    return this.ack.granted;
  }

  /** This connection's server-assigned id, which the operator's logs are keyed by. */
  get sessionId(): bigint {
    return this.ack.sessionId;
  }

  /**
   * Whether a compression dictionary is in use on this connection.
   *
   * False only when the node has none at all. There is nothing to configure for it to be true: a
   * node using a dictionary hands it over during the handshake.
   */
  get dictionaryActive(): boolean {
    return this.dictionary !== null;
  }

  /**
   * Whether the dictionary arrived over the wire rather than out of the cache.
   *
   * Expected once — the first time this subscriber ever connects to a given node, and again after
   * the operator changes the node's dictionary. True on *every* connection means the cache is not
   * being written: the directory is read-only, or absent, or the process has no home. The
   * connection is unaffected and streams at the full ratio; it is simply paying about a megabyte
   * each time it reconnects.
   *
   * This package writes nothing to the console, so this is how that fact is reported. See
   * `dictcache` for where the cache lives and how to move it.
   */
  get dictionaryWasSent(): boolean {
    return this.pushedDictionary;
  }

  /** Compressed bytes received. */
  get wireBytes(): bigint {
    return this.wire;
  }

  /** Bytes after decompression. Against {@link wireBytes}, this is the achieved ratio. */
  get decodedBytes(): bigint {
    return this.decoded;
  }

  /** Frames dropped because this client could not keep up. */
  get gaps(): bigint {
    return this.gapCount;
  }

  /**
   * Replaces the server-side filter.
   *
   * Returns once the request is written, not once it is in force: the server applies it
   * asynchronously and confirms with a `filter-ack` event. Frames already in flight still arrive
   * under the previous filter, so a consumer that needs certainty should wait for the ack.
   */
  setFilter(spec: object): void {
    this.setFilters([{ spec }]);
  }

  /**
   * Replaces this connection's filters with a named set, up to sixteen.
   *
   * Every transaction says which of them it matched — see `matched` on the event — so one
   * connection can carry several interests and still tell them apart on arrival. The set is
   * accepted or refused together, so a connection never ends up holding part of what was asked for.
   */
  setFilters(filters: NamedFilter[]): void {
    this.socket.write(writeFrame(FrameKind.SetFilter, 0n, writeSetFilter(filters)));
  }

  /** Sends a liveness probe. The server answers with a `pong` event. */
  ping(): void {
    this.socket.write(writeFrame(FrameKind.Ping, 0n, Buffer.alloc(0)));
  }

  /** Closes the connection. The iterator ends. */
  close(): void {
    this.socket.close();
  }

  /**
   * Waits for the next event, leaving the connection open.
   *
   * Use this when you need to read until something specific happens and then carry on — waiting
   * for a `filter-ack` before trusting the filter, say. Doing that with `for await` and a `break`
   * closes the connection, which is right for "I am done" and wrong for "I am done waiting".
   *
   * Rejects if the connection failed, and resolves to `null` once it has closed.
   */
  next(): Promise<MankaShredsEvent | null> {
    const ready = this.queue.shift();
    if (ready !== undefined) {
      this.drained();
      return Promise.resolve(ready);
    }
    if (this.error !== null) return Promise.reject(this.error);
    if (this.done) return Promise.resolve(null);
    return new Promise((resolve, reject) => {
      this.pending.push((result) => resolve(result.done ? null : result.value));
      this.failed.push(reject);
    });
  }

  [Symbol.asyncIterator](): AsyncIterator<MankaShredsEvent> {
    return {
      next: (): Promise<IteratorResult<MankaShredsEvent>> => {
        const ready = this.queue.shift();
        if (ready !== undefined) {
          this.drained();
          return Promise.resolve({ value: ready, done: false });
        }
        if (this.error !== null) return Promise.reject(this.error);
        if (this.done) return Promise.resolve({ value: undefined, done: true });
        return new Promise((resolve, reject) => {
          this.pending.push(resolve);
          this.failed.push(reject);
        });
      },
      return: (): Promise<IteratorResult<MankaShredsEvent>> => {
        this.close();
        return Promise.resolve({ value: undefined, done: true });
      },
    };
  }

  private emit(event: MankaShredsEvent): void {
    const waiter = this.pending.shift();
    this.failed.shift();
    if (waiter) {
      waiter({ value: event, done: false });
      return;
    }
    this.queue.push(event);
    // Nobody is waiting and the backlog has grown, so stop reading rather than buffering the
    // firehose. Two things depend on this. Memory: an unbounded queue is a client that dies of the
    // stream it could not keep up with, and on a busy node that is seconds away. And honesty: the
    // server decides what a subscriber which cannot keep up is owed — it drops the oldest frames and
    // sends a `Lag` naming the count — but only if it can *see* the client falling behind. Draining
    // the socket into memory hides that, so the client silently accumulates stale events while the
    // server believes it is keeping up.
    if (!this.paused && this.queue.length >= MAX_BACKLOG) {
      this.paused = true;
      this.socket.pause();
    }
  }

  /** Resumes reading once the consumer has taken enough of the backlog to be worth refilling. */
  private drained(): void {
    if (this.paused && this.queue.length <= RESUME_BACKLOG) {
      this.paused = false;
      this.socket.resume();
    }
  }

  private fail(reason: unknown): void {
    if (this.error !== null || this.done) return;
    this.error = reason;
    const waiters = this.failed.splice(0);
    this.pending.splice(0);
    for (const reject of waiters) reject(reason);
  }

  private finish(): void {
    if (this.done) return;
    this.done = true;
    const waiters = this.pending.splice(0);
    this.failed.splice(0);
    for (const resolve of waiters) resolve({ value: undefined, done: true });
  }

  private onData(chunk: Buffer): void {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    try {
      this.drain();
    } catch (err) {
      this.fail(err);
      this.socket.close();
    }
  }

  /** Pulls every whole frame out of the buffer. */
  private drain(): void {
    let at = 0;
    while (this.buffer.length - at >= FRAME_HEADER_LEN) {
      const header = readFrameHeader(this.buffer, at);
      // Refused on the number rather than after buffering up to it. Checking only what a compressed
      // body expands into would leave this setting with no effect at all on an uncompressed frame,
      // which is exactly the case someone lowering it is trying to bound.
      if (header.len > this.maxMessageBytes) {
        throw new ProtocolError(
          `the server sent a ${FrameKind[header.kind] ?? header.rawKind} frame of ${header.len} ` +
            `bytes, and this connection accepts at most ${this.maxMessageBytes}`,
        );
      }
      const end = at + FRAME_HEADER_LEN + header.len;
      if (this.buffer.length < end) break;
      const payload = this.buffer.subarray(at + FRAME_HEADER_LEN, end);
      at = end;

      this.wire += BigInt(FRAME_HEADER_LEN + header.len);
      const body = header.compressed ? this.decompress(payload, header.codec) : payload;
      this.decoded += BigInt(body.length);

      // A sequence gap means the server dropped frames for this connection; it is reported by the
      // Lag frame too, but counting here catches a gap even if that frame is itself lost.
      if (header.kind !== FrameKind.Hello && header.kind !== FrameKind.HelloAck) {
        if (this.expectedSeq !== 0n && header.seq > this.expectedSeq) {
          this.gapCount += header.seq - this.expectedSeq;
        }
        this.expectedSeq = header.seq + 1n;
      }

      const event = this.decode(header.kind, header.rawKind, header.seq, body, header.matched);
      if (event) this.emit(event);
    }
    this.buffer = at === 0 ? this.buffer : this.buffer.subarray(at);
  }

  private decompress(payload: Buffer, codec: Codec): Buffer {
    if (codec !== Codec.Zstd) {
      throw new ProtocolError(`server sent ${Codec[codec] ?? codec}, which was never offered`);
    }
    return zstdDecompressSync(payload, {
      maxOutputLength: this.maxMessageBytes,
      ...(this.dictionary ? { dictionary: this.dictionary } : {}),
    });
  }

  private decode(
    kind: FrameKind,
    rawKind: number,
    seq: bigint,
    body: Buffer,
    matched: number,
  ): MankaShredsEvent | null {
    switch (kind) {
      case FrameKind.Transaction:
        return {
          type: 'transaction',
          seq,
          transaction: Transaction.read(body),
          matched,
        };
      case FrameKind.Entry:
        return { type: 'entry', seq, entry: readEntry(body) };
      case FrameKind.SlotStart:
        return { type: 'slot-start', seq, slot: readSlotStart(body) };
      case FrameKind.SlotEnd:
        return { type: 'slot-end', seq, slot: readSlotEnd(body) };
      case FrameKind.Duplicate:
        return { type: 'duplicate', seq, duplicate: readDuplicate(body) };
      case FrameKind.RawShred:
        return { type: 'raw-shred', seq, shred: readRawShred(body) };
      case FrameKind.Lag: {
        const lag = readLag(body);
        this.gapCount += lag.dropped;
        this.expectedSeq = lag.resumeSeq;
        return { type: 'lag', seq, lag };
      }
      case FrameKind.FilterAck:
        return { type: 'filter-ack', seq, ack: readFilterAck(body) };
      case FrameKind.Ping:
        // Answered here so a consumer that is slow to iterate is not disconnected for being idle.
        this.socket.write(writeFrame(FrameKind.Pong, 0n, Buffer.alloc(0)));
        return { type: 'ping', seq };
      case FrameKind.Pong:
        return { type: 'pong', seq };
      case FrameKind.Error:
        this.fail(readError(body));
        this.socket.close();
        return null;
      // The dictionary is settled during the handshake and does not change while a connection
      // runs. One arriving here is refused rather than skipped: a server that meant it would be
      // compressing the next frame with something this side is not decoding with, and every
      // message after it would fail for a reason nothing in the error would explain. Better to
      // name the cause than to let it surface as corruption several frames later.
      case FrameKind.Dictionary:
        this.fail(
          new ProtocolError(
            'the server sent a dictionary mid-stream; the dictionary is fixed for the life of a ' +
              'connection',
          ),
        );
        this.socket.close();
        return null;
      default:
        return { type: 'other', seq, kind: rawKind, payload: Buffer.from(body) };
    }
  }
}

/**
 * The TLS name to present when the caller did not choose one.
 *
 * The host as written, unless it is a bare IP address. A certificate cannot usefully be issued for
 * an address the way it can for a name, and a node's generated certificate names `localhost`, so
 * that is what an address is dialled as — with a pinned fingerprint the name establishes nothing
 * anyway, and identity comes from the certificate itself.
 */
function defaultServerName(host: string): string {
  const bare = host.replace(/^\[|\]$/g, '');
  const isIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(bare);
  const isIpv6 = bare.includes(':');
  return isIpv4 || isIpv6 ? 'localhost' : host;
}

/**
 * Writes one frame and reads the single frame that answers it.
 *
 * Used for the handshake, before the streaming loop takes over. Anything that arrived past that
 * frame is handed back rather than dropped: over either transport a reply and the first stream
 * bytes can land in one read.
 */
/**
 * Runs the whole handshake over one data subscription.
 *
 * Two frames arrive in sequence — the challenge, then the acknowledgement — and `onData` is
 * registered exactly once for both. Registering it per frame would attach a second listener to the
 * TCP socket, which appends rather than replaces, so every later chunk would be delivered twice.
 *
 * `respond` is called with each frame in turn and returns the bytes to send next, or `null` when
 * the exchange is finished.
 */
/**
 * Returned by a handshake step that consumes a frame and waits for another without replying.
 *
 * The dictionary needs this: the server sends it unprompted after the acknowledgement, so there is
 * a frame to read that no request of ours precedes.
 */
const KEEP_READING = Symbol('keep-reading');

function exchange(
  wire: Wire,
  request: Buffer,
  timeoutMs: number,
  respond: (header: FrameHeader, payload: Buffer) => Buffer | null | typeof KEEP_READING,
): Promise<{ header: FrameHeader; payload: Buffer; rest: Buffer }> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let settled = false;
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(
      () => finish(() => reject(new ProtocolError(`handshake timed out after ${timeoutMs}ms`))),
      timeoutMs,
    );

    wire.onError((err) => finish(() => reject(err)));
    wire.onClose(() =>
      finish(() => reject(new ProtocolError('the server closed the connection during the handshake'))),
    );
    const onChunk = (chunk: Buffer): void => {
      if (settled) return;
      // Always concatenated rather than aliased: this runs once per connection, and aliasing a
      // chunk the transport may reuse would be a subtle way to corrupt the handshake.
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < FRAME_HEADER_LEN) return;
      let header: FrameHeader;
      try {
        header = readFrameHeader(buffer);
      } catch (err) {
        finish(() => reject(err));
        return;
      }
      // Per kind, not one bound for the exchange. Everything here comes from a peer that has proved
      // nothing yet except the dictionary, which arrives after it has, and which is the only one of
      // them that is legitimately large.
      const limit =
        header.kind === FrameKind.Dictionary
          ? DICTIONARY_HEADER_LEN + MAX_DICTIONARY_BYTES
          : MAX_HANDSHAKE_BYTES;
      if (header.len > limit) {
        finish(() =>
          reject(
            new ProtocolError(
              `the server sent a ${FrameKind[header.kind] ?? header.rawKind} frame of ` +
                `${header.len} bytes during the handshake, and one may be at most ${limit}`,
            ),
          ),
        );
        return;
      }
      const end = FRAME_HEADER_LEN + header.len;
      if (buffer.length < end) return;
      const payload = buffer.subarray(FRAME_HEADER_LEN, end);
      let next: Buffer | null | typeof KEEP_READING;
      try {
        next = respond(header, payload);
      } catch (err) {
        finish(() => reject(err));
        return;
      }
      if (next === null) {
        finish(() =>
          resolve({ header, payload, rest: buffer.subarray(end) }),
        );
        return;
      }
      // Consumed; whatever follows belongs to the next frame.
      buffer = Buffer.from(buffer.subarray(end));
      if (next === KEEP_READING) {
        // Nothing to send, but more to read. The buffer may already hold the next whole frame —
        // the acknowledgement and the dictionary usually arrive in one chunk — and no further
        // `onData` is guaranteed, so it has to be re-examined now rather than waited for.
        if (buffer.length > 0) {
          const pending = buffer;
          buffer = Buffer.alloc(0);
          onChunk(pending);
        }
        return;
      }
      wire.write(next);
    };
    wire.onData(onChunk);

    wire.write(request);
    wire.resume();
  });
}

export { ServerError, ProtocolError };
