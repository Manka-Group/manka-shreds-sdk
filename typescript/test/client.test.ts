/**
 * Exercises the client against a stub server that speaks the real wire format.
 *
 * The frames it sends are the committed fixtures, so this tests the client's framing, handshake and
 * decompression without asserting anything about layout that `fixtures.test.ts` does not already
 * pin down.
 */

import assert from 'node:assert/strict';
import { readdirSync, readFileSync, rmSync } from 'node:fs';
import { createServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { zstdCompressSync } from 'node:zlib';

import { MankaShredsClient } from '../src/client.js';
import {
  Capability,
  Codec,
  DICTIONARY_HEADER_LEN,
  ErrorCode,
  FrameKind,
  FRAME_HEADER_LEN,
  MAX_DICTIONARY_BYTES,
  MAX_FRAME_PAYLOAD,
  MAX_HANDSHAKE_BYTES,
  ServerError,
  Stream,
  dictionaryId,
  readFrameHeader,
  writeDictionary,
  writeFrame,
} from '../src/protocol.js';
import { DictionaryCache, scratchDir } from '../src/dictcache.js';
import {
  NO_BINDING,
  clientProof,
  keyRef,
  serverProof,
  type Transcript,
} from '../src/handshake.js';

/** The key every stub authenticates against, and every test connects with. */
const SECRET = Buffer.from('secret');

const dir = fileURLToPath(new URL('../../../fixtures/', import.meta.url));
const load = (name: string): Buffer => readFileSync(dir + name);

/** Encodes a hello ack the way the server does. */
function helloAck(codec: Codec, granted: number, dictId: number): Buffer {
  const body = Buffer.alloc(22);
  body.writeUInt16LE(1, 0);
  body.writeUInt32LE(granted, 2);
  body.writeBigUInt64LE(99n, 6);
  body.writeUInt8(codec, 14);
  body.writeUInt16LE(15_000, 16);
  body.writeUInt32LE(dictId, 18);
  return writeFrame(FrameKind.HelloAck, 0n, body);
}

/** Encodes an error the way the server does. */
function errorFrame(code: ErrorCode, detail: string): Buffer {
  const text = Buffer.from(detail, 'utf8');
  const body = Buffer.alloc(4 + text.length);
  body.writeUInt16LE(code, 0);
  body.writeUInt16LE(text.length, 2);
  text.copy(body, 4);
  return writeFrame(FrameKind.Error, 0n, body);
}

interface Stub {
  port: number;
  /** The hello the client sent, once it arrives. */
  hello: Promise<Buffer>;
  close: () => Promise<void>;
}

/** Starts a server that runs `onHello` when the client's greeting arrives. */
async function stub(onHello: (socket: Socket, hello: Buffer) => void): Promise<Stub> {
  let resolveHello: (value: Buffer) => void;
  const hello = new Promise<Buffer>((resolve) => {
    resolveHello = resolve;
  });
  let transcript: Transcript | null = null;
  let lastHello: Buffer | null = null;
  const server: Server = createServer((socket) => {
    let buffer = Buffer.alloc(0);
    let challenged = false;
    socket.on('error', () => {});
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < FRAME_HEADER_LEN) return;
      const header = readFrameHeader(buffer);
      const end = FRAME_HEADER_LEN + header.len;
      if (buffer.length < end) return;
      const body = buffer.subarray(FRAME_HEADER_LEN, end);

      // The greeting is answered with a challenge, not with the acknowledgement: the client will
      // not accept a peer that skipped proving it holds the key. Every test therefore exercises the
      // exchange, so a client that stopped proving fails the whole file.
      if (header.kind === FrameKind.Hello && !challenged) {
        challenged = true;
        buffer = buffer.subarray(end);
        const reference = body.subarray(8, 40);
        const clientNonce = body.subarray(40, 72);
        transcript = {
          keyRef: Buffer.from(reference),
          clientNonce: Buffer.from(clientNonce),
          serverNonce: Buffer.alloc(32, 42),
          // TCP, so nothing binds the exchange to a session.
          binding: NO_BINDING,
        };
        const proof = Buffer.concat([
          transcript.serverNonce,
          serverProof(transcript, SECRET),
        ]);
        socket.write(writeFrame(FrameKind.Challenge, 0n, proof));
        lastHello = Buffer.from(body);
        resolveHello(lastHello);
        return;
      }

      // Then the client's proof, which must be the one this key produces.
      if (header.kind === FrameKind.Prove) {
        buffer = buffer.subarray(end);
        // Only meaningful when the client actually holds this stub's key; one test deliberately
        // connects with another, and is refused before reaching here.
        if (Buffer.from(transcript!.keyRef).equals(keyRef(SECRET))) {
          assert.deepEqual(
            Buffer.from(body.subarray(0, 32)),
            clientProof(transcript!, SECRET),
            'the client proved possession of something other than its key',
          );
        }
        onHello(socket, lastHello!);
        return;
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as AddressInfo).port,
    hello,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

/**
 * Connects to a stub over TCP.
 *
 * These stubs are TCP servers, so the transport is named rather than defaulted. QUIC — the actual
 * default — is exercised against a real node in the integration suite, where there is a real
 * certificate to verify and a real endpoint to negotiate with; a QUIC stub here would test this
 * SDK against another mock rather than against the server.
 */
// The dictionary cache is off by default here. It defaults to the user's cache directory, which is
// right for a subscriber and wrong for a test suite: these would leave megabytes in a developer's
// home and read one another's. The tests that exercise the cache point it at a scratch directory.
const connect = (port: number, extra: Record<string, unknown> = {}) =>
  MankaShredsClient.connect({
    host: '127.0.0.1',
    port,
    transport: 'tcp',
    secret: SECRET,
    connectTimeoutMs: 5_000,
    dictionaryCache: null,
    ...extra,
  });

test('the client only ever offers zstd, so a server cannot hand it an uncompressed stream', async () => {
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
  });
  const client = await connect(server.port);
  const hello = await server.hello;

  // Byte 6 is the codec mask. Only the zstd bit may be set: offering `none` is exactly how a
  // client would quietly negotiate its way out of compression.
  assert.equal(hello.readUInt8(6), 1 << 2);
  client.close();
  await server.close();
});

test('the key is never sent, in any form', async () => {
  // This replaces a test asserting the secret was transmitted verbatim. It is now the opposite
  // property, and the stronger one: nothing a listener captures is usable, so a packet capture of a
  // whole handshake is worth nothing. Asserted against the key's own bytes, because a regression
  // that put them back would satisfy every other test in this file.
  const secret = '0123456789abcdef0123456789abcdef0123456789abcdef';
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
  });
  const client = await connect(server.port, {
    secret,
    // The stub proves against its own key, so this connection is expected to be refused; what is
    // under test is what the client *sent* before that.
  }).catch(() => null);
  const hello = await server.hello;

  const key = Buffer.from(secret, 'utf8');
  assert.ok(!hello.includes(key), 'the key itself appears in the greeting');
  for (let length = 8; length <= key.length; length += 1) {
    assert.ok(
      !hello.includes(key.subarray(0, length)),
      `a ${length}-byte prefix of the key appears in the greeting`,
    );
  }
  // What is sent instead identifies the key without being it.
  assert.deepEqual(Buffer.from(hello.subarray(8, 40)), keyRef(key));

  client?.close();
  await server.close();
});

test('filters given to connect travel in the greeting, not in a later frame', async () => {
  // The point of the option is that the filter is in force before the first frame. If the client
  // sent it as a `SetFilter` after the handshake instead, the connection would be unfiltered for a
  // round trip — which is the cost the option exists to avoid, and it would be invisible from the
  // consumer's side.
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
  });
  const client = await connect(server.port, {
    filters: [{ name: 'mine', spec: { is_vote: { value: false } } }],
  });
  const hello = await server.hello;

  // Version, streams, codecs, pad, the fixed-width reference and nonce, then the dictionary id.
  const base = 8 + 32 + 32 + 4;
  const length = hello.readUInt32LE(base);
  const document = hello.subarray(base + 4, base + 4 + length).toString('utf8');

  assert.equal(hello.length, base + 4 + length, 'the greeting ends exactly where the filter does');
  assert.deepEqual(JSON.parse(document), {
    filters: [{ name: 'mine', spec: { is_vote: { value: false } } }],
  });

  client.close();
  await server.close();
});

test('connecting without filters sends a greeting that ends at the dictionary id', async () => {
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
  });
  const client = await connect(server.port);
  const hello = await server.hello;

  assert.equal(
    hello.length,
    8 + 32 + 32 + 4,
    'an absent filter must add nothing at all, not a zero-length prefix',
  );

  client.close();
  await server.close();
});

test('a server that negotiates no compression is refused by the client', async () => {
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.None, Stream.TRANSACTIONS, 0));
  });
  await assert.rejects(connect(server.port), /requires zstd/);
  await server.close();
});

test('a server rejecting an uncompressed client surfaces as a server error', async () => {
  const detail = 'this server requires a compressed stream; offer zstd or lz4 in the handshake';
  const server = await stub((socket) => {
    socket.write(errorFrame(ErrorCode.BadRequest, detail));
  });
  await assert.rejects(connect(server.port), (err: unknown) => {
    assert.ok(err instanceof ServerError);
    assert.equal(err.code, ErrorCode.BadRequest);
    assert.equal(err.detail, detail);
    return true;
  });
  await server.close();
});

test('transactions arrive decoded, decompressed and in order', async () => {
  const tx = load('tx_simple.bin');
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
    for (let seq = 0; seq < 3; seq += 1) {
      const body = zstdCompressSync(tx);
      const frame = writeFrame(FrameKind.Transaction, BigInt(seq), body);
      // Set the compressed flag, which `writeFrame` leaves clear for control frames.
      frame.writeUInt8(0b100 | Codec.Zstd, 4 + 1);
      socket.write(frame);
    }
  });

  const client = await connect(server.port, { streams: Stream.TRANSACTIONS });
  assert.equal(client.granted, Stream.TRANSACTIONS);
  assert.equal(client.sessionId, 99n);
  assert.equal(client.dictionaryActive, false);

  const seen: bigint[] = [];
  for await (const event of client) {
    assert.equal(event.type, 'transaction');
    if (event.type === 'transaction') {
      assert.equal(event.transaction.slot, 250_000_001n);
      assert.equal(event.transaction.accountCount, 3);
    }
    seen.push(event.seq);
    if (seen.length === 3) break;
  }
  assert.deepEqual(seen, [0n, 1n, 2n]);
  assert.ok(client.decodedBytes > client.wireBytes, 'compression should shrink the stream');

  client.close();
  await server.close();
});

test('the negotiated dictionary is used, and a mismatched one is ignored', async () => {
  const dictionary = load('dictionary.bin');
  const id = dictionaryId(dictionary);
  const frame = load('frame_zstd_dictionary.bin');

  const server = await stub((socket, hello) => {
    // The offered id trails the fixed-width reference and nonce.
    const offered = hello.readUInt32LE(8 + 32 + 32);
    assert.equal(offered, id, 'the client should offer the dictionary it holds');
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, id));
    socket.write(frame);
  });

  const client = await connect(server.port, { dictionary });
  assert.equal(client.dictionaryActive, true);
  for await (const event of client) {
    assert.equal(event.type, 'transaction');
    if (event.type === 'transaction') assert.equal(event.transaction.slot, 250_000_001n);
    break;
  }
  client.close();
  await server.close();

  // A server holding no dictionary announces none, and the connection works without one.
  const other = await stub((socket) => socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0)));
  const second = await connect(other.port, { dictionary });
  assert.equal(second.dictionaryActive, false);
  assert.equal(second.dictionaryWasSent, false);
  second.close();
  await other.close();
});

/**
 * A client that holds nothing is given the dictionary and uses it on this connection.
 *
 * The whole point: no file to ship, no configuration, and the full ratio from the first message
 * rather than after somebody notices it was missing.
 */
test('a client holding nothing is given the dictionary', async () => {
  const dictionary = load('dictionary.bin');
  const id = dictionaryId(dictionary);

  const server = await stub((socket, hello) => {
    // The client asked for it: the capability byte follows version, streams and codecs.
    assert.equal(hello.readUInt8(7) & Capability.ACCEPTS_DICTIONARY, Capability.ACCEPTS_DICTIONARY);
    // And offered nothing, since it holds nothing.
    assert.equal(hello.readUInt32LE(8 + 32 + 32), 0);

    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, id));
    socket.write(writeFrame(FrameKind.Dictionary, 0n, writeDictionary({ id, bytes: dictionary })));
    socket.write(load('frame_zstd_dictionary.bin'));
  });

  const client = await connect(server.port);
  assert.equal(client.dictionaryActive, true, 'the pushed dictionary was not applied');
  assert.equal(client.dictionaryWasSent, true);

  // And it decodes the body the server compressed with it, which is what the id stands for.
  for await (const event of client) {
    assert.equal(event.type, 'transaction');
    if (event.type === 'transaction') assert.equal(event.transaction.slot, 250_000_001n);
    break;
  }
  client.close();
  await server.close();
});

/** A received dictionary is cached, and the next connection offers it instead of being sent it. */
test('a received dictionary is cached and offered next time', async () => {
  const dictionary = load('dictionary.bin');
  const id = dictionaryId(dictionary);
  const dir = scratchDir('client');
  try {
    const pushing = await stub((socket) => {
      socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, id));
      socket.write(writeFrame(FrameKind.Dictionary, 0n, writeDictionary({ id, bytes: dictionary })));
    });
    const first = await connect(pushing.port, { dictionaryCache: dir });
    assert.equal(first.dictionaryActive, true);
    assert.equal(first.dictionaryWasSent, true);
    first.close();
    await pushing.close();

    const reusing = await stub((socket, hello) => {
      assert.equal(hello.readUInt32LE(8 + 32 + 32), id, 'the cached dictionary was not offered');
      socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, id));
    });
    const second = await connect(reusing.port, { dictionaryCache: dir });
    assert.equal(second.dictionaryActive, true, 'the cached dictionary was not applied');
    assert.equal(
      second.dictionaryWasSent,
      false,
      'the dictionary was fetched again despite being cached',
    );
    second.close();
    await reusing.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * A client whose dictionary is the wrong one is brought up to date.
 *
 * "Outdated" is only ever "a different hash" — there is no ordering between dictionary ids — so
 * this is the same path as holding none, and has to work the same way.
 */
test('a client holding a different dictionary is brought up to date', async () => {
  const dictionary = load('dictionary.bin');
  const id = dictionaryId(dictionary);
  const stale = Buffer.from(dictionary).reverse();
  assert.notEqual(dictionaryId(stale), id);

  const server = await stub((socket, hello) => {
    assert.equal(hello.readUInt32LE(8 + 32 + 32), dictionaryId(stale));
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, id));
    socket.write(writeFrame(FrameKind.Dictionary, 0n, writeDictionary({ id, bytes: dictionary })));
  });

  const client = await connect(server.port, { dictionary: stale });
  assert.equal(client.dictionaryActive, true, 'a stale holder was left on plain zstd');
  assert.equal(client.dictionaryWasSent, true);
  client.close();
  await server.close();
});

/**
 * What a server that is wrong, rather than merely absent, does after the acknowledgement.
 *
 * The checks around the pushed dictionary all guard against a peer that lies — a compromised node,
 * a proxy rewriting frames, a build whose dictionary and id came apart. The stub proves the key
 * honestly, so what these establish is that this client keeps checking *after* the peer is
 * authenticated: possession of the key buys the right to stream, not the right to be believed
 * about what it is sending.
 */
test('a dictionary whose bytes do not match what was announced is refused', async () => {
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 12_345));
    socket.write(
      writeFrame(
        FrameKind.Dictionary,
        0n,
        writeDictionary({ id: 12_345, bytes: Buffer.from('not the dictionary') }),
      ),
    );
  });
  await assert.rejects(connect(server.port), /not the one it announced/);
  await server.close();
});

/** So is one whose frame names a different id than the acknowledgement did. */
test('a dictionary under a different id is refused', async () => {
  const dictionary = load('dictionary.bin');
  const id = dictionaryId(dictionary);
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, id));
    // The right bytes, under a label that is not what the ack promised.
    socket.write(
      writeFrame(FrameKind.Dictionary, 0n, writeDictionary({ id: id + 1, bytes: dictionary })),
    );
  });
  await assert.rejects(connect(server.port), /not the one it announced/);
  await server.close();
});

/** A frame that is not a dictionary, where the dictionary belongs, ends the handshake. */
test('something other than a dictionary ends the handshake', async () => {
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 12_345));
    socket.write(writeFrame(FrameKind.Pong, 0n, Buffer.alloc(0)));
  });
  await assert.rejects(connect(server.port), /announced dictionary/);
  await server.close();
});

/**
 * A server that announces a dictionary and never sends it does not hang the client.
 *
 * Silence is the failure mode a timeout exists for. Without one this client would wait in `connect`
 * indefinitely, which from the outside looks like a slow network rather than a peer that will never
 * answer.
 */
test('an announced dictionary that never arrives times out', async () => {
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 12_345));
  });
  await assert.rejects(connect(server.port, { connectTimeoutMs: 500 }), /timed out/);
  await server.close();
});

/**
 * A dictionary larger than this client accepts is refused on its declared length.
 *
 * Refused before the body is taken, so the number a peer invented never decides how much this side
 * allocates. Otherwise an eight-byte message would be an instruction to reserve as much memory as
 * the length field can express.
 */
test('a dictionary past the limit is refused on its length', async () => {
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 12_345));
    const body = Buffer.alloc(DICTIONARY_HEADER_LEN);
    body.writeUInt32LE(12_345, 0);
    body.writeUInt32LE(MAX_DICTIONARY_BYTES + 1, 4);
    socket.write(writeFrame(FrameKind.Dictionary, 0n, body));
  });
  await assert.rejects(connect(server.port), /limit/);
  await server.close();
});

/**
 * A second dictionary, once the stream is running, is refused rather than ignored.
 *
 * "The dictionary does not change during a run" is what a subscriber relies on to decode anything
 * at all. A server sending another means the next frame is compressed with something this side is
 * not decoding with — so it is named here, rather than surfacing as corruption several frames later
 * with nothing pointing at the cause.
 */
test('a second dictionary mid-stream is refused', async () => {
  const dictionary = load('dictionary.bin');
  const id = dictionaryId(dictionary);
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, id));
    const frame = writeFrame(FrameKind.Dictionary, 0n, writeDictionary({ id, bytes: dictionary }));
    socket.write(frame);
    // And again, once the connection is up.
    socket.write(frame);
  });

  const client = await connect(server.port);
  assert.equal(client.dictionaryActive, true);
  await assert.rejects(async () => {
    for await (const _event of client) {
      // Drains until the second dictionary is reached.
    }
  }, /mid-stream/);
  client.close();
  await server.close();
});

test('a ping is answered without the consumer doing anything', async () => {
  let pongs = 0;
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
    socket.write(writeFrame(FrameKind.Ping, 1n, Buffer.alloc(0)));
    socket.on('data', (chunk) => {
      if (chunk.length >= FRAME_HEADER_LEN && readFrameHeader(chunk).kind === FrameKind.Pong) {
        pongs += 1;
      }
    });
  });

  const client = await connect(server.port);
  for await (const event of client) {
    if (event.type === 'ping') break;
  }
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(pongs, 1);
  client.close();
  await server.close();
});

test('a lag report is counted as a gap and resets the expected sequence', async () => {
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
    const body = Buffer.alloc(16);
    body.writeBigUInt64LE(500n, 0);
    body.writeBigUInt64LE(1000n, 8);
    socket.write(writeFrame(FrameKind.Lag, 3n, body));
  });

  const client = await connect(server.port);
  for await (const event of client) {
    if (event.type === 'lag') {
      assert.equal(event.lag.dropped, 500n);
      assert.equal(event.lag.resumeSeq, 1000n);
      break;
    }
  }
  assert.equal(client.gaps, 500n);
  client.close();
  await server.close();
});

test('an unknown frame kind is delivered rather than killing the connection', async () => {
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
    socket.write(writeFrame(200 as FrameKind, 1n, Buffer.from([1, 2, 3])));
    socket.write(writeFrame(FrameKind.Pong, 2n, Buffer.alloc(0)));
  });

  const client = await connect(server.port);
  const kinds: string[] = [];
  for await (const event of client) {
    kinds.push(event.type);
    if (event.type === 'other') assert.equal(event.kind, 200);
    if (event.type === 'pong') break;
  }
  assert.deepEqual(kinds, ['other', 'pong']);
  client.close();
  await server.close();
});

test('a frame split across TCP reads is reassembled', async () => {
  const tx = load('tx_simple.bin');
  const frame = writeFrame(FrameKind.Transaction, 0n, tx);
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
    // One byte at a time is the worst case a stream socket can produce.
    for (const byte of frame) socket.write(Buffer.from([byte]));
  });

  const client = await connect(server.port);
  for await (const event of client) {
    assert.equal(event.type, 'transaction');
    if (event.type === 'transaction') assert.equal(event.transaction.slot, 250_000_001n);
    break;
  }
  client.close();
  await server.close();
});

test('a server error mid-stream rejects the iterator', async () => {
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
    socket.write(errorFrame(ErrorCode.TooSlow, 'subscriber fell too far behind'));
  });

  const client = await connect(server.port);
  await assert.rejects(
    (async () => {
      for await (const _ of client) {
        // Drains until the error arrives.
      }
    })(),
    (err: unknown) => {
      assert.ok(err instanceof ServerError);
      assert.equal(err.code, ErrorCode.TooSlow);
      return true;
    },
  );
  await server.close();
});

/**
 * A consumer that stops asking for events stops the client reading bytes.
 *
 * Without this the client drains the socket into an unbounded array, which is wrong twice over. It
 * is a memory leak shaped like a fast client — on a busy node the heap is gone in seconds — and it
 * hides the fall behind from the server, which decides what a slow subscriber is owed and can only
 * do so if flow control lets it see one. The observable form is the server's writes ceasing to be
 * accepted once the backlog bound is reached.
 */
test('a consumer that stops reading stops the client reading the socket', async () => {
  const tx = load('tx_simple.bin');
  let written = 0;

  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
    // Writes until the kernel stops accepting, then resumes on `drain`. A client that keeps reading
    // keeps draining it, so this never stops; one that has stopped wedges it within a socket buffer
    // and a backlog. The *count* is the observable, not whether it ever blocked — a synchronous
    // write loop outruns any reader momentarily, so a single stall proves nothing.
    const pump = (): void => {
      for (;;) {
        const body = zstdCompressSync(tx);
        const frame = writeFrame(FrameKind.Transaction, BigInt(written), body);
        frame.writeUInt8(0b100 | Codec.Zstd, 4 + 1);
        written += 1;
        if (!socket.write(frame)) {
          socket.once('drain', pump);
          return;
        }
        // Bounded so an unbounded client ends this test rather than running until it dies.
        if (written >= 400_000) return;
      }
    };
    pump();
  });

  const client = await connect(server.port, { streams: Stream.TRANSACTIONS });
  // One event, then nothing: the consumer has gone away mid-stream.
  const first = await client.next();
  assert.equal(first?.type, 'transaction');

  await new Promise((resolve) => setTimeout(resolve, 750));
  const settled = written;
  await new Promise((resolve) => setTimeout(resolve, 750));

  // The point: with the consumer gone, the frames the server got away with are bounded by one
  // socket buffer plus one backlog, and stop. A client draining into memory never stops accepting,
  // so this second sample would be far above the first.
  assert.equal(
    written,
    settled,
    `the server sent ${written - settled} more frames while the consumer was not reading, so the ` +
      'client is buffering without bound rather than applying backpressure',
  );
  assert.ok(
    written < 400_000,
    'the server ran out of frames to send before backpressure could be observed',
  );

  client.close();
  await server.close();
});

/**
 * And reading again lets the stream go on, rather than wedging the connection permanently.
 *
 * This is the risk the pause above introduces: a socket paused and never resumed is a subscriber
 * that stops receiving for good, which is worse than the unbounded buffer it replaced.
 */
test('resuming a paused consumer restarts the stream', async () => {
  const tx = load('tx_simple.bin');
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
    let seq = 0;
    const pump = (): void => {
      for (;;) {
        const body = zstdCompressSync(tx);
        const frame = writeFrame(FrameKind.Transaction, BigInt(seq), body);
        frame.writeUInt8(0b100 | Codec.Zstd, 4 + 1);
        seq += 1;
        if (seq > 40_000) return;
        if (!socket.write(frame)) {
          socket.once('drain', pump);
          return;
        }
      }
    };
    pump();
  });

  const client = await connect(server.port, { streams: Stream.TRANSACTIONS });
  assert.equal((await client.next())?.type, 'transaction');
  await new Promise((resolve) => setTimeout(resolve, 800));

  // Draining the backlog has to bring the socket back, or a consumer that pauses once is stuck.
  let seen = 0;
  const deadline = Date.now() + 10_000;
  while (seen < 12_000) {
    const event = await client.next();
    assert.ok(event !== null, `the stream ended after ${seen} events`);
    seen += 1;
    if (Date.now() > deadline) break;
  }
  assert.ok(
    seen >= 12_000,
    `only ${seen} events arrived, which is fewer than the backlog bound could have held, so the ` +
      'socket never resumed',
  );

  client.close();
  await server.close();
});

/**
 * A raw server socket, for tests that must answer the greeting themselves.
 *
 * `stub` runs the whole exchange correctly by design, which is what makes every other test in this
 * file also a handshake test. These need the opposite: a peer that gets the exchange *wrong*.
 */
async function rawStub(onFrame: (socket: Socket, header: ReturnType<typeof readFrameHeader>, body: Buffer) => void): Promise<Stub> {
  const server: Server = createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on('error', () => {});
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        if (buffer.length < FRAME_HEADER_LEN) return;
        const header = readFrameHeader(buffer);
        const end = FRAME_HEADER_LEN + header.len;
        if (buffer.length < end) return;
        const body = Buffer.from(buffer.subarray(FRAME_HEADER_LEN, end));
        buffer = buffer.subarray(end);
        onFrame(socket, header, body);
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as AddressInfo).port,
    hello: Promise.resolve(Buffer.alloc(0)),
    close: () => new Promise<void>((resolve) => { server.close(() => resolve()); }),
  };
}

/**
 * A peer that skips the challenge entirely is refused.
 *
 * This is the failure that makes the whole exchange decorative: if an acknowledgement arriving
 * without a challenge were accepted, anything that could accept a TCP connection would be trusted,
 * and proving possession would be optional in exactly the case where it matters.
 */
test('a server that answers the greeting without proving anything is refused', async () => {
  const server = await rawStub((socket, header) => {
    if (header.kind === FrameKind.Hello) {
      socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
    }
  });

  await assert.rejects(
    () => connect(server.port),
    (error: Error) => /without proving|did not prove/.test(error.message),
    'a server that never challenged was accepted',
  );
  await server.close();
});

/** A challenge carrying a proof the key does not produce is refused. */
test('a server that cannot prove it holds the key is refused', async () => {
  const server = await rawStub((socket, header, body) => {
    if (header.kind !== FrameKind.Hello) return;
    // A well-formed challenge whose proof is simply wrong: the shape is right, the secret is not.
    const forged = Buffer.concat([Buffer.alloc(32, 42), Buffer.alloc(32, 0xff)]);
    socket.write(writeFrame(FrameKind.Challenge, 0n, forged));
    void body;
  });

  await assert.rejects(
    () => connect(server.port),
    (error: Error) => /did not prove/.test(error.message),
    'a forged proof was accepted',
  );
  await server.close();
});

/**
 * A proof valid for one connection does not satisfy the next.
 *
 * The client's nonce is what makes that true, so this fails if the nonce is ever reused or
 * predictable — which is what would let a recorded handshake be replayed at a client.
 */
test('a server proof captured from one connection is refused at the next', async () => {
  const captured: { serverNonce: Buffer; proof: Buffer }[] = [];
  const server = await rawStub((socket, header, body) => {
    if (header.kind !== FrameKind.Hello) return;
    const transcript: Transcript = {
      keyRef: Buffer.from(body.subarray(8, 40)),
      clientNonce: Buffer.from(body.subarray(40, 72)),
      serverNonce: Buffer.alloc(32, 42),
      binding: NO_BINDING,
    };
    // The first connection is answered honestly and recorded; every later one replays it.
    const answer =
      captured.length === 0
        ? { serverNonce: transcript.serverNonce, proof: serverProof(transcript, SECRET) }
        : captured[0]!;
    if (captured.length === 0) captured.push(answer);
    socket.write(writeFrame(FrameKind.Challenge, 0n, Buffer.concat([answer.serverNonce, answer.proof])));
    if (header.kind === FrameKind.Hello) {
      // Acknowledge after the proof arrives, so an accepted handshake completes.
      socket.once('data', () => socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0)));
    }
  });

  const first = await connect(server.port);
  first.close();

  // The second client sends a different nonce, so the recorded proof no longer fits its transcript.
  await assert.rejects(
    () => connect(server.port),
    (error: Error) => /did not prove/.test(error.message),
    'a replayed proof was accepted, so the client nonce is not doing its job',
  );
  await server.close();
});

/** A challenge that is too short is a protocol error, not a crash or a silent pass. */
test('a truncated challenge is refused rather than read past its end', async () => {
  for (const length of [0, 31, 63]) {
    const server = await rawStub((socket, header) => {
      if (header.kind === FrameKind.Hello) {
        socket.write(writeFrame(FrameKind.Challenge, 0n, Buffer.alloc(length)));
      }
    });
    await assert.rejects(() => connect(server.port), `a ${length}-byte challenge was accepted`);
    await server.close();
  }
});

/** A peer that accepts the connection and says nothing is given up on. */
test('a server that never answers is timed out', async () => {
  const server = await rawStub(() => {});
  await assert.rejects(
    () => connect(server.port, { connectTimeoutMs: 200 }),
    (error: Error) => /timed out|timeout/i.test(error.message),
    'a silent server held the client open',
  );
  await server.close();
});

/** Two frames arriving in one TCP segment are both delivered. */
test('frames coalesced into one read are both delivered', async () => {
  const tx = load('tx_simple.bin');
  const server = await stub((socket) => {
    const frames = [
      helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0),
      writeFrame(FrameKind.Transaction, 0n, tx),
      writeFrame(FrameKind.Transaction, 1n, tx),
    ];
    // One write, so the client sees the acknowledgement and both transactions as a single chunk.
    socket.write(Buffer.concat(frames));
  });

  const client = await connect(server.port, { streams: Stream.TRANSACTIONS });
  for (let i = 0; i < 2; i += 1) {
    const event = await client.next();
    assert.equal(event?.type, 'transaction', `event ${i}`);
  }
  client.close();
  await server.close();
});

/** Raw shreds decode, and carry the bytes the node received unchanged. */
test('a raw shred arrives with its bytes intact', async () => {
  const shredBytes = Buffer.alloc(1203);
  for (let i = 0; i < shredBytes.length; i += 1) shredBytes[i] = i % 251;

  const body = Buffer.alloc(32 + shredBytes.length);
  body.writeBigUInt64LE(300_000_007n, 0);
  body.writeUInt32LE(41, 8);
  body.writeUInt32LE(32, 12);
  body.writeBigUInt64LE(1_700_000_000_000n, 16);
  body.writeUInt16LE(2, 24);
  body.writeUInt8(1, 26); // parity
  shredBytes.copy(body, 32);

  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.RAW_SHREDS, 0));
    socket.write(writeFrame(FrameKind.RawShred, 0n, body));
  });

  const client = await connect(server.port, { streams: Stream.RAW_SHREDS });
  const event = await client.next();
  assert.equal(event?.type, 'raw-shred');
  if (event?.type !== 'raw-shred') throw new Error('unreachable');
  assert.equal(event.shred.slot, 300_000_007n);
  assert.equal(event.shred.index, 41);
  assert.equal(event.shred.fecSetIndex, 32);
  assert.equal(event.shred.rxTsNs, 1_700_000_000_000n);
  assert.equal(event.shred.source, 2);
  assert.equal(event.shred.isData, false);
  assert.deepEqual(Buffer.from(event.shred.bytes), shredBytes);

  client.close();
  await server.close();
});

/** Slot boundaries, entries and duplicates all reach a consumer that asked for them. */
test('every event stream decodes into its own event type', async () => {
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.SLOT_EVENTS | Stream.ENTRIES | Stream.DUPLICATES, 0));
    socket.write(writeFrame(FrameKind.SlotStart, 0n, load('slot_start.bin')));
    socket.write(writeFrame(FrameKind.Entry, 1n, load('entry.bin')));
    socket.write(writeFrame(FrameKind.Duplicate, 2n, load('duplicate.bin')));
    socket.write(writeFrame(FrameKind.SlotEnd, 3n, load('slot_end.bin')));
  });

  const client = await connect(server.port, {
    streams: Stream.SLOT_EVENTS | Stream.ENTRIES | Stream.DUPLICATES,
  });
  const seen: string[] = [];
  for (let i = 0; i < 4; i += 1) {
    const event = await client.next();
    assert.ok(event !== null, `the stream ended after ${seen.length} events`);
    seen.push(event.type);
  }
  assert.deepEqual(seen, ['slot-start', 'entry', 'duplicate', 'slot-end']);

  client.close();
  await server.close();
});

/** Closing twice is not an error, and neither is closing before anything was read. */
test('closing is idempotent', async () => {
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
  });
  const client = await connect(server.port, { streams: Stream.TRANSACTIONS });
  client.close();
  client.close();
  assert.equal(await client.next(), null, 'a closed client kept yielding events');
  await server.close();
});

/**
 * The dictionary arrives correctly however the network fragments it.
 *
 * A real dictionary is about a megabyte, so it *always* spans many reads — unlike every other
 * control message, which fits in one. The handshake reader has to reassemble it before parsing, and
 * a byte-at-a-time delivery is the strongest form of that: if any part of the reader assumed a
 * whole frame per chunk, this is where it shows.
 */
test('a dictionary split across many reads is reassembled', async () => {
  const dictionary = load('dictionary.bin');
  const id = dictionaryId(dictionary);

  const server = await stub((socket) => {
    const bytes = Buffer.concat([
      helloAck(Codec.Zstd, Stream.TRANSACTIONS, id),
      writeFrame(FrameKind.Dictionary, 0n, writeDictionary({ id, bytes: dictionary })),
      load('frame_zstd_dictionary.bin'),
    ]);
    // Small, uneven chunks, including ones that split the length prefix itself.
    let at = 0;
    const push = (): void => {
      if (at >= bytes.length) return;
      const size = (at % 7) + 1;
      socket.write(bytes.subarray(at, at + size));
      at += size;
      setImmediate(push);
    };
    push();
  });

  const client = await connect(server.port);
  assert.equal(client.dictionaryActive, true, 'a fragmented dictionary was not reassembled');
  assert.equal(client.dictionaryWasSent, true);
  for await (const event of client) {
    assert.equal(event.type, 'transaction');
    if (event.type === 'transaction') assert.equal(event.transaction.slot, 250_000_001n);
    break;
  }
  client.close();
  await server.close();
});

/**
 * And when the acknowledgement, the dictionary and the first data frame arrive in one read.
 *
 * The opposite fragmentation, and the one that catches a reader which waits for another chunk that
 * never comes: everything it needs is already in the buffer. A stream that stalled here would look
 * like a hung connection rather than a parsing fault.
 */
test('an acknowledgement, dictionary and data frame in one read all land', async () => {
  const dictionary = load('dictionary.bin');
  const id = dictionaryId(dictionary);

  const server = await stub((socket) => {
    socket.write(
      Buffer.concat([
        helloAck(Codec.Zstd, Stream.TRANSACTIONS, id),
        writeFrame(FrameKind.Dictionary, 0n, writeDictionary({ id, bytes: dictionary })),
        load('frame_zstd_dictionary.bin'),
      ]),
    );
  });

  const client = await connect(server.port);
  assert.equal(client.dictionaryActive, true);
  // The data frame rode in behind the dictionary and must not have been dropped with it.
  for await (const event of client) {
    assert.equal(event.type, 'transaction');
    if (event.type === 'transaction') assert.equal(event.transaction.slot, 250_000_001n);
    break;
  }
  client.close();
  await server.close();
});

/**
 * A dictionary id with the high bit set survives the round trip.
 *
 * The id is a `u32` and half of all possible ids exceed 2^31. JavaScript has no unsigned integer
 * type, so anything that read or compared it through a signed path would work for half the
 * dictionaries in existence and silently fail for the other half — the kind of defect that passes
 * every test written against one fixture.
 */
test('a dictionary id with the high bit set is handled unsigned', async () => {
  const high = 0xdead_beef;
  assert.ok(high > 0x7fff_ffff, 'the fixture must actually exercise the high bit');

  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, high));
    // Bytes that do not hash to it, so the client's check must reject — and the rejection message
    // has to show the id it was comparing, unsigned.
    socket.write(
      writeFrame(FrameKind.Dictionary, 0n, writeDictionary({ id: high, bytes: Buffer.from('x') })),
    );
  });
  await assert.rejects(connect(server.port), (error: Error) => {
    assert.match(error.message, /not the one it announced/);
    assert.match(error.message, new RegExp(String(high)), 'the id was reported signed');
    return true;
  });
  await server.close();
});

/**
 * A hostile node cannot fill the disk by handing out endless dictionaries.
 *
 * Every distinct dictionary a node sends is cached, so without a bound a node could write as much
 * as it liked into a subscriber's filesystem, a megabyte per connection, for as long as the
 * subscriber kept reconnecting.
 */
test('the dictionary cache stays bounded against a node that keeps changing it', async () => {
  const dir = scratchDir('flood');
  try {
    const cache = new DictionaryCache(dir);
    const base = load('dictionary.bin');
    for (let round = 0; round < 24; round += 1) {
      // A distinct dictionary each time, as a node changing its own would produce.
      const bytes = Buffer.concat([base, Buffer.from([round])]);
      assert.ok(cache.store(dictionaryId(bytes), bytes));
    }
    const held = readdirSync(dir).filter((name) => name.endsWith('.dict'));
    assert.ok(held.length <= 8, `the cache holds ${held.length} dictionaries, past its own bound`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * What a peer can make this client hold before it has proved anything.
 *
 * The `len` in every frame header belongs to the sender, and it is what this side buffers against.
 * During the handshake the sender is an address the caller typed and nothing more: it has produced
 * no proof, and a challenge or a refusal is the first thing it says. Bounded only by what a frame
 * may be, either of them is sixteen megabytes for the price of a header.
 *
 * The stubs below answer the greeting with a bare header and no body on purpose. A client that
 * refuses on the number never waits; one that refuses after reading would sit until the connect
 * timeout, which is what the short timeout in each of these catches.
 */

/** A bare header announcing bytes that will never follow it. */
function lyingHeader(kind: FrameKind, len: number): Buffer {
  const header = writeFrame(kind, 0n, Buffer.alloc(0)).subarray(0, FRAME_HEADER_LEN);
  const copy = Buffer.from(header);
  copy.writeUInt32LE(len, 0);
  return copy;
}

test('a refusal cannot cost a frame\'s worth of memory', async () => {
  const server = await rawStub((socket) =>
    socket.write(lyingHeader(FrameKind.Error, MAX_FRAME_PAYLOAD)),
  );
  await assert.rejects(
    connect(server.port, { connectTimeoutMs: 2_000 }),
    new RegExp(String(MAX_HANDSHAKE_BYTES)),
  );
  await server.close();
});

test('a challenge cannot cost a frame\'s worth of memory', async () => {
  const server = await rawStub((socket) =>
    socket.write(lyingHeader(FrameKind.Challenge, MAX_FRAME_PAYLOAD)),
  );
  await assert.rejects(connect(server.port, { connectTimeoutMs: 2_000 }), /Challenge/);
  await server.close();
});

test('a dictionary is allowed to be larger than a control message', async () => {
  // The one handshake frame the ceiling does not apply to, and the only one that arrives after the
  // server has proved itself — which is what makes the larger allowance affordable.
  const bytes = Buffer.alloc(MAX_HANDSHAKE_BYTES * 2, 0x5a);
  const id = dictionaryId(bytes);
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, id));
    socket.write(writeFrame(FrameKind.Dictionary, 0n, writeDictionary({ id, bytes })));
  });

  const client = await connect(server.port);
  assert.equal(client.dictionaryActive, true);
  assert.equal(client.dictionaryWasSent, true);
  client.close();
  await server.close();
});

test('a frame past the configured size is refused rather than buffered up to', async () => {
  // Applied to the frame, not only to what a compressed body expands into: applied only to the
  // expansion it would do nothing at all against one that arrives uncompressed, which is exactly
  // the case someone lowering it is trying to bound.
  const server = await stub((socket) => {
    socket.write(helloAck(Codec.Zstd, Stream.TRANSACTIONS, 0));
    socket.write(lyingHeader(FrameKind.Transaction, MAX_FRAME_PAYLOAD));
  });

  const client = await connect(server.port, { maxMessageBytes: 64 * 1024 });
  await assert.rejects(async () => {
    for await (const _event of client) {
      // Drains until the oversized frame is reached.
    }
  }, new RegExp(String(64 * 1024)));
  client.close();
  await server.close();
});
