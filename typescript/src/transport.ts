/**
 * How the client reaches the server: QUIC, or TCP.
 *
 * # Why QUIC is the default
 *
 * Over a WAN one lost packet stalls a TCP stream until it is retransmitted, holding back every
 * message behind it — including messages that already arrived intact. For a latency product
 * carrying a firehose that is the wrong failure mode: the data you are paying to receive early is
 * held hostage by a packet you already have the successor to.
 *
 * QUIC does not head-of-line block the same way, establishes in one round trip, and survives the
 * client changing address. Inside a datacentre TCP is simpler and marginally faster, which is why
 * it remains available — but it is the exception, chosen deliberately, not the default.
 *
 * A node serves both on the same address: QUIC is UDP, so the port number is shared.
 *
 * # The one dependency
 *
 * Node has no QUIC of its own — `node:quic` does not exist in Node 22 LTS, and is experimental and
 * flag-gated where it does. QUIC therefore comes from `@matrixai/quic`, a native addon. It is
 * loaded lazily, so a consumer that only ever uses TCP never pays for it and never fails on a
 * platform it has no binary for.
 */

import { connect as tcpConnect, type Socket } from 'node:net';
import { createHash, webcrypto } from 'node:crypto';

import { NO_BINDING, bindingOf } from './handshake.js';

/** Which transport to use. */
export type Transport = 'quic' | 'tcp';

/**
 * What, if anything, the client checks the server's certificate against.
 *
 * # The node is not authenticated by its certificate
 *
 * It is authenticated by your key. During the handshake the node proves it holds that key, over a
 * transcript bound to the certificate the session completed against — so anything terminating your
 * TLS and reconnecting onwards produces a transcript that does not match, and cannot forge one. See
 * `handshake`.
 *
 * That is why `{ unchecked: true }` is the default and is *not* a downgrade: the certificate carries
 * no trust to begin with, and the node may rotate it whenever it likes without breaking you.
 *
 * - `{ unchecked: true }` — the default. Accept whatever certificate is presented and rely on the
 *   key to authenticate the node. The connection is still encrypted; what is skipped is a trust
 *   store check that would prove nothing a manka-shreds node needs proved.
 * - `{ fingerprint }` — additionally require the leaf certificate's SHA-256 to be exactly this.
 *   Belt and braces: the proof exchange already detects a substituted certificate, and this brings
 *   back the cost it was invented for, since the value must be reissued on every rotation.
 *
 * There is deliberately no trust-store option. This library cannot both delegate verification to
 * its trust store *and* observe the certificate, and observing it is what the channel binding needs
 * — so offering the mode would mean silently giving up the protection the binding provides.
 */
export type ServerVerification = { unchecked: true } | { fingerprint: string };

/** Application-layer protocol identifier, matched against the server's. */
export const ALPN = 'manka-shreds/1';

/** Anything the transport could not do. */
export class TransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TransportError';
  }
}

/**
 * A connection to the server, whichever transport carries it.
 *
 * The framing above this is identical either way, which is the point: one protocol implementation,
 * two ways of moving its bytes.
 */
export interface Wire {
  /** Called with every chunk that arrives. */
  onData(handler: (chunk: Buffer) => void): void;
  /** Called once the peer is done. */
  onClose(handler: () => void): void;
  /** Called when the connection fails. */
  onError(handler: (err: Error) => void): void;
  /** Writes bytes. */
  write(bytes: Buffer): void;
  /** Closes the connection. */
  close(): void;
  /** Starts or restarts delivering data. Called once the handshake reply has been consumed. */
  resume(): void;
  /**
   * What a proof of key possession is bound to on this connection.
   *
   * The hash of whatever certificate the TLS session completed against — nothing verified it, and
   * nothing needed to. Its only job is to differ between two TLS sessions, so that anything
   * terminating yours and reconnecting onwards produces a transcript neither end agrees with.
   *
   * All zeroes over TCP, which presents no certificate: the key still never crosses the wire, but
   * an interposed relay stops being detectable.
   */
  channelBinding(): Buffer;
  /**
   * Stops reading, so the transport's flow control pushes back on the server.
   *
   * A client that stops consuming events must stop consuming *bytes*, or it buffers the firehose in
   * memory and the server goes on believing it is keeping up. See the backlog bound in `client.ts`.
   */
  pause(): void;
}

/** The SHA-256 fingerprint of a DER certificate, lowercase hex. */
export function fingerprintOf(der: Uint8Array): string {
  return createHash('sha256').update(der).digest('hex');
}

/** Normalises a fingerprint written with colons, spaces or capitals. */
function normaliseFingerprint(value: string): string {
  const cleaned = value.replace(/[:\s-]/g, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(cleaned)) {
    throw new TransportError(
      `a certificate fingerprint is 64 hex characters (32 bytes of SHA-256), got ${cleaned.length}`,
    );
  }
  return cleaned;
}

/** Opens a TCP connection with Nagle disabled. */
export function connectTcp(host: string, port: number, timeoutMs: number): Promise<Wire> {
  return new Promise((resolve, reject) => {
    const socket = tcpConnect({ host, port, noDelay: true });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new TransportError(`connecting to ${host}:${port} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    const onError = (err: Error): void => {
      clearTimeout(timer);
      reject(err);
    };
    socket.once('error', onError);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.removeListener('error', onError);
      socket.pause();
      resolve(wrapSocket(socket));
    });
  });
}

function wrapSocket(socket: Socket): Wire {
  return {
    onData: (handler) => socket.on('data', handler),
    onClose: (handler) => socket.on('close', handler),
    onError: (handler) => socket.on('error', handler),
    write: (bytes) => void socket.write(bytes),
    close: () => socket.destroy(),
    resume: () => socket.resume(),
    pause: () => socket.pause(),
    channelBinding: () => NO_BINDING,
  };
}

/** How to open a QUIC connection. */
export interface QuicOptions {
  host: string;
  port: number;
  /** Name presented for TLS. */
  serverName: string;
  verification: ServerVerification;
  timeoutMs: number;
}

/**
 * Opens a QUIC connection and its session stream.
 *
 * The client opens the stream, so the server does not have to guess when it is ready to talk.
 */
export async function connectQuic(options: QuicOptions): Promise<Wire> {
  let QUICClient: typeof import('@matrixai/quic').QUICClient;
  try {
    ({ QUICClient } = await import('@matrixai/quic'));
  } catch (cause) {
    throw new TransportError(
      'QUIC needs the optional @matrixai/quic package, which failed to load. Install it, or ' +
        `pass transport: 'tcp' to use TCP instead. (${(cause as Error).message})`,
    );
  }

  // Captured from the verify callback, which is the only place this library hands the certificate
  // over. Populated during the TLS handshake, so it is set by the time anything reads it.
  let leafCertificate: Uint8Array | null = null;
  const verify = buildVerifier(options.verification, (leaf) => {
    leafCertificate = leaf;
  });
  const client = await QUICClient.createQUICClient(
    {
      host: options.host,
      port: options.port,
      serverName: options.serverName,
      crypto: {
        ops: {
          randomBytes: async (data: ArrayBuffer) => {
            webcrypto.getRandomValues(new Uint8Array(data));
          },
        },
      },
      config: {
        applicationProtos: [ALPN],
        verifyPeer: verify.verifyPeer,
        ...(verify.callback ? { verifyCallback: verify.callback as never } : {}),
        maxIdleTimeout: 60_000,
        keepAliveIntervalTime: 5_000,
      },
      // The library logs to the console at info level by default, which a library has no business
      // doing to its consumer's output.
      logger: quietLogger(),
    },
    { timer: options.timeoutMs },
  );

  const stream = client.connection.newStream('bidi');
  return wrapQuic(client, stream, () => leafCertificate);
}

/** What the TLS layer should do, kept as two separate facts rather than one nullable callback. */
interface Verifier {
  /** Whether the peer's certificate is checked at all. */
  verifyPeer: boolean;
  /** An extra check run when it is. */
  callback?: (certs: Uint8Array[]) => Promise<number | undefined>;
}

/**
 * Builds the certificate check.
 *
 * "Verify nothing" and "verify with a callback that happens to pass" are different things, and
 * collapsing them into one nullable callback is how a client ends up believing it verified
 * something it did not. They are two fields here so that cannot happen by accident.
 */
function buildVerifier(
  verification: ServerVerification,
  onLeaf: (leaf: Uint8Array) => void,
): Verifier {
  // Always a callback, whatever the mode: it is the only place this library hands over the
  // certificate, and the channel binding is computed from it. Without it there is nothing to bind
  // a proof to, and an interposed relay stops being detectable.
  const expected = 'fingerprint' in verification ? normaliseFingerprint(verification.fingerprint) : null;
  return {
    verifyPeer: true,
    callback: async (certs: Uint8Array[]) => {
      const leaf = certs[0];
      if (!leaf) return TLS_BAD_CERTIFICATE;
      onLeaf(leaf);
      if (expected === null) return undefined;
      // Not constant time, and it need not be: the fingerprint is public, and an attacker learning
      // it learns nothing they could not read off the certificate the server shows anyone.
      return fingerprintOf(leaf) === expected ? undefined : TLS_BAD_CERTIFICATE;
    },
  };
}

/** The TLS alert this library reports a rejected certificate with. */
const TLS_BAD_CERTIFICATE = 298;

function wrapQuic(
  client: import('@matrixai/quic').QUICClient,
  stream: import('@matrixai/quic').QUICStream,
  leafCertificate: () => Uint8Array | null,
): Wire {
  const writer = stream.writable.getWriter();
  let onData: (chunk: Buffer) => void = () => {};
  let onClose: () => void = () => {};
  let onError: (err: Error) => void = () => {};
  let started = false;
  let closed = false;
  // Resolved while reading is allowed, replaced with a pending promise while it is not. Awaiting it
  // before each read is what makes a pause reach the wire: the QUIC stream is only drained as fast
  // as this loop reads it, so not reading is flow control rather than a local buffer.
  let gate: Promise<void> = Promise.resolve();
  let open: () => void = () => {};

  const pump = async (): Promise<void> => {
    const reader = stream.readable.getReader();
    try {
      for (;;) {
        await gate;
        const { value, done } = await reader.read();
        if (done) break;
        if (value) onData(Buffer.from(value));
      }
    } catch (err) {
      if (!closed) onError(err as Error);
      return;
    }
    if (!closed) onClose();
  };

  return {
    onData: (handler) => {
      onData = handler;
    },
    onClose: (handler) => {
      onClose = handler;
    },
    onError: (handler) => {
      onError = handler;
    },
    write: (bytes) => {
      writer.write(bytes).catch((err: Error) => {
        if (!closed) onError(err);
      });
    },
    close: () => {
      closed = true;
      // Released so a pump parked on the gate wakes, sees the closed stream and ends, rather than
      // holding the reader — and the process — open forever.
      open();
      void client.destroy({ force: true }).catch(() => {});
    },
    resume: () => {
      open();
      if (started) return;
      started = true;
      void pump();
    },
    channelBinding: () => {
      const leaf = leafCertificate();
      return leaf === null ? NO_BINDING : bindingOf(leaf);
    },
    pause: () => {
      if (closed) return;
      gate = new Promise((resolve) => {
        open = () => {
          open = () => {};
          gate = Promise.resolve();
          resolve();
        };
      });
    },
  };
}

/** A logger that says nothing, for a library that would otherwise print to the console. */
function quietLogger(): never {
  const noop = (): void => {};
  const logger = {
    debug: noop,
    info: noop,
    warn: noop,
    error: noop,
    getChild: () => logger,
  };
  return logger as never;
}
