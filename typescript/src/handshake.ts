/**
 * Proving possession of your key without ever sending it.
 *
 * # What this replaces
 *
 * A password-style handshake sends the credential to authenticate. Your key is a single value that
 * is both name and secret, so sending it puts a fully usable credential on the wire on every
 * connect — recoverable by anyone who can capture the traffic or terminate the TLS in front of it.
 *
 * Nothing here sends it. Both ends prove they hold it instead.
 *
 * ```text
 * you  → node   key reference, your nonce
 * node → you    its nonce, HMAC(key, "server" ‖ transcript)
 * you           check it — a peer that cannot produce this does not hold your key
 * you  → node   HMAC(key, "client" ‖ transcript)
 * ```
 *
 * # Why there is no fingerprint to configure
 *
 * QUIC is always TLS, so the node presents a certificate. **Nothing verifies it**, nobody
 * distributes it, and the node may mint a fresh one on every restart. It is not what authenticates
 * the node — your key is.
 *
 * Its hash goes into the transcript, and that is all it is for. Anything that terminates your TLS
 * and reconnects onwards must present a certificate of its own, so the transcript it shares with you
 * differs from the one it shares with the node. It cannot compute either proof without your key, and
 * it cannot pass a proof between the two sessions, because each is bound to a different certificate.
 *
 * That is why this SDK needs no fingerprint, no certificate authority, and no domain name — and why
 * a node rotating its certificate does not break you.
 *
 * Over plain TCP there is no certificate and therefore no binding. Your key still never crosses the
 * wire, but an interposed relay is no longer detectable, which is why TCP is for a subscriber that
 * is not crossing a network it does not control.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const REF_DOMAIN = Buffer.from('manka-shreds/key-ref/v1');
const SERVER_DOMAIN = Buffer.from('manka-shreds/server-proof/v1');
const CLIENT_DOMAIN = Buffer.from('manka-shreds/client-proof/v1');

/** Bytes in a key reference, a nonce, a binding and a proof — all SHA-256 sized. */
export const DIGEST_LEN = 32;

/**
 * A public, stable reference to an API key.
 *
 * SHA-256 of the key under a domain separator. This is what travels in the greeting, and what
 * belongs in a log or a support ticket: it identifies your key without being it.
 */
export function keyRef(key: Buffer): Buffer {
  return createHash('sha256').update(REF_DOMAIN).update(key).digest();
}

/** A key reference rendered for a log — the first sixteen hex characters. */
export function shortRef(reference: Buffer): string {
  return reference.toString('hex').slice(0, 16);
}

/**
 * What ties a proof to one TLS session: the hash of the certificate the server presented.
 *
 * All zeroes for a transport that presents no certificate — plain TCP.
 */
export const NO_BINDING: Buffer = Buffer.alloc(DIGEST_LEN);

/** The binding for a server presenting `certificateDer`. */
export function bindingOf(certificateDer: Uint8Array): Buffer {
  return createHash('sha256').update(certificateDer).digest();
}

/** Everything both ends must agree on for a proof to mean anything. */
export interface Transcript {
  /** Which key is claimed. */
  keyRef: Buffer;
  /** Chosen by the client. */
  clientNonce: Buffer;
  /** Chosen by the server. */
  serverNonce: Buffer;
  /** The TLS session this belongs to. */
  binding: Buffer;
}

function proof(transcript: Transcript, key: Buffer, domain: Buffer): Buffer {
  return createHmac('sha256', key)
    .update(domain)
    .update(transcript.keyRef)
    .update(transcript.clientNonce)
    .update(transcript.serverNonce)
    .update(transcript.binding)
    .digest();
}

/** The proof the server sends, which authenticates the node to you. */
export function serverProof(transcript: Transcript, key: Buffer): Buffer {
  return proof(transcript, key, SERVER_DOMAIN);
}

/** The proof you send, which authenticates you to the node. */
export function clientProof(transcript: Transcript, key: Buffer): Buffer {
  return proof(transcript, key, CLIENT_DOMAIN);
}

/**
 * Whether `presented` is the proof the server should have sent.
 *
 * Compared in constant time: returning early on the first differing byte would tell a forger how
 * much of a guess was right, which is the one piece of feedback it needs.
 */
export function verifyServer(transcript: Transcript, key: Buffer, presented: Buffer): boolean {
  const expected = serverProof(transcript, key);
  // `timingSafeEqual` throws on a length mismatch rather than returning false, and a short proof is
  // something a peer can send, so the length is checked first and separately.
  if (presented.length !== expected.length) return false;
  return timingSafeEqual(expected, presented);
}

/**
 * A nonce for one handshake.
 *
 * From the operating system's generator: it must be unpredictable, not merely unique. A nonce an
 * attacker can anticipate lets it collect a proof over a transcript you are about to produce.
 */
export function freshNonce(): Buffer {
  return randomBytes(DIGEST_LEN);
}
