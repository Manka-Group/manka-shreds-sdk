/**
 * Where this client keeps the compression dictionaries a node gave it.
 *
 * # Why on disk at all
 *
 * The node hands over its dictionary during the handshake when this client does not already hold
 * it. That costs about a megabyte, once, and buys roughly three times the compression for the whole
 * session — a trade worth making every time. Keeping it means paying that megabyte once ever rather
 * than once per connect, which matters for a subscriber that reconnects after a deploy, a network
 * blip, or a restart.
 *
 * # Why keyed by the dictionary's own id
 *
 * There is no version ordering between dictionaries; the id is a hash of the bytes. So the cache is
 * content-addressed: a file is named for what is in it, this client offers whichever id it holds,
 * and the node either agrees or sends the one it wants. "Outdated" simply means "a different hash",
 * and that is the only comparison anyone needs to make.
 *
 * # Failing softly, and saying so
 *
 * A read-only filesystem, a container with no home directory, a full disk — all normal deployments.
 * None of them may stop a subscriber connecting, so every operation here degrades to "no cache".
 * The connection still gets the dictionary and still streams at the full ratio; it just pays the
 * megabyte again next time.
 *
 * This package writes nothing to the console, so the fact is reported as state instead:
 * `MankaShredsClient.dictionaryWasSent` is true when the dictionary came over the wire rather than out
 * of this cache. A subscriber seeing that on *every* connection has a cache that is not working,
 * which is worth knowing and otherwise invisible.
 */

import {
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

import { dictionaryId } from './protocol.js';

/**
 * How many dictionaries a cache keeps before it starts discarding the least recently used.
 *
 * More than one because a subscriber may talk to several nodes — two regions, a candidate alongside
 * production — and thrashing between them would defeat the cache entirely. Small, because each is
 * about a megabyte and nothing needs a long history: the node always sends whatever it wants if
 * this side does not have it.
 */
const KEEP = 8;

/**
 * The environment variable that redirects or disables the cache.
 *
 * A deployment that cannot change the code — a container image, a vendored bundle, a CI job — still
 * needs to say where this may write, or that it may not write at all. `off` (or `none`) disables
 * it; any other value is used as the directory.
 */
export const CACHE_ENV = 'MANKA_SHREDS_DICTIONARY_CACHE';

/**
 * The default location, or `null` when there is nowhere to write.
 *
 * {@link CACHE_ENV} first, then `$XDG_CACHE_HOME/manka-shreds`, then `~/.cache/manka-shreds`. A library writing
 * to a user's home is intrusive enough to be worth naming precisely, and worth being overridable
 * without touching the code that constructs the client.
 */
export function defaultDir(): string | null {
  const explicit = process.env[CACHE_ENV];
  if (explicit !== undefined && explicit !== '') {
    const lowered = explicit.toLowerCase();
    if (lowered === 'off' || lowered === 'none') return null;
    return explicit;
  }
  const xdg = process.env.XDG_CACHE_HOME;
  if (xdg !== undefined && xdg !== '') return join(xdg, 'manka-shreds');
  const home = homedir();
  return home === '' ? null : join(home, '.cache', 'manka-shreds');
}

/** Counter making each temporary filename unique within this process. */
let nextTemp = 0;

/** A directory of dictionaries, addressed by id. */
export class DictionaryCache {
  constructor(readonly dir: string) {}

  /** The cache in the platform's default location, if there is one. */
  static defaultLocation(): DictionaryCache | null {
    const dir = defaultDir();
    return dir === null ? null : new DictionaryCache(dir);
  }

  private pathFor(id: number): string {
    return join(this.dir, `${(id >>> 0).toString(16).padStart(8, '0')}.dict`);
  }

  /**
   * The most recently used dictionary, if any.
   *
   * What this client offers when it connects. Most recent rather than any, because a subscriber
   * that talks to one node overwhelmingly wants that node's dictionary, and offering an older one
   * would make the node send a megabyte it did not need to.
   */
  newest(): { id: number; bytes: Buffer } | null {
    const entries = this.entries().sort((a, b) => b.used - a.used);
    for (const entry of entries) {
      const bytes = this.load(entry.id);
      if (bytes !== null) return { id: entry.id, bytes };
    }
    return null;
  }

  /**
   * Loads the dictionary with this id, if it is held and intact.
   *
   * The bytes are verified against the id in the filename. A file that does not hash to its own
   * name is corrupt or was written by something else, and using it would mean offering an id the
   * bytes do not match — so the node would compress with one dictionary while this side decoded
   * with another. Deleted, and treated as absent.
   */
  load(id: number): Buffer | null {
    const path = this.pathFor(id);
    let bytes: Buffer;
    try {
      bytes = readFileSync(path);
    } catch {
      return null;
    }
    if (dictionaryId(bytes) !== (id >>> 0)) {
      try {
        rmSync(path, { force: true });
      } catch {
        // Nothing to do: it is already being ignored.
      }
      return null;
    }
    this.touch(path);
    return bytes;
  }

  /**
   * Stores `bytes` under `id`, returning whether it was written.
   *
   * Never an error a caller has to handle: the dictionary is already in hand and the connection
   * works either way. A failure simply means it will be sent again next time.
   */
  store(id: number, bytes: Buffer): boolean {
    if (dictionaryId(bytes) !== (id >>> 0)) return false;
    try {
      mkdirSync(this.dir, { recursive: true });
    } catch {
      return false;
    }

    // Written to a temporary name and renamed, so a crash or a full disk leaves either the old file
    // or the new one — never a half-written dictionary that would fail its own id check on the next
    // run and be silently discarded.
    //
    // The temporary name is unique per call, not per process: a subscriber opening several
    // connections at once has each of them receive the same dictionary and store it at the same
    // moment. Sharing one temporary path would let two writes interleave into it and the rename
    // publish the mixture. The rename itself is atomic, so whichever finishes last wins with
    // identical bytes.
    const unique = nextTemp++;
    const finalPath = this.pathFor(id);
    const tempPath = join(
      this.dir,
      `${(id >>> 0).toString(16).padStart(8, '0')}.${process.pid}.${unique}.tmp`,
    );
    try {
      writeFileSync(tempPath, bytes);
      renameSync(tempPath, finalPath);
    } catch {
      try {
        rmSync(tempPath, { force: true });
      } catch {
        // Already gone, or never created.
      }
      return false;
    }
    // Stamped by the same clock `load` touches with, not by whatever the write left behind. A
    // file's timestamp comes from a coarse kernel clock that can sit a tick behind the one
    // `Date.now` reads, so mixing the two lets a dictionary loaded a moment *earlier* outrank one
    // stored later — and a client that had just been brought up to date would go on offering the
    // dictionary it replaced, and be sent a megabyte again on every connection.
    this.touch(finalPath);
    this.prune();
    return true;
  }

  /** Marks a file as used now, so the cache can order by use rather than by creation. */
  private touch(path: string): void {
    try {
      const now = Date.now() / 1000;
      utimesSync(path, now, now);
    } catch {
      // The entry is still readable; the only cost is offering a slightly staler one.
    }
  }

  /** Ids currently held, with when each was last used. */
  private entries(): Array<{ used: number; id: number }> {
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch {
      return [];
    }
    const held: Array<{ used: number; id: number }> = [];
    for (const name of names) {
      if (!name.endsWith('.dict')) continue;
      const stem = name.slice(0, -'.dict'.length);
      if (!/^[0-9a-f]{8}$/.test(stem)) continue;
      const id = Number.parseInt(stem, 16) >>> 0;
      let used = 0;
      try {
        used = statSync(join(this.dir, name)).mtimeMs;
      } catch {
        continue;
      }
      held.push({ used, id });
    }
    return held;
  }

  /** Discards the least recently used dictionaries past {@link KEEP}. */
  private prune(): void {
    const entries = this.entries().sort((a, b) => b.used - a.used);
    for (const entry of entries.slice(KEEP)) {
      try {
        rmSync(this.pathFor(entry.id), { force: true });
      } catch {
        // Left for the next run to try again.
      }
    }
  }
}

/** A scratch directory under the system temp directory. Exported for tests. */
export function scratchDir(tag: string): string {
  return join(tmpdir(), `manka-shreds-dictcache-${tag}-${process.pid}-${nextTemp++}`);
}
