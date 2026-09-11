"""Where this client keeps the compression dictionaries a node gave it.

# Why on disk at all

The node hands over its dictionary during the handshake when this client does not already hold it.
That costs about a megabyte, once, and buys roughly three times the compression for the whole
session — a trade worth making every time. Keeping it means paying that megabyte once ever rather
than once per connect, which matters for a subscriber that reconnects after a deploy, a network
blip, or a restart.

# Why keyed by the dictionary's own id

There is no version ordering between dictionaries; the id is a hash of the bytes. So the cache is
content-addressed: a file is named for what is in it, this client offers whichever id it holds, and
the node either agrees or sends the one it wants. "Outdated" simply means "a different hash", and
that is the only comparison anyone needs to make.

# Failing softly, and saying so

A read-only filesystem, a container with no home directory, a full disk — all normal deployments.
None of them may stop a subscriber connecting, so every operation here degrades to "no cache". The
connection still gets the dictionary and still streams at the full ratio; it just pays the megabyte
again next time.

This package writes nothing to stdout, so the fact is reported as state instead:
:attr:`~manka_shreds_sdk.client.Client.dictionary_was_sent` is true when the dictionary came over
the wire rather than out of this cache. A subscriber seeing that on *every* connection has a cache
that is not working, which is worth knowing and otherwise invisible.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .protocol import dictionary_id

__all__ = ["CACHE_ENV", "DictionaryCache", "default_dir", "scratch_dir"]

#: How many dictionaries a cache keeps before it starts discarding the least recently used.
#:
#: More than one because a subscriber may talk to several nodes — two regions, a candidate
#: alongside production — and thrashing between them would defeat the cache entirely. Small,
#: because each is about a megabyte and nothing needs a long history.
_KEEP = 8

#: The environment variable that redirects or disables the cache.
#:
#: A deployment that cannot change the code — a container image, a vendored bundle, a CI job — still
#: needs to say where this may write, or that it may not write at all. ``off`` (or ``none``)
#: disables it; any other value is used as the directory.
CACHE_ENV = "MANKA_SHREDS_DICTIONARY_CACHE"


def default_dir() -> Path | None:
    """The default location, or ``None`` when there is nowhere to write.

    :data:`CACHE_ENV` first, then ``$XDG_CACHE_HOME/manka-shreds``, then
    ``~/.cache/manka-shreds``. A library writing to a user's home is intrusive enough to be worth
    naming precisely, and worth being overridable without touching the code that constructs the
    client.
    """
    explicit = os.environ.get(CACHE_ENV)
    if explicit:
        if explicit.lower() in ("off", "none"):
            return None
        return Path(explicit)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "manka-shreds"
    home = Path.home()
    return None if str(home) == "" else home / ".cache" / "manka-shreds"


@dataclass(frozen=True, slots=True)
class _Entry:
    id: int
    used: float


class DictionaryCache:
    """A directory of dictionaries, addressed by id."""

    __slots__ = ("dir",)

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self.dir = Path(directory)

    @staticmethod
    def default_location() -> DictionaryCache | None:
        """The cache in the platform's default location, if there is one."""
        directory = default_dir()
        return None if directory is None else DictionaryCache(directory)

    def _path_for(self, ident: int) -> Path:
        return self.dir / f"{ident & 0xFFFFFFFF:08x}.dict"

    def _entries(self) -> list[_Entry]:
        out: list[_Entry] = []
        try:
            names = list(self.dir.iterdir())
        except OSError:
            return out
        for path in names:
            if path.suffix != ".dict":
                continue
            try:
                ident = int(path.stem, 16)
                out.append(_Entry(id=ident, used=path.stat().st_mtime))
            except (ValueError, OSError):
                continue
        return out

    def newest(self) -> tuple[int, bytes] | None:
        """The most recently used dictionary, if any.

        What this client offers when it connects. Most recent rather than any, because a subscriber
        that talks to one node overwhelmingly wants that node's dictionary, and offering an older
        one would make the node send a megabyte it did not need to.
        """
        for entry in sorted(self._entries(), key=lambda e: e.used, reverse=True):
            found = self.load(entry.id)
            if found is not None:
                return entry.id, found
        return None

    def load(self, ident: int) -> bytes | None:
        """Load the dictionary with this id, if it is held and intact.

        The bytes are verified against the id in the filename. A file that does not hash to its own
        name is corrupt or was written by something else, and using it would mean offering an id
        the bytes do not match — so the node would compress with one dictionary while this side
        decoded with another. Deleted, and treated as absent.
        """
        path = self._path_for(ident)
        try:
            data = path.read_bytes()
        except OSError:
            return None
        if dictionary_id(data) != (ident & 0xFFFFFFFF):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass  # Nothing to do: it is already being ignored.
            return None
        self._touch(path)
        return data

    def store(self, ident: int, data: bytes) -> bool:
        """Store ``data`` under ``ident``, returning whether it was written.

        Never an error a caller has to handle: the dictionary is already in hand and the connection
        works either way. A failure simply means it will be sent again next time.
        """
        if dictionary_id(data) != (ident & 0xFFFFFFFF):
            return False
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False

        # Written to a temporary name and renamed, so a crash or a full disk leaves either the old
        # file or the new one — never a half-written dictionary that would fail its own id check on
        # the next run and be silently discarded.
        #
        # The temporary name is unique per call, not per process: a subscriber opening several
        # connections at once has each of them receive the same dictionary and store it at the same
        # moment. Sharing one temporary path would let two writes interleave into it and the rename
        # publish the mixture. The rename itself is atomic, so whichever finishes last wins with
        # identical bytes.
        final = self._path_for(ident)
        handle = None
        try:
            fd, temp_name = tempfile.mkstemp(
                dir=self.dir, prefix=f"{ident & 0xFFFFFFFF:08x}.", suffix=".tmp"
            )
            handle = temp_name
            with os.fdopen(fd, "wb") as out:
                out.write(data)
            os.replace(temp_name, final)
            handle = None
        except OSError:
            if handle is not None:
                try:
                    os.unlink(handle)
                except OSError:
                    pass
            return False
        self._prune()
        return True

    def _touch(self, path: Path) -> None:
        try:
            os.utime(path, None)
        except OSError:
            pass

    def _prune(self) -> None:
        """Discard the least recently used beyond :data:`_KEEP`."""
        entries = sorted(self._entries(), key=lambda e: e.used, reverse=True)
        for entry in entries[_KEEP:]:
            try:
                self._path_for(entry.id).unlink(missing_ok=True)
            except OSError:
                pass


def scratch_dir(tag: str) -> Path:
    """A unique directory under the platform temporary path, for tests."""
    return Path(tempfile.gettempdir()) / f"manka-shreds-sdk-{tag}-{os.getpid()}"
