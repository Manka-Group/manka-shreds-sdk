"""The dictionary cache, including the ways it is allowed to fail.

Every operation here degrades to "no cache" rather than raising: a read-only filesystem, a
container with no home directory and a full disk are all normal deployments, and none of them may
stop a subscriber connecting. That makes the failure paths the interesting ones — a cache that
raised would take the connection down with it, and a cache that silently returned corrupt bytes
would have the node compressing with one dictionary while this side decoded with another.
"""

from __future__ import annotations

import os

import pytest

from manka_shreds_sdk import DictionaryCache, dictionary_id
from manka_shreds_sdk.dictcache import CACHE_ENV, default_dir

BODY = b"a dictionary, as far as the cache is concerned" * 40
IDENT = dictionary_id(BODY)


@pytest.fixture
def cache(tmp_path) -> DictionaryCache:
    return DictionaryCache(tmp_path / "dictionaries")


def test_a_stored_dictionary_comes_back(cache: DictionaryCache) -> None:
    assert cache.store(IDENT, BODY) is True
    assert cache.load(IDENT) == BODY


def test_the_newest_is_what_is_offered(cache: DictionaryCache) -> None:
    """A subscriber talking to one node wants that node's dictionary, not an older one."""
    other = BODY + b"!"
    cache.store(IDENT, BODY)
    cache.store(dictionary_id(other), other)
    # mtime has one-second resolution on some filesystems, so order it explicitly.
    os.utime(cache._path_for(dictionary_id(other)), (10_000_000, 10_000_000))
    os.utime(cache._path_for(IDENT), (20_000_000, 20_000_000))
    newest = cache.newest()
    assert newest is not None
    assert newest == (IDENT, BODY)


def test_an_id_that_does_not_match_its_bytes_is_refused(cache: DictionaryCache) -> None:
    """Storing under the wrong id would mean offering an id the bytes do not hash to.

    The node would then compress with one dictionary while this side decoded with another, and
    every frame after the handshake would be unreadable for a reason nothing on the wire explains.
    """
    assert cache.store(IDENT + 1, BODY) is False
    assert cache.load(IDENT + 1) is None


def test_a_corrupt_file_is_discarded_rather_than_used(cache: DictionaryCache) -> None:
    cache.store(IDENT, BODY)
    path = cache._path_for(IDENT)
    path.write_bytes(b"not the dictionary this file is named for")
    assert cache.load(IDENT) is None
    assert not path.exists(), "a file that fails its own id check must not be left to fail again"


def test_a_missing_dictionary_is_absent_rather_than_an_error(cache: DictionaryCache) -> None:
    assert cache.load(0xDEADBEEF) is None
    assert cache.newest() is None


def test_an_unwritable_directory_degrades_to_no_cache(tmp_path) -> None:
    """A read-only filesystem must not stop a subscriber connecting."""
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    blocked.chmod(0o500)
    try:
        cache = DictionaryCache(blocked / "dictionaries")
        assert cache.store(IDENT, BODY) is False
        assert cache.load(IDENT) is None
        assert cache.newest() is None
    finally:
        blocked.chmod(0o700)


def test_the_cache_keeps_a_bounded_number(cache: DictionaryCache) -> None:
    """Each is about a megabyte, and the node resends whatever this side does not hold."""
    from manka_shreds_sdk.dictcache import _KEEP

    stamp = 1_000_000
    for i in range(_KEEP + 4):
        body = BODY + bytes([i])
        ident = dictionary_id(body)
        assert cache.store(ident, body)
        os.utime(cache._path_for(ident), (stamp, stamp))
        stamp += 1_000
    held = list(cache.dir.glob("*.dict"))
    assert len(held) <= _KEEP, f"kept {len(held)}, limit is {_KEEP}"


def test_no_temporary_files_are_left_behind(cache: DictionaryCache) -> None:
    """A half-written dictionary would fail its own id check and be silently discarded."""
    cache.store(IDENT, BODY)
    assert list(cache.dir.glob("*.tmp")) == []


def test_the_environment_can_redirect_or_disable_the_cache(monkeypatch, tmp_path) -> None:
    """A container image or a vendored bundle cannot change the code, but must still say where
    this may write — or that it may not."""
    monkeypatch.setenv(CACHE_ENV, str(tmp_path / "elsewhere"))
    assert default_dir() == tmp_path / "elsewhere"

    for disabled in ("off", "none", "OFF", "None"):
        monkeypatch.setenv(CACHE_ENV, disabled)
        assert default_dir() is None, f"{disabled!r} must disable the cache"

    monkeypatch.delenv(CACHE_ENV, raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert default_dir() == tmp_path / "xdg" / "manka-shreds"


def test_an_empty_dictionary_hashes_to_the_no_dictionary_sentinel(cache: DictionaryCache) -> None:
    """Zero is what the greeting carries for "I hold none", and empty bytes hash to it.

    So an empty dictionary round-trips through the cache without incident and offering it says
    exactly what offering nothing says. The node sends its own either way, which is why this is a
    curiosity rather than a case the cache has to special-case.
    """
    assert dictionary_id(b"") == 0
    assert cache.store(0, b"") is True
    assert cache.load(0) == b""
