//! Where this client keeps the compression dictionaries a node gave it.
//!
//! # Why on disk at all
//!
//! The node hands over its dictionary during the handshake when this client does not already hold
//! it. That costs about a megabyte, once, and buys roughly three times the compression for the
//! whole session — a trade worth making every time. Keeping it means paying that megabyte once
//! ever rather than once per connect, which matters for a subscriber that reconnects after a
//! deploy, a network blip, or a restart.
//!
//! # Why keyed by the dictionary's own id
//!
//! There is no version ordering between dictionaries; the id is a hash of the bytes. So the cache
//! is content-addressed: a file is named for what is in it, this client offers whichever id it
//! holds, and the node either agrees or sends the one it wants. "Outdated" simply means "a
//! different hash", and that is the only comparison anyone needs to make.
//!
//! # Failing softly, and saying so
//!
//! A read-only filesystem, a container with no home directory, a full disk — all normal
//! deployments. None of them may stop a subscriber connecting, so every operation here degrades to
//! "no cache". The connection still gets the dictionary and still streams at the full ratio; it
//! just pays the megabyte again next time.
//!
//! This crate has no logging dependency and is not going to acquire one to say so, so the fact is
//! reported as state instead: [`crate::Client::dictionary_was_sent`] is true when the dictionary
//! came over the wire rather than out of this cache. A subscriber seeing that on *every* connection
//! has a cache that is not working, which is worth knowing and otherwise invisible.
//!
//! # What the id check is, and is not
//!
//! Every entry is verified against the id in its own filename, which catches the accidents: a
//! truncated write, a half-copied file, a name that no longer matches its contents. Those are the
//! realistic failures, and they matter because the symptom would otherwise be a node compressing
//! with one dictionary while this side decoded with another.
//!
//! It is **not** a defence against a hostile local process. The id is a 32-bit hash, so bytes can be
//! crafted to collide with one this client would otherwise fetch, and such an entry is
//! indistinguishable from the real thing. Anyone able to write here can also edit the binary that
//! reads it, so the trust boundary is the filesystem, not this check. Point [`CACHE_ENV`] somewhere
//! only the subscriber can write if that distinction matters to your deployment.

use std::path::{Path, PathBuf};

use crate::protocol::dictionary_id;

/// How many dictionaries a cache keeps before it starts discarding the least recently used.
///
/// More than one because a subscriber may talk to several nodes — two regions, a candidate
/// alongside production — and thrashing between them would defeat the cache entirely. Small,
/// because each is about a megabyte and nothing needs a long history: the node always sends
/// whatever it wants if this side does not have it.
const KEEP: usize = 8;

/// The environment variable that redirects or disables the cache.
///
/// A deployment that cannot change the code — a container image, a vendored binary, a CI job —
/// still needs to say where this may write, or that it may not write at all. `off` (or `none`)
/// disables it; any other value is used as the directory.
pub const CACHE_ENV: &str = "MANKA_SHREDS_DICTIONARY_CACHE";

/// A directory of dictionaries, addressed by id.
#[derive(Clone, Debug)]
pub struct DictionaryCache {
    dir: PathBuf,
}

/// The default location, or `None` when there is nowhere to write.
///
/// [`CACHE_ENV`] first, then `$XDG_CACHE_HOME/manka-shreds`, then `~/.cache/manka-shreds`. A library writing to
/// a user's home is intrusive enough to be worth naming precisely, and worth being overridable
/// without touching the code that constructs the client.
pub fn default_dir() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os(CACHE_ENV).filter(|value| !value.is_empty()) {
        if explicit.eq_ignore_ascii_case("off") || explicit.eq_ignore_ascii_case("none") {
            return None;
        }
        return Some(PathBuf::from(explicit));
    }
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(xdg).join("manka-shreds"));
    }
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(".cache").join("manka-shreds"))
}

impl DictionaryCache {
    /// A cache in `dir`. The directory is created when something is first written.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The cache in the platform's default location, if there is one.
    pub fn default_location() -> Option<Self> {
        default_dir().map(Self::new)
    }

    /// Where this cache lives.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_for(&self, id: u32) -> PathBuf {
        self.dir.join(format!("{id:08x}.dict"))
    }

    /// The most recently used dictionary, if any, as `(id, bytes)`.
    ///
    /// What this client offers when it connects. Most recent rather than any, because a subscriber
    /// that talks to one node overwhelmingly wants that node's dictionary, and offering an older
    /// one would make the node send a megabyte it did not need to.
    pub fn newest(&self) -> Option<(u32, Vec<u8>)> {
        let mut entries = self.entries();
        // Most recently used first.
        entries.sort_unstable_by_key(|(used, _)| std::cmp::Reverse(*used));
        entries
            .into_iter()
            .find_map(|(_, id)| self.load(id).map(|bytes| (id, bytes)))
    }

    /// Loads the dictionary with this id, if it is held and intact.
    ///
    /// The bytes are verified against the id in the filename. A file that does not hash to its own
    /// name is corrupt or was written by something else, and using it would mean offering an id the
    /// bytes do not match — so the node would compress with one dictionary while this side decoded
    /// with another. Deleted, and treated as absent.
    pub fn load(&self, id: u32) -> Option<Vec<u8>> {
        let path = self.path_for(id);
        let bytes = std::fs::read(&path).ok()?;
        if dictionary_id(&bytes) != id {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        // Touched so `newest` reflects use rather than only creation.
        let _ = touch(&path);
        Some(bytes)
    }

    /// Stores `bytes` under `id`, returning whether it was written.
    ///
    /// Never an error a caller has to handle: the dictionary is already in hand and the connection
    /// works either way. A failure simply means it will be sent again next time.
    pub fn store(&self, id: u32, bytes: &[u8]) -> bool {
        if dictionary_id(bytes) != id {
            return false;
        }
        if std::fs::create_dir_all(&self.dir).is_err() {
            return false;
        }

        // Written to a temporary name and renamed, so a crash or a full disk leaves either the old
        // file or the new one — never a half-written dictionary that would fail its own id check on
        // the next run and be silently discarded.
        //
        // The temporary name is unique per call, not per process: a subscriber opening several
        // connections at once has each of them receive the same dictionary and store it at the same
        // moment. Sharing one temporary path would let two writes interleave into it and the rename
        // publish the mixture. The rename itself is atomic, so whichever finishes last wins with
        // identical bytes.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let final_path = self.path_for(id);
        let temp_path = self
            .dir
            .join(format!("{id:08x}.{}.{unique}.tmp", std::process::id()));

        if std::fs::write(&temp_path, bytes).is_err() {
            let _ = std::fs::remove_file(&temp_path);
            return false;
        }
        if std::fs::rename(&temp_path, &final_path).is_err() {
            let _ = std::fs::remove_file(&temp_path);
            return false;
        }
        // Stamped by the same clock `load` touches with, not by whatever the write left behind. The
        // kernel timestamps a file from a coarse clock that can sit a whole tick behind the one
        // `SystemTime::now` reads, so mixing the two lets a dictionary loaded a moment *earlier*
        // outrank one stored later — and a client that had just been brought up to date would go on
        // offering the dictionary it replaced, and be sent a megabyte again on every connection.
        let _ = touch(&final_path);
        self.prune();
        true
    }

    /// Ids currently held, with when each was last used.
    fn entries(&self) -> Vec<(std::time::SystemTime, u32)> {
        let Ok(dir) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        dir.filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            let id = u32::from_str_radix(name.strip_suffix(".dict")?, 16).ok()?;
            let used = entry
                .metadata()
                .ok()
                .and_then(|meta| meta.modified().ok())
                .unwrap_or(std::time::UNIX_EPOCH);
            Some((used, id))
        })
        .collect()
    }

    /// Discards the least recently used dictionaries past [`KEEP`].
    fn prune(&self) {
        let mut entries = self.entries();
        if entries.len() <= KEEP {
            return;
        }
        entries.sort_unstable_by_key(|(used, _)| std::cmp::Reverse(*used));
        for (_, id) in entries.into_iter().skip(KEEP) {
            let _ = std::fs::remove_file(self.path_for(id));
        }
    }
}

/// Marks a file as used now, so the cache can order by use rather than by creation.
///
/// Set explicitly rather than by rewriting the file: a truncation to the length a file already has
/// is only required to update the timestamp *if the size changed*, so on some filesystems it does
/// nothing and the ordering silently becomes creation order.
fn touch(path: &Path) -> std::io::Result<()> {
    let now = std::time::SystemTime::now();
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .set_times(std::fs::FileTimes::new().set_accessed(now).set_modified(now))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "manka-shreds-sdk-dictcache-{tag}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Bytes and the id they hash to.
    fn dictionary(seed: u8) -> (u32, Vec<u8>) {
        let bytes: Vec<u8> = (0..4096u32).map(|i| (i as u8).wrapping_add(seed)).collect();
        (dictionary_id(&bytes), bytes)
    }

    #[test]
    fn a_stored_dictionary_comes_back() {
        let dir = Dir::new("roundtrip");
        let cache = DictionaryCache::new(&dir.0);
        let (id, bytes) = dictionary(1);

        assert!(cache.load(id).is_none(), "an empty cache held something");
        assert!(cache.store(id, &bytes));
        assert_eq!(cache.load(id).as_deref(), Some(bytes.as_slice()));
        assert_eq!(cache.newest(), Some((id, bytes)));
    }

    /// A file that does not hash to its own name is discarded rather than offered.
    ///
    /// Offering an id whose bytes do not match it would have the node compress with one dictionary
    /// while this side decoded with another — every frame unreadable, and the cause a file on disk
    /// rather than anything on the wire.
    #[test]
    fn a_corrupt_entry_is_ignored_and_removed() {
        let dir = Dir::new("corrupt");
        let cache = DictionaryCache::new(&dir.0);
        let (id, bytes) = dictionary(2);
        assert!(cache.store(id, &bytes));

        std::fs::write(dir.0.join(format!("{id:08x}.dict")), b"not the dictionary").unwrap();
        assert!(cache.load(id).is_none(), "a corrupt entry was returned");
        assert!(
            !dir.0.join(format!("{id:08x}.dict")).exists(),
            "a corrupt entry was left to be found again next time"
        );
        assert!(cache.newest().is_none());
    }

    /// Bytes that do not match the id they are offered under are never written.
    #[test]
    fn a_mismatched_pair_is_refused() {
        let dir = Dir::new("mismatch");
        let cache = DictionaryCache::new(&dir.0);
        let (id, _) = dictionary(3);
        let (_, other) = dictionary(4);
        assert!(!cache.store(id, &other), "a mismatched pair was cached");
        assert!(cache.load(id).is_none());
    }

    /// An unwritable cache reports false rather than failing.
    ///
    /// A read-only container must still be able to subscribe. The dictionary is already in hand by
    /// the time this is called, so the only cost of not storing it is being sent it again.
    #[cfg(unix)]
    #[test]
    fn an_unwritable_cache_reports_false_rather_than_failing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = Dir::new("readonly");
        std::fs::create_dir_all(&dir.0).unwrap();
        let locked = dir.0.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();

        let cache = DictionaryCache::new(locked.join("cache"));
        let (id, bytes) = dictionary(5);
        let stored = cache.store(id, &bytes);

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!stored, "an unwritable cache claimed to have stored something");
    }

    /// A dictionary stored right after another was loaded is the newer of the two.
    ///
    /// Exactly the sequence a connection performs: offer what the cache holds, be handed a
    /// different one, store it. With no sleep anywhere, because the bug this guards against only
    /// appears when the two happen close together — a file's timestamp comes from a coarse kernel
    /// clock that can lag the one an explicit touch reads, so a load could outrank a later store
    /// and this client would go on offering the dictionary it had just replaced.
    #[test]
    fn a_dictionary_stored_after_a_load_wins_without_waiting() {
        for round in 0..32u8 {
            let dir = Dir::new("clock");
            let cache = DictionaryCache::new(&dir.0);
            let (old, old_bytes) = dictionary(50 + round);
            let (new, new_bytes) = dictionary(150u8.wrapping_add(round));
            assert_ne!(old, new);

            assert!(cache.store(old, &old_bytes));
            assert_eq!(cache.newest().map(|(id, _)| id), Some(old));
            assert!(cache.store(new, &new_bytes));

            assert_eq!(
                cache.newest().map(|(id, _)| id),
                Some(new),
                "round {round}: the replaced dictionary is still the one offered"
            );
        }
    }

    /// Loading a dictionary makes it the one offered next, not the one stored last.
    #[test]
    fn using_a_dictionary_makes_it_the_one_offered() {
        let dir = Dir::new("touch");
        let cache = DictionaryCache::new(&dir.0);
        let (first, first_bytes) = dictionary(20);
        let (second, second_bytes) = dictionary(21);

        assert!(cache.store(first, &first_bytes));
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(cache.store(second, &second_bytes));
        assert_eq!(cache.newest().map(|(id, _)| id), Some(second));

        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(cache.load(first).is_some());
        assert_eq!(
            cache.newest().map(|(id, _)| id),
            Some(first),
            "using a dictionary did not make it the most recent"
        );
    }

    /// The cache keeps a bounded number of dictionaries, discarding the least recently used.
    #[test]
    fn the_cache_does_not_grow_without_bound() {
        let dir = Dir::new("prune");
        let cache = DictionaryCache::new(&dir.0);
        for seed in 0..(KEEP as u8 + 4) {
            let (id, bytes) = dictionary(seed);
            assert!(cache.store(id, &bytes));
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let held = std::fs::read_dir(&dir.0)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".dict"))
            .count();
        assert!(held <= KEEP, "the cache holds {held}, past the limit of {KEEP}");
    }

    /// Several connections storing the same dictionary at once cannot corrupt the entry.
    #[test]
    fn concurrent_stores_of_the_same_dictionary_leave_it_intact() {
        let dir = Dir::new("concurrent");
        let cache = DictionaryCache::new(&dir.0);
        let (id, bytes) = dictionary(40);

        std::thread::scope(|scope| {
            for _ in 0..8 {
                let cache = cache.clone();
                let bytes = bytes.clone();
                scope.spawn(move || {
                    assert!(cache.store(id, &bytes));
                });
            }
        });

        assert_eq!(
            cache.load(id).as_deref(),
            Some(bytes.as_slice()),
            "concurrent stores left the entry unreadable or wrong"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&dir.0)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary files left behind: {leftovers:?}");
    }

    /// A cache pointed at a directory that does not exist is empty rather than an error.
    #[test]
    fn an_absent_cache_directory_is_simply_empty() {
        let cache = DictionaryCache::new("/nonexistent/manka-shreds/cache");
        assert!(cache.newest().is_none());
        assert!(cache.load(1234).is_none());
    }

    /// The environment can redirect the cache, or switch it off.
    ///
    /// Read rather than set: mutating the environment is unsound in a parallel test run, so this
    /// asserts against whatever the harness has configured.
    #[test]
    fn the_environment_decides_where_the_cache_lives() {
        match std::env::var_os(CACHE_ENV) {
            Some(value)
                if value.eq_ignore_ascii_case("off") || value.eq_ignore_ascii_case("none") =>
            {
                assert!(default_dir().is_none(), "\"off\" did not disable the cache");
            }
            Some(value) if !value.is_empty() => {
                assert_eq!(default_dir(), Some(PathBuf::from(&value)));
            }
            _ => {
                // Unset: the platform default applies.
                if let Some(dir) = default_dir() {
                    assert!(dir.ends_with("manka-shreds"), "{}", dir.display());
                }
            }
        }
    }
}
