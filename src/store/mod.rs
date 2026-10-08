//! The file store: blob and metadata files on disk, the in-memory index and
//! its states, quota reservations, and crash-safe commits.
//!
//! Layout under `data_dir` (all directories `0700`, all files `0600`):
//!
//! ```text
//! lock              held (flock) for the store's lifetime: one instance per dir
//! tmp/              uploads and metadata writes in progress; emptied at startup
//! files/{id}        file contents
//! files/{id}.json   metadata (`Meta`)
//! ```
//!
//! Paths are built only from validated hex ids, so names can neither
//! traverse nor follow symlinks.
//!
//! # Locking
//!
//! All mutable state lives in one `Index` behind a `std::sync::Mutex`,
//! taken through `Store::index`. The lock is never held across an
//! `.await`: callers do their I/O, then lock, update, and unlock.
//!
//! # Counters
//!
//! Every counter the store increments is owned by an RAII guard:
//! `Reservation` releases its file slot and bytes on `Drop` unless `commit`
//! converted them into committed usage; `TempFile` deletes `tmp/{id}` on
//! `Drop` unless `commit` renamed it into `files/`.
//!
//! # Ending a file
//!
//! Revoke and expiry follow the spec's five-step protocol in `end`; the
//! in-memory flip to `Ending` (step 1) releases the file's quota at once.
//! `recover` reconciles the disk with the index at startup.

pub mod disk;
mod end;
mod recover;

pub use end::{ExpiredFile, RevokeOutcome, SweepReport};

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::clock::Clock;
use crate::config::Config;

/// Streamed uploads grow their byte reservation in steps of this size,
/// re-checking every limit at each step.
const GROW_STEP: u64 = 1 << 20;

/// A file's state as persisted in its `.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiskState {
    Live,
    Expired,
    Revoked,
}

/// The contents of `files/{id}.json`. Field names match the spec's JSON;
/// times are RFC 3339 with whole seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub id: String,
    pub name: String,
    pub urlname: String,
    pub size: u64,
    pub sha256: String,
    pub uploader: String,
    #[serde(with = "rfc3339")]
    pub created_at: SystemTime,
    #[serde(with = "rfc3339")]
    pub expires_at: SystemTime,
    pub state: DiskState,
    #[serde(with = "rfc3339::option")]
    pub ended_at: Option<SystemTime>,
}

/// Serde adapters for `SystemTime` as an RFC 3339 string (whole seconds).
mod rfc3339 {
    use std::time::SystemTime;

    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&humantime::format_rfc3339_seconds(*t))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let s = String::deserialize(d)?;
        humantime::parse_rfc3339(&s).map_err(D::Error::custom)
    }

    pub mod option {
        use std::time::SystemTime;

        use serde::{de::Error, Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(t: &Option<SystemTime>, s: S) -> Result<S::Ok, S::Error> {
            match t {
                Some(t) => s.collect_str(&humantime::format_rfc3339_seconds(*t)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Option<SystemTime>, D::Error> {
            Option::<String>::deserialize(d)?
                .map(|s| humantime::parse_rfc3339(&s).map_err(D::Error::custom))
                .transpose()
        }
    }
}

/// A new file id: 32 lowercase hex characters from 16 random bytes.
pub fn new_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// True if `id` has the shape `new_id` produces: 32 lowercase hex chars.
pub fn is_valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Truncates `t` to whole seconds, so in-memory times equal what the
/// `.json` stores and what a restart reloads.
fn whole_seconds(t: SystemTime) -> SystemTime {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => UNIX_EPOCH + Duration::from_secs(d.as_secs()),
        Err(_) => t,
    }
}

/// Errors opening the store or committing a file.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("{0} must be owned by the current user with mode 0700")]
    Permissions(PathBuf),
    /// `data_dir` (or a directory or the lock file inside it) could not be
    /// read or created: most often it does not exist yet.
    #[error("data_dir {}: {source}", .path.display())]
    DataDir { path: PathBuf, source: io::Error },
    /// Another process holds `data_dir/lock`: a second filepass on the
    /// same `data_dir` would empty the first one's `tmp/` and race its
    /// index.
    #[error("{} is held by another filepass process; refusing to start", .0.display())]
    Locked(PathBuf),
    /// Startup recovery could not write or unlink this path; the store
    /// refuses to open. The message shortens the file name so it never
    /// shows a full file id.
    #[error("startup recovery failed at {}", redact_path(.0))]
    Recovery(PathBuf),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Why an upload cannot reserve (or keep growing) its space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ReserveError {
    /// Over `max_file_size`, or past the declared `Content-Length` (`413`).
    #[error("file too large")]
    TooLarge,
    /// `max_files`, a quota, free space, or free inodes would be exceeded
    /// (`507`).
    #[error("insufficient storage")]
    Insufficient,
}

/// Shortens `name` to its first 8 characters, the most of a file id that
/// may appear in a log line.
fn redact(name: &str) -> String {
    match name.char_indices().nth(8) {
        Some((cut, _)) => format!("{}…", &name[..cut]),
        None => name.to_string(),
    }
}

/// `path` with its file name shortened by `redact`.
fn redact_path(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| redact(&n.to_string_lossy()))
        .unwrap_or_default();
    match path.parent() {
        Some(parent) => parent.join(name).display().to_string(),
        None => name,
    }
}

/// Warnings from startup recovery, for the caller to log. They never
/// contain a full file id.
#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub warnings: Vec<String>,
}

/// What `commit` needs to know about an upload besides its bytes.
#[derive(Debug, Clone)]
pub struct NewFile {
    pub id: String,
    pub name: String,
    pub urlname: String,
    pub sha256: String,
    pub size: u64,
    pub uploader: String,
    pub ttl: Duration,
}

/// A downloadable file, as seen by `lookup`.
#[derive(Debug, Clone)]
pub struct LiveFile {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
    pub name: String,
    pub urlname: String,
    pub uploader: String,
    pub expires_at: SystemTime,
    pub created_at: SystemTime,
    /// Fired when the file is revoked, aborting its downloads.
    pub cancel: CancellationToken,
}

/// The result of `Store::lookup`.
#[derive(Debug)]
pub enum Lookup {
    /// Malformed id, unknown id, or urlname mismatch (`404`).
    NotFound,
    /// Ending, expired, revoked, or past `expires_at` (`410`).
    Gone,
    Live(LiveFile),
}

/// Returned by `record_download` for a file's first download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstDownload {
    pub uploader: String,
    pub since_upload: Duration,
}

/// A snapshot of stored usage for the gauges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    /// Committed bytes of live files, per uploader.
    pub per_agent_bytes: BTreeMap<String, u64>,
    /// Committed bytes of live files, all uploaders.
    pub total_bytes: u64,
    /// Entries in the `live` state.
    pub live_files: usize,
    /// Stored tombstones: entries in the `expired` or `revoked` state. An
    /// entry still `ending` counts as neither live nor a tombstone.
    pub tombstones: usize,
}

/// An index entry's in-memory state. Every transition happens under the
/// index lock. `Ending` is the window of the spec's ending protocol between
/// the in-memory flip (step 1) and the final state (step 5); it carries the
/// state the entry is ending into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Live,
    Ending(End),
    Expired,
    Revoked,
}

impl State {
    /// True for a stored tombstone: `Expired` or `Revoked`.
    fn is_tombstone(self) -> bool {
        matches!(self, State::Expired | State::Revoked)
    }
}

/// How a file stops being live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Expired,
    Revoked,
}

impl End {
    /// The state written to the `.json` (step 3).
    fn disk_state(self) -> DiskState {
        match self {
            End::Expired => DiskState::Expired,
            End::Revoked => DiskState::Revoked,
        }
    }

    /// The in-memory state once the protocol completes (step 5).
    fn final_state(self) -> State {
        match self {
            End::Expired => State::Expired,
            End::Revoked => State::Revoked,
        }
    }
}

/// One file known to the index.
#[derive(Debug)]
struct Entry {
    /// The metadata as last written (or about to be written) to disk.
    meta: Meta,
    state: State,
    /// Fired by a revoke to abort the file's downloads.
    cancel: CancellationToken,
    /// Set by the first `record_download`; in memory only.
    first_download: Option<SystemTime>,
    /// True if recovery loaded this entry from disk, so its first-download
    /// time is unknown.
    loaded_at_startup: bool,
    /// When the entry entered `Ending` (or the sweep last retried it), so
    /// the sweep can retry stuck ones.
    ending_since: Option<Instant>,
}

/// Usage counted against one agent's limits.
#[derive(Debug, Clone, Copy, Default)]
struct AgentUsage {
    /// Committed bytes of this agent's `Live` entries.
    live_bytes: u64,
    /// Number of this agent's `Live` entries.
    live_files: usize,
    /// Bytes held by this agent's active reservations.
    reserved_bytes: u64,
    /// Active reservations (uploads in progress) for this agent.
    reserved_slots: usize,
}

/// The in-memory index. Invariants, all maintained under the lock:
///
/// - `live_bytes` and every `AgentUsage::{live_bytes, live_files}` sum over
///   entries in `State::Live` only. Leaving `Live` (to `Ending`) calls
///   `release_live` in the same critical section.
/// - `reserved_bytes`, `reserved_slots`, `unwritten`, and every
///   `AgentUsage::{reserved_bytes, reserved_slots}` sum over active
///   `Reservation`s.
#[derive(Debug, Default)]
struct Index {
    entries: HashMap<String, Entry>,
    agents: HashMap<String, AgentUsage>,
    /// Committed bytes of all `Live` entries.
    live_bytes: u64,
    /// Bytes held by all active reservations.
    reserved_bytes: u64,
    /// Active reservations, all agents.
    reserved_slots: usize,
    /// Σ(reserved − written) over active reservations: bytes promised but
    /// not yet on disk, which the free-space check subtracts.
    unwritten: u64,
}

impl Index {
    fn usage(&self, agent: &str) -> AgentUsage {
        self.agents.get(agent).copied().unwrap_or_default()
    }

    fn usage_mut(&mut self, agent: &str) -> &mut AgentUsage {
        self.agents.entry(agent.to_string()).or_default()
    }

    /// Inserts `entry`, counting it toward its uploader's usage if live.
    /// The id must be new to the index.
    fn insert(&mut self, entry: Entry) {
        debug_assert!(
            !self.entries.contains_key(&entry.meta.id),
            "index already holds this id"
        );
        if entry.state == State::Live {
            let size = entry.meta.size;
            let usage = self.usage_mut(&entry.meta.uploader);
            usage.live_bytes += size;
            usage.live_files += 1;
            self.live_bytes += size;
        }
        self.entries.insert(entry.meta.id.clone(), entry);
    }

    /// Releases a live file's committed bytes and file slot. The undo of
    /// `insert`'s counting, called when the entry leaves `Live`.
    fn release_live(&mut self, uploader: &str, size: u64) {
        let usage = self.usage_mut(uploader);
        usage.live_bytes -= size;
        usage.live_files -= 1;
        self.live_bytes -= size;
    }
}

/// The file store. Share it as `Arc<Store>`.
pub struct Store {
    cfg: Config,
    clock: Arc<dyn Clock>,
    tmp_dir: PathBuf,
    files_dir: PathBuf,
    index: Mutex<Index>,
    /// `data_dir/lock`, exclusively locked for as long as the store lives;
    /// closing it on drop releases the lock.
    _lock: File,
    /// Test hook: replaces `statvfs` with fixed `(free bytes, free inodes)`.
    fs_override: Mutex<Option<(u64, u64)>>,
    /// Test hook: makes every metadata write fail.
    fail_meta_writes: AtomicBool,
}

impl Store {
    /// Opens the store at `cfg.data_dir`: checks that it is owned by the
    /// current user with mode `0700`, takes the exclusive `data_dir/lock`
    /// (refusing to open if another process holds it), creates `tmp/` and
    /// `files/`, and runs startup recovery.
    pub fn open(
        cfg: &Config,
        clock: Arc<dyn Clock>,
    ) -> Result<(Store, RecoveryReport), StoreError> {
        let data_dir = &cfg.data_dir;
        let at = |path: &Path| {
            let path = path.to_path_buf();
            move |source| StoreError::DataDir { path, source }
        };
        if !disk::is_private_dir(data_dir).map_err(at(data_dir))? {
            return Err(StoreError::Permissions(data_dir.clone()));
        }
        // Lock before recovery touches anything: recovery empties `tmp/`,
        // which would destroy a running instance's uploads in progress.
        let lock_path = data_dir.join("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(at(&lock_path))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(StoreError::Locked(lock_path)),
            Err(TryLockError::Error(source)) => {
                return Err(StoreError::DataDir {
                    path: lock_path,
                    source,
                })
            }
        }
        let tmp_dir = data_dir.join("tmp");
        let files_dir = data_dir.join("files");
        for dir in [&tmp_dir, &files_dir] {
            create_private_dir(dir).map_err(at(dir))?;
        }
        let store = Store {
            cfg: cfg.clone(),
            clock,
            tmp_dir,
            files_dir,
            index: Mutex::new(Index::default()),
            _lock: lock,
            fs_override: Mutex::new(None),
            fail_meta_writes: AtomicBool::new(false),
        };
        let report = recover::run(&store)?;
        Ok((store, report))
    }

    /// Locks the index. A poisoned lock is recovered: every critical
    /// section leaves the counters consistent before it can panic, and
    /// guards must still release from `Drop` after a panic elsewhere.
    fn index(&self) -> MutexGuard<'_, Index> {
        self.index.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn blob_path(&self, id: &str) -> PathBuf {
        self.files_dir.join(id)
    }

    fn meta_path(&self, id: &str) -> PathBuf {
        self.files_dir.join(format!("{id}.json"))
    }

    /// Free bytes and inodes on the data filesystem, or `None` if they
    /// cannot be measured (the checks then fail closed).
    fn fs_free(&self) -> Option<(u64, u64)> {
        if let Some(v) = *self
            .fs_override
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
        {
            return Some(v);
        }
        match disk::fs_free(&self.files_dir) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(error = %e, "statvfs on data_dir failed; refusing uploads");
                None
            }
        }
    }

    /// Checks every space limit for `agent` taking `slots` more file slots
    /// and `bytes` more reserved bytes, of which `incoming` are not yet on
    /// disk. `free` is the `fs_free` reading.
    fn check(
        &self,
        idx: &Index,
        agent: &str,
        slots: usize,
        bytes: u64,
        incoming: u64,
        free: Option<(u64, u64)>,
    ) -> Result<(), ReserveError> {
        let cfg = &self.cfg;
        let usage = idx.usage(agent);
        if usage.live_files + usage.reserved_slots + slots > cfg.max_files {
            return Err(ReserveError::Insufficient);
        }
        if usage.live_bytes + usage.reserved_bytes + bytes > cfg.agent_quota {
            return Err(ReserveError::Insufficient);
        }
        if idx.live_bytes + idx.reserved_bytes + bytes > cfg.total_quota {
            return Err(ReserveError::Insufficient);
        }
        let Some((free_bytes, free_inodes)) = free else {
            return Err(ReserveError::Insufficient);
        };
        // f_bavail × f_frsize − Σ(reserved − written) − incoming ≥ min_free_space
        let left = free_bytes
            .checked_sub(idx.unwritten)
            .and_then(|v| v.checked_sub(incoming));
        if left.is_none_or(|left| left < cfg.min_free_space) {
            return Err(ReserveError::Insufficient);
        }
        if free_inodes < cfg.min_free_inodes as u64 {
            return Err(ReserveError::Insufficient);
        }
        Ok(())
    }

    /// Reserves one file slot and `declared.unwrap_or(0)` bytes for an
    /// upload by `agent`, after checking `max_file_size` (`TooLarge`), then
    /// `max_files`, `agent_quota`, `total_quota`, free space, and free
    /// inodes (`Insufficient`).
    pub fn reserve(
        self: &Arc<Self>,
        agent: &str,
        declared: Option<u64>,
    ) -> Result<Reservation, ReserveError> {
        let bytes = declared.unwrap_or(0);
        if bytes > self.cfg.max_file_size {
            return Err(ReserveError::TooLarge);
        }
        let free = self.fs_free();
        let mut idx = self.index();
        self.check(&idx, agent, 1, bytes, bytes, free)?;
        let usage = idx.usage_mut(agent);
        usage.reserved_bytes += bytes;
        usage.reserved_slots += 1;
        idx.reserved_bytes += bytes;
        idx.reserved_slots += 1;
        idx.unwritten += bytes;
        Ok(Reservation {
            store: Arc::clone(self),
            agent: agent.to_string(),
            declared,
            reserved: bytes,
            written: 0,
            active: true,
        })
    }

    /// Creates `tmp/{id}` (mode `0600`) for an upload's body. Dropping the
    /// returned `TempFile` deletes it unless `commit` renamed it.
    pub fn temp_file(&self, id: &str) -> io::Result<TempFile> {
        if !is_valid_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid file id",
            ));
        }
        let path = self.tmp_dir.join(id);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        Ok(TempFile {
            file: tokio::fs::File::from_std(file),
            id: id.to_string(),
            path,
            renamed: false,
        })
    }

    /// Writes `meta` to `files/{id}.json` atomically.
    async fn write_meta(&self, meta: &Meta) -> io::Result<()> {
        if self.fail_meta_writes.load(Ordering::SeqCst) {
            return Err(io::Error::other("injected metadata write failure"));
        }
        let tmp_dir = self.tmp_dir.clone();
        let dest = self.meta_path(&meta.id);
        let meta = meta.clone();
        tokio::task::spawn_blocking(move || disk::write_json_atomic(&tmp_dir, &dest, &meta))
            .await
            .map_err(io::Error::other)?
    }

    /// Commits a fully received upload: flush and fsync the temp file,
    /// rename it to `files/{id}`, write `files/{id}.json`, then, under the
    /// lock, insert the `live` entry and convert the reservation into
    /// committed usage. If the `.json` write fails, the blob is unlinked
    /// and the reservation is released.
    ///
    /// Callers run this in a spawned task so a client disconnect cannot
    /// cancel it midway.
    pub async fn commit(
        self: &Arc<Self>,
        mut temp: TempFile,
        mut res: Reservation,
        new: NewFile,
    ) -> Result<Meta, StoreError> {
        debug_assert_eq!(temp.id, new.id);
        debug_assert_eq!(res.agent, new.uploader);
        let blob = self.blob_path(&temp.id);
        temp.file.flush().await?;
        temp.file.sync_all().await?;
        tokio::fs::rename(&temp.path, &blob).await?;
        temp.renamed = true;
        drop(temp);

        let created_at = whole_seconds(self.clock.now());
        let meta = Meta {
            id: new.id,
            name: new.name,
            urlname: new.urlname,
            size: new.size,
            sha256: new.sha256,
            uploader: new.uploader,
            created_at,
            expires_at: created_at + new.ttl,
            state: DiskState::Live,
            ended_at: None,
        };
        if let Err(e) = self.write_meta(&meta).await {
            for path in [blob, self.meta_path(&meta.id)] {
                remove_if_exists(&path).await;
            }
            return Err(e.into());
        }

        // One critical section: the reservation becomes committed usage in
        // the same step that inserts the live entry.
        {
            let mut idx = self.index();
            res.release(&mut idx);
            idx.insert(Entry {
                meta: meta.clone(),
                state: State::Live,
                cancel: CancellationToken::new(),
                first_download: None,
                loaded_at_startup: false,
                ending_since: None,
            });
        }
        Ok(meta)
    }

    /// Finds a file for download. `NotFound` for a malformed or unknown id
    /// or a urlname mismatch; `Gone` once the file is not `live` or its
    /// `expires_at` has passed.
    pub fn lookup(&self, id: &str, urlname: &str) -> Lookup {
        if !is_valid_id(id) {
            return Lookup::NotFound;
        }
        let now = self.clock.now();
        let idx = self.index();
        let Some(entry) = idx.entries.get(id) else {
            return Lookup::NotFound;
        };
        let meta = &entry.meta;
        if meta.urlname != urlname {
            return Lookup::NotFound;
        }
        if entry.state != State::Live || now >= meta.expires_at {
            return Lookup::Gone;
        }
        Lookup::Live(LiveFile {
            path: self.blob_path(id),
            size: meta.size,
            sha256: meta.sha256.clone(),
            name: meta.name.clone(),
            urlname: meta.urlname.clone(),
            uploader: meta.uploader.clone(),
            expires_at: meta.expires_at,
            created_at: meta.created_at,
            cancel: entry.cancel.clone(),
        })
    }

    /// Records a download of `id`. Returns `Some` only for the first call
    /// on a live file, with the time since upload.
    pub fn record_download(&self, id: &str) -> Option<FirstDownload> {
        let now = self.clock.now();
        let mut idx = self.index();
        let entry = idx.entries.get_mut(id)?;
        if entry.state != State::Live || entry.first_download.is_some() {
            return None;
        }
        entry.first_download = Some(now);
        Some(FirstDownload {
            uploader: entry.meta.uploader.clone(),
            since_upload: now
                .duration_since(entry.meta.created_at)
                .unwrap_or_default(),
        })
    }

    /// A snapshot of stored usage.
    pub fn stats(&self) -> Stats {
        let idx = self.index();
        let live_files = idx
            .entries
            .values()
            .filter(|e| e.state == State::Live)
            .count();
        Stats {
            per_agent_bytes: idx
                .agents
                .iter()
                .map(|(agent, usage)| (agent.clone(), usage.live_bytes))
                .collect(),
            total_bytes: idx.live_bytes,
            live_files,
            tombstones: idx
                .entries
                .values()
                .filter(|e| e.state.is_tombstone())
                .count(),
        }
    }

    #[doc(hidden)]
    pub fn set_fs_override(&self, v: Option<(u64, u64)>) {
        *self
            .fs_override
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = v;
    }

    #[doc(hidden)]
    pub fn set_fail_meta_writes(&self, on: bool) {
        self.fail_meta_writes.store(on, Ordering::SeqCst);
    }

    /// Test hook: releases `data_dir/lock` early, so a unit test can reopen
    /// the same `data_dir` (to exercise recovery) while this store is still
    /// alive.
    #[cfg(test)]
    pub(crate) fn unlock_data_dir(&self) {
        self._lock.unlock().expect("unlock data_dir/lock");
    }

    #[doc(hidden)]
    pub fn reserved_bytes(&self) -> u64 {
        self.index().reserved_bytes
    }

    #[doc(hidden)]
    pub fn reserved_slots(&self) -> usize {
        self.index().reserved_slots
    }
}

/// Creates `dir` with mode `0700` if it does not exist.
fn create_private_dir(dir: &Path) -> io::Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    }
}

/// Unlinks `path`; a missing file counts as success, other errors are
/// logged (startup recovery removes whatever is left).
async fn remove_if_exists(path: &Path) {
    if let Err(e) = tokio::fs::remove_file(path).await {
        if e.kind() != io::ErrorKind::NotFound {
            tracing::warn!(error = %e, "failed to unlink after metadata write failure");
        }
    }
}

/// A file slot and byte reservation for one upload. `Drop` releases both
/// unless `commit` converted them into committed usage.
#[derive(Debug)]
pub struct Reservation {
    store: Arc<Store>,
    agent: String,
    /// The declared `Content-Length`, if any. Declared uploads reserve it
    /// all up front and may not exceed it.
    declared: Option<u64>,
    /// Bytes currently reserved.
    reserved: u64,
    /// Bytes reported written so far via `grow`.
    written: u64,
    /// False once released (by `Drop` or by `commit`).
    active: bool,
}

impl Reservation {
    /// Reports that `written_total` bytes of the body have been received.
    ///
    /// A declared upload fails with `TooLarge` past its declared length.
    /// A streamed upload fails with `TooLarge` past `max_file_size`; when
    /// it outgrows its reservation, the reservation extends to the next
    /// 1 MiB step with a full re-check of every limit. A step never
    /// reserves past `max_file_size` or a quota's remaining room, so it
    /// fails only when the bytes actually written do not fit.
    pub fn grow(&mut self, written_total: u64) -> Result<(), ReserveError> {
        let store = Arc::clone(&self.store);
        let cfg = &store.cfg;
        let limit = self.declared.unwrap_or(cfg.max_file_size);
        if written_total > limit {
            return Err(ReserveError::TooLarge);
        }
        if written_total <= self.reserved {
            if written_total != self.written {
                let mut idx = store.index();
                self.set_written(&mut idx, written_total);
            }
            return Ok(());
        }

        // Only streamed uploads get here: a declared upload's reservation
        // already covers everything up to `limit`.
        let free = store.fs_free();
        let mut idx = store.index();
        self.set_written(&mut idx, written_total);
        let usage = idx.usage(&self.agent);
        let agent_room = cfg
            .agent_quota
            .saturating_sub(usage.live_bytes + usage.reserved_bytes);
        let total_room = cfg
            .total_quota
            .saturating_sub(idx.live_bytes + idx.reserved_bytes);
        let short = written_total - self.reserved;
        let step = short
            .div_ceil(GROW_STEP)
            .saturating_mul(GROW_STEP)
            .min(cfg.max_file_size.saturating_sub(self.reserved))
            .min(agent_room)
            .min(total_room)
            .max(short);
        let target = self.reserved + step;
        let incoming = target - written_total;
        store.check(&idx, &self.agent, 0, step, incoming, free)?;

        let usage = idx.usage_mut(&self.agent);
        usage.reserved_bytes += step;
        idx.reserved_bytes += step;
        idx.unwritten += incoming;
        self.reserved = target;
        Ok(())
    }

    /// The bytes this reservation has promised but not yet received.
    fn unwritten(&self) -> u64 {
        self.reserved - self.written.min(self.reserved)
    }

    fn set_written(&mut self, idx: &mut Index, written_total: u64) {
        idx.unwritten -= self.unwritten();
        self.written = written_total;
        idx.unwritten += self.unwritten();
    }

    /// Returns this reservation's slot and bytes to the index. Idempotent.
    fn release(&mut self, idx: &mut Index) {
        if !self.active {
            return;
        }
        self.active = false;
        idx.unwritten -= self.unwritten();
        idx.reserved_bytes -= self.reserved;
        idx.reserved_slots -= 1;
        let usage = idx.usage_mut(&self.agent);
        usage.reserved_bytes -= self.reserved;
        usage.reserved_slots -= 1;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.active {
            let store = Arc::clone(&self.store);
            let mut idx = store.index();
            self.release(&mut idx);
        }
    }
}

/// An upload's body in `tmp/{id}`. `Drop` deletes the file unless `commit`
/// renamed it into `files/`.
#[derive(Debug)]
pub struct TempFile {
    pub file: tokio::fs::File,
    id: String,
    path: PathBuf,
    renamed: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.renamed {
            return;
        }
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != io::ErrorKind::NotFound {
                tracing::warn!(id = &self.id[..8], error = %e, "failed to delete temp file");
            }
        }
    }
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("files_dir", &self.files_dir)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::UNIX_EPOCH;

    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;

    use crate::clock::TestClock;
    use crate::config::Config;

    const MIB: u64 = 1 << 20;

    pub(super) struct Harness {
        pub(super) dir: TempDir,
        pub(super) cfg: Config,
        pub(super) store: Arc<Store>,
        pub(super) clock: Arc<TestClock>,
    }

    /// Opens a store in a fresh 0700 `TempDir`, with `tweak` applied to the
    /// spec-default config. Free space and inodes are pinned high so tests do
    /// not depend on the host disk.
    pub(super) fn harness(tweak: impl FnOnce(&mut Config)) -> Harness {
        let dir = TempDir::new().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod");
        let mut cfg = Config::for_tests(dir.path().to_path_buf());
        tweak(&mut cfg);
        let clock = Arc::new(TestClock::new(
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        ));
        let (store, report) = Store::open(&cfg, clock.clone()).expect("open store");
        assert!(report.warnings.is_empty());
        let store = Arc::new(store);
        store.set_fs_override(Some((1 << 50, 1 << 40)));
        Harness {
            dir,
            cfg,
            store,
            clock,
        }
    }

    fn new_file(id: &str, size: u64) -> NewFile {
        NewFile {
            id: id.to_string(),
            name: "my file.txt".to_string(),
            urlname: "my_file.txt".to_string(),
            sha256: "ab".repeat(32),
            size,
            uploader: "planner".to_string(),
            ttl: Duration::from_secs(30 * 60),
        }
    }

    /// Reserves, writes `body`, and commits one file for `planner`. The
    /// commit runs in a spawned task, as the upload handler runs it.
    pub(super) async fn upload(h: &Harness, body: &[u8]) -> Meta {
        let res = h
            .store
            .reserve("planner", Some(body.len() as u64))
            .expect("reserve");
        let id = new_id();
        let mut temp = h.store.temp_file(&id).expect("temp file");
        temp.file.write_all(body).await.expect("write");
        let store = Arc::clone(&h.store);
        let new = new_file(&id, body.len() as u64);
        tokio::spawn(async move { store.commit(temp, res, new).await })
            .await
            .expect("commit task")
            .expect("commit")
    }

    pub(super) fn dir_entries(path: &Path) -> Vec<String> {
        fs::read_dir(path)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn new_id_is_32_lowercase_hex() {
        let a = new_id();
        let b = new_id();
        assert_eq!(a.len(), 32);
        assert!(is_valid_id(&a));
        assert_ne!(a, b);
        assert!(!is_valid_id("XYZ"));
        assert!(!is_valid_id(&a.to_uppercase()));
    }

    #[test]
    fn open_refuses_wrong_mode() {
        let dir = TempDir::new().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod");
        let cfg = Config::for_tests(dir.path().to_path_buf());
        let clock = Arc::new(TestClock::new(UNIX_EPOCH));
        match Store::open(&cfg, clock) {
            Err(StoreError::Permissions(p)) => assert_eq!(p, dir.path()),
            other => panic!("expected Permissions error, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn open_creates_private_subdirs_and_empties_tmp() {
        let h = harness(|_| {});
        for sub in ["tmp", "files"] {
            let mode = fs::metadata(h.dir.path().join(sub))
                .expect("subdir exists")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{sub} mode");
        }
        fs::write(h.dir.path().join("tmp").join("junk"), b"x").expect("write junk");
        let cfg = Config::for_tests(h.dir.path().to_path_buf());
        h.store.unlock_data_dir();
        let (_store, _report) = Store::open(&cfg, h.clock.clone()).expect("reopen");
        assert!(dir_entries(&h.dir.path().join("tmp")).is_empty());
    }

    #[test]
    fn open_names_a_missing_data_dir() {
        let parent = TempDir::new().expect("tempdir");
        let missing = parent.path().join("not-created");
        let cfg = Config::for_tests(missing.clone());
        let clock = Arc::new(TestClock::new(UNIX_EPOCH));
        let err = Store::open(&cfg, clock).map(|_| ()).expect_err("must fail");
        assert!(
            err.to_string().contains(&missing.display().to_string()),
            "error must name the data_dir: {err}"
        );
        match err {
            StoreError::DataDir { path, source } => {
                assert_eq!(path, missing);
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
            }
            other => panic!("expected DataDir error, got {other:?}"),
        }
    }

    #[test]
    fn second_open_on_same_dir_refuses_and_leaves_tmp_alone() {
        let h = harness(|_| {});
        let junk = h.dir.path().join("tmp").join("upload-in-progress");
        fs::write(&junk, b"x").expect("write junk");

        let err = Store::open(&h.cfg, h.clock.clone())
            .map(|_| ())
            .expect_err("a second store on a locked data_dir must not open");
        let lock_path = h.dir.path().join("lock");
        assert!(
            err.to_string().contains(&lock_path.display().to_string()),
            "error must name the lock file: {err}"
        );
        assert!(
            matches!(&err, StoreError::Locked(p) if *p == lock_path),
            "expected Locked error, got {err:?}"
        );
        assert_eq!(
            fs::read(&junk).expect("tmp entry survives"),
            b"x",
            "a refused open must not run recovery"
        );

        // Once the first store is gone, the lock is free again, and
        // recovery leaves the lock file (outside `tmp/` and `files/`) alone.
        drop(h.store);
        let (_store, report) = Store::open(&h.cfg, h.clock.clone()).expect("open after drop");
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert!(lock_path.exists(), "recovery must not touch data_dir/lock");
        assert!(dir_entries(&h.dir.path().join("tmp")).is_empty());
    }

    #[tokio::test]
    async fn commit_then_lookup_live() {
        let h = harness(|_| {});
        let meta = upload(&h, b"abc").await;

        let json_path = h.dir.path().join("files").join(format!("{}.json", meta.id));
        let on_disk: Meta =
            serde_json::from_slice(&fs::read(&json_path).expect("json exists")).expect("parses");
        assert_eq!(on_disk, meta);
        assert_eq!(on_disk.state, DiskState::Live);
        assert_eq!(on_disk.ended_at, None);
        assert_eq!(
            on_disk.expires_at,
            on_disk.created_at + Duration::from_secs(30 * 60)
        );
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(&json_path).expect("json")).expect("value");
        assert_eq!(raw["state"], "live");
        assert_eq!(raw["created_at"], "2027-01-15T08:00:00Z");
        assert!(raw["ended_at"].is_null());

        for path in [json_path.clone(), h.dir.path().join("files").join(&meta.id)] {
            let mode = fs::metadata(&path).expect("exists").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{}", path.display());
        }

        match h.store.lookup(&meta.id, "my_file.txt") {
            Lookup::Live(f) => {
                assert_eq!(f.size, 3);
                assert_eq!(fs::read(&f.path).expect("blob"), b"abc");
                assert_eq!(f.uploader, "planner");
                assert_eq!(f.name, "my file.txt");
                assert!(!f.cancel.is_cancelled());
            }
            _ => panic!("expected Live"),
        }
        assert!(matches!(
            h.store.lookup(&meta.id, "other.txt"),
            Lookup::NotFound
        ));
        assert!(matches!(
            h.store.lookup("XYZ", "my_file.txt"),
            Lookup::NotFound
        ));
        assert!(matches!(
            h.store.lookup(&new_id(), "my_file.txt"),
            Lookup::NotFound
        ));

        let stats = h.store.stats();
        assert_eq!(stats.live_files, 1);
        assert_eq!(stats.total_bytes, 3);
        assert_eq!(stats.per_agent_bytes.get("planner"), Some(&3));
        assert_eq!(stats.tombstones, 0);
        assert_eq!(h.store.reserved_bytes(), 0);
        assert_eq!(h.store.reserved_slots(), 0);
        assert!(dir_entries(&h.dir.path().join("tmp")).is_empty());
    }

    #[tokio::test]
    async fn lookup_gone_after_expires_at() {
        let h = harness(|_| {});
        let meta = upload(&h, b"abc").await;
        h.clock.advance(Duration::from_secs(30 * 60 - 1));
        assert!(matches!(
            h.store.lookup(&meta.id, "my_file.txt"),
            Lookup::Live(_)
        ));
        h.clock.advance(Duration::from_secs(1));
        assert!(matches!(
            h.store.lookup(&meta.id, "my_file.txt"),
            Lookup::Gone
        ));
    }

    #[test]
    fn reserve_limits() {
        // declared over max_file_size
        let h = harness(|c| c.max_file_size = 100);
        assert_eq!(
            h.store.reserve("planner", Some(101)).err(),
            Some(ReserveError::TooLarge)
        );
        assert!(h.store.reserve("planner", Some(100)).is_ok());

        // max_files counts reservations in progress
        let h = harness(|c| c.max_files = 1);
        let held = h.store.reserve("planner", None).expect("first slot");
        assert_eq!(
            h.store.reserve("planner", None).err(),
            Some(ReserveError::Insufficient)
        );
        drop(held);
        assert!(h.store.reserve("planner", None).is_ok());

        // agent_quota counts reserved bytes
        let h = harness(|c| c.agent_quota = 10);
        let _first = h.store.reserve("planner", Some(6)).expect("first 6");
        assert_eq!(
            h.store.reserve("planner", Some(6)).err(),
            Some(ReserveError::Insufficient)
        );
        assert!(h.store.reserve("other", Some(6)).is_ok());

        // total_quota spans agents
        let h = harness(|c| c.total_quota = 10);
        let _first = h.store.reserve("planner", Some(6)).expect("first 6");
        assert_eq!(
            h.store.reserve("other", Some(6)).err(),
            Some(ReserveError::Insufficient)
        );

        // free space below min_free_space
        let h = harness(|c| c.min_free_space = 5 << 30);
        h.store.set_fs_override(Some((1 << 20, 1 << 20)));
        assert_eq!(
            h.store.reserve("planner", Some(1)).err(),
            Some(ReserveError::Insufficient)
        );

        // free space accounts for bytes promised to other reservations
        let h = harness(|c| c.min_free_space = 10);
        h.store.set_fs_override(Some((30, 1 << 20)));
        let _first = h.store.reserve("planner", Some(15)).expect("15 fits");
        assert_eq!(
            h.store.reserve("other", Some(6)).err(),
            Some(ReserveError::Insufficient)
        );
        assert!(h.store.reserve("other", Some(5)).is_ok());

        // free inodes below min_free_inodes
        let h = harness(|c| c.min_free_inodes = 10);
        h.store.set_fs_override(Some((u64::MAX, 5)));
        assert_eq!(
            h.store.reserve("planner", None).err(),
            Some(ReserveError::Insufficient)
        );
    }

    #[test]
    fn streamed_grow_crosses_max_file_size() {
        let h = harness(|c| c.max_file_size = 2 * MIB);
        let mut res = h.store.reserve("planner", None).expect("reserve");
        assert_eq!(h.store.reserved_bytes(), 0);
        res.grow(1).expect("first byte");
        assert_eq!(h.store.reserved_bytes(), MIB);
        res.grow(MIB).expect("exactly 1 MiB");
        assert_eq!(h.store.reserved_bytes(), MIB);
        res.grow(2 * MIB).expect("exactly max_file_size");
        assert_eq!(h.store.reserved_bytes(), 2 * MIB);
        assert_eq!(res.grow(2 * MIB + 1).err(), Some(ReserveError::TooLarge));
        assert_eq!(res.grow(3 * MIB).err(), Some(ReserveError::TooLarge));
    }

    #[test]
    fn streamed_grow_rechecks_quota_and_free_space() {
        // A step never reserves past the agent's quota, so a stream that ends
        // exactly at the quota fits.
        let h = harness(|c| c.agent_quota = 10);
        let mut res = h.store.reserve("planner", None).expect("reserve");
        res.grow(10).expect("exactly agent_quota");
        assert_eq!(h.store.reserved_bytes(), 10);
        assert_eq!(res.grow(11).err(), Some(ReserveError::Insufficient));

        let h = harness(|c| c.min_free_space = 0);
        h.store.set_fs_override(Some((MIB + MIB / 2, 1 << 20)));
        let mut res = h.store.reserve("planner", None).expect("reserve");
        res.grow(1).expect("first MiB fits");
        // The first MiB is now on disk; half a MiB remains free, so the
        // next step (one more MiB, minus the byte already written) does not fit.
        h.store.set_fs_override(Some((MIB / 2, 1 << 20)));
        assert_eq!(res.grow(MIB + 1).err(), Some(ReserveError::Insufficient));
        assert_eq!(h.store.reserved_bytes(), MIB);
        drop(res);
        assert_eq!(h.store.reserved_bytes(), 0);
    }

    #[test]
    fn declared_grow_past_declared_is_too_large() {
        let h = harness(|_| {});
        let mut res = h.store.reserve("planner", Some(5)).expect("reserve");
        res.grow(5).expect("exactly declared");
        assert_eq!(h.store.reserved_bytes(), 5);
        assert_eq!(res.grow(6).err(), Some(ReserveError::TooLarge));
    }

    #[test]
    fn reservation_drop_releases() {
        let h = harness(|_| {});
        let declared = h.store.reserve("planner", Some(1000)).expect("declared");
        let mut streamed = h.store.reserve("planner", None).expect("streamed");
        streamed.grow(3 * MIB).expect("grow");
        assert_eq!(h.store.reserved_slots(), 2);
        assert_eq!(h.store.reserved_bytes(), 1000 + 3 * MIB);
        drop(declared);
        drop(streamed);
        assert_eq!(h.store.reserved_bytes(), 0);
        assert_eq!(h.store.reserved_slots(), 0);
        // Released capacity is reusable.
        let h = harness(|c| c.agent_quota = 10);
        drop(h.store.reserve("planner", Some(10)).expect("fill quota"));
        assert!(h.store.reserve("planner", Some(10)).is_ok());
    }

    #[tokio::test]
    async fn temp_file_drop_deletes() {
        let h = harness(|_| {});
        let id = new_id();
        let mut temp = h.store.temp_file(&id).expect("temp");
        temp.file.write_all(b"partial").await.expect("write");
        let tmp = h.dir.path().join("tmp");
        let mode = fs::metadata(tmp.join(&id))
            .expect("temp exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(temp);
        assert!(dir_entries(&tmp).is_empty());
    }

    #[tokio::test]
    async fn json_failure_after_rename_unlinks_blob() {
        let h = harness(|_| {});
        h.store.set_fail_meta_writes(true);
        let res = h.store.reserve("planner", Some(3)).expect("reserve");
        let id = new_id();
        let mut temp = h.store.temp_file(&id).expect("temp");
        temp.file.write_all(b"abc").await.expect("write");
        let result = h.store.commit(temp, res, new_file(&id, 3)).await;
        assert!(result.is_err());
        assert!(dir_entries(&h.dir.path().join("files")).is_empty());
        assert!(dir_entries(&h.dir.path().join("tmp")).is_empty());
        assert_eq!(h.store.reserved_bytes(), 0);
        assert_eq!(h.store.reserved_slots(), 0);
        let stats = h.store.stats();
        assert_eq!(stats.live_files, 0);
        assert_eq!(stats.total_bytes, 0);
        assert!(matches!(
            h.store.lookup(&id, "my_file.txt"),
            Lookup::NotFound
        ));
    }

    #[tokio::test]
    async fn record_download_first_only() {
        let h = harness(|_| {});
        let meta = upload(&h, b"abc").await;
        h.clock.advance(Duration::from_secs(90));
        let first = h.store.record_download(&meta.id).expect("first download");
        assert_eq!(first.uploader, "planner");
        assert_eq!(first.since_upload, Duration::from_secs(90));
        assert!(h.store.record_download(&meta.id).is_none());
        assert!(h.store.record_download(&new_id()).is_none());
    }

    #[test]
    fn meta_round_trips_rfc3339() {
        let t = UNIX_EPOCH + Duration::from_secs(1_791_403_200); // 2026-10-07T20:00:00Z
        let meta = Meta {
            id: "3f9c2a7e1b3d4c5e8f9a0b1c2d3e4f5a".to_string(),
            name: "my file.zip".to_string(),
            urlname: "my_file.zip".to_string(),
            size: 734_003_200,
            sha256: "ab".repeat(32),
            uploader: "planner".to_string(),
            created_at: t,
            expires_at: t + Duration::from_secs(1800),
            state: DiskState::Revoked,
            ended_at: Some(t + Duration::from_secs(60)),
        };
        let v = serde_json::to_value(&meta).expect("serialize");
        assert_eq!(v["created_at"], "2026-10-07T20:00:00Z");
        assert_eq!(v["expires_at"], "2026-10-07T20:30:00Z");
        assert_eq!(v["ended_at"], "2026-10-07T20:01:00Z");
        assert_eq!(v["state"], "revoked");
        let back: Meta = serde_json::from_value(v).expect("deserialize");
        assert_eq!(back, meta);
    }
}
