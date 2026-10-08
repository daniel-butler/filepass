//! Startup recovery: reconciles `tmp/` and `files/` with the spec's
//! Startup recovery table and loads the index, before the listener binds.
//!
//! | Found | Action |
//! |---|---|
//! | Anything in `tmp/` | Delete |
//! | A name in `files/` that is neither `{32 hex}` nor `{32 hex}.json` | Delete; warn |
//! | A blob with no `.json` | Delete |
//! | A `.json` that fails to parse | Delete it and its blob; warn |
//! | `expired`/`revoked` `.json` whose blob still exists | Delete the blob |
//! | A `.json` whose `id` differs from its filename | Delete it and its blob; warn |
//! | `live` `.json` whose `size` differs from the blob's length | Delete both; warn |
//! | `live` `.json` with no blob | Write it as `expired`, `ended_at` = now |
//! | `.json` whose `uploader` is not configured | Load normally |
//! | `live` `.json` past `expires_at` | End it as expired, `ended_at` = `expires_at` |
//! | `expired`/`revoked` `.json` past `ended_at + tombstone_ttl` | Delete |
//!
//! Only regular files count as blobs or metadata; anything else under a
//! valid name (a directory or symlink) is a stray. Any failed write or
//! unlink aborts with `StoreError::Recovery(path)`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, FileType};
use std::io;
use std::path::Path;
use std::time::SystemTime;

use tokio_util::sync::CancellationToken;

use super::{
    disk, is_valid_id, redact, redact_path, whole_seconds, DiskState, Entry, Meta, RecoveryReport,
    State, Store, StoreError,
};

/// What `files/` held after strays were removed: metadata ids, and blob
/// ids with their lengths.
#[derive(Default)]
struct Listing {
    jsons: BTreeSet<String>,
    blobs: BTreeMap<String, u64>,
}

/// Runs recovery against a freshly opened `store` and loads its index.
pub(super) fn run(store: &Store) -> Result<RecoveryReport, StoreError> {
    let mut report = RecoveryReport::default();
    empty_tmp(&store.tmp_dir)?;
    let mut listing = list_files(&store.files_dir, &mut report)?;
    let now = store.clock.now();

    let mut entries = Vec::new();
    for id in &listing.jsons {
        let blob_len = listing.blobs.remove(id);
        if let Some(entry) = recover_one(store, id, blob_len, now, &mut report)? {
            entries.push(entry);
        }
    }
    for id in listing.blobs.keys() {
        remove(&store.blob_path(id))?;
    }
    disk::fsync_dir(&store.files_dir).map_err(failed(&store.files_dir))?;

    let mut idx = store.index();
    for entry in entries {
        idx.insert(entry);
    }
    Ok(report)
}

/// Wraps an I/O error at `path` as `StoreError::Recovery`, logging the
/// cause (the error variant carries only the path).
fn failed(path: &Path) -> impl FnOnce(io::Error) -> StoreError + '_ {
    move |e| {
        tracing::error!(path = %redact_path(path), error = %e, "startup recovery failed");
        StoreError::Recovery(path.to_path_buf())
    }
}

/// Unlinks the file at `path`; a missing file counts as success.
fn remove(path: &Path) -> Result<(), StoreError> {
    disk::remove_file_if_exists(path).map_err(failed(path))
}

/// Removes `path` without following symlinks: a directory with its
/// contents, anything else as a file.
fn remove_any(path: &Path, kind: FileType) -> Result<(), StoreError> {
    if kind.is_dir() {
        fs::remove_dir_all(path).map_err(failed(path))
    } else {
        remove(path)
    }
}

fn empty_tmp(tmp_dir: &Path) -> Result<(), StoreError> {
    for entry in fs::read_dir(tmp_dir).map_err(failed(tmp_dir))? {
        let entry = entry.map_err(failed(tmp_dir))?;
        let path = entry.path();
        let kind = entry.file_type().map_err(failed(&path))?;
        remove_any(&path, kind)?;
    }
    Ok(())
}

/// Lists `files/`, deleting (with a warning) every entry that is not a
/// regular file named `{32 hex}` or `{32 hex}.json`.
fn list_files(files_dir: &Path, report: &mut RecoveryReport) -> Result<Listing, StoreError> {
    let mut listing = Listing::default();
    for entry in fs::read_dir(files_dir).map_err(failed(files_dir))? {
        let entry = entry.map_err(failed(files_dir))?;
        let path = entry.path();
        // `file_type` and `metadata` on a `DirEntry` do not follow symlinks.
        let kind = entry.file_type().map_err(failed(&path))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if kind.is_file() {
            if is_valid_id(&name) {
                let len = entry.metadata().map_err(failed(&path))?.len();
                listing.blobs.insert(name.into_owned(), len);
                continue;
            }
            if let Some(id) = name.strip_suffix(".json").filter(|id| is_valid_id(id)) {
                listing.jsons.insert(id.to_string());
                continue;
            }
        }
        remove_any(&path, kind)?;
        report
            .warnings
            .push(format!("deleted unexpected entry files/{}", redact(&name)));
    }
    Ok(listing)
}

/// Applies the recovery table to `files/{id}.json` (and its blob, of
/// length `blob_len` if present). Returns the entry to load, if any.
fn recover_one(
    store: &Store,
    id: &str,
    blob_len: Option<u64>,
    now: SystemTime,
    report: &mut RecoveryReport,
) -> Result<Option<Entry>, StoreError> {
    let json = store.meta_path(id);
    let blob = store.blob_path(id);
    let short = &id[..8];
    let delete_both = || -> Result<Option<Entry>, StoreError> {
        remove(&json)?;
        remove(&blob)?;
        Ok(None)
    };

    let bytes = fs::read(&json).map_err(failed(&json))?;
    let Ok(mut meta) = serde_json::from_slice::<Meta>(&bytes) else {
        report.warnings.push(format!(
            "deleted files/{short}… whose metadata does not parse, and its blob"
        ));
        return delete_both();
    };
    if meta.id != id {
        report.warnings.push(format!(
            "deleted files/{short}… whose metadata names another id, and its blob"
        ));
        return delete_both();
    }

    if meta.state == DiskState::Live {
        match blob_len {
            None => {
                end_as_expired(store, &mut meta, whole_seconds(now))?;
            }
            Some(len) if len != meta.size => {
                report.warnings.push(format!(
                    "deleted files/{short}… whose blob length differs from its metadata"
                ));
                return delete_both();
            }
            Some(_) if now >= meta.expires_at => {
                let expires_at = meta.expires_at;
                end_as_expired(store, &mut meta, expires_at)?;
                remove(&blob)?;
            }
            Some(_) => return Ok(Some(entry(meta, State::Live))),
        }
    } else if blob_len.is_some() {
        remove(&blob)?;
    }

    // `meta` is now a tombstone.
    let Some(ended_at) = meta.ended_at else {
        report.warnings.push(format!(
            "deleted files/{short}… whose metadata ended without an ended_at"
        ));
        remove(&json)?;
        return Ok(None);
    };
    let past_window = ended_at
        .checked_add(store.cfg.tombstone_ttl)
        .is_some_and(|t| now >= t);
    if past_window {
        remove(&json)?;
        return Ok(None);
    }
    let state = match meta.state {
        DiskState::Revoked => State::Revoked,
        _ => State::Expired,
    };
    Ok(Some(entry(meta, state)))
}

/// Ending step 3 for a live file at startup: rewrites its `.json` as
/// `expired` with `ended_at`. The caller unlinks the blob (step 4).
fn end_as_expired(store: &Store, meta: &mut Meta, ended_at: SystemTime) -> Result<(), StoreError> {
    meta.state = DiskState::Expired;
    meta.ended_at = Some(ended_at);
    let json = store.meta_path(&meta.id);
    disk::write_json_atomic(&store.tmp_dir, &json, meta).map_err(failed(&json))
}

/// An index entry for a file loaded from disk.
fn entry(meta: Meta, state: State) -> Entry {
    Entry {
        meta,
        state,
        cancel: CancellationToken::new(),
        first_download: None,
        loaded_at_startup: true,
        ending_since: None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::Duration;

    use crate::clock::Clock;
    use crate::store::tests::{dir_entries, harness, Harness};
    use crate::store::{new_id, DiskState, Lookup, Meta, RecoveryReport, Store, StoreError};

    const HOUR: Duration = Duration::from_secs(60 * 60);

    fn files(h: &Harness) -> PathBuf {
        h.dir.path().join("files")
    }

    /// A metadata record for `id` created an hour ago, expiring
    /// `expires_in` from now.
    fn meta(h: &Harness, id: &str, size: u64, state: DiskState) -> Meta {
        let now = h.clock.now();
        Meta {
            id: id.to_string(),
            name: "my file.txt".to_string(),
            urlname: "my_file.txt".to_string(),
            size,
            sha256: "ab".repeat(32),
            uploader: "planner".to_string(),
            created_at: now - HOUR,
            expires_at: now + HOUR,
            state,
            ended_at: match state {
                DiskState::Live => None,
                _ => Some(now - HOUR / 2),
            },
        }
    }

    fn write_json(h: &Harness, file_id: &str, meta: &Meta) {
        fs::write(
            files(h).join(format!("{file_id}.json")),
            serde_json::to_vec(meta).expect("serialize"),
        )
        .expect("write json");
    }

    fn write_blob(h: &Harness, id: &str, body: &[u8]) {
        fs::write(files(h).join(id), body).expect("write blob");
    }

    fn read_json(h: &Harness, id: &str) -> Meta {
        serde_json::from_slice(&fs::read(files(h).join(format!("{id}.json"))).expect("json"))
            .expect("parses")
    }

    /// Opens a second store on `h`'s `data_dir`, as a restart would. The
    /// harness's own store gives up `data_dir/lock` first.
    fn reopen(h: &Harness) -> (Store, RecoveryReport) {
        h.store.unlock_data_dir();
        Store::open(&h.cfg, h.clock.clone()).expect("reopen")
    }

    fn assert_no_full_ids(report: &RecoveryReport, ids: &[&str]) {
        for w in &report.warnings {
            for id in ids {
                assert!(!w.contains(id), "warning leaks a full id: {w}");
            }
        }
    }

    #[test]
    fn tmp_junk_deleted() {
        let h = harness(|_| {});
        let tmp = h.dir.path().join("tmp");
        fs::write(tmp.join("junk"), b"x").expect("junk");
        fs::create_dir(tmp.join("subdir")).expect("subdir");
        fs::write(tmp.join("subdir").join("x"), b"x").expect("nested");
        let (_store, report) = reopen(&h);
        assert!(dir_entries(&tmp).is_empty());
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn stray_names_deleted_with_warning() {
        let h = harness(|_| {});
        let id = new_id();
        fs::write(files(&h).join("notes.txt"), b"x").expect("stray");
        fs::write(files(&h).join(format!("{id}.bak")), b"x").expect("stray");
        fs::write(files(&h).join(id.to_uppercase()), b"x").expect("stray");
        fs::create_dir(files(&h).join(new_id())).expect("stray dir");
        let (_store, report) = reopen(&h);
        assert!(dir_entries(&files(&h)).is_empty());
        assert_eq!(report.warnings.len(), 4, "{:?}", report.warnings);
        assert_no_full_ids(&report, &[&id, &id.to_uppercase()]);
    }

    #[test]
    fn blob_without_json_deleted() {
        let h = harness(|_| {});
        write_blob(&h, &new_id(), b"abc");
        let (_store, report) = reopen(&h);
        assert!(dir_entries(&files(&h)).is_empty());
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn unparseable_json_deleted_with_blob() {
        let h = harness(|_| {});
        let id = new_id();
        fs::write(files(&h).join(format!("{id}.json")), b"{not json").expect("json");
        write_blob(&h, &id, b"abc");
        let (store, report) = reopen(&h);
        assert!(dir_entries(&files(&h)).is_empty());
        assert_eq!(report.warnings.len(), 1);
        assert_no_full_ids(&report, &[&id]);
        assert!(matches!(store.lookup(&id, "my_file.txt"), Lookup::NotFound));
    }

    #[test]
    fn tombstone_with_blob_loses_blob() {
        let h = harness(|_| {});
        let expired = new_id();
        let revoked = new_id();
        let m = meta(&h, &expired, 3, DiskState::Expired);
        write_json(&h, &expired, &m);
        write_blob(&h, &expired, b"abc");
        write_json(&h, &revoked, &meta(&h, &revoked, 3, DiskState::Revoked));
        write_blob(&h, &revoked, b"abc");
        let (store, report) = reopen(&h);
        assert!(report.warnings.is_empty());
        let mut left = dir_entries(&files(&h));
        left.sort();
        let mut want = vec![format!("{expired}.json"), format!("{revoked}.json")];
        want.sort();
        assert_eq!(left, want);
        assert_eq!(read_json(&h, &expired), m);
        for id in [&expired, &revoked] {
            assert!(matches!(store.lookup(id, "my_file.txt"), Lookup::Gone));
        }
        assert_eq!(store.stats().tombstones, 2);
        assert_eq!(store.stats().total_bytes, 0);
    }

    #[test]
    fn id_mismatch_deleted() {
        let h = harness(|_| {});
        let file_id = new_id();
        let inner_id = new_id();
        write_json(&h, &file_id, &meta(&h, &inner_id, 3, DiskState::Live));
        write_blob(&h, &file_id, b"abc");
        let (store, report) = reopen(&h);
        assert!(dir_entries(&files(&h)).is_empty());
        assert_eq!(report.warnings.len(), 1);
        assert_no_full_ids(&report, &[&file_id, &inner_id]);
        assert!(store.live_ids().is_empty());
    }

    #[test]
    fn size_mismatch_deleted() {
        let h = harness(|_| {});
        let id = new_id();
        write_json(&h, &id, &meta(&h, &id, 10, DiskState::Live));
        write_blob(&h, &id, b"abc");
        let (store, report) = reopen(&h);
        assert!(dir_entries(&files(&h)).is_empty());
        assert_eq!(report.warnings.len(), 1);
        assert_no_full_ids(&report, &[&id]);
        assert!(matches!(store.lookup(&id, "my_file.txt"), Lookup::NotFound));
    }

    #[test]
    fn live_json_without_blob_becomes_expired() {
        let h = harness(|_| {});
        let id = new_id();
        let m = meta(&h, &id, 3, DiskState::Live);
        write_json(&h, &id, &m);
        let (store, report) = reopen(&h);
        assert!(report.warnings.is_empty());
        let disk = read_json(&h, &id);
        assert_eq!(disk.state, DiskState::Expired);
        assert_eq!(disk.ended_at, Some(h.clock.now()));
        assert_eq!(disk.expires_at, m.expires_at);
        assert!(matches!(store.lookup(&id, "my_file.txt"), Lookup::Gone));
        assert_eq!(store.stats().total_bytes, 0);
        assert!(dir_entries(&h.dir.path().join("tmp")).is_empty());
    }

    #[test]
    fn unknown_uploader_loads_live() {
        let h = harness(|_| {});
        let id = new_id();
        let mut m = meta(&h, &id, 3, DiskState::Live);
        m.uploader = "ghost".to_string();
        write_json(&h, &id, &m);
        write_blob(&h, &id, b"abc");
        let (store, report) = reopen(&h);
        assert!(report.warnings.is_empty());
        match store.lookup(&id, "my_file.txt") {
            Lookup::Live(f) => {
                assert_eq!(f.uploader, "ghost");
                assert_eq!(f.size, 3);
                assert_eq!(f.expires_at, m.expires_at);
            }
            _ => panic!("expected Live"),
        }
        assert_eq!(store.live_ids(), vec![id.clone()]);
        let stats = store.stats();
        assert_eq!(stats.per_agent_bytes.get("ghost"), Some(&3));
        assert_eq!(stats.total_bytes, 3);
        assert_eq!(stats.live_files, 1);
        assert_eq!(read_json(&h, &id), m);
    }

    #[test]
    fn live_past_expires_at_ends_as_expired() {
        let h = harness(|_| {});
        let id = new_id();
        let mut m = meta(&h, &id, 3, DiskState::Live);
        m.expires_at = h.clock.now() - Duration::from_secs(10 * 60);
        write_json(&h, &id, &m);
        write_blob(&h, &id, b"abc");
        let (store, report) = reopen(&h);
        assert!(report.warnings.is_empty());
        let disk = read_json(&h, &id);
        assert_eq!(disk.state, DiskState::Expired);
        assert_eq!(disk.ended_at, Some(m.expires_at));
        assert!(!files(&h).join(&id).exists());
        assert!(matches!(store.lookup(&id, "my_file.txt"), Lookup::Gone));
        assert_eq!(store.stats().total_bytes, 0);
        assert_eq!(store.stats().tombstones, 1);
    }

    #[test]
    fn tombstone_past_window_deleted() {
        let h = harness(|_| {});
        let old = new_id();
        let recent = new_id();
        let now = h.clock.now();
        let mut m = meta(&h, &old, 3, DiskState::Revoked);
        m.ended_at = Some(now - 48 * HOUR);
        write_json(&h, &old, &m);
        let mut m = meta(&h, &recent, 3, DiskState::Expired);
        m.ended_at = Some(now - 48 * HOUR + Duration::from_secs(1));
        write_json(&h, &recent, &m);
        let (store, report) = reopen(&h);
        assert!(report.warnings.is_empty());
        assert_eq!(dir_entries(&files(&h)), vec![format!("{recent}.json")]);
        assert!(matches!(
            store.lookup(&old, "my_file.txt"),
            Lookup::NotFound
        ));
        assert!(matches!(store.lookup(&recent, "my_file.txt"), Lookup::Gone));
    }

    #[test]
    fn tombstone_without_ended_at_deleted_with_warning() {
        let h = harness(|_| {});
        let id = new_id();
        let mut m = meta(&h, &id, 3, DiskState::Expired);
        m.ended_at = None;
        write_json(&h, &id, &m);
        let (store, report) = reopen(&h);
        assert!(dir_entries(&files(&h)).is_empty());
        assert_eq!(report.warnings.len(), 1);
        assert_no_full_ids(&report, &[&id]);
        assert!(matches!(store.lookup(&id, "my_file.txt"), Lookup::NotFound));
    }

    #[tokio::test]
    async fn loaded_files_flagged_for_metrics() {
        let h = harness(|_| {});
        let id = new_id();
        write_json(&h, &id, &meta(&h, &id, 3, DiskState::Live));
        write_blob(&h, &id, b"abc");
        let (store, _report) = reopen(&h);
        assert!(matches!(store.lookup(&id, "my_file.txt"), Lookup::Live(_)));
        h.clock.advance(HOUR);
        let report = store.sweep().await;
        assert_eq!(report.expired.len(), 1);
        assert!(report.expired[0].loaded_at_startup);
        assert!(!report.expired[0].downloaded);
        assert_eq!(report.expired[0].uploader, "planner");
    }

    #[test]
    fn recovery_io_error_refuses_to_start() {
        if nix::unistd::geteuid().is_root() {
            return; // root ignores the permission bits this test relies on
        }
        let h = harness(|_| {});
        let id = new_id();
        let stray = files(&h).join(format!("{id}.bak"));
        fs::write(&stray, b"x").expect("stray");
        fs::set_permissions(files(&h), fs::Permissions::from_mode(0o500)).expect("chmod");
        h.store.unlock_data_dir();
        let result = Store::open(&h.cfg, h.clock.clone());
        fs::set_permissions(files(&h), fs::Permissions::from_mode(0o700)).expect("chmod back");
        let err = result.expect_err("recovery must fail");
        let message = err.to_string();
        assert!(!message.contains(&id), "error leaks a full id: {message}");
        match err {
            StoreError::Recovery(path) => assert_eq!(path, stray),
            other => panic!("expected Recovery error, got {other:?}"),
        }
    }

    #[test]
    fn recovered_entries_survive_a_second_restart() {
        let h = harness(|_| {});
        let id = new_id();
        let m = meta(&h, &id, 3, DiskState::Live);
        write_json(&h, &id, &m);
        write_blob(&h, &id, b"abc");
        drop(reopen(&h));
        let (store, report) = reopen(&h);
        assert!(report.warnings.is_empty());
        assert!(matches!(store.lookup(&id, "my_file.txt"), Lookup::Live(_)));
    }
}
