//! Low-level disk helpers: crash-safe JSON writes, directory fsync, the
//! data-dir permission check, and free-space measurement.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use nix::sys::statvfs::statvfs;
use rand::RngCore;
use serde::Serialize;

/// Writes `value` as JSON to `dest` so a crash leaves either the old file or
/// the complete new one: write a uniquely named file in `tmp_dir`, flush,
/// fsync, rename over `dest`, then fsync `dest`'s directory. The unique name
/// means concurrent writers never interleave in one file. The file is
/// created with mode `0600`; on failure the temp file is removed.
pub fn write_json_atomic(tmp_dir: &Path, dest: &Path, value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    let mut suffix = [0u8; 8];
    rand::rng().fill_bytes(&mut suffix);
    let file_name = dest
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "dest has no file name"))?;
    let tmp = tmp_dir.join(format!(
        "{}.{}.tmp",
        file_name.to_string_lossy(),
        hex::encode(suffix)
    ));

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, dest)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "dest has no parent"))?;
    fsync_dir(parent)
}

/// Unlinks `path`; a missing file counts as success.
pub fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Fsyncs a directory so renames and unlinks inside it are durable.
pub fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// True if `dir` is owned by the current effective user and has mode
/// exactly `0700`.
pub fn is_private_dir(dir: &Path) -> io::Result<bool> {
    let meta = fs::metadata(dir)?;
    let owner_ok = meta.uid() == nix::unistd::geteuid().as_raw();
    Ok(meta.is_dir() && owner_ok && meta.mode() & 0o777 == 0o700)
}

/// Free bytes and free inodes available to unprivileged users on the
/// filesystem holding `dir`: `(f_bavail × f_frsize, f_favail)`.
pub fn fs_free(dir: &Path) -> io::Result<(u64, u64)> {
    let st = statvfs(dir).map_err(io::Error::from)?;
    let bytes = (st.blocks_available() as u64).saturating_mul(st.fragment_size() as u64);
    Ok((bytes, st.files_available() as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn write_json_atomic_replaces_and_cleans_tmp() {
        let dir = TempDir::new().expect("tempdir");
        let tmp = dir.path().join("tmp");
        fs::create_dir(&tmp).expect("mkdir");
        let dest = dir.path().join("x.json");
        write_json_atomic(&tmp, &dest, &serde_json::json!({"a": 1})).expect("first");
        write_json_atomic(&tmp, &dest, &serde_json::json!({"a": 2})).expect("second");
        let v: serde_json::Value =
            serde_json::from_slice(&fs::read(&dest).expect("read")).expect("parse");
        assert_eq!(v["a"], 2);
        let mode = fs::metadata(&dest).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(fs::read_dir(&tmp).expect("read_dir").count(), 0);
    }

    #[test]
    fn write_json_atomic_failure_leaves_no_tmp() {
        let dir = TempDir::new().expect("tempdir");
        let tmp = dir.path().join("tmp");
        fs::create_dir(&tmp).expect("mkdir");
        let dest = dir.path().join("missing-dir").join("x.json");
        assert!(write_json_atomic(&tmp, &dest, &1).is_err());
        assert_eq!(fs::read_dir(&tmp).expect("read_dir").count(), 0);
    }

    #[test]
    fn is_private_dir_checks_mode() {
        let dir = TempDir::new().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(is_private_dir(dir.path()).expect("stat"));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).expect("chmod");
        assert!(!is_private_dir(dir.path()).expect("stat"));
    }

    #[test]
    fn fs_free_reports_space() {
        let dir = TempDir::new().expect("tempdir");
        let (bytes, inodes) = fs_free(dir.path()).expect("statvfs");
        assert!(bytes > 0);
        assert!(inodes > 0);
    }
}
