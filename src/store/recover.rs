//! Startup recovery: reconciles `tmp/` and `files/` with the spec's
//! Startup recovery table and loads the index, before the listener binds.
//!
//! This stub only empties `tmp/`; loading `files/` and the remaining table
//! rows come with the revoke/expiry work.

use std::fs;

use super::{RecoveryReport, Store, StoreError};

/// Runs recovery against a freshly opened `store`.
pub(super) fn run(store: &Store) -> Result<RecoveryReport, StoreError> {
    for entry in fs::read_dir(&store.tmp_dir)? {
        let entry = entry?;
        let path = entry.path();
        // `file_type` does not follow symlinks, so a link is removed, not
        // its target.
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(RecoveryReport::default())
}
