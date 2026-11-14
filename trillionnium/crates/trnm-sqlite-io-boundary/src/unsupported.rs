//! Non-Linux defaults still compile. The explicit bounded factory has no
//! constructible owner/lease here and always returns unsupported; it never
//! opens an ordinary/default-VFS connection as a fallback.
use crate::{BoundaryError, OwnedConnection, Result, RootReceipt, ROOT_COUNT};
use rusqlite::OpenFlags;
use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};

pub enum NativeIoOwner {}
#[derive(Clone)]
pub enum NativeIoLease {}

fn unsupported<T>() -> Result<T> {
    Err(BoundaryError(
        "owned native SQLite I/O is unsupported on this target; no bounded connection was opened"
            .into(),
    ))
}
pub fn registered_receipt(_vfs_name: &str) -> Result<RootReceipt> {
    unsupported()
}

impl NativeIoOwner {
    pub fn create(_paths: [PathBuf; ROOT_COUNT]) -> Result<Self> {
        unsupported()
    }
    pub fn create_at(_parents: [(File, OsString); ROOT_COUNT]) -> Result<Self> {
        unsupported()
    }
    pub fn create_with_reservation_v2(_paths: [PathBuf; ROOT_COUNT]) -> Result<Self> {
        unsupported()
    }
    pub fn create_at_with_reservation_v2(_parents: [(File, OsString); ROOT_COUNT]) -> Result<Self> {
        unsupported()
    }
    pub fn lease(&self, _index: usize) -> Result<NativeIoLease> {
        unsupported()
    }
    pub fn receipts(&self) -> Result<Vec<RootReceipt>> {
        unsupported()
    }
}
impl NativeIoLease {
    pub fn vfs_name(&self) -> &str {
        match *self {}
    }
    pub fn check(&self) -> Result<()> {
        unsupported()
    }
    pub fn receipt(&self) -> Result<RootReceipt> {
        unsupported()
    }
    pub fn open(&self, _path: &Path, _flags: OpenFlags) -> Result<OwnedConnection> {
        unsupported()
    }
    pub fn open_in_memory(&self) -> Result<OwnedConnection> {
        unsupported()
    }
    pub fn directory(&self) -> PathBuf {
        match *self {}
    }
    pub fn identity(&self) -> (u64, u64) {
        match *self {}
    }
}
