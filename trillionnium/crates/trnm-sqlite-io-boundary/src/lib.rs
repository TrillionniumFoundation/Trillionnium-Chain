//! Explicit, process-owned experimental SQLite I/O domain.
//!
//! This is not a general SQLite sandbox or a filesystem allocated-block quota.
//! It bounds the logical high-water lengths of at most three retained real
//! inodes at each of seven private roots, including unlinked-open objects.
//! The caller must exclusively own those roots; hostile same-UID filesystem
//! mutation and foreign/default-VFS connections are outside the admitted domain.
//! No global default VFS or Unix syscall hook is replaced. The at-most-seven
//! published registrations retain their real root objects until process exit,
//! including when a safe foreign memory connection has retained the VFS name.
//! On supported targets, fresh roots may also be created relative to consumed
//! parent directory Files with `NativeIoOwner::create_at`; parent pathnames are
//! never reopened. The caller owns the capabilities and creates phase ancestors.
#![deny(unsafe_op_in_unsafe_fn)]

mod ledger;
#[cfg(target_os = "linux")]
mod owner;
mod sql;
mod transaction_scope;
#[cfg(target_os = "linux")]
mod unix_abi;
#[cfg(not(target_os = "linux"))]
mod unsupported;
#[cfg(target_os = "linux")]
mod vfs;

pub use ledger::{LifecycleReceipt, ObjectReceipt, RootReceipt, SecondaryFailureReceipt};
#[cfg(target_os = "linux")]
pub use owner::{NativeIoLease, NativeIoOwner};
pub use sql::OwnedConnection;
pub use transaction_scope::TransactionScope;
#[cfg(not(target_os = "linux"))]
pub use unsupported::{registered_receipt, NativeIoLease, NativeIoOwner};
#[cfg(target_os = "linux")]
pub use vfs::registered_receipt;

pub const DOMAIN: &str = "pn1-owned-sqlite-real-inode-v1";
/// Separate evidence domain for fixed-size logical growth reservations.
/// This does not describe allocated blocks or increase any original limit.
pub const RESERVATION_DOMAIN_V2: &str = "pn1-owned-sqlite-reservation-v2";
pub const GROWTH_QUANTUM_BYTES_V2: u64 = 64 * 1024;
pub const ROOT_COUNT: usize = 7;
pub const OBJECTS_PER_ROOT: usize = 3;
pub const FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const DOMAIN_BYTES: u64 = ROOT_COUNT as u64 * OBJECTS_PER_ROOT as u64 * FILE_BYTES;

#[derive(Debug)]
pub struct BoundaryError(pub String);
impl std::fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", DOMAIN, self.0)
    }
}
impl std::error::Error for BoundaryError {}
impl From<std::io::Error> for BoundaryError {
    fn from(value: std::io::Error) -> Self {
        Self(value.to_string())
    }
}
type Result<T> = std::result::Result<T, BoundaryError>;
