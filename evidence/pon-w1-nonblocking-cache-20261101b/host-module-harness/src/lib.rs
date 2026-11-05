#![forbid(unsafe_code)]
// Scoped module execution only, not the full Node build or Host qualification.
#[path = "/workspace/scratch/41dfa6d31b4e/pon-security/trillionnium/crates/trnm-pon-node/src/error.rs"]
mod error;
pub use error::{Error, ErrorCode, ErrorKind};
pub type Result<T> = std::result::Result<T, Error>;
#[path = "/workspace/scratch/41dfa6d31b4e/pon-security/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs"]
pub mod host_kernel_parent;
