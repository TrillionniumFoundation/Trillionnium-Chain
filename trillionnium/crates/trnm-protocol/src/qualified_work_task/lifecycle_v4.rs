//! Revision9 relaxes only atomic successor inclusion from an exact height to a
//! source-signed overlapping window. The bounded QDL2/QWA2 codec is shared; strict
//! network/parameters and registered source authority select this fresh profile.
pub const PROFILE: &str = "signed-task-lifecycle-dev-v4";
pub const CONSENSUS_REVISION: u64 = 9;
pub use super::lifecycle_v3::{
    AtomicRenewTaskV3 as AtomicRenewTaskV4, ATOMIC_RENEW_BYTES, ATOMIC_RENEW_TAG,
};
