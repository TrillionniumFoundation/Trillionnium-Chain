use trnm_state::StateStore;
use trnm_types::{Hash32, ObjectRef, ProofType, TaskMetadata, TaskObject, TaskStatus};

use crate::verification;
use crate::verification::{emit_proof_verification_observation, VerificationResult};

use super::*;

#[path = "apply_path/commit_reveal_challenge.rs"]
mod commit_reveal_challenge;
#[path = "apply_path/create_accept.rs"]
mod create_accept;
#[path = "apply_path/resolve_timeout.rs"]
mod resolve_timeout;
#[path = "apply_path/settlement.rs"]
mod settlement;

pub use commit_reveal_challenge::*;
pub use create_accept::*;
pub use resolve_timeout::*;
pub(crate) use settlement::*;

#[cfg(test)]
#[path = "apply_path/tests.rs"]
mod tests;
