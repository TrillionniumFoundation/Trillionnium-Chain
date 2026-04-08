use serde::{Deserialize, Serialize};
use trnm_types::TaskObject;

/// Result of a verification attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    /// The proof is valid and the task result is accepted.
    Valid,
    /// The proof is invalid (e.g., bad signature, bad zk-snark).
    Invalid(String),
    /// The verification could not be completed (e.g., network error, resource exhaustion).
    /// This might warrant a retry or a specific error state.
    Indeterminate(String),
}

/// Stable observability outcome bucket for proof verification metrics/logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcomeLabel {
    Valid,
    Invalid,
    Indeterminate,
}

impl VerificationOutcomeLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Indeterminate => "indeterminate",
        }
    }
}

impl std::fmt::Display for VerificationOutcomeLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl VerificationResult {
    /// Collapses runtime verification results into stable low-cardinality labels.
    pub fn outcome_label(&self) -> VerificationOutcomeLabel {
        match self {
            Self::Valid => VerificationOutcomeLabel::Valid,
            Self::Invalid(_) => VerificationOutcomeLabel::Invalid,
            Self::Indeterminate(_) => VerificationOutcomeLabel::Indeterminate,
        }
    }

    /// Returns the attached human-readable reason, when any.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Valid => None,
            Self::Invalid(reason) | Self::Indeterminate(reason) => Some(reason.as_str()),
        }
    }
}

/// A trait for pluggable verification logic (Fraud Proof, TEE, ZK).
///
/// This allows the market to be agnostic to *how* the work is verified.
pub trait ProofVerifier {
    /// Returns the type of proof this verifier handles.
    fn proof_type(&self) -> &str;

    /// Verifies a proof for a given task.
    ///
    /// # Arguments
    /// * `task` - The task object being verified.
    /// * `proof_data` - The proof payload (e.g., TEE quote, ZK proof bytes, fraud challenge data).
    fn verify_proof(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult;
}
