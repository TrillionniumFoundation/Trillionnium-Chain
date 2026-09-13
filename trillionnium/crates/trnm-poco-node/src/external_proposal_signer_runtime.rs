//! Explicit, proposal-purpose-only signer client composition.
//!
//! This module is intentionally separate from `external_signer_runtime`:
//! the latter composes the bounded timeout host, while this module exposes
//! only the opt-in proposal-purpose Unix client.  It does not wire Core,
//! SafetyRules, a proposer loop, or any activation flag.  The underlying
//! client carries no private key and performs strict request/response binding
//! and signature verification in its owning crate.

#![cfg(feature = "external-proposal-signer")]

use trnm_consensus_unix_remote_signer::{
    UnixRemoteProposalSignerProducer, UnixRemoteProposalSignerProducerConfig, UnixRemoteSignerError,
};

/// Concrete proposal-purpose client available only behind the explicit
/// `external-proposal-signer` feature.  It implements the proposal producer
/// trait only; it cannot substitute for the Vote/Timeout host producer.
pub type UnixExternalProposalSignerV0 = UnixRemoteProposalSignerProducer;

/// Configuration constructor kept in the Node crate so callers compose the
/// exact feature-gated type rather than reusing the timeout producer config.
pub fn initialize_unix_external_proposal_signer_v0(
    config: UnixRemoteProposalSignerProducerConfig,
) -> Result<UnixExternalProposalSignerV0, UnixRemoteSignerError> {
    UnixRemoteProposalSignerProducer::new(config)
}

/// This module is a client composition seam, not a runtime activation.
pub const UNIX_EXTERNAL_PROPOSAL_SIGNER_CLIENT_COMPOSITION_V0: bool = true;
pub const UNIX_EXTERNAL_PROPOSAL_SIGNER_RUNTIME_ACTIVATION_V0: bool = false;
pub const UNIX_EXTERNAL_PROPOSAL_SIGNER_PRODUCTION_CANDIDATE_V0: bool = false;

#[cfg(test)]
mod tests {
    #[test]
    fn proposal_client_composition_keeps_runtime_and_production_closed() {
        assert!(super::UNIX_EXTERNAL_PROPOSAL_SIGNER_CLIENT_COMPOSITION_V0);
        assert!(!super::UNIX_EXTERNAL_PROPOSAL_SIGNER_RUNTIME_ACTIVATION_V0);
        assert!(!super::UNIX_EXTERNAL_PROPOSAL_SIGNER_PRODUCTION_CANDIDATE_V0);
    }
}
