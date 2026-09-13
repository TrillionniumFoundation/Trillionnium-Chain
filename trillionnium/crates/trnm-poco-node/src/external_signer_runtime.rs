//! Explicit composition seam for the bounded timeout host.
//!
//! This module is behind `external-signer-runtime` on purpose.  It composes
//! the already fail-closed [`PocoNodeHostV0`] with two independent Unix
//! clients: an append-only external watermark authority and the request-bound
//! remote signer adapter.  The default node build does not carry either edge,
//! and this module does not provide a production activation or a general
//! proposal/vote loop.

#![cfg(feature = "external-signer-runtime")]

use trnm_consensus_external_watermark::UnixWatermarkClient;
use trnm_consensus_types::GenesisQcV0;
use trnm_consensus_unix_remote_signer::UnixRemoteSignerProducer;

use crate::{PocoNodeHostErrorV0, PocoNodeHostV0, PocoNodeStartConfigV0};

/// The concrete host composition used by the P0 timeout integration test.
///
/// The type remains bounded to `PocoNodeHostV0`: it can only resume Core's
/// durable outbox or derive a timeout from Core's authenticated state.  It
/// cannot accept caller-selected signing roots, proposal bytes, or an
/// activation request.
pub type UnixExternalTimeoutHostV0 = PocoNodeHostV0<UnixWatermarkClient, UnixRemoteSignerProducer>;

/// Runtime composition is available only behind an explicit feature.  It is
/// still not a production activation claim: the host's own gate remains
/// closed and the remote signer service has independent P0 limitations.
pub const UNIX_EXTERNAL_TIMEOUT_RUNTIME_COMPOSITION_V0: bool = true;
pub const UNIX_EXTERNAL_TIMEOUT_PRODUCTION_ACTIVATION_V0: bool = false;
pub const UNIX_EXTERNAL_TIMEOUT_PROPOSAL_SIGNING_V0: bool = false;
pub const UNIX_EXTERNAL_TIMEOUT_LOCKED_QC_AUTHORITY_V0: bool = false;

/// Initializes a fresh bounded host with independently constructed Unix
/// clients.  Requiring already-validated clients keeps transport/configuration
/// errors in their owning crates and prevents this helper from manufacturing
/// credentials or silently falling back to a local watermark/key.
pub fn initialize_unix_external_timeout_host_v0(
    config: PocoNodeStartConfigV0,
    genesis_qc: GenesisQcV0,
    watermark: UnixWatermarkClient,
    signer: UnixRemoteSignerProducer,
) -> Result<UnixExternalTimeoutHostV0, PocoNodeHostErrorV0> {
    PocoNodeHostV0::initialize_new(config, genesis_qc, watermark, signer)
}

/// Reopens the same bounded host after a clean process restart.  The external
/// watermark client must point at the same authority namespace and the remote
/// signer client must retain the exact process-generation/lease/checkpoint
/// binding; callers cannot use this helper to repair or roll back either side.
pub fn open_unix_external_timeout_host_v0(
    config: PocoNodeStartConfigV0,
    watermark: UnixWatermarkClient,
    signer: UnixRemoteSignerProducer,
) -> Result<UnixExternalTimeoutHostV0, PocoNodeHostErrorV0> {
    PocoNodeHostV0::open_existing(config, watermark, signer)
}

#[cfg(test)]
mod tests {
    #[test]
    fn composition_flags_keep_activation_and_unimplemented_roles_closed() {
        assert!(super::UNIX_EXTERNAL_TIMEOUT_RUNTIME_COMPOSITION_V0);
        assert!(!super::UNIX_EXTERNAL_TIMEOUT_PRODUCTION_ACTIVATION_V0);
        assert!(!super::UNIX_EXTERNAL_TIMEOUT_PROPOSAL_SIGNING_V0);
        assert!(!super::UNIX_EXTERNAL_TIMEOUT_LOCKED_QC_AUTHORITY_V0);
    }
}
