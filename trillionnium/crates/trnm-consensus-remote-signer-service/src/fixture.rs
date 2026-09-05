//! Deterministic fixtures used by the Rust and Python transport tests.
//!
//! The fixture is deliberately not a deployment configuration format.  It
//! gives the standalone P0 binary a reproducible validator set and binding so
//! tests can exercise the real protocol bytes without teaching a Python test
//! the CEV0 canonical-intent encoder.

use std::path::Path;

use ed25519_dalek::SigningKey;
use trnm_consensus_remote_signer_protocol::{
    proposal_purpose_profile_digest_v1, ProcessGenerationV1, RemoteConsensusCommandV1,
    RemoteSignerCheckpointWitnessV1, RemoteSignerClientProfileRefV1, RemoteSignerLeaseIdV1,
    RemoteSignerRequestBindingV1, RemoteSignerRequestNonceV1, RemoteSignerRequestV1,
    RemoteSignerRoleProfileRefV1, RemoteSignerServiceProfileRefV1,
};
use trnm_consensus_types::{
    BlockId, CanonicalSignIntentV0, CertificateId, ChainId, ConsensusParametersHash,
    ConsensusPublicKey, Epoch, GenesisHash, Height, ProtocolVersion, QcRef, Validator, ValidatorId,
    ValidatorSet, View, VotingPower,
};

use crate::{PurposePolicyV1, RemoteSignerServiceConfig};

// Test-only material. The standalone fixture binary is never a credential
// loader and must not be used for validator deployment.
const SIGNING_SEED: [u8; 32] = [0x19; 32];

/// Reproducible local fixture for the standalone P0 binary.
pub struct Fixture {
    pub validator_set: ValidatorSet,
    pub binding: RemoteSignerRequestBindingV1,
    pub signing_key: SigningKey,
}

impl Fixture {
    pub fn new() -> Self {
        let signing_key = SigningKey::from_bytes(&SIGNING_SEED);
        let author = ValidatorId::from_bytes(b"validator-a").expect("fixture author");
        let author_validator = Validator::new(
            author,
            ConsensusPublicKey::new(signing_key.verifying_key().to_bytes()),
            VotingPower::new(1).expect("fixture voting power"),
        )
        .expect("fixture validator");
        let second_validator = Validator::new(
            ValidatorId::from_bytes(b"validator-b").expect("fixture second author"),
            ConsensusPublicKey::new(
                SigningKey::from_bytes(&[0x29; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            VotingPower::new(1).expect("fixture second voting power"),
        )
        .expect("fixture second validator");
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0x31; 32]),
            ChainId::from_static("trnm-remote-signer-p0"),
            ProtocolVersion::V0,
            Epoch::new(4),
            ConsensusParametersHash::new([0x42; 32]),
            vec![author_validator, second_validator],
        )
        .expect("fixture validator set");
        let binding = RemoteSignerRequestBindingV1::new(
            &validator_set,
            author,
            RemoteSignerRoleProfileRefV1::from_public_descriptor(b"p0-consensus-role").unwrap(),
            RemoteSignerServiceProfileRefV1::from_public_descriptor(b"p0-service").unwrap(),
            RemoteSignerClientProfileRefV1::from_public_descriptor(b"p0-client").unwrap(),
            ProcessGenerationV1::new(1).unwrap(),
            RemoteSignerLeaseIdV1::from_public_grant_descriptor(b"p0-lease").unwrap(),
            RemoteSignerCheckpointWitnessV1::new(1, [0x52; 32]).unwrap(),
        )
        .expect("fixture signer binding");
        Self {
            validator_set,
            binding,
            signing_key,
        }
    }

    /// Returns the same deterministic fixture binding with an explicitly
    /// selected process generation and public lease descriptor.  This is
    /// test-only shaping: neither value is an authority grant.  Keeping the
    /// constructor here lets an OS-process test prove that a restarted
    /// service cannot attach a local watermark namespace under a stale or
    /// unrelated binding.
    pub fn binding_for_generation_and_lease(
        &self,
        generation: u64,
        lease_descriptor: &[u8],
    ) -> Result<RemoteSignerRequestBindingV1, String> {
        RemoteSignerRequestBindingV1::new(
            &self.validator_set,
            self.binding.author(),
            self.binding.role_profile_ref(),
            self.binding.service_profile_ref(),
            self.binding.client_profile_ref(),
            ProcessGenerationV1::new(generation).map_err(|error| error.to_string())?,
            RemoteSignerLeaseIdV1::from_public_grant_descriptor(lease_descriptor)
                .map_err(|error| error.to_string())?,
            self.binding.checkpoint_witness(),
        )
        .map_err(|error| error.to_string())
    }

    /// Returns the same deterministic fixture context under the isolated
    /// proposal purpose profile. This is test material only; proposal
    /// production authority remains disabled.
    pub fn proposal_binding(&self) -> Result<RemoteSignerRequestBindingV1, String> {
        RemoteSignerRequestBindingV1::new_with_purpose_profile_v1(
            &self.validator_set,
            self.binding.author(),
            self.binding.role_profile_ref(),
            self.binding.service_profile_ref(),
            self.binding.client_profile_ref(),
            self.binding.process_generation(),
            self.binding.lease_id(),
            self.binding.checkpoint_witness(),
            proposal_purpose_profile_digest_v1(),
        )
        .map_err(|error| error.to_string())
    }
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a service config from the deterministic fixture.
pub fn fixture_service_config(
    watermark_path: &Path,
    purpose_policy: PurposePolicyV1,
) -> RemoteSignerServiceConfig {
    let fixture = Fixture::new();
    fixture_service_config_with_binding(
        watermark_path,
        purpose_policy,
        fixture.validator_set,
        fixture.binding,
        fixture.signing_key,
    )
}

/// Builds a fixture service config with an explicitly selected binding.  The
/// helper is used only by process-boundary tests; production code must obtain
/// generation/lease facts from an independent authority.
pub fn fixture_service_config_with_binding(
    watermark_path: &Path,
    purpose_policy: PurposePolicyV1,
    validator_set: ValidatorSet,
    binding: RemoteSignerRequestBindingV1,
    signing_key: SigningKey,
) -> RemoteSignerServiceConfig {
    RemoteSignerServiceConfig {
        validator_set,
        binding,
        signing_key,
        watermark_path: watermark_path.to_path_buf(),
        purpose_policy,
    }
}

/// Builds a proposal-purpose fixture config. The separate binding/profile is
/// intentional: an old Vote/Timeout service must reject proposal bytes.
pub fn fixture_proposal_service_config(
    watermark_path: &Path,
) -> Result<RemoteSignerServiceConfig, String> {
    let fixture = Fixture::new();
    let binding = fixture.proposal_binding()?;
    Ok(RemoteSignerServiceConfig {
        validator_set: fixture.validator_set,
        binding,
        signing_key: fixture.signing_key,
        watermark_path: watermark_path.to_path_buf(),
        purpose_policy: PurposePolicyV1::proposal_only(),
    })
}

/// Builds one exact protocol request.  `kind` accepts only `vote` or
/// `timeout`; the returned request still has to pass the service's own exact
/// decoder before a key is reached.
pub fn fixture_request(
    fixture: &Fixture,
    kind: &str,
    view: u64,
    nonce_material: &[u8],
) -> Result<RemoteSignerRequestV1, String> {
    let author = fixture.binding.author();
    // Keep fixture SafetyState revisions strictly increasing across both
    // purposes; the service intentionally rejects equal revisions for a new
    // request even when the round/purpose differs.
    let revision = match kind {
        "vote" => view.saturating_mul(2).saturating_add(1),
        "timeout" => view.saturating_mul(2).saturating_add(2),
        _ => 1,
    }
    .max(1);
    let intent = match kind {
        "vote" => CanonicalSignIntentV0::vote(
            &fixture.validator_set,
            author,
            revision,
            View::new(view),
            Height::new(view.saturating_add(1)),
            BlockId::new([0x60_u8.wrapping_add(view as u8); 32]),
        ),
        "timeout" => {
            if view == 0 {
                return Err("timeout fixture view must be positive".to_owned());
            }
            CanonicalSignIntentV0::timeout_vote(
                &fixture.validator_set,
                author,
                revision,
                View::new(view),
                QcRef::new(
                    CertificateId::new([0x70_u8.wrapping_add(view as u8); 32]),
                    fixture.validator_set.epoch(),
                    View::new(view - 1),
                    Height::new(view),
                    BlockId::new([0x71_u8.wrapping_add(view as u8); 32]),
                    fixture.validator_set.id(),
                ),
            )
        }
        other => return Err(format!("unsupported fixture purpose {other}")),
    }
    .map_err(|error| format!("build fixture intent: {error}"))?;
    RemoteSignerRequestV1::new(
        RemoteConsensusCommandV1::from_canonical_intent(intent, &fixture.validator_set)
            .map_err(|error| format!("classify fixture intent: {error}"))?,
        &fixture.validator_set,
        fixture.binding,
        RemoteSignerRequestNonceV1::from_public_nonce_material(nonce_material)
            .map_err(|error| format!("derive fixture nonce: {error}"))?,
    )
    .map_err(|error| format!("build fixture request: {error}"))
}
