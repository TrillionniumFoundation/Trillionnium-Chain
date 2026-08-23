//! Opt-in test material for the authenticated native h1 ordinary takeover.
//!
//! This module exists only behind `lab-validator-runtime-test-support`.  It
//! authors one deterministic h1-h3 chain, drives the real source Safety owner,
//! commissions the native h1 trusted base, and consumes the public takeover
//! facade into the same linear Lab runtime used by the validator harness.  No
//! production feature exposes these deterministic private keys.

use std::{convert::Infallible, error::Error, fmt, path::Path};

use ed25519_dalek::{Signer, SigningKey};
use trnm_consensus_core::{leader_for, CoreConfig};
use trnm_consensus_signer_journal::ExternalMonotonicWatermarkV0;
use trnm_consensus_types::{
    ApplicationPayloadV0, Block, BlockHeader, BlockKind, CertifiedHeaderV0, ChainId,
    ConsensusParametersV0, ConsensusPublicKey, Epoch, FinalityProofV0, GenesisHash, GenesisQcV0,
    Height, ProposalWitnessV0, ProtocolVersion, QcReferenceV0, QuorumCertificate, SignatureBytes,
    SignedProposalV0, SigningRoot, Validator, ValidatorId, ValidatorSet, View, Vote, VotingPower,
};
use trnm_finality_types::SignedCommandEnvelopeV1;
use trnm_native_execution_v0::{
    AuthorizedSignerV0, CanonicalLabNativeApplicationConfigInputsV0,
    CanonicalLabNativeChainGenesisInputsV0, CanonicalLabNativeEmptyBootstrapPrefixV0,
    NativeApplicationConfigV0,
};
use trnm_protocol::{
    CanonicalCommandV1, CanonicalTxV1, CANONICAL_TX_PAYLOAD_TYPE_V1, CANONICAL_TX_SCHEMA_V1,
};

use crate::PocoNodeLabOrdinaryProposalRuntimeV0;

const TEST_CHAIN: ChainId = ChainId::from_static("trnm-native-anchor-takeover-test");
const ORDINARY_START_HEIGHT_V0: u64 = 4;

/// Failure while authoring or commissioning the deterministic test-only
/// takeover. The stage is stable enough for a consuming test to identify the
/// exact authority boundary without exposing store contents or private keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeNativeH1OrdinaryLabTestSupportErrorV0 {
    stage: &'static str,
    detail: String,
}

impl PocoNodeNativeH1OrdinaryLabTestSupportErrorV0 {
    fn from_debug(stage: &'static str, error: impl fmt::Debug) -> Self {
        Self {
            stage,
            detail: format!("{error:?}"),
        }
    }

    fn message(stage: &'static str, detail: impl Into<String>) -> Self {
        Self {
            stage,
            detail: detail.into(),
        }
    }

    pub const fn stage_v0(&self) -> &'static str {
        self.stage
    }
}

impl fmt::Display for PocoNodeNativeH1OrdinaryLabTestSupportErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "native h1 ordinary Lab test support failed at {}: {}",
            self.stage, self.detail
        )
    }
}

impl Error for PocoNodeNativeH1OrdinaryLabTestSupportErrorV0 {}

macro_rules! support_try {
    ($stage:literal, $expression:expr) => {
        $expression.map_err(|error| {
            PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::from_debug($stage, error)
        })?
    };
}

/// Test-only one-way owner produced by the exact native h1-h3 takeover.
///
/// Consumers can either borrow its chain context, sign a deterministic
/// bootstrap proposal root, or consume it into the six inputs required by the
/// continuous runtime. The runtime itself never has a borrow-only escape hatch.
#[must_use = "the test takeover runtime must be consumed by a continuous owner"]
pub struct PocoNodeNativeH1OrdinaryLabTestBundleV0<W: ExternalMonotonicWatermarkV0> {
    runtime: PocoNodeLabOrdinaryProposalRuntimeV0<W>,
    core_config: CoreConfig,
    application_config: NativeApplicationConfigV0,
    reopen_application_config: NativeApplicationConfigV0,
    local_validator: ValidatorId,
    validator_set: ValidatorSet,
    consensus_parameters: ConsensusParametersV0,
    local_signing_key: SigningKey,
    consensus_signing_keys: Vec<(ValidatorId, SigningKey)>,
    validator_count: usize,
    local_validator_index: usize,
    ordinary_start_height: u64,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeNativeH1OrdinaryLabTestBundleV0<W> {
    pub const fn runtime_v0(&self) -> &PocoNodeLabOrdinaryProposalRuntimeV0<W> {
        &self.runtime
    }

    pub const fn core_config_v0(&self) -> &CoreConfig {
        &self.core_config
    }

    pub const fn application_config_v0(&self) -> &NativeApplicationConfigV0 {
        &self.application_config
    }

    pub const fn local_validator_v0(&self) -> ValidatorId {
        self.local_validator
    }

    pub const fn validator_set_v0(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub const fn consensus_parameters_v0(&self) -> &ConsensusParametersV0 {
        &self.consensus_parameters
    }

    pub const fn signing_key_v0(&self) -> &SigningKey {
        &self.local_signing_key
    }

    pub const fn ordinary_start_height_v0(&self) -> u64 {
        self.ordinary_start_height
    }

    pub const fn validator_count_v0(&self) -> usize {
        self.validator_count
    }

    pub const fn local_validator_index_v0(&self) -> usize {
        self.local_validator_index
    }

    pub fn sign_consensus_root_v0(
        &self,
        author: ValidatorId,
        root: SigningRoot,
    ) -> Result<SignatureBytes, PocoNodeNativeH1OrdinaryLabTestSupportErrorV0> {
        sign_v0(&self.consensus_signing_keys, author, root)
    }

    /// Produces the exact signed canonical application transaction for one
    /// ordinary fixture height without exposing the fixed operator key. The
    /// signer nonce is the one-based ordinary-block ordinal, so sequential
    /// h4, h5, ... calls remain valid against the same native application.
    pub fn ordinary_transactions_v0(
        &self,
        height: u64,
        timestamp_ms: u64,
    ) -> Result<Vec<Vec<u8>>, PocoNodeNativeH1OrdinaryLabTestSupportErrorV0> {
        if height < self.ordinary_start_height || timestamp_ms == 0 {
            return Err(PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::message(
                "workload.coordinate",
                "ordinary transaction height/time is outside the fixture profile",
            ));
        }
        let nonce = height
            .checked_sub(self.ordinary_start_height)
            .and_then(|ordinal| ordinal.checked_add(1))
            .ok_or_else(|| {
                PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::message(
                    "workload.nonce",
                    "ordinary transaction nonce overflowed",
                )
            })?;
        let expires_at_ms = timestamp_ms.checked_add(10_000).ok_or_else(|| {
            PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::message(
                "workload.expiry",
                "ordinary transaction expiry overflowed",
            )
        })?;
        let operator = SigningKey::from_bytes(&[0x51; 32]);
        let transaction = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:operator:anchor-test".to_string(),
            nonce,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreditAccount {
                account: "did:client:anchor-test".to_string(),
                amount: 10_000,
            },
        };
        let payload = serde_json::to_vec(&transaction).map_err(|error| {
            PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::from_debug(
                "workload.payload_encode",
                error,
            )
        })?;
        let request_id = format!("anchor-h{height}-credit-{nonce}");
        let envelope = SignedCommandEnvelopeV1::sign(
            self.validator_set.chain_id().as_str(),
            &request_id,
            "did:operator:anchor-test",
            "operator",
            nonce,
            timestamp_ms,
            expires_at_ms,
            CANONICAL_TX_PAYLOAD_TYPE_V1,
            &payload,
            &operator,
        )
        .map_err(|error| {
            PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::from_debug(
                "workload.envelope_sign",
                error,
            )
        })?;
        let envelope = serde_json::to_vec(&envelope).map_err(|error| {
            PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::from_debug(
                "workload.envelope_encode",
                error,
            )
        })?;
        Ok(vec![envelope])
    }

    /// Exact consuming shape used by `trnm-poco-lab-validator` tests.
    #[allow(clippy::type_complexity)]
    pub fn into_continuous_runtime_parts_v0(
        self,
    ) -> (
        ValidatorId,
        ValidatorSet,
        ConsensusParametersV0,
        SigningKey,
        u64,
        PocoNodeLabOrdinaryProposalRuntimeV0<W>,
    ) {
        (
            self.local_validator,
            self.validator_set,
            self.consensus_parameters,
            self.local_signing_key,
            self.ordinary_start_height,
            self.runtime,
        )
    }

    /// Test-only consuming shape for a process drop followed by existing-root
    /// recovery. The immutable configurations are returned with the runtime so
    /// the test cannot recreate either from copied live authority facts.
    pub fn into_recovery_test_parts_v0(
        self,
    ) -> (
        CoreConfig,
        NativeApplicationConfigV0,
        PocoNodeLabOrdinaryProposalRuntimeV0<W>,
    ) {
        (self.core_config, self.application_config, self.runtime)
    }

    /// Test-only consuming shape for an exact process drop followed by a
    /// second reopen of the same durable root.  A fresh immutable config is
    /// retained for the second host so the production config type does not
    /// become cloneable merely to support a test fixture.
    #[allow(clippy::type_complexity)]
    pub fn into_reopen_test_parts_v0(
        self,
    ) -> (
        CoreConfig,
        NativeApplicationConfigV0,
        NativeApplicationConfigV0,
        PocoNodeLabOrdinaryProposalRuntimeV0<W>,
    ) {
        (
            self.core_config,
            self.application_config,
            self.reopen_application_config,
            self.runtime,
        )
    }
}

/// Authors and consumes one exact fresh h1 takeover under an empty protected
/// root. `watermark` is supplied by the consumer so the returned runtime has
/// the same concrete external-watermark type as the continuous owner.
pub fn commission_native_h1_ordinary_lab_test_bundle_v0<W: ExternalMonotonicWatermarkV0>(
    root: impl AsRef<Path>,
    watermark: W,
    validator_count: usize,
    local_validator_index: usize,
) -> Result<PocoNodeNativeH1OrdinaryLabTestBundleV0<W>, PocoNodeNativeH1OrdinaryLabTestSupportErrorV0>
{
    if !(4..=100).contains(&validator_count) || local_validator_index >= validator_count {
        return Err(PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::message(
            "fixture.validator_inventory",
            "validator_count must be 4..=100 and local_validator_index must be in range",
        ));
    }
    let (keys, parameters, validator_set) = consensus_fixture_v0(validator_count)?;
    let local_validator = keys[local_validator_index].0;
    let application_config =
        native_application_config_v0(validator_set.clone(), parameters, local_validator)?;
    let recovery_application_config =
        native_application_config_v0(validator_set.clone(), parameters, local_validator)?;
    let reopen_application_config =
        native_application_config_v0(validator_set.clone(), parameters, local_validator)?;
    let (proof, [h1, h2, h3]) = canonical_empty_prefix_v0(&keys, parameters, &validator_set)?;
    let core_config = support_try!(
        "fixture.core_config",
        CoreConfig::new(
            local_validator,
            validator_set.clone(),
            parameters,
            0,
            32,
            64,
        )
    );
    let bootstrap = support_try!(
        "fixture.bootstrap_admit",
        crate::PocoNodeDeployedLabBootstrapV0::admit_exact_v0(
            &core_config,
            &application_config,
            [h1, h2, h3],
            proof,
        )
    );
    let runtime = support_try!(
        "fixture.deployed_commission",
        crate::commission_deployed_lab_ordinary_runtime_v0(
            root,
            core_config.clone(),
            application_config,
            bootstrap,
            |_record_path| Ok::<W, Infallible>(watermark),
        )
    );

    Ok(PocoNodeNativeH1OrdinaryLabTestBundleV0 {
        runtime,
        core_config,
        application_config: recovery_application_config,
        reopen_application_config,
        local_validator,
        validator_set,
        consensus_parameters: parameters,
        local_signing_key: keys[local_validator_index].1.clone(),
        consensus_signing_keys: keys,
        validator_count,
        local_validator_index,
        ordinary_start_height: ORDINARY_START_HEIGHT_V0,
    })
}

type ConsensusFixtureV0 = (
    Vec<(ValidatorId, SigningKey)>,
    ConsensusParametersV0,
    ValidatorSet,
);

fn consensus_fixture_v0(
    validator_count: usize,
) -> Result<ConsensusFixtureV0, PocoNodeNativeH1OrdinaryLabTestSupportErrorV0> {
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let keys = (0..validator_count)
        .map(|zero_based_index| {
            let index = u8::try_from(zero_based_index + 1).map_err(|error| {
                PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::from_debug(
                    "fixture.validator_index",
                    error,
                )
            })?;
            Ok::<_, PocoNodeNativeH1OrdinaryLabTestSupportErrorV0>((
                ValidatorId::new([index; 32]),
                SigningKey::from_bytes(&[index.saturating_add(40); 32]),
            ))
        })
        .collect::<Result<Vec<_>, PocoNodeNativeH1OrdinaryLabTestSupportErrorV0>>()?;
    let validators = keys
        .iter()
        .map(|(id, key)| {
            Validator::new(
                *id,
                ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                VotingPower::new(1).expect("fixture voting power is positive"),
            )
            .map_err(|error| {
                PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::from_debug(
                    "fixture.validator",
                    error,
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let validator_set = support_try!(
        "fixture.validator_set",
        ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            TEST_CHAIN,
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
    );
    Ok((keys, parameters, validator_set))
}

fn application_signers_v0(
) -> Result<Vec<AuthorizedSignerV0>, PocoNodeNativeH1OrdinaryLabTestSupportErrorV0> {
    let operator = SigningKey::from_bytes(&[0x51; 32]);
    Ok(vec![support_try!(
        "fixture.application_signer",
        AuthorizedSignerV0::new(
            "did:operator:anchor-test",
            "operator",
            hex_v0(&operator.verifying_key().to_bytes()),
        )
    )])
}

fn native_application_config_v0(
    validator_set: ValidatorSet,
    parameters: ConsensusParametersV0,
    local_validator: ValidatorId,
) -> Result<NativeApplicationConfigV0, PocoNodeNativeH1OrdinaryLabTestSupportErrorV0> {
    let inputs = support_try!(
        "fixture.application_inputs",
        CanonicalLabNativeApplicationConfigInputsV0::new(
            "anchor-takeover-test-001",
            [0x91; 32],
            [0x92; 32],
            [0x93; 32],
            [0x94; 32],
            local_validator,
            validator_set,
            parameters,
            application_signers_v0()?,
            "did:operator:anchor-test",
        )
    );
    Ok(support_try!(
        "fixture.application_config",
        NativeApplicationConfigV0::from_canonical_lab_inputs_v0(inputs)
    ))
}

fn canonical_empty_prefix_v0(
    keys: &[(ValidatorId, SigningKey)],
    parameters: ConsensusParametersV0,
    validator_set: &ValidatorSet,
) -> Result<(FinalityProofV0, [SignedProposalV0; 3]), PocoNodeNativeH1OrdinaryLabTestSupportErrorV0>
{
    let chain_inputs = support_try!(
        "bootstrap.chain_inputs",
        CanonicalLabNativeChainGenesisInputsV0::new(
            validator_set.clone(),
            parameters,
            application_signers_v0()?,
            "did:operator:anchor-test",
        )
    );
    let mut prefix = support_try!(
        "bootstrap.prefix",
        CanonicalLabNativeEmptyBootstrapPrefixV0::new(chain_inputs)
    );
    let genesis_qc = support_try!(
        "bootstrap.genesis_qc",
        GenesisQcV0::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            validator_set,
        )
    );
    let mut justify = QcReferenceV0::genesis_anchor(genesis_qc);
    let mut parent_timestamp_ms = 0;
    let mut proposals = Vec::with_capacity(3);
    let mut certificates = Vec::with_capacity(3);

    for height in 1_u64..=3 {
        let timestamp_ms = height * 100;
        let prepared = support_try!(
            "bootstrap.prepare_block",
            prefix.prepare_next_empty_block_v0(timestamp_ms)
        );
        let facts = prepared.facts_v0();
        let view = View::new(height);
        let proposer = leader_for(validator_set, view);
        let header = support_try!(
            "bootstrap.header",
            BlockHeader::new(
                validator_set.genesis_hash(),
                validator_set.chain_id(),
                validator_set.protocol_version(),
                validator_set.epoch(),
                view,
                Height::new(height),
                BlockKind::Regular,
                facts.parent_block_id_v0(),
                proposer,
                validator_set.id(),
                parameters.hash(),
                facts.payload_root_v0(),
                facts.post_state_root_v0(),
                facts.receipts_root_v0(),
                facts.evidence_root_v0(),
                timestamp_ms,
                None,
            )
        );
        let payload = support_try!("bootstrap.payload", ApplicationPayloadV0::new(Vec::new()));
        let payload = support_try!("bootstrap.payload_encode", payload.try_cev0_bytes());
        let block = support_try!("bootstrap.block", Block::new(header, payload, Vec::new()));
        let proposal_root = support_try!(
            "bootstrap.proposal_root",
            ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
        );
        let witness = support_try!(
            "bootstrap.witness",
            ProposalWitnessV0::new(
                block.header(),
                justify,
                None,
                None,
                sign_v0(keys, proposer, proposal_root)?,
                validator_set,
                None,
                &parameters,
                parent_timestamp_ms,
            )
        );
        let proposal = support_try!(
            "bootstrap.proposal",
            SignedProposalV0::new(
                block,
                witness,
                validator_set,
                None,
                &parameters,
                parent_timestamp_ms,
            )
        );
        prefix = support_try!(
            "bootstrap.commit",
            prefix.commit_exact_block_v0(prepared, proposal.block())
        );

        let vote_root = support_try!(
            "bootstrap.vote_root",
            Vote::signing_root_for_set(
                validator_set,
                view,
                Height::new(height),
                proposal.block().id(),
            )
        );
        let votes = validator_set
            .validators()
            .iter()
            .map(|validator| {
                Vote::new(
                    validator_set.chain_id(),
                    validator_set.protocol_version(),
                    validator_set.epoch(),
                    view,
                    Height::new(height),
                    proposal.block().id(),
                    validator_set.id(),
                    validator.id(),
                    sign_v0(keys, validator.id(), vote_root)?,
                    validator_set,
                )
                .map_err(|error| {
                    PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::from_debug(
                        "bootstrap.vote",
                        error,
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let qc = support_try!(
            "bootstrap.qc",
            QuorumCertificate::new(
                validator_set.chain_id(),
                validator_set.protocol_version(),
                validator_set.epoch(),
                view,
                Height::new(height),
                proposal.block().id(),
                validator_set.id(),
                votes,
                validator_set,
            )
        );
        parent_timestamp_ms = timestamp_ms;
        justify = QcReferenceV0::ordinary(qc.clone());
        proposals.push(proposal);
        certificates.push(qc);
    }
    if !prefix.is_complete_v0() {
        return Err(PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::message(
            "bootstrap.complete",
            "canonical h1-h3 prefix is incomplete",
        ));
    }

    let certified_h1 = support_try!(
        "bootstrap.certified_h1",
        CertifiedHeaderV0::from_signed_proposal(
            proposals[0].clone(),
            certificates[0].clone(),
            validator_set,
            None,
            &parameters,
            0,
        )
    );
    let certified_h2 = support_try!(
        "bootstrap.certified_h2",
        CertifiedHeaderV0::from_signed_proposal(
            proposals[1].clone(),
            certificates[1].clone(),
            validator_set,
            None,
            &parameters,
            100,
        )
    );
    let certified_h3 = support_try!(
        "bootstrap.certified_h3",
        CertifiedHeaderV0::from_signed_proposal(
            proposals[2].clone(),
            certificates[2].clone(),
            validator_set,
            None,
            &parameters,
            200,
        )
    );
    let proof = support_try!(
        "bootstrap.finality_proof",
        FinalityProofV0::new(
            certified_h1,
            certified_h2,
            certified_h3,
            validator_set,
            None,
            &parameters,
            0,
        )
    );
    Ok((
        proof,
        [
            proposals[0].clone(),
            proposals[1].clone(),
            proposals[2].clone(),
        ],
    ))
}

fn sign_v0(
    keys: &[(ValidatorId, SigningKey)],
    author: ValidatorId,
    root: SigningRoot,
) -> Result<SignatureBytes, PocoNodeNativeH1OrdinaryLabTestSupportErrorV0> {
    let key = keys
        .iter()
        .find_map(|(id, key)| (*id == author).then_some(key))
        .ok_or_else(|| {
            PocoNodeNativeH1OrdinaryLabTestSupportErrorV0::message(
                "fixture.signing_key",
                "requested validator has no deterministic signing key",
            )
        })?;
    Ok(SignatureBytes::from_array(
        key.sign(root.as_bytes()).to_bytes(),
    ))
}

fn hex_v0(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
    };

    use tempfile::tempdir;
    use trnm_consensus_signer_journal::{ExternalWatermarkErrorV0, SignerWatermarkV0};

    use super::*;

    #[derive(Debug, Default)]
    struct MemoryWatermarkV0 {
        value: Option<SignerWatermarkV0>,
    }

    impl ExternalMonotonicWatermarkV0 for MemoryWatermarkV0 {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            if self
                .value
                .is_some_and(|watermark| watermark.scope() != scope)
            {
                return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
            }
            Ok(self.value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            if self.value != expected {
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            match expected {
                None if target.sequence() == 0 => {}
                Some(previous)
                    if previous.scope() == target.scope()
                        && previous.journal_id() == target.journal_id()
                        && previous.sequence().checked_add(1) == Some(target.sequence()) => {}
                _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
            }
            self.value = Some(target);
            Ok(())
        }
    }

    #[test]
    fn typed_deployed_bootstrap_rejects_readdressed_successors_v0() {
        let (keys, parameters, validator_set) = consensus_fixture_v0(4).expect("fixture set");
        let local_validator = keys[0].0;
        let application =
            native_application_config_v0(validator_set.clone(), parameters, local_validator)
                .expect("native application config");
        let (proof, [h1, h2, h3]) =
            canonical_empty_prefix_v0(&keys, parameters, &validator_set).expect("public prefix");
        let core = CoreConfig::new(local_validator, validator_set, parameters, 0, 32, 64)
            .expect("plain core config");

        let error = crate::PocoNodeDeployedLabBootstrapV0::admit_exact_v0(
            &core,
            &application,
            [h1, h3, h2],
            proof,
        )
        .expect_err("readdressed h2/h3 must be rejected");
        assert_eq!(error.stage_v0(), "bootstrap.geometry");
    }

    #[test]
    fn fresh_deployed_commission_reaches_exact_h3_ordinary_cut_v0() {
        std::thread::Builder::new()
            .name("deployed-lab-commission-e2e".to_owned())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let temporary = tempdir().expect("temporary parent");
                fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
                    .expect("private temporary parent");
                let authority = temporary.path().join("authority");
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                builder.create(&authority).expect("private authority root");

                let bundle = commission_native_h1_ordinary_lab_test_bundle_v0(
                    authority,
                    MemoryWatermarkV0::default(),
                    4,
                    0,
                )
                .expect("fresh deployed commissioning");
                let facts = bundle.runtime_v0().facts_v0();
                assert_eq!(facts.proposal_parent_height_v0(), 3);
                assert_eq!(facts.application_applied_height_v0(), 1);
                assert_eq!(bundle.ordinary_start_height_v0(), 4);
                assert!(bundle.runtime_v0().matches_consensus_context_v0(
                    bundle.local_validator_v0(),
                    bundle.validator_set_v0(),
                    bundle.consensus_parameters_v0(),
                ));
            })
            .expect("spawn bounded deployed commissioning owner")
            .join()
            .expect("deployed commissioning owner panicked");
    }
}
