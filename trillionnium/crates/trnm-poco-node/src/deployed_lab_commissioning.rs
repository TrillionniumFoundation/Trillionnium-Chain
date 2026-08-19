//! Fresh, laboratory-only commissioning of the public zero-Comet h1-h3 prefix.
//!
//! This owner is available only with `lab-validator-runtime`.  It consumes an
//! already decoded public bootstrap through a second strict admission pass,
//! drives Core's real authenticated-genesis h1 source typestate, commissions
//! the proof-derived native h1 trusted base, and consumes the retained h2/h3
//! successor path into the ordinary laboratory runtime.  It is deliberately a
//! fresh-only path: an existing or partially created authority namespace is
//! rejected and no recovery claim is made here.

use std::{
    convert::Infallible,
    error::Error,
    fmt, fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    native_valid_result_checksum_v0, ApplicationNativeValidDeliveryFactsV0,
    AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
    AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0,
    AuthenticatedGenesisApplicationParentV0, BlockIdOverlayRefV0, Core, CoreConfig,
    NativeValidPostAckActionV0, PayloadValidationRouteV0, SafetyStateRecordLimitsV0,
    ValidatedPayloadArtifactRefV0,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{SafetyStateStoreProfileV0, SqliteSafetyStateStoreV0};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, SignerJournalProfileV0, SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, ApplicationPayloadV0, Block, BlockBodyV0, BlockKind,
    ExecutionReceiptsV0, FinalityProofV0, GenesisQcV0, Height, SignedProposalV0, StateRoot, View,
};
use trnm_native_application::{
    ChainIdV0, GenesisHashV0, Hash32V0, NativeApplicationGenesisRequestV0, NativeApplicationV0,
    StateRootV0 as NativeStateRootV0,
};
use trnm_native_application_sqlite::{
    ProposalValidationOwnerIdV0, ProposalValidationStoreScopeV0, SqliteProposalValidationStoreV0,
};
use trnm_native_execution_v0::{DurableNativeApplicationV0, NativeApplicationConfigV0};

use crate::{
    derive_signer_watermark_scope_v0, PocoNodeLabOrdinaryProposalRuntimeV0,
    PocoNodeLabProposalJournalConfigV0, PocoNodeNativeH1StateSyncCommissioningConfigV0,
    PocoNodeNativeH1StateSyncPromotionSourceV0, SqliteExternalNodeCheckpointStoreV0,
    SIGNER_JOURNAL_PROFILE_REF_V0, STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
};

const MAXIMUM_RECORD_BYTES_V0: usize = 64 * 1024 * 1024;
const MAXIMUM_BLOB_BYTES_V0: usize = 16 * 1024 * 1024;
const MAXIMUM_SAFETY_DATABASE_BYTES_V0: usize = 256 * 1024 * 1024;
const MAXIMUM_SIGNER_INTENTS_V0: u64 = 4_096;
const MAXIMUM_SIGNER_INTENT_BYTES_V0: usize = 4_096;
const MAXIMUM_SIGNER_DATABASE_BYTES_V0: usize = 64 * 1024 * 1024;
const PROJECTION_PROFILE_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.deployed-lab.authenticated-genesis-projection.v0";
const SOURCE_ARTIFACT_DOMAIN_V0: &[u8] = b"trnm.poco-node.deployed-lab.source-artifact.v0";
const SOURCE_DELIVERY_DOMAIN_V0: &[u8] = b"trnm.poco-node.deployed-lab.source-delivery.v0";
const PROPOSAL_SCOPE_DOMAIN_V0: &[u8] = b"trnm.poco-node.deployed-lab.proposal-scope.v0";
const PROPOSAL_OWNER_DOMAIN_V0: &[u8] = b"trnm.poco-node.deployed-lab.proposal-owner.v0";

/// Stage-addressed failure for the fresh laboratory commissioning owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeDeployedLabCommissioningErrorV0 {
    stage: &'static str,
    detail: String,
}

impl PocoNodeDeployedLabCommissioningErrorV0 {
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

impl fmt::Display for PocoNodeDeployedLabCommissioningErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "deployed Lab commissioning failed at {}: {}",
            self.stage, self.detail
        )
    }
}

impl Error for PocoNodeDeployedLabCommissioningErrorV0 {}

macro_rules! deploy_try {
    ($stage:literal, $expression:expr) => {
        $expression
            .map_err(|error| PocoNodeDeployedLabCommissioningErrorV0::from_debug($stage, error))?
    };
}

/// Second-pass, Node-owned admission of one exact public h1-h3 bootstrap.
///
/// The fields are private and the owner is intentionally neither `Clone` nor
/// `Copy`.  Admission verifies every proposal signature, the complete finality
/// proof, exact certified-header equality, all-validator QC membership, the
/// empty h1-h3 payload geometry, and the native application genesis context.
#[must_use = "the verified public bootstrap must be commissioned or discarded"]
pub struct PocoNodeDeployedLabBootstrapV0 {
    h1: SignedProposalV0,
    h2: SignedProposalV0,
    h3: SignedProposalV0,
    proof: FinalityProofV0,
}

impl fmt::Debug for PocoNodeDeployedLabBootstrapV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeDeployedLabBootstrapV0")
            .field("h1", &self.h1.block().id())
            .field("h2", &self.h2.block().id())
            .field("h3", &self.h3.block().id())
            .field("proof", &self.proof.id())
            .finish()
    }
}

impl PocoNodeDeployedLabBootstrapV0 {
    pub fn admit_exact_v0(
        core_config: &CoreConfig,
        application_config: &NativeApplicationConfigV0,
        proposals: [SignedProposalV0; 3],
        proof: FinalityProofV0,
    ) -> Result<Self, PocoNodeDeployedLabCommissioningErrorV0> {
        if core_config
            .authenticated_genesis_application_parent_v0()
            .is_some()
            || application_config.validator_set_v0() != core_config.validator_set()
            || application_config.consensus_parameters_v0() != core_config.consensus_parameters()
            || application_config.chain_id_v0() != core_config.validator_set().chain_id().as_str()
            || application_config.genesis_hash_v0()
                != *core_config.validator_set().genesis_hash().as_bytes()
            || application_config.initial_block_id_v0()
                != *core_config.genesis_block_id().as_bytes()
        {
            return Err(PocoNodeDeployedLabCommissioningErrorV0::message(
                "bootstrap.context",
                "public bootstrap differs from the plain Core/native application context",
            ));
        }

        let mut parent_timestamp_ms = core_config.trusted_genesis_timestamp_ms();
        for (index, proposal) in proposals.iter().enumerate() {
            let height = u64::try_from(index + 1).expect("h1-h3 index fits u64");
            deploy_try!(
                "bootstrap.proposal_verify",
                proposal.verify(
                    core_config.validator_set(),
                    None,
                    core_config.consensus_parameters(),
                    parent_timestamp_ms,
                    &StrictEd25519Verifier,
                )
            );
            let header = proposal.block().header();
            let payload = deploy_try!(
                "bootstrap.payload_decode",
                decode_application_payload_v0_exact(
                    proposal.block().application_payload(),
                    core_config.consensus_parameters(),
                )
            );
            if header.height() != Height::new(height)
                || header.view() != View::new(height)
                || header.block_kind() != BlockKind::Regular
                || !payload.transactions().is_empty()
                || !proposal.block().evidence_objects().is_empty()
                || (index == 0
                    && header.parent_id()
                        != trnm_consensus_types::BlockId::new(
                            application_config.initial_block_id_v0(),
                        ))
                || (index > 0 && header.parent_id() != proposals[index - 1].block().id())
            {
                return Err(PocoNodeDeployedLabCommissioningErrorV0::message(
                    "bootstrap.geometry",
                    "public bootstrap is not the exact empty h1-h3 chain",
                ));
            }
            parent_timestamp_ms = header.timestamp_ms();
        }

        deploy_try!(
            "bootstrap.finality_verify",
            proof.verify(
                core_config.validator_set(),
                None,
                core_config.consensus_parameters(),
                core_config.trusted_genesis_timestamp_ms(),
                &StrictEd25519Verifier,
            )
        );
        let certified = [proof.finalized_block(), proof.child(), proof.grandchild()];
        for (index, (certificate, proposal)) in certified.iter().zip(proposals.iter()).enumerate() {
            let votes = certificate.certifying_qc().votes();
            if certificate.header() != proposal.block().header()
                || certificate.witness() != proposal.witness()
                || votes.len() != core_config.validator_set().validators().len()
                || !votes
                    .iter()
                    .zip(core_config.validator_set().validators())
                    .all(|(vote, validator)| vote.author() == validator.id())
                || (index > 0
                    && proposal.witness().justify_qc().as_ordinary()
                        != Some(certified[index - 1].certifying_qc()))
            {
                return Err(PocoNodeDeployedLabCommissioningErrorV0::message(
                    "bootstrap.certified_chain",
                    "public bootstrap differs from the exact all-signer finality carrier",
                ));
            }
        }

        let [h1, h2, h3] = proposals;
        Ok(Self { h1, h2, h3, proof })
    }
}

struct ExactRegistrarV0;

impl AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0 for ExactRegistrarV0 {
    type Output = AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0;
    type Error = Infallible;

    fn register_authenticated_genesis_application_h1_offline_v0(
        self,
        owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
    ) -> Result<Self::Output, Self::Error> {
        Ok(owner)
    }
}

struct AuthorityPathsV0 {
    source_safety: PathBuf,
    target_safety: PathBuf,
    signer: PathBuf,
    application: PathBuf,
    checkpoint: PathBuf,
    validation: PathBuf,
    watermark: PathBuf,
}

/// Consumes one admitted public bootstrap into the ordinary laboratory owner.
///
/// `authority_root` must be an existing, canonical, empty `0700` directory.
/// The function creates seven mutually disjoint `0700` namespaces below it.
/// `open_watermark` receives the sole permitted external-watermark record path
/// only after that namespace has been created.  Any partial failure leaves the
/// root non-empty, making all retries fail closed in this fresh-only tranche.
pub fn commission_deployed_lab_ordinary_runtime_v0<W, F, E>(
    authority_root: impl AsRef<Path>,
    core_config: CoreConfig,
    application_config: NativeApplicationConfigV0,
    bootstrap: PocoNodeDeployedLabBootstrapV0,
    open_watermark: F,
) -> Result<PocoNodeLabOrdinaryProposalRuntimeV0<W>, PocoNodeDeployedLabCommissioningErrorV0>
where
    W: ExternalMonotonicWatermarkV0,
    F: FnOnce(&Path) -> Result<W, E>,
    E: fmt::Debug,
{
    let paths = prepare_paths_v0(authority_root.as_ref())?;
    let watermark = deploy_try!("watermark.open", open_watermark(&paths.watermark));
    let limits = record_limits_v0()?;
    let chain_facts = application_config.chain_genesis_facts_v0();
    let application = initialize_native_application_v0(&paths.application, application_config)?;

    let projection_profile = hash_v0(
        PROJECTION_PROFILE_DOMAIN_V0,
        &[
            &chain_facts.chain_descriptor_hash_v0(),
            &chain_facts.signer_policy_commitment_v0(),
            &chain_facts.initial_commit_id_v0(),
        ],
    );
    let authenticated_parent = deploy_try!(
        "source.authenticated_parent",
        AuthenticatedGenesisApplicationParentV0::new(
            trnm_consensus_types::BlockId::new(chain_facts.initial_block_id_v0()),
            core_config.trusted_genesis_timestamp_ms(),
            0,
            StateRoot::new(chain_facts.initial_state_root_v0()),
            chain_facts.chain_descriptor_hash_v0(),
            projection_profile,
        )
    );
    let source_core_config = deploy_try!(
        "source.core_config",
        CoreConfig::new_with_authenticated_genesis_application_parent_v0(
            core_config.local_validator(),
            core_config.validator_set().clone(),
            *core_config.consensus_parameters(),
            core_config.trusted_genesis_timestamp_ms(),
            authenticated_parent,
            core_config.max_blocks(),
            core_config.max_observed_messages(),
        )
    );
    let genesis_qc = deploy_try!(
        "source.genesis_qc",
        GenesisQcV0::new(
            source_core_config.validator_set().genesis_hash(),
            source_core_config.validator_set().chain_id(),
            source_core_config.validator_set(),
        )
    );
    let prepared = deploy_try!(
        "source.prepare",
        Core::prepare_authenticated_genesis_application_bootstrap_v0(
            source_core_config.clone(),
            genesis_qc,
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            limits,
            &StrictEd25519Verifier,
        )
    );
    let source_profile = deploy_try!(
        "source.safety_profile",
        SafetyStateStoreProfileV0::new(
            source_core_config.clone(),
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            limits,
            MAXIMUM_SAFETY_DATABASE_BYTES_V0,
        )
    );
    let (mut source_safety_store, _) = deploy_try!(
        "source.safety_initialize",
        SqliteSafetyStateStoreV0::initialize_or_resume_authenticated_genesis_application_exact_v0(
            &paths.source_safety,
            source_profile,
            StrictEd25519Verifier,
            &prepared,
        )
    );
    let confirmed_source = deploy_try!(
        "source.safety_confirm",
        source_safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)
    );
    let activation = deploy_try!(
        "source.activate",
        Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
            source_core_config.clone(),
            prepared,
            &StrictEd25519Verifier,
        )
    );
    let mut source_owner = activation
        .activate_application_v0(ExactRegistrarV0)
        .unwrap_or_else(|never| match never {});
    let PocoNodeDeployedLabBootstrapV0 { h1, h2, h3, proof } = bootstrap;
    let obligation = deploy_try!(
        "source.h1_obligation",
        source_owner.submit_exact_h1_synced_proposal_v0(h1, &StrictEd25519Verifier)
    );
    let binding = deploy_try!(
        "source.safety_binding",
        source_owner.issue_safety_persistence_binding_v0()
    );
    deploy_try!(
        "source.safety_bind",
        source_safety_store
            .bind_authenticated_genesis_application_h1_offline_v0(confirmed_source, binding)
    );
    deploy_try!(
        "source.obligation_persist",
        source_safety_store
            .persist_authenticated_genesis_application_h1_obligation_exact_v0(&obligation)
    );
    let request = deploy_try!(
        "source.obligation_ack",
        source_owner.acknowledge_obligation_persisted_v0(
            &obligation,
            obligation.barrier_v0(),
            &StrictEd25519Verifier,
        )
    );
    let validation_id = request.validation_id_v0();
    let claimed = request.try_claim_v0().map_err(|_| {
        PocoNodeDeployedLabCommissioningErrorV0::message(
            "source.request_claim",
            "exact h1 request was already claimed",
        )
    })?;
    let (_route, _id, block, _parent, permit) = claimed.into_parts();
    let sealed = source_owner.seal_after_application_store_commit_v0(
        permit,
        h1_valid_commitments_v0(
            &block,
            source_core_config.validator_set(),
            source_core_config.consensus_parameters(),
        )?,
        h1_artifact_ref_v0(&block, &chain_facts.initial_commit_id_v0()),
    );
    let completion = deploy_try!(
        "source.valid_accept",
        source_owner.accept_application_sealed_valid_v0(&sealed, &StrictEd25519Verifier)
    );
    let [durable_completion] = completion
        .persistence_v0()
        .state()
        .payload_validation_completions()
    else {
        return Err(PocoNodeDeployedLabCommissioningErrorV0::message(
            "source.valid_completion",
            "source h1 completion is not unique",
        ));
    };
    let result_checksum =
        native_valid_result_checksum_v0(durable_completion.result()).ok_or_else(|| {
            PocoNodeDeployedLabCommissioningErrorV0::message(
                "source.valid_result_checksum",
                "canonical source h1 valid-result checksum is unavailable",
            )
        })?;
    let delivery_parts = (0_u8..7)
        .map(|index| {
            let validation_view = validation_id.view().get().to_be_bytes();
            let validation_generation = validation_id.generation().to_be_bytes();
            hash_v0(
                SOURCE_DELIVERY_DOMAIN_V0,
                &[
                    validation_id.block_id().as_bytes(),
                    &validation_view,
                    &validation_generation,
                    block.id().as_bytes(),
                    &chain_facts.initial_commit_id_v0(),
                    &[index],
                ],
            )
        })
        .collect::<Vec<_>>();
    let delivery = deploy_try!(
        "source.delivery_facts",
        ApplicationNativeValidDeliveryFactsV0::new(
            PayloadValidationRouteV0::Synced,
            validation_id,
            delivery_parts[0],
            delivery_parts[1],
            delivery_parts[2],
            result_checksum,
            delivery_parts[3],
            delivery_parts[4],
            1,
            delivery_parts[5],
            delivery_parts[6],
            NativeValidPostAckActionV0::None,
            2,
        )
    );
    let sealed_transition = deploy_try!(
        "source.delivery_seal",
        source_owner.seal_authenticated_genesis_h1_native_valid_transition_v0(completion, delivery)
    );
    let confirmed_native_valid = deploy_try!(
        "source.delivery_persist",
        source_safety_store
            .persist_authenticated_genesis_application_h1_native_valid_exact_v0(&sealed_transition)
    );
    if confirmed_native_valid.revision() != 2 {
        return Err(PocoNodeDeployedLabCommissioningErrorV0::message(
            "source.delivery_revision",
            "source h1 NativeValid did not persist at revision two",
        ));
    }
    drop(confirmed_native_valid);
    let completed = deploy_try!(
        "source.delivery_ack",
        source_owner.acknowledge_completion_persisted_v0(
            &sealed_transition,
            sealed_transition.completion_persistence_v0().barrier_v0(),
            &StrictEd25519Verifier,
        )
    );
    if completed.validation_id_v0() != validation_id {
        return Err(PocoNodeDeployedLabCommissioningErrorV0::message(
            "source.delivery_identity",
            "source h1 completion changed validation identity",
        ));
    }
    let candidate = deploy_try!(
        "source.retire",
        source_owner
            .retire_completed_into_h1_state_sync_promotion_v0(proof, &StrictEd25519Verifier,)
    );

    let signer_profile = deploy_try!(
        "target.signer_profile",
        SignerJournalProfileV0::new(
            source_core_config.validator_set().clone(),
            source_core_config.local_validator(),
            SIGNER_JOURNAL_PROFILE_REF_V0,
            derive_signer_watermark_scope_v0(&source_core_config),
            MAXIMUM_SIGNER_INTENTS_V0,
            MAXIMUM_SIGNER_INTENT_BYTES_V0,
            MAXIMUM_SIGNER_DATABASE_BYTES_V0,
        )
    );
    let pinned_signer = deploy_try!(
        "target.signer_initialize",
        SqliteSignerJournalV0::initialize_new(&paths.signer, signer_profile, watermark)
    );
    let pinned_signer = deploy_try!("target.signer_pin", pinned_signer.into_pinned_v0());
    let checkpoint_store = deploy_try!(
        "target.checkpoint_initialize",
        SqliteExternalNodeCheckpointStoreV0::initialize_new(&paths.checkpoint)
    );
    let source = PocoNodeNativeH1StateSyncPromotionSourceV0::from_completed_authorities_v0(
        candidate,
        source_safety_store,
        pinned_signer,
    );
    let commissioning_config = deploy_try!(
        "target.commissioning_config",
        PocoNodeNativeH1StateSyncCommissioningConfigV0::new(
            &paths.target_safety,
            limits,
            MAXIMUM_SAFETY_DATABASE_BYTES_V0,
            application,
            checkpoint_store,
        )
    );
    let commissioned = deploy_try!(
        "target.commission",
        source.commission_native_h1_state_sync_v0(commissioning_config)
    );

    let scope_bytes = hash_v0(
        PROPOSAL_SCOPE_DOMAIN_V0,
        &[
            source_core_config.validator_set().id().as_bytes(),
            source_core_config.local_validator().as_bytes(),
        ],
    );
    let owner_bytes = hash_v0(
        PROPOSAL_OWNER_DOMAIN_V0,
        &[
            &chain_facts.chain_descriptor_hash_v0(),
            source_core_config.local_validator().as_bytes(),
        ],
    );
    let validation_scope = deploy_try!(
        "takeover.validation_scope",
        ProposalValidationStoreScopeV0::new(scope_bytes)
    );
    let validation_owner = deploy_try!(
        "takeover.validation_owner",
        ProposalValidationOwnerIdV0::new(owner_bytes)
    );
    let validation_store = deploy_try!(
        "takeover.validation_open",
        SqliteProposalValidationStoreV0::open(&paths.validation, validation_scope, 0)
    );
    let proposal_journal = deploy_try!(
        "takeover.proposal_journal",
        PocoNodeLabProposalJournalConfigV0::new(paths.validation, scope_bytes, owner_bytes, 6,)
    );
    let runtime = deploy_try!(
        "takeover.facade",
        commissioned.complete_lab_ordinary_takeover_v0(
            h2,
            h3,
            validation_store,
            validation_owner,
            proposal_journal,
        )
    );
    if !runtime.matches_consensus_context_v0(
        source_core_config.local_validator(),
        source_core_config.validator_set(),
        source_core_config.consensus_parameters(),
    ) || runtime.facts_v0().proposal_parent_height_v0() != 3
        || runtime.facts_v0().application_applied_height_v0() != 1
    {
        return Err(PocoNodeDeployedLabCommissioningErrorV0::message(
            "takeover.final_join",
            "returned runtime differs from the exact h3/applied-h1 context",
        ));
    }
    Ok(runtime)
}

fn prepare_paths_v0(
    root: &Path,
) -> Result<AuthorityPathsV0, PocoNodeDeployedLabCommissioningErrorV0> {
    let metadata = deploy_try!("filesystem.root_metadata", fs::symlink_metadata(root));
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(PocoNodeDeployedLabCommissioningErrorV0::message(
            "filesystem.root",
            "authority root must be one existing non-symlink 0700 directory",
        ));
    }
    let root = deploy_try!("filesystem.root_canonicalize", root.canonicalize());
    let mut entries = deploy_try!("filesystem.root_inventory", fs::read_dir(&root));
    if entries.next().is_some() {
        return Err(PocoNodeDeployedLabCommissioningErrorV0::message(
            "filesystem.root_fresh",
            "fresh authority root is not empty",
        ));
    }

    let make = |namespace: &'static str, filename: &'static str| {
        let parent = root.join(namespace);
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&parent).map_err(|error| {
            PocoNodeDeployedLabCommissioningErrorV0::from_debug(
                "filesystem.namespace_create",
                (namespace, error),
            )
        })?;
        let metadata = fs::symlink_metadata(&parent).map_err(|error| {
            PocoNodeDeployedLabCommissioningErrorV0::from_debug(
                "filesystem.namespace_metadata",
                (namespace, error),
            )
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(PocoNodeDeployedLabCommissioningErrorV0::message(
                "filesystem.namespace_permissions",
                "new authority namespace is not exactly 0700",
            ));
        }
        Ok(parent.join(filename))
    };

    Ok(AuthorityPathsV0 {
        source_safety: make("source-safety", "safety.sqlite3")?,
        target_safety: make("target-safety", "safety.sqlite3")?,
        signer: make("signer", "signer.sqlite3")?,
        application: make("application", "application.sqlite3")?,
        checkpoint: make("checkpoint", "checkpoint.sqlite3")?,
        validation: make("validation", "validation.sqlite3")?,
        watermark: make("watermark", "signer-watermark.v1")?,
    })
}

fn record_limits_v0() -> Result<SafetyStateRecordLimitsV0, PocoNodeDeployedLabCommissioningErrorV0>
{
    SafetyStateRecordLimitsV0::new(MAXIMUM_RECORD_BYTES_V0, MAXIMUM_BLOB_BYTES_V0).map_err(
        |error| PocoNodeDeployedLabCommissioningErrorV0::from_debug("source.record_limits", error),
    )
}

fn h1_valid_commitments_v0(
    block: &Block,
    validator_set: &trnm_consensus_types::ValidatorSet,
    parameters: &trnm_consensus_types::ConsensusParametersV0,
) -> Result<
    trnm_consensus_types::ValidatedBlockCommitmentsV0,
    PocoNodeDeployedLabCommissioningErrorV0,
> {
    let payload = deploy_try!("source.h1_payload", ApplicationPayloadV0::new(Vec::new()));
    let receipts = deploy_try!(
        "source.h1_receipts",
        ExecutionReceiptsV0::new(&payload, Vec::new())
    );
    let body = deploy_try!("source.h1_body", BlockBodyV0::new(payload, Vec::new()));
    let commitments = deploy_try!(
        "source.h1_commitments",
        body.validate_ordinary_commitments(
            block.header(),
            &receipts,
            parameters,
            validator_set,
            &StrictEd25519Verifier,
        )
    );
    Ok(commitments)
}

fn h1_artifact_ref_v0(
    block: &Block,
    initial_commit_id: &[u8; 32],
) -> ValidatedPayloadArtifactRefV0 {
    ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(
            block.id(),
            block.header().parent_id(),
            hash_v0(
                SOURCE_ARTIFACT_DOMAIN_V0,
                &[b"overlay", block.id().as_bytes(), initial_commit_id],
            ),
        ),
        hash_v0(
            SOURCE_ARTIFACT_DOMAIN_V0,
            &[b"source", block.id().as_bytes(), initial_commit_id],
        ),
    )
}

fn initialize_native_application_v0(
    path: &Path,
    config: NativeApplicationConfigV0,
) -> Result<DurableNativeApplicationV0, PocoNodeDeployedLabCommissioningErrorV0> {
    let genesis_request = deploy_try!(
        "application.genesis_request",
        NativeApplicationGenesisRequestV0::new(
            deploy_try!("application.chain_id", ChainIdV0::new(config.chain_id_v0())),
            deploy_try!(
                "application.genesis_hash",
                GenesisHashV0::new(config.genesis_hash_v0())
            ),
            Hash32V0::new(config.chain_descriptor_hash_v0()),
            Hash32V0::new(config.signer_policy_commitment_v0()),
            deploy_try!(
                "application.initial_state_root",
                NativeStateRootV0::new(config.initial_state_root())
            ),
            config.initial_validator_set().clone(),
        )
    );
    let application = deploy_try!(
        "application.open",
        DurableNativeApplicationV0::open(path, config)
    );
    deploy_try!(
        "application.initialize",
        application.initialize(genesis_request)
    );
    Ok(application)
}

fn hash_v0(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}
