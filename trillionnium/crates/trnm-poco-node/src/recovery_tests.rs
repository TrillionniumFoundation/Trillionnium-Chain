use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;

use crate::external_node_checkpoint::{
    confirm_existing_node_checkpoint_candidate_v0, ExistingNodeCheckpointJoinErrorV0,
};
use trnm_consensus_app::{
    empty_native_application_trusted_base_root_for_recovery_test_v0,
    empty_state_sync_anchor_successor_commitments_for_recovery_test_v0,
    initialize_empty_native_application_test_fixture_v0,
    initialize_native_validation_recovery_test_fixture_v0, NativeConsensusApplicationHostConfigV0,
    NativeConsensusApplicationHostV0, NativeEmptyAnchorSuccessorCommitmentsV0,
    NativeValidationRecoveredInvalidCallbackFactsV0, NativeValidationRecoveredInvalidReasonV0,
    NativeValidationRecoveredInvalidStateV0, NativeValidationRecoveryStoreConfigV0,
    NativeValidationRecoveryStoreV0, NativeValidationRecoveryTestConfigBundleV0,
    NativeValidationRecoveryTestFixtureConfigV0, NativeValidationRecoveryTestFixtureErrorV0,
    NativeValidationRecoveryTestFixtureStateV0,
};
use trnm_consensus_core::{
    leader_for, AuthenticatedGenesisApplicationParentV0, BlockIdOverlayRefV0, Core,
    DurablePayloadValidationResultV1, Effect, Input, OutboundMessage, PayloadTerminalResult,
    PayloadValidationParentProvenanceV0, PayloadValidationRecoverySessionV0,
    PayloadValidationResult, PayloadValidationRouteV0, SafetyState, SafetyStatePersistenceV0,
    SignId, StateSyncAnchorSuccessorRecoveryChallengeV0,
    StateSyncAnchorSuccessorRecoveryReconcilerV0, ValidatedPayloadArtifactRefV0, ValidationId,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    native_valid_result_checksum_v0, NativeValidTransitionV0, SafetyStateStoreProfileV0,
    SafetyStoreErrorV0, SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
    NATIVE_VALID_POST_ACK_REQUEST_SIGNATURE_V0,
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, SignatureProducerErrorV0,
    SignatureProducerV0, SignatureRequestV0, SignerJournalProfileV0, SignerWatermarkV0,
    SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader,
    BlockId, BlockKind, CanonicalSignIntentV0, CertifiedHeaderV0, ChainId, ConsensusParametersV0,
    ConsensusPublicKey, Epoch, ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, FinalityProofV0,
    GenesisHash, GenesisQcV0, Height, ProposalWitnessV0, ProtocolVersion, QcReferenceV0,
    QuorumCertificate, SignatureBytes, SignedProposalV0, SigningRoot, StateRoot,
    ValidatedBlockCommitmentsV0, Validator, ValidatorId, ValidatorSet, View, Vote, VotingPower,
};

use super::*;

const TEST_CHAIN: ChainId = ChainId::from_static("trnm-poco-node-g1c-test");
const GENESIS_TIMESTAMP_MS: u64 = 0;
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_SAFETY_DATABASE_BYTES: usize = 192 * 1024 * 1024;
const MAXIMUM_SIGNER_INTENTS: u64 = 64;
const MAXIMUM_SIGNER_INTENT_BYTES: usize = 4096;
const MAXIMUM_SIGNER_DATABASE_BYTES: usize = 32 * 1024 * 1024;
const SIGNER_POLICY_HASH: [u8; 32] = [0x77; 32];

#[derive(Debug, Clone, Default)]
struct MemoryWatermark {
    value: Arc<Mutex<Option<SignerWatermarkV0>>>,
    load_calls: Arc<AtomicUsize>,
    compare_calls: Arc<AtomicUsize>,
    fail_target_sequence_once: Arc<Mutex<Option<u64>>>,
}

impl MemoryWatermark {
    fn load_call_count(&self) -> usize {
        self.load_calls.load(Ordering::SeqCst)
    }

    fn compare_call_count(&self) -> usize {
        self.compare_calls.load(Ordering::SeqCst)
    }

    fn fail_target_sequence_once(&self, sequence: u64) {
        *self
            .fail_target_sequence_once
            .lock()
            .expect("test watermark failure lock") = Some(sequence);
    }
}

impl ExternalMonotonicWatermarkV0 for MemoryWatermark {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        self.load_calls.fetch_add(1, Ordering::SeqCst);
        let value = *self.value.lock().expect("test watermark lock");
        if value.is_some_and(|watermark| watermark.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(value)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        self.compare_calls.fetch_add(1, Ordering::SeqCst);
        let mut fail_target = self
            .fail_target_sequence_once
            .lock()
            .expect("test watermark failure lock");
        if *fail_target == Some(target.sequence()) {
            *fail_target = None;
            return Err(ExternalWatermarkErrorV0::Unavailable);
        }
        drop(fail_target);
        let mut value = self.value.lock().expect("test watermark lock");
        if *value != expected {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        match expected {
            None if target.sequence() == 0 => {}
            Some(source)
                if source.scope() == target.scope()
                    && source.journal_id() == target.journal_id()
                    && source.sequence().checked_add(1) == Some(target.sequence()) => {}
            _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
        }
        *value = Some(target);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct UnavailableProducerV0;

impl SignatureProducerV0 for UnavailableProducerV0 {
    fn sign(
        &mut self,
        _request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        Err(SignatureProducerErrorV0::Unavailable)
    }
}

struct FixtureSigningProducerV0(SigningKey);

impl SignatureProducerV0 for FixtureSigningProducerV0 {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        Ok(SignatureBytes::from_array(
            self.0.sign(request.signing_root().as_bytes()).to_bytes(),
        ))
    }
}

struct StrictConsensusFixtureV0 {
    keys: Vec<(ValidatorId, SigningKey)>,
    parameters: ConsensusParametersV0,
    validator_set: ValidatorSet,
    core_config: CoreConfig,
}

impl StrictConsensusFixtureV0 {
    fn new() -> Self {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let keys = (1_u8..=4)
            .map(|index| {
                (
                    ValidatorId::new([index; 32]),
                    SigningKey::from_bytes(&[index.saturating_add(40); 32]),
                )
            })
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .map(|(id, key)| {
                Validator::new(
                    *id,
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).expect("positive test voting power"),
                )
                .expect("valid strict-Ed25519 test validator")
            })
            .collect();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            TEST_CHAIN,
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid strict-Ed25519 validator set");
        let core_config = CoreConfig::new(
            keys[0].0,
            validator_set.clone(),
            parameters,
            GENESIS_TIMESTAMP_MS,
            32,
            64,
        )
        .expect("valid strict-Ed25519 Core config");
        Self {
            keys,
            parameters,
            validator_set,
            core_config,
        }
    }

    fn key(&self, author: ValidatorId) -> &SigningKey {
        self.keys
            .iter()
            .find_map(|(id, key)| (*id == author).then_some(key))
            .expect("validator has a fixture signing key")
    }

    fn genesis_qc(&self) -> GenesisQcV0 {
        GenesisQcV0::new(
            self.validator_set.genesis_hash(),
            self.validator_set.chain_id(),
            &self.validator_set,
        )
        .expect("valid genesis anchor")
    }

    fn sign(&self, author: ValidatorId, root: SigningRoot) -> SignatureBytes {
        SignatureBytes::from_array(self.key(author).sign(root.as_bytes()).to_bytes())
    }

    fn proposal(&self, justify: QcReferenceV0, view: u64, payload: &[u8]) -> SignedProposalV0 {
        let height = justify
            .qc_ref()
            .height()
            .get()
            .checked_add(1)
            .expect("test height does not overflow");
        self.proposal_with_state_root(justify, view, payload, StateRoot::new([height as u8; 32]))
    }

    fn proposal_with_state_root(
        &self,
        justify: QcReferenceV0,
        view: u64,
        payload: &[u8],
        state_root: StateRoot,
    ) -> SignedProposalV0 {
        let justify_ref = justify.qc_ref();
        let height = justify_ref
            .height()
            .get()
            .checked_add(1)
            .expect("test height does not overflow");
        let proposer = leader_for(&self.validator_set, View::new(view));
        let block = canonical_block_with_state_root_v0(
            &self.validator_set,
            view,
            height,
            justify_ref.block_id(),
            payload,
            proposer,
            state_root,
        );
        let root = ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
            .expect("valid proposal signing preimage");
        let witness = ProposalWitnessV0::new(
            block.header(),
            justify,
            None,
            None,
            self.sign(proposer, root),
            &self.validator_set,
            None,
            &self.parameters,
            justify_ref.height().get().saturating_mul(100),
        )
        .expect("valid strict-Ed25519 proposal witness");
        SignedProposalV0::new(
            block,
            witness,
            &self.validator_set,
            None,
            &self.parameters,
            justify_ref.height().get().saturating_mul(100),
        )
        .expect("valid strict-Ed25519 proposal")
    }

    fn empty_proposal_with_state_root(
        &self,
        justify: QcReferenceV0,
        view: u64,
        state_root: StateRoot,
    ) -> SignedProposalV0 {
        let justify_ref = justify.qc_ref();
        let height = justify_ref
            .height()
            .get()
            .checked_add(1)
            .expect("test height does not overflow");
        let proposer = leader_for(&self.validator_set, View::new(view));
        let block = canonical_block_with_transactions_and_state_root_v0(
            &self.validator_set,
            view,
            height,
            justify_ref.block_id(),
            Vec::new(),
            proposer,
            state_root,
        );
        let root = ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
            .expect("valid empty proposal signing preimage");
        let witness = ProposalWitnessV0::new(
            block.header(),
            justify,
            None,
            None,
            self.sign(proposer, root),
            &self.validator_set,
            None,
            &self.parameters,
            justify_ref.height().get().saturating_mul(100),
        )
        .expect("valid strict-Ed25519 empty proposal witness");
        SignedProposalV0::new(
            block,
            witness,
            &self.validator_set,
            None,
            &self.parameters,
            justify_ref.height().get().saturating_mul(100),
        )
        .expect("valid strict-Ed25519 empty proposal")
    }

    fn parent_qc(&self, parent: &SignedProposalV0) -> QuorumCertificate {
        let header = parent.block().header();
        let votes = self
            .keys
            .iter()
            .take(3)
            .map(|(author, _)| {
                let root = Vote::signing_root_for_set(
                    &self.validator_set,
                    header.view(),
                    header.height(),
                    parent.block().id(),
                )
                .expect("valid vote signing preimage");
                Vote::new(
                    self.validator_set.chain_id(),
                    self.validator_set.protocol_version(),
                    self.validator_set.epoch(),
                    header.view(),
                    header.height(),
                    parent.block().id(),
                    self.validator_set.id(),
                    *author,
                    self.sign(*author, root),
                    &self.validator_set,
                )
                .expect("valid strict-Ed25519 vote")
            })
            .collect();
        QuorumCertificate::new(
            self.validator_set.chain_id(),
            self.validator_set.protocol_version(),
            self.validator_set.epoch(),
            header.view(),
            header.height(),
            parent.block().id(),
            self.validator_set.id(),
            votes,
            &self.validator_set,
        )
        .expect("valid strict-Ed25519 parent QC")
    }
}

fn h1_state_sync_proof_v0(
    fixture: &StrictConsensusFixtureV0,
    h1_state_root: StateRoot,
    successors: NativeEmptyAnchorSuccessorCommitmentsV0,
) -> (
    FinalityProofV0,
    SignedProposalV0,
    SignedProposalV0,
    SignedProposalV0,
) {
    let h1 = fixture.empty_proposal_with_state_root(
        QcReferenceV0::genesis_anchor(fixture.genesis_qc()),
        1,
        h1_state_root,
    );
    let q1 = fixture.parent_qc(&h1);
    let h2 = fixture.empty_proposal_with_state_root(
        QcReferenceV0::ordinary(q1.clone()),
        2,
        StateRoot::new(successors.h2_state_root()),
    );
    assert_eq!(
        h2.block().header().receipts_root().as_bytes(),
        &successors.h2_receipts_root(),
    );
    let q2 = fixture.parent_qc(&h2);
    let h3 = fixture.empty_proposal_with_state_root(
        QcReferenceV0::ordinary(q2.clone()),
        3,
        StateRoot::new(successors.h3_state_root()),
    );
    assert_eq!(
        h3.block().header().receipts_root().as_bytes(),
        &successors.h3_receipts_root(),
    );
    let q3 = fixture.parent_qc(&h3);
    let certified_h1 = CertifiedHeaderV0::from_signed_proposal(
        h1.clone(),
        q1,
        &fixture.validator_set,
        None,
        &fixture.parameters,
        GENESIS_TIMESTAMP_MS,
    )
    .expect("strict Ed25519 h1 certificate");
    let certified_h2 = CertifiedHeaderV0::from_signed_proposal(
        h2.clone(),
        q2,
        &fixture.validator_set,
        None,
        &fixture.parameters,
        h1.block().header().timestamp_ms(),
    )
    .expect("strict Ed25519 h2 certificate");
    let certified_h3 = CertifiedHeaderV0::from_signed_proposal(
        h3.clone(),
        q3,
        &fixture.validator_set,
        None,
        &fixture.parameters,
        h2.block().header().timestamp_ms(),
    )
    .expect("strict Ed25519 h3 certificate");
    let proof = FinalityProofV0::new(
        certified_h1,
        certified_h2,
        certified_h3,
        &fixture.validator_set,
        None,
        &fixture.parameters,
        GENESIS_TIMESTAMP_MS,
    )
    .expect("strict Ed25519 genesis-anchored h1 finality proof");
    (proof, h1, h2, h3)
}

fn canonical_block_with_state_root_v0(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    parent: BlockId,
    payload: &[u8],
    proposer: ValidatorId,
    state_root: StateRoot,
) -> Block {
    canonical_block_with_transactions_and_state_root_v0(
        set,
        view,
        height,
        parent,
        vec![payload.to_vec()],
        proposer,
        state_root,
    )
}

fn canonical_block_with_transactions_and_state_root_v0(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    parent: BlockId,
    transactions: Vec<Vec<u8>>,
    proposer: ValidatorId,
    state_root: StateRoot,
) -> Block {
    let application_payload =
        ApplicationPayloadV0::new(transactions).expect("canonical test payload");
    let receipts = ExecutionReceiptsV0::new(
        &application_payload,
        (0..application_payload.transaction_count())
            .map(|index| {
                ExecutionReceiptCommitmentV0::for_transaction(
                    &application_payload,
                    index,
                    0,
                    0,
                    Vec::new(),
                )
                .expect("canonical test receipt")
            })
            .collect(),
    )
    .expect("canonical test receipts");
    let body = BlockBodyV0::new(application_payload, Vec::new()).expect("canonical test body");
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        BlockKind::Regular,
        parent,
        proposer,
        set.id(),
        set.consensus_parameters_hash(),
        body.payload_root().expect("canonical payload root"),
        state_root,
        receipts.receipts_root().expect("canonical receipts root"),
        body.evidence_root().expect("canonical evidence root"),
        height.saturating_mul(100),
        None,
    )
    .expect("valid strict-Ed25519 test header");
    Block::new(
        header,
        body.application_payload()
            .try_cev0_bytes()
            .expect("canonical application payload bytes"),
        Vec::new(),
    )
    .expect("body matches strict-Ed25519 test header")
}

fn valid_commitments_v0(core: &Core, block: &Block) -> ValidatedBlockCommitmentsV0 {
    let application_payload = decode_application_payload_v0_exact(
        block.application_payload(),
        core.config().consensus_parameters(),
    )
    .expect("decode canonical application payload");
    let receipts = ExecutionReceiptsV0::new(
        &application_payload,
        (0..application_payload.transaction_count())
            .map(|index| {
                ExecutionReceiptCommitmentV0::for_transaction(
                    &application_payload,
                    index,
                    0,
                    0,
                    Vec::new(),
                )
                .expect("canonical test receipt")
            })
            .collect(),
    )
    .expect("canonical test receipts");
    let body = BlockBodyV0::new(application_payload, Vec::new()).expect("canonical test body");
    body.validate_ordinary_commitments(
        block.header(),
        &receipts,
        core.config().consensus_parameters(),
        core.config().validator_set(),
        &StrictEd25519Verifier,
    )
    .expect("strict verifier validates canonical commitments")
}

fn fixture_artifact_ref_v0(block: &Block) -> ValidatedPayloadArtifactRefV0 {
    let block_id = block.id();
    let mut overlay_checksum = *block_id.as_bytes();
    overlay_checksum[0] ^= 0x5a;
    let mut source_artifact_checksum = *block_id.as_bytes();
    source_artifact_checksum[0] ^= 0xa5;
    ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(block_id, block.header().parent_id(), overlay_checksum),
        source_artifact_checksum,
    )
}

fn protected_temp_dir_v0() -> TempDir {
    let directory = TempDir::new().expect("temporary recovery root");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("protect temporary recovery root");
    directory
}

fn protected_namespace_v0(root: &TempDir, name: &str) -> PathBuf {
    let namespace = root.path().join(name);
    fs::create_dir(&namespace).expect("create isolated recovery namespace");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700))
        .expect("protect isolated recovery namespace");
    namespace
}

fn assert_store_parent_empty_v0(path: &Path, context: &str) {
    let parent = path.parent().expect("store path retains its parent");
    let entries = fs::read_dir(parent)
        .expect("read protected store parent")
        .map(|entry| {
            entry
                .expect("read protected store-parent entry")
                .file_name()
        })
        .collect::<Vec<_>>();
    assert!(
        entries.is_empty(),
        "{context} must leave the complete store parent empty: {entries:?}"
    );
}

fn node_start_config_v0(
    safety_path: &Path,
    signer_path: &Path,
    core_config: CoreConfig,
) -> PocoNodeStartConfigV0 {
    PocoNodeStartConfigV0::new(
        safety_path,
        signer_path,
        core_config,
        SafetyStateRecordLimitsV0::new(MAXIMUM_RECORD_BYTES, MAXIMUM_BLOB_BYTES)
            .expect("valid test record bounds"),
        MAXIMUM_SAFETY_DATABASE_BYTES,
        MAXIMUM_SIGNER_INTENTS,
        MAXIMUM_SIGNER_INTENT_BYTES,
        MAXIMUM_SIGNER_DATABASE_BYTES,
    )
    .expect("valid recovery node start config")
}

fn authenticated_genesis_core_config_v0(fixture: &StrictConsensusFixtureV0) -> CoreConfig {
    let parent = AuthenticatedGenesisApplicationParentV0::new(
        fixture.core_config.genesis_block_id(),
        fixture.core_config.trusted_genesis_timestamp_ms(),
        0,
        StateRoot::new([0x31; 32]),
        [0x41; 32],
        [0x51; 32],
    )
    .expect("shape-valid authenticated genesis application parent");
    CoreConfig::new_with_authenticated_genesis_application_parent_v0(
        fixture.core_config.local_validator(),
        fixture.validator_set.clone(),
        fixture.parameters,
        fixture.core_config.trusted_genesis_timestamp_ms(),
        parent,
        fixture.core_config.max_blocks(),
        fixture.core_config.max_observed_messages(),
    )
    .expect("shadow authenticated-genesis Core config")
}

fn unchecked_node_start_config_v0(
    safety_path: &Path,
    signer_path: &Path,
    core_config: CoreConfig,
) -> PocoNodeStartConfigV0 {
    let signer_journal_profile = SignerJournalProfileV0::new(
        core_config.validator_set().clone(),
        core_config.local_validator(),
        SIGNER_JOURNAL_PROFILE_REF_V0,
        derive_signer_watermark_scope_v0(&core_config),
        MAXIMUM_SIGNER_INTENTS,
        MAXIMUM_SIGNER_INTENT_BYTES,
        MAXIMUM_SIGNER_DATABASE_BYTES,
    )
    .expect("construct test-only signer profile before the process fence");
    let safety_store_profile = SafetyStateStoreProfileV0::new(
        core_config,
        STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
        SafetyStateRecordLimitsV0::new(MAXIMUM_RECORD_BYTES, MAXIMUM_BLOB_BYTES)
            .expect("valid test record bounds"),
        MAXIMUM_SAFETY_DATABASE_BYTES,
    )
    .expect("construct test-only Safety profile before the process fence");
    PocoNodeStartConfigV0 {
        safety_store_path: safety_path.to_path_buf(),
        safety_store_profile,
        signer_journal_path: signer_path.to_path_buf(),
        signer_journal_profile,
    }
}

#[test]
fn process_config_and_open_surfaces_table_fence_authenticated_genesis_before_every_owner_v0() {
    #[derive(Clone, Copy, Debug)]
    enum Surface {
        Ordinary,
        AnchorSuccessor,
    }

    let root = protected_temp_dir_v0();
    let safety_path = protected_namespace_v0(&root, "genesis-fence-safety").join("safety.sqlite3");
    let signer_path = protected_namespace_v0(&root, "genesis-fence-signer").join("signer.sqlite3");
    let application_path =
        protected_namespace_v0(&root, "genesis-fence-application").join("state.json");
    let fixture = StrictConsensusFixtureV0::new();
    let core_config = authenticated_genesis_core_config_v0(&fixture);
    let child = fixture.proposal(QcReferenceV0::genesis_anchor(fixture.genesis_qc()), 1, &[]);
    let grandchild = fixture.proposal(QcReferenceV0::ordinary(fixture.parent_qc(&child)), 2, &[]);
    let mut application = NativeValidationRecoveryTestConfigBundleV0::new(
        &application_path,
        TEST_CHAIN,
        [0; 32],
        [0; 32],
    )
    .expect("construct a complete application config before corrupting its schema")
    .application_config_v0();
    application.schema = "intentionally-invalid-before-process-fence".to_owned();

    let config_error = PocoNodeProcessConfigV0::new(
        unchecked_node_start_config_v0(&safety_path, &signer_path, core_config.clone()),
        application.clone(),
    )
    .expect_err("process config must fence before application validation");
    assert!(matches!(
        config_error,
        PocoNodeProcessHostErrorV0::AuthenticatedGenesisCommissioningRequiresDedicatedHost
    ));
    assert!(!safety_path.exists());
    assert!(!signer_path.exists());
    assert!(!application_path.exists());
    assert_store_parent_empty_v0(&safety_path, "process-config Safety fence");
    assert_store_parent_empty_v0(&signer_path, "process-config signer fence");
    assert_store_parent_empty_v0(&application_path, "process-config application fence");

    for surface in [Surface::Ordinary, Surface::AnchorSuccessor] {
        let watermark = MemoryWatermark::default();
        let config = PocoNodeProcessConfigV0::new_for_authenticated_genesis_fence_test_v0(
            unchecked_node_start_config_v0(&safety_path, &signer_path, core_config.clone()),
            application.clone(),
        );
        let error = match surface {
            Surface::Ordinary => PocoNodeProcessHostV0::open_existing_v0(config, watermark.clone())
                .expect_err("ordinary process open must fence authenticated genesis"),
            Surface::AnchorSuccessor => {
                PocoNodeProcessHostV0::open_existing_state_sync_anchor_successors_v0(
                    config,
                    watermark.clone(),
                    child.clone(),
                    grandchild.clone(),
                )
                .expect_err("anchor-successor process open must fence authenticated genesis")
            }
        };
        assert!(matches!(
            error,
            PocoNodeProcessHostErrorV0::AuthenticatedGenesisCommissioningRequiresDedicatedHost
        ));
        assert_eq!(
            watermark.load_call_count(),
            0,
            "{surface:?} must reject before external watermark load",
        );
        assert_eq!(
            watermark.compare_call_count(),
            0,
            "{surface:?} must reject before external watermark CAS",
        );
        assert!(
            !safety_path.exists(),
            "{surface:?} must reject before SafetyStore open",
        );
        assert!(
            !signer_path.exists(),
            "{surface:?} must reject before signer open",
        );
        assert!(
            !application_path.exists(),
            "{surface:?} must reject before ApplicationStore open",
        );
        assert_store_parent_empty_v0(&safety_path, "process-open Safety fence");
        assert_store_parent_empty_v0(&signer_path, "process-open signer fence");
        assert_store_parent_empty_v0(&application_path, "process-open application fence");
    }
}

#[test]
#[cfg(feature = "recovery-process-test-support")]
fn validation_recovery_observer_open_fences_authenticated_genesis_before_every_owner_v0() {
    let root = protected_temp_dir_v0();
    let safety_path = protected_namespace_v0(&root, "observer-fence-safety").join("safety.sqlite3");
    let signer_path = protected_namespace_v0(&root, "observer-fence-signer").join("signer.sqlite3");
    let application_path =
        protected_namespace_v0(&root, "observer-fence-application").join("state.json");
    let fixture = StrictConsensusFixtureV0::new();
    let watermark = MemoryWatermark::default();
    let observer_calls = Arc::new(AtomicUsize::new(0));
    let observed = observer_calls.clone();
    let error =
        PocoNodeValidationRecoveryHostV0::open_existing_with_process_checkpoint_observer_v0(
            PocoNodeValidationRecoveryConfigV0 {
                node: unchecked_node_start_config_v0(
                    &safety_path,
                    &signer_path,
                    authenticated_genesis_core_config_v0(&fixture),
                ),
                application_status_path: application_path.clone(),
                signer_policy_hash: SIGNER_POLICY_HASH,
            },
            watermark.clone(),
            move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
            },
        )
        .err()
        .expect("observer recovery open must fence authenticated genesis");
    assert!(matches!(
        error,
        PocoNodeHostErrorV0::AuthenticatedGenesisCommissioningRequiresDedicatedHost
    ));
    assert_eq!(observer_calls.load(Ordering::SeqCst), 0);
    assert_eq!(watermark.load_call_count(), 0);
    assert_eq!(watermark.compare_call_count(), 0);
    assert!(!safety_path.exists());
    assert!(!signer_path.exists());
    assert!(!application_path.exists());
    assert_store_parent_empty_v0(&safety_path, "observer Safety fence");
    assert_store_parent_empty_v0(&signer_path, "observer signer fence");
    assert_store_parent_empty_v0(&application_path, "observer application fence");
}

fn persist_and_ack_v0(
    core: &mut Core,
    store: &mut SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    effects: Vec<Effect>,
) -> Vec<Effect> {
    let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
        panic!("expected one exact Core persistence request: {effects:?}");
    };
    let barrier = request.barrier();
    let context = request
        .state()
        .payload_validation_completions()
        .iter()
        .find(|completion| {
            completion.first_recorded_revision() == request.state().revision()
                && completion.result().is_valid()
        })
        .map(|completion| {
            SafetyTransitionContextV0::native_valid(
                NativeValidTransitionV0::new(
                    completion.route(),
                    completion.id(),
                    [0x31; 32],
                    [0x32; 32],
                    [0x33; 32],
                    native_valid_result_checksum_v0(completion.result())
                        .expect("derive fixture Valid result checksum"),
                    [0x34; 32],
                    [0x35; 32],
                    1,
                    [0x36; 32],
                    [0x37; 32],
                    NATIVE_VALID_POST_ACK_REQUEST_SIGNATURE_V0,
                    request.state().revision(),
                )
                .expect("construct fixture NativeValid transition context"),
            )
        })
        .unwrap_or_else(SafetyTransitionContextV0::ordinary);
    store
        .persist_exact_v0(request, &context)
        .expect("persist exact Core request in the real SafetyStore");
    let head = store.head().expect("authenticate exact persisted head");
    assert_eq!(head.state(), request.state());
    assert_eq!(head.transition_context(), &context);
    core.step(Input::StorageAck { barrier }, &StrictEd25519Verifier)
        .expect("ack only the exact durable Core request")
}

fn create_obligation_head_v0(
    fixture: &StrictConsensusFixtureV0,
    route: PayloadValidationRouteV0,
    start: &PocoNodeStartConfigV0,
    watermark: MemoryWatermark,
    model_only_speculative_parent: bool,
    application_status: Option<&Path>,
) -> (
    Core,
    SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    SqliteSignerJournalV0<MemoryWatermark>,
) {
    let verifier = StrictEd25519Verifier;
    let mut core = Core::new(fixture.core_config.clone(), fixture.genesis_qc(), &verifier)
        .expect("initialize strict-Ed25519 Core");
    let application_seal_authority = core
        .issue_application_seal_authority_v0()
        .expect("issue the fixture Core application seal authority exactly once");
    let mut safety_store = SqliteSafetyStateStoreV0::initialize_new(
        start.safety_store_path.clone(),
        start.safety_store_profile.clone(),
        verifier,
        core.safety_state(),
    )
    .expect("initialize real SafetyStore");
    safety_store
        .bind_core_v0(core.safety_state_persistence_binding_v0())
        .expect("bind SafetyStore to the exact fixture Core");
    let mut signer_journal = SqliteSignerJournalV0::initialize_new(
        start.signer_journal_path.clone(),
        start.signer_journal_profile.clone(),
        watermark,
    )
    .expect("initialize real signer journal");
    let _ = application_status;

    let target = if model_only_speculative_parent {
        let parent = fixture.proposal(
            QcReferenceV0::genesis_anchor(fixture.genesis_qc()),
            1,
            b"strict parent",
        );
        let effects = core
            .step(
                Input::Proposal(Box::new(parent.clone())),
                &StrictEd25519Verifier,
            )
            .expect("register parent validation obligation");
        let released = persist_and_ack_v0(&mut core, &mut safety_store, effects);
        let parent_request = match released.as_slice() {
            [Effect::ArmViewTimer { .. }, Effect::ValidatePayload(request)] => request.clone(),
            _ => panic!("parent persistence did not release exact validation: {released:?}"),
        };
        let (_, _, _, _, parent_valid_permit) = parent_request
            .try_claim()
            .expect("claim the exact parent validation request")
            .into_parts();
        let commitments = valid_commitments_v0(&core, parent.block());
        let artifact_ref = fixture_artifact_ref_v0(parent.block());
        let application_proof = application_seal_authority.seal_after_application_store_commit_v0(
            parent_valid_permit,
            commitments,
            artifact_ref,
        );
        let effects = core
            .step_application_sealed_valid_v0(&application_proof, &StrictEd25519Verifier)
            .expect("accept model-only valid parent payload");
        let released = persist_and_ack_v0(&mut core, &mut safety_store, effects);
        let intent = match released.as_slice() {
            [Effect::RequestSignature { intent }] => intent,
            _ => panic!("parent validation did not release vote intent: {released:?}"),
        };
        let signing_root = intent.signing_root();
        let mut producer = FixtureSigningProducerV0(SigningKey::from_bytes(
            &fixture
                .key(fixture.core_config.local_validator())
                .to_bytes(),
        ));
        let local_signature = signer_journal
            .sign_exact_v0(intent, &mut producer)
            .expect("journal and sign exact fixture vote");
        let broadcast = core
            .step(
                Input::SignatureReady {
                    id: SignId::new(signing_root),
                    signature: local_signature,
                },
                &StrictEd25519Verifier,
            )
            .expect("strictly verify local vote signature");
        assert!(matches!(
            broadcast.as_slice(),
            [Effect::Broadcast(OutboundMessage::Vote(_))]
        ));

        let parent_qc = fixture.parent_qc(&parent);
        let effects = core
            .step(
                Input::QuorumCertificate(parent_qc.clone()),
                &StrictEd25519Verifier,
            )
            .expect("strictly verify and persist parent QC");
        let released = persist_and_ack_v0(&mut core, &mut safety_store, effects);
        assert!(matches!(released.as_slice(), [Effect::ArmViewTimer { .. }]));
        fixture.proposal(
            QcReferenceV0::ordinary(parent_qc),
            2,
            b"strict invalid target",
        )
    } else {
        // The positive invalid-recovery matrix starts at the exact synthetic
        // genesis parent understood by both Core and an empty AppStore. It
        // must not depend on a model-only speculative Valid parent that the
        // application never durably executed.
        fixture.proposal(
            QcReferenceV0::genesis_anchor(fixture.genesis_qc()),
            1,
            b"strict invalid target",
        )
    };
    let input = match route {
        PayloadValidationRouteV0::Proposal => Input::Proposal(Box::new(target.clone())),
        PayloadValidationRouteV0::Synced => Input::SyncedProposal(Box::new(target.clone())),
    };
    let target_effects = core
        .step(input, &StrictEd25519Verifier)
        .expect("register target validation obligation");
    let released = persist_and_ack_v0(&mut core, &mut safety_store, target_effects);
    match (route, released.as_slice()) {
        (
            PayloadValidationRouteV0::Proposal,
            [Effect::ArmViewTimer { .. }, Effect::ValidatePayload(_)],
        )
        | (PayloadValidationRouteV0::Synced, [Effect::ValidateSyncedPayload(_)]) => {}
        _ => panic!("target persistence did not release exact validation: {released:?}"),
    }
    let head = safety_store.head().expect("authenticate obligation head");
    let [obligation] = head.state().payload_validation_obligations() else {
        panic!("target must leave exactly one durable obligation");
    };
    assert_eq!(obligation.route(), route);
    assert_eq!(obligation.proposal(), &target);
    (core, safety_store, signer_journal)
}

struct PendingRecoveryCaseV0 {
    _root: TempDir,
    start: PocoNodeStartConfigV0,
    watermark: MemoryWatermark,
    application_status: PathBuf,
    original_core: Core,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    signer_journal: SqliteSignerJournalV0<MemoryWatermark>,
    recovery_session: PayloadValidationRecoverySessionV0,
    validation_id: ValidationId,
    obligation_revision: u64,
}

fn prepare_pending_recovery_case_v0(
    route: PayloadValidationRouteV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
) -> PendingRecoveryCaseV0 {
    let root = protected_temp_dir_v0();
    let safety_path = protected_namespace_v0(&root, "safety").join("safety.sqlite3");
    let signer_path = protected_namespace_v0(&root, "signer").join("signer.sqlite3");
    let application_status = protected_namespace_v0(&root, "application").join("state.json");
    let fixture = StrictConsensusFixtureV0::new();
    let start = node_start_config_v0(&safety_path, &signer_path, fixture.core_config.clone());
    let watermark = MemoryWatermark::default();
    let (original_core, safety_store, signer_journal) = create_obligation_head_v0(
        &fixture,
        route,
        &start,
        watermark.clone(),
        false,
        Some(&application_status),
    );
    assert_eq!(
        watermark.compare_call_count(),
        1,
        "genesis-parent recovery fixture only initializes the external signer watermark"
    );
    let head = safety_store.head().expect("read exact obligation head");
    let obligation_revision = head.revision();
    let recovery_session = Core::begin_payload_validation_obligation_recovery_v0(
        fixture.core_config,
        head.state().clone(),
        &StrictEd25519Verifier,
    )
    .expect("construct authentic Core recovery challenge");
    let application_fixture = NativeValidationRecoveryTestFixtureConfigV0::new(
        &application_status,
        TEST_CHAIN,
        SIGNER_POLICY_HASH,
        safety_store.journal_id_v0(),
        safety_store.verifier_profile_ref_v0(),
    )
    .expect("valid application recovery fixture config");
    let pending = initialize_native_validation_recovery_test_fixture_v0(
        &application_fixture,
        recovery_session.challenge(),
        reason,
    )
    .expect("create real CallbackPending application row");
    assert_eq!(
        pending.state(),
        NativeValidationRecoveryTestFixtureStateV0::CallbackPending
    );
    assert_eq!(pending.route(), route);
    assert_eq!(pending.reason(), reason);
    let validation_id = pending.validation_id();
    assert_eq!(validation_id, recovery_session.challenge().id());

    PendingRecoveryCaseV0 {
        _root: root,
        start,
        watermark,
        application_status,
        original_core,
        safety_store,
        signer_journal,
        recovery_session,
        validation_id,
        obligation_revision,
    }
}

fn application_recovery_config_v0(
    status_path: &Path,
    safety_store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
) -> NativeValidationRecoveryStoreConfigV0 {
    NativeValidationRecoveryStoreConfigV0::new(
        status_path.to_path_buf(),
        TEST_CHAIN,
        SIGNER_POLICY_HASH,
        safety_store.journal_id_v0(),
        safety_store.verifier_profile_ref_v0(),
    )
}

fn exact_invalid_input_v0(route: PayloadValidationRouteV0, id: ValidationId) -> Input {
    match route {
        PayloadValidationRouteV0::Proposal => Input::PayloadValidated {
            id,
            result: PayloadValidationResult::DeterministicallyInvalid,
        },
        PayloadValidationRouteV0::Synced => Input::SyncedPayloadValidated {
            id,
            result: PayloadValidationResult::DeterministicallyInvalid,
        },
    }
}

fn assert_exact_invalid_completion_v0(
    state: &SafetyState,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    obligation_revision: u64,
) {
    assert_eq!(
        state.revision(),
        obligation_revision
            .checked_add(1)
            .expect("test obligation revision does not overflow")
    );
    assert!(state.payload_validation_obligations().is_empty());
    let matching = state
        .payload_validation_completions()
        .iter()
        .filter(|completion| completion.route() == route && completion.id() == validation_id)
        .collect::<Vec<_>>();
    let [completion] = matching.as_slice() else {
        panic!("expected exactly one matching completion tombstone: {matching:?}");
    };
    assert_eq!(
        completion.result(),
        DurablePayloadValidationResultV1::DeterministicallyInvalid
    );
    assert_eq!(completion.first_recorded_revision(), state.revision());
    assert_eq!(
        state.payload_terminal_result(validation_id.block_id()),
        Some(PayloadTerminalResult::DeterministicallyInvalid)
    );
}

fn activate_and_record_delivered_v0(
    session: PayloadValidationRecoverySessionV0,
    application: &mut NativeValidationRecoveryStoreV0,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    reason: NativeValidationRecoveredInvalidReasonV0,
    obligation_revision: u64,
) -> (
    Core,
    SafetyStatePersistenceV0,
    NativeValidationRecoveredInvalidCallbackFactsV0,
) {
    let mut recovered_core = session
        .reconcile_and_activate_v0(application)
        .expect("production application facade accepts its exact Core challenge");
    assert_eq!(
        application.recovered_obligation_state_v0(),
        Some(NativeValidationRecoveredInvalidStateV0::CallbackPending)
    );
    let effects = recovered_core
        .step(
            exact_invalid_input_v0(route, validation_id),
            &StrictEd25519Verifier,
        )
        .expect("recovered Core accepts the exact deterministic-invalid callback");
    let request = take_exact_recovery_persistence_v0(effects)
        .expect("recovered callback emits one opaque persistence request");
    assert_exact_invalid_completion_v0(request.state(), route, validation_id, obligation_revision);
    let callback_facts = application
        .record_recovered_core_acceptance_v0(&request)
        .expect("production application facade durably records Delivered");
    assert_eq!(callback_facts.route(), route);
    assert_eq!(callback_facts.validation_id(), validation_id);
    assert_eq!(callback_facts.reason(), reason);
    assert_eq!(callback_facts.delivery_attempt(), 1);
    assert_eq!(
        application.recovered_obligation_state_v0(),
        Some(NativeValidationRecoveredInvalidStateV0::Delivered)
    );
    application
        .final_exact_audit_v0()
        .expect("Delivered application row survives an exact audit");
    (recovered_core, request, callback_facts)
}

fn assert_live_host_holds_official_lock_v0(
    start: &PocoNodeStartConfigV0,
    application_status: &Path,
    watermark: MemoryWatermark,
) {
    let error = match PocoNodeValidationRecoveryHostV0::open_existing(
        PocoNodeValidationRecoveryConfigV0::new(
            start.clone(),
            application_status,
            SIGNER_POLICY_HASH,
        )
        .expect("valid competing recovery config"),
        watermark,
    ) {
        Ok(_) => panic!("a second official host acquired the live recovery namespace"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        PocoNodeHostErrorV0::SafetyStore(error)
            if matches!(error.as_ref(), SafetyStoreErrorV0::Locked)
    ));
}

fn assert_reopened_c_k_v0(
    start: &PocoNodeStartConfigV0,
    application_status: &Path,
    watermark: MemoryWatermark,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    obligation_revision: u64,
) {
    let repeated = PocoNodeValidationRecoveryHostV0::open_existing(
        PocoNodeValidationRecoveryConfigV0::new(
            start.clone(),
            application_status,
            SIGNER_POLICY_HASH,
        )
        .expect("valid repeated recovery config"),
        watermark,
    )
    .expect("C+K recovery must be exactly idempotent");
    assert_eq!(
        repeated.recovery(),
        ValidationRecoveryBootstrapV0::CompletionConfirmed {
            route,
            validation_id,
            completion_revision: obligation_revision + 1,
            source: ValidationRecoverySourceStateV0::Acked,
        }
    );
    assert_eq!(repeated.pending_inert_effect_count(), 0);
    assert_exact_invalid_completion_v0(
        repeated.safety_state(),
        route,
        validation_id,
        obligation_revision,
    );
    drop(repeated);
}

fn exercise_recovery_case_v0(
    route: PayloadValidationRouteV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
) {
    let PendingRecoveryCaseV0 {
        _root,
        start,
        watermark,
        application_status,
        original_core,
        safety_store,
        signer_journal,
        recovery_session,
        validation_id,
        obligation_revision,
    } = prepare_pending_recovery_case_v0(route, reason);
    drop(recovery_session);
    drop(original_core);
    drop(safety_store);
    drop(signer_journal);

    let recovery_config = PocoNodeValidationRecoveryConfigV0::new(
        start.clone(),
        &application_status,
        SIGNER_POLICY_HASH,
    )
    .expect("valid three-store node recovery config");
    let host = PocoNodeValidationRecoveryHostV0::open_existing(recovery_config, watermark.clone())
        .expect("O+P recovery must durably reach C+K");
    assert_eq!(
        host.recovery(),
        ValidationRecoveryBootstrapV0::ObligationCompleted {
            route,
            validation_id,
            completion_revision: obligation_revision + 1,
            source: ValidationRecoverySourceStateV0::CallbackPending,
        }
    );
    assert_eq!(host.pending_inert_effect_count(), 0);
    assert_exact_invalid_completion_v0(
        host.safety_state(),
        route,
        validation_id,
        obligation_revision,
    );
    let completed_head = host
        .safety_head()
        .expect("authenticate completed safety head");
    let native = completed_head
        .transition_context()
        .native_invalid()
        .expect("completed head carries exact native-invalid context");
    assert_eq!(native.route(), route);
    assert_eq!(native.validation_id(), validation_id);
    assert_eq!(native.reason_code(), reason.code_v0());
    assert_eq!(native.completion_revision(), completed_head.revision());
    assert_live_host_holds_official_lock_v0(&start, &application_status, watermark.clone());
    drop(host);

    assert_reopened_c_k_v0(
        &start,
        &application_status,
        watermark.clone(),
        route,
        validation_id,
        obligation_revision,
    );

    let legacy_error = match PocoNodeHostV0::open_existing(start, watermark, UnavailableProducerV0)
    {
        Ok(_) => panic!("legacy host bypassed application-aware C+K recovery"),
        Err(error) => error,
    };
    assert!(matches!(
        legacy_error,
        PocoNodeHostErrorV0::ValidationRecoveryAwareOpenRequired { .. }
    ));
}

fn exercise_o_d_recovery_case_v0(
    route: PayloadValidationRouteV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
) {
    let PendingRecoveryCaseV0 {
        _root,
        start,
        watermark,
        application_status,
        original_core,
        safety_store,
        signer_journal,
        recovery_session,
        validation_id,
        obligation_revision,
    } = prepare_pending_recovery_case_v0(route, reason);
    let mut application = NativeValidationRecoveryStoreV0::open_existing_v8(
        application_recovery_config_v0(&application_status, &safety_store),
    )
    .expect("production application recovery facade opens P");
    let (recovered_core, request, _) = activate_and_record_delivered_v0(
        recovery_session,
        &mut application,
        route,
        validation_id,
        reason,
        obligation_revision,
    );

    // Crash entry O+D: D is durable, but the exact Core request never reaches
    // the SafetyStore. The official host must replay that request from O.
    drop(request);
    drop(recovered_core);
    drop(application);
    drop(original_core);
    drop(safety_store);
    drop(signer_journal);

    let host = PocoNodeValidationRecoveryHostV0::open_existing(
        PocoNodeValidationRecoveryConfigV0::new(
            start.clone(),
            &application_status,
            SIGNER_POLICY_HASH,
        )
        .expect("valid O+D recovery config"),
        watermark.clone(),
    )
    .expect("O+D recovery must durably reach C+K");
    assert_eq!(
        host.recovery(),
        ValidationRecoveryBootstrapV0::ObligationCompleted {
            route,
            validation_id,
            completion_revision: obligation_revision + 1,
            source: ValidationRecoverySourceStateV0::Delivered,
        }
    );
    assert_eq!(host.pending_inert_effect_count(), 0);
    assert_exact_invalid_completion_v0(
        host.safety_state(),
        route,
        validation_id,
        obligation_revision,
    );
    assert_live_host_holds_official_lock_v0(&start, &application_status, watermark.clone());
    drop(host);

    assert_reopened_c_k_v0(
        &start,
        &application_status,
        watermark,
        route,
        validation_id,
        obligation_revision,
    );
}

fn exercise_c_d_recovery_case_v0(
    route: PayloadValidationRouteV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
) {
    let PendingRecoveryCaseV0 {
        _root,
        start,
        watermark,
        application_status,
        original_core,
        safety_store,
        signer_journal,
        recovery_session,
        validation_id,
        obligation_revision,
    } = prepare_pending_recovery_case_v0(route, reason);
    let mut application = NativeValidationRecoveryStoreV0::open_existing_v8(
        application_recovery_config_v0(&application_status, &safety_store),
    )
    .expect("production application recovery facade opens P");
    let (recovered_core, request, callback_facts) = activate_and_record_delivered_v0(
        recovery_session,
        &mut application,
        route,
        validation_id,
        reason,
        obligation_revision,
    );

    // The initial store is affined to the pre-crash Core. Reopen and bind it
    // to the authentic recovery Core before persisting that Core's exact C.
    drop(original_core);
    drop(safety_store);
    let mut completion_store = SqliteSafetyStateStoreV0::open_existing(
        start.safety_store_path.clone(),
        start.safety_store_profile.clone(),
        StrictEd25519Verifier,
    )
    .expect("reopen real SafetyStore for recovered Core");
    completion_store
        .bind_core_v0(recovered_core.safety_state_persistence_binding_v0())
        .expect("bind exact recovered Core to SafetyStore");
    let context = native_invalid_transition_context_v0(&callback_facts, request.state().revision())
        .expect("construct complete application-derived transition context");
    completion_store
        .persist_exact_v0(&request, &context)
        .expect("persist exact C without acknowledging application or Core");
    let confirmed = completion_store
        .confirmed_native_deterministic_invalid_head_exact_v0(request.state(), &context)
        .expect("authenticate exact C readback");
    assert_eq!(confirmed.revision(), obligation_revision + 1);
    assert_eq!(confirmed.transition().route(), route);
    assert_eq!(confirmed.transition().validation_id(), validation_id);
    assert_eq!(confirmed.transition().reason_code(), reason.code_v0());
    assert_exact_invalid_completion_v0(
        confirmed.state(),
        route,
        validation_id,
        obligation_revision,
    );

    // Crash entry C+D: do not recover/ack the application row and do not send
    // StorageAck to Core. The official host must authenticate C and close K.
    application
        .final_exact_audit_v0()
        .expect("Delivered application row remains exact before simulated crash");
    drop(confirmed);
    drop(request);
    drop(recovered_core);
    drop(completion_store);
    drop(application);
    drop(signer_journal);

    let host = PocoNodeValidationRecoveryHostV0::open_existing(
        PocoNodeValidationRecoveryConfigV0::new(
            start.clone(),
            &application_status,
            SIGNER_POLICY_HASH,
        )
        .expect("valid C+D recovery config"),
        watermark.clone(),
    )
    .expect("C+D recovery must durably reach K without a synthetic StorageAck");
    assert_eq!(
        host.recovery(),
        ValidationRecoveryBootstrapV0::CompletionConfirmed {
            route,
            validation_id,
            completion_revision: obligation_revision + 1,
            source: ValidationRecoverySourceStateV0::Delivered,
        }
    );
    assert_eq!(host.pending_inert_effect_count(), 0);
    assert_exact_invalid_completion_v0(
        host.safety_state(),
        route,
        validation_id,
        obligation_revision,
    );
    assert_live_host_holds_official_lock_v0(&start, &application_status, watermark.clone());
    drop(host);

    assert_reopened_c_k_v0(
        &start,
        &application_status,
        watermark,
        route,
        validation_id,
        obligation_revision,
    );
}

#[test]
fn unified_process_fixture_refuses_a_model_only_speculative_parent_without_its_app_overlay() {
    let root = protected_temp_dir_v0();
    let safety_path = protected_namespace_v0(&root, "unified-safety").join("safety.sqlite3");
    let signer_path = protected_namespace_v0(&root, "unified-signer").join("signer.sqlite3");
    let application_status =
        protected_namespace_v0(&root, "unified-application").join("state.json");
    let fixture = StrictConsensusFixtureV0::new();
    let start = node_start_config_v0(&safety_path, &signer_path, fixture.core_config.clone());
    let watermark = MemoryWatermark::default();
    let (original_core, safety_store, signer_journal) = create_obligation_head_v0(
        &fixture,
        PayloadValidationRouteV0::Proposal,
        &start,
        watermark.clone(),
        true,
        None,
    );
    let head = safety_store.head().expect("read exact obligation head");
    let recovery_session = Core::begin_payload_validation_obligation_recovery_v0(
        fixture.core_config,
        head.state().clone(),
        &StrictEd25519Verifier,
    )
    .expect("construct authentic Core recovery challenge");
    assert!(matches!(
        recovery_session.challenge().parent().provenance(),
        PayloadValidationParentProvenanceV0::Speculative(_)
    ));
    let application = NativeValidationRecoveryTestConfigBundleV0::new(
        &application_status,
        TEST_CHAIN,
        safety_store.journal_id_v0(),
        safety_store.verifier_profile_ref_v0(),
    )
    .expect("construct paired application and recovery config");
    let external_calls_before = watermark.compare_call_count();
    let error = initialize_native_validation_recovery_test_fixture_v0(
        application.recovery_fixture_config_v0(),
        recovery_session.challenge(),
        NativeValidationRecoveredInvalidReasonV0::ComputedStateRootMismatch,
    )
    .expect_err("a model-only Core overlay must not seed an ApplicationStore parent");
    assert_eq!(
        error,
        NativeValidationRecoveryTestFixtureErrorV0::ReservationFailed
    );
    assert_eq!(
        watermark.compare_call_count(),
        external_calls_before,
        "failed application fixture setup must not touch the external signer watermark"
    );
    drop((original_core, safety_store, signer_journal));
}

#[test]
fn unified_process_host_opens_authenticated_h1_checkpoint_replay_fenced_and_reopens() {
    let fixture = std::thread::Builder::new()
        .name("poco-h1-state-sync-fixture".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(prepare_authenticated_h1_checkpoint_process_host_v0)
        .expect("spawn the bounded large-stack h1 process-host fixture")
        .join()
        .expect("the h1 process-host fixture must not panic");

    for opening in 0..2 {
        let start = fixture.start.clone();
        let application = fixture.application.application_config_v0();
        let watermark = fixture.watermark.clone();
        std::thread::Builder::new()
            .name(format!("poco-h1-state-sync-default-stack-open-{opening}"))
            .spawn(move || {
                assert_authenticated_h1_checkpoint_process_host_open_v0(
                    opening,
                    start,
                    application,
                    watermark,
                )
            })
            .expect("spawn an ordinary default-stack h1 process-host opening")
            .join()
            .expect("the default-stack h1 process-host opening must not panic");
    }
}

#[test]
fn unified_process_host_closes_real_h1_h2_h3_empty_bodies_and_reopens_stable_rev2_rev4_v0() {
    std::thread::Builder::new()
        .name("poco-h1-anchor-successor-vertical".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let fixture = prepare_authenticated_h1_checkpoint_process_host_v0();
            assert_anchor_successor_stable_reopen_vertical_v0(&fixture);
        })
        .expect("spawn the bounded large-stack anchored-successor vertical")
        .join()
        .expect("the anchored-successor vertical must not panic");
}

#[test]
fn ordinary_public_entry_rejects_anchored_native_valid_before_signer_mutation_v0() {
    std::thread::Builder::new()
        .name("poco-ordinary-native-valid-anchor-negative".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let fixture = prepare_authenticated_h1_checkpoint_process_host_v0();
            let h1 = open_anchor_successor_process_fixture_v0(&fixture)
                .expect("open the genuine bounded h1 successor owner");
            let h2 = h1
                .complete_next_state_sync_anchor_successor_v0()
                .expect("persist a genuine anchored NativeValid C+K cut");
            assert_eq!(h2.bootstrap_facts().safety_revision(), 2);
            drop(h2);

            let compare_calls = fixture.watermark.compare_call_count();
            let error = PocoNodeProcessHostV0::open_existing_v0(
                PocoNodeProcessConfigV0::new(
                    fixture.start.clone(),
                    fixture.application.application_config_v0(),
                )
                .expect("construct the ordinary public process-host config"),
                fixture.watermark.clone(),
            )
            .expect_err(
                "the ordinary NativeValid completion branch must reject an anchored history",
            );
            assert!(matches!(
                error,
                PocoNodeProcessHostErrorV0::Core(
                    trnm_consensus_core::CoreError::NativeValidCompletionRecoveryRejected(_)
                )
            ));
            assert_eq!(
                fixture.watermark.compare_call_count(),
                compare_calls,
                "anchored rejection must not mutate the external signer watermark"
            );
        })
        .expect("spawn the bounded anchored NativeValid rejection fixture")
        .join()
        .expect("anchored NativeValid rejection must not panic");
}

#[test]
fn unified_anchor_successor_public_entry_rejects_nonvirgin_and_local_one_ahead_signers_v0() {
    std::thread::Builder::new()
        .name("poco-anchor-successor-signer-negative-matrix".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let nonvirgin = prepare_authenticated_h1_checkpoint_process_host_v0();
            let intent = anchor_successor_nonvirgin_sign_intent_v0(&nonvirgin);
            let mut signer = SqliteSignerJournalV0::open_existing(
                nonvirgin.start.signer_journal_path(),
                nonvirgin.start.signer_journal_profile.clone(),
                nonvirgin.watermark.clone(),
            )
            .expect("open exact signer solely to create a genuine non-virgin namespace");
            let mut producer = FixtureSigningProducerV0(nonvirgin.signer_key.clone());
            signer
                .sign_exact_v0(&intent, &mut producer)
                .expect("persist one genuine exact signer intent and signature");
            drop(signer);
            let compare_calls = nonvirgin.watermark.compare_call_count();
            let error = open_anchor_successor_process_fixture_v0(&nonvirgin)
                .expect_err("a genuine non-virgin signer cannot enter anchor replay");
            assert!(matches!(
                error,
                PocoNodeProcessHostErrorV0::SignerAheadOfSafety {
                    signer_revision: 1,
                    safety_revision: 0,
                }
            ));
            assert_eq!(
                nonvirgin.watermark.compare_call_count(),
                compare_calls,
                "non-virgin rejection must not advance the external watermark"
            );

            let local_one_ahead = prepare_authenticated_h1_checkpoint_process_host_v0();
            let intent = anchor_successor_nonvirgin_sign_intent_v0(&local_one_ahead);
            let mut signer = SqliteSignerJournalV0::open_existing(
                local_one_ahead.start.signer_journal_path(),
                local_one_ahead.start.signer_journal_profile.clone(),
                local_one_ahead.watermark.clone(),
            )
            .expect("open exact signer solely to create a local-first crash cut");
            local_one_ahead.watermark.fail_target_sequence_once(1);
            let mut producer = FixtureSigningProducerV0(local_one_ahead.signer_key.clone());
            signer
                .sign_exact_v0(&intent, &mut producer)
                .expect_err("the injected external failure must retain one local prepared event");
            drop(signer);
            let compare_calls = local_one_ahead.watermark.compare_call_count();
            let error = open_anchor_successor_process_fixture_v0(&local_one_ahead)
                .expect_err("a local-one-ahead external repair window must stay offline");
            assert!(matches!(
                error,
                PocoNodeProcessHostErrorV0::SignerExternalRepairRequired
            ));
            assert_eq!(
                local_one_ahead.watermark.compare_call_count(),
                compare_calls,
                "local-one-ahead rejection must not repair or advance external state"
            );
        })
        .expect("spawn the bounded signer rejection matrix")
        .join()
        .expect("the signer rejection matrix must not panic");
}

fn open_anchor_successor_process_fixture_v0(
    fixture: &PreparedAuthenticatedH1CheckpointProcessHostV0,
) -> Result<PocoNodeProcessHostV0<MemoryWatermark>, PocoNodeProcessHostErrorV0> {
    PocoNodeProcessHostV0::open_existing_state_sync_anchor_successors_v0(
        PocoNodeProcessConfigV0::new(
            fixture.start.clone(),
            fixture.application.application_config_v0(),
        )
        .expect("construct anchored-successor process config"),
        fixture.watermark.clone(),
        fixture.child.clone(),
        fixture.grandchild.clone(),
    )
}

fn anchor_successor_nonvirgin_sign_intent_v0(
    fixture: &PreparedAuthenticatedH1CheckpointProcessHostV0,
) -> CanonicalSignIntentV0 {
    let config = fixture.start.core_config();
    CanonicalSignIntentV0::vote(
        config.validator_set(),
        config.local_validator(),
        1,
        fixture.child.block().header().view(),
        fixture.child.block().header().height(),
        fixture.child.block().id(),
    )
    .expect("construct one exact canonical signer intent")
}

fn assert_anchor_successor_stable_reopen_vertical_v0(
    fixture: &PreparedAuthenticatedH1CheckpointProcessHostV0,
) {
    let open = || {
        PocoNodeProcessHostV0::open_existing_state_sync_anchor_successors_v0(
            PocoNodeProcessConfigV0::new(
                fixture.start.clone(),
                fixture.application.application_config_v0(),
            )
            .expect("construct anchored-successor process config"),
            fixture.watermark.clone(),
            fixture.child.clone(),
            fixture.grandchild.clone(),
        )
    };

    let host = open().expect("open the exact stable revision-zero successor owner");
    assert_eq!(
        host.lifecycle_phase(),
        PocoNodeProcessLifecyclePhaseV0::StateSyncAnchorSuccessorOffline,
    );
    let facts = host.bootstrap_facts();
    assert_eq!(
        facts.mode(),
        PocoNodeProcessBootstrapModeV0::StateSyncAnchorSuccessor,
    );
    assert_eq!(facts.safety_revision(), 0);
    assert!(!facts.application_authorities_installed());
    assert!(facts.application_seal_authority_installed());
    assert!(!facts.application_finalization_authority_installed());
    assert!(!facts.signer_activated());
    assert_eq!(host.pending_inert_effect_count(), 0);

    let h2 = host
        .complete_next_state_sync_anchor_successor_v0()
        .expect("close the real empty h2 O/P/D/C/K/StorageAck sequence");
    let facts = h2.bootstrap_facts();
    assert_eq!(facts.safety_revision(), 2);
    assert_eq!(facts.application_height(), 1);
    assert_eq!(facts.application_receipt_count(), 0);
    assert_eq!(facts.application_valid_completion_count(), 1);
    assert!(!facts.application_authorities_installed());
    assert!(facts.application_seal_authority_installed());
    assert!(!facts.application_finalization_authority_installed());
    assert!(!facts.signer_activated());
    assert_eq!(h2.pending_inert_effect_count(), 0);
    drop(h2);

    let reopened_h2 = open().expect("reopen the exact stable revision-two K cut");
    assert_eq!(reopened_h2.bootstrap_facts().safety_revision(), 2);
    assert!(reopened_h2
        .bootstrap_facts()
        .application_seal_authority_installed());
    let h3 = reopened_h2
        .complete_next_state_sync_anchor_successor_v0()
        .expect("close h3 from the authenticated h2 speculative parent");
    let facts = h3.bootstrap_facts();
    assert_eq!(facts.safety_revision(), 4);
    assert_eq!(facts.application_height(), 1);
    assert_eq!(facts.application_receipt_count(), 0);
    assert_eq!(facts.application_valid_completion_count(), 2);
    assert!(!facts.application_authorities_installed());
    assert!(!facts.application_seal_authority_installed());
    assert!(!facts.application_finalization_authority_installed());
    assert!(!facts.signer_activated());
    assert_eq!(h3.pending_inert_effect_count(), 0);
    assert!(h3.production_activation_check().is_err());
    assert_eq!(
        fixture.watermark.compare_call_count(),
        1,
        "anchored-successor replay must never advance the signer watermark"
    );
    drop(h3);

    let reopened_h3 = open()
        .expect("reopen rev4 after reconstructing h2 against the retained rev3 Safety predecessor");
    let facts = reopened_h3.bootstrap_facts();
    assert_eq!(facts.safety_revision(), 4);
    assert_eq!(facts.application_valid_completion_count(), 2);
    assert!(!facts.application_authorities_installed());
    assert!(!facts.application_seal_authority_installed());
    assert!(!facts.application_finalization_authority_installed());
    assert!(!facts.signer_activated());
    assert_eq!(reopened_h3.pending_inert_effect_count(), 0);
    drop(reopened_h3);
    assert_eq!(fixture.watermark.compare_call_count(), 1);
}

#[test]
fn unified_process_host_rejects_rev1_and_rev3_before_signer_mutation() {
    std::thread::Builder::new()
        .name("poco-anchor-successor-in-flight-matrix".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(assert_anchor_successor_in_flight_rejection_matrix_v0)
        .expect("spawn the bounded large-stack in-flight rejection matrix")
        .join()
        .expect("the in-flight rejection matrix must not panic");
}

fn assert_anchor_successor_in_flight_rejection_matrix_v0() {
    for target_revision in [1_u64, 3] {
        let fixture = prepare_authenticated_h1_checkpoint_process_host_v0();
        if target_revision == 3 {
            let h1 = PocoNodeProcessHostV0::open_existing_state_sync_anchor_successors_v0(
                PocoNodeProcessConfigV0::new(
                    fixture.start.clone(),
                    fixture.application.application_config_v0(),
                )
                .expect("construct rev3 prerequisite config"),
                fixture.watermark.clone(),
                fixture.child.clone(),
                fixture.grandchild.clone(),
            )
            .expect("open h1 successor prerequisite");
            let h2 = h1
                .complete_next_state_sync_anchor_successor_v0()
                .expect("close genuine h2 before constructing rev3 negative cut");
            drop(h2);
        }
        persist_model_only_anchor_successor_obligation_cut_v0(&fixture);
        let compare_calls = fixture.watermark.compare_call_count();
        let error = PocoNodeProcessHostV0::open_existing_state_sync_anchor_successors_v0(
            PocoNodeProcessConfigV0::new(
                fixture.start.clone(),
                fixture.application.application_config_v0(),
            )
            .expect("construct in-flight rejection config"),
            fixture.watermark.clone(),
            fixture.child.clone(),
            fixture.grandchild.clone(),
        )
        .expect_err("an in-flight successor cut cannot cross process restart");
        assert!(matches!(
            error,
            PocoNodeProcessHostErrorV0::AnchorSuccessorInFlightRecoveryUnavailable { revision }
                if revision == target_revision
        ));
        assert_eq!(
            fixture.watermark.compare_call_count(),
            compare_calls,
            "rev1/rev3 rejection must happen before signer pin/load/CAS"
        );
    }
}

struct ModelOnlyAnchorSuccessorReconcilerV0;

impl StateSyncAnchorSuccessorRecoveryReconcilerV0 for ModelOnlyAnchorSuccessorReconcilerV0 {
    fn reconcile_state_sync_anchor_successors_v0(
        &mut self,
        _challenge: &StateSyncAnchorSuccessorRecoveryChallengeV0,
    ) -> bool {
        true
    }
}

fn persist_model_only_anchor_successor_obligation_cut_v0(
    fixture: &PreparedAuthenticatedH1CheckpointProcessHostV0,
) {
    let mut safety_store = SqliteSafetyStateStoreV0::open_existing(
        fixture.start.safety_store_path(),
        fixture.start.safety_store_profile.clone(),
        StrictEd25519Verifier,
    )
    .expect("open SafetyStore solely to construct a negative in-flight cut");
    let head = safety_store
        .head()
        .expect("read stable predecessor for negative in-flight cut");
    let bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
        fixture.start.core_config(),
        head.state(),
        fixture.child.clone(),
        fixture.grandchild.clone(),
        &StrictEd25519Verifier,
    )
    .expect("authenticate exact successor bodies for negative cut");
    let session = Core::begin_state_sync_anchor_successor_recovery_v0(
        fixture.start.core_config().clone(),
        head.state().clone(),
        bundle,
        &StrictEd25519Verifier,
    )
    .expect("begin model-only negative-cut session");
    let mut replay = session
        .reconcile_and_activate_v0(&mut ModelOnlyAnchorSuccessorReconcilerV0)
        .expect("model-only reconciler is used solely to persist an unrecoverable negative cut");
    safety_store
        .bind_core_v0(replay.safety_state_persistence_binding_v0())
        .expect("bind negative-cut replay affinity");
    let effects = replay
        .step_next_proposal_v0(&StrictEd25519Verifier)
        .expect("produce the exact negative-cut obligation");
    let persistence = match effects.as_slice() {
        [Effect::PersistSafetyState(persistence)] => persistence,
        _ => panic!("negative-cut proposal must emit exactly one persistence"),
    };
    safety_store
        .persist_exact_v0(persistence, &SafetyTransitionContextV0::ordinary())
        .expect("persist exact ordinary in-flight cut");
}

struct PreparedAuthenticatedH1CheckpointProcessHostV0 {
    _root: TempDir,
    start: PocoNodeStartConfigV0,
    application: NativeValidationRecoveryTestConfigBundleV0,
    watermark: MemoryWatermark,
    signer_key: SigningKey,
    child: SignedProposalV0,
    grandchild: SignedProposalV0,
}

fn prepare_authenticated_h1_checkpoint_process_host_v0(
) -> Box<PreparedAuthenticatedH1CheckpointProcessHostV0> {
    let root = protected_temp_dir_v0();
    let safety_path = protected_namespace_v0(&root, "h1-safety").join("safety.sqlite3");
    let signer_path = protected_namespace_v0(&root, "h1-signer").join("signer.sqlite3");
    let application_status = protected_namespace_v0(&root, "h1-application").join("state.json");
    let fixture = StrictConsensusFixtureV0::new();
    let start = node_start_config_v0(&safety_path, &signer_path, fixture.core_config.clone());

    let provisional_application = NativeValidationRecoveryTestConfigBundleV0::new(
        &application_status,
        TEST_CHAIN,
        [0; 32],
        [0; 32],
    )
    .expect("construct the signer-policy-bound root preimage");
    let empty_root = empty_native_application_trusted_base_root_for_recovery_test_v0(
        1,
        &provisional_application,
        &fixture.core_config,
    )
    .expect("derive the exact empty height-one JMT root before creating any namespace");
    let successors = empty_state_sync_anchor_successor_commitments_for_recovery_test_v0(
        &provisional_application,
        &fixture.core_config,
    )
    .expect("plan exact empty h2/h3 production commitments");
    let (proof, h1, child, grandchild) =
        h1_state_sync_proof_v0(&fixture, StateRoot::new(empty_root), successors);
    assert_eq!(*h1.block().header().state_root().as_bytes(), empty_root);
    assert_eq!(
        decode_application_payload_v0_exact(
            h1.block().application_payload(),
            fixture.core_config.consensus_parameters(),
        )
        .expect("decode empty h1 payload")
        .transaction_count(),
        0,
    );
    let prepared = Core::prepare_h1_state_sync_bootstrap_v0(
        fixture.core_config.clone(),
        proof,
        &StrictEd25519Verifier,
    )
    .expect("prepare the strict Ed25519 h1 anchor without a live Core");
    let safety_store = SqliteSafetyStateStoreV0::initialize_h1_state_sync_v0(
        &safety_path,
        start.safety_store_profile.clone(),
        StrictEd25519Verifier,
        &prepared,
    )
    .expect("persist the exact revision-zero tag-4 Safety head");
    let application = NativeValidationRecoveryTestConfigBundleV0::new(
        &application_status,
        TEST_CHAIN,
        safety_store.journal_id_v0(),
        safety_store.verifier_profile_ref_v0(),
    )
    .expect("construct the bound ApplicationStore configuration");
    let application_fixture = initialize_empty_native_application_test_fixture_v0(
        &application,
        &fixture.core_config,
        prepared.safety_state(),
    )
    .expect("install the exact h1 TrustedBase and Safety provenance binding");
    assert_eq!(application_fixture.height(), 1);
    assert_eq!(application_fixture.state_root(), empty_root);
    let signer_key = fixture.key(fixture.core_config.local_validator()).clone();

    let watermark = MemoryWatermark::default();
    let signer_journal = SqliteSignerJournalV0::initialize_new(
        &signer_path,
        start.signer_journal_profile.clone(),
        watermark.clone(),
    )
    .expect("initialize a genuinely virgin signer journal");
    let capacity = signer_journal
        .capacity()
        .expect("read virgin signer capacity");
    assert_eq!(capacity.intent_count(), 0);
    assert_eq!(capacity.event_count(), 0);
    assert_eq!(capacity.intent_bytes(), 0);
    assert_eq!(watermark.compare_call_count(), 1);
    drop((signer_journal, safety_store, prepared));

    Box::new(PreparedAuthenticatedH1CheckpointProcessHostV0 {
        _root: root,
        start,
        application,
        watermark,
        signer_key,
        child,
        grandchild,
    })
}

fn assert_authenticated_h1_checkpoint_process_host_open_v0(
    opening: usize,
    start: PocoNodeStartConfigV0,
    application: trnm_consensus_app::ConsensusAppConfig,
    watermark: MemoryWatermark,
) {
    let host = PocoNodeProcessHostV0::open_existing_v0(
        PocoNodeProcessConfigV0::new(start, application)
            .expect("construct the existing-only unified process config"),
        watermark.clone(),
    )
    .unwrap_or_else(|error| panic!("authenticated h1 opening {opening} failed: {error}"));
    assert_eq!(
        host.lifecycle_phase(),
        PocoNodeProcessLifecyclePhaseV0::StateSyncReplayFencedOffline,
    );
    let facts = host.bootstrap_facts();
    assert_eq!(
        facts.mode(),
        PocoNodeProcessBootstrapModeV0::StateSyncCheckpointBootstrap
    );
    assert_eq!(facts.safety_revision(), 0);
    assert_eq!(
        facts.application_kind(),
        trnm_consensus_app::NativeConsensusApplicationAppliedKindV0::TrustedBase
    );
    assert_eq!(facts.application_height(), 1);
    assert_eq!(facts.application_receipt_count(), 0);
    assert_eq!(facts.application_valid_completion_count(), 0);
    assert!(!facts.application_authorities_installed());
    assert!(!facts.signer_activated());
    assert_eq!(facts.signer().capacity().intent_count(), 0);
    assert_eq!(facts.signer().capacity().event_count(), 0);
    assert_eq!(facts.signer().capacity().intent_bytes(), 0);
    assert_eq!(
        host.pending_inert_effect_kinds(),
        vec![PocoNodeInertEffectKindV0::RequestSafetyReplay]
    );
    assert_eq!(host.pending_inert_effect_count(), 1);
    assert!(host.production_activation_check().is_err());
    assert_eq!(
        watermark.compare_call_count(),
        1,
        "pinned replay-fenced h1 opening must not activate or advance the signer"
    );
    drop(host);
}

#[test]
fn genuine_h1_three_owner_wrapper_reconfirms_then_rejects_replay_fence_v0() {
    let fixture = std::thread::Builder::new()
        .name("poco-h1-node-checkpoint-join-fixture".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(prepare_authenticated_h1_checkpoint_process_host_v0)
        .expect("spawn the bounded large-stack h1 checkpoint fixture")
        .join()
        .expect("the h1 checkpoint fixture must not panic");

    let process_config = PocoNodeProcessConfigV0::new(
        fixture.start.clone(),
        fixture.application.application_config_v0(),
    )
    .expect("construct exact three-store process config");
    let mut safety_store = SqliteSafetyStateStoreV0::open_existing(
        fixture.start.safety_store_path(),
        fixture.start.safety_store_profile.clone(),
        StrictEd25519Verifier,
    )
    .expect("open genuine strict SafetyStore owner");
    let application_config =
        NativeConsensusApplicationHostConfigV0::from_authenticated_safety_store_v0(
            fixture.application.application_config_v0(),
            &safety_store,
        )
        .expect("bind genuine App host config to SafetyStore");
    let mut application_host =
        NativeConsensusApplicationHostV0::open_existing_v0(application_config)
            .expect("open genuine ApplicationStore owner");
    let mut pinned_signer = SqliteSignerJournalV0::pin_existing_v0(
        fixture.start.signer_journal_path(),
        fixture.start.signer_journal_profile.clone(),
        fixture.watermark.clone(),
    )
    .expect("pin genuine signer owner without activation");

    let safety_head = safety_store.head().expect("read authenticated h1 head");
    let safety = safety_store
        .confirm_node_checkpoint_head_exact_v0(safety_head.state())
        .expect("mint genuine Safety checkpoint facts");
    let application = application_host
        .confirm_node_checkpoint_facts_v0(&safety)
        .expect("mint genuine App checkpoint facts");
    let signer = pinned_signer
        .confirm_node_checkpoint_head_exact_v0()
        .expect("mint genuine signer checkpoint facts");
    let observed = ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
        scope: signer.identity().external_watermark_scope(),
        generation: 7,
        predecessor_checksum: [0x71; 32],
        safety_journal_id: safety.journal_id_v0(),
        safety_verifier_profile_ref: safety.verifier_profile_ref_v0(),
        safety_revision: safety.revision_v0(),
        safety_state_record_checksum: safety.state_record_checksum_v0(),
        safety_record_chain_checksum: safety.chain_checksum_v0(),
        application_host_config_ref: application.host_config_ref_v0(),
        application_projection_profile_ref: application.projection_profile_ref_v0(),
        application_safety_binding_manifest_checksum: application
            .safety_binding_manifest_checksum_v0(),
        application_committed_head_row_checksum: application.committed_head_row_checksum_v0(),
        application_recovery_closure_checksum: application.recovery_closure_checksum_v0(),
        application_block_id: application.block_id_v0(),
        application_height: application.height_v0(),
        application_state_root: StateRoot::new(application.state_root_v0()),
        application_view: application.view_v0(),
        application_timestamp_ms: application.timestamp_ms_v0(),
        signer_journal_id: signer.journal_id(),
        signer_profile_checksum: signer.profile_checksum(),
        signer_exact_watermark: signer.exact_watermark(),
    })
    .expect("construct exact externally observed h1 cut");
    let external_load_calls = fixture.watermark.load_call_count();
    let external_compare_calls = fixture.watermark.compare_call_count();

    let ordinary_core = fixture.start.core_config();
    let authenticated_parent = AuthenticatedGenesisApplicationParentV0::new(
        ordinary_core.genesis_block_id(),
        ordinary_core.trusted_genesis_timestamp_ms(),
        0,
        StateRoot::new([0x31; 32]),
        [0x41; 32],
        [0x51; 32],
    )
    .expect("construct shape-valid authenticated-genesis parent for the external-join fence");
    let authenticated_core = CoreConfig::new_with_authenticated_genesis_application_parent_v0(
        ordinary_core.local_validator(),
        ordinary_core.validator_set().clone(),
        *ordinary_core.consensus_parameters(),
        ordinary_core.trusted_genesis_timestamp_ms(),
        authenticated_parent,
        ordinary_core.max_blocks(),
        ordinary_core.max_observed_messages(),
    )
    .expect("construct authenticated-genesis Core config for the external-join fence");
    let authenticated_process_config =
        PocoNodeProcessConfigV0::new_for_authenticated_genesis_fence_test_v0(
            unchecked_node_start_config_v0(
                fixture.start.safety_store_path(),
                fixture.start.signer_journal_path(),
                authenticated_core,
            ),
            fixture.application.application_config_v0(),
        );
    let error = confirm_existing_node_checkpoint_candidate_v0(
        observed,
        &authenticated_process_config,
        &mut safety_store,
        &mut application_host,
        &mut pinned_signer,
        (safety, application, signer),
    )
    .expect_err("generic external checkpoint join must fence authenticated genesis");
    assert_eq!(
        error,
        ExistingNodeCheckpointJoinErrorV0::AuthenticatedGenesisCommissioningRequiresDedicatedHost
    );
    assert_eq!(
        fixture.watermark.load_call_count(),
        external_load_calls,
        "external join must fence before fresh signer watermark observation"
    );
    assert_eq!(
        fixture.watermark.compare_call_count(),
        external_compare_calls,
        "external join fence must never advance external state"
    );

    let safety = safety_store
        .confirm_node_checkpoint_head_exact_v0(safety_head.state())
        .expect("remint Safety facts after the external-join mode fence");
    let application = application_host
        .confirm_node_checkpoint_facts_v0(&safety)
        .expect("remint application facts after the external-join mode fence");
    let signer = pinned_signer
        .confirm_node_checkpoint_head_exact_v0()
        .expect("remint signer facts after the external-join mode fence");

    let exact_signer_watermark = signer.exact_watermark();
    let ahead_signer_watermark = SignerWatermarkV0::from_persisted_parts(
        exact_signer_watermark.scope(),
        exact_signer_watermark.journal_id(),
        exact_signer_watermark
            .sequence()
            .checked_add(1)
            .expect("test signer sequence has a successor"),
        [0x72; 32],
    )
    .expect("construct canonical external-ahead signer watermark");
    *fixture.watermark.value.lock().expect("test watermark lock") = Some(ahead_signer_watermark);
    let error = confirm_existing_node_checkpoint_candidate_v0(
        observed,
        &process_config,
        &mut safety_store,
        &mut application_host,
        &mut pinned_signer,
        (safety, application, signer),
    )
    .expect_err("fresh signer confirmation rejects a capability after external advance");
    assert_eq!(
        error,
        ExistingNodeCheckpointJoinErrorV0::SignerHeadReconfirmationUnavailable
    );
    assert_eq!(
        fixture.watermark.compare_call_count(),
        external_compare_calls,
        "freshness rejection performs no external compare-and-advance"
    );

    *fixture.watermark.value.lock().expect("test watermark lock") = Some(exact_signer_watermark);
    let safety = safety_store
        .confirm_node_checkpoint_head_exact_v0(safety_head.state())
        .expect("remint genuine Safety checkpoint facts after inert rejection");
    let application = application_host
        .confirm_node_checkpoint_facts_v0(&safety)
        .expect("remint genuine App checkpoint facts after inert rejection");
    let signer = pinned_signer
        .confirm_node_checkpoint_head_exact_v0()
        .expect("remint genuine signer checkpoint facts after restoring exact watermark");

    let error = confirm_existing_node_checkpoint_candidate_v0(
        observed,
        &process_config,
        &mut safety_store,
        &mut application_host,
        &mut pinned_signer,
        (safety, application, signer),
    )
    .expect_err("genuine h1 owners remain permanently outside existing-checkpoint join");
    assert_eq!(
        error,
        ExistingNodeCheckpointJoinErrorV0::ReplayFencedStateUnavailable
    );
    assert_eq!(
        fixture.watermark.compare_call_count(),
        external_compare_calls,
        "fresh signer confirmation performs load only and never advances external state"
    );
    assert_eq!(
        safety_store
            .head()
            .expect("SafetyStore remains open")
            .revision(),
        0
    );
    application_host
        .reconcile_current_application_applied_v0(safety_head.state())
        .expect("App host remains exactly reconciled after refusal");
    let _ = pinned_signer
        .confirm_node_checkpoint_head_exact_v0()
        .expect("signer remains pinned and exact after refusal");
}

#[test]
fn deterministic_invalid_fixture_rejects_synthetic_genesis_without_exact_application_parent_v0() {
    let root = protected_temp_dir_v0();
    let safety_path = protected_namespace_v0(&root, "genesis-parent-safety").join("safety.sqlite3");
    let signer_path = protected_namespace_v0(&root, "genesis-parent-signer").join("signer.sqlite3");
    let application_status =
        protected_namespace_v0(&root, "genesis-parent-application").join("state.json");
    let fixture = StrictConsensusFixtureV0::new();
    let start = node_start_config_v0(&safety_path, &signer_path, fixture.core_config.clone());
    let watermark = MemoryWatermark::default();
    let (original_core, safety_store, signer_journal) = create_obligation_head_v0(
        &fixture,
        PayloadValidationRouteV0::Proposal,
        &start,
        watermark.clone(),
        false,
        Some(&application_status),
    );
    let head = safety_store
        .head()
        .expect("read the synthetic-genesis-parent obligation head");
    let recovery_session = Core::begin_payload_validation_obligation_recovery_v0(
        fixture.core_config,
        head.state().clone(),
        &StrictEd25519Verifier,
    )
    .expect("construct the authentic synthetic-genesis-parent recovery challenge");
    assert!(recovery_session
        .challenge()
        .parent()
        .exact_header()
        .is_none());
    let application = NativeValidationRecoveryTestConfigBundleV0::new(
        &application_status,
        TEST_CHAIN,
        safety_store.journal_id_v0(),
        safety_store.verifier_profile_ref_v0(),
    )
    .expect("construct the exact application recovery configuration");
    let external_calls_before = watermark.compare_call_count();
    let error = initialize_native_validation_recovery_test_fixture_v0(
        application.recovery_fixture_config_v0(),
        recovery_session.challenge(),
        NativeValidationRecoveredInvalidReasonV0::ComputedStateRootMismatch,
    )
    .expect_err("synthetic genesis has no canonical native header/state-root parent");
    assert_eq!(
        error,
        NativeValidationRecoveryTestFixtureErrorV0::ReservationFailed
    );
    assert_eq!(
        watermark.compare_call_count(),
        external_calls_before,
        "fail-closed application admission must not touch the signer watermark"
    );
    drop((original_core, safety_store, signer_journal));
}

#[test]
#[ignore = "legacy positive recovery requires authenticated anchored-successor replay and real Valid overlays; the current h1 replay fence deliberately blocks both"]
fn strict_three_store_recovery_matrix_closes_o_p_o_d_c_d_and_c_k() {
    for route in [
        PayloadValidationRouteV0::Proposal,
        PayloadValidationRouteV0::Synced,
    ] {
        for reason in [
            NativeValidationRecoveredInvalidReasonV0::ComputedStateRootMismatch,
            NativeValidationRecoveredInvalidReasonV0::ComputedReceiptsRootMismatch,
        ] {
            exercise_recovery_case_v0(route, reason);
            exercise_o_d_recovery_case_v0(route, reason);
            exercise_c_d_recovery_case_v0(route, reason);
        }
    }
}
