use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    leader_for, BlockIdOverlayRefV0, Core, CoreConfig, Effect, Input, NativeValidPostAckActionV0,
    PayloadValidationRouteV0, SafetyStateRecordLimitsV0, ValidatedPayloadArtifactRefV0,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    SafetyPersistDispositionV0, SafetyStateStoreProfileV0, SafetyTransitionContextV0,
    SqliteSafetyStateStoreV0,
};
use trnm_consensus_types::{
    ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader, BlockKind, ChainId,
    ConsensusParametersV0, ConsensusPublicKey, Epoch, ExecutionReceiptCommitmentV0,
    ExecutionReceiptsV0, GenesisHash, GenesisQcV0, Height, ProposalWitnessV0, ProtocolVersion,
    QcReferenceV0, SignatureBytes, SignedProposalV0, StateRoot, Validator, ValidatorId,
    ValidatorSet, View, VotingPower,
};

use trnm_native_application::{
    encode_native_executed_block_artifact_v0, ApplicationCommitIdV0, ApplicationHeadV0, BlockIdV0,
    ChainIdV0, GenesisHashV0, Hash32V0, HeightV0, NativeBlockExecutionRequestV0,
    NativeEventAttributeV0, NativeEventV0, NativeExecutedBlockV0, NativeExecutionReceiptV0,
    NativeExpectedBlockCommitmentsV0, ReceiptsRootV0, StateRootV0, ValidatorSetIdV0,
};

use crate::{
    store::{
        complete_single_replay_link_for_activation_test_v0, duplicate_reserved_for_test_v0,
        rewrite_anchor_successor_no_sign_closure_for_test_v0,
        rewrite_artifact_self_consistent_for_test_v0,
        rewrite_safety_core_delivery_self_consistent_for_test_v0, TestCommitFaultV0,
    },
    AckTransitionOutcomeV0, CoreDeliveryConfirmationV0, DeliverTransitionOutcomeV0,
    DurableReplayLinkStageV0, DurableValidationStageV0, NonZeroDigestV0, ProposalRouteV0,
    ProposalValidationBindingV0, ProposalValidationOwnerIdV0, ProposalValidationStoreScopeV0,
    ReplayActivationBindingV0, ReplayLinkReservationOutcomeV0, ReplaySessionOpenOutcomeV0,
    ReplaySessionPlanV0, ReplaySessionResumeOutcomeV0, ReservationOutcomeV0,
    SafetyConfirmationReadRequestV0, SafetyConfirmationReadbackV0, SqliteProposalValidationStoreV0,
    UntrustedSafetyConfirmationReadbackV0, ValidationIdV0, ValidationStoreErrorCodeV0,
    ValidationStoreResultV0,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectoryV0(PathBuf);

impl TestDirectoryV0 {
    fn new() -> Self {
        let unique = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "trnm-native-validation-store-{}-{}",
            std::process::id(),
            unique
        ));
        fs::create_dir(&path).expect("test directory must be created once");
        Self(path)
    }

    fn database(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectoryV0 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn digest(byte: u8) -> NonZeroDigestV0 {
    NonZeroDigestV0::new([byte; 32]).expect("fixture digest is nonzero")
}

fn scope(byte: u8) -> ProposalValidationStoreScopeV0 {
    ProposalValidationStoreScopeV0::new([byte; 32]).expect("fixture scope is nonzero")
}

fn owner(byte: u8) -> ProposalValidationOwnerIdV0 {
    ProposalValidationOwnerIdV0::new([byte; 32]).expect("fixture owner is nonzero")
}

fn replay_plan(expected_count: u64) -> ReplaySessionPlanV0 {
    ReplaySessionPlanV0::new(
        digest(0xB0),
        digest(0xB1),
        digest(0xB2),
        1,
        digest(0xB3),
        expected_count,
        digest(0xB4),
        5,
        digest(0xB5),
        digest(0xB6),
        digest(0xB7),
        digest(0xB8),
        7,
        digest(0xB9),
        digest(0xBA),
        digest(0xBB),
        9,
        digest(0xBC),
    )
    .expect("fixture replay session plan is valid")
}

fn replay_activation_binding(
    inventory: &crate::ConfirmedReplayInventoryV0,
    signer_inventory_byte: u8,
    selected_replay_byte: u8,
) -> ReplayActivationBindingV0 {
    let session = inventory.session_v0();
    let last = inventory
        .links_v0()
        .last()
        .expect("activation fixture has one checkpointed replay link");
    let target = last.target_binding_v0();
    ReplayActivationBindingV0::new(
        NonZeroDigestV0::new(session.session_id_v0()).expect("nonzero session id"),
        digest(0xC5),
        session
            .initial_safety_revision_v0()
            .checked_add(session.expected_count_v0() * 2)
            .expect("fixture safety revision"),
        digest(0xC6),
        NonZeroDigestV0::new(session.application_history_digest_v0())
            .expect("nonzero application history"),
        target.height().get(),
        NonZeroDigestV0::new(*target.block_id().as_bytes()).expect("nonzero parent block"),
        NonZeroDigestV0::new(*target.commitments().post_state_root().as_bytes())
            .expect("nonzero parent state"),
        digest(0xC7),
        last.checkpoint_generation_v0()
            .expect("checkpoint generation"),
        NonZeroDigestV0::new(last.checkpoint_checksum_v0().expect("checkpoint checksum"))
            .expect("nonzero checkpoint checksum"),
        NonZeroDigestV0::new(session.signer_scope_v0()).expect("nonzero signer scope"),
        NonZeroDigestV0::new(session.signer_journal_id_v0()).expect("nonzero signer journal"),
        session.signer_sequence_v0(),
        NonZeroDigestV0::new(session.signer_chain_checksum_v0()).expect("nonzero signer checksum"),
        digest(signer_inventory_byte),
        digest(selected_replay_byte),
    )
    .expect("valid activation binding")
}

fn completed_replay_activation_fixture(
    path: &Path,
    scope_byte: u8,
    fixture_byte: u8,
) -> (
    SqliteProposalValidationStoreV0,
    ReplayActivationBindingV0,
    ReplayActivationBindingV0,
) {
    let source = binding(
        u64::from(fixture_byte),
        u64::from(fixture_byte) + 1,
        fixture_byte,
    );
    let target = synced_replay_binding(&source, u64::from(fixture_byte) + 2);
    let mut store =
        SqliteProposalValidationStoreV0::open(path, scope(scope_byte), 0).expect("open fixture");
    let reserved = reserve(&mut store, &source);
    let delivered = deliver(
        &mut store,
        reserved,
        core_delivery(source.validation_id(), 43, fixture_byte.wrapping_add(1)),
    );
    match store
        .acknowledge_v0(delivered, &mut ExactSafetyReadbackV0::exact(43, 0x84))
        .expect("close source K")
    {
        AckTransitionOutcomeV0::Applied(_) => {}
        AckTransitionOutcomeV0::NotApplied(_) => panic!("normal source K must apply"),
    }
    let terminal = store
        .confirm_terminal_k_audit_v0()
        .expect("fresh terminal inventory");
    let session = match store
        .begin_replay_session_v0(terminal, replay_plan(1))
        .expect("open replay session")
    {
        ReplaySessionOpenOutcomeV0::Applied(session) => session,
        other => panic!("fresh replay session must apply: {other:?}"),
    };
    let source_k = store
        .confirm_proposal_validation_checkpoint_facts_exact_v0(&source)
        .expect("fresh source K");
    match store
        .reserve_synced_replay_link_v0(session, source_k, digest(0xBD), &target, owner(6))
        .expect("reserve replay link")
    {
        ReplayLinkReservationOutcomeV0::Applied(_) => {}
        other => panic!("fresh replay link must apply: {other:?}"),
    }
    complete_single_replay_link_for_activation_test_v0(&mut store, target.validation_id())
        .expect("complete minimal audited replay fixture");
    let inventory = store
        .confirm_replay_inventory_v0()
        .expect("fresh complete replay inventory");
    assert!(inventory.session_v0().is_durable_complete_v0());
    assert_eq!(
        inventory.links_v0()[0].stage_v0(),
        DurableReplayLinkStageV0::Checkpointed
    );
    let binding = replay_activation_binding(&inventory, 0xC8, 0xCA);
    let conflicting = replay_activation_binding(&inventory, 0xC9, 0xCA);
    (store, binding, conflicting)
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

const REAL_SAFETY_CHAIN_V0: ChainId = ChainId::from_static("trnm-real-safety-c-test");

struct RealSafetyFixtureV0 {
    keys: Vec<(ValidatorId, SigningKey)>,
    parameters: ConsensusParametersV0,
    validator_set: ValidatorSet,
    config: CoreConfig,
}

impl RealSafetyFixtureV0 {
    fn new() -> Self {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let keys = (1_u8..=4)
            .map(|index| {
                (
                    ValidatorId::new([index; 32]),
                    SigningKey::from_bytes(&[index.saturating_add(70); 32]),
                )
            })
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .map(|(id, key)| {
                Validator::new(
                    *id,
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("valid validator")
            })
            .collect::<Vec<_>>();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xA6; 32]),
            REAL_SAFETY_CHAIN_V0,
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid validator set");
        let config = CoreConfig::new(keys[0].0, validator_set.clone(), parameters, 0, 32, 64)
            .expect("valid Core config");
        Self {
            keys,
            parameters,
            validator_set,
            config,
        }
    }

    fn proposal(&self) -> (SignedProposalV0, ApplicationPayloadV0, ExecutionReceiptsV0) {
        let payload =
            ApplicationPayloadV0::new(vec![b"real-safety-c".to_vec()]).expect("non-empty payload");
        let receipt = ExecutionReceiptCommitmentV0::for_transaction(&payload, 0, 17, 3, Vec::new())
            .expect("canonical receipt");
        let receipts =
            ExecutionReceiptsV0::new(&payload, vec![receipt]).expect("canonical receipt list");
        let body = BlockBodyV0::new(payload.clone(), Vec::new()).expect("canonical body");
        let view = View::new(1);
        let proposer = leader_for(&self.validator_set, view);
        let header = BlockHeader::new(
            self.validator_set.genesis_hash(),
            self.validator_set.chain_id(),
            self.validator_set.protocol_version(),
            self.validator_set.epoch(),
            view,
            Height::new(1),
            BlockKind::Regular,
            trnm_consensus_types::BlockId::new(*self.validator_set.genesis_hash().as_bytes()),
            proposer,
            self.validator_set.id(),
            self.validator_set.consensus_parameters_hash(),
            body.payload_root().expect("payload root"),
            StateRoot::new([0x91; 32]),
            receipts.receipts_root().expect("receipts root"),
            body.evidence_root().expect("evidence root"),
            100,
            None,
        )
        .expect("valid header");
        let block = Block::new(
            header,
            body.application_payload()
                .try_cev0_bytes()
                .expect("canonical payload bytes"),
            Vec::new(),
        )
        .expect("valid block");
        let justify = QcReferenceV0::genesis_anchor(
            GenesisQcV0::new(
                self.validator_set.genesis_hash(),
                self.validator_set.chain_id(),
                &self.validator_set,
            )
            .expect("valid genesis QC"),
        );
        let root = ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
            .expect("proposal signing root");
        let key = self
            .keys
            .iter()
            .find_map(|(id, key)| (*id == proposer).then_some(key))
            .expect("leader key");
        let witness = ProposalWitnessV0::new(
            block.header(),
            justify,
            None,
            None,
            SignatureBytes::from_array(key.sign(root.as_bytes()).to_bytes()),
            &self.validator_set,
            None,
            &self.parameters,
            0,
        )
        .expect("strict proposal witness");
        let proposal = SignedProposalV0::new(
            block,
            witness,
            &self.validator_set,
            None,
            &self.parameters,
            0,
        )
        .expect("strict signed proposal");
        (proposal, payload, receipts)
    }
}

fn directory_entries(path: &Path) -> Vec<OsString> {
    let mut entries = fs::read_dir(path)
        .expect("read test directory")
        .map(|entry| entry.expect("read directory entry").file_name())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

fn main_database_snapshot(path: &Path) -> (Vec<u8>, std::time::SystemTime, Vec<OsString>) {
    let metadata = fs::metadata(path).expect("read database metadata");
    (
        fs::read(path).expect("read database bytes"),
        metadata.modified().expect("read database mtime"),
        directory_entries(path.parent().expect("database parent")),
    )
}

fn core_delivery(
    validation_id: ValidationIdV0,
    revision: u64,
    byte: u8,
) -> CoreDeliveryConfirmationV0 {
    CoreDeliveryConfirmationV0::new(
        validation_id,
        revision,
        digest(byte),
        digest(byte.wrapping_add(1)),
    )
    .expect("fixture Core delivery is valid")
}

struct ExactSafetyReadbackV0 {
    revision: u64,
    byte: u8,
    wrong_validation_id: Option<crate::ValidationIdV0>,
    wrong_delivery_digest: Option<NonZeroDigestV0>,
}

impl ExactSafetyReadbackV0 {
    const fn exact(revision: u64, byte: u8) -> Self {
        Self {
            revision,
            byte,
            wrong_validation_id: None,
            wrong_delivery_digest: None,
        }
    }
}

impl SafetyConfirmationReadbackV0 for ExactSafetyReadbackV0 {
    fn read_exact_safety_confirmation_v0(
        &mut self,
        request: SafetyConfirmationReadRequestV0,
    ) -> ValidationStoreResultV0<UntrustedSafetyConfirmationReadbackV0> {
        UntrustedSafetyConfirmationReadbackV0::new(
            self.wrong_validation_id.unwrap_or(request.validation_id()),
            self.wrong_delivery_digest
                .unwrap_or(request.core_delivery_digest()),
            self.revision,
            digest(self.byte),
            digest(self.byte.wrapping_add(1)),
        )
    }
}

fn binding(view: u64, generation: u64, root_byte: u8) -> ProposalValidationBindingV0 {
    binding_full(view, generation, root_byte, 1_700_000_000_000, 0x42)
}

fn binding_full(
    view: u64,
    generation: u64,
    root_byte: u8,
    timestamp_ms: u64,
    validator_set_byte: u8,
) -> ProposalValidationBindingV0 {
    binding_full_route(
        view,
        generation,
        root_byte,
        timestamp_ms,
        validator_set_byte,
        ProposalRouteV0::Proposal,
    )
}

fn binding_full_route(
    view: u64,
    generation: u64,
    root_byte: u8,
    timestamp_ms: u64,
    validator_set_byte: u8,
    route: ProposalRouteV0,
) -> ProposalValidationBindingV0 {
    let parent = ApplicationHeadV0::new(
        HeightV0::GENESIS,
        BlockIdV0::new([1; 32]).expect("parent block id"),
        StateRootV0::new([2; 32]).expect("parent state root"),
        ApplicationCommitIdV0::new([3; 32]).expect("parent commit id"),
    );
    let commitments = NativeExpectedBlockCommitmentsV0::new(
        Hash32V0::new([root_byte; 32]),
        StateRootV0::new([root_byte.wrapping_add(1); 32]).expect("state root"),
        ReceiptsRootV0::new([root_byte.wrapping_add(2); 32]).expect("receipts root"),
        Hash32V0::new([root_byte.wrapping_add(3); 32]),
    )
    .expect("commitments");
    ProposalValidationBindingV0::new(
        ChainIdV0::new("trnm-validation-test").expect("chain id"),
        GenesisHashV0::new([4; 32]).expect("genesis hash"),
        parent,
        BlockIdV0::new([5; 32]).expect("block id"),
        HeightV0::new(1),
        timestamp_ms,
        ValidatorSetIdV0::new([validator_set_byte; 32]).expect("validator set"),
        view,
        generation,
        route,
        commitments,
    )
    .expect("binding")
}

fn synced_replay_binding(
    source: &ProposalValidationBindingV0,
    generation: u64,
) -> ProposalValidationBindingV0 {
    ProposalValidationBindingV0::new(
        source.chain_id().clone(),
        source.genesis_hash(),
        source.parent().clone(),
        source.block_id(),
        source.height(),
        source.timestamp_ms(),
        source.active_validator_set_id(),
        source.view(),
        generation,
        ProposalRouteV0::Synced,
        source.commitments(),
    )
    .expect("same-edge Synced replay binding")
}

fn executed(binding: &ProposalValidationBindingV0, transaction_byte: u8) -> NativeExecutedBlockV0 {
    let transactions = vec![vec![transaction_byte, transaction_byte.wrapping_add(1)]];
    let request = NativeBlockExecutionRequestV0::new(
        binding.chain_id().clone(),
        binding.genesis_hash(),
        binding.parent().clone(),
        binding.block_id(),
        binding.height(),
        binding.timestamp_ms(),
        binding.active_validator_set_id(),
        transactions,
        binding.commitments(),
    )
    .expect("execution request");
    let event = NativeEventV0::new(
        "transfer",
        vec![NativeEventAttributeV0::new("amount", "1").expect("attribute")],
    )
    .expect("event");
    let receipt = NativeExecutionReceiptV0::new(
        0,
        Hash32V0::new([transaction_byte; 32]),
        123,
        456,
        vec![event],
        Hash32V0::new([transaction_byte.wrapping_add(2); 32]),
    )
    .expect("receipt");
    NativeExecutedBlockV0::new(
        request,
        binding.commitments().payload_root(),
        binding.commitments().post_state_root(),
        binding.commitments().receipts_root(),
        binding.commitments().evidence_root(),
        vec![receipt],
    )
    .expect("executed block")
}

fn exact_executed_for_consensus_payload_v0(
    binding: &ProposalValidationBindingV0,
    payload: &ApplicationPayloadV0,
    receipts: &ExecutionReceiptsV0,
) -> NativeExecutedBlockV0 {
    let request = NativeBlockExecutionRequestV0::new(
        binding.chain_id().clone(),
        binding.genesis_hash(),
        binding.parent().clone(),
        binding.block_id(),
        binding.height(),
        binding.timestamp_ms(),
        binding.active_validator_set_id(),
        payload.transactions().to_vec(),
        binding.commitments(),
    )
    .expect("exact execution request");
    let canonical = &receipts.receipts()[0];
    let encoded = canonical.try_cev0_bytes().expect("canonical receipt bytes");
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((b"trnm.native-application.execution-receipt.v0".len() as u64).to_be_bytes());
    hasher.update(b"trnm.native-application.execution-receipt.v0");
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(&encoded);
    let commitment: [u8; 32] = hasher.finalize().into();
    let native_receipt = NativeExecutionReceiptV0::new(
        0,
        Hash32V0::new(*canonical.payload_leaf_hash()),
        canonical.gas_used(),
        canonical.fee_charged(),
        Vec::new(),
        Hash32V0::new(commitment),
    )
    .expect("exact native receipt");
    NativeExecutedBlockV0::new(
        request,
        binding.commitments().payload_root(),
        binding.commitments().post_state_root(),
        binding.commitments().receipts_root(),
        binding.commitments().evidence_root(),
        vec![native_receipt],
    )
    .expect("exact executed block")
}

fn reserve(
    store: &mut SqliteProposalValidationStoreV0,
    binding: &ProposalValidationBindingV0,
) -> crate::ReservedValidationV0 {
    match store
        .reserve_v0(binding, owner(6), &executed(binding, 7))
        .expect("reservation must succeed")
    {
        ReservationOutcomeV0::Applied(token) => token,
        ReservationOutcomeV0::NotApplied => panic!("normal reservation must apply"),
    }
}

#[test]
fn opaque_core_d_real_safety_c_closes_k_without_core_storage_ack_or_signature_release() {
    let directory = TestDirectoryV0::new();
    #[cfg(unix)]
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700))
        .expect("protect test root");
    let validation_path = directory.database("real-c-validation.sqlite3");
    let safety_parent = directory.0.join("safety");
    fs::create_dir(&safety_parent).expect("create protected Safety parent");
    #[cfg(unix)]
    fs::set_permissions(&safety_parent, fs::Permissions::from_mode(0o700))
        .expect("protect Safety parent");
    let safety_path = safety_parent.join("safety.sqlite3");

    let fixture = RealSafetyFixtureV0::new();
    let genesis_qc = GenesisQcV0::new(
        fixture.validator_set.genesis_hash(),
        fixture.validator_set.chain_id(),
        &fixture.validator_set,
    )
    .expect("valid genesis QC");
    let mut core = Core::new(fixture.config.clone(), genesis_qc, &StrictEd25519Verifier)
        .expect("fresh strict Core");
    let genesis_state = core.safety_state().clone();
    let profile = SafetyStateStoreProfileV0::new(
        fixture.config.clone(),
        [0xA7; 32],
        SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
            .expect("valid record limits"),
        192 * 1024 * 1024,
    )
    .expect("valid Safety profile");
    let mut safety = SqliteSafetyStateStoreV0::initialize_new(
        &safety_path,
        profile,
        StrictEd25519Verifier,
        &genesis_state,
    )
    .expect("initialize real Safety journal");
    safety
        .bind_core_v0(core.safety_state_persistence_binding_v0())
        .expect("bind exact live Core");
    let seal = core
        .issue_application_seal_authority_v0()
        .expect("issue one application seal");

    let (proposal, payload, receipts) = fixture.proposal();
    let effects = core
        .step(Input::Proposal(Box::new(proposal)), &StrictEd25519Verifier)
        .expect("proposal creates one durable validation obligation");
    let [Effect::PersistSafetyState(obligation)] = effects.as_slice() else {
        panic!("expected one proposal persistence effect: {effects:?}");
    };
    assert_eq!(
        safety
            .persist_exact_v0(obligation, &SafetyTransitionContextV0::Ordinary)
            .expect("persist exact obligation"),
        SafetyPersistDispositionV0::Inserted
    );
    let released = core
        .step(
            Input::StorageAck {
                barrier: obligation.barrier(),
            },
            &StrictEd25519Verifier,
        )
        .expect("release exact payload-validation request");
    let request = released
        .into_iter()
        .find_map(|effect| match effect {
            Effect::ValidatePayload(request) => Some(request),
            _ => None,
        })
        .expect("one Proposal validation request");
    let claimed = request.try_claim().expect("claim exact request");
    let (route, core_id, block, parent, permit) = claimed.into_parts();
    assert_eq!(route, PayloadValidationRouteV0::Proposal);

    let binding = ProposalValidationBindingV0::new(
        ChainIdV0::new(block.header().chain_id().as_str()).expect("native chain id"),
        GenesisHashV0::new(*block.header().genesis_hash().as_bytes()).expect("native genesis hash"),
        ApplicationHeadV0::new(
            HeightV0::GENESIS,
            BlockIdV0::new(*parent.tip().block_id().as_bytes()).expect("parent block"),
            StateRootV0::new([0x81; 32]).expect("parent state root"),
            ApplicationCommitIdV0::new([0x82; 32]).expect("parent commit"),
        ),
        BlockIdV0::new(*block.id().as_bytes()).expect("native block id"),
        HeightV0::new(block.header().height().get()),
        block.header().timestamp_ms(),
        ValidatorSetIdV0::new(*block.header().validator_set_id().as_bytes())
            .expect("native validator set"),
        core_id.view().get(),
        core_id.generation(),
        ProposalRouteV0::Proposal,
        NativeExpectedBlockCommitmentsV0::new(
            Hash32V0::new(*block.header().payload_root().as_bytes()),
            StateRootV0::new(*block.header().state_root().as_bytes()).expect("state root"),
            ReceiptsRootV0::new(*block.header().receipts_root().as_bytes()).expect("receipts root"),
            Hash32V0::new(*block.header().evidence_root().as_bytes()),
        )
        .expect("native commitments"),
    )
    .expect("exact proposal binding");
    let executed = exact_executed_for_consensus_payload_v0(&binding, &payload, &receipts);
    let mut validation = SqliteProposalValidationStoreV0::open(&validation_path, scope(0xB1), 0)
        .expect("open validation journal");
    let reserved = match validation
        .reserve_v0(&binding, owner(0xB2), &executed)
        .expect("reserve exact P")
    {
        ReservationOutcomeV0::Applied(reserved) => reserved,
        ReservationOutcomeV0::NotApplied => panic!("normal P reservation must apply"),
    };
    let body = BlockBodyV0::new(payload, Vec::new()).expect("canonical body");
    let commitments = body
        .validate_ordinary_commitments(
            block.header(),
            &receipts,
            &fixture.parameters,
            &fixture.validator_set,
            &StrictEd25519Verifier,
        )
        .expect("strict ordinary commitments");
    let sealed = seal.seal_after_application_store_commit_v0(
        permit,
        commitments,
        ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(block.id(), block.header().parent_id(), [0xC1; 32]),
            [0xC2; 32],
        ),
    );
    let accepted = core
        .step_application_sealed_valid_to_delivery_v0(&sealed, &StrictEd25519Verifier)
        .expect("Core mints opaque D authority");
    let delivered = match validation
        .deliver_core_accepted_v0(reserved, &binding, &accepted)
        .expect("persist exact Core D")
    {
        DeliverTransitionOutcomeV0::Applied(delivered) => delivered,
        DeliverTransitionOutcomeV0::NotApplied(_) => panic!("normal D transition must apply"),
    };
    let context = validation
        .native_valid_transition_context_exact_v0(&binding, &delivered, &accepted)
        .expect("derive exact D-bound Safety context");
    assert_eq!(
        safety
            .persist_exact_v0(accepted.persistence_request_v0(), &context)
            .expect("persist real Safety C"),
        SafetyPersistDispositionV0::Inserted
    );
    let acked = match validation
        .acknowledge_confirmed_safety_v0(delivered, &binding, &accepted, &safety, &safety_path)
        .expect("fresh-confirm C and close K")
    {
        AckTransitionOutcomeV0::Applied(acked) => acked,
        AckTransitionOutcomeV0::NotApplied(_) => panic!("normal K transition must apply"),
    };

    assert_eq!(
        acked.request_bound_safety_confirmation().safety_revision(),
        accepted.completion_revision_v0()
    );
    assert_eq!(
        acked
            .request_bound_safety_confirmation()
            .vote_intent_digest()
            .as_bytes(),
        core.safety_state()
            .pending_sign()
            .expect("Core retains the inert Vote intent")
            .signing_root()
            .as_bytes()
    );
    let checkpoint = validation
        .confirm_proposal_validation_checkpoint_facts_exact_v0(&binding)
        .expect("freshly confirm exact K facts");
    assert!(checkpoint.belongs_to_store_at_path_v0(&validation, &validation_path));
    assert_eq!(checkpoint.owner_id_v0(), owner(0xB2));
    assert_eq!(
        checkpoint.safety_closure_v0().safety_revision(),
        accepted.completion_revision_v0()
    );
    assert_eq!(
        safety.head().expect("real C head").revision(),
        accepted.completion_revision_v0()
    );
    assert_eq!(
        core.safety_state(),
        accepted.persistence_request_v0().state()
    );
    assert_eq!(validation.durable_sequence_v0().expect("K sequence"), 3);
    // Deliberately no Core StorageAck here. The pending Vote intent remains
    // durable comparison state only; this test cannot obtain RequestSignature.
}

fn deliver(
    store: &mut SqliteProposalValidationStoreV0,
    reserved: crate::ReservedValidationV0,
    delivery: CoreDeliveryConfirmationV0,
) -> crate::DeliveredValidationV0 {
    match store
        .deliver_v0(reserved, delivery)
        .expect("delivery must succeed")
    {
        DeliverTransitionOutcomeV0::Applied(token) => token,
        DeliverTransitionOutcomeV0::NotApplied(_) => panic!("normal delivery must apply"),
    }
}

#[test]
fn exact_reservation_d_c_k_lifecycle_survives_reopen_without_advancing_application_head() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("validation.sqlite3");
    let binding = binding(8, 9, 10);
    let mut store = SqliteProposalValidationStoreV0::open(&path, scope(1), 0).expect("open store");

    let reserved = reserve(&mut store, &binding);
    let expected_artifact = executed(&binding, 7);
    assert_eq!(
        store.read_artifact_exact_v0(&binding).expect("read P"),
        expected_artifact
    );
    let fact = store
        .inspect_exact_v0(&binding)
        .expect("inspect binding-digest reservation");
    assert_eq!(fact.stage(), DurableValidationStageV0::Reserved);
    assert!(!fact.outbox_present());
    assert_eq!(
        store
            .confirm_terminal_k_audit_v0()
            .expect_err("a live P row is not an all-terminal K cut")
            .code(),
        ValidationStoreErrorCodeV0::BindingMismatch
    );

    let delivery = core_delivery(binding.validation_id(), 11, 12);
    let delivered = deliver(&mut store, reserved, delivery);
    let fact = store.inspect_exact_v0(&binding).expect("inspect D");
    assert_eq!(fact.stage(), DurableValidationStageV0::Delivered);
    assert!(fact.outbox_present());

    let acked = match store
        .acknowledge_v0(delivered, &mut ExactSafetyReadbackV0::exact(11, 14))
        .expect("ack must succeed")
    {
        AckTransitionOutcomeV0::Applied(token) => token,
        AckTransitionOutcomeV0::NotApplied(_) => panic!("normal ack must apply"),
    };
    assert_eq!(acked.validation_id(), binding.validation_id());
    let live_safety = acked.request_bound_safety_confirmation();
    assert_eq!(live_safety.validation_id(), binding.validation_id());
    assert_eq!(live_safety.core_delivery_digest(), delivery.digest());
    assert_eq!(live_safety.safety_revision(), 11);
    assert_eq!(live_safety.safety_record_digest(), digest(14));
    assert_eq!(live_safety.vote_intent_digest(), digest(15));
    assert_eq!(store.durable_sequence_v0().expect("sequence"), 3);
    let live_checkpoint_facts = store
        .confirm_proposal_validation_checkpoint_facts_exact_v0(&binding)
        .expect("freshly confirm exact K checkpoint facts");
    assert!(live_checkpoint_facts.belongs_to_store_at_path_v0(&store, &path));
    assert_eq!(live_checkpoint_facts.scope_v0(), scope(1));
    assert_eq!(live_checkpoint_facts.binding_v0(), &binding);
    assert_eq!(live_checkpoint_facts.owner_id_v0(), owner(6));
    assert_eq!(live_checkpoint_facts.store_sequence_v0(), 3);
    assert!(live_checkpoint_facts.row_revision_v0() > 0);
    assert_eq!(
        live_checkpoint_facts.core_delivery_digest_v0(),
        delivery.digest()
    );
    let live_terminal_audit = store
        .confirm_terminal_k_audit_v0()
        .expect("freshly audit the complete terminal K store");
    assert!(live_terminal_audit.belongs_to_store_at_path_v0(&store, &path));
    assert_eq!(live_terminal_audit.scope_v0(), scope(1));
    assert_eq!(live_terminal_audit.store_id_v0(), store.store_id_v0());
    assert_eq!(live_terminal_audit.owner_id_v0(), owner(6));
    assert_eq!(live_terminal_audit.store_sequence_v0(), 3);
    assert_eq!(live_terminal_audit.terminal_row_count_v0(), 1);
    assert_eq!(
        live_terminal_audit.maximum_terminal_height_v0(),
        binding.height().get()
    );
    let live_checkpoint_closure = live_checkpoint_facts.safety_closure_v0();
    assert_eq!(
        live_checkpoint_closure.validation_id(),
        live_safety.validation_id()
    );
    assert_eq!(
        live_checkpoint_closure.core_delivery_digest(),
        live_safety.core_delivery_digest()
    );
    assert_eq!(
        live_checkpoint_closure.safety_revision(),
        live_safety.safety_revision()
    );
    assert_eq!(
        live_checkpoint_closure.safety_record_digest(),
        live_safety.safety_record_digest()
    );
    assert_eq!(
        live_checkpoint_closure.vote_intent_digest(),
        live_safety.vote_intent_digest()
    );
    drop(store);

    let mut reopened =
        SqliteProposalValidationStoreV0::open(&path, scope(1), 3).expect("reopen at floor");
    assert!(!live_checkpoint_facts.belongs_to_store_at_path_v0(&reopened, &path));
    assert!(!live_terminal_audit.belongs_to_store_at_path_v0(&reopened, &path));
    let old_owner_error = reopened
        .reconfirm_proposal_validation_checkpoint_facts_exact_v0(&live_checkpoint_facts)
        .expect_err("a dropped owner cannot lend authority to a reopened store");
    assert_eq!(
        old_owner_error.code(),
        ValidationStoreErrorCodeV0::ForeignToken
    );
    let fact = reopened.inspect_exact_v0(&binding).expect("inspect K");
    assert_eq!(fact.stage(), DurableValidationStageV0::Acked);
    assert!(!fact.outbox_present());
    assert_eq!(fact.store_sequence(), 3);
    let closure = reopened
        .inspect_request_bound_safety_closure_exact_v0(&binding)
        .expect("reconstruct exact C provenance from K");
    assert_eq!(closure.validation_id(), binding.validation_id());
    assert_eq!(closure.core_delivery_digest(), delivery.digest());
    assert_eq!(closure.safety_revision(), 11);
    assert_eq!(closure.safety_record_digest(), digest(14));
    assert_eq!(closure.vote_intent_digest(), digest(15));
    let reopened_checkpoint_facts = reopened
        .confirm_proposal_validation_checkpoint_facts_exact_v0(&binding)
        .expect("issue fresh K checkpoint facts after reopen");
    assert_eq!(reopened_checkpoint_facts.owner_id_v0(), owner(6));
    assert_eq!(reopened_checkpoint_facts.store_sequence_v0(), 3);
    assert!(!reopened_checkpoint_facts.belongs_to_store_at_path_v0(
        // The prior owner was dropped, so only the reopened store may issue a
        // capability that passes owner affinity.
        &reopened,
        &path.with_extension("foreign")
    ));
    let reconfirmed = reopened
        .reconfirm_proposal_validation_checkpoint_facts_exact_v0(&reopened_checkpoint_facts)
        .expect("fresh owner may reconfirm unchanged terminal K");
    assert_eq!(
        reconfirmed.row_checksum_v0(),
        reopened_checkpoint_facts.row_checksum_v0()
    );
    assert_eq!(reconfirmed.owner_id_v0(), owner(6));
    assert_eq!(
        reconfirmed.artifact_digest_v0(),
        reopened_checkpoint_facts.artifact_digest_v0()
    );
    assert_eq!(
        reopened
            .read_artifact_exact_v0(&binding)
            .expect("reconstruct P after reopen"),
        expected_artifact
    );
}

#[test]
fn replay_sidecar_reserves_one_alias_without_copying_the_canonical_job() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("replay-sidecar-p.sqlite3");
    let source = binding(40, 41, 0x81);
    let target = synced_replay_binding(&source, 42);
    let expected_artifact = executed(&source, 7);
    let mut store =
        SqliteProposalValidationStoreV0::open(&path, scope(0x41), 0).expect("open store");

    let reserved = reserve(&mut store, &source);
    let delivered = deliver(
        &mut store,
        reserved,
        core_delivery(source.validation_id(), 43, 0x82),
    );
    match store
        .acknowledge_v0(delivered, &mut ExactSafetyReadbackV0::exact(43, 0x84))
        .expect("close source K")
    {
        AckTransitionOutcomeV0::Applied(_) => {}
        AckTransitionOutcomeV0::NotApplied(_) => panic!("normal source K must apply"),
    }

    let terminal = store
        .confirm_terminal_k_audit_v0()
        .expect("fresh terminal inventory");
    let session = match store
        .begin_replay_session_v0(terminal, replay_plan(1))
        .expect("open exact replay O")
    {
        ReplaySessionOpenOutcomeV0::Applied(session) => session,
        ReplaySessionOpenOutcomeV0::Existing(_) => panic!("fresh O cannot preexist"),
        ReplaySessionOpenOutcomeV0::NotApplied => panic!("normal O must apply"),
    };
    let expected_session_id = session.session_id_v0();
    let source_k = store
        .confirm_proposal_validation_checkpoint_facts_exact_v0(&source)
        .expect("fresh source K");
    let replay_p = match store
        .reserve_synced_replay_link_v0(session, source_k, digest(0xBD), &target, owner(6))
        .expect("reserve replay sidecar P")
    {
        ReplayLinkReservationOutcomeV0::Applied(replay_p) => replay_p,
        ReplayLinkReservationOutcomeV0::Existing(_) => panic!("fresh replay P cannot preexist"),
        ReplayLinkReservationOutcomeV0::NotApplied => panic!("normal replay P must apply"),
    };
    let live_inventory = store
        .confirm_replay_inventory_v0()
        .expect("fresh owner-affined replay inventory");
    assert!(live_inventory.belongs_to_store_at_path_v0(&store, &path));
    assert_eq!(
        live_inventory.session_v0().session_id_v0(),
        expected_session_id
    );
    assert_eq!(live_inventory.session_v0().next_cursor_v0(), 0);
    assert!(!live_inventory.session_v0().is_durable_complete_v0());
    assert_eq!(live_inventory.links_v0().len(), 1);
    assert_eq!(
        live_inventory.links_v0()[0].stage_v0(),
        DurableReplayLinkStageV0::Reserved
    );
    assert_eq!(live_inventory.links_v0()[0].cursor_v0(), 0);
    assert_eq!(live_inventory.links_v0()[0].target_binding_v0(), &target);
    assert_eq!(replay_p.session_id_v0(), expected_session_id);
    assert_eq!(replay_p.cursor_v0(), 0);
    assert_eq!(replay_p.source_validation_id_v0(), source.validation_id());
    assert_eq!(replay_p.target_validation_id_v0(), target.validation_id());
    assert_eq!(
        store
            .read_replay_artifact_exact_v0(&replay_p, &target)
            .expect("read source artifact through exact replay P"),
        expected_artifact
    );
    assert_eq!(
        store.durable_sequence_v0().expect("canonical sequence"),
        3,
        "sidecar P must not advance canonical job sequence"
    );
    let terminal_after = store
        .confirm_terminal_k_audit_v0()
        .expect("canonical inventory remains terminal");
    assert_eq!(terminal_after.store_sequence_v0(), 3);
    assert_eq!(terminal_after.terminal_row_count_v0(), 1);
    assert_eq!(
        store
            .inspect_exact_v0(&target)
            .expect_err("replay target must not become a canonical job")
            .code(),
        ValidationStoreErrorCodeV0::NotFound
    );
    drop(store);

    let mut reopened =
        SqliteProposalValidationStoreV0::open(&path, scope(0x41), 3).expect("reopen store");
    assert!(!live_inventory.belongs_to_store_at_path_v0(&reopened, &path));
    let reopened_inventory = reopened
        .confirm_replay_inventory_v0()
        .expect("fresh reopened replay inventory");
    assert!(reopened_inventory.belongs_to_store_at_path_v0(&reopened, &path));
    assert_eq!(
        reopened_inventory.session_v0().session_id_v0(),
        expected_session_id
    );
    assert_eq!(reopened_inventory.links_v0().len(), 1);
    let terminal = reopened
        .confirm_terminal_k_audit_v0()
        .expect("fresh reopened terminal inventory");
    match reopened
        .resume_replay_session_v0(terminal, replay_plan(1))
        .expect("resume exact durable P frontier")
    {
        ReplaySessionResumeOutcomeV0::Reserved(recovered) => {
            assert_eq!(recovered.session_id_v0(), expected_session_id);
            assert_eq!(recovered.cursor_v0(), 0);
            assert_eq!(recovered.source_validation_id_v0(), source.validation_id());
            assert_eq!(recovered.target_validation_id_v0(), target.validation_id());
        }
        other => panic!("expected exact replay P frontier, got {other:?}"),
    }
}

#[test]
fn replay_activation_ready_cas_transaction_matrix_v0() {
    let success_directory = TestDirectoryV0::new();
    let success_path = success_directory.database("activation-success.sqlite3");
    let (mut success, binding, conflicting) =
        completed_replay_activation_fixture(&success_path, 0x51, 0x41);
    assert_eq!(
        binding.selected_replay_digest_v0(),
        conflicting.selected_replay_digest_v0(),
        "same selected replay isolates the signer-inventory substitution",
    );
    assert_ne!(
        binding.signer_inventory_digest_v1(),
        conflicting.signer_inventory_digest_v1(),
        "the fixture isolates an opaque signer-inventory digest substitution",
    );
    assert_ne!(
        binding.binding_digest_v0(),
        conflicting.binding_digest_v0(),
        "the canonical activation binding must commit to signer inventory",
    );
    let source = success
        .confirm_replay_inventory_v0()
        .expect("fresh durable-complete source");
    let source_facts = source.session_v0();
    let ready = success
        .confirm_replay_activation_ready_v0(source, binding)
        .expect("fresh activation CAS applies");
    assert!(ready.belongs_to_store_at_path_v0(&success, &success_path));
    assert_eq!(ready.binding_v0(), binding);
    assert_eq!(ready.row_revision_v0(), source_facts.row_revision_v0() + 1);
    let ready_facts = success
        .confirm_replay_inventory_v0()
        .expect("fresh activation-ready target")
        .session_v0();
    assert!(ready_facts.is_activation_ready_v0());
    assert_eq!(
        ready_facts.activation_source_row_revision_v0(),
        Some(source_facts.row_revision_v0())
    );
    assert_eq!(
        ready_facts.activation_source_row_checksum_v0(),
        Some(source_facts.row_checksum_v0())
    );
    let retry_inventory = success
        .confirm_replay_inventory_v0()
        .expect("fresh exact-retry inventory");
    let exact_retry = success
        .confirm_replay_activation_ready_v0(retry_inventory, binding)
        .expect("exact activation retry is idempotent");
    assert_eq!(exact_retry.row_revision_v0(), ready.row_revision_v0());
    assert_eq!(exact_retry.row_checksum_v0(), ready.row_checksum_v0());
    let conflict_inventory = success
        .confirm_replay_inventory_v0()
        .expect("fresh conflicting inventory");
    let conflict = success
        .confirm_replay_activation_ready_v0(conflict_inventory, conflicting)
        .expect_err("another signer-inventory binding must not replace activation-ready");
    assert_eq!(conflict.code(), ValidationStoreErrorCodeV0::Duplicate);

    let not_applied_directory = TestDirectoryV0::new();
    let not_applied_path = not_applied_directory.database("activation-not-applied.sqlite3");
    let (mut not_applied, binding, _) =
        completed_replay_activation_fixture(&not_applied_path, 0x52, 0x42);
    let source_facts = not_applied
        .confirm_replay_inventory_v0()
        .expect("fresh not-applied source")
        .session_v0();
    not_applied.inject_next_commit_fault_v0(TestCommitFaultV0::NotAppliedAckLost);
    let not_applied_inventory = not_applied
        .confirm_replay_inventory_v0()
        .expect("fresh not-applied inventory");
    let error = not_applied
        .confirm_replay_activation_ready_v0(not_applied_inventory, binding)
        .expect_err("lost acknowledgement before commit must report uncertain source");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::CommitUncertain);
    drop(not_applied);
    let mut not_applied = SqliteProposalValidationStoreV0::open(&not_applied_path, scope(0x52), 3)
        .expect("reopen confirmed source after acknowledgement loss");
    let observed_source = not_applied
        .confirm_replay_inventory_v0()
        .expect("source remains freshly readable")
        .session_v0();
    assert!(observed_source.is_durable_complete_v0());
    assert!(!observed_source.is_activation_ready_v0());
    assert_eq!(
        observed_source.row_revision_v0(),
        source_facts.row_revision_v0()
    );
    assert_eq!(
        observed_source.row_checksum_v0(),
        source_facts.row_checksum_v0()
    );
    let retry_source = not_applied
        .confirm_replay_inventory_v0()
        .expect("fresh retry source");
    let _activation_ready = not_applied
        .confirm_replay_activation_ready_v0(retry_source, binding)
        .expect("retry after confirmed source applies");

    let applied_directory = TestDirectoryV0::new();
    let applied_path = applied_directory.database("activation-applied.sqlite3");
    let (mut applied, binding, _) = completed_replay_activation_fixture(&applied_path, 0x53, 0x43);
    let source_revision = applied
        .confirm_replay_inventory_v0()
        .expect("fresh applied source")
        .session_v0()
        .row_revision_v0();
    applied.inject_next_commit_fault_v0(TestCommitFaultV0::AppliedAckLost);
    let applied_inventory = applied
        .confirm_replay_inventory_v0()
        .expect("fresh applied inventory");
    let recovered_target = applied
        .confirm_replay_activation_ready_v0(applied_inventory, binding)
        .expect("lost post-commit acknowledgement recognizes exact target");
    assert_eq!(recovered_target.row_revision_v0(), source_revision + 1);
    drop(applied);
    let mut applied = SqliteProposalValidationStoreV0::open(&applied_path, scope(0x53), 3)
        .expect("reopen recognized activation target");
    assert!(applied
        .confirm_replay_inventory_v0()
        .expect("fresh recovered target")
        .session_v0()
        .is_activation_ready_v0());

    let third_directory = TestDirectoryV0::new();
    let third_path = third_directory.database("activation-third-state.sqlite3");
    let (mut third, binding, _) = completed_replay_activation_fixture(&third_path, 0x55, 0x45);
    let third_inventory = third
        .confirm_replay_inventory_v0()
        .expect("fresh third-state source");
    third.inject_next_commit_fault_v0(TestCommitFaultV0::ThirdState);
    let error = third
        .confirm_replay_activation_ready_v0(third_inventory, binding)
        .expect_err("third durable activation row must release no carrier");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::CommitUncertain);
    assert_eq!(
        third
            .durable_sequence_v0()
            .expect_err("third-state handle remains permanently fenced")
            .code(),
        ValidationStoreErrorCodeV0::CommitUncertain
    );
    drop(third);
    let error = match SqliteProposalValidationStoreV0::open(&third_path, scope(0x55), 3) {
        Ok(_) => panic!("third durable activation row must fail fresh reopen"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::CorruptStore);

    for (name, column) in [
        (
            "activation-source-revision.sqlite3",
            "activation_source_row_revision",
        ),
        (
            "activation-source-checksum.sqlite3",
            "activation_source_row_checksum",
        ),
    ] {
        let directory = TestDirectoryV0::new();
        let path = directory.database(name);
        let (mut store, binding, _) = completed_replay_activation_fixture(&path, 0x54, 0x44);
        let tamper_source = store
            .confirm_replay_inventory_v0()
            .expect("fresh tamper source");
        let _activation_ready = store
            .confirm_replay_activation_ready_v0(tamper_source, binding)
            .expect("write activation-ready target");
        drop(store);
        let connection = rusqlite::Connection::open(&path).expect("open raw activation store");
        let sql = format!(
            "UPDATE proposal_validation_replay_session_v0 SET {column} = ?1 WHERE singleton = 1"
        );
        let mutant = if column == "activation_source_row_revision" {
            99_u64.to_be_bytes().to_vec()
        } else {
            vec![0xDD; 32]
        };
        connection
            .execute(&sql, rusqlite::params![mutant])
            .expect("mutate exactly one retained predecessor field");
        drop(connection);
        let error = match SqliteProposalValidationStoreV0::open(&path, scope(0x54), 3) {
            Ok(_) => panic!("single-field predecessor mutant must fail reopen"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ValidationStoreErrorCodeV0::CorruptStore);
    }
}

#[test]
fn replay_session_rejects_expected_count_larger_than_terminal_inventory() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("replay-session-count.sqlite3");
    let source = binding(50, 51, 0x91);
    let mut store =
        SqliteProposalValidationStoreV0::open(&path, scope(0x42), 0).expect("open store");
    let reserved = reserve(&mut store, &source);
    let delivered = deliver(
        &mut store,
        reserved,
        core_delivery(source.validation_id(), 52, 0x92),
    );
    match store
        .acknowledge_v0(delivered, &mut ExactSafetyReadbackV0::exact(52, 0x94))
        .expect("close source K")
    {
        AckTransitionOutcomeV0::Applied(_) => {}
        AckTransitionOutcomeV0::NotApplied(_) => panic!("normal source K must apply"),
    }
    let terminal = store
        .confirm_terminal_k_audit_v0()
        .expect("fresh terminal inventory");
    assert_eq!(
        store
            .begin_replay_session_v0(terminal, replay_plan(2))
            .expect_err("replay cannot exceed the frozen terminal inventory")
            .code(),
        ValidationStoreErrorCodeV0::BindingMismatch
    );
    assert_eq!(
        store
            .replay_session_presence_v0()
            .expect("session presence remains readable"),
        crate::ReplaySessionPresenceV0::None
    );
    assert_eq!(store.durable_sequence_v0().expect("canonical sequence"), 3);
}

#[test]
fn anchored_successor_terminal_k_reconstructs_exact_no_sign_native_valid_context() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("anchored-successor-k.sqlite3");
    let binding = binding_full_route(8, 9, 10, 1_700_000_000_000, 0x42, ProposalRouteV0::Synced);
    let mut store =
        SqliteProposalValidationStoreV0::open(&path, scope(0x31), 0).expect("open store");
    let reserved = reserve(&mut store, &binding);
    let delivery = core_delivery(binding.validation_id(), 2, 12);
    let delivered = deliver(&mut store, reserved, delivery);
    match store
        .acknowledge_v0(delivered, &mut ExactSafetyReadbackV0::exact(2, 14))
        .expect("close terminal K fixture")
    {
        AckTransitionOutcomeV0::Applied(_) => {}
        AckTransitionOutcomeV0::NotApplied(_) => panic!("normal K transition must apply"),
    }
    drop(store);
    rewrite_anchor_successor_no_sign_closure_for_test_v0(&path, &binding)
        .expect("rewrite exact anchored no-sign closure");

    let mut reopened = SqliteProposalValidationStoreV0::open(&path, scope(0x31), 3)
        .expect("reopen anchored terminal K");
    let context = reopened
        .reconstruct_anchor_successor_native_valid_context_from_k_v0(&binding)
        .expect("reconstruct exact anchored NativeValid context");
    let transition = context
        .native_valid_transition()
        .expect("reconstructed context is NativeValid");
    assert_eq!(transition.route(), PayloadValidationRouteV0::Synced);
    assert_eq!(
        transition.validation_id().block_id().as_bytes(),
        binding.block_id().as_bytes()
    );
    assert_eq!(transition.validation_id().view().get(), binding.view());
    assert_eq!(
        transition.validation_id().generation(),
        binding.generation()
    );
    assert_eq!(transition.completion_revision(), 2);
    assert_eq!(
        transition.post_ack_action_code(),
        NativeValidPostAckActionV0::None.code()
    );
    let closure = reopened
        .inspect_request_bound_safety_closure_exact_v0(&binding)
        .expect("terminal K retains exact safety closure");
    assert_eq!(closure.safety_revision(), 2);
    assert_eq!(closure.core_delivery_digest(), delivery.digest());
}

#[test]
fn checkpoint_facts_are_owner_affine_and_global_sequence_fresh() {
    let first_directory = TestDirectoryV0::new();
    let second_directory = TestDirectoryV0::new();
    let first_path = first_directory.database("checkpoint-first.sqlite3");
    let second_path = second_directory.database("checkpoint-second.sqlite3");
    let first_binding = binding(30, 31, 110);
    let second_binding = binding(32, 33, 120);
    let mut first =
        SqliteProposalValidationStoreV0::open(&first_path, scope(24), 0).expect("first store");
    let mut second =
        SqliteProposalValidationStoreV0::open(&second_path, scope(24), 0).expect("second store");

    let first_reserved = reserve(&mut first, &first_binding);
    let first_delivered = deliver(
        &mut first,
        first_reserved,
        core_delivery(first_binding.validation_id(), 4, 111),
    );
    match first
        .acknowledge_v0(first_delivered, &mut ExactSafetyReadbackV0::exact(4, 113))
        .expect("close first K")
    {
        AckTransitionOutcomeV0::Applied(_) => {}
        AckTransitionOutcomeV0::NotApplied(_) => panic!("normal ack must apply"),
    }
    let prior = first
        .confirm_proposal_validation_checkpoint_facts_exact_v0(&first_binding)
        .expect("confirm first K");

    assert!(!prior.belongs_to_store_at_path_v0(&second, &second_path));
    let foreign_error = second
        .reconfirm_proposal_validation_checkpoint_facts_exact_v0(&prior)
        .expect_err("another live owner cannot reconfirm the capability");
    assert_eq!(
        foreign_error.code(),
        ValidationStoreErrorCodeV0::ForeignToken
    );

    let second_reserved = reserve(&mut first, &second_binding);
    let second_delivered = deliver(
        &mut first,
        second_reserved,
        core_delivery(second_binding.validation_id(), 5, 121),
    );
    match first
        .acknowledge_v0(second_delivered, &mut ExactSafetyReadbackV0::exact(5, 123))
        .expect("close second K")
    {
        AckTransitionOutcomeV0::Applied(_) => {}
        AckTransitionOutcomeV0::NotApplied(_) => panic!("normal ack must apply"),
    }
    let stale_error = first
        .reconfirm_proposal_validation_checkpoint_facts_exact_v0(&prior)
        .expect_err("global store sequence advance invalidates the prior facts");
    assert_eq!(
        stale_error.code(),
        ValidationStoreErrorCodeV0::BindingMismatch
    );
}

#[test]
fn every_request_coordinate_changes_the_validation_identity() {
    let base = binding(8, 9, 10);
    assert_ne!(base.validation_id(), binding(9, 9, 10).validation_id());
    assert_ne!(base.validation_id(), binding(8, 10, 10).validation_id());
    assert_ne!(base.validation_id(), binding(8, 9, 20).validation_id());
    assert_ne!(
        base.validation_id(),
        binding_full(8, 9, 10, 1_700_000_000_001, 0x42).validation_id()
    );
    assert_ne!(
        base.validation_id(),
        binding_full(8, 9, 10, 1_700_000_000_000, 0x43).validation_id()
    );

    let parent = ApplicationHeadV0::new(
        HeightV0::new(1),
        BlockIdV0::new([1; 32]).expect("block"),
        StateRootV0::new([2; 32]).expect("state"),
        ApplicationCommitIdV0::new([3; 32]).expect("commit"),
    );
    let commitments = NativeExpectedBlockCommitmentsV0::new(
        Hash32V0::new([10; 32]),
        StateRootV0::new([11; 32]).expect("state"),
        ReceiptsRootV0::new([12; 32]).expect("receipts"),
        Hash32V0::new([13; 32]),
    )
    .expect("commitments");
    let error = ProposalValidationBindingV0::new(
        ChainIdV0::new("trnm-validation-test").expect("chain"),
        GenesisHashV0::new([4; 32]).expect("genesis"),
        parent,
        BlockIdV0::new([5; 32]).expect("block"),
        HeightV0::new(1),
        1_700_000_000_000,
        ValidatorSetIdV0::new([0x42; 32]).expect("validator set"),
        8,
        9,
        ProposalRouteV0::Proposal,
        commitments,
    )
    .expect_err("noncontiguous parent must fail");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::InvalidBinding);
}

#[test]
fn reservation_rejects_artifact_substitution_before_any_durable_write() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("substitution.sqlite3");
    let binding = binding(20, 21, 90);
    let foreign_binding = binding_full(20, 21, 90, binding.timestamp_ms() + 1, 0x42);
    let foreign_artifact = executed(&foreign_binding, 7);
    let mut store = SqliteProposalValidationStoreV0::open(&path, scope(15), 0).expect("open store");
    let error = store
        .reserve_v0(&binding, owner(6), &foreign_artifact)
        .expect_err("substituted execution artifact must fail");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::BindingMismatch);
    assert_eq!(store.durable_sequence_v0().expect("unchanged sequence"), 0);
    assert_eq!(
        store
            .inspect_exact_v0(&binding)
            .expect_err("no P written")
            .code(),
        ValidationStoreErrorCodeV0::NotFound
    );
}

#[test]
fn core_delivery_for_another_validation_cannot_cross_replay_into_d() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("cross-p-delivery.sqlite3");
    let first_binding = binding(21, 22, 91);
    let second_binding = binding(21, 23, 91);
    let mut store = SqliteProposalValidationStoreV0::open(&path, scope(20), 0).expect("open store");
    let reserved = reserve(&mut store, &second_binding);
    let error = store
        .deliver_v0(
            reserved,
            core_delivery(first_binding.validation_id(), 1, 92),
        )
        .expect_err("D for another P must fail before journal mutation");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::BindingMismatch);
    let fact = store
        .inspect_exact_v0(&second_binding)
        .expect("second P remains reserved");
    assert_eq!(fact.stage(), DurableValidationStageV0::Reserved);
    assert!(!fact.outbox_present());
    assert_eq!(fact.store_sequence(), 1);
}

#[test]
fn duplicate_stale_and_foreign_tokens_fail_closed() {
    let first_directory = TestDirectoryV0::new();
    let second_directory = TestDirectoryV0::new();
    let first_path = first_directory.database("first.sqlite3");
    let second_path = second_directory.database("second.sqlite3");
    let first_binding = binding(1, 1, 30);
    let mut first =
        SqliteProposalValidationStoreV0::open(&first_path, scope(2), 0).expect("first store");
    let mut second =
        SqliteProposalValidationStoreV0::open(&second_path, scope(2), 0).expect("second store");

    let reserved = reserve(&mut first, &first_binding);
    let stale = duplicate_reserved_for_test_v0(&reserved);
    let duplicate_error = first
        .reserve_v0(&first_binding, owner(6), &executed(&first_binding, 7))
        .expect_err("duplicate validation id must fail");
    assert_eq!(
        duplicate_error.code(),
        ValidationStoreErrorCodeV0::Duplicate
    );
    let delivered = deliver(
        &mut first,
        reserved,
        core_delivery(first_binding.validation_id(), 2, 31),
    );
    let stale_error = first
        .deliver_v0(stale, core_delivery(first_binding.validation_id(), 2, 31))
        .expect_err("stale reservation token must fail");
    assert_eq!(
        stale_error.code(),
        ValidationStoreErrorCodeV0::InvalidTransition
    );

    let second_binding = binding(2, 1, 30);
    let foreign = reserve(&mut first, &second_binding);
    let foreign_error = second
        .deliver_v0(
            foreign,
            core_delivery(second_binding.validation_id(), 3, 32),
        )
        .expect_err("foreign store token must fail");
    assert_eq!(
        foreign_error.code(),
        ValidationStoreErrorCodeV0::ForeignToken
    );
    assert_eq!(delivered.validation_id(), first_binding.validation_id());
}

#[test]
fn foreign_delivered_token_cannot_enter_k() {
    let first_directory = TestDirectoryV0::new();
    let second_directory = TestDirectoryV0::new();
    let first_path = first_directory.database("foreign-delivered-first.sqlite3");
    let second_path = second_directory.database("foreign-delivered-second.sqlite3");
    let binding = binding(22, 24, 93);
    let mut first =
        SqliteProposalValidationStoreV0::open(&first_path, scope(21), 0).expect("first store");
    let mut second =
        SqliteProposalValidationStoreV0::open(&second_path, scope(21), 0).expect("second store");
    let reserved = reserve(&mut first, &binding);
    let delivered = deliver(
        &mut first,
        reserved,
        core_delivery(binding.validation_id(), 2, 94),
    );
    let error = second
        .acknowledge_v0(delivered, &mut ExactSafetyReadbackV0::exact(2, 95))
        .expect_err("foreign D carrier must fail before Safety readback can close K");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::ForeignToken);
    assert_eq!(second.durable_sequence_v0().expect("second sequence"), 0);
    let first_fact = first.inspect_exact_v0(&binding).expect("first D remains");
    assert_eq!(first_fact.stage(), DurableValidationStageV0::Delivered);
    assert!(first_fact.outbox_present());
}

#[test]
fn safety_confirmation_mismatch_does_not_close_k() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("confirmation.sqlite3");
    let binding = binding(3, 4, 40);
    let mut store = SqliteProposalValidationStoreV0::open(&path, scope(3), 0).expect("open store");
    let reserved = reserve(&mut store, &binding);
    let delivered = deliver(
        &mut store,
        reserved,
        core_delivery(binding.validation_id(), 5, 41),
    );
    let mut wrong_readback = ExactSafetyReadbackV0::exact(5, 41);
    wrong_readback.wrong_delivery_digest = Some(digest(99));
    let error = store
        .acknowledge_v0(delivered, &mut wrong_readback)
        .expect_err("Safety readback for a different D must fail");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::BindingMismatch);
    let fact = store.inspect_exact_v0(&binding).expect("D remains durable");
    assert_eq!(fact.stage(), DurableValidationStageV0::Delivered);
    assert!(fact.outbox_present());
    assert_eq!(
        store
            .inspect_request_bound_safety_closure_exact_v0(&binding)
            .expect_err("D must not expose terminal C provenance")
            .code(),
        ValidationStoreErrorCodeV0::InvalidTransition
    );
}

#[test]
fn safety_revision_must_equal_the_exact_core_delivery_revision() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("wrong-safety-revision.sqlite3");
    let binding = binding(23, 25, 96);
    let mut store = SqliteProposalValidationStoreV0::open(&path, scope(22), 0).expect("open store");
    let reserved = reserve(&mut store, &binding);
    let delivered = deliver(
        &mut store,
        reserved,
        core_delivery(binding.validation_id(), 7, 97),
    );
    let error = store
        .acknowledge_v0(delivered, &mut ExactSafetyReadbackV0::exact(8, 98))
        .expect_err("C-shaped readback for another revision must fail");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::BindingMismatch);
    let fact = store.inspect_exact_v0(&binding).expect("D remains durable");
    assert_eq!(fact.stage(), DurableValidationStageV0::Delivered);
    assert!(fact.outbox_present());
}

#[test]
fn persisted_safety_confirmation_tampering_is_detected_on_reopen() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("safety-tamper.sqlite3");
    let binding = binding(4, 5, 45);
    let mut store = SqliteProposalValidationStoreV0::open(&path, scope(18), 0).expect("open store");
    let reserved = reserve(&mut store, &binding);
    let delivered = deliver(
        &mut store,
        reserved,
        core_delivery(binding.validation_id(), 6, 46),
    );
    match store
        .acknowledge_v0(delivered, &mut ExactSafetyReadbackV0::exact(6, 48))
        .expect("close K")
    {
        AckTransitionOutcomeV0::Applied(_) => {}
        AckTransitionOutcomeV0::NotApplied(_) => panic!("normal ack must apply"),
    }
    drop(store);

    let connection = rusqlite::Connection::open(&path).expect("open raw database");
    connection
        .execute(
            "UPDATE proposal_validation_jobs_v0 SET safety_record_digest = ?1",
            rusqlite::params![[0x77u8; 32].as_slice()],
        )
        .expect("tamper persisted C provenance");
    drop(connection);

    let error = match SqliteProposalValidationStoreV0::open(&path, scope(18), 0) {
        Ok(_) => panic!("tampered C provenance must fail audit"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::CorruptStore);
}

#[test]
fn self_consistent_safety_delivery_substitution_is_rejected_on_reopen() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("safety-delivery-substitution.sqlite3");
    let binding = binding(5, 6, 50);
    let mut store = SqliteProposalValidationStoreV0::open(&path, scope(19), 0).expect("open store");
    let reserved = reserve(&mut store, &binding);
    let delivered = deliver(
        &mut store,
        reserved,
        core_delivery(binding.validation_id(), 7, 51),
    );
    match store
        .acknowledge_v0(delivered, &mut ExactSafetyReadbackV0::exact(7, 53))
        .expect("close K")
    {
        AckTransitionOutcomeV0::Applied(_) => {}
        AckTransitionOutcomeV0::NotApplied(_) => panic!("normal ack must apply"),
    }
    drop(store);

    rewrite_safety_core_delivery_self_consistent_for_test_v0(
        &path,
        binding.validation_id(),
        [0x88; 32],
    )
    .expect("write internally checksummed but D-inconsistent C provenance");
    let error = match SqliteProposalValidationStoreV0::open(&path, scope(19), 0) {
        Ok(_) => panic!("C provenance for another D must fail audit"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::CorruptStore);
}

#[test]
fn ack_loss_resolves_only_exact_source_or_target_using_a_fresh_connection() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("uncertainty.sqlite3");
    let binding = binding(5, 6, 50);
    let mut store = SqliteProposalValidationStoreV0::open(&path, scope(4), 0).expect("open store");

    store.inject_next_commit_fault_v0(TestCommitFaultV0::AppliedAckLost);
    let reserved = match store
        .reserve_v0(&binding, owner(6), &executed(&binding, 7))
        .expect("target readback must recover the reservation")
    {
        ReservationOutcomeV0::Applied(token) => token,
        ReservationOutcomeV0::NotApplied => panic!("committed reservation must be target"),
    };

    store.inject_next_commit_fault_v0(TestCommitFaultV0::NotAppliedAckLost);
    let reserved = match store
        .deliver_v0(reserved, core_delivery(binding.validation_id(), 7, 51))
        .expect("source readback must recover the reservation")
    {
        DeliverTransitionOutcomeV0::NotApplied(token) => token,
        DeliverTransitionOutcomeV0::Applied(_) => panic!("rolled back delivery must be source"),
    };
    assert_eq!(
        store.inspect_exact_v0(&binding).expect("inspect").stage(),
        DurableValidationStageV0::Reserved
    );

    let delivered = deliver(
        &mut store,
        reserved,
        core_delivery(binding.validation_id(), 7, 51),
    );
    store.inject_next_commit_fault_v0(TestCommitFaultV0::NotAppliedAckLost);
    let delivered = match store
        .acknowledge_v0(delivered, &mut ExactSafetyReadbackV0::exact(7, 53))
        .expect("source readback must recover D")
    {
        AckTransitionOutcomeV0::NotApplied(token) => token,
        AckTransitionOutcomeV0::Applied(_) => panic!("rolled back ack must remain D"),
    };
    let fact = store.inspect_exact_v0(&binding).expect("inspect D source");
    assert_eq!(fact.stage(), DurableValidationStageV0::Delivered);
    assert!(fact.outbox_present());

    store.inject_next_commit_fault_v0(TestCommitFaultV0::AppliedAckLost);
    match store
        .acknowledge_v0(delivered, &mut ExactSafetyReadbackV0::exact(7, 53))
        .expect("target readback must recover K")
    {
        AckTransitionOutcomeV0::Applied(_) => {}
        AckTransitionOutcomeV0::NotApplied(_) => panic!("committed ack must be target"),
    }
    assert_eq!(
        store.inspect_exact_v0(&binding).expect("inspect").stage(),
        DurableValidationStageV0::Acked
    );
    drop(store);

    let mut reopened =
        SqliteProposalValidationStoreV0::open(&path, scope(4), 3).expect("reopen recovered K");
    let closure = reopened
        .inspect_request_bound_safety_closure_exact_v0(&binding)
        .expect("request-bound closure survives reopen");
    assert_eq!(closure.validation_id(), binding.validation_id());
    assert_eq!(
        closure.core_delivery_digest(),
        core_delivery(binding.validation_id(), 7, 51).digest()
    );
    assert_eq!(closure.safety_revision(), 7);
    assert_eq!(closure.safety_record_digest(), digest(53));
    assert_eq!(closure.vote_intent_digest(), digest(54));
}

#[test]
fn third_state_during_uncertain_ack_fences_and_reopen_rejects_it() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("ack-third-state.sqlite3");
    let binding = binding(24, 26, 99);
    let mut store = SqliteProposalValidationStoreV0::open(&path, scope(23), 0).expect("open store");
    let reserved = reserve(&mut store, &binding);
    let delivered = deliver(
        &mut store,
        reserved,
        core_delivery(binding.validation_id(), 3, 100),
    );
    store.inject_next_commit_fault_v0(TestCommitFaultV0::ThirdState);
    let error = store
        .acknowledge_v0(delivered, &mut ExactSafetyReadbackV0::exact(3, 101))
        .expect_err("third state must never release K");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::CommitUncertain);
    assert_eq!(
        store
            .durable_sequence_v0()
            .expect_err("handle remains fenced")
            .code(),
        ValidationStoreErrorCodeV0::CommitUncertain
    );
    drop(store);
    let reopened = SqliteProposalValidationStoreV0::open(&path, scope(23), 0);
    let error = match reopened {
        Ok(_) => panic!("third durable state must fail reopen audit"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::CorruptStore);
}

#[test]
fn third_state_during_uncertain_commit_permanently_fences_the_handle() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("third-state.sqlite3");
    let binding = binding(7, 8, 60);
    let mut store = SqliteProposalValidationStoreV0::open(&path, scope(5), 0).expect("open store");
    let reserved = reserve(&mut store, &binding);

    store.inject_next_commit_fault_v0(TestCommitFaultV0::ThirdState);
    let error = store
        .deliver_v0(reserved, core_delivery(binding.validation_id(), 9, 61))
        .expect_err("third state must not be accepted");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::CommitUncertain);
    let fenced = store
        .durable_sequence_v0()
        .expect_err("handle must remain fenced");
    assert_eq!(fenced.code(), ValidationStoreErrorCodeV0::CommitUncertain);
}

#[test]
#[cfg(unix)]
fn file_replacement_hardlink_and_mode_drift_are_rejected() {
    let replacement_directory = TestDirectoryV0::new();
    let replacement_path = replacement_directory.database("replace.sqlite3");
    let mut replacement_store =
        SqliteProposalValidationStoreV0::open(&replacement_path, scope(6), 0)
            .expect("open replacement store");
    fs::rename(&replacement_path, replacement_path.with_extension("old"))
        .expect("move original inode");
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&replacement_path)
        .expect("create replacement inode");
    let error = replacement_store
        .durable_sequence_v0()
        .expect_err("replacement must fail");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::ReplacedStore);

    let hardlink_directory = TestDirectoryV0::new();
    let hardlink_path = hardlink_directory.database("hardlink.sqlite3");
    let mut hardlink_store = SqliteProposalValidationStoreV0::open(&hardlink_path, scope(7), 0)
        .expect("open hardlink store");
    fs::hard_link(&hardlink_path, hardlink_path.with_extension("alias")).expect("create hardlink");
    let error = hardlink_store
        .durable_sequence_v0()
        .expect_err("hardlink must fail");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::InvalidPermissions);

    let mode_directory = TestDirectoryV0::new();
    let mode_path = mode_directory.database("mode.sqlite3");
    let mut mode_store =
        SqliteProposalValidationStoreV0::open(&mode_path, scope(8), 0).expect("open mode store");
    fs::set_permissions(&mode_path, fs::Permissions::from_mode(0o640)).expect("change mode");
    let error = mode_store
        .durable_sequence_v0()
        .expect_err("mode drift must fail");
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::InvalidPermissions);
}

#[test]
fn external_sequence_floor_rejects_a_local_rollback() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("floor.sqlite3");
    let mut store = SqliteProposalValidationStoreV0::open(&path, scope(9), 0).expect("open store");
    let binding = binding(10, 11, 70);
    let _reserved = reserve(&mut store, &binding);
    drop(store);

    let error = match SqliteProposalValidationStoreV0::open(&path, scope(9), 2) {
        Ok(_) => panic!("sequence below external floor must fail"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::RollbackDetected);
}

#[test]
fn row_tampering_is_detected_on_reopen() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("tamper.sqlite3");
    let mut store = SqliteProposalValidationStoreV0::open(&path, scope(10), 0).expect("open store");
    let binding = binding(12, 13, 80);
    let _reserved = reserve(&mut store, &binding);
    drop(store);

    let connection = rusqlite::Connection::open(&path).expect("open raw database");
    connection
        .execute(
            "UPDATE proposal_validation_jobs_v0 SET artifact_digest = ?1",
            rusqlite::params![[0x55u8; 32].as_slice()],
        )
        .expect("tamper row");
    drop(connection);
    let error = match SqliteProposalValidationStoreV0::open(&path, scope(10), 0) {
        Ok(_) => panic!("tampered row must fail audit"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::CorruptStore);
}

#[test]
fn artifact_corruption_and_truncation_are_detected_on_reopen() {
    for name in ["corrupt", "truncate", "trailing"] {
        let directory = TestDirectoryV0::new();
        let path = directory.database(&format!("artifact-{name}.sqlite3"));
        let mut store =
            SqliteProposalValidationStoreV0::open(&path, scope(16), 0).expect("open store");
        let binding = binding(30, 31, 100);
        let _reserved = reserve(&mut store, &binding);
        drop(store);

        let mut artifact =
            encode_native_executed_block_artifact_v0(&executed(&binding, 7)).expect("encode P");
        match name {
            "corrupt" => artifact[0] ^= 1,
            "truncate" => {
                artifact.pop();
            }
            "trailing" => artifact.push(0),
            _ => unreachable!(),
        }
        rewrite_artifact_self_consistent_for_test_v0(&path, binding.validation_id(), artifact)
            .expect("rewrite internally consistent adversarial artifact");
        let error = match SqliteProposalValidationStoreV0::open(&path, scope(16), 0) {
            Ok(_) => panic!("mutated artifact must fail audit"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ValidationStoreErrorCodeV0::CorruptStore);
    }
}

#[test]
fn opening_with_wrong_scope_is_rejected() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("scope.sqlite3");
    let store =
        SqliteProposalValidationStoreV0::open(&path, scope(11), 0).expect("open original scope");
    drop(store);
    let error = match SqliteProposalValidationStoreV0::open(&path, scope(12), 0) {
        Ok(_) => panic!("wrong scope must fail"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::BindingMismatch);
}

#[test]
fn schema_or_trigger_drift_is_rejected_on_reopen() {
    let trigger_directory = TestDirectoryV0::new();
    let trigger_path = trigger_directory.database("trigger.sqlite3");
    let trigger_store = SqliteProposalValidationStoreV0::open(&trigger_path, scope(13), 0)
        .expect("open trigger fixture");
    drop(trigger_store);
    let connection = rusqlite::Connection::open(&trigger_path).expect("open raw trigger store");
    connection
        .execute_batch(
            "CREATE TRIGGER forbidden_trigger_v0 AFTER UPDATE ON validation_store_metadata_v0
             BEGIN SELECT 1; END;",
        )
        .expect("inject trigger");
    drop(connection);
    let error = match SqliteProposalValidationStoreV0::open(&trigger_path, scope(13), 0) {
        Ok(_) => panic!("trigger drift must fail"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::CorruptStore);

    let table_directory = TestDirectoryV0::new();
    let table_path = table_directory.database("table.sqlite3");
    let table_store = SqliteProposalValidationStoreV0::open(&table_path, scope(14), 0)
        .expect("open table fixture");
    drop(table_store);
    let connection = rusqlite::Connection::open(&table_path).expect("open raw table store");
    connection
        .execute_batch("CREATE TABLE forbidden_extra_table_v0 (value INTEGER NOT NULL);")
        .expect("inject extra table");
    drop(connection);
    let error = match SqliteProposalValidationStoreV0::open(&table_path, scope(14), 0) {
        Ok(_) => panic!("schema drift must fail"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::CorruptStore);
}

#[test]
fn missing_expected_table_is_rejected_without_recreation() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("missing-table.sqlite3");
    let store =
        SqliteProposalValidationStoreV0::open(&path, scope(24), 0).expect("create exact schema");
    drop(store);

    let connection = rusqlite::Connection::open(&path).expect("open raw database");
    connection
        .execute_batch("DROP TABLE proposal_validation_outbox_v0;")
        .expect("remove expected table");
    drop(connection);
    let before = main_database_snapshot(&path);

    let error = match SqliteProposalValidationStoreV0::open(&path, scope(24), 0) {
        Ok(_) => panic!("missing expected table must fail before writable open"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::CorruptStore);
    assert_eq!(
        main_database_snapshot(&path),
        before,
        "failed immutable preflight must preserve DB bytes, mtime, and directory entries"
    );

    let read_only = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("read malformed store without modifying it");
    let table_count: i64 = read_only
        .query_row(
            "SELECT count(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'proposal_validation_outbox_v0'",
            [],
            |row| row.get(0),
        )
        .expect("query missing table");
    assert_eq!(table_count, 0, "open must not recreate missing schema");
}

#[test]
fn old_schema_marker_is_rejected_without_migration_or_rewrite() {
    let directory = TestDirectoryV0::new();
    let path = directory.database("old-schema.sqlite3");
    let store =
        SqliteProposalValidationStoreV0::open(&path, scope(25), 0).expect("create exact schema");
    drop(store);

    let connection = rusqlite::Connection::open(&path).expect("open raw database");
    connection
        .execute(
            "UPDATE validation_store_metadata_v0 SET schema_version = 2 WHERE singleton = 1",
            [],
        )
        .expect("install old schema marker");
    drop(connection);

    let error = match SqliteProposalValidationStoreV0::open(&path, scope(25), 0) {
        Ok(_) => panic!("old schema must fail without implicit migration"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ValidationStoreErrorCodeV0::BindingMismatch);

    let read_only = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("read old marker without modifying it");
    let schema_version: i64 = read_only
        .query_row(
            "SELECT schema_version FROM validation_store_metadata_v0 WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read preserved schema marker");
    assert_eq!(
        schema_version, 2,
        "open must not migrate or rewrite metadata"
    );
}

#[test]
fn existing_sqlite_sidecars_are_rejected_before_sqlite_without_side_effects() {
    for (index, suffix) in ["-wal", "-shm", "-journal"].into_iter().enumerate() {
        let directory = TestDirectoryV0::new();
        let path = directory.database(&format!("existing-sidecar-{index}.sqlite3"));
        let store = SqliteProposalValidationStoreV0::open(&path, scope(26), 0)
            .expect("create exact schema");
        drop(store);
        let sidecar = sidecar_path(&path, suffix);
        let sentinel = format!("untrusted{suffix}").into_bytes();
        fs::write(&sidecar, &sentinel).expect("write sidecar sentinel");
        let before = main_database_snapshot(&path);

        let error = match SqliteProposalValidationStoreV0::open(&path, scope(26), 0) {
            Ok(_) => panic!("existing SQLite sidecar requires separate recovery authority"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ValidationStoreErrorCodeV0::CommitUncertain);
        assert_eq!(main_database_snapshot(&path), before);
        assert_eq!(fs::read(&sidecar).expect("sidecar remains"), sentinel);
    }
}

#[allow(dead_code)]
fn assert_path_is_inside(directory: &Path, path: &Path) {
    assert!(path.starts_with(directory));
}
