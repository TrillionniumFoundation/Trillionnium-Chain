//! Shared real native checkpoint producer. No synthetic receipt/ACK constructors.
//! Compiled only for this crate's tests or the explicit, default-off test feature.

use super::*;
use crate::{
    validator_lifecycle::{
        ValidatorGovernanceV1, ValidatorLifecycleStateV1, VALIDATOR_GOVERNANCE_SCHEMA_V1,
    },
    AuthorizedSignerV0, NativeApplicationConfigV0, NativeStateWriteV0,
};
use ed25519_dalek::{Signer, SigningKey};
use trnm_consensus_types::{
    BlockHeader, BlockKind, CertifiedHeaderV0, ConsensusPublicKey, EvidenceRoot, FinalityProofV0,
    ProposalWitnessV0, QcReferenceV0, QuorumCertificate, Signature64, Validator, ValidatorId, View,
    Vote, VotingPower,
};
use trnm_native_application::{
    BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, NativeApplicationCommitRequestV0,
    NativeApplicationGenesisRequestV0, NativeApplicationV0, NativeBlockExecutionRequestV0,
    NativeBlockExecutionResultV0, NativeExpectedBlockCommitmentsV0, StateRootV0,
};

pub(super) const CHAIN: &str = "native-poco-authorization-test";

pub(super) fn key(index: usize) -> SigningKey {
    SigningKey::from_bytes(&[20 + index as u8; 32])
}

fn config_with_initial_block(initial_block: [u8; 32]) -> NativeApplicationConfigV0 {
    let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
    fields.epoch_length_blocks = 10;
    fields.snapshot_lead_blocks = 3;
    let parameters = ConsensusParametersV0::new(fields).unwrap();
    let set = ValidatorSet::new(
        GenesisHash::new([7; 32]),
        ChainId::new(CHAIN).unwrap(),
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        (0..4)
            .map(|index| {
                Validator::new(
                    ValidatorId::from_bytes(format!("validator-{index}").as_bytes()).unwrap(),
                    ConsensusPublicKey::new(key(index).verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    let signers = vec![AuthorizedSignerV0::new(
        "did:operator:1",
        "operator",
        hex::encode(SigningKey::from_bytes(&[81; 32]).verifying_key().to_bytes()),
    )
    .unwrap()];
    let lifecycle = ValidatorLifecycleStateV1::from_genesis(
        CHAIN.to_string(),
        1,
        hex::encode(crate::signer_policy_commitment_v0(&signers).unwrap()),
        ValidatorGovernanceV1 {
            schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_string(),
            signer_id: "did:operator:1".to_string(),
            min_activation_delay_blocks: 2,
            unsafe_allow_single_validator_genesis: false,
        },
        set.validators()
            .iter()
            .map(|v| ConsensusValidatorV1 {
                public_key_hex: hex::encode(v.consensus_key().as_bytes()),
                voting_power: v.voting_power().get(),
            })
            .collect(),
    )
    .unwrap();
    let mut entries = vec![];
    let mut identity = vec![1];
    identity.extend_from_slice(&0u64.to_be_bytes());
    for (kind, raw) in [
        (
            PocoSnapshotEntryKindV0::ValidatorConfiguration,
            set.try_cev0_bytes().unwrap(),
        ),
        (
            PocoSnapshotEntryKindV0::ConsensusParameters,
            parameters.canonical_bytes(),
        ),
    ] {
        let (logical_key, value) = crate::poco_transition::encode_poco_snapshot_value_envelope_v0(
            kind, 1, &identity, &raw,
        )
        .unwrap();
        entries.push(
            crate::poco_snapshot::PocoSnapshotEntryV0::new(kind, logical_key, value).unwrap(),
        );
    }
    entries.push(crate::poco_application::genesis_poco_application_authority_entry_v0().unwrap());
    entries.sort_by(|a, b| (a.kind, &a.logical_key).cmp(&(b.kind, &b.logical_key)));
    let writes = crate::poco_transition::genesis_poco_snapshot_writes_v0(&entries)
        .unwrap()
        .into_iter()
        .map(|write| {
            NativeStateWriteV0::raw(write.key().to_vec(), write.value().unwrap().to_vec()).unwrap()
        })
        .collect();
    NativeApplicationConfigV0::new(
        CHAIN,
        [7; 32],
        [8; 32],
        [11; 32],
        initial_block,
        [10; 32],
        set,
        parameters,
        serde_json::to_vec(&lifecycle).unwrap(),
        signers,
        writes,
    )
    .unwrap()
}

#[cfg(test)]
pub(super) fn config() -> NativeApplicationConfigV0 {
    config_with_initial_block([9; 32])
}

pub(super) fn open(
    path: &std::path::Path,
    config: NativeApplicationConfigV0,
) -> DurableNativeApplicationV0 {
    let application = DurableNativeApplicationV0::open(path, config).unwrap();
    let config = application.config_v0();
    application
        .initialize(
            NativeApplicationGenesisRequestV0::new(
                ChainIdV0::new(CHAIN).unwrap(),
                GenesisHashV0::new([7; 32]).unwrap(),
                Hash32V0::new([8; 32]),
                Hash32V0::new(config.signer_policy_commitment_v0()),
                StateRootV0::new(config.initial_state_root()).unwrap(),
                config.initial_validator_set().clone(),
            )
            .unwrap(),
        )
        .unwrap();
    application
}

pub(super) fn next_request(app: &DurableNativeApplicationV0) -> NativeBlockPreviewRequestV0 {
    let parent = app.confirmed_committed_head_v0().unwrap();
    let height = parent.height().checked_next().unwrap();
    NativeBlockPreviewRequestV0::new(
        ChainIdV0::new(CHAIN).unwrap(),
        GenesisHashV0::new([7; 32]).unwrap(),
        parent,
        height,
        height.get() * 1000,
        trnm_native_application::ValidatorSetIdV0::new(
            *app.config_v0().validator_set_v0().id().as_bytes(),
        )
        .unwrap(),
        vec![],
    )
    .unwrap()
}

pub(super) fn execute(
    app: &DurableNativeApplicationV0,
    preview_request: NativeBlockPreviewRequestV0,
    kind: BlockKind,
) -> (BlockHeader, NativeExecutedBlockV0) {
    let preview = app.preview_block_v0(&preview_request).unwrap();
    let height = preview_request.height().get();
    let set = app.config_v0().validator_set_v0();
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(height),
        Height::new(height),
        kind,
        BlockId::new(*preview_request.parent().block_id().as_bytes()),
        set.validators()[((height - 1) % 4) as usize].id(),
        set.id(),
        set.consensus_parameters_hash(),
        PayloadDigest::new(*preview.payload_root().as_bytes()),
        StateRoot::new(*preview.post_state_root().as_bytes()),
        ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
        EvidenceRoot::new(*preview.evidence_root().as_bytes()),
        preview_request.timestamp_ms(),
        None,
    )
    .unwrap();
    let request = NativeBlockExecutionRequestV0::new(
        preview_request.chain_id().clone(),
        preview_request.genesis_hash(),
        preview_request.parent().clone(),
        BlockIdV0::new(*header.id().as_bytes()).unwrap(),
        preview_request.height(),
        preview_request.timestamp_ms(),
        preview_request.active_validator_set_id(),
        preview_request.transactions().to_vec(),
        NativeExpectedBlockCommitmentsV0::new(
            preview.payload_root(),
            preview.post_state_root(),
            preview.receipts_root(),
            preview.evidence_root(),
        )
        .unwrap(),
    )
    .unwrap();
    let NativeBlockExecutionResultV0::Valid(executed) = app.execute_block(request).unwrap() else {
        panic!("valid empty native execution rejected")
    };
    (header, *executed)
}

pub(super) fn qc(header: &BlockHeader, set: &ValidatorSet) -> QuorumCertificate {
    let votes = set
        .validators()
        .iter()
        .enumerate()
        .take(3)
        .map(|(index, v)| {
            let root = Vote::signing_root_for_set(set, header.view(), header.height(), header.id())
                .unwrap();
            Vote::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                header.view(),
                header.height(),
                header.id(),
                set.id(),
                v.id(),
                Signature64::from_array(key(index).sign(root.as_bytes()).to_bytes()),
                set,
            )
            .unwrap()
        })
        .collect();
    QuorumCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        header.view(),
        header.height(),
        header.id(),
        set.id(),
        votes,
        set,
    )
    .unwrap()
}

pub(super) fn cutoff_proof(headers: &[BlockHeader], config: &NativeApplicationConfigV0) -> Vec<u8> {
    let set = config.validator_set_v0();
    let parameters = config.consensus_parameters_v0();
    let certified = |index: usize| {
        let header = headers[index].clone();
        let justify = QcReferenceV0::ordinary(qc(&headers[index - 1], set));
        let root = ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
        let signer = set
            .validators()
            .iter()
            .position(|v| v.id() == header.proposer_id())
            .unwrap();
        CertifiedHeaderV0::new(
            header.clone(),
            justify,
            None,
            None,
            Signature64::from_array(key(signer).sign(root.as_bytes()).to_bytes()),
            qc(&header, set),
            set,
            None,
            parameters,
            headers[index - 1].timestamp_ms(),
        )
        .unwrap()
    };
    FinalityProofV0::new(
        certified(4),
        certified(5),
        certified(6),
        set,
        None,
        parameters,
        headers[3].timestamp_ms(),
    )
    .unwrap()
    .try_cev0_bytes()
    .unwrap()
}

pub(super) fn handoff_proofs(prepared: &PreparedNativePocoCheckpointV0) -> (Vec<u8>, Vec<u8>) {
    use trnm_consensus_types::{
        HandoffCertificateV0, HandoffDescriptorV0, HandoffDescriptorV0Fields, SignatureShareV0,
    };
    let preheader = prepared.bound.authorized().prepared();
    let authority = preheader.commitment_authority();
    let set = authority.old_validator_set();
    let parameters = authority.old_parameters();
    let checkpoint = prepared.header().clone();
    let parent = preheader.checkpoint_parent().header();
    let mut chain = vec![checkpoint.clone()];
    for (height, kind) in [(9, BlockKind::EpochSeal1), (10, BlockKind::EpochSeal2)] {
        chain.push(
            BlockHeader::new(
                set.genesis_hash(),
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(height),
                Height::new(height),
                kind,
                chain.last().unwrap().id(),
                set.validators()[((height - 1) % 4) as usize].id(),
                set.id(),
                parameters.hash(),
                checkpoint.payload_digest(),
                checkpoint.state_root(),
                checkpoint.receipts_root(),
                checkpoint.evidence_root(),
                height * 1000,
                Some(authority.commitment().id()),
            )
            .unwrap(),
        );
    }
    let certified = |index: usize| {
        let header = chain[index].clone();
        let parent_header = if index == 0 {
            parent
        } else {
            &chain[index - 1]
        };
        let justify = QcReferenceV0::ordinary(qc(parent_header, set));
        let root = ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
        let index = set
            .validators()
            .iter()
            .position(|v| v.id() == header.proposer_id())
            .unwrap();
        CertifiedHeaderV0::new(
            header.clone(),
            justify,
            None,
            None,
            Signature64::from_array(key(index).sign(root.as_bytes()).to_bytes()),
            qc(&header, set),
            set,
            None,
            parameters,
            parent_header.timestamp_ms(),
        )
        .unwrap()
    };
    let finality = FinalityProofV0::new(
        certified(0),
        certified(1),
        certified(2),
        set,
        None,
        parameters,
        parent.timestamp_ms(),
    )
    .unwrap();
    let terminal = &chain[2];
    let terminal_qc = qc(terminal, set);
    let new_set = authority.new_validator_set();
    let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
        genesis_hash: set.genesis_hash(),
        chain_id: set.chain_id(),
        old_epoch: set.epoch(),
        new_epoch: new_set.epoch(),
        old_protocol_version: set.protocol_version(),
        new_protocol_version: new_set.protocol_version(),
        old_validator_set_hash: set.id(),
        new_validator_set_hash: new_set.id(),
        old_consensus_parameters_hash: parameters.hash(),
        new_consensus_parameters_hash: authority.new_parameters().hash(),
        checkpoint_height: checkpoint.height(),
        checkpoint_block_id: checkpoint.id(),
        checkpoint_state_root: checkpoint.state_root(),
        next_epoch_commitment_digest: authority.commitment().id(),
        terminal_old_height: terminal.height(),
        terminal_old_block_id: terminal.id(),
        terminal_old_qc_digest: terminal_qc.id(),
        terminal_old_view: terminal.view(),
        activation_height: Height::new(11),
        initial_new_view: View::new(1),
    })
    .unwrap();
    let shares = |old: bool| {
        let root = if old {
            descriptor.old_set_signing_root()
        } else {
            descriptor.new_set_signing_root()
        };
        (0..4)
            .map(|index| {
                SignatureShareV0::new(
                    set.validators()[index].id(),
                    Signature64::from_array(key(index).sign(root.as_bytes()).to_bytes()),
                )
                .unwrap()
            })
            .collect()
    };
    let certificate = HandoffCertificateV0::new(
        descriptor.clone(),
        shares(true),
        shares(false),
        set,
        new_set,
    )
    .unwrap();
    let mut anchor = terminal.try_cev0_bytes().unwrap();
    anchor.extend_from_slice(&terminal_qc.try_cev0_bytes().unwrap());
    anchor.extend_from_slice(&certificate.try_cev0_bytes().unwrap());
    (finality.try_cev0_bytes().unwrap(), anchor)
}

#[cfg(test)]
pub(super) fn ordinary_prefix(app: &DurableNativeApplicationV0) -> Vec<BlockHeader> {
    (0..7)
        .map(|_| {
            let (header, executed) = execute(app, next_request(app), BlockKind::Regular);
            app.commit_block(NativeApplicationCommitRequestV0::new(executed))
                .unwrap();
            header
        })
        .collect()
}

pub(super) fn preparation(
    app: &DurableNativeApplicationV0,
    headers: &[BlockHeader],
) -> PreparedNativePocoCheckpointV0 {
    app.prepare_native_poco_checkpoint_v0(
        &next_request(app),
        View::new(8),
        app.config_v0().validator_set_v0().validators()[3].id(),
        &cutoff_proof(headers, app.config_v0()),
        &headers[3].try_cev0_bytes().unwrap(),
    )
    .unwrap()
}

/// Actual application owner and cryptographically signed reference chain for
/// cross-crate integration tests. All capabilities are produced by ordinary
/// native APIs; the consumer must run its own Core/Safety/custody transitions.
/// Genesis is explicitly operator-trusted, not CanonicalLab commissioned.
#[cfg(feature = "test-fixtures")]
pub struct NativeCheckpointFixtureV1 {
    pub application: DurableNativeApplicationV0,
    pub config: NativeApplicationConfigV0,
    pub ordinary_headers: Vec<BlockHeader>,
    pub ordinary_executions: Vec<NativeExecutedBlockV0>,
    pub ordinary_certified_headers: Vec<CertifiedHeaderV0>,
    pub cutoff_finality_bytes: Vec<u8>,
    pub cutoff_parent_header_bytes: Vec<u8>,
    pub checkpoint: PreparedNativePocoCheckpointV0,
    pub pre_handoff_preparation: PreparedNativePocoCheckpointV0,
    pub checkpoint_execution: NativeExecutedBlockV0,
    pub checkpoint_finality_bytes: Vec<u8>,
    pub handoff_anchor_bytes: Vec<u8>,
}

/// Pure operator-trusted fixture configuration for commissioning the matching
/// real signer/Safety profiles before any application file is created.
#[cfg(feature = "test-fixtures")]
pub fn native_checkpoint_fixture_config_v1() -> NativeApplicationConfigV0 {
    config_with_initial_block([7; 32])
}

/// Open only the trusted deterministic genesis. Consumers can replay the
/// reference requests against this second actual owner at each correct height.
/// Panics on fixture setup failure, like an ordinary test assertion.
#[cfg(feature = "test-fixtures")]
pub fn open_native_checkpoint_fixture_genesis_v1(
    path: &std::path::Path,
) -> DurableNativeApplicationV0 {
    open(path, native_checkpoint_fixture_config_v1())
}

/// Build real durable P/committed application rows for H1..C8 plus a strictly
/// signed checkpoint/two-seal proof. Seals never execute or create native P.
/// The returned prepared handles still require normal fresh owner readback.
/// Panics on fixture failure; the supplied path must be a new test database.
#[cfg(feature = "test-fixtures")]
pub fn build_native_checkpoint_fixture_v1(path: &std::path::Path) -> NativeCheckpointFixtureV1 {
    let application = open_native_checkpoint_fixture_genesis_v1(path);
    let config = native_checkpoint_fixture_config_v1();
    let mut ordinary_headers = Vec::new();
    let mut ordinary_executions = Vec::new();
    for _ in 0..7 {
        let (header, executed) =
            execute(&application, next_request(&application), BlockKind::Regular);
        application
            .commit_block(NativeApplicationCommitRequestV0::new(executed.clone()))
            .unwrap();
        ordinary_headers.push(header);
        ordinary_executions.push(executed);
    }
    let set = config.validator_set_v0();
    let parameters = config.consensus_parameters_v0();
    let genesis =
        trnm_consensus_types::GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).unwrap();
    let ordinary_certified_headers = ordinary_headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            let justify = if index == 0 {
                QcReferenceV0::genesis_anchor(genesis.clone())
            } else {
                QcReferenceV0::ordinary(qc(&ordinary_headers[index - 1], set))
            };
            let signer = set
                .validators()
                .iter()
                .position(|v| v.id() == header.proposer_id())
                .unwrap();
            let root = ProposalWitnessV0::signing_root_for(header, &justify, None, None).unwrap();
            CertifiedHeaderV0::new(
                header.clone(),
                justify,
                None,
                None,
                Signature64::from_array(key(signer).sign(root.as_bytes()).to_bytes()),
                qc(header, set),
                set,
                None,
                parameters,
                if index == 0 {
                    0
                } else {
                    ordinary_headers[index - 1].timestamp_ms()
                },
            )
            .unwrap()
        })
        .collect();
    let cutoff_finality_bytes = cutoff_proof(&ordinary_headers, &config);
    let cutoff_parent_header_bytes = ordinary_headers[3].try_cev0_bytes().unwrap();
    let checkpoint = preparation(&application, &ordinary_headers);
    let pre_handoff_preparation = preparation(&application, &ordinary_headers);
    let (checkpoint_finality_bytes, handoff_anchor_bytes) = handoff_proofs(&checkpoint);
    let request = next_request(&application);
    let preview = application.preview_block_v0(&request).unwrap();
    let request = NativeBlockExecutionRequestV0::new(
        request.chain_id().clone(),
        request.genesis_hash(),
        request.parent().clone(),
        BlockIdV0::new(*checkpoint.header().id().as_bytes()).unwrap(),
        request.height(),
        request.timestamp_ms(),
        request.active_validator_set_id(),
        request.transactions().to_vec(),
        NativeExpectedBlockCommitmentsV0::new(
            preview.payload_root(),
            preview.post_state_root(),
            preview.receipts_root(),
            preview.evidence_root(),
        )
        .unwrap(),
    )
    .unwrap();
    let NativeBlockExecutionResultV0::Valid(executed) = application.execute_block(request).unwrap()
    else {
        panic!("actual checkpoint execution invalid");
    };
    let checkpoint_execution = *executed;
    drop(
        application
            .confirm_prepared_checkpoint_execution_v1(&checkpoint, &checkpoint_execution)
            .unwrap(),
    );
    application
        .commit_block(NativeApplicationCommitRequestV0::new(
            checkpoint_execution.clone(),
        ))
        .unwrap();
    NativeCheckpointFixtureV1 {
        application,
        config,
        ordinary_headers,
        ordinary_executions,
        ordinary_certified_headers,
        cutoff_finality_bytes,
        cutoff_parent_header_bytes,
        checkpoint,
        pre_handoff_preparation,
        checkpoint_execution,
        checkpoint_finality_bytes,
        handoff_anchor_bytes,
    }
}

#[cfg(all(test, feature = "test-fixtures"))]
mod feature_tests {
    use super::*;

    #[test]
    fn exported_fixture_replays_actual_native_rows_and_issues_strict_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let fixture =
            build_native_checkpoint_fixture_v1(&directory.path().join("reference.sqlite3"));
        assert_eq!(fixture.ordinary_headers[0].parent_id().as_bytes(), &[7; 32]);
        let replay =
            open_native_checkpoint_fixture_genesis_v1(&directory.path().join("replay.sqlite3"));
        for reference in &fixture.ordinary_executions {
            let NativeBlockExecutionResultV0::Valid(actual) =
                replay.execute_block(reference.request().clone()).unwrap()
            else {
                panic!("actual fixture replay rejected");
            };
            let row = replay
                .confirm_durable_execution_history_row_v0(&actual)
                .unwrap();
            assert_eq!(
                row.status_v0(),
                crate::DurableExecutionHistoryStatusV0::Prepared
            );
            assert_eq!(
                row.target_head_v0().unwrap().height(),
                reference.request().height()
            );
            replay
                .commit_block(NativeApplicationCommitRequestV0::new(*actual))
                .unwrap();
        }
        let replay_preparation = replay
            .prepare_native_poco_checkpoint_v0(
                &next_request(&replay),
                View::new(8),
                fixture.checkpoint.header().proposer_id(),
                &fixture.cutoff_finality_bytes,
                &fixture.cutoff_parent_header_bytes,
            )
            .unwrap();
        assert_eq!(replay_preparation.header(), fixture.checkpoint.header());
        let NativeBlockExecutionResultV0::Valid(actual) = replay
            .execute_block(fixture.checkpoint_execution.request().clone())
            .unwrap()
        else {
            panic!("actual checkpoint replay rejected");
        };
        let prepared = replay
            .confirm_prepared_checkpoint_execution_v1(&replay_preparation, &actual)
            .unwrap();
        assert_eq!(
            prepared.durable_row().status_v0(),
            crate::DurableExecutionHistoryStatusV0::Prepared
        );
        drop(prepared);
        replay
            .commit_block(NativeApplicationCommitRequestV0::new(*actual))
            .unwrap();
        let receipt = replay
            .confirm_pre_handoff_checkpoint_v1(
                replay_preparation,
                &fixture.checkpoint_finality_bytes,
            )
            .unwrap();
        assert_eq!(receipt.header(), fixture.checkpoint.header());
        assert_eq!(
            receipt.durable_row().status_v0(),
            crate::DurableExecutionHistoryStatusV0::Committed
        );
        assert!(receipt
            .durable_row()
            .belongs_to_application_at_path_v0(&replay, replay.path()));
        assert!(!receipt
            .durable_row()
            .belongs_to_application_at_path_v0(&fixture.application, fixture.application.path()));
        let original = fixture
            .application
            .confirm_pre_handoff_checkpoint_v1(
                fixture.pre_handoff_preparation,
                &fixture.checkpoint_finality_bytes,
            )
            .unwrap();
        assert_eq!(
            original.checkpoint_finality(),
            receipt.checkpoint_finality()
        );
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
pub fn epoch_first_finality(
    edge: &crate::AuthenticatedEpochApplicationEdgeV1,
    headers: &[BlockHeader],
) -> Vec<u8> {
    let mut budget = trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0();
    let audit = edge
        .recovery_evidence()
        .audit_strict(edge.old_validator_set(), edge.old_parameters(), &mut budget)
        .unwrap();
    let activation = &audit.activation;
    let set = edge.new_validator_set();
    let parameters = edge.new_parameters();
    let common = || {
        let mut bytes = 0u16.to_be_bytes().to_vec();
        bytes.extend(set.genesis_hash().as_bytes());
        bytes.extend((set.chain_id().as_bytes().len() as u16).to_be_bytes());
        bytes.extend(set.chain_id().as_bytes());
        bytes.extend(set.protocol_version().get().to_be_bytes());
        bytes.extend(set.epoch().get().to_be_bytes());
        bytes.extend(set.id().as_bytes());
        bytes
    };
    let mut bytes = common();
    bytes.extend(parameters.hash().as_bytes());
    let mut anchor = common();
    anchor.extend(0u64.to_be_bytes());
    anchor.extend(edge.consensus_parent().height().get().to_be_bytes());
    anchor.extend(edge.consensus_parent().id().as_bytes());
    anchor.extend(0u32.to_be_bytes());
    for (index, header) in headers.iter().enumerate() {
        let key_index = set
            .validators()
            .iter()
            .position(|v| v.id() == header.proposer_id())
            .unwrap();
        if index == 0 {
            let root = trnm_consensus_types::epoch_first_proposal_signing_root_v0(
                header,
                activation.authorization_kernel(),
                edge.old_validator_set(),
                set,
                parameters,
            )
            .unwrap();
            bytes.extend(header.try_cev0_bytes().unwrap());
            bytes.extend(&anchor);
            bytes.push(0);
            bytes.push(1);
            bytes.extend(activation.authorization_cev0_bytes().unwrap());
            bytes.extend(key(key_index).sign(root.as_bytes()).to_bytes());
            bytes.extend(qc(header, set).try_cev0_bytes().unwrap());
        } else {
            let justify = QcReferenceV0::ordinary(qc(&headers[index - 1], set));
            let witness = ProposalWitnessV0::new(
                header,
                justify.clone(),
                None,
                None,
                Signature64::from_array([1; 64]),
                set,
                None,
                parameters,
                headers[index - 1].timestamp_ms(),
            )
            .unwrap();
            let signature = Signature64::from_array(
                key(key_index)
                    .sign(witness.signing_root_for_header(header).unwrap().as_bytes())
                    .to_bytes(),
            );
            let certified = CertifiedHeaderV0::new(
                header.clone(),
                justify,
                None,
                None,
                signature,
                qc(header, set),
                set,
                None,
                parameters,
                headers[index - 1].timestamp_ms(),
            )
            .unwrap();
            bytes.extend(certified.try_cev0_bytes().unwrap());
        }
    }
    bytes
}

/// Build an ordinary new-set three-chain for one sparse epoch descendant.
///
/// This fixture helper deliberately takes the authenticated epoch edge and
/// parent header rather than a caller-supplied validator set.  It is test-only
/// evidence for the schema7 ordinary descendant commit path; it does not
/// create checkpoint/two-seal/handoff evidence.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn ordinary_epoch_finality(
    edge: &crate::AuthenticatedEpochApplicationEdgeV1,
    parent: &BlockHeader,
    headers: &[BlockHeader],
) -> Vec<u8> {
    assert_eq!(headers.len(), 3, "ordinary finality requires a three-chain");
    let set = edge.new_validator_set();
    let parameters = edge.new_parameters();
    let certified = |header: &BlockHeader, parent: &BlockHeader| {
        let justify = QcReferenceV0::ordinary(qc(parent, set));
        let root = ProposalWitnessV0::signing_root_for(header, &justify, None, None).unwrap();
        let proposer = set
            .validators()
            .iter()
            .position(|validator| validator.id() == header.proposer_id())
            .unwrap();
        CertifiedHeaderV0::new(
            header.clone(),
            justify,
            None,
            None,
            Signature64::from_array(key(proposer).sign(root.as_bytes()).to_bytes()),
            qc(header, set),
            set,
            None,
            parameters,
            parent.timestamp_ms(),
        )
        .unwrap()
    };
    FinalityProofV0::new(
        certified(&headers[0], parent),
        certified(&headers[1], &headers[0]),
        certified(&headers[2], &headers[1]),
        set,
        None,
        parameters,
        parent.timestamp_ms(),
    )
    .unwrap()
    .try_cev0_bytes()
    .unwrap()
}
