use alloc::{vec, vec::Vec};

use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    BlockId, ChainId, ConsensusParametersHash, Epoch, EvidenceRoot, GenesisHash, Height,
    PayloadDigest, ProtocolVersion, ReceiptsRoot, SigningRoot, StateRoot, ValidatorId,
    ValidatorSetId, View,
};

use super::*;

const GOLDEN_SIGNATURE_COMMITTED_LENGTH_V1: usize = 3_296;
const GOLDEN_SIGNATURE_COMMITTED_CHECKSUM_V1: [u8; 32] = [
    0xa1, 0x98, 0x8c, 0xda, 0xd1, 0x84, 0xfb, 0x78, 0x0c, 0x00, 0x4f, 0x05, 0x0c, 0x8e, 0xf4, 0x20,
    0xf5, 0xeb, 0x1a, 0xcb, 0xf0, 0xa8, 0xc3, 0xaa, 0xcd, 0x6d, 0x06, 0x9e, 0xa4, 0xc5, 0x5e, 0x7f,
];
const GOLDEN_SIGNATURE_COMMITTED_BYTES_SHA256_V1: [u8; 32] = [
    0xa9, 0x23, 0xe8, 0x08, 0xa6, 0x4a, 0x24, 0xda, 0xb3, 0x99, 0x1b, 0xca, 0x1b, 0x11, 0x48, 0x0d,
    0x38, 0x1b, 0x0f, 0x1d, 0xa4, 0xbe, 0x1e, 0xee, 0xa0, 0x5d, 0xb7, 0x94, 0xc9, 0x43, 0x48, 0x61,
];
const GOLDEN_EPOCH_ACTIVE_REF_BYTES_V1: [u8; WHOLE_NODE_CHECKPOINT_REF_BYTES_V1] = [
    0x54, 0x52, 0x4e, 0x4d, 0x57, 0x52, 0x30, 0x31, 0x00, 0x01, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
    0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
    0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x05, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2,
    0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2,
    0xb2, 0xb2, 0xb2, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3,
    0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3,
    0xc3, 0xc3, 0xc3,
];
const GOLDEN_EPOCH_ACTIVE_REF_BYTES_SHA256_V1: [u8; 32] = [
    0x8c, 0xc3, 0x4d, 0x87, 0x4c, 0xa4, 0x1a, 0x5b, 0x32, 0x41, 0x2e, 0x08, 0xf8, 0xe4, 0x33, 0xf6,
    0xd2, 0x11, 0xda, 0x25, 0x59, 0x81, 0xbb, 0x17, 0x88, 0x37, 0x4d, 0xa2, 0x55, 0xdc, 0x7f, 0x58,
];

fn digest(byte: u8) -> WholeNodeCutDigestV1 {
    WholeNodeCutDigestV1::from_exact_bytes([byte; 32]).expect("non-zero test digest")
}

fn checkpoint_checksum(byte: u8) -> WholeNodeCheckpointChecksumV1 {
    WholeNodeCheckpointChecksumV1::from_exact_bytes([byte; 32])
        .expect("non-zero test checkpoint checksum")
}

fn initial_chain() -> ChainCutRefV1 {
    ChainCutRefV1::new(
        GenesisHash::new([1; 32]),
        ChainId::new("trnm-checkpoint-v1").expect("test chain id"),
        ProtocolVersion::new(7).expect("test protocol version"),
        Epoch::new(11),
        ValidatorSetId::new([2; 32]),
        ConsensusParametersHash::new([3; 32]),
        ValidatorId::new([4; 32]),
    )
    .expect("test Chain cut")
}

fn process_fence(generation: u64, first_digest: u8) -> ProcessFenceRefV1 {
    ProcessFenceRefV1::new(
        ProcessGenerationV1::new(generation).expect("test process generation"),
        digest(first_digest),
        digest(first_digest + 1),
        digest(first_digest + 2),
    )
}

fn initial_fences() -> ProcessFencesCutRefV1 {
    ProcessFencesCutRefV1::new(
        process_fence(1, 10),
        process_fence(2, 14),
        process_fence(3, 18),
    )
}

fn roles() -> RoleBindingsCutRefV1 {
    RoleBindingsCutRefV1::new(
        digest(30),
        digest(31),
        digest(32),
        digest(33),
        digest(34),
        digest(35),
        digest(36),
        digest(37),
        digest(38),
    )
}

fn commissioned_checkpoint() -> WholeNodeCheckpointV1 {
    WholeNodeCheckpointV1::commissioned(
        WholeNodeCheckpointScopeV1::from_exact_bytes([0xa0; 32]).expect("test scope"),
        initial_chain(),
        initial_fences(),
        roles(),
        CoreSafetyCutRefV1::new(
            digest(40),
            digest(41),
            digest(42),
            7,
            digest(43),
            digest(44),
            digest(45),
            None,
            None,
        ),
        ApplicationCutRefV1::new(
            digest(50),
            digest(51),
            digest(52),
            digest(53),
            9,
            digest(54),
            digest(55),
            digest(56),
            None,
            BlockId::new([57; 32]),
            Height::new(20),
            StateRoot::new([58; 32]),
            View::new(30),
            1_000,
            None,
            None,
        )
        .expect("initial Application cut"),
        AppAttestorCutRefV1::new(
            digest(60),
            digest(61),
            digest(62),
            4,
            digest(63),
            digest(64),
            digest(65),
            None,
            None,
        ),
        RemoteSafetyCutRefV1::new(
            digest(70),
            digest(71),
            digest(72),
            5,
            digest(73),
            digest(74),
            digest(75),
            digest(76),
            None,
            None,
        ),
        SignerCutRefV1::new(
            digest(80),
            digest(81),
            digest(82),
            6,
            digest(83),
            digest(84),
            digest(85),
            None,
            SignerJournalStateV1::Stable,
            None,
            None,
        ),
    )
    .expect("commissioned checkpoint")
}

fn vote_cycle() -> (
    WholeNodeCheckpointV1,
    WholeNodeCheckpointV1,
    WholeNodeCheckpointV1,
    WholeNodeCheckpointV1,
) {
    let commissioned = commissioned_checkpoint();
    let core = CoreSafetyCutRefV1::new(
        digest(40),
        digest(41),
        digest(42),
        8,
        digest(92),
        digest(93),
        digest(94),
        Some(digest(45)),
        Some(digest(90)),
    );
    let validation = ApplicationValidationCutRefV1::new(
        ApplicationValidationGenerationV1::new(1).expect("validation generation"),
        digest(95),
        digest(96),
        digest(126),
        digest(127),
        None,
        None,
        BlockId::new([97; 32]),
        BlockId::new([57; 32]),
        Height::new(21),
        View::new(31),
        PayloadDigest::new([98; 32]),
        StateRoot::new([99; 32]),
        ReceiptsRoot::new([100; 32]),
        EvidenceRoot::new([101; 32]),
        digest(102),
        digest(103),
        digest(104),
        digest(56),
        digest(92),
        commissioned.checkpoint_checksum(),
    )
    .expect("validation cut");
    let application = ApplicationCutRefV1::new(
        digest(50),
        digest(51),
        digest(52),
        digest(53),
        9,
        digest(54),
        digest(55),
        digest(56),
        None,
        BlockId::new([57; 32]),
        Height::new(20),
        StateRoot::new([58; 32]),
        View::new(30),
        1_000,
        Some(validation.lineage_cut()),
        Some(validation),
    )
    .expect("validated Application cut");
    let operation = SignOperationCutRefV1::new(
        SignOperationKindV1::Vote,
        digest(86),
        digest(87),
        digest(88),
        digest(90),
        SigningRoot::new([89; 32]),
        digest(91),
        commissioned.checkpoint_checksum(),
        Some(validation.statement_digest()),
    )
    .expect("Vote operation");
    let app_validated = WholeNodeCheckpointV1::app_validated_successor(
        &commissioned,
        initial_fences(),
        operation,
        core,
        application,
        AppAttestorCutRefV1::new(
            digest(60),
            digest(61),
            digest(62),
            5,
            digest(105),
            digest(106),
            digest(107),
            Some(digest(65)),
            Some(validation.statement_digest()),
        ),
    )
    .expect("AppValidated successor");

    let safety_prepared = WholeNodeCheckpointV1::safety_prepared_successor(
        &app_validated,
        RemoteSafetyCutRefV1::new(
            digest(70),
            digest(71),
            digest(72),
            6,
            digest(108),
            digest(109),
            digest(110),
            digest(111),
            Some(digest(76)),
            Some(digest(91)),
        ),
        SignerCutRefV1::new(
            digest(80),
            digest(81),
            digest(82),
            7,
            digest(112),
            digest(113),
            digest(114),
            Some(digest(85)),
            SignerJournalStateV1::Prepared,
            Some(digest(88)),
            None,
        ),
    )
    .expect("SafetyPrepared successor");

    let signature_committed = WholeNodeCheckpointV1::signature_committed_successor(
        &safety_prepared,
        SignerCutRefV1::new(
            digest(80),
            digest(81),
            digest(82),
            8,
            digest(115),
            digest(116),
            digest(117),
            Some(digest(114)),
            SignerJournalStateV1::Signed,
            Some(digest(88)),
            Some(digest(118)),
        ),
    )
    .expect("SignatureCommitted successor");

    (
        commissioned,
        app_validated,
        safety_prepared,
        signature_committed,
    )
}

fn application_without_validation(source: ApplicationCutRefV1) -> ApplicationCutRefV1 {
    ApplicationCutRefV1::new(
        source.host_config_ref(),
        source.projection_profile_ref(),
        source.safety_binding_manifest_checksum(),
        source.store_scope(),
        source.committed_sequence(),
        source.committed_head_row_checksum(),
        source.recovery_closure_checksum(),
        source.active_head_checksum(),
        source.checkpoint_predecessor_head_checksum(),
        source.block_id(),
        source.height(),
        source.state_root(),
        source.view(),
        source.timestamp_ms(),
        source.validation_lineage(),
        None,
    )
    .expect("Application cut without validation")
}

#[allow(clippy::too_many_arguments)]
fn vote_app_validated_successor(
    predecessor: &WholeNodeCheckpointV1,
    validation_generation: u64,
    validation_store_scope: WholeNodeCutDigestV1,
    validation_id: WholeNodeCutDigestV1,
    validation_record_chain_checksum: WholeNodeCutDigestV1,
    validation_active_head_checksum: WholeNodeCutDigestV1,
    seed: u8,
) -> WholeNodeCheckpointResultV1<WholeNodeCheckpointV1> {
    let previous_core = predecessor.core_safety();
    let previous_application = predecessor.application();
    let previous_attestor = predecessor.application_attestor();
    let previous_lineage = previous_application.validation_lineage();
    let canonical_intent_checksum = digest(seed);
    let core = CoreSafetyCutRefV1::new(
        previous_core.journal_id(),
        previous_core.verifier_profile_ref(),
        previous_core.config_ref(),
        previous_core.revision() + 1,
        digest(seed + 1),
        digest(seed + 2),
        digest(seed + 3),
        Some(previous_core.active_head_checksum()),
        Some(canonical_intent_checksum),
    );
    let validation = ApplicationValidationCutRefV1::new(
        ApplicationValidationGenerationV1::new(validation_generation)?,
        validation_store_scope,
        validation_id,
        validation_record_chain_checksum,
        validation_active_head_checksum,
        previous_lineage.map(|lineage| lineage.record_chain_checksum()),
        previous_lineage.map(|lineage| lineage.active_head_checksum()),
        BlockId::new([seed + 4; 32]),
        previous_application.block_id(),
        Height::new(previous_application.height().get() + 1),
        View::new(previous_application.view().get() + 1),
        PayloadDigest::new([seed + 5; 32]),
        StateRoot::new([seed + 6; 32]),
        ReceiptsRoot::new([seed + 7; 32]),
        EvidenceRoot::new([seed + 8; 32]),
        digest(seed + 9),
        digest(seed + 10),
        digest(seed + 11),
        previous_application.active_head_checksum(),
        core.state_record_checksum(),
        predecessor.checkpoint_checksum(),
    )?;
    let application = ApplicationCutRefV1::new(
        previous_application.host_config_ref(),
        previous_application.projection_profile_ref(),
        previous_application.safety_binding_manifest_checksum(),
        previous_application.store_scope(),
        previous_application.committed_sequence(),
        previous_application.committed_head_row_checksum(),
        previous_application.recovery_closure_checksum(),
        previous_application.active_head_checksum(),
        previous_application.checkpoint_predecessor_head_checksum(),
        previous_application.block_id(),
        previous_application.height(),
        previous_application.state_root(),
        previous_application.view(),
        previous_application.timestamp_ms(),
        Some(validation.lineage_cut()),
        Some(validation),
    )?;
    let operation = SignOperationCutRefV1::new(
        SignOperationKindV1::Vote,
        digest(seed + 12),
        digest(seed + 13),
        digest(seed + 14),
        canonical_intent_checksum,
        SigningRoot::new([seed + 15; 32]),
        digest(seed + 16),
        predecessor.checkpoint_checksum(),
        Some(validation.statement_digest()),
    )?;
    WholeNodeCheckpointV1::app_validated_successor(
        predecessor,
        predecessor.fences(),
        operation,
        core,
        application,
        AppAttestorCutRefV1::new(
            previous_attestor.journal_id(),
            previous_attestor.profile_checksum(),
            previous_attestor.store_scope(),
            previous_attestor.sequence() + 1,
            digest(seed + 17),
            digest(seed + 18),
            digest(seed + 19),
            Some(previous_attestor.active_head_checksum()),
            Some(validation.statement_digest()),
        ),
    )
}

fn timeout_app_validated_successor(
    predecessor: &WholeNodeCheckpointV1,
    seed: u8,
) -> WholeNodeCheckpointResultV1<WholeNodeCheckpointV1> {
    let previous_core = predecessor.core_safety();
    let canonical_intent_checksum = digest(seed);
    WholeNodeCheckpointV1::app_validated_successor(
        predecessor,
        predecessor.fences(),
        SignOperationCutRefV1::new(
            SignOperationKindV1::TimeoutVote,
            digest(seed + 4),
            digest(seed + 5),
            digest(seed + 6),
            canonical_intent_checksum,
            SigningRoot::new([seed + 7; 32]),
            digest(seed + 8),
            predecessor.checkpoint_checksum(),
            None,
        )?,
        CoreSafetyCutRefV1::new(
            previous_core.journal_id(),
            previous_core.verifier_profile_ref(),
            previous_core.config_ref(),
            previous_core.revision() + 1,
            digest(seed + 1),
            digest(seed + 2),
            digest(seed + 3),
            Some(previous_core.active_head_checksum()),
            Some(canonical_intent_checksum),
        ),
        application_without_validation(predecessor.application()),
        predecessor.application_attestor(),
    )
}

fn complete_signing_cycle(
    predecessor: &WholeNodeCheckpointV1,
    seed: u8,
) -> WholeNodeCheckpointResultV1<WholeNodeCheckpointV1> {
    let operation = predecessor
        .operation()
        .ok_or(WholeNodeCheckpointErrorV1::InvalidField(
            "test signing-cycle operation",
        ))?;
    let previous_remote = predecessor.remote_safety();
    let previous_signer = predecessor.signer();
    let safety_prepared = WholeNodeCheckpointV1::safety_prepared_successor(
        predecessor,
        RemoteSafetyCutRefV1::new(
            previous_remote.store_scope(),
            previous_remote.journal_id(),
            previous_remote.profile_checksum(),
            previous_remote.revision() + 1,
            digest(seed),
            digest(seed + 1),
            digest(seed + 2),
            digest(seed + 3),
            Some(previous_remote.active_head_checksum()),
            Some(operation.safety_transition_digest()),
        ),
        SignerCutRefV1::new(
            previous_signer.journal_id(),
            previous_signer.profile_checksum(),
            previous_signer.store_scope(),
            previous_signer.sequence() + 1,
            digest(seed + 4),
            digest(seed + 5),
            digest(seed + 6),
            Some(previous_signer.active_head_checksum()),
            SignerJournalStateV1::Prepared,
            Some(operation.request_fingerprint()),
            None,
        ),
    )?;
    let prepared_signer = safety_prepared.signer();
    WholeNodeCheckpointV1::signature_committed_successor(
        &safety_prepared,
        SignerCutRefV1::new(
            prepared_signer.journal_id(),
            prepared_signer.profile_checksum(),
            prepared_signer.store_scope(),
            prepared_signer.sequence() + 1,
            digest(seed + 7),
            digest(seed + 8),
            digest(seed + 9),
            Some(prepared_signer.active_head_checksum()),
            SignerJournalStateV1::Signed,
            Some(operation.request_fingerprint()),
            Some(digest(seed + 10)),
        ),
    )
}

#[test]
fn four_phase_vote_cycle_is_exact_bounded_and_round_trips() {
    let (commissioned, app_validated, safety_prepared, signature_committed) = vote_cycle();
    let values = [
        commissioned,
        app_validated,
        safety_prepared,
        signature_committed,
    ];
    for (expected_generation, value) in values.into_iter().enumerate() {
        assert_eq!(value.generation().get(), expected_generation as u64);
        let encoded = value.try_exact_bytes().expect("canonical bytes");
        assert!(encoded.len() <= MAX_WHOLE_NODE_CHECKPOINT_BYTES_V1);
        assert_eq!(
            decode_whole_node_checkpoint_v1_exact(&encoded).expect("exact decode"),
            value
        );
    }
    app_validated
        .validate_successor_of(&commissioned)
        .expect("Commissioned -> AppValidated");
    safety_prepared
        .validate_successor_of(&app_validated)
        .expect("AppValidated -> SafetyPrepared");
    signature_committed
        .validate_successor_of(&safety_prepared)
        .expect("SafetyPrepared -> SignatureCommitted");
}

#[test]
fn unique_checkpoint_reference_projects_round_trips_and_enforces_phase_successors() {
    let (commissioned, app_validated, safety_prepared, signature_committed) = vote_cycle();
    let refs = [
        commissioned.checkpoint_ref(),
        app_validated.checkpoint_ref(),
        safety_prepared.checkpoint_ref(),
        signature_committed.checkpoint_ref(),
    ];
    for (index, checkpoint_ref) in refs.into_iter().enumerate() {
        assert_eq!(checkpoint_ref.generation().get(), index as u64);
        assert_eq!(
            decode_whole_node_checkpoint_ref_v1_exact(&checkpoint_ref.exact_bytes())
                .expect("exact checkpoint ref"),
            checkpoint_ref
        );
    }
    refs[1]
        .validate_successor_of(&refs[0])
        .expect("reference Commissioned -> AppValidated");
    refs[2]
        .validate_successor_of(&refs[1])
        .expect("reference AppValidated -> SafetyPrepared");
    refs[3]
        .validate_successor_of(&refs[2])
        .expect("reference SafetyPrepared -> SignatureCommitted");
    assert!(refs[3].validate_successor_of(&refs[1]).is_err());
    assert!(refs[1].validate_successor_of(&refs[1]).is_err());

    let mut reserved = refs[3].exact_bytes();
    reserved[50] = 0xff;
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&reserved),
        Err(WholeNodeCheckpointErrorV1::ReservedTag("phase"))
    );
    let mut zero_noninitial_predecessor = refs[3].exact_bytes();
    zero_noninitial_predecessor[51..83].fill(0);
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&zero_noninitial_predecessor),
        Err(WholeNodeCheckpointErrorV1::InvalidField(
            "noninitial checkpoint reference"
        ))
    );
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&refs[3].exact_bytes()[..114]),
        Err(WholeNodeCheckpointErrorV1::InvalidField(
            "checkpoint reference length"
        ))
    );
}

#[test]
fn checkpoint_reference_phase_tags_and_complete_successor_matrix_are_frozen() {
    let phases = [
        WholeNodeCheckpointPhaseV1::Commissioned,
        WholeNodeCheckpointPhaseV1::AppValidated,
        WholeNodeCheckpointPhaseV1::SafetyPrepared,
        WholeNodeCheckpointPhaseV1::SignatureCommitted,
        WholeNodeCheckpointPhaseV1::EpochActivationPrepared,
        WholeNodeCheckpointPhaseV1::EpochActive,
    ];
    assert_eq!(
        phases.map(WholeNodeCheckpointPhaseV1::tag),
        [0, 1, 2, 3, 4, 5]
    );

    for predecessor_phase in phases {
        let predecessor_generation =
            if predecessor_phase == WholeNodeCheckpointPhaseV1::Commissioned {
                WholeNodeCheckpointGenerationV1::ZERO
            } else {
                WholeNodeCheckpointGenerationV1::new(9)
            };
        let predecessor = WholeNodeCheckpointRefV1::new(
            WholeNodeCheckpointScopeV1::from_exact_bytes([0xa4; 32]).expect("matrix scope"),
            predecessor_generation,
            predecessor_phase,
            (predecessor_generation != WholeNodeCheckpointGenerationV1::ZERO)
                .then(|| checkpoint_checksum(0xd0)),
            checkpoint_checksum(0xd1 + predecessor_phase.tag()),
        )
        .expect("matrix predecessor reference");

        for successor_phase in phases {
            let expected = matches!(
                (predecessor_phase, successor_phase),
                (
                    WholeNodeCheckpointPhaseV1::Commissioned
                        | WholeNodeCheckpointPhaseV1::SignatureCommitted
                        | WholeNodeCheckpointPhaseV1::EpochActive,
                    WholeNodeCheckpointPhaseV1::AppValidated
                        | WholeNodeCheckpointPhaseV1::EpochActivationPrepared
                ) | (
                    WholeNodeCheckpointPhaseV1::AppValidated,
                    WholeNodeCheckpointPhaseV1::SafetyPrepared
                ) | (
                    WholeNodeCheckpointPhaseV1::SafetyPrepared,
                    WholeNodeCheckpointPhaseV1::SignatureCommitted
                ) | (
                    WholeNodeCheckpointPhaseV1::EpochActivationPrepared,
                    WholeNodeCheckpointPhaseV1::EpochActive
                )
            );
            let successor = WholeNodeCheckpointRefV1::new(
                predecessor.scope(),
                predecessor
                    .generation()
                    .checked_next()
                    .expect("next generation"),
                successor_phase,
                Some(predecessor.checksum()),
                checkpoint_checksum(0xe0 + successor_phase.tag()),
            );
            if successor_phase == WholeNodeCheckpointPhaseV1::Commissioned {
                assert_eq!(
                    successor,
                    Err(WholeNodeCheckpointErrorV1::InvalidField(
                        "noninitial checkpoint reference"
                    ))
                );
                assert!(!expected);
                continue;
            }
            assert_eq!(
                successor
                    .expect("noninitial reference shape")
                    .validate_successor_of(&predecessor)
                    .is_ok(),
                expected,
                "unexpected reference edge {predecessor_phase:?} -> {successor_phase:?}"
            );
        }
    }
}

#[test]
fn checkpoint_reference_exact_codec_has_hard_coded_golden_and_rejects_mutants() {
    assert_eq!(WHOLE_NODE_CHECKPOINT_REF_BYTES_V1, 115);
    let value = WholeNodeCheckpointRefV1::new(
        WholeNodeCheckpointScopeV1::from_exact_bytes([0xa1; 32]).expect("golden scope"),
        WholeNodeCheckpointGenerationV1::new(0x0102_0304_0506_0708),
        WholeNodeCheckpointPhaseV1::EpochActive,
        Some(checkpoint_checksum(0xb2)),
        checkpoint_checksum(0xc3),
    )
    .expect("golden EpochActive reference");
    let exact = value.exact_bytes();
    assert_eq!(exact, GOLDEN_EPOCH_ACTIVE_REF_BYTES_V1);
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&exact).expect("golden exact decode"),
        value
    );
    let bytes_digest: [u8; 32] = Sha256::digest(exact).into();
    assert_eq!(bytes_digest, GOLDEN_EPOCH_ACTIVE_REF_BYTES_SHA256_V1);

    let mut wrong_magic = exact;
    wrong_magic[0] ^= 1;
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&wrong_magic),
        Err(WholeNodeCheckpointErrorV1::WrongMagic)
    );
    let mut wrong_schema = exact;
    wrong_schema[9] = 2;
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&wrong_schema),
        Err(WholeNodeCheckpointErrorV1::UnsupportedSchema)
    );
    let mut reserved_phase = exact;
    reserved_phase[50] = 6;
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&reserved_phase),
        Err(WholeNodeCheckpointErrorV1::ReservedTag("phase"))
    );
    let mut zero_scope = exact;
    zero_scope[10..42].fill(0);
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&zero_scope),
        Err(WholeNodeCheckpointErrorV1::Type(
            WholeNodeCheckpointTypeErrorV1::ZeroScope
        ))
    );
    let mut zero_predecessor = exact;
    zero_predecessor[51..83].fill(0);
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&zero_predecessor),
        Err(WholeNodeCheckpointErrorV1::InvalidField(
            "noninitial checkpoint reference"
        ))
    );
    let mut zero_checksum = exact;
    zero_checksum[83..115].fill(0);
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&zero_checksum),
        Err(WholeNodeCheckpointErrorV1::Type(
            WholeNodeCheckpointTypeErrorV1::ZeroCheckpointChecksum
        ))
    );
    let mut noninitial_commissioned = exact;
    noninitial_commissioned[50] = WholeNodeCheckpointPhaseV1::Commissioned.tag();
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&noninitial_commissioned),
        Err(WholeNodeCheckpointErrorV1::InvalidField(
            "noninitial checkpoint reference"
        ))
    );
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&exact[..114]),
        Err(WholeNodeCheckpointErrorV1::InvalidField(
            "checkpoint reference length"
        ))
    );
    let mut trailing = exact.to_vec();
    trailing.push(0);
    assert_eq!(
        decode_whole_node_checkpoint_ref_v1_exact(&trailing),
        Err(WholeNodeCheckpointErrorV1::InvalidField(
            "checkpoint reference length"
        ))
    );
}

#[test]
fn full_checkpoint_record_rejects_reference_only_epoch_phase_payloads() {
    let commissioned = commissioned_checkpoint();
    let exact = commissioned.try_exact_bytes().expect("Commissioned bytes");
    for (phase, tag) in [
        (WholeNodeCheckpointPhaseV1::EpochActivationPrepared, 4),
        (WholeNodeCheckpointPhaseV1::EpochActive, 5),
    ] {
        let mut payload_mutant = exact.clone();
        payload_mutant[10] = tag;
        assert_eq!(
            decode_whole_node_checkpoint_v1_exact(&payload_mutant),
            Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                "epoch-transition reference-only phase"
            ))
        );

        let mut parts = commissioned.parts;
        parts.phase = phase;
        assert_eq!(
            WholeNodeCheckpointV1::from_parts(parts),
            Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                "epoch-transition reference-only phase"
            ))
        );
    }
}

#[test]
fn signature_committed_has_hard_coded_golden_length_checksum_and_bytes_digest() {
    let (_, _, _, value) = vote_cycle();
    let encoded = value.try_exact_bytes().expect("canonical bytes");
    assert_eq!(encoded.len(), GOLDEN_SIGNATURE_COMMITTED_LENGTH_V1);
    assert_eq!(
        value.checkpoint_checksum().as_bytes(),
        &GOLDEN_SIGNATURE_COMMITTED_CHECKSUM_V1
    );
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    assert_eq!(digest, GOLDEN_SIGNATURE_COMMITTED_BYTES_SHA256_V1);
}

#[test]
fn timeout_starts_a_new_cycle_without_application_attestation() {
    let (_, _, _, predecessor) = vote_cycle();
    let previous_core = predecessor.core_safety();
    let previous_fences = predecessor.fences();
    let fences = ProcessFencesCutRefV1::new(
        previous_fences.node(),
        previous_fences.application_attestor(),
        process_fence(4, 130),
    );
    let operation = SignOperationCutRefV1::new(
        SignOperationKindV1::TimeoutVote,
        digest(120),
        digest(121),
        digest(122),
        digest(123),
        SigningRoot::new([124; 32]),
        digest(125),
        predecessor.checkpoint_checksum(),
        None,
    )
    .expect("TimeoutVote operation");
    let timeout = WholeNodeCheckpointV1::app_validated_successor(
        &predecessor,
        fences,
        operation,
        CoreSafetyCutRefV1::new(
            previous_core.journal_id(),
            previous_core.verifier_profile_ref(),
            previous_core.config_ref(),
            9,
            digest(133),
            digest(134),
            digest(135),
            Some(previous_core.active_head_checksum()),
            Some(digest(123)),
        ),
        application_without_validation(predecessor.application()),
        predecessor.application_attestor(),
    )
    .expect("new timeout AppValidated cycle");
    timeout
        .validate_successor_of(&predecessor)
        .expect("SignatureCommitted -> AppValidated");
    assert_eq!(timeout.phase(), WholeNodeCheckpointPhaseV1::AppValidated);
    assert_eq!(timeout.generation().get(), 4);
    assert!(timeout.application().validation().is_none());
    assert_eq!(
        timeout.application().validation_lineage(),
        predecessor.application().validation_lineage()
    );
}

#[test]
fn validation_lineage_survives_timeout_and_rejects_scope_rollback_reuse_and_mutants() {
    let commissioned = commissioned_checkpoint();
    let store_scope_a = digest(150);
    let validation_id_10 = digest(151);
    let vote_10 = vote_app_validated_successor(
        &commissioned,
        10,
        store_scope_a,
        validation_id_10,
        digest(152),
        digest(153),
        130,
    )
    .expect("Vote generation 10");
    let vote_10_committed =
        complete_signing_cycle(&vote_10, 155).expect("Vote generation 10 committed");
    let timeout = timeout_app_validated_successor(&vote_10_committed, 170)
        .expect("Timeout retains validation lineage");
    assert!(timeout.application().validation().is_none());
    assert_eq!(
        timeout.application().validation_lineage(),
        vote_10_committed.application().validation_lineage()
    );
    let timeout_committed =
        complete_signing_cycle(&timeout, 180).expect("Timeout committed with retained lineage");
    let predecessor_lineage = timeout_committed
        .application()
        .validation_lineage()
        .expect("generation-10 lineage");
    assert_eq!(predecessor_lineage.validation_store_scope(), store_scope_a);
    assert_eq!(predecessor_lineage.last_generation().get(), 10);
    assert_eq!(predecessor_lineage.last_validation_id(), validation_id_10);

    assert_eq!(
        vote_app_validated_successor(
            &timeout_committed,
            11,
            digest(192),
            digest(193),
            digest(194),
            digest(195),
            195,
        ),
        Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
            "application validation store scope"
        ))
    );
    assert_eq!(
        vote_app_validated_successor(
            &timeout_committed,
            1,
            store_scope_a,
            digest(196),
            digest(197),
            digest(198),
            215,
        ),
        Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
            "application validation generation watermark"
        ))
    );
    assert_eq!(
        vote_app_validated_successor(
            &timeout_committed,
            11,
            store_scope_a,
            validation_id_10,
            digest(199),
            digest(200),
            205,
        ),
        Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
            "application validation identity"
        ))
    );

    let accepted = vote_app_validated_successor(
        &timeout_committed,
        11,
        store_scope_a,
        digest(201),
        digest(202),
        digest(203),
        225,
    )
    .expect("same-scope generation 11 with exact predecessor heads");
    accepted
        .validate_successor_of(&timeout_committed)
        .expect("accepted validation-lineage edge");
    let accepted_validation = accepted
        .application()
        .validation()
        .expect("generation-11 validation");
    assert_eq!(
        accepted_validation.validation_predecessor_record_chain_checksum(),
        Some(predecessor_lineage.record_chain_checksum())
    );
    assert_eq!(
        accepted_validation.validation_predecessor_active_head_checksum(),
        Some(predecessor_lineage.active_head_checksum())
    );

    let timeout_exact = timeout.try_exact_bytes().expect("Timeout exact bytes");
    let mut no_lineage = timeout;
    no_lineage.parts.application.validation_lineage = None;
    let no_lineage_exact = exact_bytes_after_private_mutation(&mut no_lineage);
    assert_eq!(timeout_exact.len(), no_lineage_exact.len() + 136);
    let lineage_offset = timeout_exact
        .iter()
        .zip(&no_lineage_exact)
        .position(|(with_lineage, without_lineage)| with_lineage != without_lineage)
        .expect("validation-lineage option offset");
    assert_eq!(timeout_exact[lineage_offset], 1);
    assert_eq!(no_lineage_exact[lineage_offset], 0);

    let mut reserved_lineage = timeout_exact.clone();
    reserved_lineage[lineage_offset] = 2;
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&reserved_lineage),
        Err(WholeNodeCheckpointErrorV1::ReservedTag(
            "Application validation lineage"
        ))
    );
    let mut zero_lineage_generation = timeout_exact.clone();
    zero_lineage_generation[lineage_offset + 33..lineage_offset + 41].fill(0);
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&zero_lineage_generation),
        Err(WholeNodeCheckpointErrorV1::Type(
            WholeNodeCheckpointTypeErrorV1::ZeroApplicationValidationGeneration
        ))
    );
    let mut stale_checksum = timeout_exact;
    stale_checksum[lineage_offset + 40] ^= 1;
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&stale_checksum),
        Err(WholeNodeCheckpointErrorV1::ChecksumMismatch)
    );

    let mut mismatched_lineage = accepted;
    mismatched_lineage
        .parts
        .application
        .validation_lineage
        .as_mut()
        .expect("accepted lineage")
        .active_head_checksum = digest(204);
    let mismatched_lineage_exact = exact_bytes_after_private_mutation(&mut mismatched_lineage);
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&mismatched_lineage_exact),
        Err(WholeNodeCheckpointErrorV1::InvalidField(
            "Application validation lineage/current cut"
        ))
    );

    let original_validation = accepted_validation;
    let wrong_predecessor_validation = ApplicationValidationCutRefV1::new(
        original_validation.generation(),
        original_validation.validation_store_scope(),
        original_validation.validation_id(),
        original_validation.validation_record_chain_checksum(),
        original_validation.validation_active_head_checksum(),
        original_validation.validation_predecessor_record_chain_checksum(),
        Some(digest(204)),
        original_validation.block_id(),
        original_validation.parent_block_id(),
        original_validation.height(),
        original_validation.view(),
        original_validation.payload_digest(),
        original_validation.result_state_root(),
        original_validation.receipts_root(),
        original_validation.evidence_root(),
        original_validation.overlay_checksum(),
        original_validation.source_artifact_checksum(),
        original_validation.validation_artifact_checksum(),
        original_validation.application_head_checksum(),
        original_validation.core_safety_record_checksum(),
        original_validation.whole_node_predecessor_checksum(),
    )
    .expect("coherent wrong-predecessor validation mutant");
    let mut wrong_predecessor = accepted;
    wrong_predecessor.parts.application.validation = Some(wrong_predecessor_validation);
    wrong_predecessor
        .parts
        .operation
        .as_mut()
        .expect("Vote operation")
        .application_validation_statement_digest =
        Some(wrong_predecessor_validation.statement_digest());
    wrong_predecessor
        .parts
        .application_attestor
        .attestation_digest = Some(wrong_predecessor_validation.statement_digest());
    let wrong_predecessor_exact = exact_bytes_after_private_mutation(&mut wrong_predecessor);
    let decoded_wrong_predecessor = decode_whole_node_checkpoint_v1_exact(&wrong_predecessor_exact)
        .expect("shape/checksum-coherent wrong predecessor mutant");
    assert_eq!(
        decoded_wrong_predecessor.validate_successor_of(&timeout_committed),
        Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
            "application validation lineage head"
        ))
    );
}

#[test]
fn reserved_tags_trailing_truncation_and_length_overflow_fail_closed() {
    let (_, _, _, value) = vote_cycle();
    let encoded = value.try_exact_bytes().expect("canonical bytes");

    let mut reserved_phase = encoded.clone();
    reserved_phase[10] = 0xff;
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&reserved_phase),
        Err(WholeNodeCheckpointErrorV1::ReservedTag("phase"))
    );

    let mut reserved_predecessor = encoded.clone();
    reserved_predecessor[19] = 0xff;
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&reserved_predecessor),
        Err(WholeNodeCheckpointErrorV1::ReservedTag(
            "predecessor checksum"
        ))
    );

    let operation_start = encoded.len() - 32 - 259;
    let mut reserved_operation_kind = encoded.clone();
    reserved_operation_kind[operation_start + 1] = 0xfe;
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&reserved_operation_kind),
        Err(WholeNodeCheckpointErrorV1::ReservedTag(
            "sign operation kind"
        ))
    );

    let signer_start = operation_start - 300;
    let mut reserved_signer_state = encoded.clone();
    reserved_signer_state[signer_start + 233] = 0xfd;
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&reserved_signer_state),
        Err(WholeNodeCheckpointErrorV1::ReservedTag(
            "signer journal state"
        ))
    );

    let mut trailing = encoded.clone();
    trailing.push(1);
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&trailing),
        Err(WholeNodeCheckpointErrorV1::TrailingBytes)
    );
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&encoded[..encoded.len() - 1]),
        Err(WholeNodeCheckpointErrorV1::UnexpectedEnd)
    );
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&vec![0; MAX_WHOLE_NODE_CHECKPOINT_BYTES_V1 + 1]),
        Err(WholeNodeCheckpointErrorV1::LengthLimitExceeded)
    );
}

fn exact_bytes_after_private_mutation(value: &mut WholeNodeCheckpointV1) -> Vec<u8> {
    value.checkpoint_checksum =
        crate::codec::recompute_checkpoint_checksum_v1(value).expect("mutant checksum");
    let mut encoded = crate::codec::encode_checkpoint_prefix_v1(value).expect("mutant prefix");
    encoded.extend_from_slice(value.checkpoint_checksum.as_bytes());
    encoded
}

#[test]
fn checksum_and_cross_binding_field_mutants_fail_closed() {
    let (commissioned, app_validated, safety_prepared, signature_committed) = vote_cycle();
    let mut raw_checksum_mutant = signature_committed
        .try_exact_bytes()
        .expect("canonical bytes");
    raw_checksum_mutant[84] ^= 1;
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&raw_checksum_mutant),
        Err(WholeNodeCheckpointErrorV1::ChecksumMismatch)
    );

    let mut chain_mutant = app_validated;
    chain_mutant.parts.chain.genesis_hash = GenesisHash::new([119; 32]);
    let chain_mutant_bytes = exact_bytes_after_private_mutation(&mut chain_mutant);
    let decoded_chain_mutant =
        decode_whole_node_checkpoint_v1_exact(&chain_mutant_bytes).expect("shape-valid mutant");
    assert!(decoded_chain_mutant
        .validate_successor_of(&commissioned)
        .is_err());

    let mut intent_mutant = safety_prepared;
    intent_mutant.parts.core_safety.pending_intent_checksum = Some(digest(119));
    let intent_mutant_bytes = exact_bytes_after_private_mutation(&mut intent_mutant);
    assert!(matches!(
        decode_whole_node_checkpoint_v1_exact(&intent_mutant_bytes),
        Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(_))
    ));

    let mut validation_mutant = signature_committed;
    validation_mutant
        .parts
        .application
        .validation
        .as_mut()
        .expect("Vote validation")
        .statement_digest = digest(119);
    let validation_mutant_bytes = exact_bytes_after_private_mutation(&mut validation_mutant);
    assert_eq!(
        decode_whole_node_checkpoint_v1_exact(&validation_mutant_bytes),
        Err(WholeNodeCheckpointErrorV1::InvalidField(
            "application validation statement digest"
        ))
    );
}

#[test]
fn skip_reorder_repeat_and_cumulative_cut_mutants_are_rejected() {
    let (commissioned, app_validated, safety_prepared, signature_committed) = vote_cycle();
    assert!(safety_prepared
        .validate_successor_of(&commissioned)
        .is_err());
    assert!(signature_committed
        .validate_successor_of(&app_validated)
        .is_err());
    assert!(app_validated
        .validate_successor_of(&safety_prepared)
        .is_err());
    assert!(signature_committed
        .validate_successor_of(&signature_committed)
        .is_err());

    let mut cuts = [
        safety_prepared,
        safety_prepared,
        safety_prepared,
        safety_prepared,
        safety_prepared,
    ];
    cuts[0].parts.fences.node = process_fence(2, 140);
    cuts[1].parts.roles.node_role_bindings_checksum = digest(140);
    cuts[2].parts.core_safety.active_head_checksum = digest(140);
    cuts[3].parts.application.active_head_checksum = digest(140);
    cuts[4].parts.application_attestor.active_head_checksum = digest(140);
    for mutant in cuts {
        assert!(mutant.validate_successor_of(&app_validated).is_err());
    }

    let mut remote_identity = safety_prepared;
    remote_identity.parts.remote_safety.profile_checksum = digest(140);
    assert!(remote_identity
        .validate_successor_of(&app_validated)
        .is_err());
    let mut signer_identity = safety_prepared;
    signer_identity.parts.signer.profile_checksum = digest(140);
    assert!(signer_identity
        .validate_successor_of(&app_validated)
        .is_err());
    let mut operation = safety_prepared;
    operation
        .parts
        .operation
        .as_mut()
        .expect("operation")
        .request_nonce = digest(140);
    assert!(operation.validate_successor_of(&app_validated).is_err());
}

#[test]
fn source_and_manifest_keep_every_authority_and_effect_boundary_closed() {
    let lib_source = include_str!("lib.rs");
    let model_source = include_str!("model.rs");
    let codec_source = include_str!("codec.rs");
    let reference_source = include_str!("reference.rs");
    let sources = [
        lib_source,
        include_str!("ids.rs"),
        model_source,
        codec_source,
        reference_source,
    ]
    .concat();
    let manifest = include_str!("../Cargo.toml");

    for required_false_truth in [
        "decoded_record_authority = false",
        "checkpoint_reference_authority = false",
        "epoch_activation_authority = false",
        "application_validation_authority = false",
        "safety_rules_authority = false",
        "signer_authority = false",
        "lease_authority = false",
        "role_binding_authority = false",
        "persistence_authority = false",
        "checkpoint_store = false",
        "successor_cas = false",
        "external_anti_rollback_authority = false",
        "application_attestation_producer = false",
        "signature_producer = false",
        "hsm_adapter = false",
        "runtime_activation = false",
        "post_epoch_signing_cycle_bridge = false",
        "production_candidate = false",
        "production_activation = false",
        "production_consensus_activation = false",
    ] {
        assert!(manifest.contains(required_false_truth));
    }
    for forbidden_dependency in [
        "rusqlite",
        "tokio",
        "ed25519-dalek",
        "trnm-consensus-core",
        "trnm-consensus-safety-store",
        "trnm-consensus-signer-journal",
        "trnm-native-application-sqlite",
        "trnm-poco-node",
    ] {
        assert!(!manifest.contains(forbidden_dependency));
    }
    for forbidden_api in [
        concat!("pub trait ", "CheckpointStore"),
        concat!("pub fn ", "compare_and_swap"),
        concat!("pub fn ", "compare_and_advance"),
        concat!("pub fn ", "sign("),
        concat!("pub fn ", "produce_attestation"),
        concat!("pub struct ", "Committed"),
        concat!("pub struct ", "Authorization"),
        concat!("pub struct ", "Capability"),
        concat!("Secret", "Key"),
        concat!("Signing", "Key"),
    ] {
        assert!(
            !sources.contains(forbidden_api),
            "forbidden API: {forbidden_api}"
        );
    }
    assert!(sources.contains(
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct WholeNodeCheckpointV1"
    ));
    assert_eq!(
        sources
            .matches("pub struct WholeNodeCheckpointRefV1")
            .count(),
        1
    );
    assert_eq!(
        sources
            .lines()
            .filter(|line| line.starts_with("pub struct ") && line.contains("CheckpointRefV1"))
            .count(),
        1
    );
    assert_eq!(sources.matches("b\"TRNMWR01\"").count(), 1);
    assert!(reference_source.contains(
        "pub const WHOLE_NODE_CHECKPOINT_REF_BYTES_V1: usize = 8 + 2 + 32 + 8 + 1 + 32 + 32;"
    ));
    assert_eq!(lib_source.matches("WholeNodeCheckpointRefV1").count(), 1);
    assert!(model_source.contains("Self::EpochActivationPrepared => 4"));
    assert!(model_source.contains("Self::EpochActive => 5"));
    assert!(model_source.contains("pub struct ApplicationValidationLineageCutRefV1"));
    assert!(model_source.contains("validation_predecessor_record_chain_checksum"));
    assert!(model_source.contains("validation_predecessor_active_head_checksum"));
    assert!(codec_source.contains("if !phase.is_signing_cycle_record_phase()"));
    assert!(codec_source.contains("encode_option_application_validation_lineage_v1"));
    assert!(codec_source.contains("decode_option_application_validation_lineage_v1"));
    for required_false_api in [
        "pub const WHOLE_NODE_CHECKPOINT_DECODED_RECORD_AUTHORITY_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_REFERENCE_AUTHORITY_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_EPOCH_ACTIVATION_AUTHORITY_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_APPLICATION_VALIDATION_AUTHORITY_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_SAFETY_RULES_AUTHORITY_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_SIGNER_AUTHORITY_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_LEASE_AUTHORITY_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_ROLE_BINDING_AUTHORITY_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_PERSISTENCE_AUTHORITY_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_STORE_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_SUCCESSOR_CAS_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_EXTERNAL_ANTI_ROLLBACK_AUTHORITY_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_APPLICATION_ATTESTATION_PRODUCER_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_SIGNATURE_PRODUCER_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_HSM_ADAPTER_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_RUNTIME_ACTIVATION_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_POST_EPOCH_SIGNING_CYCLE_BRIDGE_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_PRODUCTION_CANDIDATE_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_PRODUCTION_ACTIVATION_V1: bool = false;",
        "pub const WHOLE_NODE_CHECKPOINT_PRODUCTION_CONSENSUS_ACTIVATION_V1: bool = false;",
    ] {
        assert!(sources.contains(required_false_api));
    }
    for forbidden_public_field in [
        "pub scope:",
        "pub generation:",
        "pub phase:",
        "pub chain:",
        "pub signer:",
        "pub operation:",
    ] {
        assert!(!sources.contains(forbidden_public_field));
    }
}
