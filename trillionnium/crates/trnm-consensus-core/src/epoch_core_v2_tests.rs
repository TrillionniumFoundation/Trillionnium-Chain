use super::*;
use crate::epoch_state_tests_v1;
use crate::epoch_successor_fixture_tests_v2 as fixture;
use crate::{
    decode_epoch_safety_record_v1_exact, decode_epoch_safety_record_v2_exact,
    encode_epoch_safety_record_v1, encode_epoch_safety_record_v2,
    minimum_epoch_safety_record_limits_v1, minimum_epoch_safety_record_limits_v2,
    prepare_epoch_handoff_evidence_v2, EpochPreparationEntryV2, EpochPreparationV2,
    EpochSafetyStateRecordContextV1, EpochSafetyStateRecordContextV2,
};
use crate::{BlockIdOverlayRefV0, ValidatedPayloadArtifactRefV0};
use trnm_consensus_crypto::{StrictEd25519Verifier, StrictEpochRuntimeContextV1};
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_validator_set_v0_exact, Cev0AdmissionBudgetV0,
    EpochActivationEvidencePreimagesV0,
};

const SOURCE_GENERATION: u64 = 7;
const SOURCE_REVISION: u64 = 91;
const UNRESOLVED: &str =
    "epoch activation predecessor is unresolved, foreign, or not exact checkpoint";

struct TransitionFixture {
    evidence: fixture::GenuineSuccessorFixtureV1,
    old_config: CoreConfig,
    next_config: CoreConfig,
    initial_artifact: ValidatedPayloadArtifactRefV0,
}
impl TransitionFixture {
    fn new() -> Box<Self> {
        let runtime = Box::new(
            StrictEpochRuntimeContextV1::from_activation_v1(fixture::predecessor()).unwrap(),
        );
        let evidence = fixture::genuine_successor_fixture_v1(&runtime, true);
        let old_config = epoch_state_tests_v1::config(&runtime);
        let next_config = CoreConfig::new(
            old_config.local_validator(),
            decode_validator_set_v0_exact(&evidence.second_roots[5]).unwrap(),
            decode_consensus_parameters_v0_exact(&evidence.second_roots[6]).unwrap(),
            old_config.trusted_genesis_timestamp_ms(),
            old_config.max_blocks(),
            old_config.max_observed_messages(),
        )
        .unwrap();
        let initial_artifact = epoch_state_tests_v1::artifact(&runtime);
        Box::new(Self {
            evidence,
            old_config,
            next_config,
            initial_artifact,
        })
    }

    fn preparation(&self, include_successor: bool) -> EpochPreparationV2 {
        let bytes: Vec<_> = self
            .evidence
            .canonical_ancestry
            .iter()
            .map(|header| header.try_cev0_bytes().unwrap())
            .collect();
        let ancestry: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
        let entries = [
            EpochPreparationEntryV2 {
                binding_ref: self.evidence.root_binding,
                retained_ancestry: &[],
                evidence: roots(&self.evidence.original_roots),
            },
            EpochPreparationEntryV2 {
                binding_ref: self.evidence.terminal_binding,
                retained_ancestry: &ancestry,
                evidence: roots(&self.evidence.second_roots),
            },
        ];
        prepare_epoch_handoff_evidence_v2(
            &entries[..if include_successor { 2 } else { 1 }],
            &self.evidence.root_validator_set,
            &self.evidence.root_parameters,
            self.evidence.root_binding,
            if include_successor {
                self.evidence.terminal_binding
            } else {
                self.evidence.root_binding
            },
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap()
    }

    fn source_context(&self) -> EpochSafetyStateRecordContextV2<'_> {
        let preparation = self.preparation(false);
        let limits = minimum_epoch_safety_record_limits_v2(&self.old_config, &preparation).unwrap();
        EpochSafetyStateRecordContextV2::new(
            &self.old_config,
            preparation,
            self.initial_artifact,
            SOURCE_GENERATION,
            limits,
        )
        .unwrap()
    }

    fn target_context(
        &self,
        generation: u64,
        overlay_checksum: u8,
    ) -> EpochSafetyStateRecordContextV2<'_> {
        let preparation = self.preparation(true);
        let header = preparation
            .authority_v2()
            .old_checkpoint_finality()
            .finalized_block()
            .header();
        // Explicit inert application fixture IDs. No native execution, native
        // receipt or actual journal durability is asserted by these Core tests.
        let artifact = ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(header.id(), header.parent_id(), [overlay_checksum; 32]),
            [0x72; 32],
        );
        let limits =
            minimum_epoch_safety_record_limits_v2(&self.next_config, &preparation).unwrap();
        EpochSafetyStateRecordContextV2::new(
            &self.next_config,
            preparation,
            artifact,
            generation,
            limits,
        )
        .unwrap()
    }
}

fn roots(r: &[Vec<u8>; 8]) -> EpochActivationEvidencePreimagesV0<'_> {
    EpochActivationEvidencePreimagesV0 {
        old_checkpoint_finality: &r[0],
        next_epoch_commitment: &r[1],
        authorization_kernel: &r[2],
        old_validator_set: &r[3],
        old_consensus_parameters: &r[4],
        new_validator_set: &r[5],
        new_consensus_parameters: &r[6],
        authenticated_checkpoint_parent_header: &r[7],
    }
}

fn settled_source(
    config: &CoreConfig,
    epoch: crate::EpochCoreStateV1,
    next: &EpochSafetyStateRecordContextV2<'_>,
) -> SafetyState {
    let mut state = SafetyState::from_epoch_activation_v1(config, epoch, SOURCE_REVISION).unwrap();
    let activation = next.runtime().activation();
    let proof = activation.old_checkpoint_finality();
    let target =
        crate::QualifiedFinalizedTipV1::from_header(proof.finalized_block().header()).tip();
    let parent = crate::QualifiedFinalizedTipV1::from_header(
        activation.authenticated_checkpoint_parent_header(),
    )
    .tip();
    let overlay = next.epoch().checkpoint_artifact().overlay();
    let durable = DurableFinalizationV0::new(parent, proof.clone(), overlay).unwrap();
    state.set_finalized(target);
    state.set_application_applied(target);
    state.set_high_qc(QcReferenceV0::ordinary(
        proof.grandchild().certifying_qc().clone(),
    ));
    state.set_locked_qc(QcReferenceV0::ordinary(
        proof.child().certifying_qc().clone(),
    ));
    state.set_current_view(proof.grandchild().header().view().checked_next().unwrap());
    state.set_payload_terminal_facts(vec![PayloadTerminalFact::new_valid(
        overlay,
        SOURCE_REVISION,
    )]);
    state.set_last_finalization(durable);
    // The signed proof, original predecessor runtime and all durable semantic
    // joins must pass before any activation assertion can count as coverage.
    Core::validate_persisted_state_v0(config, &state, &StrictEd25519Verifier).unwrap();
    state
}

fn recover_source(
    state: &SafetyState,
    context: &EpochSafetyStateRecordContextV2<'_>,
) -> StrictEpochCoreRecoveryV2 {
    Core::validate_persisted_state_v0(context.core_config(), state, &StrictEd25519Verifier)
        .unwrap();
    let raw = encode_epoch_safety_record_v2(state, context).unwrap();
    let record = decode_epoch_safety_record_v2_exact(&raw, context).unwrap();
    Core::prepare_epoch_recovery_v2(&record, context, record.record_checksum()).unwrap()
}

fn assert_pending_barrier(mut prepared: PreparedEpochCoreActivationV2, previous: &SafetyState) {
    assert_eq!(prepared.predecessor(), previous);
    assert_eq!(prepared.state().revision(), previous.revision() + 1);
    assert_eq!(
        prepared
            .state()
            .epoch_state_v1()
            .unwrap()
            .owner_generation(),
        SOURCE_GENERATION + 1
    );
    assert_eq!(prepared.initial_persistence_v2().state(), prepared.state());
    assert!(prepared
        .persistence_binding_v2()
        .accepts(prepared.initial_persistence_v2()));
    assert!(prepared.state().pending_sign().is_none());
    assert!(!prepared.inner.core.awaiting_signature);
    let pending = prepared
        .inner
        .core
        .pending_persistence
        .as_ref()
        .unwrap()
        .clone();
    assert_eq!(pending.barrier, prepared.initial_persistence_v2().barrier());
    assert_eq!(pending.deferred.as_slice(), &[DeferredEffect::ArmViewTimer]);
    // Test-only access to the private Core verifies that neither Resume nor a
    // mismatching ACK can run the deferred timer or request any signature.
    assert!(matches!(
        prepared
            .inner
            .core
            .step(Input::Resume, &StrictEd25519Verifier),
        Err(CoreError::Busy(
            "waiting for durable safety-state acknowledgement"
        ))
    ));
    assert!(matches!(
        prepared.inner.core.step(
            Input::StorageAck {
                barrier: BarrierId::new(1)
            },
            &StrictEd25519Verifier
        ),
        Err(CoreError::UnexpectedStorageAck)
    ));
    assert_eq!(
        prepared.inner.core.pending_persistence.as_ref(),
        Some(&pending)
    );
    assert_eq!(prepared.state().revision(), previous.revision() + 1);
    assert!(prepared.state().pending_sign().is_none());
    // There is deliberately no successful synthetic ACK here. The public V2
    // wrappers' compile-fail tests separately prohibit V1 host conversions.
}

#[test]
fn genuine_codec2_source_transition_retains_exact_prefix_and_initial_barrier() {
    let fixture = TransitionFixture::new();
    let source_context = fixture.source_context();
    let target = fixture.target_context(SOURCE_GENERATION + 1, 0x71);
    let source = settled_source(&fixture.old_config, source_context.epoch().clone(), &target);
    let recovery = recover_source(&source, &source_context);
    let prepared = recovery.prepare_next_epoch_v2(&target).unwrap();
    assert_eq!(prepared.state().epoch_state_v1(), Some(target.epoch()));
    assert_eq!(prepared.state().finalized(), source.finalized());
    assert_eq!(
        prepared.state().application_applied(),
        source.application_applied()
    );
    assert_eq!(prepared.state().current_view(), View::new(1));
    let raw = encode_epoch_safety_record_v2(prepared.state(), &target).unwrap();
    let record = decode_epoch_safety_record_v2_exact(&raw, &target).unwrap();
    let reopened =
        Core::prepare_epoch_recovery_v2(&record, &target, record.record_checksum()).unwrap();
    assert_eq!(reopened.state(), prepared.state());
    assert_pending_barrier(prepared, &source);

    let wrong_generation = fixture.target_context(SOURCE_GENERATION + 2, 0x71);
    assert!(matches!(
        recovery.prepare_next_epoch_v2(&wrong_generation),
        Err(CoreError::InvalidRecovery(UNRESOLVED))
    ));
    let foreign_overlay = fixture.target_context(SOURCE_GENERATION + 1, 0x73);
    assert!(matches!(
        recovery.prepare_next_epoch_v2(&foreign_overlay),
        Err(CoreError::InvalidRecovery(UNRESOLVED))
    ));

    // A fully valid but unapplied finalization cut is also an inert recovery;
    // it must not be mistaken for the settled source of the next epoch.
    let mut unsettled = source.clone();
    let durable = source.last_finalization().unwrap().clone();
    unsettled.set_application_applied(durable.authenticated_parent());
    unsettled.set_finalization_queue(vec![durable.clone()]);
    unsettled.set_pending_finalize(Some(durable.proof_id()));
    let unsettled_recovery = recover_source(&unsettled, &source_context);
    assert!(matches!(
        unsettled_recovery.prepare_next_epoch_v2(&target),
        Err(CoreError::InvalidRecovery(UNRESOLVED))
    ));
}

#[test]
fn genuine_legacy_source_can_upgrade_only_with_its_retained_first_entry() {
    let fixture = TransitionFixture::new();
    let runtime = StrictEpochRuntimeContextV1::from_activation_v1(fixture::predecessor()).unwrap();
    let limits = minimum_epoch_safety_record_limits_v1(&fixture.old_config, &runtime).unwrap();
    let source_context = EpochSafetyStateRecordContextV1::new(
        &fixture.old_config,
        runtime,
        fixture.initial_artifact,
        SOURCE_GENERATION,
        limits,
    )
    .unwrap();
    let target = fixture.target_context(SOURCE_GENERATION + 1, 0x71);
    let source = settled_source(&fixture.old_config, source_context.epoch().clone(), &target);
    let raw = encode_epoch_safety_record_v1(&source, &source_context).unwrap();
    let record = decode_epoch_safety_record_v1_exact(&raw, &source_context).unwrap();
    let recovery =
        Core::prepare_epoch_recovery_v1(&record, &source_context, record.record_checksum())
            .unwrap();
    assert_pending_barrier(recovery.prepare_next_epoch_v2(&target).unwrap(), &source);

    // A genuine one-entry target omits the required successor; its own strict
    // context is valid, but it cannot replace the two-entry upgrade provenance.
    let no_append = fixture.source_context();
    no_append.epoch().strict_context().unwrap();
    assert!(matches!(
        recovery.prepare_next_epoch_v2(&no_append),
        Err(CoreError::InvalidRecovery(
            "epoch provenance is not an exact one-entry extension"
        ))
    ));
}

#[test]
fn genuine_three_entry_prefix_cannot_skip_one_source_transition() {
    let fixture = TransitionFixture::new();
    let source_context = fixture.source_context();
    let target = fixture.target_context(SOURCE_GENERATION + 1, 0x71);
    let source = settled_source(&fixture.old_config, source_context.epoch().clone(), &target);
    let recovery = recover_source(&source, &source_context);
    let third = fixture::genuine_successor_fixture_v1(target.runtime(), true);
    let first_bytes: Vec<_> = fixture
        .evidence
        .canonical_ancestry
        .iter()
        .map(|h| h.try_cev0_bytes().unwrap())
        .collect();
    let first_headers: Vec<&[u8]> = first_bytes.iter().map(Vec::as_slice).collect();
    let second_bytes: Vec<_> = third
        .canonical_ancestry
        .iter()
        .map(|h| h.try_cev0_bytes().unwrap())
        .collect();
    let second_headers: Vec<&[u8]> = second_bytes.iter().map(Vec::as_slice).collect();
    let entries = [
        EpochPreparationEntryV2 {
            binding_ref: fixture.evidence.root_binding,
            retained_ancestry: &[],
            evidence: roots(&fixture.evidence.original_roots),
        },
        EpochPreparationEntryV2 {
            binding_ref: fixture.evidence.terminal_binding,
            retained_ancestry: &first_headers,
            evidence: roots(&fixture.evidence.second_roots),
        },
        EpochPreparationEntryV2 {
            binding_ref: third.terminal_binding,
            retained_ancestry: &second_headers,
            evidence: roots(&third.second_roots),
        },
    ];
    let preparation = prepare_epoch_handoff_evidence_v2(
        &entries,
        &fixture.evidence.root_validator_set,
        &fixture.evidence.root_parameters,
        fixture.evidence.root_binding,
        third.terminal_binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let activation = preparation.authority_v2();
    let config = CoreConfig::new(
        fixture.old_config.local_validator(),
        activation.new_validator_set().clone(),
        *activation.new_consensus_parameters(),
        0,
        32,
        32,
    )
    .unwrap();
    let header = activation
        .old_checkpoint_finality()
        .finalized_block()
        .header();
    let artifact = ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(header.id(), header.parent_id(), [0x71; 32]),
        [0x72; 32],
    );
    let limits = minimum_epoch_safety_record_limits_v2(&config, &preparation).unwrap();
    let skip = EpochSafetyStateRecordContextV2::new(
        &config,
        preparation,
        artifact,
        SOURCE_GENERATION + 1,
        limits,
    )
    .unwrap();
    skip.epoch().strict_context().unwrap();
    assert!(matches!(
        recovery.prepare_next_epoch_v2(&skip),
        Err(CoreError::InvalidRecovery(
            "epoch provenance is not an exact one-entry extension"
        ))
    ));
}
