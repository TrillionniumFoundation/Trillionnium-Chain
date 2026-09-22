// Genuine candidate Core/native application adapter. No Safety row is invented
// or promoted with SQL: every P/Valid, signature and apply callback follows the
// exact corresponding physical-store readback. This is test custody only.
include!("crash.rs");
use std::collections::{BTreeMap, VecDeque};
use trnm_native_application::{
    BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0, NativeBlockExecutionRequestV0,
    NativeEpochBlockExecutionRequestV1, NativeEpochBlockPreviewRequestV1,
    NativeExpectedBlockCommitmentsV0, ValidatorSetIdV0,
};
use trnm_native_execution_v0::{
    AuthenticatedEpochApplicationEdgeV1, CommittedLaterEpochPreHandoffV1,
    DurableNativeApplicationV0, LaterEpochApplicationEdgeV1, NativeBlockPreviewRequestV0,
    PreparedNativeEpochExecutionV1,
};

enum ActualJournalV4 {
    Eleven {
        owner: SqliteEpochSafetyJournalV3,
        profile: EpochSafetyJournalProfileV3,
        pin: EpochSafetyHeadPinV3,
    },
    Twelve {
        owner: SqliteEpochSafetyJournalV4,
        profile: EpochSafetyJournalProfileV4,
        pin: EpochSafetyHeadPinV4,
    },
}
impl ActualJournalV4 {
    fn require_state(&self, state: &SafetyState) {
        match self {
            Self::Eleven { owner, pin, .. } => {
                let fresh = owner.fresh_read_v3(*pin).unwrap();
                assert!(fresh.belongs_to_store_at_path_v3(owner, owner.path_v3()));
                assert_eq!(fresh.state_v3(), state);
            }
            Self::Twelve { owner, pin, .. } => {
                let fresh = owner.fresh_read_v4(*pin).unwrap();
                assert!(fresh.belongs_to_store_at_path_v4(owner, owner.path_v4()));
                assert_eq!(fresh.state_v4(), state);
            }
        }
    }
    fn persist(
        &mut self,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
    ) {
        match self {
            Self::Eleven { owner, pin, .. } => {
                let fresh = owner.persist_exact_v3(*pin, request, transition).unwrap();
                if request.native_finalization_applied_v0().is_some()
                    && request.state().application_applied().height().get() % 10 == 8
                {
                    let retry = owner
                        .persist_exact_v3(fresh.pin_v3(), request, transition)
                        .unwrap();
                    assert_eq!(fresh.pin_v3(), retry.pin_v3());
                }
                assert_eq!(fresh.state_v3(), request.state());
                *pin = fresh.pin_v3();
            }
            Self::Twelve { owner, pin, .. } => {
                let fresh = owner.persist_exact_v4(*pin, request, transition).unwrap();
                if request.native_finalization_applied_v0().is_some()
                    && request.state().application_applied().height().get() % 10 == 8
                {
                    let retry = owner
                        .persist_exact_v4(fresh.pin_v4(), request, transition)
                        .unwrap();
                    assert_eq!(fresh.pin_v4(), retry.pin_v4());
                }
                assert_eq!(fresh.state_v4(), request.state());
                *pin = fresh.pin_v4();
            }
        }
    }
    fn generation(&self) -> u64 {
        match self {
            Self::Eleven { profile, .. } => profile.owner_generation_v3(),
            Self::Twelve { profile, .. } => profile.owner_generation_v4(),
        }
    }
    fn path(&self) -> &Path {
        match self {
            Self::Eleven { owner, .. } => owner.path_v3(),
            Self::Twelve { owner, .. } => owner.path_v4(),
        }
    }
    fn source(&self) -> EpochSafetySourceOwnerV4<'_> {
        match self {
            Self::Eleven { owner, pin, .. } => EpochSafetySourceOwnerV4::Journal11(owner, *pin),
            Self::Twelve { owner, pin, .. } => EpochSafetySourceOwnerV4::Journal12(owner, *pin),
        }
    }
    fn stale_source(&self) -> EpochSafetySourceOwnerV4<'_> {
        match self {
            Self::Eleven { owner, pin, .. } => EpochSafetySourceOwnerV4::Journal11(
                owner,
                EpochSafetyHeadPinV3 {
                    revision: pin.revision - 1,
                    ..*pin
                },
            ),
            Self::Twelve { owner, pin, .. } => EpochSafetySourceOwnerV4::Journal12(
                owner,
                EpochSafetyHeadPinV4 {
                    revision: pin.revision - 1,
                    ..*pin
                },
            ),
        }
    }
    fn target_profile(
        &self,
        context: &EpochSafetyStateRecordContextV2<'_>,
    ) -> EpochSafetyJournalProfileV4 {
        match self {
            Self::Eleven { profile, .. } => {
                EpochSafetyJournalProfileV4::from_journal11_v4(profile, context).unwrap()
            }
            Self::Twelve { profile, .. } => {
                EpochSafetyJournalProfileV4::from_journal12_v4(profile, context).unwrap()
            }
        }
    }
}

enum ActualNativeEdgeV4 {
    First(Box<AuthenticatedEpochApplicationEdgeV1>),
    Later(Box<LaterEpochApplicationEdgeV1>),
}
struct ActualPV4 {
    prepared: PreparedNativeEpochExecutionV1,
    commitments: ValidatedBlockCommitmentsV0,
    artifact: ValidatedPayloadArtifactRefV0,
    route: Option<(PayloadValidationRouteV0, ValidationId)>,
}
struct NextCheckpointV4 {
    set: ValidatorSet,
    parameters: ConsensusParametersV0,
    commitment: NextEpochCommitmentV0,
    header: BlockHeader,
    parent: BlockHeader,
    receipt: Option<CommittedLaterEpochPreHandoffV1>,
    proof: Option<FinalityProofV0>,
    descriptor: Option<HandoffDescriptorV0>,
}
struct ActualEpochDriverV4 {
    core: Option<Box<PendingEpochHostDriverV2>>,
    journal: ActualJournalV4,
    source_commissioning: OldEpochSafetyJournalProfileV1,
    app: DurableNativeApplicationV0,
    edge: ActualNativeEdgeV4,
    contexts: Vec<Box<StrictEpochRuntimeContextV1>>,
    ancestries: Vec<Vec<BlockHeader>>,
    headers: BTreeMap<u64, BlockHeader>,
    blocks: BTreeMap<BlockId, ActualPV4>,
    seal: CoreIssuedApplicationSealAuthorityV0,
    apply: CoreIssuedApplicationFinalizationApplyAuthorityV0,
    checkpoint: Option<NextCheckpointV4>,
    signatures: usize,
}
fn native_test_digest_v4(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"trnm.journal12.real-native-fixture.v1");
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}
fn epoch_fixture_key_v4(set: &ValidatorSet, id: ValidatorId) -> SigningKey {
    let index = set.validators().iter().position(|v| v.id() == id).unwrap();
    SigningKey::from_bytes(&[20 + index as u8; 32])
}
fn epoch_fixture_qc_v4(header: &BlockHeader, set: &ValidatorSet) -> QuorumCertificate {
    let root =
        Vote::signing_root_for_set(set, header.view(), header.height(), header.id()).unwrap();
    let votes = set
        .validators()
        .iter()
        .take(3)
        .map(|v| {
            Vote::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                header.view(),
                header.height(),
                header.id(),
                set.id(),
                v.id(),
                SignatureBytes::from_array(
                    epoch_fixture_key_v4(set, v.id())
                        .sign(root.as_bytes())
                        .to_bytes(),
                ),
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

impl ActualEpochDriverV4 {
    fn core(&self) -> &PendingEpochHostDriverV2 {
        self.core.as_ref().unwrap()
    }
    fn core_mut(&mut self) -> &mut PendingEpochHostDriverV2 {
        self.core.as_mut().unwrap()
    }
    fn runtime(&self) -> &StrictEpochRuntimeContextV1 {
        self.contexts.last().unwrap()
    }
    fn step(&mut self, input: Input) {
        let effects = self.core_mut().step_v2(input).unwrap();
        self.effects(effects);
    }
    #[inline(never)]
    fn effects(&mut self, effects: Vec<Effect>) {
        let mut pending: VecDeque<_> = effects.into();
        while let Some(effect) = pending.pop_front() {
            let next = match effect {
                Effect::PersistSafetyState(request) => {
                    let transition = self.transition(&request);
                    self.journal.persist(&request, &transition);
                    self.core_mut()
                        .step_v2(Input::StorageAck {
                            barrier: request.barrier(),
                        })
                        .unwrap()
                }
                Effect::ValidatePayload(request) | Effect::ValidateSyncedPayload(request) => {
                    let (route, id, block, _parent, permit) =
                        request.try_claim().unwrap().into_parts();
                    let actual = self
                        .blocks
                        .get_mut(&block.id())
                        .expect("Core validation has actual native P");
                    let fresh = self
                        .app
                        .confirm_prepared_epoch_execution_v1(&actual.prepared)
                        .unwrap();
                    assert!(fresh.belongs_to_application_at_path(&self.app, self.app.path()));
                    assert_eq!(
                        fresh.artifact_checksum(),
                        actual.artifact.source_artifact_checksum()
                    );
                    assert_eq!(fresh.prepared().header().unwrap(), *block.header());
                    actual.route = Some((route, id));
                    let proof = self.seal.seal_after_application_store_commit_v0(
                        permit,
                        actual.commitments,
                        actual.artifact,
                    );
                    self.core_mut()
                        .step_application_sealed_valid_v2(&proof)
                        .unwrap()
                }
                Effect::RequestSignature { intent } => {
                    self.journal.require_state(self.core().state());
                    let before = Box::new(self.core().state().clone());
                    let signature = SignatureBytes::from_array(
                        epoch_fixture_key_v4(
                            self.core().config().validator_set(),
                            self.core().config().local_validator(),
                        )
                        .sign(intent.signing_root().as_bytes())
                        .to_bytes(),
                    );
                    self.signatures += 1;
                    let released = self
                        .core_mut()
                        .step_v2(Input::SignatureReady {
                            id: SignId::new(intent.signing_root()),
                            signature,
                        })
                        .unwrap();
                    assert!(released
                        .iter()
                        .all(|effect| matches!(effect, Effect::Broadcast(_))));
                    self.core_mut()
                        .persist_signature_release_v2(&before)
                        .unwrap()
                }
                Effect::Finalize(finalization) => self.apply_finalization(&finalization),
                Effect::Broadcast(_) | Effect::ArmViewTimer { .. } => Vec::new(),
                other => panic!("unexpected actual epoch fixture effect: {other:?}"),
            };
            pending.extend(next);
        }
    }
    fn transition(&self, request: &SafetyStatePersistenceV0) -> SafetyTransitionContextV0 {
        if let Some(manifest) = request.native_finalization_applied_v0() {
            let r = manifest.application_store_readback_v0();
            return SafetyTransitionContextV0::native_finalization_applied(
                NativeFinalizationAppliedTransitionV0::new(
                    r.source_route(),
                    r.source_validation_id(),
                    r.ordinal(),
                    r.application_host_config_ref(),
                    r.finalization_checksum(),
                    r.prior_head_checksum(),
                    r.new_head_checksum(),
                    r.source_artifact_checksum(),
                    r.accepted_source_checksum(),
                    r.applied_job_row_checksum(),
                    r.receipt_row_checksum(),
                    manifest.post_ack_action_v0().code(),
                    request.state().revision(),
                )
                .unwrap(),
            );
        }
        if let Some(action) = request.native_valid_post_ack_action_v0() {
            let c = request
                .state()
                .payload_validation_completions()
                .iter()
                .find(|c| c.first_recorded_revision() == request.state().revision())
                .unwrap();
            let actual = &self.blocks[&c.id().block_id()];
            let fresh = self
                .app
                .confirm_prepared_epoch_execution_v1(&actual.prepared)
                .unwrap();
            let sum = trnm_consensus_core::native_valid_result_checksum_v0(c.result()).unwrap();
            let binding = native_test_digest_v4(&[
                &fresh.prepared().p_digest(),
                &fresh.prepared().persist_sequence().to_be_bytes(),
                &sum,
            ]);
            return SafetyTransitionContextV0::native_valid(
                NativeValidTransitionV0::new(
                    c.route(),
                    c.id(),
                    binding,
                    binding,
                    native_test_digest_v4(&[b"host"]),
                    sum,
                    binding,
                    binding,
                    1,
                    binding,
                    binding,
                    action.code(),
                    request.state().revision(),
                )
                .unwrap(),
            );
        }
        SafetyTransitionContextV0::ordinary()
    }
    #[inline(never)]
    fn apply_finalization(&mut self, finalization: &DurableFinalizationV0) -> Vec<Effect> {
        let permit = self
            .core()
            .issue_application_finalization_permit_v2()
            .unwrap();
        assert_eq!(permit.finalization(), finalization);
        let header = finalization.proof().finalized_block().header();
        let actual = &self.blocks[&header.id()];
        let (route, validation) = actual.route.unwrap();
        let prior = self.app.confirmed_committed_head_v0().unwrap();
        assert_eq!(
            prior.height().get(),
            finalization.authenticated_parent().height().get()
        );
        assert_eq!(
            prior.block_id().as_bytes(),
            finalization.authenticated_parent().block_id().as_bytes()
        );
        let proof = finalization.proof().try_cev0_bytes().unwrap();
        if header.block_kind() == BlockKind::EpochCheckpoint {
            if header.epoch().get() == 1 {
                self.app.upgrade_later_epoch_schema_v1(&prior).unwrap();
                self.app
                    .upgrade_later_epoch_pre_handoff_schema_v1(&prior)
                    .unwrap();
            }
            let next = self.checkpoint.as_mut().unwrap();
            let terminal = finalization.proof().grandchild();
            let old = self
                .contexts
                .last()
                .unwrap()
                .activation()
                .new_validator_set();
            let params = self
                .contexts
                .last()
                .unwrap()
                .activation()
                .new_consensus_parameters();
            let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
                genesis_hash: old.genesis_hash(),
                chain_id: old.chain_id(),
                old_epoch: old.epoch(),
                new_epoch: next.set.epoch(),
                old_protocol_version: old.protocol_version(),
                new_protocol_version: next.set.protocol_version(),
                old_validator_set_hash: old.id(),
                new_validator_set_hash: next.set.id(),
                old_consensus_parameters_hash: params.hash(),
                new_consensus_parameters_hash: next.parameters.hash(),
                checkpoint_height: header.height(),
                checkpoint_block_id: header.id(),
                checkpoint_state_root: header.state_root(),
                next_epoch_commitment_digest: next.commitment.id(),
                terminal_old_height: terminal.header().height(),
                terminal_old_block_id: terminal.header().id(),
                terminal_old_qc_digest: terminal.certifying_qc().id(),
                terminal_old_view: terminal.header().view(),
                activation_height: next.commitment.fields().activation_height,
                initial_new_view: View::new(1),
            })
            .unwrap();
            let receipt = self
                .app
                .commit_later_epoch_pre_handoff_v1(
                    &actual.prepared,
                    &proof,
                    &descriptor,
                    &next.commitment.try_cev0_bytes().unwrap(),
                    &next.set.try_cev0_bytes().unwrap(),
                    &next.parameters.canonical_bytes(),
                    &mut Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .unwrap();
            assert!(receipt.belongs_to_application(&self.app));
            next.receipt = Some(receipt);
            next.proof = Some(finalization.proof().clone());
            next.descriptor = Some(descriptor);
        } else {
            let committed = self
                .app
                .commit_epoch_finality_bytes_v1(
                    &actual.prepared,
                    &proof,
                    &mut Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .unwrap();
            assert!(committed.belongs_to_application(&self.app));
        }
        let fresh = self
            .app
            .confirm_prepared_epoch_execution_v1(&actual.prepared)
            .unwrap();
        let head = self.app.confirmed_committed_head_v0().unwrap();
        assert_eq!(fresh.prepared().overlay_parent_head().unwrap(), head);
        let sequence = fresh
            .commit_sequence()
            .expect("real native P committed before apply callback");
        let before = native_test_digest_v4(&[
            prior.block_id().as_bytes(),
            prior.state_root().as_bytes(),
            prior.commit_id().as_bytes(),
        ]);
        let after = native_test_digest_v4(&[
            head.block_id().as_bytes(),
            head.state_root().as_bytes(),
            head.commit_id().as_bytes(),
        ]);
        let accepted = native_test_digest_v4(&[
            &fresh.prepared().p_digest(),
            &fresh.artifact_checksum(),
            &fresh.overlay_checksum(),
        ]);
        let committed = native_test_digest_v4(&[&accepted, &sequence.to_be_bytes(), &after]);
        let readback = self
            .apply
            .application_store_apply_readback_v0(
                &permit,
                route,
                validation,
                head.height().get(),
                native_test_digest_v4(&[b"host"]),
                before,
                after,
                fresh.artifact_checksum(),
                accepted,
                committed,
                committed,
            )
            .unwrap();
        let receipt = self
            .apply
            .receipt_after_application_store_apply_v0(permit, readback)
            .unwrap();
        self.core_mut()
            .step_application_finalization_receipt_v2(receipt)
            .unwrap()
    }
}

impl ActualEpochDriverV4 {
    #[inline(never)]
    fn execute_epoch_to_terminal(&mut self) {
        let epoch = self
            .runtime()
            .activation()
            .new_validator_set()
            .epoch()
            .get();
        let first = epoch * 10 + 1;
        for height in first..=first + 9 {
            self.execute_consensus_height(height);
        }
        let expected = first + 7;
        assert_eq!(self.core().state().finalized().height().get(), expected);
        assert_eq!(
            self.core().state().application_applied(),
            self.core().state().finalized()
        );
        assert!(self.core().state().pending_sign().is_none());
        assert_eq!(
            self.app
                .confirmed_committed_head_v0()
                .unwrap()
                .height()
                .get(),
            expected
        );
        self.journal.require_state(self.core().state());
        assert!(self.checkpoint.as_ref().unwrap().receipt.is_some());
    }

    #[inline(never)]
    fn execute_consensus_height(&mut self, height: u64) {
        let set = self.runtime().activation().new_validator_set().clone();
        let parameters = *self.runtime().activation().new_consensus_parameters();
        let geometry = EpochGeometryV0::new(set.epoch(), &parameters).unwrap();
        let kind = geometry.expected_block_kind(Height::new(height)).unwrap();
        let parent = self.headers[&(height - 1)].clone();
        let view = View::new(height - set.epoch().get() * 10);
        let mut commitment = None;
        if kind == BlockKind::EpochCheckpoint {
            let cutoff = self
                .app
                .read_finalized_by_height_v1(HeightV0::new(height - 3))
                .unwrap();
            let (new_set, new_parameters, next_commitment) =
                cutoff.test_fixture_next_epoch_facts_v1(&self.app).unwrap();
            assert_eq!(
                next_commitment.fields().snapshot_state_root.as_bytes(),
                cutoff.finalized_head_v1().unwrap().state_root().as_bytes()
            );
            commitment = Some(next_commitment);
            self.checkpoint = Some(NextCheckpointV4 {
                set: new_set,
                parameters: new_parameters,
                commitment: next_commitment,
                header: parent.clone(),
                parent: parent.clone(),
                receipt: None,
                proof: None,
                descriptor: None,
            });
        }
        let body =
            BlockBodyV0::new(ApplicationPayloadV0::new(Vec::new()).unwrap(), Vec::new()).unwrap();
        let receipts = ExecutionReceiptsV0::new(body.application_payload(), Vec::new()).unwrap();
        let make_header = |state_root, payload_root, receipts_root, evidence_root, next| {
            BlockHeader::new(
                set.genesis_hash(),
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                view,
                Height::new(height),
                kind,
                parent.id(),
                leader_for(&set, view),
                set.id(),
                parameters.hash(),
                payload_root,
                state_root,
                receipts_root,
                evidence_root,
                height * 1000,
                next,
            )
            .unwrap()
        };
        let (header, prepared) = if matches!(kind, BlockKind::EpochSeal1 | BlockKind::EpochSeal2) {
            let next = self.checkpoint.as_ref().unwrap();
            (
                make_header(
                    next.header.state_root(),
                    body.application_payload().payload_root().unwrap(),
                    receipts.receipts_root().unwrap(),
                    EvidenceRoot::new(
                        OrderedRootV0::from_items::<&[u8]>(RootKind::Evidence, &[])
                            .unwrap()
                            .digest(),
                    ),
                    Some(next.commitment.id()),
                ),
                None,
            )
        } else if kind == BlockKind::EpochHandoff {
            let request = match &self.edge {
                ActualNativeEdgeV4::First(edge) => {
                    edge.preview_request_v1(height * 1000, Vec::new()).unwrap()
                }
                ActualNativeEdgeV4::Later(edge) => NativeEpochBlockPreviewRequestV1::new(
                    ChainIdV0::new(set.chain_id().as_str()).unwrap(),
                    GenesisHashV0::new(*set.genesis_hash().as_bytes()).unwrap(),
                    self.app.confirmed_committed_head_v0().unwrap(),
                    BlockIdV0::new(edge.terminal_block()).unwrap(),
                    HeightV0::new(edge.terminal_height()),
                    Hash32V0::new(edge.successor_binding()),
                    HeightV0::new(height),
                    height * 1000,
                    ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
                    Vec::new(),
                )
                .unwrap(),
            };
            let preview = match &self.edge {
                ActualNativeEdgeV4::First(edge) => {
                    self.app.preview_epoch_block_v1(edge, &request).unwrap()
                }
                ActualNativeEdgeV4::Later(edge) => self
                    .app
                    .preview_later_epoch_block_v1(edge, &request)
                    .unwrap(),
            };
            let header = make_header(
                StateRoot::new(*preview.post_state_root().as_bytes()),
                PayloadDigest::new(*preview.payload_root().as_bytes()),
                ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
                EvidenceRoot::new(*preview.evidence_root().as_bytes()),
                None,
            );
            let execution = NativeEpochBlockExecutionRequestV1::new(
                request,
                BlockIdV0::new(*header.id().as_bytes()).unwrap(),
                NativeExpectedBlockCommitmentsV0::new(
                    preview.payload_root(),
                    preview.post_state_root(),
                    preview.receipts_root(),
                    preview.evidence_root(),
                )
                .unwrap(),
            )
            .unwrap();
            let p = match &self.edge {
                ActualNativeEdgeV4::First(edge) => self
                    .app
                    .execute_epoch_block_v1(edge, execution, &header)
                    .unwrap(),
                ActualNativeEdgeV4::Later(edge) => self
                    .app
                    .prepare_later_epoch_first_new_block_v1(edge, execution, &header)
                    .unwrap(),
            };
            (header, Some(p))
        } else {
            let previous = &self.blocks[&parent.id()].prepared;
            let request = NativeBlockPreviewRequestV0::new(
                ChainIdV0::new(set.chain_id().as_str()).unwrap(),
                GenesisHashV0::new(*set.genesis_hash().as_bytes()).unwrap(),
                previous.overlay_parent_head().unwrap(),
                HeightV0::new(height),
                height * 1000,
                ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
                Vec::new(),
            )
            .unwrap();
            let preview = self
                .app
                .preview_epoch_descendant_v1(previous, &request)
                .unwrap();
            let header = make_header(
                StateRoot::new(*preview.post_state_root().as_bytes()),
                PayloadDigest::new(*preview.payload_root().as_bytes()),
                ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
                EvidenceRoot::new(*preview.evidence_root().as_bytes()),
                commitment.map(|c| c.id()),
            );
            let execution = NativeBlockExecutionRequestV0::new(
                request.chain_id().clone(),
                request.genesis_hash(),
                request.parent().clone(),
                BlockIdV0::new(*header.id().as_bytes()).unwrap(),
                request.height(),
                request.timestamp_ms(),
                request.active_validator_set_id(),
                Vec::new(),
                NativeExpectedBlockCommitmentsV0::new(
                    preview.payload_root(),
                    preview.post_state_root(),
                    preview.receipts_root(),
                    preview.evidence_root(),
                )
                .unwrap(),
            )
            .unwrap();
            let p = self
                .app
                .execute_epoch_descendant_v1(previous, execution, &header)
                .unwrap();
            (header, Some(p))
        };
        if let Some(prepared) = prepared {
            let fresh = self
                .app
                .confirm_prepared_epoch_execution_v1(&prepared)
                .unwrap();
            assert!(fresh.belongs_to_application_at_path(&self.app, self.app.path()));
            let (payload, actual_receipts) = fresh.application_payload_and_receipts().unwrap();
            assert_eq!(payload, *body.application_payload());
            assert_eq!(actual_receipts, receipts);
            let commitments = match kind {
                BlockKind::EpochHandoff => body
                    .validate_epoch_handoff_commitments_v1(
                        &header,
                        &actual_receipts,
                        &parameters,
                        header.state_root(),
                        &set,
                        &StrictEd25519Verifier,
                    )
                    .unwrap(),
                BlockKind::EpochCheckpoint => body
                    .validate_checkpoint_static_commitments(
                        &header,
                        &actual_receipts,
                        &parameters,
                        header.state_root(),
                        commitment.unwrap().id(),
                    )
                    .unwrap()
                    .application_commitments_v1(),
                BlockKind::Regular => body
                    .validate_ordinary_commitments(
                        &header,
                        &actual_receipts,
                        &parameters,
                        &set,
                        &StrictEd25519Verifier,
                    )
                    .unwrap(),
                _ => unreachable!(),
            };
            let overlay = if kind == BlockKind::EpochHandoff {
                BlockIdOverlayRefV0::for_epoch_application_v1(
                    header.id(),
                    self.runtime()
                        .activation()
                        .old_checkpoint_finality()
                        .finalized_block()
                        .header()
                        .id(),
                    header.parent_id(),
                    *self.runtime().activation().binding_ref().as_bytes(),
                    fresh.overlay_checksum(),
                )
                .unwrap()
            } else {
                BlockIdOverlayRefV0::new(header.id(), header.parent_id(), fresh.overlay_checksum())
            };
            let artifact = ValidatedPayloadArtifactRefV0::new(overlay, fresh.artifact_checksum());
            self.blocks.insert(
                header.id(),
                ActualPV4 {
                    prepared,
                    commitments,
                    artifact,
                    route: None,
                },
            );
        }
        if kind == BlockKind::EpochCheckpoint {
            self.checkpoint.as_mut().unwrap().header = header.clone();
        }
        let runtime = self.runtime();
        let authorization = (kind == BlockKind::EpochHandoff)
            .then(|| runtime.structural_context().authorization().clone());
        let justify = if authorization.is_some() {
            runtime.anchor_reference().clone()
        } else {
            QcReferenceV0::ordinary(epoch_fixture_qc_v4(&parent, &set))
        };
        let root =
            ProposalWitnessV0::signing_root_for(&header, &justify, None, authorization.as_ref())
                .unwrap();
        let witness = ProposalWitnessV0::new(
            &header,
            justify,
            None,
            authorization,
            SignatureBytes::from_array(
                epoch_fixture_key_v4(&set, header.proposer_id())
                    .sign(root.as_bytes())
                    .to_bytes(),
            ),
            &set,
            Some(runtime.activation().old_validator_set()),
            &parameters,
            parent.timestamp_ms(),
        )
        .unwrap();
        let proposal = SignedProposalV0::new(
            Block::new(
                header.clone(),
                body.application_payload().try_cev0_bytes().unwrap(),
                Vec::new(),
            )
            .unwrap(),
            witness,
            &set,
            Some(runtime.activation().old_validator_set()),
            &parameters,
            parent.timestamp_ms(),
        )
        .unwrap();
        runtime
            .verify_proposal_v1(
                &proposal,
                &parent,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        self.headers.insert(height, header.clone());
        self.step(Input::Proposal(Box::new(proposal)));
        self.step(Input::QuorumCertificate(epoch_fixture_qc_v4(&header, &set)));
    }

    #[inline(never)]
    fn cross_to_journal12(&mut self, destination: &Path) {
        let (edge, artifact, current_epoch) = self.attach_next_epoch();
        self.migrate_next_epoch(destination, edge, artifact, current_epoch);
    }

    #[inline(never)]
    fn attach_next_epoch(
        &mut self,
    ) -> (
        LaterEpochApplicationEdgeV1,
        ValidatedPayloadArtifactRefV0,
        u64,
    ) {
        self.journal.require_state(self.core().state());
        let current_epoch = self
            .runtime()
            .activation()
            .new_validator_set()
            .epoch()
            .get();
        assert_eq!(
            self.core().state().finalized().height().get(),
            current_epoch * 10 + 8
        );
        assert_eq!(
            self.core().state().application_applied(),
            self.core().state().finalized()
        );
        let checkpoint = self.checkpoint.take().unwrap();
        let receipt = checkpoint.receipt.unwrap();
        assert!(receipt.belongs_to_application(&self.app));
        let descriptor = checkpoint.descriptor.unwrap();
        let proof = checkpoint.proof.unwrap();
        let old = self.runtime().activation().new_validator_set();
        let shares = |set: &ValidatorSet, root: SigningRoot| {
            set.validators()
                .iter()
                .take(3)
                .map(|v| {
                    SignatureShareV0::new(
                        v.id(),
                        SignatureBytes::from_array(
                            epoch_fixture_key_v4(set, v.id())
                                .sign(root.as_bytes())
                                .to_bytes(),
                        ),
                    )
                    .unwrap()
                })
                .collect()
        };
        // New handoff roles are signed only after the actual checkpoint has
        // committed, synced and been applied by the outgoing Core owner.
        let handoff = HandoffCertificateV0::new(
            descriptor.clone(),
            shares(old, descriptor.old_set_signing_root()),
            shares(&checkpoint.set, descriptor.new_set_signing_root()),
            old,
            &checkpoint.set,
        )
        .unwrap();
        let kernel = EpochAnchorAuthorizationKernelV0::from_parts_v0(
            proof.grandchild().header().clone(),
            proof.grandchild().certifying_qc().clone(),
            handoff,
            old,
            &checkpoint.set,
        )
        .unwrap();
        let first = self
            .runtime()
            .activation()
            .terminal_old_header()
            .height()
            .get();
        let ancestry = (first..=checkpoint.parent.height().get())
            .map(|height| self.headers[&height].clone())
            .collect::<Vec<_>>();
        let evidence = EpochActivationEvidenceBytesV0 {
            old_checkpoint_finality: proof.try_cev0_bytes().unwrap(),
            next_epoch_commitment: checkpoint.commitment.try_cev0_bytes().unwrap(),
            authorization_kernel: kernel.try_cev0_bytes().unwrap(),
            old_validator_set: old.try_cev0_bytes().unwrap(),
            old_consensus_parameters: self
                .runtime()
                .activation()
                .new_consensus_parameters()
                .canonical_bytes(),
            new_validator_set: checkpoint.set.try_cev0_bytes().unwrap(),
            new_consensus_parameters: checkpoint.parameters.canonical_bytes(),
            authenticated_checkpoint_parent_header: checkpoint.parent.try_cev0_bytes().unwrap(),
        };
        let strict = decode_verify_successor_epoch_activation_strict_v1(
            self.runtime().activation(),
            &ancestry,
            evidence.as_preimages(),
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
        let runtime = Box::new(StrictEpochRuntimeContextV1::from_activation_v1(strict).unwrap());
        let edge = self
            .app
            .attach_later_epoch_handoff_v1(&receipt, &kernel.try_cev0_bytes().unwrap())
            .unwrap();
        self.contexts.push(runtime);
        self.ancestries.push(ancestry);
        let artifact = self.blocks[&checkpoint.header.id()].artifact;
        (edge, artifact, current_epoch)
    }

    #[inline(never)]
    fn migrate_next_epoch(
        &mut self,
        destination: &Path,
        edge: LaterEpochApplicationEdgeV1,
        artifact: ValidatedPayloadArtifactRefV0,
        current_epoch: u64,
    ) {
        let source_record = original_prefix_record_v4(self.journal.path());
        let (profile, prepared) = self.prepare_successor(artifact);
        assert!(SqliteEpochSafetyJournalV4::initialize_from_source_v4(
            destination,
            profile.clone(),
            self.journal.stale_source(),
            &prepared,
        )
        .is_err());
        assert_no_namespace(destination);
        let (journal, fresh) = SqliteEpochSafetyJournalV4::initialize_from_source_v4(
            destination,
            profile.clone(),
            self.journal.source(),
            &prepared,
        )
        .unwrap();
        let selected = fresh.pin_v4();
        drop(journal);
        let mut wrong = selected;
        wrong.chain_checksum[0] ^= 1;
        assert!(SqliteEpochSafetyJournalV4::reopen_initial_from_source_v4(
            destination,
            profile.clone(),
            wrong,
            self.journal.source(),
            &prepared,
        )
        .is_err());
        let (journal, fresh) = SqliteEpochSafetyJournalV4::reopen_initial_from_source_v4(
            destination,
            profile.clone(),
            selected,
            self.journal.source(),
            &prepared,
        )
        .unwrap();
        assert_eq!(fresh.pin_v4(), selected);
        journal
            .confirm_exact_request_v4(
                selected,
                prepared.initial_persistence_v2(),
                &SafetyTransitionContextV0::ordinary(),
            )
            .unwrap();
        assert_eq!(
            fresh.migration_source_v4().state_record_checksum_v4(),
            *source_record.last_chunk::<32>().unwrap()
        );
        let expected_source_kind = if current_epoch == 1 {
            EpochSafetySourceKindV4::Journal11
        } else {
            EpochSafetySourceKindV4::Journal12
        };
        assert_eq!(
            fresh.migration_source_v4().pin_v4().kind,
            expected_source_kind
        );
        assert_eq!(fresh.state_v4(), prepared.state());
        assert_eq!(fresh.owner_generation_v4(), self.journal.generation() + 1);
        assert_eq!(
            fresh
                .state_v4()
                .epoch_state_v1()
                .unwrap()
                .preparation_record_v2()
                .unwrap()
                .entry_count_v2(),
            self.contexts.len()
        );
        let sql = rusqlite::Connection::open_with_flags(
            destination,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let (kind, raw, count): (i64, Vec<u8>, i64) = sql.query_row("SELECT source_kind,source_record,(SELECT COUNT(*) FROM epoch_provenance) FROM epoch_metadata", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!(kind, if current_epoch == 1 { 3 } else { 4 });
        assert_eq!(
            raw, source_record,
            "full independently confirmed source record is retained unchanged"
        );
        assert_eq!(count, 1);
        let pin = fresh.pin_v4();
        drop(sql);
        self.journal = ActualJournalV4::Twelve {
            owner: journal,
            profile,
            pin,
        };
        self.edge = ActualNativeEdgeV4::Later(Box::new(edge));
        self.core = Some(Box::new(prepared.into_candidate_host_pending_v2()));
        self.activate();
    }

    #[inline(never)]
    fn prepare_successor(
        &mut self,
        artifact: ValidatedPayloadArtifactRefV0,
    ) -> (EpochSafetyJournalProfileV4, PreparedEpochCoreActivationV2) {
        let core = *self.core.take().unwrap();
        with_epoch_context_v4(
            &self.contexts,
            &self.ancestries,
            artifact,
            self.journal.generation() + 1,
            |context| {
                (
                    self.journal.target_profile(context),
                    core.prepare_next_epoch_v2(context).unwrap(),
                )
            },
        )
    }
    fn activate(&mut self) {
        self.journal.require_state(self.core().state());
        assert!(self.core().activation_persistence_pending_v2());
        let barrier = self.core().initial_persistence_v2().barrier();
        let effects = self
            .core_mut()
            .step_v2(Input::StorageAck { barrier })
            .unwrap();
        assert!(effects
            .iter()
            .all(|e| matches!(e, Effect::ArmViewTimer { .. })));
        self.seal = self.core().issue_application_seal_authority_v2().unwrap();
        self.apply = self
            .core()
            .issue_application_finalization_apply_authority_v2()
            .unwrap();
    }
}

#[inline(never)]
fn with_epoch_context_v4<T>(
    contexts: &[Box<StrictEpochRuntimeContextV1>],
    ancestries: &[Vec<BlockHeader>],
    artifact: ValidatedPayloadArtifactRefV0,
    generation: u64,
    action: impl FnOnce(&EpochSafetyStateRecordContextV2<'_>) -> T,
) -> T {
    let encoded_ancestries = ancestries
        .iter()
        .map(|ancestry| {
            ancestry
                .iter()
                .map(|header| header.try_cev0_bytes().unwrap())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let borrowed_ancestries = encoded_ancestries
        .iter()
        .map(|ancestry| ancestry.iter().map(Vec::as_slice).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let entries = contexts
        .iter()
        .zip(&borrowed_ancestries)
        .map(|(runtime, ancestry)| EpochPreparationEntryV2 {
            binding_ref: *runtime.activation().binding_ref().as_bytes(),
            retained_ancestry: ancestry,
            evidence: runtime.evidence_bytes().as_preimages(),
        })
        .collect::<Vec<_>>();
    let first = contexts.first().unwrap().activation();
    let last = contexts.last().unwrap().activation();
    let evidence = prepare_epoch_handoff_evidence_v2(
        &entries,
        first.old_validator_set(),
        first.old_consensus_parameters(),
        *first.binding_ref().as_bytes(),
        *last.binding_ref().as_bytes(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let config = CoreConfig::new(
        last.new_validator_set().validators()[0].id(),
        last.new_validator_set().clone(),
        *last.new_consensus_parameters(),
        0,
        32,
        64,
    )
    .unwrap();
    let limits = minimum_epoch_safety_record_limits_v2(&config, &evidence).unwrap();
    let context =
        EpochSafetyStateRecordContextV2::new(&config, evidence, artifact, generation, limits)
            .unwrap();
    action(&context)
}

fn original_prefix_record_v4(path: &Path) -> Vec<u8> {
    let sql =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let (mut before, provenance, after): (Vec<u8>, Vec<u8>, Vec<u8>) = sql.query_row(
        "SELECT record_before,provenance,record_after FROM epoch_records JOIN epoch_head USING(revision) JOIN epoch_provenance ON provenance_id=epoch_provenance.singleton", [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    before.extend(provenance);
    before.extend(after);
    before
}

#[inline(never)]
fn actual_epoch_driver_v4(path: &Path) -> Box<ActualEpochDriverV4> {
    let fixture = actual_fixture(&path.join("source8"));
    eprintln!("journal12 fixture: genuine source8 constructed");
    initialize_actual_epoch_driver_v4(path, fixture)
}

#[inline(never)]
fn initialize_actual_epoch_driver_v4(
    path: &Path,
    fixture: Box<NativeOldEpochTerminalFixtureV1>,
) -> Box<ActualEpochDriverV4> {
    let runtime = Box::new(activation(&fixture));
    let (profile, prepared) = prepare11(&fixture);
    let (journal, fresh) = SqliteEpochSafetyJournalV3::initialize_from_source_v3(
        path.join("epoch11.db"),
        profile.clone(),
        EpochSafetySourceOwnerV2::Journal8(&fixture.journal, fixture.pin),
        &prepared,
    )
    .unwrap();
    let mut core = Box::new(prepared.into_candidate_host_pending_v2());
    let pin = fresh.pin_v3();
    assert_eq!(fresh.state_v3(), core.state());
    let effects = core
        .step_v2(Input::StorageAck {
            barrier: core.initial_persistence_v2().barrier(),
        })
        .unwrap();
    assert!(effects
        .iter()
        .all(|e| matches!(e, Effect::ArmViewTimer { .. })));
    let seal = core.issue_application_seal_authority_v2().unwrap();
    let apply = core
        .issue_application_finalization_apply_authority_v2()
        .unwrap();
    let source_commissioning = fixture.profile.clone();
    let NativeOldEpochTerminalFixtureV1 {
        application: app,
        pre_handoff_preparation,
        checkpoint_finality_bytes,
        handoff_anchor_bytes,
        ..
    } = *fixture;
    let confirmed = app
        .confirm_poco_checkpoint_v0(
            pre_handoff_preparation,
            &checkpoint_finality_bytes,
            &handoff_anchor_bytes,
        )
        .unwrap();
    let edge = confirmed.into_epoch_application_edge_v1().unwrap();
    app.upgrade_epoch_schema_v1(edge.application_parent())
        .unwrap();
    let terminal = runtime.activation().terminal_old_header().clone();
    Box::new(ActualEpochDriverV4 {
        core: Some(core),
        journal: ActualJournalV4::Eleven {
            owner: journal,
            profile,
            pin,
        },
        app,
        source_commissioning,
        edge: ActualNativeEdgeV4::First(Box::new(edge)),
        contexts: vec![runtime],
        ancestries: vec![Vec::new()],
        headers: BTreeMap::from([(terminal.height().get(), terminal)]),
        blocks: BTreeMap::new(),
        seal,
        apply,
        checkpoint: None,
        signatures: 0,
    })
}

#[test]
fn journal12_actual_source8_initial_cut_is_inert_and_old_layouts_refuse_it() {
    let dir = directory();
    let source = actual_fixture(&dir.path().join("chain"));
    journal12_source8_checks(dir.path(), &source);
}

#[inline(never)]
fn journal12_source8_checks(path: &Path, source: &NativeOldEpochTerminalFixtureV1) {
    with_context(source, None, |context| {
        let profile =
            EpochSafetyJournalProfileV4::from_journal8_v4(&source.profile, context).unwrap();
        let legacy10 =
            EpochSafetyJournalProfileV2::from_journal8_v2(&source.profile, context).unwrap();
        let legacy11 =
            EpochSafetyJournalProfileV3::from_journal8_v3(&source.profile, context).unwrap();
        let (_, recovered) = source
            .journal
            .prepare_terminal_recovery_v1(source.pin)
            .unwrap();
        let prepared = recovered.prepare_epoch_activation_v2(context).unwrap();
        let target = path.join("source8-to12.db");
        let (owner, head) = SqliteEpochSafetyJournalV4::initialize_from_source_v4(
            &target,
            profile.clone(),
            EpochSafetySourceOwnerV4::Journal8(&source.journal, source.pin),
            &prepared,
        )
        .unwrap();
        let pin = head.pin_v4();
        assert_eq!(head.state_v4(), prepared.state());
        assert_eq!(
            head.migration_source_v4().pin_v4().kind,
            EpochSafetySourceKindV4::Journal8
        );
        let stored = journal11_blobs(&target);
        let parts = encode_epoch_safety_record_parts_v2(prepared.state(), context).unwrap();
        assert_eq!(stored.0, parts.provenance());
        assert_eq!(
            stored.2,
            vec![(pin.revision, parts.record_bytes().to_vec())]
        );
        drop(owner);
        assert!(SqliteEpochSafetyJournalV2::open_existing_v2(
            &target,
            legacy10,
            EpochSafetyHeadPinV2 {
                journal_id: pin.journal_id,
                revision: pin.revision,
                chain_checksum: pin.chain_checksum
            }
        )
        .is_err());
        assert!(SqliteEpochSafetyJournalV3::open_existing_v3(
            &target,
            legacy11,
            EpochSafetyHeadPinV3 {
                journal_id: pin.journal_id,
                revision: pin.revision,
                chain_checksum: pin.chain_checksum
            }
        )
        .is_err());
        let (owner, fresh) = SqliteEpochSafetyJournalV4::reopen_initial_from_source_v4(
            &target,
            profile,
            pin,
            EpochSafetySourceOwnerV4::Journal8(&source.journal, source.pin),
            &prepared,
        )
        .unwrap();
        assert_eq!(fresh.pin_v4(), pin);
        owner
            .confirm_exact_request_v4(
                pin,
                prepared.initial_persistence_v2(),
                &SafetyTransitionContextV0::ordinary(),
            )
            .unwrap();
        assert_eq!(journal11_blobs(&target), stored);
        assert!(fresh.state_v4().pending_sign().is_none());
        // No driver was made and no ACK or key callback was invoked.
    });
}

#[test]
fn journal12_real_native_source11_then_source12_settled_successors_keep_flat_original_records() {
    let dir = directory();
    let mut driver = actual_epoch_driver_v4(dir.path());
    eprintln!("journal12 fixture: genuine journal11 activated");
    driver.execute_epoch_to_terminal();
    assert_eq!(driver.signatures, 10);
    driver.cross_to_journal12(&dir.path().join("epoch12-first.db"));
    driver.execute_epoch_to_terminal();
    assert_eq!(driver.signatures, 20);
    driver.cross_to_journal12(&dir.path().join("epoch12-second.db"));
    assert_eq!(driver.core().state().current_view(), View::new(1));
    assert_eq!(
        driver.core().state().application_applied().height(),
        Height::new(28)
    );
    cold_check_final_journal12(driver);
}

#[inline(never)]
fn cold_check_final_journal12(driver: Box<ActualEpochDriverV4>) {
    let ActualEpochDriverV4 { journal, core, .. } = *driver;
    let ActualJournalV4::Twelve {
        owner,
        profile,
        pin,
    } = journal
    else {
        panic!("stable physical12")
    };
    let expected = Box::new(core.unwrap().state().clone());
    let path = owner.path_v4().to_path_buf();
    drop(owner);
    let owner = SqliteEpochSafetyJournalV4::open_existing_v4(&path, profile.clone(), pin).unwrap();
    let (head, recovery) = owner.prepare_recovery_v4(pin).unwrap();
    assert_eq!(head.state_v4(), expected.as_ref());
    assert_eq!(recovery.state(), expected.as_ref());
    assert_eq!(
        head.migration_source_v4().pin_v4().kind,
        EpochSafetySourceKindV4::Journal12
    );
    drop(owner);
    let exact = original_prefix_record_v4(&path);
    for (name, sql) in [
        ("source-layout", "UPDATE epoch_metadata SET source_kind=2"),
        ("source-checksum", "UPDATE epoch_metadata SET source_record=CAST(substr(source_record,1,length(source_record)-1)||CASE WHEN substr(source_record,-1)=x'ff' THEN x'00' ELSE x'ff' END AS BLOB)"),
        ("fifth-object", "CREATE VIEW fifth AS SELECT 1"),
        ("prefix-graft", "UPDATE epoch_provenance SET provenance=zeroblob(length(provenance))"),
        ("relocated-boundary", "UPDATE epoch_records SET record_before=CAST(record_before||substr((SELECT provenance FROM epoch_provenance),1,1) AS BLOB); UPDATE epoch_provenance SET provenance=substr(provenance,2)"),
    ] {
        let copy = path.with_file_name(format!("journal12-{name}.db"));
        copy_namespace(&path, &copy);
        mutate(&copy, sql);
        if name == "relocated-boundary" {
            assert_eq!(original_prefix_record_v4(&copy), exact, "reconstructed bytes and original record checksum remain identical");
        }
        assert!(SqliteEpochSafetyJournalV4::open_existing_v4(&copy, profile.clone(), pin).is_err(), "cold audit must reject {name}");
    }
    assert_eq!(original_prefix_record_v4(&path), exact);
}
