//! Default-off, real native/Core/Safety integration fixture. Genesis is an
//! explicitly operator-trusted test input. Application callback authorities
//! stay private here; every callback follows fresh real P/commit readback.
//! The host comparison hashes below describe this fixture adapter, not a
//! production application-job/outbox schema or a commissioning certificate.
use crate::*;
use anyhow::{anyhow, ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
};
use trnm_consensus_core::*;
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::*;
use trnm_native_application::{
    NativeApplicationCommitRequestV0, NativeApplicationV0, NativeBlockExecutionRequestV0,
    NativeBlockExecutionResultV0, NativeExecutedBlockV0,
};
use trnm_native_execution_v0::{
    test_fixtures::{
        build_native_checkpoint_fixture_v1, open_native_checkpoint_fixture_genesis_v1,
    },
    DurableNativeApplicationV0, NativeApplicationConfigV0, NativeBlockPreviewRequestV0,
    PreparedNativePocoCheckpointV0,
};

/// Owners are deliberately non-Clone. The source journal is the actual virgin
/// genesis cut before any callback; all ten old-epoch votes occur in journal8.
pub struct NativeOldEpochTerminalFixtureV1 {
    pub source_journal: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    pub journal: SqliteOldEpochSafetyJournalV1,
    pub owner: Box<OldEpochBoundaryCoreV1>,
    pub pin: OldEpochSafetyHeadPinV1,
    pub profile: OldEpochSafetyJournalProfileV1,
    pub application: DurableNativeApplicationV0,
    pub config: NativeApplicationConfigV0,
    pub checkpoint: PreparedNativePocoCheckpointV0,
    pub pre_handoff_preparation: PreparedNativePocoCheckpointV0,
    pub checkpoint_execution: NativeExecutedBlockV0,
    pub cutoff_finality_bytes: Vec<u8>,
    pub cutoff_parent_header_bytes: Vec<u8>,
    pub checkpoint_parent_header: BlockHeader,
    pub checkpoint_finality_bytes: Vec<u8>,
    pub handoff_anchor_bytes: Vec<u8>,
    pub sign_intents: Vec<CanonicalSignIntentV0>,
}
fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"trnm.real-native-safety.fixture.v1");
    for part in parts {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}
fn persistence(effects: &[Effect]) -> Result<&SafetyStatePersistenceV0> {
    effects
        .iter()
        .find_map(|e| {
            if let Effect::PersistSafetyState(r) = e {
                Some(r)
            } else {
                None
            }
        })
        .context("missing exact persistence request")
}
struct ActualBlock {
    executed: NativeExecutedBlockV0,
    commitments: ValidatedBlockCommitmentsV0,
    artifact: ValidatedPayloadArtifactRefV0,
    route_id: Option<(PayloadValidationRouteV0, ValidationId)>,
}
struct Driver<F> {
    owner: Box<OldEpochBoundaryCoreV1>,
    journal: SqliteOldEpochSafetyJournalV1,
    pin: OldEpochSafetyHeadPinV1,
    application: DurableNativeApplicationV0,
    seal: CoreIssuedApplicationSealAuthorityV0,
    apply: CoreIssuedApplicationFinalizationApplyAuthorityV0,
    blocks: BTreeMap<BlockId, ActualBlock>,
    sign: F,
    intents: Vec<CanonicalSignIntentV0>,
    host_ref: [u8; 32],
}
impl<F: FnMut(&CanonicalSignIntentV0) -> Result<SignatureBytes>> Driver<F> {
    fn transition(&self, request: &SafetyStatePersistenceV0) -> Result<SafetyTransitionContextV0> {
        if let Some(manifest) = request.native_finalization_applied_v0() {
            let r = manifest.application_store_readback_v0();
            return Ok(SafetyTransitionContextV0::native_finalization_applied(
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
                .fixture()?,
            ));
        }
        if let Some(action) = request.native_valid_post_ack_action_v0() {
            let c = request
                .state()
                .payload_validation_completions()
                .iter()
                .find(|c| c.first_recorded_revision() == request.state().revision())
                .context("fresh native completion")
                .fixture()?;
            let actual = self
                .blocks
                .get(&c.id().block_id())
                .context("actual P for completion")
                .fixture()?;
            let row = self
                .application
                .confirm_durable_execution_history_row_v0(&actual.executed)
                .fixture()?;
            let sum = trnm_consensus_core::native_valid_result_checksum_v0(c.result())
                .context("valid result checksum")
                .fixture()?;
            let binding = digest(&[&row.p_digest_v0(), &row.p_sequence_v0().to_le_bytes(), &sum]);
            return Ok(SafetyTransitionContextV0::native_valid(
                NativeValidTransitionV0::new(
                    c.route(),
                    c.id(),
                    binding,
                    binding,
                    self.host_ref,
                    sum,
                    binding,
                    binding,
                    1,
                    binding,
                    binding,
                    action.code(),
                    request.state().revision(),
                )
                .fixture()?,
            ));
        }
        Ok(SafetyTransitionContextV0::ordinary())
    }
    fn drive(&mut self, input: Input) -> Result<()> {
        let effects = self.owner.step_v1(input).fixture()?;
        self.effects(effects)
    }
    fn effects(&mut self, effects: Vec<Effect>) -> Result<()> {
        let mut pending: VecDeque<_> = effects.into();
        while let Some(effect) = pending.pop_front() {
            let next = match effect {
                Effect::PersistSafetyState(request) => {
                    let transition = self.transition(&request).fixture()?;
                    let actual = self
                        .journal
                        .persist_exact_v1(self.pin, &request, &transition)
                        .fixture()?;
                    self.pin = actual.pin_v1();
                    ensure!(
                        actual.belongs_to_store_at_path_v1(&self.journal, self.journal.path_v1()),
                        "fresh journal8 owner"
                    );
                    self.owner
                        .step_v1(Input::StorageAck {
                            barrier: request.barrier(),
                        })
                        .fixture()?
                }
                Effect::ValidatePayload(request) | Effect::ValidateSyncedPayload(request) => {
                    let (route, id, block, parent, permit) = request
                        .try_claim()
                        .map_err(|_| anyhow!("duplicate fixture validation"))
                        .fixture()?
                        .into_parts();
                    let actual = self
                        .blocks
                        .get_mut(&block.id())
                        .context("native block missing")
                        .fixture()?;
                    ensure!(
                        block.header().height().get() == actual.executed.request().height().get(),
                        "native/header height"
                    );
                    ensure!(
                        block.header().parent_id().as_bytes()
                            == actual.executed.request().parent().block_id().as_bytes(),
                        "native/header parent"
                    );
                    let _ = parent; // Core retained and checks the exact parent again on receipt.
                    let row = self
                        .application
                        .confirm_durable_execution_history_row_v0(&actual.executed)
                        .fixture()?;
                    ensure!(
                        row.belongs_to_application_at_path_v0(
                            &self.application,
                            self.application.path()
                        ),
                        "P owner"
                    );
                    ensure!(
                        row.artifact_digest_v0() == actual.artifact.source_artifact_checksum(),
                        "P artifact changed"
                    );
                    actual.route_id = Some((route, id));
                    let proof = self.seal.seal_after_application_store_commit_v0(
                        permit,
                        actual.commitments,
                        actual.artifact,
                    );
                    self.owner
                        .step_application_sealed_valid_v1(&proof)
                        .fixture()?
                }
                Effect::RequestSignature { intent } => {
                    let head = self.journal.fresh_read_v1(self.pin).fixture()?;
                    ensure!(
                        head.state_v1() == self.owner.safety_state(),
                        "sign before exact persisted Safety"
                    );
                    let before = self.owner.safety_state().clone();
                    let signature = (self.sign)(&intent).fixture()?;
                    self.intents.push(intent.clone());
                    let released = self
                        .owner
                        .step_v1(Input::SignatureReady {
                            id: SignId::new(intent.signing_root()),
                            signature,
                        })
                        .fixture()?;
                    ensure!(
                        released.iter().all(|e| matches!(e, Effect::Broadcast(_))),
                        "unexpected signature release"
                    );
                    self.owner.persist_signature_release_v1(&before).fixture()?
                }
                Effect::Finalize(finalization) => {
                    let permit = self
                        .owner
                        .issue_application_finalization_permit_v1()
                        .fixture()?;
                    ensure!(
                        permit.finalization() == finalization.as_ref(),
                        "queue-front differs"
                    );
                    let id = finalization.proof().finalized_block().header().id();
                    let actual = self
                        .blocks
                        .get(&id)
                        .context("finalized actual P missing")
                        .fixture()?;
                    let (route, validation) = actual
                        .route_id
                        .context("finalized source validation")
                        .fixture()?;
                    let prior = self.application.confirmed_committed_head_v0().fixture()?;
                    ensure!(
                        prior.height().get() == finalization.authenticated_parent().height().get(),
                        "native finalization parent height"
                    );
                    ensure!(
                        prior.block_id().as_bytes()
                            == finalization.authenticated_parent().block_id().as_bytes(),
                        "native finalization parent block"
                    );
                    self.application
                        .commit_block(NativeApplicationCommitRequestV0::new(
                            actual.executed.clone(),
                        ))
                        .fixture()?;
                    let row = self
                        .application
                        .confirm_durable_execution_history_row_v0(&actual.executed)
                        .fixture()?;
                    let head = self.application.confirmed_committed_head_v0().fixture()?;
                    ensure!(
                        row.target_head_v0().fixture()? == head
                            && row.commit_sequence_v0().is_some(),
                        "fresh exact committed P"
                    );
                    let before = digest(&[
                        prior.block_id().as_bytes(),
                        prior.state_root().as_bytes(),
                        prior.commit_id().as_bytes(),
                    ]);
                    let after = digest(&[
                        head.block_id().as_bytes(),
                        head.state_root().as_bytes(),
                        head.commit_id().as_bytes(),
                    ]);
                    let accepted = digest(&[
                        &row.p_digest_v0(),
                        &row.artifact_digest_v0(),
                        &row.overlay_digest_v0(),
                    ]);
                    let committed = digest(&[
                        &accepted,
                        &row.commit_sequence_v0().unwrap().to_le_bytes(),
                        &after,
                    ]);
                    let readback = self
                        .apply
                        .application_store_apply_readback_v0(
                            &permit,
                            route,
                            validation,
                            head.height().get(),
                            self.host_ref,
                            before,
                            after,
                            row.artifact_digest_v0(),
                            accepted,
                            committed,
                            committed,
                        )
                        .fixture()?;
                    let receipt = self
                        .apply
                        .receipt_after_application_store_apply_v0(permit, readback)
                        .map_err(|e| anyhow!("apply receipt: {e:?}"))
                        .fixture()?;
                    self.owner
                        .step_application_finalization_receipt_v1(receipt)
                        .map_err(|e| anyhow!("Core apply receipt: {e:?}"))
                        .fixture()?
                }
                Effect::Broadcast(_) | Effect::ArmViewTimer { .. } => Vec::new(),
                other => return Err(anyhow!("unexpected fixture effect: {other:?}")),
            };
            pending.extend(next);
        }
        Ok(())
    }
    fn exact_request(
        &self,
        reference: &NativeBlockExecutionRequestV0,
    ) -> Result<NativeBlockExecutionRequestV0> {
        let parent = if reference.parent().height().get() == 0 {
            self.application.confirmed_committed_head_v0().fixture()?
        } else {
            let id = BlockId::new(*reference.parent().block_id().as_bytes());
            let actual = self.blocks.get(&id).context("actual parent P").fixture()?;
            self.application
                .confirm_durable_execution_history_row_v0(&actual.executed)
                .fixture()?
                .target_head_v0()
                .fixture()?
        };
        NativeBlockExecutionRequestV0::new(
            reference.chain_id().clone(),
            reference.genesis_hash(),
            parent,
            reference.block_id(),
            reference.height(),
            reference.timestamp_ms(),
            reference.active_validator_set_id(),
            reference.transactions().to_vec(),
            reference.expected(),
        )
        .fixture()
    }
    fn add_actual(
        &mut self,
        executed: NativeExecutedBlockV0,
        commitments: ValidatedBlockCommitmentsV0,
    ) -> Result<()> {
        let row = self
            .application
            .confirm_durable_execution_history_row_v0(&executed)
            .fixture()?;
        let id = BlockId::new(*executed.request().block_id().as_bytes());
        let parent = BlockId::new(*executed.request().parent().block_id().as_bytes());
        let artifact = ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(id, parent, row.overlay_digest_v0()),
            row.artifact_digest_v0(),
        );
        self.blocks.insert(
            id,
            ActualBlock {
                executed,
                commitments,
                artifact,
                route_id: None,
            },
        );
        Ok(())
    }
}
/// The callback runs only after the actual corresponding journal8 Safety
/// request has committed, synced and freshly matched. It must use a real signer
/// journal in tests claiming whole-node custody joins. The helper itself never
/// manufactures signer permission, a signature, or an application receipt.
pub fn build_native_old_epoch_terminal_v1(
    path: &Path,
    sign_after_persist: impl FnMut(&CanonicalSignIntentV0) -> Result<SignatureBytes>,
) -> Result<NativeOldEpochTerminalFixtureV1> {
    fs::create_dir_all(path).fixture()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).fixture()?;
    let reference = build_native_checkpoint_fixture_v1(&path.join("reference-native.db"));
    let config = trnm_native_execution_v0::test_fixtures::native_checkpoint_fixture_config_v1();
    let set = config.validator_set_v0();
    let parameters = config.consensus_parameters_v0();
    let (source_journal, profile, mut d) =
        initialize_driver(path, &config, sign_after_persist).fixture()?;
    let payload = ApplicationPayloadV0::new(Vec::new()).fixture()?;
    let receipts = ExecutionReceiptsV0::new(&payload, Vec::new()).fixture()?;
    let body = BlockBodyV0::new(payload, Vec::new()).fixture()?;
    for (reference_execution, certified) in reference
        .ordinary_executions
        .iter()
        .zip(&reference.ordinary_certified_headers)
    {
        let NativeBlockExecutionResultV0::Valid(executed) = d
            .application
            .execute_block(d.exact_request(reference_execution.request()).fixture()?)
            .fixture()?
        else {
            return Err(anyhow!("native ordinary execute rejected"));
        };
        let commitments = body
            .validate_ordinary_commitments(
                certified.header(),
                &receipts,
                parameters,
                set,
                &StrictEd25519Verifier,
            )
            .fixture()?;
        d.add_actual(*executed, commitments).fixture()?;
        let block = Block::new(
            certified.header().clone(),
            body.application_payload().try_cev0_bytes().fixture()?,
            Vec::new(),
        )
        .fixture()?;
        let proposal = SignedProposalV0::new(
            block,
            certified.witness().clone(),
            set,
            None,
            parameters,
            (certified.header().height().get() - 1) * 1000,
        )
        .fixture()?;
        d.drive(Input::Proposal(Box::new(proposal)))
            .context("ordinary proposal")
            .fixture()?;
        d.drive(Input::QuorumCertificate(certified.certifying_qc().clone()))
            .context("ordinary QC")
            .fixture()?;
    }
    let r = d
        .exact_request(reference.checkpoint_execution.request())
        .fixture()?;
    let preview = NativeBlockPreviewRequestV0::new(
        r.chain_id().clone(),
        r.genesis_hash(),
        r.parent().clone(),
        r.height(),
        r.timestamp_ms(),
        r.active_validator_set_id(),
        r.transactions().to_vec(),
    )
    .fixture()?;
    let checkpoint = d
        .application
        .prepare_native_poco_checkpoint_v0(
            &preview,
            View::new(8),
            reference.checkpoint.header().proposer_id(),
            &reference.cutoff_finality_bytes,
            &reference.cutoff_parent_header_bytes,
        )
        .fixture()?;
    let pre_handoff_preparation = d
        .application
        .prepare_native_poco_checkpoint_v0(
            &preview,
            View::new(8),
            reference.checkpoint.header().proposer_id(),
            &reference.cutoff_finality_bytes,
            &reference.cutoff_parent_header_bytes,
        )
        .fixture()?;
    let NativeBlockExecutionResultV0::Valid(executed) =
        d.application.execute_block(r.clone()).fixture()?
    else {
        return Err(anyhow!("native checkpoint execute rejected"));
    };
    let actual = d
        .application
        .confirm_prepared_checkpoint_execution_v1(&checkpoint, &executed)
        .fixture()?;
    let commitments = actual.validated_commitments().application_commitments_v1();
    drop(actual);
    let checkpoint_execution = *executed;
    d.add_actual(checkpoint_execution.clone(), commitments)
        .fixture()?;
    let proof =
        decode_finality_proof_v0_exact(&reference.checkpoint_finality_bytes, set, parameters, 7000)
            .fixture()?;
    for certified in [proof.finalized_block(), proof.child(), proof.grandchild()] {
        let block = Block::new(
            certified.header().clone(),
            body.application_payload().try_cev0_bytes().fixture()?,
            Vec::new(),
        )
        .fixture()?;
        let proposal = SignedProposalV0::new(
            block,
            certified.witness().clone(),
            set,
            None,
            parameters,
            (certified.header().height().get() - 1) * 1000,
        )
        .fixture()?;
        d.drive(Input::Proposal(Box::new(proposal)))
            .context("boundary proposal")
            .fixture()?;
        d.drive(Input::QuorumCertificate(certified.certifying_qc().clone()))
            .context("boundary QC")
            .fixture()?;
    }
    ensure!(
        d.owner.safety_state().finalized().height().get() == 8,
        "true Core checkpoint finality"
    );
    ensure!(
        d.owner.safety_state().application_applied() == d.owner.safety_state().finalized(),
        "actual native apply watermark"
    );
    d.journal
        .prepare_terminal_recovery_v1(d.pin)
        .context("strict terminal recovery")
        .fixture()?;
    ensure!(d.intents.len() == 10, "ten real persisted old-epoch votes");
    Ok(NativeOldEpochTerminalFixtureV1 {
        source_journal,
        journal: d.journal,
        owner: d.owner,
        pin: d.pin,
        profile,
        application: d.application,
        config,
        checkpoint,
        pre_handoff_preparation,
        checkpoint_execution,
        cutoff_finality_bytes: reference.cutoff_finality_bytes,
        cutoff_parent_header_bytes: reference.cutoff_parent_header_bytes,
        checkpoint_parent_header: reference.ordinary_headers[6].clone(),
        checkpoint_finality_bytes: reference.checkpoint_finality_bytes,
        handoff_anchor_bytes: reference.handoff_anchor_bytes,
        sign_intents: d.intents,
    })
}

trait FixtureResultExt<T> {
    fn fixture(self) -> Result<T>;
}
impl<T, E: std::fmt::Debug> FixtureResultExt<T> for std::result::Result<T, E> {
    fn fixture(self) -> Result<T> {
        self.map_err(|e| anyhow!("{e:?}"))
    }
}

fn initialize_driver<F: FnMut(&CanonicalSignIntentV0) -> Result<SignatureBytes>>(
    path: &Path,
    config: &NativeApplicationConfigV0,
    sign: F,
) -> Result<(
    SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    OldEpochSafetyJournalProfileV1,
    Driver<F>,
)> {
    let set = config.validator_set_v0();
    let parameters = config.consensus_parameters_v0();
    let c = CoreConfig::new(
        set.validators()[0].id(),
        set.clone(),
        *parameters,
        0,
        32,
        64,
    )
    .fixture()?;
    let genesis = GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).fixture()?;
    let core = initial_core(c.clone(), genesis).fixture()?;
    let limits = minimum_safety_state_record_limits_v0(&c).fixture()?;
    let source_profile = SafetyStateStoreProfileV0::new(
        c.clone(),
        digest(&[b"strict-ed25519-fixture"]),
        limits,
        limits.maximum_record_bytes() * 4 + 16 * 1024 * 1024,
    )
    .fixture()?;
    let source_journal = SqliteSafetyStateStoreV0::initialize_new(
        path.join("source7.db"),
        source_profile.clone(),
        StrictEd25519Verifier,
        core.safety_state(),
    )
    .fixture()?;
    let source_chain = source_chain(&source_journal).fixture()?;
    let profile = OldEpochSafetyJournalProfileV1::new(
        source_profile,
        minimum_old_epoch_boundary_record_limits_v1(&c).fixture()?,
        1,
    )
    .fixture()?;
    let (mut owner, effects) = boundary_owner(core).fixture()?;
    let initial = persistence(&effects).fixture()?;
    let (journal, confirmed) = SqliteOldEpochSafetyJournalV1::initialize_from_journal7_v1(
        path.join("outgoing8.db"),
        profile.clone(),
        &source_journal,
        source_chain,
        &owner,
        initial,
    )
    .fixture()?;
    let pin = confirmed.pin_v1();
    ensure!(
        owner
            .step_v1(Input::StorageAck {
                barrier: initial.barrier()
            })
            .fixture()?
            .is_empty(),
        "migration effects"
    );
    let seal = owner.issue_application_seal_authority_v0().fixture()?;
    let apply = owner
        .issue_application_finalization_apply_authority_v0()
        .fixture()?;
    let d = Driver {
        owner,
        journal,
        pin,
        application: open_native_checkpoint_fixture_genesis_v1(&path.join("native.db")),
        seal,
        apply,
        blocks: BTreeMap::new(),
        sign,
        intents: Vec::new(),
        host_ref: digest(&[b"real-native-adapter"]),
    };
    Ok((source_journal, profile, d))
}

fn initial_core(config: CoreConfig, genesis: GenesisQcV0) -> Result<Box<Core>> {
    Ok(Box::new(
        Core::new(config, genesis, &StrictEd25519Verifier).fixture()?,
    ))
}
fn boundary_owner(core: Box<Core>) -> Result<(Box<OldEpochBoundaryCoreV1>, Vec<Effect>)> {
    let (owner, effects) = core.into_old_epoch_boundary_v1(1).fixture()?;
    Ok((Box::new(owner), effects))
}
fn source_chain(source: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>) -> Result<[u8; 32]> {
    Ok(source.head().fixture()?.chain_checksum())
}
