//! Terminal14O projection in the existing independent whole-node CAS envelope.
//! No ordinary signature, Core ACK or full14E activation is granted here.
use crate::external_node_checkpoint::{
    ExternalNodeCheckpointFieldsV0, ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0,
    SqliteExternalNodeCheckpointStoreV0,
};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use trnm_consensus_crypto::verify_pre_handoff_context_strict_v1;
use trnm_consensus_safety_store::{ConfirmedOldEpochSafetyHeadV1, SqliteOldEpochSafetyJournalV1};
use trnm_consensus_signer_journal::{
    ConfirmedOrdinarySignerRetirementV1, ExternalSignerRetirementV1, HandoffSignerJournalProfileV1,
    RetiredSqliteSignerJournalV1, SignerRetirementHostCutV1, SignerRetirementRecordV1,
};
use trnm_consensus_types::{CanonicalHandoffSignIntentV1, HandoffDescriptorV0};
use trnm_native_execution_v0::{
    DurableExecutionHistoryStatusV0, DurableNativeApplicationV0, PreHandoffCheckpointReceiptV1,
};

#[derive(Debug)]
pub enum EpochRetirementCheckpointErrorV1 {
    Invalid(&'static str),
    Store(crate::ExternalNodeCheckpointStoreErrorV0),
    Signer(trnm_consensus_signer_journal::SignerJournalErrorV0),
    Safety(trnm_consensus_safety_store::OldEpochJournalErrorV1),
    Application(trnm_native_execution_v0::NativeApplicationExecutionErrorV0),
    Crypto(trnm_consensus_types::ValidationError),
}
impl std::fmt::Display for EpochRetirementCheckpointErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "epoch retirement checkpoint: {self:?}")
    }
}
impl std::error::Error for EpochRetirementCheckpointErrorV1 {}
type Result<T> = std::result::Result<T, EpochRetirementCheckpointErrorV1>;
fn invalid<T>(reason: &'static str) -> Result<T> {
    Err(EpochRetirementCheckpointErrorV1::Invalid(reason))
}
fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// Fresh evidence of the original retired owner and the exact terminal14O
/// whole-node cut. It retains the independent store, and cannot be constructed
/// from a decoded checkpoint or retirement record. No ordinary signing lease.
///
/// ```compile_fail
/// use trnm_poco_node::ConfirmedRetiredEpochNodeCheckpointV1;
/// fn clone_required<T: Clone>() {}
/// clone_required::<ConfirmedRetiredEpochNodeCheckpointV1>();
/// ```
#[must_use]
pub struct ConfirmedRetiredEpochNodeCheckpointV1 {
    store: RefCell<SqliteExternalNodeCheckpointStoreV0>,
    checkpoint: ExternalNodeCheckpointV0,
    retired: ConfirmedOrdinarySignerRetirementV1,
    fenced: Cell<bool>,
}
impl ConfirmedRetiredEpochNodeCheckpointV1 {
    /// Inert persistent identity; possession of these bytes is not this token.
    pub const fn checkpoint_v1(&self) -> &ExternalNodeCheckpointV0 {
        &self.checkpoint
    }
    pub fn belongs_to_retired_owner_v1<W: ExternalSignerRetirementV1>(
        &self,
        retired: &mut RetiredSqliteSignerJournalV1<W>,
    ) -> bool {
        if self.fenced.get() {
            return false;
        }
        let valid = self.store.try_borrow_mut().ok().is_some_and(|mut store| {
            store.load(self.checkpoint.scope()).ok() == Some(Some(self.checkpoint))
                && self.retired.record_v1() == retired.record_v1()
                && retired.profile_v1().profile_checksum()
                    == self.checkpoint.fields().signer_profile_checksum
                && self.retired.belongs_to_owner_v1(retired)
                && store.load(self.checkpoint.scope()).ok() == Some(Some(self.checkpoint))
        });
        if !valid {
            self.fenced.set(true);
        }
        valid
    }
}

/// Consume the actual independent checkpoint owner after reconciling the real
/// native, terminal Safety and already-retired original signer owners. The
/// predecessor is independently recorded before retirement, never synthesized
/// from the supplied retired owner. Exact source/target retry is bounded to one
/// CAS and a fresh read. An error consumes the external handle and grants no
/// authority; it can be reopened explicitly at the same configured path.
#[allow(clippy::too_many_arguments)]
pub fn confirm_retired_epoch_node_checkpoint_v1<W: ExternalSignerRetirementV1>(
    mut store: SqliteExternalNodeCheckpointStoreV0,
    predecessor: ExternalNodeCheckpointV0,
    application: &DurableNativeApplicationV0,
    receipt: &PreHandoffCheckpointReceiptV1,
    descriptor: &HandoffDescriptorV0,
    profile: &HandoffSignerJournalProfileV1,
    safety: &SqliteOldEpochSafetyJournalV1,
    safety_head: &ConfirmedOldEpochSafetyHeadV1,
    retired: &mut RetiredSqliteSignerJournalV1<W>,
    confirmed: &ConfirmedOrdinarySignerRetirementV1,
) -> Result<ConfirmedRetiredEpochNodeCheckpointV1> {
    // Reject a substituted original identity before any reconciliation or CAS.
    check_original_identity_bounds(&predecessor, retired.record_v1())?;
    if !retired
        .confirms_ordinary_prefix_v1(predecessor.fields().signer_exact_watermark)
        .map_err(EpochRetirementCheckpointErrorV1::Signer)?
    {
        return invalid("independent original watermark is not an exact retired journal prefix");
    }
    if !confirmed.belongs_to_owner_v1(retired) {
        return invalid("fresh retired owner");
    }
    let target = joined_target(
        &predecessor,
        application,
        receipt,
        descriptor,
        profile,
        safety,
        safety_head,
        retired,
        confirmed.record_v1(),
    )?;
    let observed = store
        .load(target.scope())
        .map_err(EpochRetirementCheckpointErrorV1::Store)?;
    if observed != Some(predecessor) && observed != Some(target) {
        return invalid("independent checkpoint is neither predecessor nor exact target");
    }
    if observed == Some(predecessor) {
        let _uncertain = store.compare_and_advance(Some(predecessor), target);
    }
    // The backend fresh-confirm method executes a durability barrier even when
    // this process inherited a fully written but not yet synced predecessor run.
    store
        .confirm_exact_durable_v1(target)
        .map_err(EpochRetirementCheckpointErrorV1::Store)?;
    let fresh = retired
        .confirm_retirement_v1()
        .map_err(EpochRetirementCheckpointErrorV1::Signer)?;
    if fresh.record_v1() != confirmed.record_v1()
        || joined_target(
            &predecessor,
            application,
            receipt,
            descriptor,
            profile,
            safety,
            safety_head,
            retired,
            fresh.record_v1(),
        )? != target
    {
        return invalid("owner cut changed during independent CAS");
    }
    store
        .confirm_exact_durable_v1(target)
        .map_err(EpochRetirementCheckpointErrorV1::Store)?;
    Ok(ConfirmedRetiredEpochNodeCheckpointV1 {
        store: RefCell::new(store),
        checkpoint: target,
        retired: fresh,
        fenced: Cell::new(false),
    })
}

fn check_original_identity_bounds(
    predecessor: &ExternalNodeCheckpointV0,
    retirement: &SignerRetirementRecordV1,
) -> Result<()> {
    let source = retirement.source_v1();
    let p = predecessor.fields();
    if p.scope != source.scope()
        || p.signer_journal_id != source.journal_id()
        || p.signer_profile_checksum != retirement.source_profile_checksum_v1()
        || p.signer_exact_watermark.scope() != source.scope()
        || p.signer_exact_watermark.journal_id() != source.journal_id()
        || p.signer_exact_watermark.sequence() > source.sequence()
        || (p.signer_exact_watermark.sequence() == source.sequence()
            && p.signer_exact_watermark != source)
        || p.generation == u64::MAX
    {
        return invalid("independently pinned original signer differs");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn joined_target<W: ExternalSignerRetirementV1>(
    predecessor: &ExternalNodeCheckpointV0,
    application: &DurableNativeApplicationV0,
    receipt: &PreHandoffCheckpointReceiptV1,
    descriptor: &HandoffDescriptorV0,
    profile: &HandoffSignerJournalProfileV1,
    safety: &SqliteOldEpochSafetyJournalV1,
    safety_head: &ConfirmedOldEpochSafetyHeadV1,
    retired: &RetiredSqliteSignerJournalV1<W>,
    retirement: &SignerRetirementRecordV1,
) -> Result<ExternalNodeCheckpointV0> {
    let app_error = EpochRetirementCheckpointErrorV1::Application;
    let row = receipt.durable_row();
    let header = receipt.header();
    if !row.belongs_to_application_at_path_v0(application, application.path())
        || row.status_v0() != DurableExecutionHistoryStatusV0::Committed
        || row.commit_sequence_v0().is_none()
        || row.store_id_v0() != application.config_v0().store_id()
        || profile.old_validator_set() != receipt.old_validator_set()
        || profile.new_validator_set() != receipt.new_validator_set()
        || profile.old_consensus_parameters() != receipt.old_parameters()
        || profile.new_consensus_parameters() != receipt.new_parameters()
        || retired.profile_v1().validator_set() != receipt.old_validator_set()
        || retired.profile_v1().author() != profile.author()
        || retired.profile_v1().external_watermark_scope() == profile.external_watermark_scope()
        || retired.profile_v1().signer_profile_ref() != profile.signer_profile_ref()
        || retired.profile_v1().profile_checksum() != retirement.source_profile_checksum_v1()
    {
        return invalid("native receipt or custody profile");
    }
    let native_head = row.target_head_v0().map_err(app_error)?;
    let read = application
        .read_finalized_by_block_id_v0(native_head.block_id())
        .map_err(app_error)?;
    let fresh_row = read.durable_row_v0();
    if fresh_row.target_head_v0().map_err(app_error)? != native_head
        || fresh_row.p_digest_v0() != row.p_digest_v0()
        || fresh_row.p_sequence_v0() != row.p_sequence_v0()
        || fresh_row.artifact_digest_v0() != row.artifact_digest_v0()
        || fresh_row.overlay_digest_v0() != row.overlay_digest_v0()
        || fresh_row.commit_sequence_v0() != row.commit_sequence_v0()
    {
        return invalid("fresh native committed P cut");
    }
    // The independently pinned predecessor application must be an actual
    // ancestor in this owner, not merely a smaller height with the same key.
    let previous = predecessor.fields();
    if previous.application_height == 0 {
        if previous.application_block_id.as_bytes()
            != &application.config_v0().initial_block_id_v0()
            || previous.application_state_root.as_bytes()
                != &application.config_v0().initial_state_root()
            || previous.application_timestamp_ms != 0
        {
            return invalid("foreign genesis application predecessor");
        }
    } else {
        let ancestor = application
            .read_finalized_by_height_v0(trnm_native_application::HeightV0::new(
                previous.application_height,
            ))
            .map_err(app_error)?;
        let actual = ancestor
            .durable_row_v0()
            .target_head_v0()
            .map_err(app_error)?;
        if actual.block_id().as_bytes() != previous.application_block_id.as_bytes()
            || actual.state_root().as_bytes() != previous.application_state_root.as_bytes()
            || actual.height().get() != previous.application_height
            || ancestor.executed_v0().request().timestamp_ms() != previous.application_timestamp_ms
        {
            return invalid("foreign committed application predecessor");
        }
    }
    let context = verify_pre_handoff_context_strict_v1(
        receipt.checkpoint_finality(),
        &receipt.next_epoch_commitment(),
        descriptor,
        receipt.old_validator_set(),
        receipt.old_parameters(),
        receipt.new_validator_set(),
        receipt.new_parameters(),
        receipt.checkpoint_parent_header(),
    )
    .map_err(EpochRetirementCheckpointErrorV1::Crypto)?;
    let intent = CanonicalHandoffSignIntentV1::old_set(
        descriptor,
        profile.old_validator_set(),
        profile.new_validator_set(),
        profile.old_consensus_parameters(),
        profile.new_consensus_parameters(),
        profile.author(),
    )
    .map_err(EpochRetirementCheckpointErrorV1::Crypto)?;
    if !safety_head.belongs_to_store_at_path_v1(safety, safety.path_v1()) {
        return invalid("original terminal Safety owner");
    }
    let (head, terminal) = safety
        .prepare_terminal_recovery_v1(safety_head.pin_v1())
        .map_err(EpochRetirementCheckpointErrorV1::Safety)?;
    let migration = head.migration_source_v1();
    let previous = predecessor.fields();
    if previous.safety_journal_id != migration.journal_id_v1()
        || previous.safety_verifier_profile_ref != migration.verifier_profile_ref_v1()
        || previous.safety_revision != migration.revision_v1()
        || previous.safety_state_record_checksum != migration.state_record_checksum_v1()
        || previous.safety_record_chain_checksum != migration.chain_checksum_v1()
    {
        return invalid("independent predecessor differs from audited journal7 migration origin");
    }
    let host = SignerRetirementHostCutV1 {
        owner_generation: head.owner_generation_v1(),
        native_committed_cut: receipt.committed_owner_cut_ref_v1(),
        safety_revision: head.revision_v1(),
        safety_record_checksum: head.state_record_checksum_v1(),
    };
    if terminal.config().validator_set() != profile.old_validator_set()
        || terminal.config().local_validator() != profile.author()
        || terminal.state().last_finalization_proof() != Some(receipt.checkpoint_finality())
        || head.state_record_checksum_v1() != safety_head.state_record_checksum_v1()
        || retirement.host_cut_v1() != host
        || retirement.pre_handoff_binding_v1() != context.binding_ref()
        || retirement.descriptor_digest_v1() != *intent.preimage().descriptor_digest().as_bytes()
        || retirement.old_handoff_intent_fingerprint_v1() != *intent.fingerprint().as_bytes()
        || predecessor.fields().application_height > header.height().get()
        || predecessor.fields().safety_revision > head.revision_v1()
    {
        return invalid("terminal14O/native/retirement join");
    }
    let config = application.config_v0();
    let fields = ExternalNodeCheckpointFieldsV0 {
        scope: predecessor.scope(),
        generation: predecessor.generation().checked_add(1).ok_or(
            EpochRetirementCheckpointErrorV1::Invalid("checkpoint generation exhausted"),
        )?,
        predecessor_checksum: predecessor.checkpoint_checksum(),
        safety_journal_id: head.journal_id_v1(),
        safety_verifier_profile_ref: head.context_ref_v1(),
        safety_revision: head.revision_v1(),
        safety_state_record_checksum: head.state_record_checksum_v1(),
        safety_record_chain_checksum: head.chain_checksum_v1(),
        application_host_config_ref: hash(
            b"trnm.node.epoch-retirement.native-config.v1",
            &[
                &config.store_id(),
                &config.genesis_hash_v0(),
                &config.chain_descriptor_hash_v0(),
                &config.signer_policy_commitment_v0(),
                config.chain_id_v0().as_bytes(),
            ],
        ),
        application_projection_profile_ref: hash(b"trnm.node.epoch-retirement.projection.v1", &[]),
        application_safety_binding_manifest_checksum: hash(
            b"trnm.node.epoch-retirement.join.v1",
            &[
                &context.binding_ref(),
                &retirement.descriptor_digest_v1(),
                &head.context_ref_v1(),
                &host.owner_generation.to_be_bytes(),
            ],
        ),
        application_committed_head_row_checksum: host.native_committed_cut,
        application_recovery_closure_checksum: hash(
            b"trnm.node.epoch-retirement.closure.v1",
            &[
                &retirement.encode_v1(),
                &head.chain_checksum_v1(),
                &host.native_committed_cut,
            ],
        ),
        application_block_id: header.id(),
        application_height: header.height().get(),
        application_state_root: header.state_root(),
        application_view: header.view().get(),
        application_timestamp_ms: header.timestamp_ms(),
        signer_journal_id: retirement.source_v1().journal_id(),
        signer_profile_checksum: retirement.source_profile_checksum_v1(),
        signer_exact_watermark: retirement.terminal_watermark_v1(),
    };
    ExternalNodeCheckpointV0::new(fields)
        .map_err(|_| EpochRetirementCheckpointErrorV1::Invalid("canonical checkpoint projection"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_consensus_signer_journal::SignerWatermarkV0;
    use trnm_consensus_types::{BlockId, StateRoot};

    // Codec-only fixture: no retired owner or confirmation can be produced by it.
    fn retirement() -> SignerRetirementRecordV1 {
        let mut bytes = Vec::from(b"TRNMSR01".as_slice());
        bytes.extend(1u16.to_be_bytes());
        bytes.extend([1; 32]);
        bytes.extend([2; 32]);
        bytes.extend(4u64.to_be_bytes());
        bytes.extend([3; 32]);
        bytes.extend(1u64.to_be_bytes());
        for v in [4, 5, 6, 7, 8] {
            bytes.extend([v; 32]);
        }
        bytes.extend(10u64.to_be_bytes());
        bytes.extend([9; 32]);
        let domain = b"trnm.consensus-signer-journal.retirement-record.v1";
        let mut h = Sha256::new();
        h.update(b"trnm.domain.hash.v1");
        h.update((domain.len() as u64).to_be_bytes());
        h.update(domain);
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(&bytes);
        bytes.extend(h.finalize());
        SignerRetirementRecordV1::decode_v1_exact(&bytes).unwrap()
    }
    fn predecessor(record: &SignerRetirementRecordV1) -> ExternalNodeCheckpointV0 {
        ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
            scope: record.source_v1().scope(),
            generation: 0,
            predecessor_checksum: [0; 32],
            safety_journal_id: [11; 32],
            safety_verifier_profile_ref: [12; 32],
            safety_revision: 5,
            safety_state_record_checksum: [13; 32],
            safety_record_chain_checksum: [14; 32],
            application_host_config_ref: [15; 32],
            application_projection_profile_ref: [16; 32],
            application_safety_binding_manifest_checksum: [17; 32],
            application_committed_head_row_checksum: [18; 32],
            application_recovery_closure_checksum: [19; 32],
            application_block_id: BlockId::new([20; 32]),
            application_height: 1,
            application_state_root: StateRoot::new([21; 32]),
            application_view: 1,
            application_timestamp_ms: 1000,
            signer_journal_id: record.source_v1().journal_id(),
            signer_profile_checksum: record.source_profile_checksum_v1(),
            signer_exact_watermark: record.source_v1(),
        })
        .unwrap()
    }
    #[test]
    fn independently_recorded_source_rejects_other_scope_journal_profile_and_fork() {
        let r = retirement();
        let original = predecessor(&r);
        assert!(check_original_identity_bounds(&original, &r).is_ok());
        for kind in 0..6 {
            let mut p = *original.fields();
            match kind {
                0 => {
                    p.scope = [99; 32];
                    p.signer_exact_watermark = SignerWatermarkV0::from_persisted_parts(
                        p.scope,
                        p.signer_journal_id,
                        4,
                        [3; 32],
                    )
                    .unwrap();
                }
                1 => {
                    p.signer_journal_id = [99; 32];
                    p.signer_exact_watermark = SignerWatermarkV0::from_persisted_parts(
                        p.scope,
                        p.signer_journal_id,
                        4,
                        [3; 32],
                    )
                    .unwrap();
                }
                2 => p.signer_profile_checksum = [99; 32],
                3 => {
                    p.signer_exact_watermark = SignerWatermarkV0::from_persisted_parts(
                        p.scope,
                        p.signer_journal_id,
                        6,
                        [3; 32],
                    )
                    .unwrap()
                }
                4 => {
                    p.signer_exact_watermark = SignerWatermarkV0::from_persisted_parts(
                        p.scope,
                        p.signer_journal_id,
                        4,
                        [99; 32],
                    )
                    .unwrap()
                }
                5 => {
                    p.generation = u64::MAX;
                    p.predecessor_checksum = [99; 32];
                }
                _ => unreachable!(),
            }
            let mutated = ExternalNodeCheckpointV0::new(p).unwrap();
            assert!(
                check_original_identity_bounds(&mutated, &r).is_err(),
                "mutation {kind}"
            );
        }
    }
}
