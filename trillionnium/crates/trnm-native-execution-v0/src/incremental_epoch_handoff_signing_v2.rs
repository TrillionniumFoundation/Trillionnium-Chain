//! Native comparison facts for the explicit M03 schema11 receipt adapter.
//! No signer callback, lease, Core ACK or external authority is owned here.
use super::*;

/// Fresh, pending-free native checkpoint and its original strict pre-certificate
/// context. Only this owner's complete schema11 audit constructs this value.
/// Consumers must reconfirm the local cut around their actual custody calls.
///
/// ```compile_fail
/// use trnm_native_execution_v0::ConfirmedIncrementalHandoffSigningV2;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ConfirmedIncrementalHandoffSigningV2>();
/// ```
#[must_use]
pub struct ConfirmedIncrementalHandoffSigningV2 {
    receipt: CommittedIncrementalEpochPreHandoffV2,
    header: BlockHeader,
    finality: Vec<u8>,
    strict: Box<trnm_consensus_crypto::StrictPreHandoffContextV1>,
    cut: [u8; 32],
}
impl ConfirmedIncrementalHandoffSigningV2 {
    pub fn checkpoint_receipt(&self) -> &CommittedIncrementalEpochPreHandoffV2 {
        &self.receipt
    }
    pub fn checkpoint_header(&self) -> &BlockHeader {
        &self.header
    }
    /// Original bytes retained by the genuine native commit, never reconstructed
    /// from a public descriptor, receipt or a different valid proof.
    pub fn checkpoint_finality_bytes(&self) -> &[u8] {
        &self.finality
    }
    pub fn strict_context(&self) -> &trnm_consensus_crypto::StrictPreHandoffContextV1 {
        &self.strict
    }
    /// Inert comparison digest; this does not reconstruct the confirmed owner.
    pub const fn committed_owner_cut_ref_v2(&self) -> [u8; 32] {
        self.cut
    }
}

fn exact_receipt(
    expected: &CommittedIncrementalEpochPreHandoffV2,
    fresh: &CommittedIncrementalEpochPreHandoffV2,
) -> bool {
    Arc::ptr_eq(&expected.owner, &fresh.owner)
        && expected.pin == fresh.pin
        && expected.anchor == fresh.anchor
        && expected.generation == fresh.generation
        && expected.head == fresh.head
        && expected.p_digest == fresh.p_digest
        && expected.persist_sequence == fresh.persist_sequence
        && expected.commit_sequence == fresh.commit_sequence
        && expected.storage_artifact == fresh.storage_artifact
        && expected.replay_parent == fresh.replay_parent
        && expected.replay_target == fresh.replay_target
        && expected.context == fresh.context
        && expected.strict_binding == fresh.strict_binding
        && expected.record_digest == fresh.record_digest
}

fn owner_cut(
    config: &NativeApplicationConfigV0,
    r: &CommittedIncrementalEpochPreHandoffV2,
) -> [u8; 32] {
    hash_domain(
        "trnm.native-application.incremental-handoff-signing-cut.v2",
        &[
            &config.store_id,
            &r.anchor,
            &r.pin,
            &r.generation.to_be_bytes(),
            &head_bytes(&r.head),
            &r.p_digest,
            &r.persist_sequence.to_be_bytes(),
            &r.commit_sequence.to_be_bytes(),
            &r.storage_artifact,
            &r.replay_parent.version.to_be_bytes(),
            &r.replay_parent.root,
            &r.replay_target.version.to_be_bytes(),
            &r.replay_target.root,
            &r.context,
            &r.record_digest,
            &r.strict_binding,
        ],
    )
}

impl DurableNativeApplicationV0 {
    /// Reconfirm an existing affine receipt at the current unattached checkpoint.
    /// One caller meter covers the complete retained-prefix cold audit. This
    /// performs local readbacks only and cannot call a signer or external store.
    pub fn confirm_incremental_handoff_signing_v2(
        &self,
        expected: &CommittedIncrementalEpochPreHandoffV2,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<ConfirmedIncrementalHandoffSigningV2> {
        ensure!(
            Arc::ptr_eq(&expected.owner, &self.owner_affinity),
            "schema11 signing foreign native receipt"
        );
        let _guard = self.lock_operation()?;
        self.confirm_namespace_identity_v1()?;
        sync_store_commit_boundary_v0(&self.path)?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let mut current = audited_current_with_budget(self, &tx, &m, budget)?;
        ensure!(
            current.current.pending.is_none()
                && current.current.epochs.len() == current.current.historical.len() + 1
                && current.current.ordinary.values().all(|p| p.status == 1)
                && m.durable_sequence == expected.commit_sequence,
            "schema11 signing requires unattached pending-free current checkpoint"
        );
        let fresh = receipt(
            self,
            &current,
            &m,
            *expected.head.block_id().as_bytes(),
            expected.p_digest,
        )?;
        ensure!(
            exact_receipt(expected, &fresh),
            "schema11 signing native cut changed"
        );
        let strict = current
            .signing_context
            .take()
            .context("schema11 signing strict context absent")?;
        ensure!(
            strict.binding_ref() == fresh.strict_binding,
            "schema11 signing strict context differs"
        );
        let p = current
            .current
            .ordinary
            .get(expected.head.block_id().as_bytes())
            .context("schema11 signing checkpoint P missing")?;
        let header = header(&p.header)?;
        let record = current
            .current
            .pre_handoff
            .take()
            .context("schema11 signing original proof absent")?;
        let cut = owner_cut(&self.config, &fresh);
        self.confirm_namespace_identity_v1()?;
        Ok(ConfirmedIncrementalHandoffSigningV2 {
            receipt: fresh,
            header,
            finality: record.evidence.proof,
            strict,
            cut,
        })
    }
}
