//! Explicit schema11 public evidence and current-live export. The receiver must
//! establish trust independently; no local owner capability crosses this seam.
use super::*;
use crate::{
    NativeIncrementalFinalityPathV2, NativeIncrementalFinalityStepV2,
    MAX_INCREMENTAL_FINALITY_BYTES_V2, MAX_INCREMENTAL_FINALITY_EPOCHS_V2,
    MAX_INCREMENTAL_FINALITY_HEADER_BYTES_V2, MAX_INCREMENTAL_FINALITY_LINKS_V2,
    MAX_INCREMENTAL_FINALITY_ROOT_BYTES_V2,
};
use pre_handoff::attachment;
use trnm_consensus_types::EpochActivationEvidenceBytesV0;

struct Event<'a> {
    head: &'a ApplicationHeadV0,
    parent: &'a ApplicationHeadV0,
    header: &'a [u8],
    digest: [u8; 32],
    parent_digest: Option<[u8; 32]>,
    sequence: u64,
    proof: &'a [u8],
    first: Option<[u8; 32]>,
}
struct Endpoint<'a> {
    head: &'a ApplicationHeadV0,
    header: &'a [u8],
    digest: Option<[u8; 32]>,
    sequence: u64,
}
fn endpoint<'a>(
    current: &'a Current,
    events: &'a BTreeMap<[u8; 32], Event<'a>>,
    block: &[u8; 32],
) -> Result<Endpoint<'a>> {
    if current.base.source.block_id().as_bytes() == block {
        return Ok(Endpoint {
            head: &current.base.source,
            header: &current.base.source_header,
            digest: None,
            sequence: current.base.source_sequence,
        });
    }
    let event = events
        .get(block)
        .context("schema11 export committed endpoint absent")?;
    Ok(Endpoint {
        head: event.head,
        header: event.header,
        digest: Some(event.digest),
        sequence: event.sequence,
    })
}
fn charge(total: &mut usize, bytes: &[u8], individual: usize) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= individual,
        "schema11 export field bound"
    );
    *total = total
        .checked_add(bytes.len())
        .context("schema11 export size overflow")?;
    ensure!(
        *total <= MAX_INCREMENTAL_FINALITY_BYTES_V2,
        "schema11 export aggregate bound"
    );
    Ok(())
}
fn charge_evidence(total: &mut usize, evidence: &EpochActivationEvidenceBytesV0) -> Result<()> {
    for root in [
        &evidence.old_checkpoint_finality,
        &evidence.next_epoch_commitment,
        &evidence.authorization_kernel,
        &evidence.old_validator_set,
        &evidence.old_consensus_parameters,
        &evidence.new_validator_set,
        &evidence.new_consensus_parameters,
        &evidence.authenticated_checkpoint_parent_header,
    ] {
        charge(total, root, MAX_INCREMENTAL_FINALITY_ROOT_BYTES_V2)?;
    }
    Ok(())
}
fn source_evidence(edge: &EdgeRow) -> Result<EpochActivationEvidenceBytesV0> {
    let evidence = EpochRecoveryEvidenceV1::decode(&edge.evidence)?;
    Ok(EpochActivationEvidenceBytesV0 {
        old_checkpoint_finality: evidence.checkpoint_finality,
        next_epoch_commitment: evidence.next_commitment,
        authorization_kernel: evidence.anchor,
        old_validator_set: evidence.old_set,
        old_consensus_parameters: evidence.old_parameters,
        new_validator_set: evidence.new_set,
        new_consensus_parameters: evidence.new_parameters,
        authenticated_checkpoint_parent_header: evidence.checkpoint_parent,
    })
}

impl DurableNativeApplicationV0 {
    /// Original proof bytes, authenticated locally under each retained epoch,
    /// exported as untrusted transport for the independent M13 verifier.
    #[inline(never)]
    pub fn export_incremental_epoch_finality_path_v2(
        &self,
        anchor_block: BlockIdV0,
        target_block: BlockIdV0,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<NativeIncrementalFinalityPathV2> {
        let _guard = self.lock_operation()?;
        self.confirm_namespace_identity_v1()?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let audited = audited_current_with_budget(self, &tx, &m, budget)?;
        let current = &audited.current;
        let first = lineage::load_first_records(&tx)?;
        let ordinary = load_ordinary_records(&tx)?;
        let checkpoints = pre_handoff::load_all(&tx)?;
        let attachments = attachment::load(&tx)?;
        let source = edge_row(&tx)?;
        let mut events = BTreeMap::new();
        for record in &first {
            let p = current
                .epochs
                .get(&record.block)
                .context("schema11 export first P absent")?;
            ensure!(
                p.digest == record.p_digest && p.target()? == record.head,
                "schema11 export first record differs"
            );
            ensure!(
                events
                    .insert(
                        record.block,
                        Event {
                            head: &record.head,
                            parent: &p.parent,
                            header: &p.header,
                            digest: p.digest,
                            parent_digest: None,
                            sequence: record.sequence,
                            proof: &record.proof,
                            first: Some(p.edge),
                        }
                    )
                    .is_none(),
                "schema11 export duplicate event"
            );
        }
        for record in ordinary.iter().chain(checkpoints.iter().map(|p| &p.record)) {
            let p = current
                .ordinary
                .get(&record.block)
                .context("schema11 export ordinary P absent")?;
            ensure!(
                p.status == 1
                    && p.digest == record.p_digest
                    && p.target()? == record.head
                    && p.commit_sequence == Some(record.sequence),
                "schema11 export committed record differs"
            );
            ensure!(
                events
                    .insert(
                        record.block,
                        Event {
                            head: &record.head,
                            parent: &p.parent,
                            header: &p.header,
                            digest: p.digest,
                            parent_digest: p.parent_p,
                            sequence: record.sequence,
                            proof: &record.proof,
                            first: None,
                        }
                    )
                    .is_none(),
                "schema11 export duplicate event"
            );
        }
        let anchor = endpoint(current, &events, anchor_block.as_bytes())?;
        let target = endpoint(current, &events, target_block.as_bytes())?;
        ensure!(
            anchor.head.height().get() < target.head.height().get()
                && target.head.height().get() <= m.head.height().get(),
            "schema11 export committed range"
        );
        let mut total = 0usize;
        charge(
            &mut total,
            anchor.header,
            MAX_INCREMENTAL_FINALITY_HEADER_BYTES_V2,
        )?;
        charge(
            &mut total,
            target.header,
            MAX_INCREMENTAL_FINALITY_HEADER_BYTES_V2,
        )?;
        let mut output = NativeIncrementalFinalityPathV2 {
            anchor_header_cev0: anchor.header.to_vec(),
            target_header_cev0: target.header.to_vec(),
            steps: Vec::new(),
        };
        let mut cursor = *target_block.as_bytes();
        let mut visited = BTreeSet::new();
        let mut epoch_count = 0usize;
        while cursor != *anchor_block.as_bytes() {
            ensure!(
                output.steps.len() < MAX_INCREMENTAL_FINALITY_LINKS_V2 && visited.insert(cursor),
                "schema11 export link count/cycle"
            );
            let event = events
                .get(&cursor)
                .context("schema11 export disconnected anchor")?;
            let parent = endpoint(current, &events, event.parent.block_id().as_bytes())?;
            ensure!(
                event.head.height().get() > anchor.head.height().get()
                    && parent.head == event.parent
                    && parent.sequence < event.sequence,
                "schema11 export application parent/sequence differs"
            );
            let h = header(event.header)?;
            let context = current.context_for(&h)?;
            let parent_header = header(parent.header)?;
            let (consensus_parent, evidence) = if let Some(binding) = event.first {
                epoch_count += 1;
                ensure!(
                    epoch_count <= MAX_INCREMENTAL_FINALITY_EPOCHS_V2
                        && binding == context.binding
                        && parent.head.height().get().checked_add(3) == Some(h.height().get())
                        && context
                            .runtime
                            .activation()
                            .old_checkpoint_finality()
                            .finalized_block()
                            .header()
                            == &parent_header,
                    "schema11 export first context/parent differs"
                );
                let evidence = if binding == source.binding {
                    ensure!(
                        parent.head == &current.base.source && context.prefix.len() == 1,
                        "schema11 export source edge differs"
                    );
                    source_evidence(&source)?
                } else {
                    let edge = attachments
                        .iter()
                        .find(|a| a.binding == binding)
                        .context("schema11 export consumed attachment missing")?;
                    ensure!(
                        edge.checkpoint == *parent.head
                            && Some(edge.checkpoint_p) == parent.digest
                            && edge.checkpoint_sequence == parent.sequence
                            && edge.consumed.as_ref().is_some_and(|v| v.block == cursor
                                && v.p_digest == event.digest
                                && v.sequence == event.sequence),
                        "schema11 export consumed attachment differs"
                    );
                    edge.public_evidence(&current.context_for(&parent_header)?)?
                };
                (
                    context
                        .runtime
                        .activation()
                        .terminal_old_header()
                        .try_cev0_bytes()
                        .map_err(|e| anyhow::anyhow!("schema11 export terminal: {e:?}"))?,
                    Some(evidence),
                )
            } else {
                ensure!(
                    event.parent_digest == parent.digest
                        && parent.head.height().get().checked_add(1) == Some(h.height().get()),
                    "schema11 export ordinary parent differs"
                );
                (parent.header.to_vec(), None)
            };
            ensure!(
                h.parent_id() == header(&consensus_parent)?.id(),
                "schema11 export consensus parent differs"
            );
            charge(
                &mut total,
                event.header,
                MAX_INCREMENTAL_FINALITY_HEADER_BYTES_V2,
            )?;
            charge(
                &mut total,
                &consensus_parent,
                MAX_INCREMENTAL_FINALITY_HEADER_BYTES_V2,
            )?;
            charge(
                &mut total,
                event.proof,
                MAX_INCREMENTAL_FINALITY_ROOT_BYTES_V2,
            )?;
            if let Some(evidence) = &evidence {
                charge_evidence(&mut total, evidence)?;
            }
            output.steps.push(NativeIncrementalFinalityStepV2 {
                header_cev0: event.header.to_vec(),
                consensus_parent_header_cev0: consensus_parent,
                proof: event.proof.to_vec(),
                epoch_evidence: evidence,
            });
            cursor = *event.parent.block_id().as_bytes();
        }
        output.steps.reverse();
        self.confirm_namespace_identity_v1()?;
        Ok(output)
    }

    /// Encode only the real current committed sparse leaves. This returns the
    /// existing inert M06 codec, never replay history or an installable owner.
    #[inline(never)]
    pub fn export_current_incremental_native_live_v2(
        &self,
        target_block: BlockIdV0,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<Vec<u8>> {
        let _guard = self.lock_operation()?;
        self.confirm_namespace_identity_v1()?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let audited = audited_current_with_budget(self, &tx, &m, budget)?;
        ensure!(
            m.head.block_id() == target_block,
            "schema11 live target is not current head"
        );
        let current = &audited.current;
        let raw = if let Some(p) = current.ordinary.get(target_block.as_bytes()) {
            ensure!(
                p.status == 1 && p.target()? == m.head,
                "schema11 live ordinary head differs"
            );
            &p.header
        } else {
            &current
                .epochs
                .get(target_block.as_bytes())
                .context("schema11 live first P missing")?
                .header
        };
        let h = header(raw)?;
        let context = current.context_for(&h)?;
        let active = context.runtime.activation();
        let reader = ni::open_incremental_reader_v1(
            &tx,
            &namespace(&self.config),
            ni::IncrementalParentV1::Committed(*target_block.as_bytes()),
        )?;
        ensure!(
            reader.version() == m.head.height().get()
                && reader.root().0 == *m.head.state_root().as_bytes(),
            "schema11 live sparse current head differs"
        );
        let entries = reader
            .verified_live_values_v1()?
            .into_iter()
            .map(|(key, value)| crate::NativeCurrentLiveEntryV1 { key, value })
            .collect();
        let bytes = crate::NativeCurrentLiveExportV1 {
            application_version: m.head.height().get(),
            state_root: *m.head.state_root().as_bytes(),
            schema_digest: crate::native_current_live_schema_digest_v1(),
            entries,
        }
        .encode()?;
        // The common M06 recomputer strictly readmits the target validator keys.
        // Charge those bounded checks on this same caller meter before invoking it.
        budget
            .charge_signature_work(active.new_validator_set().validators().len())
            .map_err(|e| anyhow::anyhow!("schema11 live key-check budget: {e:?}"))?;
        crate::recompute_native_current_live_v1(
            &bytes,
            &h,
            active.new_validator_set(),
            active.new_consensus_parameters(),
        )?;
        self.confirm_namespace_identity_v1()?;
        Ok(bytes)
    }
}
