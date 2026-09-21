//! Original successor evidence attached only to an actual committed checkpoint.
use super::*;

const MAX_EDGES: usize = 32;
const KIND1_CAPS: [usize; 7] = [4096, 4096, MAX_PROOF, MAX_PROOF, 4096, 1024 * 1024, 4096];

// Original local NI-EP2 bytes. This inert record never carries caller-supplied
// old trust and is not a serialized strict authority.
struct Kind1Evidence {
    parent: Vec<u8>,
    checkpoint: Vec<u8>,
    proof: Vec<u8>,
    kernel: Vec<u8>,
    commitment: Vec<u8>,
    set: Vec<u8>,
    parameters: Vec<u8>,
}
impl Kind1Evidence {
    fn fields(&self) -> [&[u8]; 7] {
        [
            &self.parent,
            &self.checkpoint,
            &self.proof,
            &self.kernel,
            &self.commitment,
            &self.set,
            &self.parameters,
        ]
    }
    fn encode(&self) -> Result<Vec<u8>> {
        let mut size = 6usize;
        for (field, cap) in self.fields().into_iter().zip(KIND1_CAPS) {
            ensure!(
                !field.is_empty() && field.len() <= cap,
                "schema11 kind1 field bound"
            );
            size = size
                .checked_add(4)
                .and_then(|n| n.checked_add(field.len()))
                .context("schema11 kind1 size overflow")?;
        }
        ensure!(
            size <= MAX_EPOCH_EVIDENCE_BYTES_V1,
            "schema11 kind1 aggregate bound"
        );
        let mut encoded = Vec::with_capacity(size);
        encoded.extend_from_slice(b"NI-EP2");
        for field in self.fields() {
            encoded.extend_from_slice(&u32::try_from(field.len())?.to_be_bytes());
            encoded.extend_from_slice(field);
        }
        Ok(encoded)
    }
    fn decode(raw: &[u8]) -> Result<Self> {
        ensure!(
            raw.len() <= MAX_EPOCH_EVIDENCE_BYTES_V1 && raw.starts_with(b"NI-EP2"),
            "schema11 kind1 codec tag/bound"
        );
        let mut cursor = 6usize;
        let mut fields = Vec::with_capacity(7);
        for cap in KIND1_CAPS {
            let end = cursor
                .checked_add(4)
                .context("schema11 kind1 length overflow")?;
            let size = u32::from_be_bytes(
                raw.get(cursor..end)
                    .context("schema11 kind1 truncated length")?
                    .try_into()?,
            ) as usize;
            ensure!(size > 0 && size <= cap, "schema11 kind1 field length");
            cursor = end;
            let end = cursor
                .checked_add(size)
                .context("schema11 kind1 field overflow")?;
            fields.push(
                raw.get(cursor..end)
                    .context("schema11 kind1 truncated field")?,
            );
            cursor = end;
        }
        ensure!(cursor == raw.len(), "schema11 kind1 trailing bytes");
        Ok(Self {
            parent: fields[0].to_vec(),
            checkpoint: fields[1].to_vec(),
            proof: fields[2].to_vec(),
            kernel: fields[3].to_vec(),
            commitment: fields[4].to_vec(),
            set: fields[5].to_vec(),
            parameters: fields[6].to_vec(),
        })
    }
    fn from_checkpoint(p: &P, parent: &P, record: &PreHandoff, kernel: &[u8]) -> Result<Self> {
        ensure!(
            !kernel.is_empty() && kernel.len() <= MAX_PROOF,
            "schema11 attachment kernel bound"
        );
        let evidence = Self {
            parent: parent.header.clone(),
            checkpoint: p.header.clone(),
            proof: record.evidence.proof.clone(),
            kernel: kernel.to_vec(),
            commitment: record.evidence.commitment.clone(),
            set: record.evidence.set.clone(),
            parameters: record.evidence.parameters.clone(),
        };
        let _ = evidence.encode()?;
        Ok(evidence)
    }
    fn verify(
        &self,
        predecessor: &trnm_consensus_crypto::StrictEpochRuntimeContextV1,
        ancestry: &[BlockHeader],
        p: &P,
        record: &PreHandoff,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<trnm_consensus_crypto::StrictEpochRuntimeContextV1> {
        ensure!(
            self.checkpoint == p.header
                && self.proof == record.evidence.proof
                && self.commitment == record.evidence.commitment
                && self.set == record.evidence.set
                && self.parameters == record.evidence.parameters
                && ancestry.last() == Some(&header(&self.parent)?),
            "schema11 attachment original checkpoint preimages differ"
        );
        let old_set = predecessor
            .activation()
            .new_validator_set()
            .try_cev0_bytes()
            .map_err(|e| anyhow::anyhow!("schema11 attachment old set: {e}"))?;
        let old_parameters = predecessor
            .activation()
            .new_consensus_parameters()
            .canonical_bytes();
        let activation = trnm_consensus_crypto::decode_verify_successor_epoch_activation_strict_v1(
            predecessor.activation(),
            ancestry,
            trnm_consensus_types::EpochActivationEvidencePreimagesV0 {
                old_checkpoint_finality: &self.proof,
                next_epoch_commitment: &self.commitment,
                authorization_kernel: &self.kernel,
                old_validator_set: &old_set,
                old_consensus_parameters: &old_parameters,
                new_validator_set: &self.set,
                new_consensus_parameters: &self.parameters,
                authenticated_checkpoint_parent_header: &self.parent,
            },
            budget,
        )?;
        ensure!(
            activation
                .old_checkpoint_finality()
                .finalized_block()
                .header()
                == &header(&p.header)?
                && activation
                    .handoff_certificate()
                    .descriptor()
                    .try_cev0_bytes()
                    .map_err(|e| anyhow::anyhow!("schema11 attachment descriptor: {e}"))?
                    == record.evidence.descriptor,
            "schema11 attachment strict checkpoint/descriptor differ"
        );
        let runtime =
            trnm_consensus_crypto::StrictEpochRuntimeContextV1::from_activation_v1(activation)
                .map_err(|e| anyhow::anyhow!("schema11 attachment strict runtime: {e}"))?;
        trnm_consensus_crypto::StrictEpochRuntimeContextV1::compose_successor_v1(
            predecessor,
            runtime,
            ancestry,
        )
        .map_err(|e| anyhow::anyhow!("schema11 attachment predecessor: {e}"))
    }
}

struct Consumed {
    block: [u8; 32],
    p_digest: [u8; 32],
    sequence: u64,
}
pub(in crate::durable) struct Attachment {
    binding: [u8; 32],
    ordinal: u64,
    predecessor: [u8; 32],
    preceding: Vec<[u8; 32]>,
    checkpoint: ApplicationHeadV0,
    checkpoint_p: [u8; 32],
    checkpoint_sequence: u64,
    context: [u8; 32],
    evidence: Kind1Evidence,
    consumed: Option<Consumed>,
    checksum: [u8; 32],
}
impl Attachment {
    fn projected(
        &self,
        config: &NativeApplicationConfigV0,
        anchor: [u8; 32],
    ) -> Result<ProjectedRow> {
        ProjectedRow::new(
            1,
            vec![
                blob(self.binding),
                number_value(self.ordinal),
                blob(self.predecessor),
                blob(prefix(&self.preceding)?),
                blob(head_bytes(&self.checkpoint)),
                blob(self.checkpoint_p),
                number_value(self.checkpoint_sequence),
                blob(self.context),
                Value::Integer(1),
                blob(self.evidence.encode()?),
                Value::Integer(i64::from(self.consumed.is_some())),
                self.consumed
                    .as_ref()
                    .map_or(Value::Null, |c| blob(c.block)),
                self.consumed
                    .as_ref()
                    .map_or(Value::Null, |c| blob(c.p_digest)),
                self.consumed
                    .as_ref()
                    .map_or(Value::Null, |c| number_value(c.sequence)),
            ],
        )
        .finish(config, anchor, &[9], &[2, 11, 12, 13], &[])
    }
}
pub(in crate::durable) struct Pending {
    record: Attachment,
    runtime: trnm_consensus_crypto::StrictEpochRuntimeContextV1,
}
impl Pending {
    pub(in crate::durable) fn runtime(
        &self,
    ) -> &trnm_consensus_crypto::StrictEpochRuntimeContextV1 {
        &self.runtime
    }
    pub(in crate::durable) fn audit_ordinary(
        &self,
        config: &NativeApplicationConfigV0,
        p: &P,
    ) -> Result<()> {
        ensure!(
            p.status == 0,
            "schema11 installed successor ordinary cannot be committed"
        );
        descendant::validate_p(
            p,
            config,
            self.runtime.activation().new_validator_set(),
            self.runtime.activation().new_consensus_parameters(),
            self.record.checkpoint.height().get(),
        )
    }
    pub(in crate::durable) fn binding(&self) -> [u8; 32] {
        self.record.binding
    }
    pub(in crate::durable) fn row(
        &self,
        config: &NativeApplicationConfigV0,
        anchor: [u8; 32],
    ) -> Result<ProjectedRow> {
        self.record.projected(config, anchor)
    }
}

impl Pending {
    pub(in crate::durable) fn audit_prepared(
        &self,
        tx: &rusqlite::Transaction<'_>,
        config: &NativeApplicationConfigV0,
        base: &Owner,
        p: &EpochP,
    ) -> Result<()> {
        p.validate_context(
            config,
            &EpochPContext {
                parent: &self.record.checkpoint,
                checkpoint_sequence: self.record.checkpoint_sequence,
                binding: self.record.binding,
                terminal: self.runtime.activation().terminal_old_header(),
                set: self.runtime.activation().new_validator_set(),
                parameters: self.runtime.activation().new_consensus_parameters(),
            },
        )?;
        ensure!(
            p.replay_parent == base.replay,
            "schema11 installed first replay checkpoint"
        );
        let (phase, consumed): (u8, Option<Vec<u8>>) = tx.query_row(
            "SELECT phase,committed_block FROM ni_epoch_edge WHERE strict_binding=?1",
            [p.edge.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            phase == 0 && consumed.is_none(),
            "schema11 installed sparse edge was consumed"
        );
        Ok(())
    }
}

#[path = "incremental_epoch_first_v2.rs"]
mod first;
pub use first::PreparedIncrementalFirstV2;

#[allow(clippy::too_many_arguments)]
pub(in crate::durable) fn audit_pending(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    base: &Owner,
    source: &EdgeRow,
    first: &EpochP,
    ordinary: &BTreeMap<[u8; 32], P>,
    predecessor: &trnm_consensus_crypto::StrictEpochRuntimeContextV1,
    pre_handoff: Option<&PreHandoff>,
    current_head: &ApplicationHeadV0,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<Option<Pending>> {
    let mut records = load(tx)?;
    // This phase admits the actual installed successor. Consumed successors
    // remain fenced until the complete first-new ledger walker is integrated.
    ensure!(
        records.len() <= 1,
        "schema11 successor prefix phase unsupported"
    );
    let Some(record) = records.pop() else {
        return Ok(None);
    };
    let checkpoint = pre_handoff.context("schema11 installed edge without pre-handoff")?;
    let p = ordinary
        .get(&checkpoint.record.block)
        .context("schema11 attached checkpoint P absent")?;
    let parent = ordinary
        .get(p.parent.block_id().as_bytes())
        .context("schema11 attached parent P absent")?;
    ensure!(
        record.ordinal == 1
            && record.predecessor == source.binding
            && record.preceding == [source.binding]
            && record.consumed.is_none()
            && record.binding != source.binding
            && record.checkpoint == *current_head
            && record.checkpoint == checkpoint.record.head
            && record.checkpoint_p == p.digest
            && record.checkpoint_sequence == checkpoint.record.sequence
            && record.context == checkpoint.context,
        "schema11 installed successor exact prefix/checkpoint"
    );
    let ancestry = retained_ancestry(first, ordinary, predecessor, parent)?;
    let runtime = record
        .evidence
        .verify(predecessor, &ancestry, p, checkpoint, budget)?;
    ensure!(
        *runtime.activation().binding_ref().as_bytes() == record.binding,
        "schema11 kind1 binding is not strict activation binding"
    );
    let projected = record.projected(config, base.anchor)?;
    ensure!(
        projected.values.last() == Some(&blob(record.checksum)),
        "schema11 attached edge checksum"
    );
    Ok(Some(Pending { record, runtime }))
}

fn decode_prefix(raw: &[u8]) -> Result<Vec<[u8; 32]>> {
    let count = u32::from_be_bytes(
        raw.get(..4)
            .context("schema11 prefix truncated")?
            .try_into()?,
    ) as usize;
    ensure!(
        count <= MAX_EDGES && raw.len() == 4 + count * 32,
        "schema11 prefix exact bound"
    );
    let values = raw[4..]
        .chunks_exact(32)
        .map(|v| v.try_into().map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()?;
    ensure!(prefix(&values)? == raw, "schema11 prefix canonical");
    Ok(values)
}

pub(in crate::durable) fn screen(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    let (count, bytes, invalid): (u64, u64, u64) = tx.query_row(
        "SELECT count(*),coalesce(sum(CASE WHEN typeof(evidence)='blob' THEN length(evidence) ELSE 0 END),0),coalesce(sum(CASE WHEN typeof(evidence)!='blob' OR length(evidence)=0 OR length(evidence)>67108864 OR typeof(prefix)!='blob' OR length(prefix)<4 OR length(prefix)>1028 OR typeof(evidence_kind)!='integer' OR evidence_kind NOT IN(0,1) THEN 1 ELSE 0 END),0) FROM native_incremental_epoch_edge_v2",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    ensure!(
        count > 0
            && count <= MAX_EDGES as u64
            && bytes <= MAX_EPOCH_EVIDENCE_BYTES_V1 as u64
            && invalid == 0,
        "schema11 attached edge capacity/type"
    );
    Ok(())
}
pub(in crate::durable) fn load(tx: &rusqlite::Transaction<'_>) -> Result<Vec<Attachment>> {
    screen(tx)?;
    let mut query = tx.prepare("SELECT binding,ordinal,predecessor,prefix,checkpoint_head,checkpoint_p,checkpoint_sequence,context_digest,evidence,phase,consumed_block,consumed_p,consumed_sequence,checksum FROM native_incremental_epoch_edge_v2 WHERE evidence_kind=1 ORDER BY ordinal LIMIT 33")?;
    let mut rows = query.query([])?;
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        ensure!(
            result.len() < MAX_EDGES - 1,
            "schema11 successor edge count"
        );
        let phase: i64 = row.get(9)?;
        let consumed = match phase {
            0 => {
                ensure!(
                    (10..=12).all(|i| matches!(row.get_ref(i), Ok(ValueRef::Null))),
                    "schema11 installed edge has consumed fields"
                );
                None
            }
            1 => Some(Consumed {
                block: fixed(row_blob(row, 10, 32, 32)?)?,
                p_digest: fixed(row_blob(row, 11, 32, 32)?)?,
                sequence: number(row_blob(row, 12, 8, 8)?)?,
            }),
            _ => anyhow::bail!("schema11 edge phase"),
        };
        result.push(Attachment {
            binding: fixed(row_blob(row, 0, 32, 32)?)?,
            ordinal: number(row_blob(row, 1, 8, 8)?)?,
            predecessor: fixed(row_blob(row, 2, 32, 32)?)?,
            preceding: decode_prefix(&row_blob(row, 3, 4, 1028)?)?,
            checkpoint: decode_head(&row_blob(row, 4, 104, 104)?)?,
            checkpoint_p: fixed(row_blob(row, 5, 32, 32)?)?,
            checkpoint_sequence: number(row_blob(row, 6, 8, 8)?)?,
            context: fixed(row_blob(row, 7, 32, 32)?)?,
            evidence: Kind1Evidence::decode(&row_blob(row, 8, 1, MAX_EPOCH_EVIDENCE_BYTES_V1)?)?,
            consumed,
            checksum: fixed(row_blob(row, 13, 32, 32)?)?,
        });
    }
    Ok(result)
}

#[must_use]
pub struct InstalledIncrementalEpochEdgeV2 {
    owner: Arc<()>,
    pin: [u8; 32],
    anchor: [u8; 32],
    generation: u64,
    record: Attachment,
    runtime: trnm_consensus_crypto::StrictEpochRuntimeContextV1,
}
impl InstalledIncrementalEpochEdgeV2 {
    pub const fn binding(&self) -> [u8; 32] {
        self.record.binding
    }
    pub fn application_parent(&self) -> &ApplicationHeadV0 {
        &self.record.checkpoint
    }
    pub fn consensus_parent(&self) -> &BlockHeader {
        self.runtime.activation().terminal_old_header()
    }
    pub fn new_validator_set(&self) -> &trnm_consensus_types::ValidatorSet {
        self.runtime.activation().new_validator_set()
    }
    pub fn new_parameters(&self) -> &ConsensusParametersV0 {
        self.runtime.activation().new_consensus_parameters()
    }
    pub fn original_kernel(&self) -> &[u8] {
        &self.record.evidence.kernel
    }
    pub fn belongs_to_application_at_path(
        &self,
        app: &DurableNativeApplicationV0,
        path: &Path,
    ) -> bool {
        path == app.path()
            && Arc::ptr_eq(&self.owner, &app.owner_affinity)
            && app
                .confirm_incremental_epoch_edge_v2(
                    self.binding(),
                    &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .is_ok_and(|fresh| {
                    fresh.pin == self.pin
                        && fresh.anchor == self.anchor
                        && fresh.generation == self.generation
                        && fresh.record.checksum == self.record.checksum
                })
    }
    pub fn preview_request(
        &self,
        timestamp_ms: u64,
        transactions: Vec<Vec<u8>>,
    ) -> Result<NativeEpochBlockPreviewRequestV1> {
        use crate::epoch_edge::EpochExecutionContextV1;
        use trnm_native_application::{
            BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0, ValidatorSetIdV0,
        };
        let request = NativeEpochBlockPreviewRequestV1::new(
            ChainIdV0::new(self.consensus_parent().chain_id().as_str())?,
            GenesisHashV0::new(*self.consensus_parent().genesis_hash().as_bytes())?,
            self.application_parent().clone(),
            BlockIdV0::new(*self.consensus_parent().id().as_bytes())?,
            HeightV0::new(self.consensus_parent().height().get()),
            Hash32V0::new(self.binding()),
            HeightV0::new(self.first_application_height_v1()),
            timestamp_ms,
            ValidatorSetIdV0::new(*self.new_validator_set().id().as_bytes())?,
            transactions,
        )?;
        self.validate_request_v1(&request)?;
        Ok(request)
    }
}
impl crate::epoch_edge::sealed::Sealed for InstalledIncrementalEpochEdgeV2 {}
impl crate::epoch_edge::EpochExecutionContextV1 for InstalledIncrementalEpochEdgeV2 {
    fn application_parent_v1(&self) -> &ApplicationHeadV0 {
        self.application_parent()
    }
    fn consensus_parent_v1(&self) -> &BlockHeader {
        self.consensus_parent()
    }
    fn first_application_height_v1(&self) -> u64 {
        self.runtime
            .activation()
            .handoff_certificate()
            .descriptor()
            .fields()
            .activation_height
            .get()
    }
    fn old_validator_set_v1(&self) -> &trnm_consensus_types::ValidatorSet {
        self.runtime.activation().old_validator_set()
    }
    fn old_parameters_v1(&self) -> &ConsensusParametersV0 {
        self.runtime.activation().old_consensus_parameters()
    }
    fn new_validator_set_v1(&self) -> &trnm_consensus_types::ValidatorSet {
        self.new_validator_set()
    }
    fn new_parameters_v1(&self) -> &ConsensusParametersV0 {
        self.new_parameters()
    }
    fn authorization_id_v1(&self) -> [u8; 32] {
        self.binding()
    }
    fn coordinates_v1(&self) -> crate::epoch_edge::EpochApplicationCoordinatesV1 {
        crate::epoch_edge::EpochApplicationCoordinatesV1 {
            checkpoint_version: self.record.checkpoint.height().get(),
            checkpoint_root: *self.record.checkpoint.state_root().as_bytes(),
            terminal_version: self.consensus_parent().height().get(),
            first_version: self.first_application_height_v1(),
            authorization_id: self.binding(),
        }
    }
}

impl DurableNativeApplicationV0 {
    pub fn confirm_incremental_epoch_edge_v2(
        &self,
        binding: [u8; 32],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<InstalledIncrementalEpochEdgeV2> {
        let _guard = self.lock_operation()?;
        self.confirm_namespace_identity_v1()?;
        sync_store_commit_boundary_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let tx = connection.unchecked_transaction()?;
        let metadata = load_metadata_v0(&tx, &self.config)?;
        let mut current = audited_current_with_budget(self, &tx, &metadata, budget)?;
        let pending = current
            .current
            .pending
            .take()
            .context("schema11 installed tail absent")?;
        ensure!(
            pending.record.binding == binding
                && pending.record.consumed.is_none()
                && pending.record.checkpoint == metadata.head,
            "schema11 installed confirmation requires exact checkpoint tail"
        );
        self.confirm_namespace_identity_v1()?;
        Ok(InstalledIncrementalEpochEdgeV2 {
            owner: Arc::clone(&self.owner_affinity),
            pin: current.pin,
            anchor: current.current.base.anchor,
            generation: current.current.generation,
            record: pending.record,
            runtime: pending.runtime,
        })
    }

    pub fn attach_incremental_epoch_handoff_v2(
        &self,
        receipt: &CommittedIncrementalEpochPreHandoffV2,
        original_kernel: &[u8],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<InstalledIncrementalEpochEdgeV2> {
        ensure!(
            !original_kernel.is_empty() && original_kernel.len() <= MAX_PROOF,
            "schema11 attachment input kernel bound"
        );
        let starting_work = budget.signature_work();
        let guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = load_metadata_v0(&tx, &self.config)?;
        let mut current = audited_current_with_budget(self, &tx, &metadata, budget)?;
        let owner_work = budget.signature_work() - starting_work;
        let checkpoint = current
            .current
            .pre_handoff
            .as_ref()
            .context("schema11 attachment needs committed pre-handoff")?;
        let p = current
            .current
            .ordinary
            .get(&checkpoint.record.block)
            .context("schema11 attachment checkpoint P missing")?;
        let parent = current
            .current
            .ordinary
            .get(p.parent.block_id().as_bytes())
            .context("schema11 attachment parent P missing")?;
        ensure!(
            Arc::ptr_eq(&receipt.owner, &self.owner_affinity)
                && receipt.pin == current.pin
                && receipt.anchor == current.current.base.anchor
                && receipt.head == metadata.head
                && receipt.head == checkpoint.record.head
                && receipt.p_digest == p.digest
                && receipt.persist_sequence == p.sequence
                && receipt.commit_sequence == checkpoint.record.sequence
                && receipt.storage_artifact == p.storage_artifact
                && receipt.replay_parent == p.replay_parent
                && receipt.replay_target == p.replay()?.head
                && receipt.context == checkpoint.context
                && receipt.strict_binding == checkpoint.strict_binding
                && receipt.record_digest == checkpoint.record.checksum,
            "schema11 attachment owner-affine exact pre-handoff receipt"
        );
        if let Some(pending) = &current.current.pending {
            ensure!(
                pending.record.evidence.kernel == original_kernel
                    && (receipt.generation == current.current.generation
                        || receipt.generation.checked_add(1) == Some(current.current.generation)),
                "schema11 attachment exact retry differs"
            );
            let binding = pending.binding();
            require_readback_budget(budget, owner_work)?;
            drop(tx);
            drop(connection);
            sync_store_commit_boundary_v0(&self.path)?;
            drop(guard);
            return self.confirm_incremental_epoch_edge_v2(binding, budget);
        }
        ensure!(
            receipt.generation == current.current.generation,
            "schema11 attachment stale generation"
        );
        let evidence = Kind1Evidence::from_checkpoint(p, parent, checkpoint, original_kernel)?;
        let ancestry = retained_ancestry(
            &current.current.first_p,
            &current.current.ordinary,
            &current.current.runtime,
            parent,
        )?;
        let runtime =
            evidence.verify(&current.current.runtime, &ancestry, p, checkpoint, budget)?;
        let binding = *runtime.activation().binding_ref().as_bytes();
        ensure!(
            binding != current.current.edge.binding,
            "schema11 cross-kind binding collision"
        );
        let mut record = Attachment {
            binding,
            ordinal: 1,
            predecessor: current.current.edge.binding,
            preceding: vec![current.current.edge.binding],
            checkpoint: checkpoint.record.head.clone(),
            checkpoint_p: p.digest,
            checkpoint_sequence: checkpoint.record.sequence,
            context: checkpoint.context,
            evidence,
            consumed: None,
            checksum: [0; 32],
        };
        let row = record.projected(&self.config, current.current.base.anchor)?;
        record.checksum = match row.values.last() {
            Some(Value::Blob(bytes)) => fixed(bytes.clone())?,
            _ => anyhow::bail!("schema11 internal attachment checksum"),
        };
        let (count, bytes): (u64, u64) = tx.query_row(
            "SELECT count(*),coalesce(sum(length(evidence)),0) FROM native_incremental_epoch_edge_v2",
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            count < MAX_EDGES as u64
                && bytes
                    .checked_add(record.evidence.encode()?.len() as u64)
                    .is_some_and(|n| n <= MAX_EPOCH_EVIDENCE_BYTES_V1 as u64),
            "schema11 prospective attachment capacity"
        );
        require_readback_budget(budget, budget.signature_work() - starting_work)?;
        let generation = current
            .current
            .generation
            .checked_add(1)
            .context("schema11 attachment generation exhausted")?;
        row.insert(&tx)?;
        current.current.pending = Some(Pending { record, runtime });
        update_owner(
            &tx,
            &self.config,
            &current.current,
            current.pin,
            &metadata.head,
            generation,
        )?;
        screen(&tx)?;
        self.confirm_namespace_identity_v1()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_attachment_before_commit");
        tx.commit()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_attachment_after_commit");
        drop(connection);
        sync_store_commit_boundary_v0(&self.path)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_attachment_after_fsync");
        drop(guard);
        self.confirm_incremental_epoch_edge_v2(binding, budget)
    }
}
