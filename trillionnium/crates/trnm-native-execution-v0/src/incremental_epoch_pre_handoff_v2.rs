//! Causal native checkpoint commit before either successor handoff role signs.
use super::checkpoint::{selection, PreparedIncrementalCheckpointV2};
use super::*;
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_handoff_descriptor_v0_exact,
    decode_next_epoch_commitment_v0_exact, decode_validator_set_v0_exact,
};
#[path = "incremental_epoch_attachment_v2.rs"]
pub(in crate::durable) mod attachment;
pub use attachment::{InstalledIncrementalEpochEdgeV2, PreparedIncrementalFirstV2};
#[path = "incremental_epoch_handoff_signing_v2.rs"]
mod signing;
pub use signing::ConfirmedIncrementalHandoffSigningV2;

pub struct IncrementalPreHandoffPreimagesV2<'a> {
    pub checkpoint_finality: &'a [u8],
    pub descriptor: &'a [u8],
    pub next_epoch_commitment: &'a [u8],
    pub new_validator_set: &'a [u8],
    pub new_parameters: &'a [u8],
}
#[derive(Clone)]
struct Evidence {
    proof: Vec<u8>,
    descriptor: Vec<u8>,
    commitment: Vec<u8>,
    set: Vec<u8>,
    parameters: Vec<u8>,
}
impl Evidence {
    fn new(input: &IncrementalPreHandoffPreimagesV2<'_>) -> Result<Self> {
        for (bytes, cap) in [
            (input.checkpoint_finality, MAX_PROOF),
            (input.descriptor, 4096),
            (input.next_epoch_commitment, 4096),
            (input.new_validator_set, 1024 * 1024),
            (input.new_parameters, 4096),
        ] {
            ensure!(
                !bytes.is_empty() && bytes.len() <= cap,
                "schema11 pre-handoff input bound"
            );
        }
        Ok(Self {
            proof: input.checkpoint_finality.to_vec(),
            descriptor: input.descriptor.to_vec(),
            commitment: input.next_epoch_commitment.to_vec(),
            set: input.new_validator_set.to_vec(),
            parameters: input.new_parameters.to_vec(),
        })
    }
}
pub(in crate::durable) struct PreHandoff {
    pub(in crate::durable) record: commit::Commit,
    evidence: Evidence,
    pub(in crate::durable) context: [u8; 32],
    pub(in crate::durable) strict_binding: [u8; 32],
}
pub(in crate::durable) fn screen(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    let (count,bytes,invalid):(u64,u64,u64)=tx.query_row("SELECT count(*),coalesce(sum(length(checkpoint_finality)+length(descriptor)+length(next_epoch_commitment)+length(new_validator_set)+length(new_parameters)),0),coalesce(sum(CASE WHEN typeof(checkpoint_finality)!='blob' OR length(checkpoint_finality)=0 OR length(checkpoint_finality)>8388608 OR typeof(descriptor)!='blob' OR length(descriptor)=0 OR length(descriptor)>4096 OR typeof(next_epoch_commitment)!='blob' OR length(next_epoch_commitment)=0 OR length(next_epoch_commitment)>4096 OR typeof(new_validator_set)!='blob' OR length(new_validator_set)=0 OR length(new_validator_set)>1048576 OR typeof(new_parameters)!='blob' OR length(new_parameters)=0 OR length(new_parameters)>4096 THEN 1 ELSE 0 END),0) FROM native_incremental_epoch_pre_handoff_v2",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    ensure!(
        count <= 32 && bytes <= MAX_EPOCH_EVIDENCE_BYTES_V1 as u64 && invalid == 0,
        "schema11 pre-handoff inventory capacity/type"
    );
    Ok(())
}
pub(in crate::durable) fn load(tx: &rusqlite::Transaction<'_>) -> Result<Option<PreHandoff>> {
    let mut values = load_all(tx)?;
    ensure!(values.len() <= 1, "schema11 legacy single-tail projection");
    Ok(values.pop())
}
pub(in crate::durable) fn load_all(tx: &rusqlite::Transaction<'_>) -> Result<Vec<PreHandoff>> {
    screen(tx)?;
    let mut q=tx.prepare("SELECT checkpoint_block,p_digest,commit_sequence,checkpoint_head,context_digest,checkpoint_finality,descriptor,next_epoch_commitment,new_validator_set,new_parameters,strict_binding,checksum FROM native_incremental_epoch_pre_handoff_v2 ORDER BY checkpoint_block LIMIT 33")?;
    let mut rows = q.query([])?;
    let mut values = Vec::new();
    while let Some(row) = rows.next()? {
        ensure!(values.len() < 32, "schema11 retained checkpoint bound");
        values.push(decode_record(row)?);
    }
    Ok(values)
}
fn decode_record(r: &rusqlite::Row<'_>) -> Result<PreHandoff> {
    let proof = row_blob(r, 5, 1, MAX_PROOF)?;
    Ok(PreHandoff {
        record: commit::Commit {
            block: fixed(row_blob(r, 0, 32, 32)?)?,
            p_digest: fixed(row_blob(r, 1, 32, 32)?)?,
            sequence: number(row_blob(r, 2, 8, 8)?)?,
            head: decode_head(&row_blob(r, 3, 104, 104)?)?,
            proof: proof.clone(),
            checksum: fixed(row_blob(r, 11, 32, 32)?)?,
        },
        evidence: Evidence {
            proof,
            descriptor: row_blob(r, 6, 1, 4096)?,
            commitment: row_blob(r, 7, 1, 4096)?,
            set: row_blob(r, 8, 1, 1024 * 1024)?,
            parameters: row_blob(r, 9, 1, 4096)?,
        },
        context: fixed(row_blob(r, 4, 32, 32)?)?,
        strict_binding: fixed(row_blob(r, 10, 32, 32)?)?,
    })
}
struct Verified {
    row: ProjectedRow,
    context: [u8; 32],
    strict_binding: [u8; 32],
    strict: Box<trnm_consensus_crypto::StrictPreHandoffContextV1>,
}
#[allow(clippy::too_many_arguments)]
fn verify(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    base: &Owner,
    bindings: &[[u8; 32]],
    first: &EpochP,
    ordinary: &BTreeMap<[u8; 32], P>,
    runtime: &trnm_consensus_crypto::StrictEpochRuntimeContextV1,
    p: &P,
    sequence: u64,
    evidence: &Evidence,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<Verified> {
    let native = |e: trnm_consensus_types::ValidationError| {
        anyhow::anyhow!("schema11 pre-handoff consensus: {e}")
    };
    let commitment = decode_next_epoch_commitment_v0_exact(&evidence.commitment)
        .map_err(|e| anyhow::anyhow!("schema11 pre-handoff exact decode: {e:?}"))?;
    let descriptor = decode_handoff_descriptor_v0_exact(&evidence.descriptor)
        .map_err(|e| anyhow::anyhow!("schema11 pre-handoff exact decode: {e:?}"))?;
    let set = decode_validator_set_v0_exact(&evidence.set)
        .map_err(|e| anyhow::anyhow!("schema11 pre-handoff exact decode: {e:?}"))?;
    let parameters = decode_consensus_parameters_v0_exact(&evidence.parameters)
        .map_err(|e| anyhow::anyhow!("schema11 pre-handoff exact decode: {e:?}"))?;
    let active = runtime.activation();
    let selected = selection(
        tx,
        config,
        ordinary,
        active.new_validator_set(),
        active.new_consensus_parameters(),
    )?;
    ensure!(
        commitment == selected.computed.commitment
            && set == selected.computed.new_validator_set
            && parameters == selected.computed.new_parameters,
        "schema11 complete deterministic cutoff selection"
    );
    let h = header(&p.header)?;
    let parent = ordinary
        .get(p.parent.block_id().as_bytes())
        .context("schema11 checkpoint committed parent absent")?;
    ensure!(
        h.block_kind() == trnm_consensus_types::BlockKind::EpochCheckpoint
            && h.height() == selected.preimage.checkpoint_height
            && h.next_epoch_commitment_hash() == Some(commitment.id())
            && parent.status == 1
            && parent.target()? == p.parent
            && p.parent_p == Some(parent.digest)
            && p.replay_parent == parent.replay()?.head
            && parent.commit_sequence.is_some_and(|s| s < sequence)
            && sequence > p.sequence,
        "schema11 checkpoint exact committed context"
    );
    let ancestry = retained_ancestry(first, ordinary, runtime, parent)?;
    let strict = trnm_consensus_crypto::decode_verify_successor_pre_handoff_context_strict_v1(
        active,
        &ancestry,
        &evidence.proof,
        &commitment,
        &descriptor,
        &set,
        &parameters,
        budget,
    )?;
    ensure!(
        strict.descriptor().fields().checkpoint_block_id == h.id()
            && strict.descriptor().fields().checkpoint_state_root == h.state_root()
            && strict.checkpoint_parent_block_id() == header(&parent.header)?.id()
            && strict.checkpoint_parent_timestamp_ms() == header(&parent.header)?.timestamp_ms(),
        "schema11 strict pre-handoff complete header"
    );
    let first_new = h
        .height()
        .get()
        .checked_add(3)
        .context("schema11 checkpoint geometry overflow")?;
    for (table, column) in [
        ("ni_roots", "version"),
        ("ni_values", "version"),
        ("ni_nodes", "node_version"),
        ("ni_pin", "version"),
    ] {
        let count: u64 = tx.query_row(
            &format!("SELECT count(*) FROM {table} WHERE {column}>?1 AND {column}<?2"),
            params![
                h.height().get().to_be_bytes().as_slice(),
                first_new.to_be_bytes().as_slice()
            ],
            |r| r.get(0),
        )?;
        ensure!(count == 0, "schema11 successor seal has physical state");
    }
    let cutoff_proof = load_ordinary_records(tx)?
        .into_iter()
        .find(|r| r.block == selected.cutoff.block)
        .context("schema11 cutoff original proof missing")?
        .proof;
    let preceding = prefix(bindings)?;
    let predecessor = *bindings
        .last()
        .context("schema11 pre-handoff empty predecessor prefix")?;
    ensure!(
        preceding.len() < 4 + 32 * 32,
        "schema11 successor attachment capacity"
    );
    let context = hash_domain(
        "trnm.native-application.incremental-epoch-context.v2",
        &[
            &config.store_id,
            &base.anchor,
            &p.digest,
            &head_bytes(&parent.target()?),
            &parent.digest,
            &parent
                .commit_sequence
                .context("schema11 parent commit sequence missing")?
                .to_be_bytes(),
            &preceding,
            &sha256_v0(
                &active
                    .new_validator_set()
                    .try_cev0_bytes()
                    .map_err(native)?,
            ),
            &sha256_v0(&active.new_consensus_parameters().canonical_bytes()),
            &head_bytes(&selected.cutoff.target()?),
            &selected.cutoff.digest,
            &selected.cutoff.sequence.to_be_bytes(),
            &selected
                .cutoff
                .commit_sequence
                .context("schema11 cutoff commit sequence missing")?
                .to_be_bytes(),
            &sha256_v0(&cutoff_proof),
            &sha256_v0(&p.header),
            &p.storage_artifact,
            &p.storage_sequence.to_be_bytes(),
            &p.replay_parent.version.to_be_bytes(),
            &p.replay_parent.root,
            &sha256_v0(&p.replay_delta),
            &sha256_v0(&p.lifecycle),
        ],
    );
    let strict_binding = strict.binding_ref();
    let row = ProjectedRow::new(
        3,
        vec![
            blob(p.block),
            blob(p.digest),
            number_value(sequence),
            blob(head_bytes(&p.target()?)),
            blob(predecessor),
            blob(preceding),
            blob(context),
            blob(&evidence.proof),
            blob(&evidence.descriptor),
            blob(&evidence.commitment),
            blob(&evidence.set),
            blob(&evidence.parameters),
            blob(strict_binding),
        ],
    )
    .finish(config, base.anchor, &[7, 8, 9, 10, 11], &[], &[])?;
    Ok(Verified {
        row,
        context,
        strict_binding,
        strict: Box::new(strict),
    })
}
fn retained_ancestry(
    first: &EpochP,
    ordinary: &BTreeMap<[u8; 32], P>,
    runtime: &trnm_consensus_crypto::StrictEpochRuntimeContextV1,
    parent: &P,
) -> Result<Vec<BlockHeader>> {
    let mut ancestry = Vec::new();
    let mut cursor = parent;
    loop {
        ensure!(
            ancestry.len() < MAX_PREPARED && cursor.status == 1,
            "schema11 pre-handoff committed ancestry bound"
        );
        ancestry.push(header(&cursor.header)?);
        if cursor.parent == first.target()? {
            ensure!(
                cursor.parent_p == Some(first.digest),
                "schema11 first ancestry digest"
            );
            break;
        }
        let previous = ordinary
            .get(cursor.parent.block_id().as_bytes())
            .context("schema11 pre-handoff ancestry missing")?;
        ensure!(
            previous.target()? == cursor.parent
                && cursor.parent_p == Some(previous.digest)
                && previous.commit_sequence < cursor.commit_sequence,
            "schema11 pre-handoff ancestry splice"
        );
        cursor = previous;
    }
    ancestry.push(header(&first.header)?);
    ancestry.push(runtime.activation().terminal_old_header().clone());
    ancestry.reverse();
    Ok(ancestry)
}
#[allow(clippy::too_many_arguments)]
pub(in crate::durable) fn audit(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    base: &Owner,
    bindings: &[[u8; 32]],
    first: &EpochP,
    ordinary: &BTreeMap<[u8; 32], P>,
    runtime: &trnm_consensus_crypto::StrictEpochRuntimeContextV1,
    record: &PreHandoff,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<(
    ProjectedRow,
    Box<trnm_consensus_crypto::StrictPreHandoffContextV1>,
)> {
    let p = ordinary
        .get(&record.record.block)
        .context("schema11 pre-handoff P missing")?;
    ensure!(
        p.status == 1
            && p.digest == record.record.p_digest
            && p.target()? == record.record.head
            && p.commit_sequence == Some(record.record.sequence),
        "schema11 pre-handoff P record differs"
    );
    let checked = verify(
        tx,
        config,
        base,
        bindings,
        first,
        ordinary,
        runtime,
        p,
        record.record.sequence,
        &record.evidence,
        budget,
    )?;
    ensure!(
        record.context == checked.context && record.strict_binding == checked.strict_binding,
        "schema11 pre-handoff strict binding/context"
    );
    Ok((checked.row, checked.strict))
}
#[must_use]
pub struct CommittedIncrementalEpochPreHandoffV2 {
    owner: Arc<()>,
    pin: [u8; 32],
    anchor: [u8; 32],
    generation: u64,
    head: ApplicationHeadV0,
    p_digest: [u8; 32],
    persist_sequence: u64,
    commit_sequence: u64,
    storage_artifact: [u8; 32],
    replay_parent: ReplayHead,
    replay_target: ReplayHead,
    context: [u8; 32],
    strict_binding: [u8; 32],
    record_digest: [u8; 32],
}
impl CommittedIncrementalEpochPreHandoffV2 {
    pub fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }
    pub const fn p_digest(&self) -> [u8; 32] {
        self.p_digest
    }
    pub const fn persist_sequence(&self) -> u64 {
        self.persist_sequence
    }
    pub const fn commit_sequence(&self) -> u64 {
        self.commit_sequence
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn context_digest(&self) -> [u8; 32] {
        self.context
    }
    pub const fn strict_binding(&self) -> [u8; 32] {
        self.strict_binding
    }
    pub const fn record_digest(&self) -> [u8; 32] {
        self.record_digest
    }
    pub const fn source_anchor(&self) -> [u8; 32] {
        self.anchor
    }
    pub const fn migration_pin(&self) -> [u8; 32] {
        self.pin
    }
    pub const fn storage_artifact(&self) -> [u8; 32] {
        self.storage_artifact
    }
    pub const fn replay_parent_root(&self) -> [u8; 32] {
        self.replay_parent.root
    }
    pub const fn replay_target_root(&self) -> [u8; 32] {
        self.replay_target.root
    }
    pub fn belongs_to_application_at_path(
        &self,
        app: &DurableNativeApplicationV0,
        path: &Path,
    ) -> bool {
        path == app.path()
            && Arc::ptr_eq(&self.owner, &app.owner_affinity)
            && app
                .confirm_incremental_epoch_pre_handoff_v2(
                    *self.head.block_id().as_bytes(),
                    self.p_digest,
                    &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .is_ok_and(|fresh| {
                    fresh.record_digest == self.record_digest
                        && fresh.generation == self.generation
                        && fresh.pin == self.pin
                        && fresh.head == self.head
                })
    }
}
fn require_sidecar(app: &DurableNativeApplicationV0, p: &P) -> Result<()> {
    use crate::poco_preparation_journal::{
        poco_preparation_sidecar_path_v0, PocoPreparationJournalV0,
    };
    let journal =
        PocoPreparationJournalV0::open_existing(poco_preparation_sidecar_path_v0(&app.path))?;
    let inventory = journal.audit_historical_source_v1()?;
    let digest = sha256_v0(&p.header);
    let matches = inventory
        .facts
        .iter()
        .filter(|r| {
            r.phase == 1
                && r.height == p.target().map(|h| h.height().get()).unwrap_or(u64::MAX)
                && r.bound_header_digest == Some(digest)
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "schema11 pre-handoff exact bound sidecar missing/ambiguous"
    );
    journal.require_retained_bound(matches[0].preparation_id, &p.header)
}
fn receipt(
    app: &DurableNativeApplicationV0,
    current: &Projection,
    m: &MetadataV0,
    block: [u8; 32],
    digest: [u8; 32],
) -> Result<CommittedIncrementalEpochPreHandoffV2> {
    let record = current
        .current
        .pre_handoff
        .as_ref()
        .context("schema11 pre-handoff row absent")?;
    let p = current
        .current
        .ordinary
        .get(&block)
        .context("schema11 pre-handoff P absent")?;
    ensure!(
        record.record.block == block
            && record.record.p_digest == digest
            && record.record.head == m.head
            && p.status == 1
            && p.digest == digest
            && p.commit_sequence == Some(record.record.sequence),
        "schema11 fresh pre-handoff requires exact current checkpoint"
    );
    require_sidecar(app, p)?;
    app.confirm_namespace_identity_v1()?;
    Ok(CommittedIncrementalEpochPreHandoffV2 {
        owner: Arc::clone(&app.owner_affinity),
        pin: current.pin,
        anchor: current.current.base.anchor,
        generation: current.current.generation,
        head: record.record.head.clone(),
        p_digest: p.digest,
        persist_sequence: p.sequence,
        commit_sequence: record.record.sequence,
        storage_artifact: p.storage_artifact,
        replay_parent: p.replay_parent,
        replay_target: p.replay()?.head,
        context: record.context,
        strict_binding: record.strict_binding,
        record_digest: record.record.checksum,
    })
}
impl DurableNativeApplicationV0 {
    pub fn confirm_incremental_epoch_pre_handoff_v2(
        &self,
        block: [u8; 32],
        digest: [u8; 32],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<CommittedIncrementalEpochPreHandoffV2> {
        let _guard = self.lock_operation()?;
        self.confirm_namespace_identity_v1()?;
        sync_store_commit_boundary_v0(&self.path)?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let current = audited_current_with_budget(self, &tx, &m, budget)?;
        receipt(self, &current, &m, block, digest)
    }
    pub fn commit_incremental_epoch_pre_handoff_v2(
        &self,
        prepared: &PreparedIncrementalCheckpointV2,
        input: IncrementalPreHandoffPreimagesV2<'_>,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<CommittedIncrementalEpochPreHandoffV2> {
        let evidence = Evidence::new(&input)?;
        let starting_work = budget.signature_work();
        let guard = self.lock_operation()?;
        let mut c = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let mut current = audited_current_with_budget(self, &tx, &m, budget)?;
        let owner_work = budget.signature_work() - starting_work;
        require_prepared(self, &prepared.prepared, &current)?;
        let p = load_p(&tx, prepared.prepared.p.block)?
            .context("schema11 pre-handoff selected P missing")?;
        require_sidecar(self, &p)?;
        if let Some(previous) = &current.current.pre_handoff {
            ensure!(
                previous.record.block == p.block
                    && previous.record.head == m.head
                    && previous.evidence.proof == evidence.proof
                    && previous.evidence.descriptor == evidence.descriptor
                    && previous.evidence.commitment == evidence.commitment
                    && previous.evidence.set == evidence.set
                    && previous.evidence.parameters == evidence.parameters,
                "schema11 pre-handoff exact retry conflict"
            );
            require_readback_budget(budget, owner_work)?;
            drop(tx);
            drop(c);
            sync_store_commit_boundary_v0(&self.path)?;
            drop(guard);
            return self.confirm_incremental_epoch_pre_handoff_v2(p.block, p.digest, budget);
        }
        ensure!(
            p.status == 0 && p.parent == m.head && p.replay_parent == current.current.base.replay,
            "schema11 pre-handoff exact current parent"
        );
        let sequence = m
            .durable_sequence
            .checked_add(1)
            .context("schema11 pre-handoff commit exhausted")?;
        let generation = current
            .current
            .generation
            .checked_add(1)
            .context("schema11 pre-handoff generation exhausted")?;
        let verified = verify(
            &tx,
            &self.config,
            &current.current.base,
            &current.current.active_prefix,
            &current.current.first_p,
            &current.current.ordinary,
            &current.current.runtime,
            &p,
            sequence,
            &evidence,
            budget,
        )?;
        require_readback_budget(budget, budget.signature_work() - starting_work)?;
        let delta = ReplayReader::new(&tx, Some(current.current.base.replay), &[])?
            .append(replay_keys(p.executed()?.request().transactions())?)?;
        ensure!(
            delta.encode()? == p.replay_delta,
            "schema11 checkpoint actual replay identities"
        );
        let head = p.target()?;
        let before = ni::read_incremental_head_v1(&tx, &namespace(&self.config))?;
        let next = ni::apply_incremental_delta_v1(
            &tx,
            &namespace(&self.config),
            &before,
            &p.storage()?,
            *head.commit_id().as_bytes(),
            current
                .current
                .runtime
                .activation()
                .new_validator_set()
                .epoch()
                .get(),
        )?;
        replay::apply(&tx, &delta)?;
        verified.row.insert(&tx)?;
        ensure!(tx.execute("UPDATE native_incremental_p_v1 SET status=1,commit_sequence=?1 WHERE block=?2 AND status=0 AND digest=?3",params![sequence.to_be_bytes().as_slice(),p.block.as_slice(),p.digest.as_slice()])?==1,"schema11 pre-handoff P CAS");
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=?,head_height=?,head_block_id=?,head_state_root=?,head_commit_id=? WHERE singleton=1 AND schema_version=? AND durable_sequence=? AND head_block_id=? AND head_state_root=? AND head_commit_id=?",params![sequence.to_be_bytes().as_slice(),head.height().get().to_be_bytes().as_slice(),head.block_id().as_bytes().as_slice(),head.state_root().as_bytes().as_slice(),head.commit_id().as_bytes().as_slice(),SCHEMA_VERSION.to_be_bytes().as_slice(),m.durable_sequence.to_be_bytes().as_slice(),m.head.block_id().as_bytes().as_slice(),m.head.state_root().as_bytes().as_slice(),m.head.commit_id().as_bytes().as_slice()])?==1,"schema11 pre-handoff head CAS");
        let base = &mut current.current.base;
        base.commit_sequence = sequence;
        base.storage_checksum = next.checksum;
        base.replay = delta.head;
        base.checksum = base.current_digest(&head);
        ensure!(tx.execute("UPDATE native_incremental_owner_v1 SET head_commit_sequence=?,storage_checksum=?,replay_version=?,replay_root=?,owner_checksum=? WHERE id=1",params![sequence.to_be_bytes().as_slice(),base.storage_checksum.as_slice(),base.replay.version.to_be_bytes().as_slice(),base.replay.root.as_slice(),base.checksum.as_slice()])?==1,"schema11 pre-handoff base CAS");
        update_owner(
            &tx,
            &self.config,
            &current.current,
            current.pin,
            &head,
            generation,
        )?;
        retire_forks_v2(&tx, &self.config, p.block)?;
        tx.execute("DELETE FROM native_incremental_epoch_p_context_v2 WHERE block NOT IN(SELECT block FROM native_incremental_p_v1 UNION ALL SELECT block FROM native_incremental_epoch_p_v1)",[])?;
        screen_inventory(&tx, SCHEMA_VERSION)?;
        screen(&tx)?;
        self.confirm_namespace_identity_v1()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_pre_handoff_before_commit");
        tx.commit()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_pre_handoff_after_commit");
        drop(c);
        sync_store_commit_boundary_v0(&self.path)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_pre_handoff_after_fsync");
        drop(guard);
        self.confirm_incremental_epoch_pre_handoff_v2(p.block, p.digest, budget)
    }
}
