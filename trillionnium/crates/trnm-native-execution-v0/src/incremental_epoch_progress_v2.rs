//! Physical schema11 continuation. Legacy schema7 capabilities never enter here.
use super::*;
#[path = "incremental_epoch_checkpoint_v2.rs"]
pub(super) mod checkpoint;
pub use checkpoint::{ComputedIncrementalEpochSelectionV2, PreparedIncrementalCheckpointV2};
#[path = "incremental_epoch_pre_handoff_v2.rs"]
pub(super) mod pre_handoff;
pub use pre_handoff::{
    CommittedIncrementalEpochPreHandoffV2, IncrementalPreHandoffPreimagesV2,
    InstalledIncrementalEpochEdgeV2, PreparedIncrementalFirstV2,
};

#[must_use]
pub struct PreparedNativeIncrementalEpochV2 {
    owner: Arc<()>,
    p: P,
    pin: [u8; 32],
    edge: [u8; 32],
}
impl PreparedNativeIncrementalEpochV2 {
    pub fn executed(&self) -> Result<NativeExecutedBlockV0> {
        self.p.executed()
    }
    pub fn header(&self) -> Result<BlockHeader> {
        header(&self.p.header)
    }
    pub fn target_head(&self) -> Result<ApplicationHeadV0> {
        self.p.target()
    }
    pub const fn p_digest(&self) -> [u8; 32] {
        self.p.digest
    }
    pub const fn persist_sequence(&self) -> u64 {
        self.p.sequence
    }
    pub const fn commit_sequence(&self) -> Option<u64> {
        self.p.commit_sequence
    }
}
#[must_use]
pub struct CommittedNativeIncrementalEpochV2 {
    head: ApplicationHeadV0,
    p_digest: [u8; 32],
    sequence: u64,
    generation: u64,
}
impl CommittedNativeIncrementalEpochV2 {
    pub fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }
    pub const fn p_digest(&self) -> [u8; 32] {
        self.p_digest
    }
    pub const fn commit_sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}
fn audited_current(
    app: &DurableNativeApplicationV0,
    tx: &rusqlite::Transaction<'_>,
    m: &MetadataV0,
) -> Result<Projection> {
    audited_current_with_budget(
        app,
        tx,
        m,
        &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
    )
}
fn audited_current_with_budget(
    app: &DurableNativeApplicationV0,
    tx: &rusqlite::Transaction<'_>,
    m: &MetadataV0,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<Projection> {
    ensure!(
        epoch_durable::schema_version(tx)? == SCHEMA_VERSION,
        "schema11 current owner required"
    );
    app.confirm_namespace_identity_v1()?;
    let result = projection_with_budget(tx, &app.config, m, budget)?;
    compare_projection(tx, &result)?;
    ensure!(
        *app.incremental_migration_pin
            .lock()
            .map_err(|_| anyhow::anyhow!("schema11 pin lock"))?
            == Some(result.pin),
        "schema11 current pin mismatch"
    );
    Ok(result)
}
// Check the measured prospective readback cost before crossing a durability
// boundary. This copy grants no authority and performs no crypto; the actual
// fresh audit must still charge the original caller meter for every check.
pub(super) fn require_readback_budget(
    budget: &trnm_consensus_types::Cev0AdmissionBudgetV0,
    work: usize,
) -> Result<()> {
    let mut prospective = *budget;
    prospective
        .charge_signature_work(work)
        .map_err(|e| anyhow::anyhow!("schema11 prospective readback budget: {e:?}"))
}
fn retire_forks_v2(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    winner: [u8; 32],
) -> Result<()> {
    ensure!(
        epoch_durable::schema_version(tx)? == SCHEMA_VERSION,
        "schema11 fork owner version"
    );
    let mut query = tx.prepare(
        "SELECT block FROM native_incremental_epoch_first_commit_v2 ORDER BY block LIMIT 33",
    )?;
    let mut rows = query.query([])?;
    let mut protected = BTreeSet::new();
    while let Some(row) = rows.next()? {
        ensure!(
            protected.len() < 32 && protected.insert(fixed(row_blob(row, 0, 32, 32)?)?),
            "schema11 protected first inventory bound"
        );
    }
    ensure!(
        !protected.is_empty(),
        "schema11 original first record absent"
    );
    descendant::retire_forks_with_protected_first(tx, config, winner, &protected)
}
fn require_prepared(
    app: &DurableNativeApplicationV0,
    prepared: &PreparedNativeIncrementalEpochV2,
    current: &Projection,
) -> Result<()> {
    ensure!(
        Arc::ptr_eq(&app.owner_affinity, &prepared.owner)
            && prepared.pin == current.pin
            && prepared.edge
                == current
                    .current
                    .context_for(&header(&prepared.p.header)?)?
                    .binding,
        "schema11 prepared owner/prefix"
    );
    let actual = current
        .current
        .ordinary
        .get(&prepared.p.block)
        .context("schema11 prepared absent")?;
    ensure!(
        actual.digest == prepared.p.digest && actual.sequence == prepared.p.sequence,
        "schema11 prepared identity"
    );
    Ok(())
}
fn resolve(current: &Current, m: &MetadataV0, p: &P) -> Result<ResolvedParent> {
    let mut cursor = p;
    let mut replay = Vec::new();
    let mut bytes = 0usize;
    loop {
        if cursor.target()? == m.head {
            break;
        }
        ensure!(
            cursor.status == 0 && replay.len() < 8,
            "schema11 parent is not a current pending descendant"
        );
        let delta = cursor.replay()?;
        bytes = bytes
            .checked_add(cursor.replay_delta.len())
            .context("schema11 replay bound overflow")?;
        ensure!(bytes <= 64 * 1024 * 1024, "schema11 replay suffix bound");
        replay.push(delta);
        if cursor.parent == m.head {
            ensure!(
                cursor.replay_parent == current.base.replay,
                "schema11 parent replay anchor"
            );
            break;
        }
        if let Some(first) = current.epochs.get(cursor.parent.block_id().as_bytes()) {
            ensure!(
                first.parent == m.head
                    && first.replay_parent == current.base.replay
                    && cursor.parent == first.target()?
                    && cursor.parent_p == Some(first.digest),
                "schema11 pending first exact application anchor"
            );
            bytes = bytes
                .checked_add(first.replay_delta.len())
                .context("schema11 pending first replay overflow")?;
            ensure!(
                replay.len() < 8 && bytes <= 64 * 1024 * 1024,
                "schema11 pending first suffix bound"
            );
            replay.push(ReplayDelta::decode(&first.replay_delta)?);
            break;
        }
        cursor = current
            .ordinary
            .get(cursor.parent.block_id().as_bytes())
            .context("schema11 pending parent missing")?;
    }
    Ok(ResolvedParent {
        state: if p.target()? == m.head {
            ni::IncrementalParentV1::Committed(p.block)
        } else {
            ni::IncrementalParentV1::Prepared(p.storage_artifact)
        },
        replay,
        digest: Some(p.digest),
    })
}
enum ExecutionParent<'a> {
    Ordinary(&'a PreparedNativeIncrementalEpochV2),
    First(&'a PreparedIncrementalFirstV2),
}
struct ExecutionParentContext<'a> {
    head: ApplicationHeadV0,
    digest: [u8; 32],
    checkpoint_height: u64,
    resolved: ResolvedParent,
    runtime: &'a trnm_consensus_crypto::StrictEpochRuntimeContextV1,
}
fn execution_parent<'a>(
    app: &DurableNativeApplicationV0,
    current: &'a Projection,
    m: &MetadataV0,
    parent: ExecutionParent<'_>,
) -> Result<ExecutionParentContext<'a>> {
    match parent {
        ExecutionParent::Ordinary(prepared) => {
            require_prepared(app, prepared, current)?;
            let p = current
                .current
                .ordinary
                .get(&prepared.p.block)
                .context("schema11 ordinary parent absent")?;
            let runtime = current.current.context_for(&header(&p.header)?)?.runtime;
            Ok(ExecutionParentContext {
                head: p.target()?,
                digest: p.digest,
                checkpoint_height: runtime
                    .activation()
                    .old_checkpoint_finality()
                    .finalized_block()
                    .header()
                    .height()
                    .get(),
                resolved: resolve(&current.current, m, p)?,
                runtime,
            })
        }
        ExecutionParent::First(prepared) => {
            let p = prepared.require(app, current)?;
            let runtime = current.current.context_for(&header(&p.header)?)?.runtime;
            ensure!(
                p.parent == m.head && p.replay_parent == current.current.base.replay,
                "schema11 first-parent current checkpoint"
            );
            Ok(ExecutionParentContext {
                head: p.target()?,
                digest: p.digest,
                checkpoint_height: p.parent.height().get(),
                resolved: ResolvedParent {
                    state: ni::IncrementalParentV1::Prepared(p.storage_artifact),
                    replay: vec![ReplayDelta::decode(&p.replay_delta)?],
                    digest: Some(p.digest),
                },
                runtime,
            })
        }
    }
}
fn context_row(
    config: &NativeApplicationConfigV0,
    current: &Current,
    p: &P,
) -> Result<ProjectedRow> {
    ProjectedRow::new(
        2,
        vec![
            blob(p.block),
            blob(p.digest),
            Value::Integer(0),
            blob(prefix(&current.context_for(&header(&p.header)?)?.prefix)?),
            Value::Null,
            Value::Null,
            Value::Null,
        ],
    )
    .finish(config, current.base.anchor, &[], &[4, 5, 6], &[])
}
fn update_owner(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    current: &Current,
    pin: [u8; 32],
    head: &ApplicationHeadV0,
    generation: u64,
) -> Result<()> {
    let owner_prefix = current.owner_prefix();
    let row = ProjectedRow::new(
        0,
        vec![
            Value::Integer(1),
            Value::Integer(2),
            blob(current.base.anchor),
            number_value(current.migration_sequence),
            blob(pin),
            blob(*owner_prefix.last().context("schema11 empty owner prefix")?),
            blob(prefix(&owner_prefix)?),
            number_value(generation),
        ],
    )
    .finish(
        config,
        current.base.anchor,
        &[],
        &[],
        &[&current.base.checksum, &head_bytes(head)],
    )?;
    ensure!(tx.execute("UPDATE native_incremental_epoch_owner_v2 SET generation=?1,checksum=?2,tip_binding=?5,prefix=?6 WHERE id=1 AND migration_digest=?3 AND generation=?4", rusqlite::params_from_iter([&row.values[7],&row.values[8],&blob(pin),&number_value(current.generation),&row.values[5],&row.values[6]]))? == 1,"schema11 generation CAS");
    Ok(())
}
impl DurableNativeApplicationV0 {
    pub fn reopen_prepared_incremental_epoch_v2(
        &self,
        block: [u8; 32],
        digest: [u8; 32],
    ) -> Result<PreparedNativeIncrementalEpochV2> {
        self.reopen_prepared_incremental_epoch_with_budget_v2(
            block,
            digest,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
    }
    fn reopen_prepared_incremental_epoch_with_budget_v2(
        &self,
        block: [u8; 32],
        digest: [u8; 32],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<PreparedNativeIncrementalEpochV2> {
        let _guard = self.lock_operation()?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let current = audited_current_with_budget(self, &tx, &m, budget)?;
        let p = load_p(&tx, block)?.context("schema11 prepared missing")?;
        ensure!(p.digest == digest, "schema11 expected prepared digest");
        if p.status == 0 {
            let _ = resolve(&current.current, &m, &p)?;
        }
        self.confirm_namespace_identity_v1()?;
        let edge = current.current.context_for(&header(&p.header)?)?.binding;
        Ok(PreparedNativeIncrementalEpochV2 {
            owner: Arc::clone(&self.owner_affinity),
            p,
            pin: current.pin,
            edge,
        })
    }
    pub fn preview_incremental_epoch_descendant_v2(
        &self,
        parent: &PreparedNativeIncrementalEpochV2,
        request: &NativeBlockPreviewRequestV0,
    ) -> Result<NativeBlockPreviewV0> {
        self.preview_incremental_descendant_from_parent_v2(
            ExecutionParent::Ordinary(parent),
            request,
        )
    }
    pub fn preview_incremental_first_descendant_v2(
        &self,
        parent: &PreparedIncrementalFirstV2,
        request: &NativeBlockPreviewRequestV0,
    ) -> Result<NativeBlockPreviewV0> {
        self.preview_incremental_descendant_from_parent_v2(ExecutionParent::First(parent), request)
    }
    fn preview_incremental_descendant_from_parent_v2(
        &self,
        parent: ExecutionParent<'_>,
        request: &NativeBlockPreviewRequestV0,
    ) -> Result<NativeBlockPreviewV0> {
        let _guard = self.lock_operation()?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let current = audited_current(self, &tx, &m)?;
        let actual = execution_parent(self, &current, &m, parent)?;
        ensure!(
            request.parent() == &actual.head,
            "schema11 preview actual parent"
        );
        let mut view = execution_view(&tx, &self.config, &current.current.base, &actual.resolved)?;
        let set = actual.runtime.activation().new_validator_set();
        view.parameters = *actual.runtime.activation().new_consensus_parameters();
        let result = preview_complete_native_block_v0(&view, set, set.genesis_hash(), request)?;
        self.confirm_namespace_identity_v1()?;
        Ok(result)
    }
    pub fn execute_incremental_epoch_descendant_v2(
        &self,
        parent: &PreparedNativeIncrementalEpochV2,
        request: NativeBlockExecutionRequestV0,
        h: &BlockHeader,
    ) -> Result<PreparedNativeIncrementalEpochV2> {
        self.execute_incremental_descendant_from_parent_v2(
            ExecutionParent::Ordinary(parent),
            request,
            h,
        )
    }
    pub fn execute_incremental_first_descendant_v2(
        &self,
        parent: &PreparedIncrementalFirstV2,
        request: NativeBlockExecutionRequestV0,
        h: &BlockHeader,
    ) -> Result<PreparedNativeIncrementalEpochV2> {
        self.execute_incremental_descendant_from_parent_v2(
            ExecutionParent::First(parent),
            request,
            h,
        )
    }
    fn execute_incremental_descendant_from_parent_v2(
        &self,
        parent: ExecutionParent<'_>,
        request: NativeBlockExecutionRequestV0,
        h: &BlockHeader,
    ) -> Result<PreparedNativeIncrementalEpochV2> {
        let mut budget = trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0();
        let guard = self.lock_operation()?;
        let mut c = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let current = audited_current_with_budget(self, &tx, &m, &mut budget)?;
        let owner_work = budget.signature_work();
        let actual = execution_parent(self, &current, &m, parent)?;
        ensure!(
            request.parent() == &actual.head,
            "schema11 execution actual parent"
        );
        if let Some(p) = load_p(&tx, *request.block_id().as_bytes())? {
            ensure!(
                p.executed()?.request() == &request
                    && header(&p.header)? == *h
                    && p.parent_p == Some(actual.digest),
                "schema11 execution exact retry"
            );
            require_readback_budget(&budget, owner_work)?;
            drop(tx);
            drop(c);
            sync_store_commit_boundary_v0(&self.path)?;
            drop(guard);
            return self.reopen_prepared_incremental_epoch_with_budget_v2(
                p.block,
                p.digest,
                &mut budget,
            );
        }
        let mut view = execution_view(&tx, &self.config, &current.current.base, &actual.resolved)?;
        let set = actual.runtime.activation().new_validator_set();
        let parameters = actual.runtime.activation().new_consensus_parameters();
        view.parameters = *parameters;
        let complete = execute_complete_native_block_v0(&view, set, set.genesis_hash(), &request)?;
        let (executed, plan, identities, lifecycle) = complete.into_parts();
        ensure_finalized_header_binding_v0(h, &request)?;
        let keys = identities
            .iter()
            .map(|i| replay::command_key(i.command_id()))
            .chain(
                identities
                    .iter()
                    .map(|i| replay::nonce_key(i.signer_id(), i.nonce())),
            )
            .collect::<Result<Vec<_>>>()?;
        let replay_parent = view
            .replay
            .head
            .context("schema11 execution replay parent")?;
        let replay = view.replay.append(keys)?;
        drop(view);
        reserve_p_capacity(
            &tx,
            &encode_native_executed_block_artifact_v0(&executed)?,
            &h.try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("schema11 header: {e}"))?,
            &replay.encode()?,
            &serde_json::to_vec(&lifecycle)?,
        )?;
        require_readback_budget(&budget, owner_work)?;
        let delta = ni::stage_incremental_plan_v1(
            &tx,
            &namespace(&self.config),
            actual.resolved.state,
            *request.block_id().as_bytes(),
            &plan,
        )?;
        let mut p = P {
            block: *request.block_id().as_bytes(),
            sequence: m
                .durable_sequence
                .checked_add(1)
                .context("schema11 persist sequence exhausted")?,
            status: 0,
            parent: actual.head.clone(),
            parent_p: Some(actual.digest),
            artifact: encode_native_executed_block_artifact_v0(&executed)?,
            header: h
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("schema11 header: {e:?}"))?,
            storage_artifact: delta.artifact,
            storage_sequence: delta.persist_sequence,
            replay_parent,
            replay_delta: replay.encode()?,
            lifecycle: serde_json::to_vec(&lifecycle)?,
            digest: [0; 32],
            commit_sequence: None,
        };
        p.digest = p.calculate_digest(&self.config);
        descendant::validate_p(&p, &self.config, set, parameters, actual.checkpoint_height)?;
        tx.execute(
            "INSERT INTO native_incremental_p_v1 VALUES(?,?,0,?,?,?,?,?,?,?,?,?,?,?,NULL)",
            params![
                p.block.as_slice(),
                p.sequence.to_be_bytes().as_slice(),
                head_bytes(&p.parent),
                p.parent_p.map(|v| v.to_vec()),
                p.artifact,
                p.header,
                p.storage_artifact.as_slice(),
                p.storage_sequence.to_be_bytes().as_slice(),
                p.replay_parent.version.to_be_bytes().as_slice(),
                p.replay_parent.root.as_slice(),
                p.replay_delta,
                p.lifecycle,
                p.digest.as_slice()
            ],
        )?;
        context_row(&self.config, &current.current, &p)?.insert(&tx)?;
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=?1 WHERE singleton=1 AND durable_sequence=?2 AND schema_version=?3",params![p.sequence.to_be_bytes().as_slice(),m.durable_sequence.to_be_bytes().as_slice(),SCHEMA_VERSION.to_be_bytes().as_slice()])?==1,"schema11 persist CAS");
        screen_inventory(&tx, SCHEMA_VERSION)?;
        self.confirm_namespace_identity_v1()?;
        tx.commit()?;
        drop(c);
        sync_store_commit_boundary_v0(&self.path)?;
        drop(guard);
        self.reopen_prepared_incremental_epoch_with_budget_v2(p.block, p.digest, &mut budget)
    }
    pub fn commit_incremental_epoch_descendant_finality_bytes_v2(
        &self,
        prepared: &PreparedNativeIncrementalEpochV2,
        proof: &[u8],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<CommittedNativeIncrementalEpochV2> {
        ensure!(proof.len() <= MAX_PROOF, "schema11 input finality bound");
        let starting_work = budget.signature_work();
        let guard = self.lock_operation()?;
        let mut c = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let mut current = audited_current_with_budget(self, &tx, &m, budget)?;
        let owner_work = budget.signature_work() - starting_work;
        require_prepared(self, prepared, &current)?;
        let p = load_p(&tx, prepared.p.block)?.context("schema11 finality P missing")?;
        ensure!(
            header(&p.header)?.block_kind() == trnm_consensus_types::BlockKind::Regular,
            "schema11 ordinary finality kind"
        );
        let parent_header = if p.parent == current.current.first.head {
            header(&current.current.first_p.header)?
        } else {
            header(
                &current
                    .current
                    .ordinary
                    .get(p.parent.block_id().as_bytes())
                    .context("schema11 proof parent missing")?
                    .header,
            )?
        };
        let verified = current
            .current
            .runtime
            .decode_verify_finality_v1(proof, parent_header.timestamp_ms(), budget)
            .map_err(|e| anyhow::anyhow!("schema11 strict finality: {e}"))?;
        ensure!(
            verified.finalized_block().header() == &header(&p.header)?,
            "schema11 full finality header"
        );
        if p.status == 1 {
            let record = load_ordinary_records(&tx)?
                .into_iter()
                .find(|r| r.block == p.block)
                .context("schema11 committed retry absent")?;
            ensure!(
                record.proof == proof,
                "schema11 committed retry proof differs"
            );
            require_readback_budget(budget, owner_work)?;
            drop(tx);
            drop(c);
            sync_store_commit_boundary_v0(&self.path)?;
            drop(guard);
            let fresh =
                self.reopen_prepared_incremental_epoch_with_budget_v2(p.block, p.digest, budget)?;
            ensure!(
                fresh.p.commit_sequence == Some(record.sequence),
                "schema11 committed retry fresh sequence"
            );
            return Ok(CommittedNativeIncrementalEpochV2 {
                head: record.head,
                p_digest: p.digest,
                sequence: record.sequence,
                generation: current.current.generation,
            });
        }
        ensure!(
            m.head == p.parent && current.current.base.replay == p.replay_parent,
            "schema11 exact commit predecessor"
        );
        require_readback_budget(budget, budget.signature_work() - starting_work)?;
        let delta = ReplayReader::new(&tx, Some(current.current.base.replay), &[])?
            .append(replay_keys(p.executed()?.request().transactions())?)?;
        ensure!(
            delta.encode()? == p.replay_delta,
            "schema11 exact replay delta"
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
        let sequence = m
            .durable_sequence
            .checked_add(1)
            .context("schema11 commit sequence exhausted")?;
        let generation = current
            .current
            .generation
            .checked_add(1)
            .context("schema11 generation exhausted")?;
        ProjectedRow::new(
            5,
            vec![
                blob(p.block),
                blob(current.current.edge.binding),
                blob(p.digest),
                number_value(sequence),
                blob(head_bytes(&head)),
                blob(proof),
                blob(sha256_v0(proof)),
            ],
        )
        .finish(&self.config, current.current.base.anchor, &[5], &[], &[])?
        .insert(&tx)?;
        ensure!(tx.execute("UPDATE native_incremental_p_v1 SET status=1,commit_sequence=?1 WHERE block=?2 AND status=0 AND digest=?3",params![sequence.to_be_bytes().as_slice(),p.block.as_slice(),p.digest.as_slice()])?==1,"schema11 P commit CAS");
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=?,head_height=?,head_block_id=?,head_state_root=?,head_commit_id=? WHERE singleton=1 AND schema_version=? AND durable_sequence=? AND head_block_id=? AND head_state_root=? AND head_commit_id=?",params![sequence.to_be_bytes().as_slice(),head.height().get().to_be_bytes().as_slice(),head.block_id().as_bytes().as_slice(),head.state_root().as_bytes().as_slice(),head.commit_id().as_bytes().as_slice(),SCHEMA_VERSION.to_be_bytes().as_slice(),m.durable_sequence.to_be_bytes().as_slice(),m.head.block_id().as_bytes().as_slice(),m.head.state_root().as_bytes().as_slice(),m.head.commit_id().as_bytes().as_slice()])?==1,"schema11 head CAS");
        let base = &mut current.current.base;
        base.commit_sequence = sequence;
        base.storage_checksum = next.checksum;
        base.replay = delta.head;
        base.checksum = base.current_digest(&head);
        ensure!(tx.execute("UPDATE native_incremental_owner_v1 SET head_commit_sequence=?,storage_checksum=?,replay_version=?,replay_root=?,owner_checksum=? WHERE id=1",params![sequence.to_be_bytes().as_slice(),base.storage_checksum.as_slice(),base.replay.version.to_be_bytes().as_slice(),base.replay.root.as_slice(),base.checksum.as_slice()])?==1,"schema11 base owner CAS");
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
        self.confirm_namespace_identity_v1()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_ordinary_before_commit");
        tx.commit()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_ordinary_after_commit");
        drop(c);
        sync_store_commit_boundary_v0(&self.path)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_ordinary_after_fsync");
        drop(guard);
        let fresh =
            self.reopen_prepared_incremental_epoch_with_budget_v2(p.block, p.digest, budget)?;
        ensure!(
            fresh.p.commit_sequence == Some(sequence),
            "schema11 commit fresh sequence"
        );
        Ok(CommittedNativeIncrementalEpochV2 {
            head,
            p_digest: p.digest,
            sequence,
            generation,
        })
    }
}
