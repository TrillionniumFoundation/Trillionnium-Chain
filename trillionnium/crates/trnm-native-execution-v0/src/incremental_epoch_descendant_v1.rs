//! Ordinary +1 descendants inside the exact authenticated new epoch lineage.
//! These APIs cannot alter schema5's ordinary configuration or admit another edge.
use super::*;
#[path = "incremental_epoch_selection_v1.rs"]
mod selection;
pub use selection::ComputedIncrementalEpochSelectionV1;
#[must_use]
pub struct PreparedNativeIncrementalEpochDescendantV1 {
    owner: Arc<()>,
    p: P,
    edge: [u8; 32],
}
impl PreparedNativeIncrementalEpochDescendantV1 {
    pub fn executed(&self) -> Result<NativeExecutedBlockV0> {
        self.p.executed()
    }
    pub fn header(&self) -> Result<BlockHeader> {
        header(&self.p.header)
    }
    pub fn application_parent(&self) -> &ApplicationHeadV0 {
        &self.p.parent
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
    pub const fn edge_binding(&self) -> [u8; 32] {
        self.edge
    }
    pub fn artifact_checksum(&self) -> [u8; 32] {
        sha256_v0(&self.p.artifact)
    }
    pub fn overlay_checksum(&self) -> [u8; 32] {
        hash_domain(
            "trnm.native-application.incremental-epoch-descendant-overlay.v1",
            &[
                &self.edge,
                &self.p.storage_artifact,
                &self.p.replay_parent.root,
                &sha256_v0(&self.p.replay_delta),
                &sha256_v0(&self.p.lifecycle),
            ],
        )
    }
    pub fn application_payload_and_receipts(
        &self,
    ) -> Result<(
        trnm_consensus_types::ApplicationPayloadV0,
        trnm_consensus_types::ExecutionReceiptsV0,
    )> {
        let executed = self.executed()?;
        let exact = crate::poco_checkpoint::native_execution_from_receipts_v0(
            executed.request().transactions(),
            executed.receipts(),
        )?;
        Ok((
            exact.application_payload().clone(),
            exact.execution_receipts().clone(),
        ))
    }
    pub fn belongs_to_application_at_path(
        &self,
        app: &DurableNativeApplicationV0,
        path: &Path,
    ) -> bool {
        path == app.path()
            && Arc::ptr_eq(&self.owner, &app.owner_affinity)
            && app
                .reopen_prepared_incremental_epoch_descendant_v1(self.p.block, self.p.digest)
                .is_ok_and(|p| {
                    p.p.status == self.p.status
                        && p.p.commit_sequence == self.p.commit_sequence
                        && p.edge == self.edge
                })
    }
}
#[derive(Clone, Copy)]
pub enum IncrementalEpochParentV1<'a> {
    First(&'a PreparedNativeIncrementalEpochExecutionV1),
    Descendant(&'a PreparedNativeIncrementalEpochDescendantV1),
}
impl IncrementalEpochParentV1<'_> {
    fn require(
        &self,
        app: &DurableNativeApplicationV0,
    ) -> Result<(ApplicationHeadV0, [u8; 32], [u8; 32])> {
        match self {
            Self::First(p) => {
                ensure!(
                    Arc::ptr_eq(&p.owner, &app.owner_affinity),
                    "epoch first parent owner"
                );
                Ok((p.target_head()?, p.p.digest, p.p.edge))
            }
            Self::Descendant(p) => {
                ensure!(
                    Arc::ptr_eq(&p.owner, &app.owner_affinity),
                    "epoch descendant parent owner"
                );
                Ok((p.target_head()?, p.p.digest, p.edge))
            }
        }
    }
}
pub(super) fn context(
    evidence: &EpochRecoveryEvidenceV1,
) -> Result<(ValidatorSet, ConsensusParametersV0)> {
    let set = trnm_consensus_types::decode_validator_set_v0_exact(&evidence.new_set)
        .map_err(|e| anyhow::anyhow!("descendant set: {e:?}"))?;
    let params =
        trnm_consensus_types::decode_consensus_parameters_v0_exact(&evidence.new_parameters)
            .map_err(|e| anyhow::anyhow!("descendant parameters: {e:?}"))?;
    Ok((set, params))
}
pub(super) fn validate_p(
    p: &P,
    config: &NativeApplicationConfigV0,
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    checkpoint: u64,
) -> Result<()> {
    p.validate_context(config, set, parameters)?;
    let h = header(&p.header)?;
    ensure!(
        h.height().get() > checkpoint.checked_add(3).context("epoch first overflow")?
            && h.height().get()
                < checkpoint
                    .checked_add(parameters.epoch_length_blocks())
                    .context("epoch terminal overflow")?
            && p.parent_p.is_some(),
        "descendant exact epoch/parent boundary"
    );
    Ok(())
}
pub(super) fn validate_storage_p(tx: &rusqlite::Transaction<'_>, p: &P) -> Result<()> {
    type StorageIdentity = (
        Vec<u8>,
        Vec<u8>,
        bool,
        Vec<u8>,
        u8,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        u8,
    );
    let row: StorageIdentity = tx.query_row("SELECT persist_sequence,block_id,edge,target_height,parent_kind,parent_id,parent_height,parent_root,phase FROM ni_prepared WHERE artifact=?1",[p.storage_artifact.as_slice()],|r|Ok((row_blob(r,0,8,8)?,row_blob(r,1,32,32)?,matches!(r.get_ref(2)?,rusqlite::types::ValueRef::Null),row_blob(r,3,8,8)?,r.get(4)?,row_blob(r,5,32,32)?,row_blob(r,6,8,8)?,row_blob(r,7,32,32)?,r.get(8)?)))?;
    let parent_block = *p.parent.block_id().as_bytes();
    let (parent_head, parent_digest, parent_artifact) =
        if let Some(first) = load_epoch_p(tx, parent_block)? {
            (first.target()?, first.digest, first.storage_artifact)
        } else {
            let parent =
                load_p(tx, parent_block)?.context("descendant storage native parent missing")?;
            (parent.target()?, parent.digest, parent.storage_artifact)
        };
    ensure!(
        parent_head == p.parent
            && p.parent_p == Some(parent_digest)
            && number(row.0)? == p.storage_sequence
            && fixed::<32>(row.1)? == p.block
            && row.2
            && number(row.3)? == p.target()?.height().get()
            && match row.4 {
                0 => fixed::<32>(row.5)? == parent_block,
                1 => fixed::<32>(row.5)? == parent_artifact,
                _ => false,
            }
            && number(row.6)? == p.parent.height().get()
            && fixed::<32>(row.7)? == *p.parent.state_root().as_bytes()
            && row.8 == p.status,
        "descendant P storage identity/sequence"
    );
    Ok(())
}
pub(super) fn audit_inventory(
    tx: &rusqlite::Transaction<'_>,
    durable_sequence: u64,
    base: &Owner,
) -> Result<u64> {
    audit_inventory_with_policy(
        tx,
        durable_sequence,
        base,
        epoch_durable::schema_version(tx)? == COMMIT_SCHEMA_VERSION,
    )
}
pub(super) fn audit_inventory_with_policy(
    tx: &rusqlite::Transaction<'_>,
    durable_sequence: u64,
    base: &Owner,
    include_commits: bool,
) -> Result<u64> {
    let (count,bytes,maxp,maxc):(u64,u64,Option<Vec<u8>>,Option<Vec<u8>>)=tx.query_row("SELECT count(*),coalesce(sum(length(artifact)+length(header)+length(replay_delta)+length(lifecycle)),0),max(sequence),max(commit_sequence) FROM native_incremental_p_v1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    ensure!(
        count <= MAX_PREPARED as u64 && bytes <= MAX_P_BYTES as u64,
        "epoch descendant inventory capacity"
    );
    if include_commits {
        let(proofs,proof_bytes):(u64,u64)=tx.query_row("SELECT count(*),coalesce(sum(length(proof)),0) FROM native_incremental_epoch_descendant_commit_v1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        let committed: u64 = tx.query_row(
            "SELECT count(*) FROM native_incremental_p_v1 WHERE status=1",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            proofs == committed && proof_bytes <= MAX_EPOCH_EVIDENCE_BYTES_V1 as u64,
            "descendant proof inventory/capacity"
        );
    }
    let max = maxp
        .map(number)
        .transpose()?
        .unwrap_or(base.source_sequence)
        .max(maxc.map(number).transpose()?.unwrap_or(0));
    ensure!(max <= durable_sequence, "epoch descendant future sequence");
    Ok(max)
}
#[allow(clippy::too_many_arguments)]
pub(super) fn audit_committed_head(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    evidence: &EpochRecoveryEvidenceV1,
    edge_row: &EdgeRow,
    base: &Owner,
    m: &MetadataV0,
    first: &commit::Commit,
    mut budget: Option<&mut trnm_consensus_types::Cev0AdmissionBudgetV0>,
) -> Result<()> {
    let p =
        load_p(tx, *m.head.block_id().as_bytes())?.context("epoch committed descendant missing")?;
    let (set, params) = context(evidence)?;
    validate_p(&p, config, &set, &params, base.source.height().get())?;
    ensure!(
        p.status == 1
            && p.target()? == m.head
            && p.commit_sequence == Some(base.commit_sequence)
            && base.commit_sequence > first.sequence
            && base.replay == p.replay()?.head,
        "epoch descendant current commit"
    );
    // Prove the retained committed ancestry, bounded by one protocol epoch and
    // the explicit local row limit; never infer descent from height alone.
    if let Some(shared) = budget.as_deref_mut() {
        audit_commit_with_budget(tx, config, edge_row, &p, first, &set, &params, shared)?;
    } else {
        audit_commit(tx, config, edge_row, &p, first, &set, &params)?;
    }
    let mut current = p;
    let mut depth = 0;
    while current.parent != first.head {
        depth += 1;
        ensure!(depth <= MAX_PREPARED, "committed epoch ancestry capacity");
        let previous = load_p(tx, *current.parent.block_id().as_bytes())?
            .context("committed ancestor missing")?;
        validate_p(&previous, config, &set, &params, base.source.height().get())?;
        ensure!(
            previous.status == 1
                && previous.target()? == current.parent
                && Some(previous.digest) == current.parent_p
                && previous.sequence < current.sequence
                && previous.replay()?.head == current.replay_parent
                && previous.commit_sequence < current.commit_sequence,
            "committed ancestor splice"
        );
        if let Some(shared) = budget.as_deref_mut() {
            audit_commit_with_budget(
                tx, config, edge_row, &previous, first, &set, &params, shared,
            )?;
        } else {
            audit_commit(tx, config, edge_row, &previous, first, &set, &params)?;
        }
        current = previous;
    }
    let count: u64 = tx.query_row(
        "SELECT count(*) FROM native_incremental_p_v1 WHERE status=1",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        count == depth as u64 + 1,
        "committed descendant orphan inventory"
    );
    ensure!(
        current.parent_p == Some(first.p_digest),
        "first committed descendant P binding"
    );
    Ok(())
}
fn resolve(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    m: &MetadataV0,
    base: &Owner,
    edge: &AuthenticatedEpochApplicationEdgeV1,
    head: &ApplicationHeadV0,
    expected_digest: [u8; 32],
) -> Result<ResolvedParent> {
    let mut current = head.clone();
    let mut digest = expected_digest;
    let mut replay = Vec::new();
    let mut bytes = 0usize;
    let mut newest = None;
    let mut younger = u64::MAX;
    loop {
        let (actual, parent, replay_parent, delta, sequence, storage, actual_digest, parent_p) =
            if current.height().get() == edge.first_application_height() {
                let p = load_epoch_p(tx, *current.block_id().as_bytes())?
                    .context("first parent P missing")?;
                p.validate(config, edge)?;
                p.validate_storage(tx)?;
                (
                    p.target()?,
                    p.parent,
                    p.replay_parent,
                    ReplayDelta::decode(&p.replay_delta)?,
                    p.sequence,
                    p.storage_artifact,
                    p.digest,
                    None,
                )
            } else {
                let p = load_p(tx, *current.block_id().as_bytes())?
                    .context("descendant parent P missing")?;
                validate_p(
                    &p,
                    config,
                    edge.new_validator_set(),
                    edge.new_parameters(),
                    base.source.height().get(),
                )?;
                validate_storage_p(tx, &p)?;
                let delta = p.replay()?;
                (
                    p.target()?,
                    p.parent,
                    p.replay_parent,
                    delta,
                    p.sequence,
                    p.storage_artifact,
                    p.digest,
                    p.parent_p,
                )
            };
        ensure!(
            actual == current
                && actual_digest == digest
                && sequence < younger
                && sequence <= m.durable_sequence,
            "epoch prepared parent splice/sequence"
        );
        younger = sequence;
        newest.get_or_insert(storage);
        if current == m.head {
            break;
        }
        ensure!(replay.len() < 8, "epoch prepared ancestry capacity");
        bytes = bytes
            .checked_add(delta.encode()?.len())
            .context("epoch replay bytes overflow")?;
        ensure!(bytes <= 64 * 1024 * 1024, "epoch replay suffix capacity");
        replay.push(delta);
        if parent == m.head {
            ensure!(replay_parent == base.replay, "epoch prepared replay anchor");
            break;
        }
        if let Some(previous) = parent_p {
            digest = previous;
        } else {
            anyhow::bail!("uncommitted first parent no longer current checkpoint");
        }
        current = parent;
    }
    let state = if head == &m.head {
        ni::IncrementalParentV1::Committed(*head.block_id().as_bytes())
    } else {
        ni::IncrementalParentV1::Prepared(newest.context("epoch parent storage missing")?)
    };
    // ReplayReader validates every root edge as it installs newest-first deltas.
    let _ = ReplayReader::new(tx, Some(base.replay), &replay)?;
    Ok(ResolvedParent {
        state,
        replay,
        digest: Some(expected_digest),
    })
}
fn ensure_schema(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    ensure!(
        epoch_durable::schema_version(tx)? == COMMIT_SCHEMA_VERSION,
        "schema7 descendants required"
    );
    Ok(())
}
impl DurableNativeApplicationV0 {
    pub fn preview_incremental_epoch_descendant_v1(
        &self,
        parent: IncrementalEpochParentV1<'_>,
        request: &NativeBlockPreviewRequestV0,
    ) -> Result<NativeBlockPreviewV0> {
        let (head, digest, binding) = parent.require(self)?;
        ensure!(*request.parent() == head, "epoch descendant preview parent");
        let edge = self.recover_incremental_epoch_edge_v1()?;
        ensure!(
            edge.authorization_id() == binding,
            "epoch descendant lineage"
        );
        let _guard = self.lock_operation()?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        ensure_schema(&tx)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let (base, row) = audit_owner(&tx, &self.config, &m)?;
        require_live_edge(self, &row, &edge)?;
        let resolved = resolve(&tx, &self.config, &m, &base, &edge, &head, digest)?;
        let mut view = execution_view(&tx, &self.config, &base, &resolved)?;
        view.parameters = *edge.new_parameters();
        preview_complete_native_block_v0(
            &view,
            edge.new_validator_set(),
            edge.new_validator_set().genesis_hash(),
            request,
        )
    }
    pub fn execute_incremental_epoch_descendant_v1(
        &self,
        parent: IncrementalEpochParentV1<'_>,
        request: NativeBlockExecutionRequestV0,
        h: &BlockHeader,
    ) -> Result<PreparedNativeIncrementalEpochDescendantV1> {
        let (head, digest, binding) = parent.require(self)?;
        ensure!(
            *request.parent() == head,
            "epoch descendant execution parent"
        );
        let edge = self.recover_incremental_epoch_edge_v1()?;
        ensure!(
            edge.authorization_id() == binding,
            "epoch descendant lineage"
        );
        let guard = self.lock_operation()?;
        let mut c = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_schema(&tx)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let (base, row) = audit_owner(&tx, &self.config, &m)?;
        require_live_edge(self, &row, &edge)?;
        if let Some(p) = load_p(&tx, *request.block_id().as_bytes())? {
            validate_p(
                &p,
                &self.config,
                edge.new_validator_set(),
                edge.new_parameters(),
                base.source.height().get(),
            )?;
            ensure!(
                p.executed()?.request() == &request
                    && header(&p.header)? == *h
                    && p.parent_p == Some(digest),
                "epoch descendant exact retry"
            );
            drop(tx);
            drop(c);
            sync_store_commit_boundary_v0(&self.path)?;
            drop(guard);
            return self.reopen_prepared_incremental_epoch_descendant_v1(p.block, p.digest);
        }
        let resolved = resolve(&tx, &self.config, &m, &base, &edge, &head, digest)?;
        let mut view = execution_view(&tx, &self.config, &base, &resolved)?;
        view.parameters = *edge.new_parameters();
        let complete = execute_complete_native_block_v0(
            &view,
            edge.new_validator_set(),
            edge.new_validator_set().genesis_hash(),
            &request,
        )?;
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
        let replay_parent = view.replay.head.context("epoch replay parent")?;
        let replay = view.replay.append(keys)?;
        drop(view);
        let delta = ni::stage_incremental_plan_v1(
            &tx,
            &namespace(&self.config),
            resolved.state,
            *request.block_id().as_bytes(),
            &plan,
        )?;
        let mut p = P {
            block: *request.block_id().as_bytes(),
            sequence: m
                .durable_sequence
                .checked_add(1)
                .context("epoch native sequence")?,
            status: 0,
            parent: head,
            parent_p: Some(digest),
            artifact: encode_native_executed_block_artifact_v0(&executed)?,
            header: h
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("epoch descendant header: {e:?}"))?,
            storage_artifact: delta.artifact,
            storage_sequence: delta.persist_sequence,
            replay_parent,
            replay_delta: replay.encode()?,
            lifecycle: serde_json::to_vec(&lifecycle)?,
            digest: [0; 32],
            commit_sequence: None,
        };
        p.digest = p.calculate_digest(&self.config);
        validate_p(
            &p,
            &self.config,
            edge.new_validator_set(),
            edge.new_parameters(),
            base.source.height().get(),
        )?;
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
        audit_inventory(&tx, p.sequence, &base)?;
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=?1 WHERE singleton=1 AND durable_sequence=?2 AND schema_version=?3",params![p.sequence.to_be_bytes().as_slice(),m.durable_sequence.to_be_bytes().as_slice(),COMMIT_SCHEMA_VERSION.to_be_bytes().as_slice()])?==1,"epoch descendant native P CAS");
        tx.commit()?;
        drop(c);
        sync_store_commit_boundary_v0(&self.path)?;
        drop(guard);
        self.reopen_prepared_incremental_epoch_descendant_v1(p.block, p.digest)
    }
    pub fn confirm_prepared_incremental_epoch_descendant_v1(
        &self,
        p: &PreparedNativeIncrementalEpochDescendantV1,
    ) -> Result<PreparedNativeIncrementalEpochDescendantV1> {
        ensure!(
            Arc::ptr_eq(&p.owner, &self.owner_affinity),
            "epoch descendant P readback foreign owner"
        );
        let fresh = self.reopen_prepared_incremental_epoch_descendant_v1(p.p.block, p.p.digest)?;
        ensure!(
            fresh.p.sequence == p.p.sequence && fresh.edge == p.edge,
            "epoch descendant readback substituted"
        );
        Ok(fresh)
    }
    pub fn reopen_prepared_incremental_epoch_descendant_v1(
        &self,
        block: [u8; 32],
        expected: [u8; 32],
    ) -> Result<PreparedNativeIncrementalEpochDescendantV1> {
        let edge = self.recover_incremental_epoch_edge_v1()?;
        let _guard = self.lock_operation()?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        ensure_schema(&tx)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let (base, row) = audit_owner(&tx, &self.config, &m)?;
        require_live_edge(self, &row, &edge)?;
        let p = load_p(&tx, block)?.context("epoch descendant P missing")?;
        validate_p(
            &p,
            &self.config,
            edge.new_validator_set(),
            edge.new_parameters(),
            base.source.height().get(),
        )?;
        ensure!(p.digest == expected, "epoch descendant expected P");
        validate_storage_p(&tx, &p)?;
        if p.status == 0 {
            let resolved = resolve(&tx, &self.config, &m, &base, &edge, &p.target()?, p.digest)?;
            let _ = execution_view(&tx, &self.config, &base, &resolved)?;
        } else {
            let state = ni::open_incremental_reader_v1(
                &tx,
                &namespace(&self.config),
                ni::IncrementalParentV1::Prepared(p.storage_artifact),
            )?;
            ensure!(
                state.version() == p.target()?.height().get()
                    && state.root().0 == *p.target()?.state_root().as_bytes(),
                "epoch committed descendant state"
            );
        }
        Ok(PreparedNativeIncrementalEpochDescendantV1 {
            owner: Arc::clone(&self.owner_affinity),
            p,
            edge: row.binding,
        })
    }
}

/// Retire only branches whose complete pending ancestry does not reach the
/// selected committed block. Storage removes children before their pinned roots.
pub(super) fn retire_forks(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    winner: [u8; 32],
) -> Result<()> {
    let committed_first = commit::load(tx)?.map(|r| r.block);
    let mut q=tx.prepare("SELECT block,parent,storage_artifact FROM native_incremental_p_v1 WHERE status=0 UNION ALL SELECT block,parent,storage_artifact FROM native_incremental_epoch_p_v1 LIMIT 257")?;
    let rows = q
        .query_map([], |r| {
            Ok((
                row_blob(r, 0, 32, 32)?,
                row_blob(r, 1, 104, 104)?,
                row_blob(r, 2, 32, 32)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(q);
    ensure!(rows.len() <= 256, "epoch fork inventory capacity");
    let mut parents = BTreeMap::new();
    for (block, parent, artifact) in rows {
        let block = fixed::<32>(block)?;
        ensure!(
            parents
                .insert(
                    block,
                    (
                        *decode_head(&parent)?.block_id().as_bytes(),
                        fixed::<32>(artifact)?
                    )
                )
                .is_none(),
            "epoch duplicate block across kinds"
        );
    }
    let mut retired = Vec::new();
    for (block, (_, artifact)) in &parents {
        if *block == winner || Some(*block) == committed_first {
            continue;
        }
        let mut cursor = *block;
        let mut depth = 0;
        while cursor != winner {
            depth += 1;
            ensure!(depth <= 256, "epoch fork ancestry cycle");
            let Some((parent, _)) = parents.get(&cursor) else {
                break;
            };
            cursor = *parent;
        }
        if cursor != winner {
            retired.push(*artifact);
        }
    }
    ni::retire_incremental_prepared_v1(tx, &namespace(config), &retired)?;
    for artifact in retired {
        tx.execute(
            "DELETE FROM native_incremental_p_v1 WHERE storage_artifact=?1 AND status=0",
            [artifact.as_slice()],
        )?;
        tx.execute(
            "DELETE FROM native_incremental_epoch_p_v1 WHERE storage_artifact=?1",
            [artifact.as_slice()],
        )?;
    }
    Ok(())
}

#[cfg(all(test, feature = "test-fixtures"))]
pub(super) fn assert_worker_parity(
    app: &DurableNativeApplicationV0,
    parent: IncrementalEpochParentV1<'_>,
    request: &NativeBlockPreviewRequestV0,
) {
    let (head, digest, _) = parent.require(app).unwrap();
    let edge = app.recover_incremental_epoch_edge_v1().unwrap();
    let c = open_immutable_connection_v0(&app.path).unwrap();
    let tx = c.unchecked_transaction().unwrap();
    let m = load_metadata_v0(&tx, &app.config).unwrap();
    let (base, _) = audit_owner(&tx, &app.config, &m).unwrap();
    let resolved = resolve(&tx, &app.config, &m, &base, &edge, &head, digest).unwrap();
    let mut view = execution_view(&tx, &app.config, &base, &resolved).unwrap();
    view.parameters = *edge.new_parameters();
    let expected = crate::complete::compute_complete_native_block_with_workers_v0(
        &view,
        edge.new_validator_set(),
        edge.new_validator_set().genesis_hash(),
        request,
        0,
    )
    .unwrap();
    for workers in [1, 2, 4, 8] {
        let actual = crate::complete::compute_complete_native_block_with_workers_v0(
            &view,
            edge.new_validator_set(),
            edge.new_validator_set().genesis_hash(),
            request,
            workers,
        )
        .unwrap();
        assert_eq!(actual.post_state_root, expected.post_state_root);
        assert_eq!(actual.payload_root, expected.payload_root);
        assert_eq!(actual.receipts_root, expected.receipts_root);
        assert_eq!(actual.native_receipts, expected.native_receipts);
    }
    if let Some(raw) = request.transactions().first() {
        let failed = NativeBlockPreviewRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            request.parent().clone(),
            request.height(),
            request.timestamp_ms(),
            request.active_validator_set_id(),
            vec![raw.clone(), raw.clone()],
        )
        .unwrap();
        let failure = crate::complete::compute_complete_native_block_with_workers_v0(
            &view,
            edge.new_validator_set(),
            edge.new_validator_set().genesis_hash(),
            &failed,
            0,
        )
        .err()
        .unwrap()
        .to_string();
        for workers in [1, 2, 4, 8] {
            assert_eq!(
                crate::complete::compute_complete_native_block_with_workers_v0(
                    &view,
                    edge.new_validator_set(),
                    edge.new_validator_set().genesis_hash(),
                    &failed,
                    workers
                )
                .err()
                .unwrap()
                .to_string(),
                failure
            );
        }
    }
}

pub(super) fn commit_digest(
    config: &NativeApplicationConfigV0,
    edge: &EdgeRow,
    r: &commit::Commit,
) -> [u8; 32] {
    hash_domain(
        "trnm.native-application.incremental-epoch-descendant-commit.v1",
        &[
            &config.store_id,
            &edge.checksum,
            &r.block,
            &r.p_digest,
            &r.sequence.to_be_bytes(),
            &head_bytes(&r.head),
            &sha256_v0(&r.proof),
        ],
    )
}
pub(super) fn load_commit(c: &Connection, block: [u8; 32]) -> Result<Option<commit::Commit>> {
    c.query_row("SELECT p_digest,sequence,head,proof,checksum FROM native_incremental_epoch_descendant_commit_v1 WHERE block=?1",[block.as_slice()],|r|Ok((row_blob(r,0,32,32)?,row_blob(r,1,8,8)?,row_blob(r,2,104,104)?,row_blob(r,3,1,MAX_EPOCH_EVIDENCE_BYTES_V1)?,row_blob(r,4,32,32)?))).optional()?.map(|r|Ok(commit::Commit {block,p_digest:fixed(r.0)?,sequence:number(r.1)?,head:decode_head(&r.2)?,proof:r.3,checksum:fixed(r.4)?})).transpose()
}
fn verify_descendant_proof(
    tx: &rusqlite::Transaction<'_>,
    p: &P,
    first: &commit::Commit,
    set: &ValidatorSet,
    params: &ConsensusParametersV0,
    proof: &[u8],
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<()> {
    ensure!(
        proof.len() <= MAX_EPOCH_EVIDENCE_BYTES_V1,
        "descendant proof capacity"
    );
    let parent = if p.parent == first.head {
        header(
            &load_epoch_p(tx, first.block)?
                .context("first commit P missing")?
                .header,
        )?
    } else {
        header(
            &load_p(tx, *p.parent.block_id().as_bytes())?
                .context("descendant parent missing")?
                .header,
        )?
    };
    ensure!(
        parent.id().as_bytes() == p.parent.block_id().as_bytes()
            && parent.height().get() == p.parent.height().get()
            && parent.state_root().as_bytes() == p.parent.state_root().as_bytes(),
        "descendant finality parent"
    );
    let h = header(&p.header)?;
    let expected = trnm_consensus_crypto::FinalityExpectationV0 {
        block_id: h.id(),
        height: h.height(),
        state_root: h.state_root(),
        receipts_root: h.receipts_root(),
        evidence_root: h.evidence_root(),
        parent_id: parent.id(),
        parent_height: parent.height(),
        parent_timestamp_ms: parent.timestamp_ms(),
    };
    let verified = trnm_consensus_crypto::decode_verify_finality_proof_strict_v0(
        trnm_consensus_crypto::POCO_THREE_CHAIN_PROOF_CLASS_V0,
        proof,
        set,
        params,
        expected,
        budget,
    )
    .map_err(|e| anyhow::anyhow!("incremental descendant strict finality: {e}"))?;
    ensure!(
        verified.proof().finalized_block().header() == &h,
        "descendant exact finality header"
    );
    Ok(())
}
fn audit_commit(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    edge: &EdgeRow,
    p: &P,
    first: &commit::Commit,
    set: &ValidatorSet,
    params: &ConsensusParametersV0,
) -> Result<()> {
    audit_commit_with_budget(
        tx,
        config,
        edge,
        p,
        first,
        set,
        params,
        &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
    )
}
#[allow(clippy::too_many_arguments)]
fn audit_commit_with_budget(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    edge: &EdgeRow,
    p: &P,
    first: &commit::Commit,
    set: &ValidatorSet,
    params: &ConsensusParametersV0,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<()> {
    validate_storage_p(tx, p)?;
    let executed = p.executed()?;
    let keys: Vec<_> = executed
        .request()
        .transactions()
        .iter()
        .map(|raw| -> Result<_> {
            let e: trnm_finality_types::SignedCommandEnvelopeV1 = serde_json::from_slice(raw)?;
            Ok([
                replay::command_key(&e.command_id)?,
                replay::nonce_key(&e.signer_id, e.nonce)?,
            ])
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    ensure!(
        ReplayReader::new(tx, Some(p.replay_parent), &[])?
            .append(keys)?
            .encode()?
            == p.replay_delta,
        "descendant committed replay identities"
    );
    let r = load_commit(tx, p.block)?.context("descendant commit proof missing")?;
    ensure!(
        r.p_digest == p.digest
            && r.head == p.target()?
            && Some(r.sequence) == p.commit_sequence
            && r.sequence > p.sequence
            && r.checksum == commit_digest(config, edge, &r),
        "descendant commit record binding"
    );
    verify_descendant_proof(tx, p, first, set, params, &r.proof, budget)
}
impl DurableNativeApplicationV0 {
    pub fn commit_incremental_epoch_descendant_finality_bytes_v1(
        &self,
        prepared: &PreparedNativeIncrementalEpochDescendantV1,
        proof: &[u8],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<CommittedNativeIncrementalEpochExecutionV1> {
        ensure!(
            Arc::ptr_eq(&prepared.owner, &self.owner_affinity),
            "descendant finality foreign owner"
        );
        let edge = self.recover_incremental_epoch_edge_v1()?;
        ensure!(
            edge.authorization_id() == prepared.edge,
            "descendant finality lineage"
        );
        let _guard = self.lock_operation()?;
        let mut c = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_schema(&tx)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let (mut base, row) = audit_owner(&tx, &self.config, &m)?;
        require_live_edge(self, &row, &edge)?;
        let first = commit::load(&tx)?.context("first-new must commit before descendant")?;
        let p = load_p(&tx, prepared.p.block)?.context("descendant finality P missing")?;
        validate_p(
            &p,
            &self.config,
            edge.new_validator_set(),
            edge.new_parameters(),
            base.source.height().get(),
        )?;
        ensure!(
            p.digest == prepared.p.digest && p.sequence == prepared.p.sequence,
            "descendant finality P substituted"
        );
        verify_descendant_proof(
            &tx,
            &p,
            &first,
            edge.new_validator_set(),
            edge.new_parameters(),
            proof,
            budget,
        )?;
        if p.status == 1 {
            let r = load_commit(&tx, p.block)?.context("descendant exact retry missing")?;
            drop(tx);
            drop(c);
            sync_store_commit_boundary_v0(&self.path)?;
            fresh_validate_v0(&self.path, &self.config)?;
            return Ok(CommittedNativeIncrementalEpochExecutionV1 {
                owner: Arc::clone(&self.owner_affinity),
                head: r.head,
                digest: r.p_digest,
                sequence: r.sequence,
            });
        }
        ensure!(
            m.head == p.parent && base.replay == p.replay_parent,
            "descendant exact commit predecessor"
        );
        let executed = p.executed()?;
        let mut keys = Vec::new();
        for raw in executed.request().transactions() {
            let e: trnm_finality_types::SignedCommandEnvelopeV1 = serde_json::from_slice(raw)?;
            keys.push(replay::command_key(&e.command_id)?);
            keys.push(replay::nonce_key(&e.signer_id, e.nonce)?);
        }
        let delta = ReplayReader::new(&tx, Some(base.replay), &[])?.append(keys)?;
        ensure!(
            delta.encode()? == p.replay_delta,
            "descendant exact replay delta"
        );
        let head = p.target()?;
        let before = ni::read_incremental_head_v1(&tx, &namespace(&self.config))?;
        let next = ni::apply_incremental_delta_v1(
            &tx,
            &namespace(&self.config),
            &before,
            &p.storage()?,
            *head.commit_id().as_bytes(),
            edge.new_validator_set().epoch().get(),
        )?;
        replay::apply(&tx, &delta)?;
        let sequence = m
            .durable_sequence
            .checked_add(1)
            .context("descendant native commit sequence")?;
        let mut r = commit::Commit {
            block: p.block,
            p_digest: p.digest,
            sequence,
            head: head.clone(),
            proof: proof.to_vec(),
            checksum: [0; 32],
        };
        r.checksum = commit_digest(&self.config, &row, &r);
        tx.execute(
            "INSERT INTO native_incremental_epoch_descendant_commit_v1 VALUES(?,?,?,?,?,?)",
            params![
                r.block.as_slice(),
                r.p_digest.as_slice(),
                sequence.to_be_bytes().as_slice(),
                head_bytes(&head),
                r.proof,
                r.checksum.as_slice()
            ],
        )?;
        ensure!(tx.execute("UPDATE native_incremental_p_v1 SET status=1,commit_sequence=?1 WHERE block=?2 AND status=0 AND digest=?3",params![sequence.to_be_bytes().as_slice(),p.block.as_slice(),p.digest.as_slice()])?==1,"descendant P commit CAS");
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=?,head_height=?,head_block_id=?,head_state_root=?,head_commit_id=? WHERE singleton=1 AND durable_sequence=? AND head_block_id=? AND head_state_root=? AND head_commit_id=?",params![sequence.to_be_bytes().as_slice(),head.height().get().to_be_bytes().as_slice(),head.block_id().as_bytes().as_slice(),head.state_root().as_bytes().as_slice(),head.commit_id().as_bytes().as_slice(),m.durable_sequence.to_be_bytes().as_slice(),m.head.block_id().as_bytes().as_slice(),m.head.state_root().as_bytes().as_slice(),m.head.commit_id().as_bytes().as_slice()])?==1,"descendant native commit CAS");
        base.commit_sequence = sequence;
        base.storage_checksum = next.checksum;
        base.replay = delta.head;
        base.checksum = base.current_digest(&head);
        tx.execute("UPDATE native_incremental_owner_v1 SET head_commit_sequence=?,storage_checksum=?,replay_version=?,replay_root=?,owner_checksum=? WHERE id=1",params![sequence.to_be_bytes().as_slice(),base.storage_checksum.as_slice(),base.replay.version.to_be_bytes().as_slice(),base.replay.root.as_slice(),base.checksum.as_slice()])?;
        retire_forks(&tx, &self.config, p.block)?;
        audit_inventory(&tx, sequence, &base)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_epoch_descendant_commit_before_commit");
        tx.commit()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_epoch_descendant_commit_after_commit");
        drop(c);
        sync_store_commit_boundary_v0(&self.path)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_epoch_descendant_commit_after_fsync");
        fresh_validate_v0(&self.path, &self.config)?;
        Ok(CommittedNativeIncrementalEpochExecutionV1 {
            owner: Arc::clone(&self.owner_affinity),
            head,
            digest: p.digest,
            sequence,
        })
    }
}
