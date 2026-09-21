//! First-new execution consumes the installed strict context and actual C18
//! sparse state. Preparation leaves the committed application checkpoint intact.
use super::*;
use crate::epoch_edge::EpochExecutionContextV1;

#[must_use]
pub struct PreparedIncrementalFirstV2 {
    owner: Arc<()>,
    pin: [u8; 32],
    p: EpochP,
}
impl PreparedIncrementalFirstV2 {
    pub(in super::super::super) fn require<'a>(
        &self,
        app: &DurableNativeApplicationV0,
        current: &'a Projection,
    ) -> Result<&'a EpochP> {
        ensure!(
            Arc::ptr_eq(&self.owner, &app.owner_affinity) && self.pin == current.pin,
            "schema11 first parent owner/pin"
        );
        let p = current
            .current
            .epochs
            .get(&self.p.block)
            .context("schema11 first parent absent")?;
        ensure!(
            p.digest == self.p.digest && p.sequence == self.p.sequence && p.edge == self.p.edge,
            "schema11 first parent identity"
        );
        Ok(p)
    }
    pub fn belongs_to_application_at_path(
        &self,
        app: &DurableNativeApplicationV0,
        path: &Path,
    ) -> bool {
        path == app.path()
            && Arc::ptr_eq(&app.owner_affinity, &self.owner)
            && app
                .reopen_incremental_first_v2(self.p.block, self.p.digest)
                .is_ok_and(|fresh| {
                    fresh.pin == self.pin
                        && fresh.p.edge == self.p.edge
                        && fresh.p.sequence == self.p.sequence
                })
    }
    pub fn executed(&self) -> Result<NativeExecutedEpochBlockV1> {
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
    pub const fn edge_binding(&self) -> [u8; 32] {
        self.p.edge
    }
}

fn require_installed(
    app: &DurableNativeApplicationV0,
    current: &Projection,
    edge: &InstalledIncrementalEpochEdgeV2,
) -> Result<()> {
    let pending = current
        .current
        .pending
        .as_ref()
        .context("schema11 installed first context absent")?;
    ensure!(
        Arc::ptr_eq(&app.owner_affinity, &edge.owner)
            && edge.pin == current.pin
            && edge.anchor == current.current.base.anchor
            && edge.generation == current.current.generation
            && edge.record.checksum == pending.record.checksum
            && edge.binding() == pending.binding()
            && edge.record.consumed.is_none(),
        "schema11 installed first owner/prefix/generation"
    );
    Ok(())
}

impl DurableNativeApplicationV0 {
    pub fn preview_incremental_first_epoch_block_v2(
        &self,
        edge: &InstalledIncrementalEpochEdgeV2,
        request: &NativeEpochBlockPreviewRequestV1,
    ) -> Result<NativeBlockPreviewV0> {
        let _guard = self.lock_operation()?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let current = audited_current(self, &tx, &m)?;
        require_installed(self, &current, edge)?;
        edge.validate_request_v1(request)?;
        let parent = ResolvedParent {
            state: ni::IncrementalParentV1::Committed(*m.head.block_id().as_bytes()),
            replay: Vec::new(),
            digest: None,
        };
        let mut view = EpochView(execution_view(
            &tx,
            &self.config,
            &current.current.base,
            &parent,
        )?);
        view.0.parameters = *edge.old_parameters_v1();
        let result =
            crate::complete::preview_complete_epoch_block_with_context_v1(&view, edge, request)?;
        self.confirm_namespace_identity_v1()?;
        Ok(result)
    }

    pub fn execute_incremental_first_epoch_block_v2(
        &self,
        edge: &InstalledIncrementalEpochEdgeV2,
        request: NativeEpochBlockExecutionRequestV1,
        h: &BlockHeader,
    ) -> Result<PreparedIncrementalFirstV2> {
        let mut budget = trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0();
        let guard = self.lock_operation()?;
        let mut c = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let current = audited_current_with_budget(self, &tx, &m, &mut budget)?;
        let owner_work = budget.signature_work();
        require_installed(self, &current, edge)?;
        edge.validate_request_v1(request.preview())?;
        let preview = request.preview();
        let expected = request.expected();
        ensure!(
            h.id().as_bytes() == request.block_id().as_bytes()
                && h.parent_id() == edge.consensus_parent().id()
                && h.height().get() == preview.height().get()
                && h.timestamp_ms() == preview.timestamp_ms()
                && h.block_kind() == trnm_consensus_types::BlockKind::EpochHandoff
                && h.epoch() == edge.new_validator_set().epoch()
                && h.validator_set_id() == edge.new_validator_set().id()
                && h.consensus_parameters_hash() == edge.new_parameters().hash()
                && h.chain_id() == edge.new_validator_set().chain_id()
                && h.genesis_hash() == edge.new_validator_set().genesis_hash()
                && h.payload_root().as_bytes() == expected.payload_root().as_bytes()
                && h.state_root().as_bytes() == expected.post_state_root().as_bytes()
                && h.receipts_root().as_bytes() == expected.receipts_root().as_bytes()
                && h.evidence_root().as_bytes() == expected.evidence_root().as_bytes(),
            "schema11 first complete input header binding"
        );
        if let Some(p) = current.current.epochs.get(request.block_id().as_bytes()) {
            ensure!(
                p.edge == edge.binding()
                    && p.executed()?.request() == &request
                    && header(&p.header)? == *h,
                "schema11 first exact retry"
            );
            require_readback_budget(&budget, owner_work)?;
            let (block, digest) = (p.block, p.digest);
            drop(tx);
            drop(c);
            sync_store_commit_boundary_v0(&self.path)?;
            drop(guard);
            return self.reopen_incremental_first_with_budget_v2(block, digest, &mut budget);
        }
        let parent = ResolvedParent {
            state: ni::IncrementalParentV1::Committed(*m.head.block_id().as_bytes()),
            replay: Vec::new(),
            digest: None,
        };
        let mut view = EpochView(execution_view(
            &tx,
            &self.config,
            &current.current.base,
            &parent,
        )?);
        view.0.parameters = *edge.old_parameters_v1();
        let computed = crate::complete::compute_complete_epoch_native_block_with_context_v1(
            &view,
            edge,
            request.preview(),
        )?;
        let expected = trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
            Hash32V0::new(computed.payload_root),
            StateRootV0::new(computed.post_state_root)?,
            trnm_native_application::ReceiptsRootV0::new(computed.receipts_root)?,
            Hash32V0::new(computed.evidence_root),
        )?;
        let executed =
            NativeExecutedEpochBlockV1::new(request, expected, computed.native_receipts)?;
        let keys = computed
            .replay_identities
            .iter()
            .map(|i| replay::command_key(i.command_id()))
            .chain(
                computed
                    .replay_identities
                    .iter()
                    .map(|i| replay::nonce_key(i.signer_id(), i.nonce())),
            )
            .collect::<Result<Vec<_>>>()?;
        let replay_parent = view.0.replay.head.context("schema11 first replay parent")?;
        let replay = view.0.replay.append(keys)?;
        drop(view);
        let artifact =
            trnm_native_application::encode_native_executed_epoch_block_artifact_v1(&executed)?;
        let header = h
            .try_cev0_bytes()
            .map_err(|e| anyhow::anyhow!("schema11 first header: {e}"))?;
        let replay_delta = replay.encode()?;
        let lifecycle = serde_json::to_vec(&computed.final_lifecycle)?;
        let (count, bytes): (usize, usize) = tx.query_row(
            "SELECT count(*),coalesce(sum(length(artifact)+length(header)+length(replay_delta)+length(lifecycle)),0) FROM native_incremental_epoch_p_v1",
            [], |r| Ok((r.get(0)?,r.get(1)?)),
        )?;
        ensure!(
            artifact.len() <= 16 * 1024 * 1024
                && header.len() <= 4096
                && replay_delta.len() <= MAX_REPLAY_DELTA
                && lifecycle.len() <= 1024 * 1024
                && count < MAX_PREPARED
                && bytes
                    .checked_add(
                        artifact.len() + header.len() + replay_delta.len() + lifecycle.len()
                    )
                    .is_some_and(|n| n <= MAX_P_BYTES),
            "schema11 prospective first P capacity"
        );
        require_readback_budget(&budget, owner_work)?;
        let delta = ni::epoch_candidate_v1::stage_multiple(
            &tx,
            &namespace(&self.config),
            edge,
            *executed.request().block_id().as_bytes(),
            &computed.plan,
        )?;
        let mut p = EpochP {
            block: *executed.request().block_id().as_bytes(),
            sequence: m
                .durable_sequence
                .checked_add(1)
                .context("schema11 first sequence exhausted")?,
            parent: edge.application_parent().clone(),
            edge: edge.binding(),
            artifact,
            header,
            storage_artifact: delta.artifact,
            storage_sequence: delta.persist_sequence,
            replay_parent,
            replay_delta,
            lifecycle,
            digest: [0; 32],
        };
        p.digest = p.digest(&self.config);
        p.validate_context(
            &self.config,
            &EpochPContext {
                parent: edge.application_parent(),
                checkpoint_sequence: edge.record.checkpoint_sequence,
                binding: edge.binding(),
                terminal: edge.consensus_parent(),
                set: edge.new_validator_set(),
                parameters: edge.new_parameters(),
            },
        )?;
        tx.execute(
            "INSERT INTO native_incremental_epoch_p_v1 VALUES(?,?,1,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                p.block.as_slice(),
                p.sequence.to_be_bytes().as_slice(),
                head_bytes(&p.parent),
                p.edge.as_slice(),
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
        ProjectedRow::new(
            2,
            vec![
                blob(p.block),
                blob(p.digest),
                Value::Integer(1),
                blob(prefix(&current.current.owner_prefix())?),
                Value::Null,
                Value::Null,
                Value::Null,
            ],
        )
        .finish(
            &self.config,
            current.current.base.anchor,
            &[],
            &[4, 5, 6],
            &[],
        )?
        .insert(&tx)?;
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=?1 WHERE singleton=1 AND durable_sequence=?2 AND schema_version=?3",params![p.sequence.to_be_bytes().as_slice(),m.durable_sequence.to_be_bytes().as_slice(),SCHEMA_VERSION.to_be_bytes().as_slice()])? == 1,"schema11 first P sequence CAS");
        screen_inventory(&tx, SCHEMA_VERSION)?;
        self.confirm_namespace_identity_v1()?;
        tx.commit()?;
        drop(c);
        sync_store_commit_boundary_v0(&self.path)?;
        drop(guard);
        self.reopen_incremental_first_with_budget_v2(p.block, p.digest, &mut budget)
    }

    pub fn reopen_incremental_first_v2(
        &self,
        block: [u8; 32],
        digest: [u8; 32],
    ) -> Result<PreparedIncrementalFirstV2> {
        self.reopen_incremental_first_with_budget_v2(
            block,
            digest,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
    }
    fn reopen_incremental_first_with_budget_v2(
        &self,
        block: [u8; 32],
        digest: [u8; 32],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<PreparedIncrementalFirstV2> {
        let _guard = self.lock_operation()?;
        sync_store_commit_boundary_v0(&self.path)?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let mut current = audited_current_with_budget(self, &tx, &m, budget)?;
        let p = current
            .current
            .epochs
            .remove(&block)
            .context("schema11 first P absent")?;
        let pending = current
            .current
            .pending
            .as_ref()
            .context("schema11 first edge is not installed")?;
        ensure!(
            p.digest == digest && p.edge == pending.binding(),
            "schema11 first P identity/context"
        );
        self.confirm_namespace_identity_v1()?;
        Ok(PreparedIncrementalFirstV2 {
            owner: Arc::clone(&self.owner_affinity),
            pin: current.pin,
            p,
        })
    }
}
