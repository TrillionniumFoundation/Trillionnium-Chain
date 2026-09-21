//! Owner-derived checkpoint selection and preparation; replay is inert.
use super::*;
use crate::poco_preparation_journal::{
    poco_checkpoint_header_authorization_id_v0, poco_checkpoint_preparation_authorization_id_v0,
    poco_preparation_sidecar_path_v0, PocoCheckpointBoundReplayRecordV0,
    PocoCheckpointPreparationReplayFieldsV0, PocoCheckpointPreparationReplayRecordV0,
    PocoPreparationJournalV0, PocoPreparationTransitionBindingV0,
};
use trnm_consensus_types::{BlockKind, CertifiedHeaderV0};

trait NativeConsensusResult<T> {
    fn native(self) -> Result<T>;
}
impl<T> NativeConsensusResult<T> for trnm_consensus_types::Result<T> {
    fn native(self) -> Result<T> {
        self.map_err(|e| anyhow::anyhow!("schema11 checkpoint consensus: {e}"))
    }
}

pub struct ComputedIncrementalEpochSelectionV2 {
    cutoff_head: ApplicationHeadV0,
    cutoff_digest: [u8; 32],
    computed: crate::poco_application::ComputedPocoNextEpochV1,
}
impl ComputedIncrementalEpochSelectionV2 {
    pub fn cutoff_head(&self) -> &ApplicationHeadV0 {
        &self.cutoff_head
    }
    pub const fn cutoff_p_digest(&self) -> [u8; 32] {
        self.cutoff_digest
    }
    pub fn next_epoch_commitment(&self) -> &trnm_consensus_types::NextEpochCommitmentV0 {
        &self.computed.commitment
    }
    pub fn new_validator_set(&self) -> &ValidatorSet {
        &self.computed.new_validator_set
    }
    pub const fn new_parameters(&self) -> &ConsensusParametersV0 {
        &self.computed.new_parameters
    }
}
#[must_use]
pub struct PreparedIncrementalCheckpointV2 {
    pub(super) prepared: PreparedNativeIncrementalEpochV2,
    preparation_id: [u8; 32],
}
impl PreparedIncrementalCheckpointV2 {
    pub fn header(&self) -> Result<BlockHeader> {
        self.prepared.header()
    }
    pub fn target_head(&self) -> Result<ApplicationHeadV0> {
        self.prepared.target_head()
    }
    pub const fn p_digest(&self) -> [u8; 32] {
        self.prepared.p_digest()
    }
    pub const fn persist_sequence(&self) -> u64 {
        self.prepared.persist_sequence()
    }
    pub const fn preparation_id(&self) -> [u8; 32] {
        self.preparation_id
    }
}
pub(super) struct Selection<'a> {
    pub(super) cutoff: &'a P,
    pub(super) computed: crate::poco_application::ComputedPocoNextEpochV1,
    pub(super) preimage: crate::poco_checkpoint::PocoScheduledCutoffAuthorizationPreimageV0,
}
pub(super) fn selection<'a>(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    ordinary: &'a BTreeMap<[u8; 32], P>,
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> Result<Selection<'a>> {
    let geometry = trnm_consensus_types::EpochGeometryV0::new(set.epoch(), parameters).native()?;
    let height = geometry
        .checkpoint_height()
        .get()
        .checked_sub(parameters.snapshot_lead_blocks())
        .context("schema11 cutoff underflow")?;
    let mut selected = ordinary
        .values()
        .filter(|p| p.status == 1 && p.target().is_ok_and(|h| h.height().get() == height));
    let cutoff = selected
        .next()
        .context("schema11 committed scheduled cutoff missing")?;
    ensure!(selected.next().is_none(), "schema11 cutoff ambiguity");
    let reader = ni::open_incremental_reader_v1(
        tx,
        &namespace(config),
        ni::IncrementalParentV1::Committed(cutoff.block),
    )?;
    let h = header(&cutoff.header)?;
    ensure!(
        reader.version() == height && reader.root().0 == *h.state_root().as_bytes(),
        "schema11 cutoff sparse root"
    );
    let mut live = reader.verified_live_values_v1()?;
    let lifecycle = load_validator_lifecycle_from_live_v0(&live, height)?;
    validate_application_validator_projection_v0(set, &lifecycle.active_validators)?;
    let projection =
        crate::poco_transition::take_and_validate_production_poco_projection_v0(height, &mut live)?
            .context("schema11 cutoff PoCO projection absent")?;
    let computed = crate::poco_application::derive_poco_next_epoch_from_cutoff_v1(
        &projection,
        h.state_root(),
        set,
        parameters,
    )?;
    let manifest = projection.manifest();
    let preimage = crate::poco_checkpoint::PocoScheduledCutoffAuthorizationPreimageV0 {
        genesis_hash: set.genesis_hash(),
        chain_id: set.chain_id(),
        protocol_profile_hash: *parameters.hash().as_bytes(),
        protocol_version: set.protocol_version(),
        epoch: set.epoch(),
        checkpoint_height: geometry.checkpoint_height(),
        cutoff_height: h.height(),
        cutoff_state_root: h.state_root(),
        cutoff_entries_root: manifest.entries_root(),
        cutoff_entry_count: manifest.entry_count(),
        old_validator_set_id: set.id(),
        old_parameters_hash: parameters.hash(),
    };
    preimage.validate_against(set, parameters)?;
    Ok(Selection {
        cutoff,
        computed,
        preimage,
    })
}
#[allow(clippy::too_many_arguments)]
pub(in crate::durable) fn checkpoint_context(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    base: &Owner,
    edge: &EdgeRow,
    ordinary: &BTreeMap<[u8; 32], P>,
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    p: &P,
) -> Result<ProjectedRow> {
    let selected = selection(tx, config, ordinary, set, parameters)?;
    let h = header(&p.header)?;
    ensure!(
        h.block_kind() == BlockKind::EpochCheckpoint
            && h.height() == selected.preimage.checkpoint_height
            && h.next_epoch_commitment_hash() == Some(selected.computed.commitment.id())
            && p.parent.height().get().checked_add(1) == Some(h.height().get()),
        "schema11 checkpoint cutoff/header binding"
    );
    ProjectedRow::new(
        2,
        vec![
            blob(p.block),
            blob(p.digest),
            Value::Integer(2),
            blob(prefix(&[edge.binding])?),
            blob(head_bytes(&selected.cutoff.target()?)),
            blob(selected.cutoff.digest),
            number_value(
                selected
                    .cutoff
                    .commit_sequence
                    .context("schema11 cutoff commit absent")?,
            ),
        ],
    )
    .finish(config, base.anchor, &[], &[4, 5, 6], &[])
}
struct CheckpointPlan {
    replay: PocoCheckpointPreparationReplayRecordV0,
    observation: [u8; 32],
    stable: [u8; 32],
}
#[allow(clippy::too_many_arguments)]
fn checkpoint_plan(
    config: &NativeApplicationConfigV0,
    tx: &rusqlite::Transaction<'_>,
    m: &MetadataV0,
    current: &Projection,
    parent: &P,
    h: &BlockHeader,
    certified: &CertifiedHeaderV0,
    executed: &NativeExecutedBlockV0,
) -> Result<CheckpointPlan> {
    let active = &current.current;
    let set = active.runtime.activation().new_validator_set();
    let parameters = active.runtime.activation().new_consensus_parameters();
    let selected = selection(tx, config, &active.ordinary, set, parameters)?;
    let parent_header = header(&parent.header)?;
    ensure!(
        certified.header() == &parent_header
            && h.block_kind() == BlockKind::EpochCheckpoint
            && h.height() == selected.preimage.checkpoint_height
            && h.parent_id() == parent_header.id()
            && h.next_epoch_commitment_hash() == Some(selected.computed.commitment.id()),
        "schema11 planned checkpoint/parent/selection"
    );
    ensure_finalized_header_binding_v0(h, executed.request())?;
    validate_native_finalized_execution_receipts_v0(executed)?;
    let old_set = set.try_cev0_bytes().native()?;
    let old_parameters = parameters.canonical_bytes();
    let commitment = selected.computed.commitment.try_cev0_bytes().native()?;
    let new_set = selected
        .computed
        .new_validator_set
        .try_cev0_bytes()
        .native()?;
    let new_parameters = selected.computed.new_parameters.canonical_bytes();
    let preimage = selected.preimage.canonical_bytes()?;
    let cutoff_proof = load_ordinary_records(tx)?
        .into_iter()
        .find(|r| r.block == selected.cutoff.block)
        .context("schema11 cutoff proof missing")?
        .proof;
    let stable = hash_domain(
        "trnm.native-application.incremental-checkpoint-commitment.v2",
        &[
            &config.store_id,
            &active.base.anchor,
            &current.pin,
            &prefix(&[active.edge.binding])?,
            &head_bytes(&selected.cutoff.target()?),
            &selected.cutoff.digest,
            &selected.cutoff.sequence.to_be_bytes(),
            &selected
                .cutoff
                .commit_sequence
                .context("schema11 cutoff commit missing")?
                .to_be_bytes(),
            &sha256_v0(&cutoff_proof),
            &sha256_v0(&preimage),
            &sha256_v0(&old_set),
            &sha256_v0(&old_parameters),
            &sha256_v0(&commitment),
            &sha256_v0(&new_set),
            &sha256_v0(&new_parameters),
        ],
    );
    let exact = crate::poco_checkpoint::native_execution_from_receipts_v0(
        executed.request().transactions(),
        executed.receipts(),
    )?;
    let payload = exact.application_payload().try_cev0_bytes().native()?;
    let receipts = exact.execution_receipts().try_cev0_bytes().native()?;
    let execution_id = crate::poco_checkpoint::native_checkpoint_execution_authorization_id_v0(
        parent_header.height(),
        parent_header.state_root(),
        h.height(),
        h.state_root(),
        h.payload_root(),
        h.receipts_root(),
        &payload,
        &receipts,
    );
    let fields = PocoCheckpointPreparationReplayFieldsV0 {
        genesis_hash: h.genesis_hash(),
        chain_id: h.chain_id(),
        protocol_version: h.protocol_version(),
        epoch: h.epoch(),
        view: h.view(),
        height: h.height(),
        parent_id: h.parent_id(),
        proposer_id: h.proposer_id(),
        validator_set_id: h.validator_set_id(),
        consensus_parameters_hash: h.consensus_parameters_hash(),
        payload_root: h.payload_root(),
        state_root: h.state_root(),
        receipts_root: h.receipts_root(),
        evidence_root: h.evidence_root(),
        timestamp_ms: h.timestamp_ms(),
        next_epoch_commitment_hash: selected.computed.commitment.id(),
        transaction_count: u32::try_from(executed.request().transactions().len())?,
        evidence_count: 0,
    };
    let certified_bytes = certified.try_cev0_bytes().native()?;
    let preparation_id = poco_checkpoint_preparation_authorization_id_v0(
        stable,
        execution_id,
        &certified_bytes,
        &fields,
    );
    let binding = PocoPreparationTransitionBindingV0 {
        genesis_hash: set.genesis_hash(),
        chain_id: set.chain_id(),
        protocol_version: set.protocol_version(),
        old_epoch: set.epoch(),
        checkpoint_height: h.height(),
        cutoff_height: selected.preimage.cutoff_height,
        cutoff_state_root: selected.preimage.cutoff_state_root,
        cutoff_entries_root: selected.preimage.cutoff_entries_root,
        cutoff_entry_count: selected.preimage.cutoff_entry_count,
        old_validator_set_id: set.id(),
        old_parameters_hash: parameters.hash(),
        new_validator_set_id: selected.computed.new_validator_set.id(),
        new_parameters_hash: selected.computed.new_parameters.hash(),
        commitment_hash: selected.computed.commitment.id(),
        scheduled_cutoff_authorization_id: selected.preimage.authorization_id()?,
        commitment_authorization_id: stable,
        scheduled_cutoff_canonical_bytes: preimage,
        old_validator_set_cev0: old_set,
        old_parameters_cev0: old_parameters,
        new_validator_set_cev0: new_set,
        new_parameters_cev0: new_parameters,
        commitment_cev0: commitment,
    };
    let observation = observation(stable, m, active.generation, parent, h, &certified_bytes)?;
    let replay = PocoCheckpointPreparationReplayRecordV0::new(
        binding,
        fields,
        preparation_id,
        execution_id,
        parent.header.clone(),
        certified_bytes,
        payload,
        Vec::new(),
        exact
            .execution_receipts()
            .receipts()
            .iter()
            .map(|r| r.try_cev0_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .native()?,
    )?;
    Ok(CheckpointPlan {
        replay,
        observation,
        stable,
    })
}
fn observation(
    stable: [u8; 32],
    m: &MetadataV0,
    generation: u64,
    parent: &P,
    h: &BlockHeader,
    certified_bytes: &[u8],
) -> Result<[u8; 32]> {
    let optional_sequence = parent
        .commit_sequence
        .map_or_else(|| vec![0], |n| [vec![1], n.to_be_bytes().to_vec()].concat());
    let observation = hash_domain(
        "trnm.native-application.incremental-checkpoint-observation.v2",
        &[
            &stable,
            &head_bytes(&m.head),
            &m.durable_sequence.to_be_bytes(),
            &generation.to_be_bytes(),
            &head_bytes(&parent.target()?),
            &parent.digest,
            &parent.sequence.to_be_bytes(),
            &optional_sequence,
            &sha256_v0(&h.try_cev0_bytes().native()?),
            &sha256_v0(certified_bytes),
        ],
    );
    Ok(observation)
}
// Native cold audit reads complete original replay bytes; no reconstructed
// reservation or inert identifier can replace the cryptographic parent join.
pub(in crate::durable) fn audit_sidecars(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    m: &MetadataV0,
    current: &Projection,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<()> {
    let checkpoints = current
        .current
        .ordinary
        .values()
        .filter(|p| header(&p.header).is_ok_and(|h| h.block_kind() == BlockKind::EpochCheckpoint))
        .collect::<Vec<_>>();
    if checkpoints.is_empty() {
        return Ok(());
    }
    let path = Path::new(tx.path().context("schema11 native path absent")?);
    let journal = PocoPreparationJournalV0::open_existing(poco_preparation_sidecar_path_v0(path))?;
    for p in checkpoints {
        let original = journal.retained_bound_replay_v1(&p.header)?;
        let parent = current
            .current
            .ordinary
            .get(p.parent.block_id().as_bytes())
            .context("schema11 sidecar actual parent missing")?;
        let grandparent = current
            .current
            .ordinary
            .get(parent.parent.block_id().as_bytes())
            .context("schema11 sidecar parent ancestry missing")?;
        let certified = current
            .current
            .runtime
            .decode_verify_certified_header_v1(
                original.certified_checkpoint_parent_bytes_v1(),
                &header(&grandparent.header)?,
                budget,
            )
            .native()?;
        let planned = checkpoint_plan(
            config,
            tx,
            m,
            current,
            parent,
            &header(&p.header)?,
            &certified,
            &p.executed()?,
        )?;
        ensure!(
            original == planned.replay,
            "schema11 sidecar complete original replay differs"
        );
    }
    Ok(())
}

impl DurableNativeApplicationV0 {
    pub fn compute_incremental_epoch_selection_v2(
        &self,
    ) -> Result<ComputedIncrementalEpochSelectionV2> {
        let _guard = self.lock_operation()?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let current = audited_current(self, &tx, &m)?;
        let selection = selection(
            &tx,
            &self.config,
            &current.current.ordinary,
            current.current.runtime.activation().new_validator_set(),
            current
                .current
                .runtime
                .activation()
                .new_consensus_parameters(),
        )?;
        self.confirm_namespace_identity_v1()?;
        Ok(ComputedIncrementalEpochSelectionV2 {
            cutoff_head: selection.cutoff.target()?,
            cutoff_digest: selection.cutoff.digest,
            computed: selection.computed,
        })
    }
    /// Re-executes the exact body and re-verifies its certified parent before
    /// reserving the persistent checkpoint tuple. Recovery calls this same path.
    pub fn prepare_incremental_epoch_checkpoint_v2(
        &self,
        parent: &PreparedNativeIncrementalEpochV2,
        request: NativeBlockExecutionRequestV0,
        h: &BlockHeader,
        certified_parent: &CertifiedHeaderV0,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<PreparedIncrementalCheckpointV2> {
        let starting_work = budget.signature_work();
        let guard = self.lock_operation()?;
        let mut c = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let current = audited_current_with_budget(self, &tx, &m, budget)?;
        let owner_work = budget.signature_work() - starting_work;
        require_prepared(self, parent, &current)?;
        let actual = current
            .current
            .ordinary
            .get(&parent.p.block)
            .context("schema11 checkpoint parent missing")?;
        ensure!(
            request.parent() == &actual.target()?,
            "schema11 checkpoint actual application parent"
        );
        let resolved = resolve(&current.current, &m, actual)?;
        let set = current.current.runtime.activation().new_validator_set();
        let parameters = current
            .current
            .runtime
            .activation()
            .new_consensus_parameters();
        let mut view = execution_view(&tx, &self.config, &current.current.base, &resolved)?;
        view.parameters = *parameters;
        let complete = execute_complete_native_block_v0(&view, set, set.genesis_hash(), &request)?;
        let (executed, plan, identities, lifecycle) = complete.into_parts();
        // No sidecar open/reservation or native staging precedes this full plan.
        let grandparent = current
            .current
            .ordinary
            .get(actual.parent.block_id().as_bytes())
            .context("schema11 checkpoint parent ancestry missing")?;
        current
            .current
            .runtime
            .verify_certified_header_v1(certified_parent, &header(&grandparent.header)?, budget)
            .native()?;
        let planned = checkpoint_plan(
            &self.config,
            &tx,
            &m,
            &current,
            actual,
            h,
            certified_parent,
            &executed,
        )?;
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
            .context("schema11 checkpoint replay parent")?;
        let replay = view.replay.append(keys)?;
        drop(view);
        let existing = load_p(&tx, *request.block_id().as_bytes())?;
        require_readback_budget(
            budget,
            if existing.is_some() {
                owner_work
            } else {
                budget.signature_work() - starting_work
            },
        )?;
        if let Some(p) = &existing {
            ensure!(
                p.parent_p == Some(actual.digest)
                    && p.header == h.try_cev0_bytes().native()?
                    && p.artifact == encode_native_executed_block_artifact_v0(&executed)?
                    && p.replay_delta == replay.encode()?,
                "schema11 checkpoint exact persisted retry"
            );
        }
        if existing.is_none() {
            reserve_p_capacity(
                &tx,
                &encode_native_executed_block_artifact_v0(&executed)?,
                &h.try_cev0_bytes().native()?,
                &replay.encode()?,
                &serde_json::to_vec(&lifecycle)?,
            )?;
        }
        // The writer lock and IMMEDIATE native transaction prohibit owner
        // advance. Still rejoin the exact observation before crossing owners.
        let observed = load_metadata_v0(&tx, &self.config)?;
        ensure!(
            observed.head == m.head
                && observed.durable_sequence == m.durable_sequence
                && load_p(&tx, actual.block)?
                    .is_some_and(|p| p.digest == actual.digest
                        && p.commit_sequence == actual.commit_sequence)
                && number(tx.query_row(
                    "SELECT generation FROM native_incremental_epoch_owner_v2 WHERE id=1",
                    [],
                    |r| row_blob(r, 0, 8, 8)
                )?)? == current.current.generation
                && *self
                    .incremental_migration_pin
                    .lock()
                    .map_err(|_| anyhow::anyhow!("schema11 checkpoint pin lock"))?
                    == Some(current.pin)
                && observation(
                    planned.stable,
                    &observed,
                    current.current.generation,
                    &load_p(&tx, actual.block)?.context("schema11 parent observation missing")?,
                    h,
                    &certified_parent.try_cev0_bytes().native()?
                )? == planned.observation,
            "schema11 checkpoint observation raced"
        );
        self.confirm_namespace_identity_v1()?;
        let journal =
            PocoPreparationJournalV0::open_existing(poco_preparation_sidecar_path_v0(&self.path))?;
        let header_bytes = h.try_cev0_bytes().native()?;
        if existing.is_some() {
            journal.require_retained_bound(planned.replay.preparation_id(), &header_bytes)?;
        }
        let reservation = journal.reserve(&planned.replay)?;
        let bound = PocoCheckpointBoundReplayRecordV0::new(
            header_bytes.clone(),
            h.id(),
            poco_checkpoint_header_authorization_id_v0(
                planned.replay.preparation_id(),
                &header_bytes,
                h.id(),
            ),
        )?;
        journal.bind(&reservation, &bound)?;
        self.confirm_namespace_identity_v1()?;
        let p = if let Some(p) = existing {
            p
        } else {
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
                    .context("schema11 checkpoint persist exhausted")?,
                status: 0,
                parent: actual.target()?,
                parent_p: Some(actual.digest),
                artifact: encode_native_executed_block_artifact_v0(&executed)?,
                header: header_bytes.clone(),
                storage_artifact: delta.artifact,
                storage_sequence: delta.persist_sequence,
                replay_parent,
                replay_delta: replay.encode()?,
                lifecycle: serde_json::to_vec(&lifecycle)?,
                digest: [0; 32],
                commit_sequence: None,
            };
            p.digest = p.calculate_digest(&self.config);
            p.validate_context_kind(&self.config, set, parameters, BlockKind::EpochCheckpoint)?;
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
            checkpoint_context(
                &tx,
                &self.config,
                &current.current.base,
                &current.current.edge,
                &current.current.ordinary,
                set,
                parameters,
                &p,
            )?
            .insert(&tx)?;
            ensure!(tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=?1 WHERE singleton=1 AND durable_sequence=?2 AND schema_version=?3",params![p.sequence.to_be_bytes().as_slice(),m.durable_sequence.to_be_bytes().as_slice(),SCHEMA_VERSION.to_be_bytes().as_slice()])?==1,"schema11 checkpoint persist CAS");
            p
        };
        screen_inventory(&tx, SCHEMA_VERSION)?;
        self.confirm_namespace_identity_v1()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_checkpoint_before_commit");
        tx.commit()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_checkpoint_after_commit");
        drop(c);
        sync_store_commit_boundary_v0(&self.path)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_checkpoint_after_fsync");
        self.confirm_namespace_identity_v1()?;
        let fresh = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&fresh)?;
        let fresh_tx = fresh.unchecked_transaction()?;
        let fresh_m = load_metadata_v0(&fresh_tx, &self.config)?;
        let fresh_owner = audited_current_with_budget(self, &fresh_tx, &fresh_m, budget)?;
        let fresh_p = load_p(&fresh_tx, p.block)?.context("schema11 checkpoint fresh P missing")?;
        ensure!(
            fresh_owner.current.generation == current.current.generation
                && fresh_m.head == m.head
                && fresh_m.durable_sequence == m.durable_sequence.max(p.sequence)
                && fresh_p.digest == p.digest
                && fresh_p.header == header_bytes
                && fresh_p.sequence == p.sequence
                && fresh_p.parent_p == Some(actual.digest),
            "schema11 checkpoint fresh observation differs"
        );
        journal.require_retained_bound(planned.replay.preparation_id(), &header_bytes)?;
        self.confirm_namespace_identity_v1()?;
        let prepared = PreparedNativeIncrementalEpochV2 {
            owner: Arc::clone(&self.owner_affinity),
            p: fresh_p,
            pin: fresh_owner.pin,
            edge: fresh_owner.current.edge.binding,
        };
        drop(guard);
        Ok(PreparedIncrementalCheckpointV2 {
            prepared,
            preparation_id: planned.replay.preparation_id(),
        })
    }
}
