//! Ordinary receiver execution above an independently replayed schema12 base.
//! Retained source rows and the base's original NHR1 identity are immutable.
use super::continuation_storage::{ReplayFinalityRowV1, ReplayPRowV1};
use super::*;
use std::collections::BTreeMap;
use trnm_native_application::decode_native_executed_block_artifact_v0;

#[cfg(all(test, feature = "test-fixtures"))]
std::thread_local! {
    static REPLAY_PROOF_BUDGET_LIMIT_V1: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(all(test, feature = "test-fixtures"))]
struct ReplayProofBudgetLimitGuardV1(Option<usize>);

#[cfg(all(test, feature = "test-fixtures"))]
impl Drop for ReplayProofBudgetLimitGuardV1 {
    fn drop(&mut self) {
        REPLAY_PROOF_BUDGET_LIMIT_V1.with(|limit| limit.set(self.0));
    }
}

/// A durable receiver-local P, not a legacy epoch or signing capability.
/// ```compile_fail
/// use trnm_native_execution_v0::ConfirmedPreparedNativeReplayExecutionV1;
/// fn copy(p: ConfirmedPreparedNativeReplayExecutionV1) { let _ = p.clone(); }
/// ```
/// ```compile_fail
/// use trnm_native_execution_v0::ConfirmedPreparedNativeReplayExecutionV1;
/// fn fabricate() { let _ = ConfirmedPreparedNativeReplayExecutionV1 {}; }
/// ```
#[must_use]
pub struct ConfirmedPreparedNativeReplayExecutionV1 {
    owner: Arc<()>,
    block_id: [u8; 32],
    base_digest: [u8; 32],
    p_digest: [u8; 32],
    p_sequence: u64,
    target_head: ApplicationHeadV0,
}

impl ConfirmedPreparedNativeReplayExecutionV1 {
    pub fn belongs_to_application(&self, application: &DurableNativeApplicationV0) -> bool {
        Arc::ptr_eq(&self.owner, &application.owner_affinity)
    }
    pub const fn block_id(&self) -> [u8; 32] {
        self.block_id
    }
    pub const fn p_digest(&self) -> [u8; 32] {
        self.p_digest
    }
    pub const fn p_sequence(&self) -> u64 {
        self.p_sequence
    }
    pub fn target_head(&self) -> &ApplicationHeadV0 {
        &self.target_head
    }
}

/// Original-proof committed receiver execution, independent of source-local P.
/// ```compile_fail
/// use trnm_native_execution_v0::CommittedNativeReplayExecutionV1;
/// fn copy(p: CommittedNativeReplayExecutionV1) { let _ = p.clone(); }
/// ```
/// ```compile_fail
/// use trnm_native_execution_v0::CommittedNativeReplayExecutionV1;
/// fn fabricate() { let _ = CommittedNativeReplayExecutionV1 {}; }
/// ```
#[must_use]
pub struct CommittedNativeReplayExecutionV1 {
    owner: Arc<()>,
    head: ApplicationHeadV0,
    p_digest: [u8; 32],
    commit_sequence: u64,
}
impl CommittedNativeReplayExecutionV1 {
    pub fn belongs_to_application(&self, application: &DurableNativeApplicationV0) -> bool {
        Arc::ptr_eq(&self.owner, &application.owner_affinity)
    }
    pub fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }
    pub const fn p_digest(&self) -> [u8; 32] {
        self.p_digest
    }
    pub const fn commit_sequence(&self) -> u64 {
        self.commit_sequence
    }
}

pub(super) struct AuditedReplayStoreV1 {
    pub(super) base: install::AuditedReplayBaseV1,
    rows: Vec<ReplayPRowV1>,
    proofs: BTreeMap<[u8; 32], ReplayFinalityRowV1>,
    head: ApplicationHeadV0,
    sequence: u64,
    /// One protocol meter covers every retained post-base proof.  Recreating
    /// this per row would make a cold audit's CPU cost depend on row count.
    proof_budget: Cev0AdmissionBudgetV0,
}

fn execution_context<'a>(
    base: &'a install::AuditedReplayBaseV1,
    config: &'a NativeApplicationConfigV0,
) -> execution::ReplayExecutionContextV1<'a> {
    execution::ReplayExecutionContextV1 {
        config,
        active_set: &base.stored.computed.target_set,
        active_parameters: &base.stored.computed.target_parameters,
        coordinates: &base.coordinates,
    }
}

fn locate_parent(
    base: &install::AuditedReplayBaseV1,
    rows: &[ReplayPRowV1],
    head: &ApplicationHeadV0,
) -> Result<Option<usize>> {
    if head == &base.stored.computed.target_head {
        return Ok(None);
    }
    let mut found = None;
    for (index, row) in rows.iter().enumerate() {
        if &row.target_head()? == head {
            ensure!(found.is_none(), "replay ambiguous parent");
            found = Some(index);
        }
    }
    found
        .map(Some)
        .context("replay parent is not an audited base/P head")
}

fn ensure_parent_identity(row: &ReplayPRowV1, parent: Option<&ReplayPRowV1>) -> Result<()> {
    match parent {
        None => ensure!(
            row.parent_kind == 0 && row.parent_p_digest.is_none(),
            "replay base parent tag"
        ),
        Some(parent) => ensure!(
            row.parent_kind == 1
                && row.parent_p_digest == Some(parent.p_digest)
                && parent.p_sequence < row.p_sequence,
            "replay P parent identity/order"
        ),
    }
    Ok(())
}

fn parent_facts<'a>(
    base: &'a install::AuditedReplayBaseV1,
    rows: &'a [ReplayPRowV1],
    parent: Option<usize>,
    head: &'a ApplicationHeadV0,
) -> execution::ReplayExecutionParentV1<'a> {
    match parent {
        None => execution::ReplayExecutionParentV1 {
            head,
            header: &base.stored.computed.target_header,
            snapshot: &base.stored.computed.snapshot,
            commands: &base.stored.computed.commands,
            nonces: &base.stored.computed.nonces,
            store: Some(&base.store),
        },
        Some(index) => execution::ReplayExecutionParentV1 {
            head,
            header: &rows[index].header,
            snapshot: &rows[index].snapshot,
            commands: &rows[index].commands,
            nonces: &rows[index].nonces,
            store: None,
        },
    }
}

fn header_bytes(header: &BlockHeader) -> Result<Vec<u8>> {
    header
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("replay header encoding: {error:?}"))
}

fn suffix_indices(
    base: &install::AuditedReplayBaseV1,
    rows: &[ReplayPRowV1],
    mut current: Option<usize>,
) -> Result<Vec<usize>> {
    let mut suffix = Vec::new();
    while let Some(index) = current {
        ensure!(
            suffix.len() < 128 && index < rows.len(),
            "replay parent walk bound"
        );
        let row = &rows[index];
        suffix.push(index);
        current = locate_parent(base, &rows[..index], &row.parent_head)?;
        ensure_parent_identity(row, current.map(|parent| &rows[parent]))?;
    }
    Ok(suffix)
}

fn ensure_successor_capacity(
    base: &install::AuditedReplayBaseV1,
    rows: &[ReplayPRowV1],
    parent: Option<usize>,
) -> Result<()> {
    let count = suffix_indices(base, rows, parent)?.len();
    ensure!(
        base.stored
            .history
            .records
            .len()
            .checked_add(count)
            .is_some_and(|count| count < 256),
        "replay successor exceeds finality history capacity"
    );
    Ok(())
}

fn verify_original_finality(
    base: &install::AuditedReplayBaseV1,
    rows: &[ReplayPRowV1],
    target: usize,
    proof: &[u8],
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<()> {
    ensure!(
        !proof.is_empty() && proof.len() <= 8 * 1024 * 1024,
        "replay finality byte bound"
    );
    let suffix = suffix_indices(base, rows, Some(target))?
        .into_iter()
        .map(|index| header_bytes(&rows[index].header))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        base.stored
            .history
            .records
            .len()
            .checked_add(suffix.len())
            .is_some_and(|n| n <= 256),
        "replay finality combined history bound"
    );
    let mut headers = base
        .stored
        .history
        .records
        .iter()
        .map(NativeHistoricalRecordV1::header_cev0)
        .collect::<Vec<_>>();
    headers.extend(suffix.iter().rev().map(Vec::as_slice));
    let activations = base
        .stored
        .history
        .activations
        .iter()
        .map(|activation| activation.as_preimages())
        .collect::<Vec<_>>();
    let verified = verify_historical_header_ancestry_v1(
        &base.source_header,
        &base.source_set,
        &base.source_parameters,
        &headers,
        &activations,
        proof,
        HistoricalAncestryLimitsV1::default(),
        budget,
    )
    .map_err(|error| anyhow::anyhow!("replay original finality: {error}"))?;
    ensure!(
        verified.terminal_header() == &rows[target].header,
        "replay original finality target mismatch"
    );
    Ok(())
}

fn compare_computation(
    row: &ReplayPRowV1,
    computed: &execution::ComputedReplayExecutionV1,
) -> Result<()> {
    ensure!(
        row.artifact == computed.artifact
            && row.snapshot == computed.snapshot
            && row.commands == computed.commands
            && row.nonces == computed.nonces
            && row.lifecycle == computed.lifecycle,
        "replay P differs from independent execution"
    );
    Ok(())
}

/// Complete cold audit, never a recursive public-owner recovery call.
pub(super) fn audit_connection_v1(
    connection: &Connection,
    path: &Path,
    config: &NativeApplicationConfigV0,
) -> Result<AuditedReplayStoreV1> {
    let base = install::audit_base_connection_v1(connection, path, config)?;
    let rows = continuation_storage::load_all_replay_p_ordered_v1(connection)?;
    let mut proofs = BTreeMap::new();
    for proof in continuation_storage::load_all_replay_finality_v1(connection)? {
        proof.verify_digests(base.stored.base_digest)?;
        ensure!(
            proofs.insert(proof.block_id, proof).is_none(),
            "replay duplicate proof"
        );
    }
    let mut sequences = BTreeSet::new();
    let mut committed = Vec::new();
    let protocol_budget = Cev0AdmissionBudgetV0::protocol_v0();
    #[cfg(all(test, feature = "test-fixtures"))]
    let maximum_signature_work = REPLAY_PROOF_BUDGET_LIMIT_V1
        .with(|limit| limit.get())
        .unwrap_or(protocol_budget.maximum_signature_work());
    #[cfg(not(all(test, feature = "test-fixtures")))]
    let maximum_signature_work = protocol_budget.maximum_signature_work();
    let mut proof_budget = Cev0AdmissionBudgetV0::with_limits(
        protocol_budget.maximum_root_bytes(),
        maximum_signature_work,
        protocol_budget.maximum_tc_aggregate_signature_shares(),
    );
    for (index, row) in rows.iter().enumerate() {
        ensure!(
            row.base_digest == base.stored.base_digest
                && row.p_sequence > base.stored.install_sequence
                && sequences.insert(row.p_sequence),
            "replay P base/sequence identity"
        );
        let parent = locate_parent(&base, &rows[..index], &row.parent_head)?;
        ensure_parent_identity(row, parent.map(|i| &rows[i]))?;
        ensure_successor_capacity(&base, &rows[..index], parent)?;
        let artifact = decode_native_executed_block_artifact_v0(&row.artifact)?;
        let context = execution_context(&base, config);
        let parent_state = parent_facts(&base, &rows, parent, &row.parent_head);
        let computed = execution::compute_replay_execution_v1(
            &context,
            &parent_state,
            artifact.request(),
            &row.header,
        )?;
        compare_computation(row, &computed)?;
        if row.status == 1 {
            let sequence = row
                .commit_sequence
                .context("replay committed sequence missing")?;
            ensure!(
                sequence > row.p_sequence && sequences.insert(sequence),
                "replay commit sequence overlap/order"
            );
            ensure!(
                row.commit_id == Some(row.commit_identity()),
                "replay commit identity"
            );
            if let Some(parent) = parent {
                ensure!(
                    rows[parent].status == 1
                        && rows[parent]
                            .commit_sequence
                            .is_some_and(|value| value < sequence),
                    "replay committed child has no earlier committed parent"
                );
            }
            let proof = proofs
                .get(&row.block_id)
                .context("replay committed P lacks original proof")?;
            ensure!(
                proof.p_digest == row.p_digest && proof.commit_sequence == sequence,
                "replay proof/P bijection mismatch"
            );
            verify_original_finality(&base, &rows, index, &proof.proof, &mut proof_budget)?;
            committed.push((sequence, index));
        } else {
            ensure!(
                !proofs.contains_key(&row.block_id),
                "replay pending P has finality row"
            );
        }
    }
    ensure!(proofs.len() == committed.len(), "replay extra finality row");
    committed.sort_unstable();
    let mut head = base.stored.computed.target_head.clone();
    let mut current = None;
    for (_, index) in committed {
        ensure!(
            rows[index].parent_head == head,
            "replay committed rows are not one exact chain"
        );
        head = rows[index].target_head()?;
        current = Some(index);
    }
    let sequence = sequences
        .last()
        .copied()
        .unwrap_or(base.stored.install_sequence);
    ensure!(
        sequence.checked_sub(base.stored.install_sequence) == Some(sequences.len() as u64),
        "replay allocated sequence suffix has a gap"
    );
    let (snapshot, commands, nonces) = match current {
        Some(index) => (
            &rows[index].snapshot,
            &rows[index].commands,
            &rows[index].nonces,
        ),
        None => (
            &base.stored.computed.snapshot,
            &base.stored.computed.commands,
            &base.stored.computed.nonces,
        ),
    };
    let matches: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM native_application_metadata_v0 WHERE singleton=1
          AND schema_version=?1 AND durable_sequence=?2 AND head_height=?3 AND head_block_id=?4
          AND head_state_root=?5 AND head_commit_id=?6 AND authenticated_snapshot=?7
          AND authenticated_snapshot_digest=?8 AND replay_command_ids=?9 AND replay_signer_nonces=?10)",
        params![storage::INSTALLED_SCHEMA_VERSION.to_be_bytes().as_slice(),sequence.to_be_bytes().as_slice(),
            head.height().get().to_be_bytes().as_slice(),head.block_id().as_bytes().as_slice(),
            head.state_root().as_bytes().as_slice(),head.commit_id().as_bytes().as_slice(),
            snapshot,sha256_v0(snapshot).as_slice(),commands,nonces], |row| row.get(0),
    )?;
    ensure!(
        matches,
        "replay current metadata differs from independent committed chain"
    );
    Ok(AuditedReplayStoreV1 {
        base,
        rows,
        proofs,
        head,
        sequence,
        proof_budget,
    })
}

fn audit_path(path: &Path, config: &NativeApplicationConfigV0) -> Result<AuditedReplayStoreV1> {
    reject_sqlite_sidecars_v0(path)?;
    let connection = open_immutable_connection_v0(path)?;
    connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
    let audited = audit_connection_v1(&connection, path, config)?;
    connection.execute_batch("ROLLBACK")?;
    Ok(audited)
}

fn prepared_receipt(
    owner: Arc<()>,
    row: &ReplayPRowV1,
) -> Result<ConfirmedPreparedNativeReplayExecutionV1> {
    Ok(ConfirmedPreparedNativeReplayExecutionV1 {
        owner,
        block_id: row.block_id,
        base_digest: row.base_digest,
        p_digest: row.p_digest,
        p_sequence: row.p_sequence,
        target_head: row.target_head()?,
    })
}

fn committed_receipt(
    owner: Arc<()>,
    row: &ReplayPRowV1,
) -> Result<CommittedNativeReplayExecutionV1> {
    ensure!(
        row.status == 1,
        "replay committed receipt requires committed P"
    );
    Ok(CommittedNativeReplayExecutionV1 {
        owner,
        head: row.target_head()?,
        p_digest: row.p_digest,
        commit_sequence: row
            .commit_sequence
            .context("replay committed receipt sequence")?,
    })
}

fn row_for_token<'a>(
    audited: &'a AuditedReplayStoreV1,
    token: &ConfirmedPreparedNativeReplayExecutionV1,
) -> Result<&'a ReplayPRowV1> {
    let row = audited
        .rows
        .iter()
        .find(|row| row.block_id == token.block_id)
        .context("replay prepared P missing")?;
    ensure!(
        row.base_digest == token.base_digest
            && row.p_digest == token.p_digest
            && row.p_sequence == token.p_sequence
            && row.target_head()? == token.target_head,
        "replay prepared token changed"
    );
    Ok(row)
}

impl DurableNativeApplicationV0 {
    #[cfg(all(test, feature = "test-fixtures"))]
    pub(crate) fn narrow_replay_proof_budget_for_test_v1(
        maximum_signature_work: usize,
    ) -> impl Drop {
        let previous =
            REPLAY_PROOF_BUDGET_LIMIT_V1.with(|limit| limit.replace(Some(maximum_signature_work)));
        ReplayProofBudgetLimitGuardV1(previous)
    }

    /// Current receiver head, after reexecuting retained source/history and P.
    pub fn confirmed_replay_head_v1(&self) -> Result<ApplicationHeadV0> {
        let _guard = self.lock_operation()?;
        let audited = audit_path(&self.path, &self.config)?;
        self.confirm_namespace_identity_v1()?;
        Ok(audited.head)
    }

    pub fn preview_replay_block_v1(
        &self,
        request: &NativeBlockPreviewRequestV0,
    ) -> Result<NativeBlockPreviewV0> {
        let _guard = self.lock_operation()?;
        let audited = audit_path(&self.path, &self.config)?;
        let parent = locate_parent(&audited.base, &audited.rows, request.parent())?;
        ensure_successor_capacity(&audited.base, &audited.rows, parent)?;
        let preview = execution::preview_replay_execution_v1(
            &execution_context(&audited.base, &self.config),
            &parent_facts(&audited.base, &audited.rows, parent, request.parent()),
            request,
        )?;
        self.confirm_namespace_identity_v1()?;
        Ok(preview)
    }

    /// Prepare one regular successor in the separate replay P family.
    #[inline(never)]
    pub fn prepare_replay_execution_v1(
        &self,
        request: &NativeBlockExecutionRequestV0,
        header: &BlockHeader,
    ) -> Result<ConfirmedPreparedNativeReplayExecutionV1> {
        let _guard = self.lock_operation()?;
        reject_sqlite_sidecars_v0(&self.path)?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let audited = audit_connection_v1(&transaction, &self.path, &self.config)?;
        let block_id = *request.block_id().as_bytes();
        let p_digest;
        if let Some(row) = audited.rows.iter().find(|row| row.block_id == block_id) {
            let artifact = decode_native_executed_block_artifact_v0(&row.artifact)?;
            ensure!(
                artifact.request() == request && &row.header == header,
                "replay preparation retry differs from original request/header"
            );
            p_digest = row.p_digest;
            transaction.rollback()?;
        } else {
            ensure!(
                audited.rows.iter().filter(|row| row.status == 0).count() < 8,
                "replay pending P capacity"
            );
            let parent = locate_parent(&audited.base, &audited.rows, request.parent())?;
            ensure_successor_capacity(&audited.base, &audited.rows, parent)?;
            let computed = execution::compute_replay_execution_v1(
                &execution_context(&audited.base, &self.config),
                &parent_facts(&audited.base, &audited.rows, parent, request.parent()),
                request,
                header,
            )?;
            let sequence = audited
                .sequence
                .checked_add(1)
                .context("replay P sequence overflow")?;
            let row = ReplayPRowV1::new_prepared(
                audited.base.stored.base_digest,
                sequence,
                u8::from(parent.is_some()),
                request.parent().clone(),
                parent.map(|index| audited.rows[index].p_digest),
                header.clone(),
                computed,
            )?;
            p_digest = row.p_digest;
            continuation_storage::insert_replay_p_v1(&transaction, &row)?;
            let changed = transaction.execute(
                "UPDATE native_application_metadata_v0 SET durable_sequence=?1
                 WHERE singleton=1 AND schema_version=?2 AND durable_sequence=?3
                 AND head_height=?4 AND head_block_id=?5 AND head_state_root=?6 AND head_commit_id=?7",
                params![sequence.to_be_bytes().as_slice(), storage::INSTALLED_SCHEMA_VERSION.to_be_bytes().as_slice(),
                    audited.sequence.to_be_bytes().as_slice(),audited.head.height().get().to_be_bytes().as_slice(),
                    audited.head.block_id().as_bytes().as_slice(),audited.head.state_root().as_bytes().as_slice(),
                    audited.head.commit_id().as_bytes().as_slice()],
            )?;
            ensure!(changed == 1, "replay preparation metadata CAS lost");
            storage::screen_inputs_v1(&transaction)?;
            #[cfg(test)]
            park_for_sigkill_commit_boundary_v0("replay_prepare_before_commit");
            transaction.commit()?;
        }
        drop(audited);
        drop(connection);
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("replay_prepare_before_fsync");
        sync_store_commit_boundary_named_v0(
            &self.path,
            "replay.prepare_fsync",
            "replay.prepare_directory_fsync",
        )?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("replay_prepare_after_fsync");
        self.confirm_namespace_identity_v1()?;
        let audited = audit_path(&self.path, &self.config)?;
        let row = audited
            .rows
            .iter()
            .find(|row| row.block_id == block_id && row.p_digest == p_digest)
            .context("replay preparation fresh P readback")?;
        ensure!(
            &row.header == header
                && decode_native_executed_block_artifact_v0(&row.artifact)?.request() == request,
            "replay preparation fresh request mismatch"
        );
        self.confirm_namespace_identity_v1()?;
        prepared_receipt(Arc::clone(&self.owner_affinity), row)
    }

    pub fn reopen_prepared_replay_execution_v1(
        &self,
        block_id: [u8; 32],
        expected_p_digest: [u8; 32],
    ) -> Result<ConfirmedPreparedNativeReplayExecutionV1> {
        let _guard = self.lock_operation()?;
        sync_store_commit_boundary_named_v0(
            &self.path,
            "replay.reopen_fsync",
            "replay.reopen_directory_fsync",
        )?;
        let audited = audit_path(&self.path, &self.config)?;
        let row = audited
            .rows
            .iter()
            .find(|row| row.block_id == block_id && row.p_digest == expected_p_digest)
            .context("replay reopen expected P identity")?;
        self.confirm_namespace_identity_v1()?;
        prepared_receipt(Arc::clone(&self.owner_affinity), row)
    }

    #[inline(never)]
    pub fn commit_replay_finality_bytes_v1(
        &self,
        prepared: &ConfirmedPreparedNativeReplayExecutionV1,
        proof: &[u8],
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<CommittedNativeReplayExecutionV1> {
        ensure!(
            prepared.belongs_to_application(self),
            "replay commit foreign owner"
        );
        ensure!(
            !proof.is_empty() && proof.len() <= 8 * 1024 * 1024,
            "replay commit proof bound"
        );
        let _guard = self.lock_operation()?;
        reject_sqlite_sidecars_v0(&self.path)?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let audited = audit_connection_v1(&transaction, &self.path, &self.config)?;
        let row = row_for_token(&audited, prepared)?;
        let index = audited
            .rows
            .iter()
            .position(|entry| entry.block_id == row.block_id)
            .context("replay commit P index")?;
        let caller_before = *budget;
        verify_original_finality(&audited.base, &audited.rows, index, proof, budget)?;
        if row.status == 1 {
            ensure!(
                audited
                    .proofs
                    .get(&row.block_id)
                    .context("replay retry proof missing")?
                    .proof
                    == proof,
                "replay acknowledged proof replacement"
            );
            transaction.rollback()?;
        } else {
            // Verify against the caller's remaining meter, then reserve the
            // measured delta in the same aggregate protocol meter used by
            // cold audits.  The reservation happens before the first write.
            let caller_delta = budget
                .signature_work()
                .checked_sub(caller_before.signature_work())
                .context("replay proof budget accounting")?;
            let mut aggregate_budget = audited.proof_budget;
            if let Err(error) = aggregate_budget.charge_signature_work(caller_delta) {
                return Err(anyhow::anyhow!(
                    "replay aggregate proof work budget: {error:?}"
                ));
            }
            ensure!(
                row.parent_head == audited.head,
                "replay commit requires current exact parent"
            );
            let sequence = audited
                .sequence
                .checked_add(1)
                .context("replay commit sequence overflow")?;
            let head = row.target_head()?;
            continuation_storage::commit_replay_p_and_insert_finality_v1(
                &transaction,
                row.block_id,
                row.p_digest,
                sequence,
                row.commit_identity(),
                proof,
                row.base_digest,
            )?;
            let changed = transaction.execute(
                "UPDATE native_application_metadata_v0 SET durable_sequence=?1,
                 head_height=?2,head_block_id=?3,head_state_root=?4,head_commit_id=?5,
                 authenticated_snapshot=?6,authenticated_snapshot_digest=?7,replay_command_ids=?8,replay_signer_nonces=?9
                 WHERE singleton=1 AND schema_version=?10 AND durable_sequence=?11
                 AND head_height=?12 AND head_block_id=?13 AND head_state_root=?14 AND head_commit_id=?15",
                params![sequence.to_be_bytes().as_slice(),head.height().get().to_be_bytes().as_slice(),
                    head.block_id().as_bytes().as_slice(),head.state_root().as_bytes().as_slice(),head.commit_id().as_bytes().as_slice(),
                    &row.snapshot,row.snapshot_digest.as_slice(),&row.commands,&row.nonces,
                    storage::INSTALLED_SCHEMA_VERSION.to_be_bytes().as_slice(),audited.sequence.to_be_bytes().as_slice(),
                    audited.head.height().get().to_be_bytes().as_slice(),audited.head.block_id().as_bytes().as_slice(),
                    audited.head.state_root().as_bytes().as_slice(),audited.head.commit_id().as_bytes().as_slice()],
            )?;
            ensure!(changed == 1, "replay commit metadata CAS lost");
            storage::screen_inputs_v1(&transaction)?;
            #[cfg(test)]
            park_for_sigkill_commit_boundary_v0("replay_commit_before_commit");
            transaction.commit()?;
        }
        drop(audited);
        drop(connection);
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("replay_commit_before_fsync");
        sync_store_commit_boundary_named_v0(
            &self.path,
            "replay.commit_fsync",
            "replay.commit_directory_fsync",
        )?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("replay_commit_after_fsync");
        self.confirm_namespace_identity_v1()?;
        let audited = audit_path(&self.path, &self.config)?;
        let row = row_for_token(&audited, prepared)?;
        ensure!(
            audited
                .proofs
                .get(&row.block_id)
                .context("replay committed proof readback")?
                .proof
                == proof,
            "replay fresh original proof mismatch"
        );
        self.confirm_namespace_identity_v1()?;
        committed_receipt(Arc::clone(&self.owner_affinity), row)
    }
}
