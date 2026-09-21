//! Explicit schema10 -> schema12 installation and independent cold replay.
//! Old source tables and their installed/consumed edge phases remain untouched.
use super::*;

/// Readback of an independently reverified installation. This is not an
/// ordinary execution, checkpoint, signing or finality capability.
/// ```compile_fail
/// use trnm_native_execution_v0::ConfirmedNativeReplayBaseV1;
/// fn copy(base: ConfirmedNativeReplayBaseV1) { let _ = base.clone(); }
/// ```
/// ```compile_fail
/// use trnm_native_execution_v0::ConfirmedNativeReplayBaseV1;
/// fn fabricate() { let _ = ConfirmedNativeReplayBaseV1 {}; }
/// ```
#[must_use]
pub struct ConfirmedNativeReplayBaseV1 {
    owner: Arc<()>,
    source_head: ApplicationHeadV0,
    target_head: ApplicationHeadV0,
    input_digest: [u8; 32],
    base_digest: [u8; 32],
    install_sequence: u64,
}

impl ConfirmedNativeReplayBaseV1 {
    pub fn belongs_to_application(&self, application: &DurableNativeApplicationV0) -> bool {
        Arc::ptr_eq(&self.owner, &application.owner_affinity)
    }
    pub fn source_head(&self) -> &ApplicationHeadV0 {
        &self.source_head
    }
    pub fn target_head(&self) -> &ApplicationHeadV0 {
        &self.target_head
    }
    pub const fn input_digest(&self) -> [u8; 32] {
        self.input_digest
    }
    pub const fn base_digest(&self) -> [u8; 32] {
        self.base_digest
    }
    pub const fn install_sequence(&self) -> u64 {
        self.install_sequence
    }
}

fn base_digest_v1(
    source: &SourcePinV1,
    input: &[u8; 32],
    run: &[u8; 32],
    computed: &execution::ComputedHistoricalReplayV1,
    install_sequence: u64,
) -> [u8; 32] {
    hash_domain(
        "trnm.native.historical-replay-base.v1",
        &[
            &source.digest(),
            input,
            run,
            &install_sequence.to_be_bytes(),
            &head_bytes(&computed.target_head),
            &sha256_v0(&computed.snapshot),
            &sha256_v0(&computed.commands),
            &sha256_v0(&computed.nonces),
            &sha256_v0(&computed.lifecycle),
        ],
    )
}

fn ensure_same_computation_v1(
    actual: &execution::ComputedHistoricalReplayV1,
    expected: &execution::ComputedHistoricalReplayV1,
) -> Result<()> {
    ensure!(
        actual.target_head == expected.target_head
            && actual.target_header == expected.target_header
            && actual.target_set == expected.target_set
            && actual.target_parameters == expected.target_parameters
            && actual.snapshot == expected.snapshot
            && actual.commands == expected.commands
            && actual.nonces == expected.nonces
            && actual.lifecycle == expected.lifecycle
            && actual.application_count == expected.application_count,
        "installed history differs from independent execution"
    );
    Ok(())
}

// Identity remains tied to the configured receiver. Only the mutable head,
// sequence, snapshot/replay bytes and explicit schema change during install.
fn validate_receiver_identity_v1(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
) -> Result<()> {
    let matches: bool = connection.query_row(
        "SELECT COUNT(*)=1 AND COALESCE(SUM(singleton=1 AND store_id=?1 AND chain_id=?2
         AND genesis_hash=?3 AND chain_descriptor_hash=?4 AND signer_policy_commitment=?5
         AND validator_set_id=?6 AND parameters_hash=?7),0)=1 FROM native_application_metadata_v0",
        params![
            config.store_id.as_slice(),
            &config.chain_id,
            config.genesis_hash.as_slice(),
            config.chain_descriptor_hash.as_slice(),
            config.signer_policy_commitment.as_slice(),
            config.validator_set.id().as_bytes().as_slice(),
            config.parameters.hash().as_bytes().as_slice()
        ],
        |row| row.get(0),
    )?;
    ensure!(
        matches,
        "installed receiver identity differs from configuration"
    );
    Ok(())
}

/// Derive the frozen source from the actual retained P inventory. Serialized
/// source fields are comparison values only, never the selector of this head.
fn reconstruct_source_metadata_v1(connection: &Connection) -> Result<MetadataV0> {
    let id = connection.query_row(
        "SELECT block_id FROM native_durable_execution_p_v1 WHERE status=1
         ORDER BY target_height DESC,commit_sequence DESC LIMIT 1",
        [],
        |row| col32(row, "block_id"),
    )?;
    let p = load_p(connection, &id)?.context("retained source current P missing")?;
    let sequence: Vec<u8> = connection.query_row(
        "SELECT MAX(sequence) FROM (
           SELECT p_sequence AS sequence FROM native_durable_execution_p_v0
           UNION ALL SELECT commit_sequence FROM native_durable_execution_p_v0 WHERE commit_sequence IS NOT NULL
           UNION ALL SELECT p_sequence FROM native_durable_execution_p_v1
           UNION ALL SELECT commit_sequence FROM native_durable_execution_p_v1 WHERE commit_sequence IS NOT NULL
         )", [], |row| row.get(0),
    )?;
    Ok(MetadataV0 {
        durable_sequence: decode_u64_v0(&sequence, "historical.source_sequence")?,
        head: p.target_head()?,
        snapshot_digest: p.snapshot_digest,
        snapshot: p.snapshot,
        command_ids: decode_borsh_v0(&p.commands, "historical.source_commands")?,
        signer_nonces: decode_borsh_v0(&p.nonces, "historical.source_nonces")?,
    })
}

fn audit_installed_connection_v1(
    connection: &Connection,
    path: &Path,
    config: &NativeApplicationConfigV0,
) -> Result<storage::StoredHistoricalBaseV1> {
    storage::verify_schema_v1(connection)?;
    storage::screen_inputs_v1(connection)?;
    validate_receiver_identity_v1(connection, config)?;
    let stored = storage::read_base_and_input_v1(connection)?;
    let metadata = reconstruct_source_metadata_v1(connection)?;
    let source = audit_historical_metadata_v1(
        path,
        config,
        connection,
        metadata,
        Some(&stored.source.journal_selection),
    )?;
    ensure!(
        source.pin == stored.source,
        "installed frozen source does not match retained evidence"
    );
    ensure!(
        stored.history.anchor_header_cev0 == source.pin.header,
        "installed history anchor differs from retained source"
    );
    let history_bytes = stored.history.encode_v1()?;
    let (input, run, computed) = replay_source_v1(
        config,
        connection,
        &source,
        &stored.history,
        &history_bytes,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )?;
    ensure!(
        input == stored.input_digest && run == stored.run_digest,
        "installed history input/run identity mismatch"
    );
    ensure_same_computation_v1(&computed, &stored.computed)?;
    ensure!(
        source.pin.sequence.checked_add(1) == Some(stored.install_sequence)
            && stored.base_digest
                == base_digest_v1(
                    &source.pin,
                    &input,
                    &run,
                    &computed,
                    stored.install_sequence
                ),
        "installed base sequence/digest mismatch"
    );
    let matches: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM native_application_metadata_v0 WHERE singleton=1
          AND schema_version=?1 AND durable_sequence=?2 AND head_height=?3 AND head_block_id=?4
          AND head_state_root=?5 AND head_commit_id=?6 AND authenticated_snapshot=?7
          AND authenticated_snapshot_digest=?8 AND replay_command_ids=?9 AND replay_signer_nonces=?10)",
        params![storage::INSTALLED_SCHEMA_VERSION.to_be_bytes().as_slice(), stored.install_sequence.to_be_bytes().as_slice(),
            computed.target_head.height().get().to_be_bytes().as_slice(), computed.target_head.block_id().as_bytes().as_slice(),
            computed.target_head.state_root().as_bytes().as_slice(), computed.target_head.commit_id().as_bytes().as_slice(),
            &computed.snapshot, sha256_v0(&computed.snapshot).as_slice(), &computed.commands, &computed.nonces],
        |row| row.get(0),
    )?;
    ensure!(
        matches,
        "installed current metadata differs from recomputed base"
    );
    Ok(stored)
}

pub(super) fn audit_path_v1(
    path: &Path,
    config: &NativeApplicationConfigV0,
) -> Result<storage::StoredHistoricalBaseV1> {
    reject_sqlite_sidecars_v0(path)?;
    let connection = open_immutable_connection_v0(path)?;
    connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
    let stored = audit_installed_connection_v1(&connection, path, config)?;
    connection.execute_batch("ROLLBACK")?;
    Ok(stored)
}

fn receipt_v1(
    owner: Arc<()>,
    stored: storage::StoredHistoricalBaseV1,
) -> ConfirmedNativeReplayBaseV1 {
    ConfirmedNativeReplayBaseV1 {
        owner,
        source_head: stored.source.head,
        target_head: stored.computed.target_head,
        input_digest: stored.input_digest,
        base_digest: stored.base_digest,
        install_sequence: stored.install_sequence,
    }
}

impl DurableNativeApplicationV0 {
    /// The only schema12 creator. The prepared bytes come from this receiver's
    /// read-only replay; all source facts are checked again under the write lock.
    #[inline(never)]
    pub fn install_historical_replay_base_v1(
        &self,
        prepared: &PreparedNativeReplayBaseV1,
    ) -> Result<ConfirmedNativeReplayBaseV1> {
        ensure!(
            prepared.belongs_to_application(self),
            "historical installation foreign owner"
        );
        let _guard = self.lock_operation()?;
        reject_sqlite_sidecars_v0(&self.path)?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if schema_version(&transaction)? == storage::INSTALLED_SCHEMA_VERSION {
            let stored = audit_installed_connection_v1(&transaction, &self.path, &self.config)?;
            ensure!(
                stored.source == prepared.source
                    && stored.input_digest == prepared.input_digest
                    && stored.run_digest == prepared.run_digest
                    && stored.history.encode_v1()? == prepared.history_bytes,
                "historical installation retry differs from original input"
            );
            ensure_same_computation_v1(&stored.computed, &prepared.computed)?;
            transaction.rollback()?;
        } else {
            let source = self.audit_historical_source_v1(&transaction)?;
            ensure!(
                source.pin == prepared.source,
                "historical installation stale source"
            );
            let sequence = source
                .pin
                .sequence
                .checked_add(1)
                .context("historical installation sequence overflow")?;
            let digest = base_digest_v1(
                &source.pin,
                &prepared.input_digest,
                &prepared.run_digest,
                &prepared.computed,
                sequence,
            );
            for (_, sql) in storage::SCHEMA_V1 {
                transaction.execute_batch(sql)?;
            }
            storage::insert_base_and_input_v1(&transaction, prepared, sequence, digest)?;
            let changed = transaction.execute(
                "UPDATE native_application_metadata_v0 SET schema_version=?1,durable_sequence=?2,
                 head_height=?3,head_block_id=?4,head_state_root=?5,head_commit_id=?6,
                 authenticated_snapshot=?7,authenticated_snapshot_digest=?8,replay_command_ids=?9,replay_signer_nonces=?10
                 WHERE singleton=1 AND schema_version=?11 AND durable_sequence=?12 AND head_height=?13
                 AND head_block_id=?14 AND head_state_root=?15 AND head_commit_id=?16
                 AND authenticated_snapshot_digest=?17 AND replay_command_ids=?18 AND replay_signer_nonces=?19",
                params![storage::INSTALLED_SCHEMA_VERSION.to_be_bytes().as_slice(), sequence.to_be_bytes().as_slice(),
                    prepared.computed.target_head.height().get().to_be_bytes().as_slice(), prepared.computed.target_head.block_id().as_bytes().as_slice(),
                    prepared.computed.target_head.state_root().as_bytes().as_slice(), prepared.computed.target_head.commit_id().as_bytes().as_slice(),
                    &prepared.computed.snapshot, sha256_v0(&prepared.computed.snapshot).as_slice(), &prepared.computed.commands, &prepared.computed.nonces,
                    LATER_SCHEMA_VERSION.to_be_bytes().as_slice(), source.pin.sequence.to_be_bytes().as_slice(),
                    source.pin.head.height().get().to_be_bytes().as_slice(), source.pin.head.block_id().as_bytes().as_slice(),
                    source.pin.head.state_root().as_bytes().as_slice(), source.pin.head.commit_id().as_bytes().as_slice(),
                    source.pin.snapshot_digest.as_slice(), borsh::to_vec(&source.metadata.command_ids)?, borsh::to_vec(&source.metadata.signer_nonces)?],
            )?;
            ensure!(changed == 1, "historical installation metadata CAS lost");
            storage::screen_inputs_v1(&transaction)?;
            #[cfg(test)]
            park_for_sigkill_commit_boundary_v0("historical_install_before_commit");
            transaction.commit()?;
        }
        drop(connection);
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("historical_install_before_fsync");
        sync_store_commit_boundary_named_v0(
            &self.path,
            "historical.install_fsync",
            "historical.install_directory_fsync",
        )?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("historical_install_after_fsync");
        #[cfg(unix)]
        self.confirm_namespace_identity_v1()?;
        let stored = audit_path_v1(&self.path, &self.config)?;
        ensure!(
            stored.source == prepared.source && stored.input_digest == prepared.input_digest,
            "historical installation fresh readback mismatch"
        );
        #[cfg(unix)]
        self.confirm_namespace_identity_v1()?;
        Ok(receipt_v1(Arc::clone(&self.owner_affinity), stored))
    }

    /// Cold readback of an existing installation, requiring independent replay.
    pub fn confirm_historical_replay_base_v1(
        &self,
        expected_input_digest: [u8; 32],
        expected_head: &ApplicationHeadV0,
    ) -> Result<ConfirmedNativeReplayBaseV1> {
        let _guard = self.lock_operation()?;
        // A restarted owner cannot reuse the prior owner's prepared token.
        // Reestablish the fence before acknowledging an uncertain old COMMIT.
        sync_store_commit_boundary_named_v0(
            &self.path,
            "historical.confirm_fsync",
            "historical.confirm_directory_fsync",
        )?;
        let stored = audit_path_v1(&self.path, &self.config)?;
        ensure!(
            stored.input_digest == expected_input_digest
                && &stored.computed.target_head == expected_head,
            "historical installation expected identity mismatch"
        );
        #[cfg(unix)]
        self.confirm_namespace_identity_v1()?;
        Ok(receipt_v1(Arc::clone(&self.owner_affinity), stored))
    }
}
