//! Receiver-owned, read-only historical replay. No import, P or signer permit.
use super::*;
use trnm_consensus_crypto::{
    verify_historical_header_ancestry_v1, HistoricalAncestryLimitsV1, StrictHistoricalHeaderPathV1,
};
use trnm_consensus_types::Cev0AdmissionBudgetV0;

#[path = "historical_replay_execution_v1.rs"]
mod execution;
#[path = "historical_replay_source_v1.rs"]
mod source;

#[derive(Debug, PartialEq, Eq)]
struct SourcePinV1 {
    store_id: [u8; 32],
    signer_policy: [u8; 32],
    head: ApplicationHeadV0,
    sequence: u64,
    p_digest: [u8; 32],
    p_sequence: u64,
    commit_sequence: u64,
    header: Vec<u8>,
    snapshot_digest: [u8; 32],
    commands_digest: [u8; 32],
    nonces_digest: [u8; 32],
    active_set: Vec<u8>,
    active_parameters: Vec<u8>,
    prefix: Vec<u8>,
    inventory_digest: [u8; 32],
}

impl SourcePinV1 {
    fn digest(&self) -> [u8; 32] {
        hash_domain(
            "trnm.native.historical-replay-source-pin.v1",
            &[
                &self.store_id,
                &self.signer_policy,
                &head_bytes(&self.head),
                &self.sequence.to_be_bytes(),
                &self.p_digest,
                &self.p_sequence.to_be_bytes(),
                &self.commit_sequence.to_be_bytes(),
                &self.header,
                &self.snapshot_digest,
                &self.commands_digest,
                &self.nonces_digest,
                &self.active_set,
                &self.active_parameters,
                &self.prefix,
                &self.inventory_digest,
            ],
        )
    }
}

fn head_bytes(head: &ApplicationHeadV0) -> [u8; 104] {
    let mut bytes = [0; 104];
    bytes[..8].copy_from_slice(&head.height().get().to_be_bytes());
    bytes[8..40].copy_from_slice(head.block_id().as_bytes());
    bytes[40..72].copy_from_slice(head.state_root().as_bytes());
    bytes[72..].copy_from_slice(head.commit_id().as_bytes());
    bytes
}

/// An exact, genuine local source. Rechecked when used; no execution permit.
/// ```compile_fail
/// use trnm_native_execution_v0::ConfirmedNativeReplayAnchorV1;
/// fn copy(anchor: ConfirmedNativeReplayAnchorV1) { let _ = anchor.clone(); }
/// ```
/// ```compile_fail
/// use trnm_native_execution_v0::ConfirmedNativeReplayAnchorV1;
/// fn fabricate() { let _ = ConfirmedNativeReplayAnchorV1 {}; }
/// ```
#[must_use]
pub struct ConfirmedNativeReplayAnchorV1 {
    owner: Arc<()>,
    pin: SourcePinV1,
}

impl ConfirmedNativeReplayAnchorV1 {
    pub fn source_head(&self) -> &ApplicationHeadV0 {
        &self.pin.head
    }
    pub const fn source_sequence(&self) -> u64 {
        self.pin.sequence
    }
    pub const fn source_inventory_digest(&self) -> [u8; 32] {
        self.pin.inventory_digest
    }
    pub fn belongs_to_application(&self, app: &DurableNativeApplicationV0) -> bool {
        Arc::ptr_eq(&self.owner, &app.owner_affinity)
    }
}

/// Locally reexecuted history, bound to its exact receiver source and input.
/// It neither installs state nor authorizes a normal execution/commit/signature.
/// ```compile_fail
/// use trnm_native_execution_v0::PreparedNativeReplayBaseV1;
/// fn copy(base: PreparedNativeReplayBaseV1) { let _ = base.clone(); }
/// ```
/// ```compile_fail
/// use trnm_native_execution_v0::PreparedNativeReplayBaseV1;
/// fn fabricate() { let _ = PreparedNativeReplayBaseV1 {}; }
/// ```
#[must_use]
pub struct PreparedNativeReplayBaseV1 {
    owner: Arc<()>,
    source: SourcePinV1,
    history_bytes: Vec<u8>,
    input_digest: [u8; 32],
    run_digest: [u8; 32],
    computed: execution::ComputedHistoricalReplayV1,
}

impl PreparedNativeReplayBaseV1 {
    pub fn belongs_to_application(&self, app: &DurableNativeApplicationV0) -> bool {
        Arc::ptr_eq(&self.owner, &app.owner_affinity)
    }
    pub fn source_head(&self) -> &ApplicationHeadV0 {
        &self.source.head
    }
    pub const fn source_sequence(&self) -> u64 {
        self.source.sequence
    }
    pub const fn source_inventory_digest(&self) -> [u8; 32] {
        self.source.inventory_digest
    }
    pub const fn input_digest(&self) -> [u8; 32] {
        self.input_digest
    }
    pub const fn run_digest(&self) -> [u8; 32] {
        self.run_digest
    }
    pub fn history_byte_len(&self) -> usize {
        self.history_bytes.len()
    }
    pub fn target_head(&self) -> &ApplicationHeadV0 {
        &self.computed.target_head
    }
    pub fn target_header(&self) -> &BlockHeader {
        &self.computed.target_header
    }
    pub fn target_validator_set(&self) -> &ValidatorSet {
        &self.computed.target_set
    }
    pub fn target_parameters(&self) -> &ConsensusParametersV0 {
        &self.computed.target_parameters
    }
    pub const fn application_count(&self) -> usize {
        self.computed.application_count
    }
    pub fn snapshot_digest(&self) -> [u8; 32] {
        sha256_v0(&self.computed.snapshot)
    }
    pub fn command_replay_digest(&self) -> [u8; 32] {
        sha256_v0(&self.computed.commands)
    }
    pub fn nonce_replay_digest(&self) -> [u8; 32] {
        sha256_v0(&self.computed.nonces)
    }
    pub fn lifecycle_digest(&self) -> [u8; 32] {
        sha256_v0(&self.computed.lifecycle)
    }
}

struct AuditedSourceV1 {
    pin: SourcePinV1,
    metadata: MetadataV0,
    header: BlockHeader,
    prefix: lineage_resolver::Prefix,
    set: ValidatorSet,
    parameters: ConsensusParametersV0,
}

impl DurableNativeApplicationV0 {
    fn audit_historical_source_v1(&self, connection: &Connection) -> Result<AuditedSourceV1> {
        source::screen_source_schema_v1(connection)?;
        verify_schema_v0(connection)?;
        ensure!(
            schema_version(connection)? == LATER_SCHEMA_VERSION,
            "historical replay source requires explicit schema10"
        );
        live_export::screen_legacy_export_inputs(connection)?;
        source::screen_source_inventory_v1(connection)?;
        let metadata = load_metadata_v0(connection, &self.config)?;
        let inventory = validate_metadata_v0(connection, &self.config, &metadata)?;
        ensure!(
            inventory.len() <= MAX_P_ROWS
                && inventory
                    .iter()
                    .all(|p| p.target_height <= metadata.head.height().get()),
            "historical source has future prepared or committed execution"
        );
        let p = load_p(connection, metadata.head.block_id().as_bytes())?
            .context("historical source genuine epoch P missing")?;
        ensure!(
            p.status == 1
                && p.target_height > 0
                && p.target_head()? == metadata.head
                && p.snapshot == metadata.snapshot
                && p.snapshot_digest == metadata.snapshot_digest,
            "historical source current committed P mismatch"
        );
        let header = decode_header(&p.header)?;
        let prefix =
            lineage_resolver::resolve(connection, &self.config, &decode_lineage(&p.lineage)?)?;
        let (set, parameters) = prefix.active(&self.config);
        ensure!(
            p.target_set
                == set
                    .try_cev0_bytes()
                    .map_err(|e| anyhow::anyhow!("source set: {e:?}"))?
                && p.target_parameters == parameters.canonical_bytes(),
            "historical source active configuration mismatch"
        );
        let set = set.clone();
        let parameters = *parameters;
        let inventory_digest =
            source::audit_source_inventory_v1(connection, &self.path, &metadata.head)?;
        let pin = SourcePinV1 {
            store_id: self.config.store_id,
            signer_policy: self.config.signer_policy_commitment,
            head: metadata.head.clone(),
            sequence: metadata.durable_sequence,
            p_digest: p.p_digest,
            p_sequence: p.p_sequence,
            commit_sequence: p
                .commit_sequence
                .context("historical source commit sequence")?,
            header: p.header,
            snapshot_digest: metadata.snapshot_digest,
            commands_digest: sha256_v0(&p.commands),
            nonces_digest: sha256_v0(&p.nonces),
            active_set: p.target_set,
            active_parameters: p.target_parameters,
            prefix: p.lineage,
            inventory_digest,
        };
        Ok(AuditedSourceV1 {
            pin,
            metadata,
            header,
            prefix,
            set,
            parameters,
        })
    }

    fn confirm_historical_source_unchanged_v1(&self, source: &SourcePinV1) -> Result<()> {
        reject_sqlite_sidecars_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
        source::screen_source_schema_v1(&connection)?;
        verify_schema_v0(&connection)?;
        ensure!(
            schema_version(&connection)? == LATER_SCHEMA_VERSION,
            "historical source schema changed"
        );
        live_export::screen_legacy_export_inputs(&connection)?;
        source::screen_source_inventory_v1(&connection)?;
        ensure!(
            source::audit_source_inventory_v1(&connection, &self.path, &source.head)?
                == source.inventory_digest,
            "historical source inventory changed"
        );
        connection.execute_batch("ROLLBACK")?;
        #[cfg(unix)]
        self.confirm_namespace_identity_v1()?;
        Ok(())
    }

    /// Pin the current genuine local head; opening/confirming never migrates.
    #[inline(never)]
    pub fn confirm_historical_replay_anchor_v1(
        &self,
        expected_head: &ApplicationHeadV0,
        expected_sequence: u64,
        expected_header: &BlockHeader,
    ) -> Result<ConfirmedNativeReplayAnchorV1> {
        let _guard = self.lock_operation()?;
        reject_sqlite_sidecars_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
        let source = self.audit_historical_source_v1(&connection)?;
        ensure!(
            &source.pin.head == expected_head
                && source.pin.sequence == expected_sequence
                && &source.header == expected_header,
            "historical source expected head/sequence/header mismatch"
        );
        connection.execute_batch("ROLLBACK")?;
        self.confirm_historical_source_unchanged_v1(&source.pin)?;
        Ok(ConfirmedNativeReplayAnchorV1 {
            owner: Arc::clone(&self.owner_affinity),
            pin: source.pin,
        })
    }

    /// Authenticate history and execute every application body against this
    /// receiver's own state and replay sets. The database and journal are read-only.
    #[inline(never)]
    pub fn prepare_historical_replay_base_v1(
        &self,
        anchor: &ConfirmedNativeReplayAnchorV1,
        history: &NativeHistoricalReplayV1,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<PreparedNativeReplayBaseV1> {
        ensure!(
            anchor.belongs_to_application(self),
            "historical anchor foreign owner"
        );
        // Full transport bounds are checked before any retained copy or replay.
        let history_bytes = history.encode_v1()?;
        ensure!(
            history.anchor_header_cev0 == anchor.pin.header,
            "historical input anchor mismatch"
        );
        let input_digest = hash_domain("trnm.native.historical-replay-input.v1", &[&history_bytes]);
        let _guard = self.lock_operation()?;
        reject_sqlite_sidecars_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
        let source = self.audit_historical_source_v1(&connection)?;
        ensure!(source.pin == anchor.pin, "historical anchor stale source");
        let header_bytes = history
            .records
            .iter()
            .map(NativeHistoricalRecordV1::header_cev0)
            .collect::<Vec<_>>();
        let activations = history
            .activations
            .iter()
            .map(|a| a.as_preimages())
            .collect::<Vec<_>>();
        let verified = verify_historical_header_ancestry_v1(
            &source.header,
            &source.set,
            &source.parameters,
            &header_bytes,
            &activations,
            &history.terminal_finality_cev0,
            HistoricalAncestryLimitsV1::default(),
            budget,
        )
        .map_err(|e| anyhow::anyhow!("historical consensus admission: {e}"))?;
        let source_cutoff_headers =
            source_cutoff_headers_v1(&connection, &source.pin.head, &verified)?;
        let contexts = source.prefix.contexts()?;
        let context_refs = contexts
            .iter()
            .map(|context| context.as_ref())
            .collect::<Vec<_>>();
        let coordinates = context_refs
            .iter()
            .map(|context| context.coordinates_v1())
            .collect::<Vec<_>>();
        // The source snapshot/replay was audited above; reuse its exact bytes
        // and the already authenticated prefix without recursively auditing P.
        let store = InMemoryNativeExecutionStoreV0::decode_epoch_snapshot_for_coordinates_v1(
            self.config.chain_id.clone(),
            self.config.signers.clone(),
            source.parameters,
            source.metadata.command_ids,
            source.metadata.signer_nonces,
            &source.metadata.snapshot,
            &coordinates,
        )?;
        let run_digest = hash_domain(
            "trnm.native.historical-replay-run.v1",
            &[
                &source.pin.store_id,
                &source.pin.digest(),
                verified.terminal_header().id().as_bytes(),
                &input_digest,
            ],
        );
        let computed = execution::replay_verified_history_v1(
            store,
            source.pin.head.clone(),
            &source.header,
            &source.set,
            &context_refs,
            &source_cutoff_headers,
            history,
            &verified,
            run_digest,
        )?;
        ensure!(
            computed.snapshot.len() <= MAX_SNAPSHOT_BYTES
                && computed.commands.len() <= MAX_REPLAY_BYTES
                && computed.nonces.len() <= MAX_REPLAY_BYTES
                && computed.lifecycle.len() <= MAX_LIFECYCLE_BYTES,
            "historical computed state resource bound"
        );
        connection.execute_batch("ROLLBACK")?;
        self.confirm_historical_source_unchanged_v1(&source.pin)?;
        Ok(PreparedNativeReplayBaseV1 {
            owner: Arc::clone(&self.owner_affinity),
            source: source.pin,
            history_bytes,
            input_digest,
            run_digest,
            computed,
        })
    }
}

fn source_cutoff_headers_v1(
    connection: &Connection,
    source_head: &ApplicationHeadV0,
    verified: &StrictHistoricalHeaderPathV1,
) -> Result<Vec<BlockHeader>> {
    let heights = verified
        .activations()
        .iter()
        .map(|activation| {
            activation
                .next_epoch_commitment()
                .fields()
                .snapshot_cutoff_height
                .get()
        })
        .filter(|height| *height <= source_head.height().get())
        .collect::<BTreeSet<_>>();
    let mut headers = Vec::with_capacity(heights.len());
    for height in heights {
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM native_durable_execution_p_v1 WHERE target_height=?1 AND status=1",
            [height.to_be_bytes().as_slice()], |row| row.get(0),
        )?;
        ensure!(
            count == 1,
            "historical source cutoff committed header missing/ambiguous"
        );
        let bytes = connection.query_row(
            "SELECT header FROM native_durable_execution_p_v1 WHERE target_height=?1 AND status=1",
            [height.to_be_bytes().as_slice()],
            |row| {
                let value = row.get_ref(0)?;
                match value {
                    rusqlite::types::ValueRef::Blob(bytes)
                        if !bytes.is_empty() && bytes.len() <= MAX_HEADER_BYTES =>
                    {
                        Ok(bytes.to_vec())
                    }
                    _ => Err(rusqlite::Error::InvalidColumnType(
                        0,
                        "historical cutoff header".into(),
                        value.data_type(),
                    )),
                }
            },
        )?;
        headers.push(decode_header(&bytes)?);
    }
    Ok(headers)
}
