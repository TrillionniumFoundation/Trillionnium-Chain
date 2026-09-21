use super::*;

/// Comparison facts from an authenticated committed sparse cutoff. This value
/// does not grant execution, migration, finality or signing authority.
pub struct ComputedIncrementalEpochSelectionV1 {
    cutoff_head: ApplicationHeadV0,
    cutoff_p_digest: [u8; 32],
    cutoff_p_sequence: u64,
    cutoff_commit_sequence: u64,
    observed_head: ApplicationHeadV0,
    observed_owner_checksum: [u8; 32],
    edge_binding: [u8; 32],
    computed: crate::poco_application::ComputedPocoNextEpochV1,
}
impl ComputedIncrementalEpochSelectionV1 {
    pub fn cutoff_head(&self) -> &ApplicationHeadV0 {
        &self.cutoff_head
    }
    pub const fn cutoff_p_digest(&self) -> [u8; 32] {
        self.cutoff_p_digest
    }
    pub const fn cutoff_p_sequence(&self) -> u64 {
        self.cutoff_p_sequence
    }
    pub const fn cutoff_commit_sequence(&self) -> u64 {
        self.cutoff_commit_sequence
    }
    pub fn observed_head(&self) -> &ApplicationHeadV0 {
        &self.observed_head
    }
    pub const fn observed_owner_checksum(&self) -> [u8; 32] {
        self.observed_owner_checksum
    }
    pub const fn edge_binding(&self) -> [u8; 32] {
        self.edge_binding
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

impl DurableNativeApplicationV0 {
    /// Derive the next configuration directly from the retained committed JMT
    /// cutoff under schema7's authenticated active configuration.
    pub fn compute_incremental_epoch_selection_v1(
        &self,
        cutoff_height: HeightV0,
    ) -> Result<ComputedIncrementalEpochSelectionV1> {
        let edge = self.recover_incremental_epoch_edge_v1()?;
        let _guard = self.lock_operation()?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        ensure_schema(&tx)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let (base, row) = audit_owner(&tx, &self.config, &m)?;
        require_live_edge(self, &row, &edge)?;
        validate_source_replay(&tx, &self.config, &base)?;
        let set = edge.new_validator_set();
        let parameters = edge.new_parameters();
        let geometry = trnm_consensus_types::EpochGeometryV0::new(set.epoch(), parameters)
            .map_err(|error| anyhow::anyhow!("incremental cutoff geometry: {error:?}"))?;
        let scheduled = geometry
            .checkpoint_height()
            .get()
            .checked_sub(parameters.snapshot_lead_blocks())
            .context("incremental cutoff underflow")?;
        ensure!(
            cutoff_height.get() == scheduled && scheduled <= m.head.height().get(),
            "incremental selection requires the current epoch's committed cutoff"
        );

        // Scan only the already bounded native inventory. Header bytes, rather
        // than an unauthenticated index or the peer's height, choose the P.
        let mut query = tx.prepare("SELECT block,header FROM native_incremental_p_v1 WHERE status=1 ORDER BY block LIMIT ?1")?;
        let mut rows = query.query([i64::try_from(MAX_PREPARED + 1)?])?;
        let mut selected = None;
        let mut count = 0usize;
        while let Some(r) = rows.next()? {
            count += 1;
            ensure!(
                count <= MAX_PREPARED,
                "incremental selection inventory capacity"
            );
            let block = fixed::<32>(row_blob(r, 0, 32, 32)?)?;
            let h = header(&row_blob(r, 1, 1, 4096)?)?;
            ensure!(
                h.id().as_bytes() == &block,
                "incremental selection header identity"
            );
            if h.height().get() == scheduled {
                ensure!(
                    selected.replace(block).is_none(),
                    "duplicate committed cutoff height"
                );
            }
        }
        drop(rows);
        drop(query);
        let p = load_p(
            &tx,
            selected.context("incremental committed cutoff P missing")?,
        )?
        .context("incremental cutoff P disappeared")?;
        validate_p(
            &p,
            &self.config,
            set,
            parameters,
            base.source.height().get(),
        )?;
        let first = commit::load(&tx)?.context("incremental first-new commit missing")?;
        audit_commit(&tx, &self.config, &row, &p, &first, set, parameters)?;
        let cutoff_head = p.target()?;
        let h = header(&p.header)?;
        ensure!(
            p.status == 1 && h.height().get() == scheduled,
            "incremental cutoff is not committed"
        );
        let reader = ni::open_incremental_reader_v1(
            &tx,
            &namespace(&self.config),
            ni::IncrementalParentV1::Committed(p.block),
        )?;
        ensure!(
            reader.version() == scheduled
                && reader.root().0 == *cutoff_head.state_root().as_bytes(),
            "incremental selection committed sparse root differs"
        );
        let mut live = reader.verified_live_values_v1()?;
        let lifecycle = load_validator_lifecycle_from_live_v0(&live, scheduled)?;
        validate_application_validator_projection_v0(set, &lifecycle.active_validators)?;
        let projection = crate::poco_transition::take_and_validate_production_poco_projection_v0(
            scheduled, &mut live,
        )?
        .context("incremental cutoff PoCO namespace missing")?;
        let computed = crate::poco_application::derive_poco_next_epoch_from_cutoff_v1(
            &projection,
            h.state_root(),
            set,
            parameters,
        )?;
        self.confirm_namespace_identity_v1()?;
        Ok(ComputedIncrementalEpochSelectionV1 {
            cutoff_head,
            cutoff_p_digest: p.digest,
            cutoff_p_sequence: p.sequence,
            cutoff_commit_sequence: p
                .commit_sequence
                .context("incremental cutoff commit sequence missing")?,
            observed_head: m.head,
            observed_owner_checksum: base.checksum,
            edge_binding: row.binding,
            computed,
        })
    }
}
