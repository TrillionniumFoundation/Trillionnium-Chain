//! Read-only retained proof export. These public bytes preserve no authority;
//! a receiver must verify them from its independently configured anchor.
use super::*;
use trnm_consensus_types::EpochActivationEvidenceBytesV0;

const MAX_PATH_BYTES: usize = 64 * 1024 * 1024;

/// Untrusted transport data, not a native application or signer capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeEpochFinalityStepV1 {
    pub header_cev0: Vec<u8>,
    pub consensus_parent_header_cev0: Vec<u8>,
    pub proof: Vec<u8>,
    pub record_digest: [u8; 32],
    pub epoch_evidence: Option<EpochActivationEvidenceBytesV0>,
}

/// Bounded local export; this does not define a consensus aggregate wire format.
/// P/sequence/record digests identify local storage, never remote trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeEpochFinalityPathV1 {
    pub anchor_header_cev0: Vec<u8>,
    pub target_header_cev0: Vec<u8>,
    pub target_schema_version: u64,
    pub target_p_digest: [u8; 32],
    pub target_commit_sequence: u64,
    pub steps: Vec<NativeEpochFinalityStepV1>,
}

enum ProofSource {
    First,
    Ordinary,
    Checkpoint,
}

/// Audit has already established the exact table inventory. Still screen the
/// selected BLOB before allocating it and charge the export's remaining budget.
fn retained_proof(
    connection: &Connection,
    p: &StoredEpochPV1,
    source: ProofSource,
    remaining: usize,
) -> Result<(Vec<u8>, [u8; 32])> {
    let (table, key, column) = match source {
        ProofSource::First => (
            "native_later_epoch_application_finality_v1",
            "block_id",
            "proof",
        ),
        ProofSource::Ordinary => (
            "native_later_epoch_descendant_finality_v1",
            "block_id",
            "proof",
        ),
        ProofSource::Checkpoint => (
            "native_later_epoch_finality_v1",
            "checkpoint_block",
            "checkpoint_finality",
        ),
    };
    // Every interpolated identifier is selected above, never caller supplied.
    let length: i64 = connection.query_row(
        &format!("SELECT CASE WHEN typeof({column})='blob' THEN length({column}) ELSE -1 END FROM {table} WHERE {key}=?1"),
        [p.block_id.as_slice()], |row| row.get(0),
    )?;
    ensure!(
        length > 0
            && length as usize <= trnm_consensus_types::MAX_CEV0_ROOT_BYTES_V0
            && length as usize <= remaining,
        "finality export proof byte budget"
    );
    let (digest, sequence, proof, record) = connection.query_row(
        &format!(
            "SELECT p_digest,commit_sequence,{column},record_digest FROM {table} WHERE {key}=?1"
        ),
        [p.block_id.as_slice()],
        |row| {
            Ok((
                col32(row, "p_digest")?,
                col64(row, "commit_sequence")?,
                row.get::<_, Vec<u8>>(2)?,
                col32(row, "record_digest")?,
            ))
        },
    )?;
    ensure!(
        digest == p.p_digest && Some(sequence) == p.commit_sequence && record != [0; 32],
        "finality export retained P binding"
    );
    Ok((proof, record))
}

fn evidence_bytes(evidence: &EpochActivationEvidenceBytesV0) -> Result<usize> {
    [
        &evidence.old_checkpoint_finality,
        &evidence.next_epoch_commitment,
        &evidence.authorization_kernel,
        &evidence.old_validator_set,
        &evidence.old_consensus_parameters,
        &evidence.new_validator_set,
        &evidence.new_consensus_parameters,
        &evidence.authenticated_checkpoint_parent_header,
    ]
    .iter()
    .try_fold(0usize, |sum, bytes| {
        ensure!(!bytes.is_empty(), "finality export empty evidence root");
        sum.checked_add(bytes.len())
            .context("finality export evidence overflow")
    })
}

impl DurableNativeApplicationV0 {
    /// Export original retained proofs from an exact historical committed
    /// anchor to a later committed target. No migration, installation, signing
    /// or authority restoration takes place. Missing original evidence rejects.
    #[inline(never)]
    pub fn export_epoch_finality_path_v1(
        &self,
        anchor_block: BlockIdV0,
        target_block: BlockIdV0,
    ) -> Result<NativeEpochFinalityPathV1> {
        let _guard = self.lock_operation()?;
        ensure!(anchor_block != target_block, "finality export empty path");
        reject_sqlite_sidecars_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
        live_export::screen_legacy_export_inputs(&connection)?;
        verify_schema_v0(&connection)?;
        ensure!(
            schema_version(&connection)? == LATER_SCHEMA_VERSION,
            "finality export requires explicit schema10"
        );
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let anchor = load_p(&connection, anchor_block.as_bytes())?
            .context("finality export retained anchor missing")?;
        let target = load_p(&connection, target_block.as_bytes())?
            .context("finality export retained target missing")?;
        ensure!(
            anchor.status == 1
                && target.status == 1
                && anchor.target_height > 0
                && anchor.target_height < target.target_height
                && target.target_height <= metadata.head.height().get(),
            "finality export committed anchor/target range"
        );
        let prefix = lineage_resolver::resolve(
            &connection,
            &self.config,
            &decode_lineage(&target.lineage)?,
        )?;
        let mut output = NativeEpochFinalityPathV1 {
            anchor_header_cev0: anchor.header.clone(),
            target_header_cev0: target.header.clone(),
            target_schema_version: LATER_SCHEMA_VERSION,
            target_p_digest: target.p_digest,
            target_commit_sequence: target
                .commit_sequence
                .context("finality export target sequence")?,
            steps: Vec::new(),
        };
        let mut total = output.anchor_header_cev0.len() + output.target_header_cev0.len();
        let mut cursor = target;
        let mut visited = BTreeSet::new();
        while cursor.block_id != *anchor_block.as_bytes() {
            ensure!(
                output.steps.len() < MAX_P_ROWS && visited.insert(cursor.block_id),
                "finality export path count/cycle"
            );
            ensure!(
                cursor.status == 1
                    && cursor.target_height > anchor.target_height
                    && cursor.parent_kind == 1,
                "finality export disconnected historical anchor"
            );
            let parent = load_p(&connection, cursor.parent.block_id().as_bytes())?
                .context("finality export committed parent missing")?;
            ensure!(
                parent.status == 1
                    && parent.target_head()? == cursor.parent
                    && cursor.parent_p_digest == Some(parent.p_digest)
                    && parent
                        .commit_sequence
                        .zip(cursor.commit_sequence)
                        .is_some_and(|(a, b)| a < b),
                "finality export exact application parent mismatch"
            );
            let header = decode_header(&cursor.header)?;
            let (source, consensus_parent, epoch_evidence) = if cursor.artifact_kind == 1 {
                let bindings = decode_lineage(&cursor.lineage)?;
                let entry = prefix
                    .entries
                    .iter()
                    .find(|entry| Some(&entry.binding) == bindings.last())
                    .context("finality export first-new edge missing")?;
                ensure!(
                    entry.later_facts.is_some()
                        && entry.phase == 1
                        && entry.consumed == Some(cursor.block_id)
                        && entry.consumed_sequence == cursor.commit_sequence
                        && entry.checkpoint == parent.target_head()?
                        && entry.checkpoint_p_digest == parent.p_digest
                        && Some(entry.checkpoint_sequence) == parent.commit_sequence
                        && bindings.len() <= prefix.entries.len()
                        && bindings == prefix.bindings()[..bindings.len()]
                        && decode_lineage(&parent.lineage)? == bindings[..bindings.len() - 1]
                        && parent.target_height.checked_add(3) == Some(cursor.target_height),
                    "finality export first-new consumed edge join"
                );
                let activation = &entry.audit.activation;
                let terminal = activation.old_checkpoint_finality().grandchild().header();
                let evidence =
                    (|| -> trnm_consensus_types::Result<EpochActivationEvidenceBytesV0> {
                        Ok(EpochActivationEvidenceBytesV0 {
                            old_checkpoint_finality: activation
                                .old_checkpoint_finality()
                                .try_cev0_bytes()?,
                            next_epoch_commitment: activation
                                .next_epoch_commitment()
                                .try_cev0_bytes()?,
                            authorization_kernel: activation.authorization_cev0_bytes()?,
                            old_validator_set: activation.old_validator_set().try_cev0_bytes()?,
                            old_consensus_parameters: activation
                                .old_consensus_parameters()
                                .canonical_bytes(),
                            new_validator_set: activation.new_validator_set().try_cev0_bytes()?,
                            new_consensus_parameters: activation
                                .new_consensus_parameters()
                                .canonical_bytes(),
                            authenticated_checkpoint_parent_header: activation
                                .authenticated_checkpoint_parent_header()
                                .try_cev0_bytes()?,
                        })
                    })()
                    .map_err(|error| {
                        anyhow::anyhow!("finality export canonical evidence: {error:?}")
                    })?;
                (
                    ProofSource::First,
                    terminal.try_cev0_bytes().map_err(|error| {
                        anyhow::anyhow!("finality export terminal header: {error:?}")
                    })?,
                    Some(evidence),
                )
            } else {
                ensure!(
                    cursor.artifact_kind == 0
                        && cursor.lineage == parent.lineage
                        && cursor.target_set == parent.target_set
                        && cursor.target_parameters == parent.target_parameters
                        && parent.target_height.checked_add(1) == Some(cursor.target_height),
                    "finality export ordinary parent context"
                );
                let source = match header.block_kind() {
                    BlockKind::Regular => {
                        ensure!(
                            descendant_finality::binding(&connection, &cursor)?.is_some(),
                            "finality export legacy ordinary proof unavailable"
                        );
                        ProofSource::Ordinary
                    }
                    BlockKind::EpochCheckpoint => ProofSource::Checkpoint,
                    _ => anyhow::bail!("finality export unsupported application block kind"),
                };
                (source, parent.header.clone(), None)
            };
            let consensus_header = decode_header(&consensus_parent)?;
            ensure!(
                header.parent_id() == consensus_header.id()
                    && cursor.consensus_parent_height == consensus_header.height().get()
                    && cursor.consensus_parent_block == *consensus_header.id().as_bytes(),
                "finality export consensus parent mismatch"
            );
            let evidence_size = epoch_evidence
                .as_ref()
                .map(evidence_bytes)
                .transpose()?
                .unwrap_or(0);
            total = total
                .checked_add(cursor.header.len())
                .and_then(|n| n.checked_add(consensus_parent.len()))
                .and_then(|n| n.checked_add(evidence_size))
                .context("finality export byte overflow")?;
            ensure!(
                total <= MAX_PATH_BYTES,
                "finality export aggregate byte budget"
            );
            let (proof, record_digest) =
                retained_proof(&connection, &cursor, source, MAX_PATH_BYTES - total)?;
            total += proof.len();
            output.steps.push(NativeEpochFinalityStepV1 {
                header_cev0: cursor.header,
                consensus_parent_header_cev0: consensus_parent,
                proof,
                record_digest,
                epoch_evidence,
            });
            cursor = parent;
        }
        ensure!(
            cursor.p_digest == anchor.p_digest && cursor.commit_sequence == anchor.commit_sequence,
            "finality export terminal anchor P mismatch"
        );
        output.steps.reverse();
        connection.execute_batch("ROLLBACK")?;
        let after = live_export::fresh_export_metadata(&self.path, &self.config)?;
        ensure!(
            after == metadata,
            "finality export concurrent metadata change"
        );
        #[cfg(unix)]
        self.confirm_namespace_identity_v1()?;
        Ok(output)
    }
}
