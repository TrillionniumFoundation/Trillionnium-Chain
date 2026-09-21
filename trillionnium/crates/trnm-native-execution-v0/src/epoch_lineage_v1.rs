//! Bounded authenticated mixed epoch prefixes. A selected-row verifier only
//! consumes prior authenticated trust; it never resolves another prefix or
//! invokes P/inventory/public owner recovery.
use super::*;

type Audit = crate::epoch_recovery::AuditedEpochEvidenceV1;

pub(super) struct Entry {
    pub(super) binding: [u8; 32],
    pub(super) checkpoint: ApplicationHeadV0,
    pub(super) checkpoint_p_digest: [u8; 32],
    pub(super) checkpoint_sequence: u64,
    pub(super) phase: i64,
    pub(super) consumed: Option<[u8; 32]>,
    pub(super) consumed_sequence: Option<u64>,
    pub(super) audit: Box<Audit>,
    pub(super) later_facts: Option<LaterSuccessorFactsV1>,
    // Preserve the legacy preparation-journal check at owner recovery/execute
    // boundaries without calling public recovery from the prefix walk.
    pub(super) legacy_preparation: Option<([u8; 32], Vec<u8>)>,
}

impl Entry {
    pub(super) fn context(&self) -> Result<LaterEpochExecutionContextV1> {
        let activation = &self.audit.activation;
        Ok(LaterEpochExecutionContextV1 {
            application_parent: self.checkpoint.clone(),
            consensus_parent: activation
                .old_checkpoint_finality()
                .grandchild()
                .header()
                .clone(),
            old_validator_set: activation.old_validator_set().clone(),
            old_parameters: *activation.old_consensus_parameters(),
            new_validator_set: activation.new_validator_set().clone(),
            new_parameters: *activation.new_consensus_parameters(),
            coordinates: self.audit.coordinates(self.binding)?,
            authorization_id: self.binding,
        })
    }
}

pub(super) struct Prefix {
    pub(super) entries: Vec<Entry>,
}

impl Prefix {
    pub(super) fn bindings(&self) -> Vec<[u8; 32]> {
        self.entries.iter().map(|entry| entry.binding).collect()
    }

    pub(super) fn active<'a>(
        &'a self,
        config: &'a NativeApplicationConfigV0,
    ) -> (&'a ValidatorSet, &'a ConsensusParametersV0) {
        match self.entries.last() {
            Some(entry) => (
                entry.audit.activation.new_validator_set(),
                entry.audit.activation.new_consensus_parameters(),
            ),
            None => (&config.validator_set, &config.parameters),
        }
    }

    pub(super) fn into_audits(self) -> Vec<([u8; 32], Audit)> {
        self.entries
            .into_iter()
            .map(|entry| (entry.binding, *entry.audit))
            .collect()
    }

    pub(super) fn contexts(&self) -> Result<Vec<Box<dyn EpochExecutionContextV1>>> {
        self.entries
            .iter()
            .map(|entry| Ok(Box::new(entry.context()?) as Box<dyn EpochExecutionContextV1>))
            .collect()
    }
}

#[inline(never)]
pub(super) fn resolve(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    ids: &[[u8; 32]],
) -> Result<Prefix> {
    resolve_with_read_policy(connection, config, ids, EpochReadPolicyV1::Physical)
}

pub(super) fn resolve_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    ids: &[[u8; 32]],
    policy: EpochReadPolicyV1<'_>,
) -> Result<Prefix> {
    ensure!(ids.len() <= MAX_EDGES, "epoch lineage count budget");
    let legacy = load_edges(connection, config)?;
    let has_later = has_later_schema(policy.schema(connection)?);
    let mut seen = BTreeSet::new();
    let mut prefix = Prefix {
        entries: Vec::with_capacity(ids.len()),
    };
    for binding in ids {
        ensure!(
            *binding != [0; 32] && seen.insert(*binding),
            "epoch lineage zero or duplicate binding"
        );
        let old = legacy.iter().find(|edge| edge.binding == *binding);
        let later: bool = if has_later {
            connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM native_later_epoch_edge_v1 WHERE successor_binding=?1)",
                [binding.as_slice()], |row| row.get(0),
            )?
        } else {
            false
        };
        ensure!(
            old.is_some() != later,
            "epoch lineage ownership missing or ambiguous"
        );
        let entry = match old {
            Some(edge) => verify_legacy(connection, config, edge, &prefix)?,
            None => verify_later(connection, config, *binding, &prefix, policy)?,
        };
        let coordinates = entry.audit.coordinates(*binding)?;
        if let Some(previous) = prefix.entries.last() {
            ensure!(
                previous.phase == 1
                    && coordinates.checkpoint_version
                        > previous.audit.coordinates(previous.binding)?.first_version,
                "epoch lineage consumed prefix or height order"
            );
        }
        validate_consumption(connection, config, &entry, &prefix, policy)?;
        prefix.entries.push(entry);
    }
    Ok(prefix)
}

/// Structural identity only; full execution/snapshot/replay validation belongs
/// to the outer inventory pass and must not be called by an authority verifier.
fn committed_identity(config: &NativeApplicationConfigV0, p: &StoredEpochPV1) -> Result<()> {
    let header = decode_header(&p.header)?;
    ensure!(
        p.store_id == config.store_id
            && p.status == 1
            && p.p_sequence > 1
            && p.commit_sequence
                .is_some_and(|sequence| sequence > p.p_sequence)
            && p.commit_id == Some(p.commit_identity())
            && p.artifact_digest == sha256_v0(&p.artifact)
            && p.snapshot_digest == sha256_v0(&p.snapshot)
            && p.lineage_digest == sha256_v0(&p.lineage)
            && p.p_digest == p.digest()?
            && header.id().as_bytes() == &p.block_id
            && header.height().get() == p.target_height
            && header.parent_id().as_bytes() == &p.consensus_parent_block
            && header.chain_id().as_str() == config.chain_id
            && header.genesis_hash().as_bytes() == &config.genesis_hash,
        "epoch prefix committed P identity"
    );
    Ok(())
}

#[inline(never)]
fn verify_legacy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    edge: &StoredEdgeV1,
    prefix: &Prefix,
) -> Result<Entry> {
    if let Some(checkpoint) =
        load_p_by_block_v0(connection, *edge.checkpoint.block_id().as_bytes())?
    {
        ensure!(
            prefix.entries.is_empty(),
            "legacy v0 checkpoint requires genesis prefix"
        );
        validate_p_v0(config, &checkpoint)?;
        validate_target_snapshot_v0(config, &checkpoint)?;
        ensure!(
            checkpoint.status == P_STATUS_COMMITTED
                && checkpoint.p_digest == edge.checkpoint_p_digest
                && checkpoint.commit_sequence == Some(edge.checkpoint_sequence)
                && checkpoint.commit_id == Some(*edge.checkpoint.commit_id().as_bytes())
                && checkpoint.target_height == edge.checkpoint.height().get()
                && checkpoint.artifact == edge.evidence.checkpoint_artifact,
            "retained checkpoint identity mismatch"
        );
    } else {
        let checkpoint = load_p(connection, edge.checkpoint.block_id().as_bytes())?
            .context("retained checkpoint P missing")?;
        committed_identity(config, &checkpoint)?;
        ensure!(
            checkpoint.artifact_kind == 0
                && checkpoint.target_head()? == edge.checkpoint
                && checkpoint.p_digest == edge.checkpoint_p_digest
                && checkpoint.commit_sequence == Some(edge.checkpoint_sequence)
                && checkpoint.artifact == edge.evidence.checkpoint_artifact
                && checkpoint.lineage == encode_lineage(&prefix.bindings())?
                && decode_header(&checkpoint.header)?.block_kind() == BlockKind::EpochCheckpoint,
            "retained later-epoch checkpoint identity mismatch"
        );
    }
    let (old_set, parameters) = prefix.active(config);
    let audit = edge.evidence.audit_strict(
        old_set,
        parameters,
        &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
    )?;
    let coordinates = audit.coordinates(edge.binding)?;
    ensure!(
        coordinates.checkpoint_version == edge.checkpoint.height().get()
            && &coordinates.checkpoint_root == edge.checkpoint.state_root().as_bytes()
            && coordinates.first_version == edge.first_height
            && coordinates.terminal_version == edge.terminal_height
            && audit
                .activation
                .authorization_kernel()
                .terminal_old_header()
                .id()
                .as_bytes()
                == &edge.terminal_block,
        "retained edge coordinate mismatch"
    );
    Ok(Entry {
        binding: edge.binding,
        checkpoint: edge.checkpoint.clone(),
        checkpoint_p_digest: edge.checkpoint_p_digest,
        checkpoint_sequence: edge.checkpoint_sequence,
        phase: edge.phase,
        consumed: edge.consumed,
        consumed_sequence: edge.consumed_sequence,
        audit: Box::new(audit),
        later_facts: None,
        legacy_preparation: Some((
            edge.evidence.preparation_id,
            edge.evidence.checkpoint_header.clone(),
        )),
    })
}

fn validate_consumption(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    entry: &Entry,
    prefix: &Prefix,
    policy: EpochReadPolicyV1<'_>,
) -> Result<()> {
    ensure!(
        (entry.phase == 0 && entry.consumed.is_none() && entry.consumed_sequence.is_none())
            || (entry.phase == 1 && entry.consumed.is_some() && entry.consumed_sequence.is_some()),
        "edge phase malformed"
    );
    if entry.phase == 0 {
        if entry.later_facts.is_some() {
            ensure!(
                policy.head(connection, config)? == entry.checkpoint,
                "installed later successor requires current checkpoint head"
            );
        }
        return Ok(());
    }
    let consumer = load_p(
        connection,
        &entry.consumed.context("consumed edge target missing")?,
    )?
    .context("consumed edge P missing")?;
    committed_identity(config, &consumer)?;
    let mut lineage = prefix.bindings();
    lineage.push(entry.binding);
    let coordinates = entry.audit.coordinates(entry.binding)?;
    let activation = &entry.audit.activation;
    let terminal = activation.old_checkpoint_finality().grandchild().header();
    ensure!(
        consumer.artifact_kind == 1
            && consumer.commit_sequence == entry.consumed_sequence
            && consumer
                .commit_sequence
                .is_some_and(|sequence| sequence > entry.checkpoint_sequence)
            && consumer.lineage == encode_lineage(&lineage)?
            && consumer.parent == entry.checkpoint
            && consumer.target_height == coordinates.first_version
            && consumer.consensus_parent_height == coordinates.terminal_version
            && consumer.consensus_parent_block == *terminal.id().as_bytes()
            && consumer.target_set
                == activation
                    .new_validator_set()
                    .try_cev0_bytes()
                    .map_err(|e| anyhow::anyhow!("consumer set: {e:?}"))?
            && consumer.target_parameters
                == activation.new_consensus_parameters().canonical_bytes()
            && ((entry.later_facts.is_some()
                && consumer.parent_kind == 1
                && consumer.parent_p_digest == Some(entry.checkpoint_p_digest))
                || (entry.later_facts.is_none()
                    && (consumer.parent_p_digest == Some(entry.checkpoint_p_digest)
                        || (prefix.entries.is_empty()
                            && consumer.parent_kind == 0
                            && consumer.parent_p_digest.is_none())))),
        "consumed edge P mismatch"
    );
    Ok(())
}

fn load_preimages(
    connection: &Connection,
    checkpoint: &[u8; 32],
) -> Result<crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1> {
    // Bound all preimages before selecting them; selected-row cold verification
    // can precede the outer inventory's whole-table resource screen.
    let lengths: [i64; 7] = connection.query_row(
        "SELECT CASE WHEN typeof(checkpoint_parent_header)='blob' THEN length(checkpoint_parent_header) ELSE -1 END,
                CASE WHEN typeof(checkpoint_header)='blob' THEN length(checkpoint_header) ELSE -1 END,
                CASE WHEN typeof(checkpoint_finality)='blob' THEN length(checkpoint_finality) ELSE -1 END,
                CASE WHEN typeof(anchor_kernel)='blob' THEN length(anchor_kernel) ELSE -1 END,
                CASE WHEN typeof(next_epoch_commitment)='blob' THEN length(next_epoch_commitment) ELSE -1 END,
                CASE WHEN typeof(new_validator_set)='blob' THEN length(new_validator_set) ELSE -1 END,
                CASE WHEN typeof(new_parameters)='blob' THEN length(new_parameters) ELSE -1 END
         FROM native_later_epoch_finality_v1 WHERE checkpoint_block=?1",
        [checkpoint.as_slice()], |row| Ok([row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?]),
    )?;
    ensure!(
        lengths
            .iter()
            .zip([
                MAX_HEADER_BYTES,
                MAX_HEADER_BYTES,
                MAX_EPOCH_EVIDENCE_BYTES_V1,
                MAX_EPOCH_EVIDENCE_BYTES_V1,
                MAX_HEADER_BYTES,
                MAX_SET_BYTES,
                MAX_PARAMETERS_BYTES
            ])
            .all(|(&n, cap)| n > 0 && n as usize <= cap)
            && lengths.iter().sum::<i64>() <= MAX_EPOCH_EVIDENCE_BYTES_V1 as i64,
        "later finality aggregate byte budget"
    );
    Ok(connection.query_row(
        "SELECT context_digest,predecessor_edge,checkpoint_parent_header,checkpoint_header,checkpoint_finality,anchor_kernel,next_epoch_commitment,new_validator_set,new_parameters
         FROM native_later_epoch_finality_v1 WHERE checkpoint_block=?1",
        [checkpoint.as_slice()], |row| Ok(crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1 {
            context_digest: col32(row,"context_digest")?, predecessor_edge: col32(row,"predecessor_edge")?, checkpoint_parent_header: row.get(2)?,checkpoint_header: row.get(3)?,checkpoint_finality: row.get(4)?,anchor_kernel: row.get(5)?,next_epoch_commitment: row.get(6)?,new_validator_set: row.get(7)?,new_parameters: row.get(8)?,
        }),
    )?)
}

#[inline(never)]
fn verify_later(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    binding: [u8; 32],
    prefix: &Prefix,
    policy: EpochReadPolicyV1<'_>,
) -> Result<Entry> {
    ensure!(
        has_later_schema(policy.schema(connection)?),
        "later successor requires retained later schema"
    );
    let (stored, phase, consumed, consumed_sequence) = connection.query_row(
        "SELECT * FROM native_later_epoch_edge_v1 WHERE successor_binding=?1",
        [binding.as_slice()],
        |row| {
            Ok((
                LaterSuccessorFactsV1 {
                    successor_binding: col32(row, "successor_binding")?,
                    predecessor_edge: col32(row, "predecessor_edge")?,
                    checkpoint_block: col32(row, "checkpoint_block")?,
                    checkpoint_p_digest: col32(row, "checkpoint_p_digest")?,
                    checkpoint_commit_sequence: col64(row, "checkpoint_commit_sequence")?,
                    checkpoint_height: col64(row, "checkpoint_height")?,
                    checkpoint_root: col32(row, "checkpoint_root")?,
                    checkpoint_commit_id: col32(row, "checkpoint_commit_id")?,
                    terminal_height: col64(row, "terminal_height")?,
                    terminal_block: col32(row, "terminal_block")?,
                    first_height: col64(row, "first_height")?,
                    proof_context_digest: col32(row, "proof_context_digest")?,
                    successor_context_digest: col32(row, "successor_context_digest")?,
                    authority_digest: col32(row, "authority_digest")?,
                    record_digest: col32(row, "record_digest")?,
                },
                row.get::<_, i64>("phase")?,
                opt32(row, "consumed_block")?,
                opt64(row, "consumed_sequence")?,
            ))
        },
    )?;
    let p = load_p(connection, &stored.checkpoint_block)?
        .context("later successor lineage P missing")?;
    committed_identity(config, &p)?;
    ensure!(
        p.artifact_kind == 0
            && p.p_digest == stored.checkpoint_p_digest
            && p.commit_sequence == Some(stored.checkpoint_commit_sequence),
        "later successor lineage checkpoint binding"
    );
    let evidence = load_preimages(connection, &p.block_id)?;
    let (p_digest, sequence, record) = connection.query_row(
        "SELECT p_digest,commit_sequence,record_digest FROM native_later_epoch_finality_v1 WHERE checkpoint_block=?1",
        [p.block_id.as_slice()], |row| Ok((col32(row,"p_digest")?,col64(row,"commit_sequence")?,col32(row,"record_digest")?)),
    )?;
    ensure!(
        p_digest == p.p_digest
            && Some(sequence) == p.commit_sequence
            && record == later_record_digest(config, &p.block_id, &p.p_digest, sequence, &evidence),
        "later finality record digest or P binding"
    );
    let audit = verify_checkpoint(connection, config, &p, &evidence, prefix)?;
    let facts = derive_later_successor_facts_from_audit(config, &p, sequence, &evidence, &audit)?;
    ensure!(
        stored == facts && facts.successor_binding == binding,
        "later successor edge record binding"
    );
    Ok(Entry {
        binding,
        checkpoint: p.target_head()?,
        checkpoint_p_digest: p.p_digest,
        checkpoint_sequence: sequence,
        phase,
        consumed,
        consumed_sequence,
        audit: Box::new(audit),
        later_facts: Some(facts),
        legacy_preparation: None,
    })
}

#[inline(never)]
pub(super) fn verify_checkpoint(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    evidence: &crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1,
    prefix: &Prefix,
) -> Result<Audit> {
    let parts = [
        (&evidence.checkpoint_parent_header, MAX_HEADER_BYTES),
        (&evidence.checkpoint_header, MAX_HEADER_BYTES),
        (&evidence.checkpoint_finality, MAX_EPOCH_EVIDENCE_BYTES_V1),
        (&evidence.anchor_kernel, MAX_EPOCH_EVIDENCE_BYTES_V1),
        (&evidence.next_epoch_commitment, MAX_HEADER_BYTES),
        (&evidence.new_validator_set, MAX_SET_BYTES),
        (&evidence.new_parameters, MAX_PARAMETERS_BYTES),
    ];
    ensure!(
        parts
            .iter()
            .all(|(bytes, cap)| !bytes.is_empty() && bytes.len() <= *cap)
            && parts.iter().map(|(bytes, _)| bytes.len()).sum::<usize>()
                <= MAX_EPOCH_EVIDENCE_BYTES_V1,
        "later finality aggregate byte budget"
    );
    ensure!(
        p.lineage == encode_lineage(&prefix.bindings())?,
        "later checkpoint full prefix mismatch"
    );
    let predecessor = prefix
        .entries
        .last()
        .context("later predecessor edge missing")?;
    ensure!(
        evidence.predecessor_edge == predecessor.binding,
        "later successor predecessor mismatch"
    );
    ensure!(
        predecessor.phase == 1
            && predecessor.consumed.is_some()
            && predecessor.consumed_sequence.is_some(),
        "later predecessor edge is not consumed"
    );
    let (old_set, old_parameters) = prefix.active(config);
    let header = decode_header(&p.header)?;
    let parent = load_p(connection, p.parent.block_id().as_bytes())?
        .context("later checkpoint parent P missing")?;
    committed_identity(config, &parent)?;
    ensure!(
        p.artifact_kind == 0
            && p.parent_kind == 1
            && parent.status == 1
            && parent.target_head()? == p.parent
            && parent.target_height.checked_add(1) == Some(p.target_height)
            && p.consensus_parent_height == parent.target_height
            && p.consensus_parent_block == parent.block_id
            && header.parent_id().as_bytes() == &parent.block_id
            && parent.lineage == p.lineage
            && p.parent_p_digest == Some(parent.p_digest)
            && p.target_set == parent.target_set
            && p.target_parameters == parent.target_parameters
            && p.target_set
                == old_set
                    .try_cev0_bytes()
                    .map_err(|e| anyhow::anyhow!("later old set encoding: {e:?}"))?
            && p.target_parameters == old_parameters.canonical_bytes()
            && p.header == evidence.checkpoint_header
            && parent.header == evidence.checkpoint_parent_header,
        "later finality native parent/configuration binding"
    );
    ensure!(
        evidence.context_digest
            == context_digest(
                config.store_id,
                &p.parent,
                parent
                    .commit_sequence
                    .context("later parent sequence missing")?,
                &parent.target_set,
                &parent.target_parameters,
                &parent.lineage,
            ),
        "later finality original context binding"
    );
    let geometry = trnm_consensus_types::EpochGeometryV0::new(old_set.epoch(), old_parameters)
        .map_err(|e| anyhow::anyhow!("later recovery geometry: {e:?}"))?;
    ensure!(
        header.block_kind() == BlockKind::EpochCheckpoint
            && header.height() == geometry.checkpoint_height()
            && header.epoch() == old_set.epoch()
            && old_set.epoch() > config.validator_set.epoch(),
        "later recovery checkpoint geometry"
    );
    let old_set_bytes = old_set
        .try_cev0_bytes()
        .map_err(|e| anyhow::anyhow!("later recovery old set: {e:?}"))?;
    let old_parameters_bytes = old_parameters.canonical_bytes();
    let decoded = trnm_consensus_types::decode_epoch_activation_evidence_v0_exact(
        trnm_consensus_types::EpochActivationEvidencePreimagesV0 {
            old_checkpoint_finality: &evidence.checkpoint_finality,
            next_epoch_commitment: &evidence.next_epoch_commitment,
            authorization_kernel: &evidence.anchor_kernel,
            old_validator_set: &old_set_bytes,
            old_consensus_parameters: &old_parameters_bytes,
            new_validator_set: &evidence.new_validator_set,
            new_consensus_parameters: &evidence.new_parameters,
            authenticated_checkpoint_parent_header: &evidence.checkpoint_parent_header,
        },
        old_set,
        old_parameters,
        &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .map_err(|e| anyhow::anyhow!("later recovery bounded decode: {e:?}"))?;
    let verified = trnm_consensus_crypto::verify_same_version_epoch_activation_authority_strict_v0(
        decoded.old_checkpoint_finality(),
        decoded.next_epoch_commitment(),
        decoded.authorization_kernel(),
        old_set,
        old_parameters,
        decoded.new_validator_set(),
        decoded.new_consensus_parameters(),
        decoded.authenticated_checkpoint_parent_header(),
    )
    .map_err(|e| anyhow::anyhow!("later recovery strict finality: {e:?}"))?;
    ensure!(
        verified
            .old_checkpoint_finality()
            .finalized_block()
            .header()
            == &header,
        "later recovery proof checkpoint substitution"
    );
    let cutoff_height = geometry
        .checkpoint_height()
        .get()
        .checked_sub(old_parameters.snapshot_lead_blocks())
        .context("later cutoff underflow")?;
    let cutoff = load_committed_p_by_height(connection, cutoff_height)?
        .context("later finality cutoff P missing")?;
    committed_identity(config, &cutoff)?;
    let commitment = decoded.next_epoch_commitment().fields();
    ensure!(
        cutoff.status == 1
            && cutoff.lineage == p.lineage
            && cutoff.target_set == p.target_set
            && cutoff.target_parameters == p.target_parameters
            && cutoff
                .commit_sequence
                .context("later cutoff sequence missing")?
                <= parent
                    .commit_sequence
                    .context("later parent sequence missing")?
            && commitment.snapshot_cutoff_height.get() == cutoff_height
            && commitment.snapshot_state_root.as_bytes()
                == cutoff.target_head()?.state_root().as_bytes(),
        "later finality cutoff binding"
    );
    let coordinates = prefix
        .entries
        .iter()
        .map(|entry| entry.audit.coordinates(entry.binding))
        .collect::<Result<Vec<_>>>()?;
    let computed = derive_poco_next_epoch_from_cutoff_p_v1(config, &cutoff, &coordinates)?;
    ensure!(
        &computed.commitment == decoded.next_epoch_commitment()
            && &computed.new_validator_set == decoded.new_validator_set()
            && &computed.new_parameters == decoded.new_consensus_parameters(),
        "later finality differs from deterministic cutoff candidate selection"
    );
    Ok(crate::epoch_recovery::AuditedEpochEvidenceV1 {
        activation: verified,
    })
}
