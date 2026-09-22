//! Explicit schema13: commit old-epoch finality before either handoff quorum.
//! The retained original evidence is never a signing or activation capability.
use super::*;
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_handoff_descriptor_v0_exact,
    decode_next_epoch_commitment_v0_exact, decode_validator_set_v0_exact, Cev0AdmissionBudgetV0,
    HandoffDescriptorV0,
};

pub(super) const SCHEMA: (&str, &str) = (
    "native_later_epoch_pre_handoff_v1",
    "CREATE TABLE native_later_epoch_pre_handoff_v1 (
     checkpoint_block BLOB PRIMARY KEY CHECK(length(checkpoint_block)=32),
     p_digest BLOB NOT NULL CHECK(length(p_digest)=32),
     commit_sequence BLOB NOT NULL CHECK(length(commit_sequence)=8),
     context_digest BLOB NOT NULL CHECK(length(context_digest)=32),
     predecessor_edge BLOB NOT NULL UNIQUE CHECK(length(predecessor_edge)=32),
     checkpoint_finality BLOB NOT NULL,
     descriptor BLOB NOT NULL,
     next_epoch_commitment BLOB NOT NULL,
     new_validator_set BLOB NOT NULL,
     new_parameters BLOB NOT NULL,
     strict_binding BLOB NOT NULL CHECK(length(strict_binding)=32),
     record_digest BLOB NOT NULL CHECK(length(record_digest)=32)
    )",
);

#[derive(PartialEq, Eq)]
pub(super) struct EvidenceV1 {
    context: [u8; 32],
    predecessor: [u8; 32],
    proof: Vec<u8>,
    descriptor: Vec<u8>,
    commitment: Vec<u8>,
    set: Vec<u8>,
    parameters: Vec<u8>,
    binding: [u8; 32],
}

impl EvidenceV1 {
    fn bounds(&self) -> Result<()> {
        let parts = [
            (&self.proof, MAX_EPOCH_EVIDENCE_BYTES_V1),
            (&self.descriptor, MAX_HEADER_BYTES),
            (&self.commitment, MAX_HEADER_BYTES),
            (&self.set, MAX_SET_BYTES),
            (&self.parameters, MAX_PARAMETERS_BYTES),
        ];
        ensure!(
            parts
                .iter()
                .all(|(bytes, cap)| !bytes.is_empty() && bytes.len() <= *cap)
                && parts.iter().map(|(bytes, _)| bytes.len()).sum::<usize>()
                    <= MAX_EPOCH_EVIDENCE_BYTES_V1,
            "pre-handoff evidence byte bounds"
        );
        Ok(())
    }
    fn digest(
        &self,
        config: &NativeApplicationConfigV0,
        p: &StoredEpochPV1,
        sequence: u64,
    ) -> [u8; 32] {
        hash_domain(
            "trnm.native-application.later-pre-handoff-record.v1",
            &[
                &config.store_id,
                &p.block_id,
                &p.p_digest,
                &sequence.to_be_bytes(),
                &self.context,
                &self.predecessor,
                &sha256_v0(&self.proof),
                &sha256_v0(&self.descriptor),
                &sha256_v0(&self.commitment),
                &sha256_v0(&self.set),
                &sha256_v0(&self.parameters),
                &self.binding,
            ],
        )
    }
    fn complete(
        &self,
        p: &StoredEpochPV1,
        parent: &StoredEpochPV1,
        anchor: &[u8],
    ) -> crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1 {
        crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1 {
            context_digest: self.context,
            predecessor_edge: self.predecessor,
            checkpoint_parent_header: parent.header.clone(),
            checkpoint_header: p.header.clone(),
            checkpoint_finality: self.proof.clone(),
            anchor_kernel: anchor.to_vec(),
            next_epoch_commitment: self.commitment.clone(),
            new_validator_set: self.set.clone(),
            new_parameters: self.parameters.clone(),
        }
    }
}

fn verify_context(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    evidence: &EvidenceV1,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<trnm_consensus_crypto::StrictPreHandoffContextV1> {
    evidence.bounds()?;
    let parent = load_p(connection, p.parent.block_id().as_bytes())?
        .context("pre-handoff parent missing")?;
    let prefix = lineage_resolver::resolve(connection, config, &decode_lineage(&p.lineage)?)?;
    let commitment = decode_next_epoch_commitment_v0_exact(&evidence.commitment)
        .map_err(|e| anyhow::anyhow!("pre-handoff commitment: {e:?}"))?;
    let descriptor = decode_handoff_descriptor_v0_exact(&evidence.descriptor)
        .map_err(|e| anyhow::anyhow!("pre-handoff descriptor: {e:?}"))?;
    let set = decode_validator_set_v0_exact(&evidence.set)
        .map_err(|e| anyhow::anyhow!("pre-handoff set: {e:?}"))?;
    let parameters = decode_consensus_parameters_v0_exact(&evidence.parameters)
        .map_err(|e| anyhow::anyhow!("pre-handoff parameters: {e:?}"))?;
    lineage_resolver::verify_pre_handoff_checkpoint(
        connection,
        config,
        p,
        &lineage_resolver::CheckpointNativeEvidenceV1 {
            context_digest: evidence.context,
            predecessor_edge: evidence.predecessor,
            checkpoint_parent_header: &parent.header,
            checkpoint_header: &p.header,
        },
        &prefix,
        &evidence.proof,
        &commitment,
        &descriptor,
        &set,
        &parameters,
        budget,
    )
}

pub(super) fn verify(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    evidence: &EvidenceV1,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<trnm_consensus_crypto::StrictPreHandoffContextV1> {
    let verified = verify_context(connection, config, p, evidence, budget)?;
    ensure!(
        evidence.binding == verified.binding_ref(),
        "pre-handoff strict context binding changed"
    );
    Ok(verified)
}

fn screen(connection: &Connection) -> Result<()> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_later_epoch_pre_handoff_v1",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        (0..=MAX_EDGES as i64).contains(&count),
        "pre-handoff record count bound"
    );
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_later_epoch_pre_handoff_v1 WHERE
         typeof(checkpoint_block)!='blob' OR length(checkpoint_block)!=32 OR
         typeof(p_digest)!='blob' OR length(p_digest)!=32 OR
         typeof(commit_sequence)!='blob' OR length(commit_sequence)!=8 OR
         typeof(context_digest)!='blob' OR length(context_digest)!=32 OR
         typeof(predecessor_edge)!='blob' OR length(predecessor_edge)!=32 OR
         typeof(strict_binding)!='blob' OR length(strict_binding)!=32 OR
         typeof(record_digest)!='blob' OR length(record_digest)!=32 OR
         typeof(checkpoint_finality)!='blob' OR length(checkpoint_finality) NOT BETWEEN 1 AND 67108864 OR
         typeof(descriptor)!='blob' OR length(descriptor) NOT BETWEEN 1 AND 4096 OR
         typeof(next_epoch_commitment)!='blob' OR length(next_epoch_commitment) NOT BETWEEN 1 AND 4096 OR
         typeof(new_validator_set)!='blob' OR length(new_validator_set) NOT BETWEEN 1 AND 1048576 OR
         typeof(new_parameters)!='blob' OR length(new_parameters) NOT BETWEEN 1 AND 4096 OR
         length(checkpoint_finality)+length(descriptor)+length(next_epoch_commitment)+length(new_validator_set)+length(new_parameters)>67108864",
         [], |r| r.get(0))?;
    ensure!(invalid == 0, "pre-handoff SQL type/byte bounds");
    Ok(())
}

fn load(
    connection: &Connection,
    block: &[u8; 32],
) -> Result<([u8; 32], u64, EvidenceV1, [u8; 32])> {
    screen(connection)?;
    Ok(connection.query_row(
        "SELECT * FROM native_later_epoch_pre_handoff_v1 WHERE checkpoint_block=?1",
        [block.as_slice()],
        |r| {
            Ok((
                col32(r, "p_digest")?,
                col64(r, "commit_sequence")?,
                EvidenceV1 {
                    context: col32(r, "context_digest")?,
                    predecessor: col32(r, "predecessor_edge")?,
                    proof: r.get("checkpoint_finality")?,
                    descriptor: r.get("descriptor")?,
                    commitment: r.get("next_epoch_commitment")?,
                    set: r.get("new_validator_set")?,
                    parameters: r.get("new_parameters")?,
                    binding: col32(r, "strict_binding")?,
                },
                col32(r, "record_digest")?,
            ))
        },
    )?)
}

pub(super) fn matching_count(connection: &Connection, p: &StoredEpochPV1) -> Result<i64> {
    Ok(connection.query_row("SELECT COUNT(*) FROM native_later_epoch_pre_handoff_v1 WHERE checkpoint_block=?1 AND p_digest=?2 AND commit_sequence=?3",
        params![p.block_id.as_slice(), p.p_digest.as_slice(), p.commit_sequence.context("pre-handoff committed sequence missing")?.to_be_bytes().as_slice()], |r| r.get(0))?)
}

pub(super) fn check_capacity(connection: &Connection, p: &StoredEpochPV1) -> Result<()> {
    screen(connection)?;
    if p.status == 0 {
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM native_later_epoch_pre_handoff_v1",
            [],
            |r| r.get(0),
        )?;
        ensure!(count < MAX_EDGES as i64, "pre-handoff ledger full");
    }
    Ok(())
}

pub(super) fn check_retry(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    sequence: u64,
    evidence: &EvidenceV1,
) -> Result<()> {
    let (digest, retained_sequence, retained, record) = load(connection, &p.block_id)?;
    ensure!(
        digest == p.p_digest
            && retained_sequence == sequence
            && &retained == evidence
            && record == evidence.digest(config, p, sequence),
        "conflicting pre-handoff retry"
    );
    Ok(())
}

pub(super) fn insert(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    sequence: u64,
    evidence: &EvidenceV1,
) -> Result<()> {
    check_capacity(connection, p)?;
    connection.execute(
        "INSERT INTO native_later_epoch_pre_handoff_v1 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            p.block_id.as_slice(),
            p.p_digest.as_slice(),
            sequence.to_be_bytes().as_slice(),
            evidence.context.as_slice(),
            evidence.predecessor.as_slice(),
            &evidence.proof,
            &evidence.descriptor,
            &evidence.commitment,
            &evidence.set,
            &evidence.parameters,
            evidence.binding.as_slice(),
            evidence.digest(config, p, sequence).as_slice(),
        ],
    )?;
    Ok(())
}

pub(super) fn audit(connection: &Connection, config: &NativeApplicationConfigV0) -> Result<()> {
    screen(connection)?;
    let mut query = connection.prepare(
        "SELECT checkpoint_block FROM native_later_epoch_pre_handoff_v1 ORDER BY commit_sequence",
    )?;
    let blocks = query
        .query_map([], |r| col32(r, "checkpoint_block"))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut previous = 0;
    for block in blocks {
        let (p_digest, sequence, evidence, record) = load(connection, &block)?;
        let p = load_p(connection, &block)?.context("pre-handoff committed P missing")?;
        ensure!(
            p.status == 1
                && p.p_digest == p_digest
                && p.commit_sequence == Some(sequence)
                && sequence > previous
                && record == evidence.digest(config, &p, sequence),
            "pre-handoff committed evidence binding"
        );
        previous = sequence;
        verify(
            connection,
            config,
            &p,
            &evidence,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )?;
        // An attached complete certificate must retain exactly these original preimages.
        let attached: i64 = connection.query_row(
            "SELECT COUNT(*) FROM native_later_epoch_finality_v1 WHERE checkpoint_block=?1",
            [block.as_slice()],
            |r| r.get(0),
        )?;
        if attached != 0 {
            // Screen lengths/types before either copying or comparing blob contents.
            let invalid: i64 = connection.query_row(
                "SELECT COUNT(*) FROM native_later_epoch_finality_v1 WHERE checkpoint_block=?1 AND (
                 typeof(checkpoint_finality)!='blob' OR length(checkpoint_finality) NOT BETWEEN 1 AND 67108864 OR
                 typeof(next_epoch_commitment)!='blob' OR length(next_epoch_commitment) NOT BETWEEN 1 AND 4096 OR
                 typeof(new_validator_set)!='blob' OR length(new_validator_set) NOT BETWEEN 1 AND 1048576 OR
                 typeof(new_parameters)!='blob' OR length(new_parameters) NOT BETWEEN 1 AND 4096 OR
                 typeof(context_digest)!='blob' OR length(context_digest)!=32 OR
                 typeof(predecessor_edge)!='blob' OR length(predecessor_edge)!=32 OR
                 length(checkpoint_finality)+length(next_epoch_commitment)+length(new_validator_set)+length(new_parameters)>67108864)",
                 [block.as_slice()], |r| r.get(0))?;
            ensure!(invalid == 0, "attached pre-handoff byte/type bounds");
            let exact: i64 = connection.query_row(
                "SELECT COUNT(*) FROM native_later_epoch_finality_v1 WHERE checkpoint_block=?1
                 AND checkpoint_finality=?2 AND next_epoch_commitment=?3 AND new_validator_set=?4
                 AND new_parameters=?5 AND context_digest=?6 AND predecessor_edge=?7",
                params![
                    block.as_slice(),
                    &evidence.proof,
                    &evidence.commitment,
                    &evidence.set,
                    &evidence.parameters,
                    evidence.context.as_slice(),
                    evidence.predecessor.as_slice()
                ],
                |r| r.get(0),
            )?;
            ensure!(
                attached == 1 && exact == 1,
                "attached handoff changed original pre-handoff evidence"
            );
        }
    }
    Ok(())
}

/// Fresh committed native checkpoint plus strict original pre-certificate context.
/// No signer, Core receipt, or successor edge is exposed by this capability.
///
/// ```compile_fail
/// use trnm_native_execution_v0::CommittedLaterEpochPreHandoffV1;
/// fn copy(value: &CommittedLaterEpochPreHandoffV1) { let _: CommittedLaterEpochPreHandoffV1 = value.clone(); }
/// ```
#[must_use]
pub struct CommittedLaterEpochPreHandoffV1 {
    committed: CommittedNativeEpochExecutionV1,
    header: BlockHeader,
    artifact: [u8; 32],
    overlay: [u8; 32],
    persist_sequence: u64,
    record: [u8; 32],
    context: trnm_consensus_crypto::StrictPreHandoffContextV1,
}
impl CommittedLaterEpochPreHandoffV1 {
    pub fn head(&self) -> &ApplicationHeadV0 {
        self.committed.head()
    }
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }
    pub fn strict_context(&self) -> &trnm_consensus_crypto::StrictPreHandoffContextV1 {
        &self.context
    }
    pub fn commit_sequence(&self) -> u64 {
        self.committed.commit_sequence()
    }
    pub fn committed_owner_cut_ref_v1(&self) -> [u8; 32] {
        hash_domain(
            "trnm.native-application.later-pre-handoff-owner-cut.v1",
            &[
                &self.record,
                &self.committed.p_digest(),
                &self.artifact,
                &self.overlay,
                &self.persist_sequence.to_be_bytes(),
                &self.commit_sequence().to_be_bytes(),
                self.header.id().as_bytes(),
                &self.context.binding_ref(),
            ],
        )
    }
    pub fn belongs_to_application(&self, application: &DurableNativeApplicationV0) -> bool {
        Arc::ptr_eq(&self.committed.owner, &application.owner_affinity)
            && application
                .recover_later_epoch_pre_handoff_v1(*self.header.id().as_bytes())
                .is_ok_and(|fresh| {
                    fresh.committed_owner_cut_ref_v1() == self.committed_owner_cut_ref_v1()
                })
    }
}

impl DurableNativeApplicationV0 {
    /// Explicit migration from the unchanged schema10 owner; never run by open.
    pub fn upgrade_later_epoch_pre_handoff_schema_v1(
        &self,
        expected: &ApplicationHeadV0,
    ) -> Result<()> {
        let _guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_schema_v0(&tx)?;
        let metadata = load_metadata_v0(&tx, &self.config)?;
        validate_metadata_v0(&tx, &self.config, &metadata)?;
        ensure!(
            &metadata.head == expected,
            "pre-handoff migration head changed"
        );
        let schema = schema_version(&tx)?;
        if schema != PRE_HANDOFF_SCHEMA_VERSION {
            ensure!(
                schema == LATER_SCHEMA_VERSION,
                "pre-handoff migration requires schema10"
            );
            tx.execute_batch(SCHEMA.1)?;
            ensure!(tx.execute("UPDATE native_application_metadata_v0 SET schema_version=?1 WHERE singleton=1 AND schema_version=?2 AND durable_sequence=?3",
            params![PRE_HANDOFF_SCHEMA_VERSION.to_be_bytes().as_slice(), LATER_SCHEMA_VERSION.to_be_bytes().as_slice(), metadata.durable_sequence.to_be_bytes().as_slice()])? == 1,
            "pre-handoff migration CAS");
        }
        tx.commit()?;
        drop(connection);
        sync_store_commit_boundary_v0(&self.path)?;
        ensure!(
            fresh_validate_v0(&self.path, &self.config)? == metadata,
            "pre-handoff migration changed state"
        );
        #[cfg(unix)]
        self.confirm_namespace_identity_v1()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_later_epoch_pre_handoff_v1(
        &self,
        prepared: &PreparedNativeEpochExecutionV1,
        proof: &[u8],
        descriptor: &HandoffDescriptorV0,
        commitment: &[u8],
        new_set: &[u8],
        new_parameters: &[u8],
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<CommittedLaterEpochPreHandoffV1> {
        ensure!(
            Arc::ptr_eq(&prepared.owner, &self.owner_affinity),
            "pre-handoff foreign prepared owner"
        );
        // Bound all untrusted byte slices before retaining any owned copies.
        let parts = [
            (proof, MAX_EPOCH_EVIDENCE_BYTES_V1),
            (commitment, MAX_HEADER_BYTES),
            (new_set, MAX_SET_BYTES),
            (new_parameters, MAX_PARAMETERS_BYTES),
        ];
        ensure!(
            parts
                .iter()
                .all(|(b, cap)| !b.is_empty() && b.len() <= *cap)
                && parts.iter().map(|(b, _)| b.len()).sum::<usize>()
                    <= MAX_EPOCH_EVIDENCE_BYTES_V1 - MAX_HEADER_BYTES,
            "pre-handoff input byte bounds"
        );
        let mut evidence = {
            let _guard = self.lock_operation()?;
            let connection = open_immutable_connection_v0(&self.path)?;
            verify_schema_v0(&connection)?;
            ensure!(
                schema_version(&connection)? == PRE_HANDOFF_SCHEMA_VERSION,
                "pre-handoff explicit schema13 required"
            );
            let metadata = load_metadata_v0(&connection, &self.config)?;
            validate_metadata_v0(&connection, &self.config, &metadata)?;
            let p =
                load_p(&connection, &prepared.row.block_id)?.context("pre-handoff P missing")?;
            ensure!(
                p.p_digest == prepared.row.p_digest && p.header == prepared.row.header,
                "pre-handoff P substituted"
            );
            validate_p(&connection, &self.config, &p)?;
            ensure!(
                metadata.head == p.parent || (p.status == 1 && metadata.head == p.target_head()?),
                "pre-handoff parent no longer current"
            );
            let parent = load_p(&connection, p.parent.block_id().as_bytes())?
                .context("pre-handoff parent missing")?;
            EvidenceV1 {
                context: context_digest(
                    self.config.store_id,
                    &p.parent,
                    parent
                        .commit_sequence
                        .context("pre-handoff parent uncommitted")?,
                    &parent.target_set,
                    &parent.target_parameters,
                    &parent.lineage,
                ),
                predecessor: *decode_lineage(&p.lineage)?
                    .last()
                    .context("pre-handoff lineage missing")?,
                proof: proof.to_vec(),
                descriptor: descriptor
                    .try_cev0_bytes()
                    .map_err(|e| anyhow::anyhow!("pre-handoff descriptor encode: {e:?}"))?,
                commitment: commitment.to_vec(),
                set: new_set.to_vec(),
                parameters: new_parameters.to_vec(),
                binding: [0; 32],
            }
        };
        {
            let _guard = self.lock_operation()?;
            let connection = open_immutable_connection_v0(&self.path)?;
            verify_schema_v0(&connection)?;
            evidence.binding =
                verify_context(&connection, &self.config, &prepared.row, &evidence, budget)?
                    .binding_ref();
        }
        let committed = self.commit_epoch_p(prepared, None, None, None, Some(&evidence))?;
        let receipt = self.recover_later_epoch_pre_handoff_v1(prepared.row.block_id)?;
        ensure!(
            receipt.head() == committed.head()
                && receipt.commit_sequence() == committed.commit_sequence()
                && receipt.committed.p_digest() == committed.p_digest(),
            "pre-handoff committed readbacks disagree"
        );
        Ok(receipt)
    }

    pub fn recover_later_epoch_pre_handoff_v1(
        &self,
        block: [u8; 32],
    ) -> Result<CommittedLaterEpochPreHandoffV1> {
        let _guard = self.lock_operation()?;
        sync_store_commit_boundary_v0(&self.path)?;
        let metadata = fresh_validate_v0(&self.path, &self.config)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        ensure!(
            schema_version(&connection)? == PRE_HANDOFF_SCHEMA_VERSION,
            "pre-handoff recovery exact schema13 required"
        );
        let (p_digest, sequence, evidence, record) = load(&connection, &block)?;
        let p = load_p(&connection, &block)?.context("pre-handoff recovery P missing")?;
        validate_p(&connection, &self.config, &p)?;
        ensure!(
            p.status == 1
                && p.target_head()? == metadata.head
                && p_digest == p.p_digest
                && p.commit_sequence == Some(sequence)
                && record == evidence.digest(&self.config, &p, sequence),
            "pre-handoff recovery exact current committed cut"
        );
        let context = verify(
            &connection,
            &self.config,
            &p,
            &evidence,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )?;
        ensure!(
            fresh_validate_v0(&self.path, &self.config)? == metadata,
            "pre-handoff recovery changed during readback"
        );
        #[cfg(unix)]
        self.confirm_namespace_identity_v1()?;
        Ok(CommittedLaterEpochPreHandoffV1 {
            committed: CommittedNativeEpochExecutionV1 {
                owner: Arc::clone(&self.owner_affinity),
                head: p.target_head()?,
                p_digest,
                commit_sequence: sequence,
            },
            header: decode_header(&p.header)?,
            artifact: p.artifact_digest,
            overlay: p.snapshot_digest,
            persist_sequence: p.p_sequence,
            record,
            context,
        })
    }
}

impl DurableNativeApplicationV0 {
    /// Attach both genuine handoff quorums to the unchanged committed checkpoint.
    /// This installs its successor edge, never a signature or Core acknowledgement.
    pub fn attach_later_epoch_handoff_v1(
        &self,
        receipt: &CommittedLaterEpochPreHandoffV1,
        anchor_kernel: &[u8],
    ) -> Result<LaterEpochApplicationEdgeV1> {
        ensure!(
            Arc::ptr_eq(&receipt.committed.owner, &self.owner_affinity),
            "pre-handoff attachment foreign owner"
        );
        ensure!(
            !anchor_kernel.is_empty() && anchor_kernel.len() <= MAX_EPOCH_EVIDENCE_BYTES_V1,
            "pre-handoff attachment kernel bound"
        );
        let block = *receipt.header.id().as_bytes();
        {
            let _guard = self.lock_operation()?;
            let mut connection = open_writable_connection_v0(&self.path)?;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            verify_schema_v0(&tx)?;
            ensure!(
                schema_version(&tx)? == PRE_HANDOFF_SCHEMA_VERSION,
                "handoff attachment exact schema13 required"
            );
            let metadata = load_metadata_v0(&tx, &self.config)?;
            validate_metadata_v0(&tx, &self.config, &metadata)?;
            let p = load_p(&tx, &block)?.context("handoff attachment P missing")?;
            validate_p(&tx, &self.config, &p)?;
            let (digest, sequence, evidence, record) = load(&tx, &block)?;
            ensure!(
                p.status == 1
                    && p.target_head()? == metadata.head
                    && digest == p.p_digest
                    && p.commit_sequence == Some(sequence)
                    && sequence == receipt.commit_sequence()
                    && record == receipt.record
                    && record == evidence.digest(&self.config, &p, sequence)
                    && evidence.binding == receipt.context.binding_ref(),
                "handoff attachment exact committed owner cut"
            );
            verify(
                &tx,
                &self.config,
                &p,
                &evidence,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )?;
            let parent = load_p(&tx, p.parent.block_id().as_bytes())?
                .context("handoff attachment parent missing")?;
            ensure!(
                evidence.proof.len()
                    + evidence.commitment.len()
                    + evidence.set.len()
                    + evidence.parameters.len()
                    + p.header.len()
                    + parent.header.len()
                    + anchor_kernel.len()
                    <= MAX_EPOCH_EVIDENCE_BYTES_V1,
                "handoff attachment aggregate byte bound"
            );
            let complete = evidence.complete(&p, &parent, anchor_kernel);
            let facts = derive_later_successor_facts(&tx, &self.config, &p, sequence, &complete)?;
            let expected =
                later_record_digest(&self.config, &block, &p.p_digest, sequence, &complete);
            let existing: Option<[u8; 32]> = tx.query_row(
                "SELECT record_digest FROM native_later_epoch_finality_v1 WHERE checkpoint_block=?1",
                [block.as_slice()], |r| col32(r, "record_digest")).optional()?;
            match existing {
                Some(value) => {
                    let edge: [u8; 32] = tx.query_row("SELECT record_digest FROM native_later_epoch_edge_v1 WHERE checkpoint_block=?1",
                        [block.as_slice()], |r| col32(r, "record_digest"))?;
                    ensure!(
                        value == expected && edge == facts.record_digest,
                        "conflicting handoff attachment retry"
                    );
                }
                None => {
                    let count: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM native_later_epoch_finality_v1",
                        [],
                        |r| r.get(0),
                    )?;
                    ensure!(count < MAX_EDGES as i64, "handoff attachment ledger full");
                    insert_later_records_v1(&tx, &self.config, &p, sequence, &complete, &facts)?;
                }
            }
            #[cfg(test)]
            park_for_sigkill_commit_boundary_v0("later_pre_handoff_attach_before_commit");
            tx.commit()?;
            #[cfg(test)]
            park_for_sigkill_commit_boundary_v0("later_pre_handoff_attach_after_commit");
            drop(connection);
            sync_store_commit_boundary_v0(&self.path)?;
            #[cfg(test)]
            park_for_sigkill_commit_boundary_v0("later_pre_handoff_attach_after_fsync");
            ensure!(
                fresh_validate_v0(&self.path, &self.config)? == metadata,
                "handoff attachment altered application state"
            );
            #[cfg(unix)]
            self.confirm_namespace_identity_v1()?;
        }
        let requirements = self.inspect_later_epoch_application_edge_requirements_v1(block)?;
        let edge = self.recover_later_epoch_application_edge_v1(&requirements)?;
        #[cfg(unix)]
        self.confirm_namespace_identity_v1()?;
        Ok(edge)
    }
}
