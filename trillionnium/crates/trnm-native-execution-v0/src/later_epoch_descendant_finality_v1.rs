//! Schema-10 retained ordinary finality. All audit reads use the caller's
//! connection; this module never reopens the owner or recurses into inventory.
use super::*;

const MAX_TOTAL_PROOF_BYTES: usize = 64 * 1024 * 1024;

pub(super) const SCHEMA: (&str, &str) = (
    "native_later_epoch_descendant_finality_v1",
    "CREATE TABLE native_later_epoch_descendant_finality_v1 (
       block_id BLOB NOT NULL PRIMARY KEY CHECK(length(block_id)=32),
       p_digest BLOB NOT NULL CHECK(length(p_digest)=32),
       commit_sequence BLOB NOT NULL UNIQUE CHECK(length(commit_sequence)=8),
       edge_binding BLOB NOT NULL CHECK(length(edge_binding)=32),
       proof BLOB NOT NULL CHECK(length(proof) BETWEEN 1 AND 8388608),
       proof_digest BLOB NOT NULL CHECK(length(proof_digest)=32),
       record_digest BLOB NOT NULL CHECK(length(record_digest)=32)
     ) STRICT",
);

pub(super) fn binding(connection: &Connection, p: &StoredEpochPV1) -> Result<Option<[u8; 32]>> {
    if p.artifact_kind != 0
        || decode_header(&p.header)?.block_kind() != BlockKind::Regular
        || !has_later_schema(schema_version(connection)?)
    {
        return Ok(None);
    }
    let lineage = decode_lineage(&p.lineage)?;
    let last = *lineage
        .last()
        .context("ordinary descendant lineage missing")?;
    let later: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM native_later_epoch_edge_v1 WHERE successor_binding=?1)",
        [last.as_slice()],
        |row| row.get(0),
    )?;
    Ok(later.then_some(last))
}

/// Bounded enumeration also serves the schema-9 migration refusal: the old
/// schema contains no original proof for any of these committed records.
pub(super) fn committed_blocks(connection: &Connection) -> Result<BTreeSet<[u8; 32]>> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_durable_execution_p_v1",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        count >= 0 && count as usize <= MAX_P_ROWS,
        "epoch P count budget"
    );
    let mut statement = connection.prepare(
        "SELECT block_id FROM native_durable_execution_p_v1 WHERE status=1 AND artifact_kind=0",
    )?;
    let ids = statement
        .query_map([], |row| col32(row, "block_id"))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut result = BTreeSet::new();
    for id in ids {
        let p = load_p(connection, &id)?.context("ordinary descendant P missing")?;
        if binding(connection, &p)?.is_some() {
            result.insert(id);
        }
    }
    Ok(result)
}

fn record_digest(
    config: &NativeApplicationConfigV0,
    block: &[u8; 32],
    p_digest: &[u8; 32],
    sequence: u64,
    edge: &[u8; 32],
    proof_digest: &[u8; 32],
) -> [u8; 32] {
    hash_domain(
        "trnm.native-application.later-epoch-descendant-finality.v1",
        &[
            &config.store_id,
            block,
            p_digest,
            &sequence.to_be_bytes(),
            edge,
            proof_digest,
        ],
    )
}

/// Inspect every SQL value's type and length, then the aggregate budget, before
/// selecting any proof blob into memory. STRICT alone is not the audit boundary.
fn statistics(connection: &Connection) -> Result<(usize, usize)> {
    let (count, bytes, invalid): (i64, i64, i64) = connection.query_row(
        "SELECT COUNT(*),COALESCE(SUM(CASE WHEN typeof(proof)='blob' THEN length(proof) ELSE 0 END),0),COALESCE(SUM(CASE WHEN
          typeof(block_id)!='blob' OR length(block_id)!=32 OR
          typeof(p_digest)!='blob' OR length(p_digest)!=32 OR
          typeof(commit_sequence)!='blob' OR length(commit_sequence)!=8 OR
          typeof(edge_binding)!='blob' OR length(edge_binding)!=32 OR
          typeof(proof)!='blob' OR length(proof) NOT BETWEEN 1 AND ?1 OR
          typeof(proof_digest)!='blob' OR length(proof_digest)!=32 OR
          typeof(record_digest)!='blob' OR length(record_digest)!=32
          THEN 1 ELSE 0 END),0)
         FROM native_later_epoch_descendant_finality_v1",
        [trnm_consensus_types::MAX_CEV0_ROOT_BYTES_V0 as i64],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    ensure!(
        invalid == 0,
        "later descendant finality SQL types or lengths"
    );
    ensure!(
        count >= 0 && count as usize <= MAX_P_ROWS,
        "later descendant finality count budget"
    );
    ensure!(
        bytes >= 0 && bytes as usize <= MAX_TOTAL_PROOF_BYTES,
        "later descendant finality total proof budget"
    );
    Ok((count as usize, bytes as usize))
}

pub(super) fn check_proof_bounds(proof: &[u8]) -> Result<()> {
    ensure!(
        !proof.is_empty() && proof.len() <= trnm_consensus_types::MAX_CEV0_ROOT_BYTES_V0,
        "later descendant finality proof budget"
    );
    Ok(())
}

pub(super) fn check_capacity(connection: &Connection, proof: &[u8]) -> Result<()> {
    check_proof_bounds(proof)?;
    let (count, bytes) = statistics(connection)?;
    ensure!(
        count < MAX_P_ROWS
            && bytes
                .checked_add(proof.len())
                .is_some_and(|n| n <= MAX_TOTAL_PROOF_BYTES),
        "later descendant finality capacity unavailable"
    );
    Ok(())
}

pub(super) fn insert(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    sequence: u64,
    edge: [u8; 32],
    proof: &[u8],
) -> Result<()> {
    let proof_digest = sha256_v0(proof);
    let record = record_digest(
        config,
        &p.block_id,
        &p.p_digest,
        sequence,
        &edge,
        &proof_digest,
    );
    connection.execute(
        "INSERT INTO native_later_epoch_descendant_finality_v1 VALUES (?,?,?,?,?,?,?)",
        params![
            p.block_id.as_slice(),
            p.p_digest.as_slice(),
            sequence.to_be_bytes().as_slice(),
            edge.as_slice(),
            proof,
            proof_digest.as_slice(),
            record.as_slice(),
        ],
    )?;
    Ok(())
}

pub(super) fn check_retry(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    sequence: u64,
    edge: [u8; 32],
    proof: &[u8],
) -> Result<()> {
    check_proof_bounds(proof)?;
    statistics(connection)?;
    let retained = connection.query_row(
        "SELECT p_digest,commit_sequence,edge_binding,proof,proof_digest,record_digest
         FROM native_later_epoch_descendant_finality_v1 WHERE block_id=?1",
        [p.block_id.as_slice()],
        |row| {
            Ok((
                col32(row, "p_digest")?,
                col64(row, "commit_sequence")?,
                col32(row, "edge_binding")?,
                row.get::<_, Vec<u8>>("proof")?,
                col32(row, "proof_digest")?,
                col32(row, "record_digest")?,
            ))
        },
    )?;
    let proof_digest = sha256_v0(proof);
    ensure!(
        retained.0 == p.p_digest
            && retained.1 == sequence
            && retained.2 == edge
            && retained.3 == proof
            && retained.4 == proof_digest
            && retained.5
                == record_digest(
                    config,
                    &p.block_id,
                    &p.p_digest,
                    sequence,
                    &edge,
                    &proof_digest
                ),
        "later descendant conflicting retry"
    );
    Ok(())
}

#[inline(never)]
pub(super) fn audit(connection: &Connection, config: &NativeApplicationConfigV0) -> Result<()> {
    let (count, _) = statistics(connection)?;
    let mut expected = committed_blocks(connection)?;
    ensure!(
        count == expected.len(),
        "later descendant finality ledger must cover every committed ordinary P"
    );
    let mut statement = connection.prepare(
        "SELECT block_id,p_digest,commit_sequence,edge_binding,proof,proof_digest,record_digest
         FROM native_later_epoch_descendant_finality_v1 ORDER BY commit_sequence",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            col32(row, "block_id")?,
            col32(row, "p_digest")?,
            col64(row, "commit_sequence")?,
            col32(row, "edge_binding")?,
            row.get::<_, Vec<u8>>("proof")?,
            col32(row, "proof_digest")?,
            col32(row, "record_digest")?,
        ))
    })?;
    let mut previous_sequence = 0;
    for row in rows {
        let (block, p_digest, sequence, edge, proof, proof_digest, record) = row?;
        ensure!(
            expected.remove(&block),
            "later descendant finality extra or duplicate P"
        );
        ensure!(
            sequence > previous_sequence,
            "later descendant finality sequence order"
        );
        previous_sequence = sequence;
        ensure!(
            sha256_v0(&proof) == proof_digest,
            "later descendant proof digest"
        );
        ensure!(
            record == record_digest(config, &block, &p_digest, sequence, &edge, &proof_digest),
            "later descendant finality record digest"
        );
        let p = load_p(connection, &block)?.context("later descendant finality P missing")?;
        ensure!(
            p.status == 1
                && p.artifact_kind == 0
                && p.p_digest == p_digest
                && p.digest()? == p_digest
                && p.commit_sequence == Some(sequence)
                && binding(connection, &p)? == Some(edge),
            "later descendant finality P binding"
        );
        validate_proof(connection, config, &p, edge, &proof)?;
    }
    ensure!(expected.is_empty(), "later descendant finality P missing");
    Ok(())
}

/// Keep the strict decoder's cryptographic temporaries off the inventory and
/// activation-audit frames. The caller has already authenticated every retained
/// checkpoint, successor and first-new proof in this same database snapshot.
#[inline(never)]
fn validate_proof(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    edge: [u8; 32],
    proof: &[u8],
) -> Result<()> {
    let (predecessor, checkpoint): ([u8; 32], [u8; 32]) = connection.query_row(
        "SELECT predecessor_edge,checkpoint_block FROM native_later_epoch_edge_v1
         WHERE successor_binding=?1 AND phase=1",
        [edge.as_slice()],
        |row| {
            Ok((
                col32(row, "predecessor_edge")?,
                col32(row, "checkpoint_block")?,
            ))
        },
    )?;
    let activation = audit_later_successor_for_lineage_v1(connection, config, edge, predecessor)?;
    let checkpoint =
        load_p(connection, &checkpoint)?.context("later descendant checkpoint P missing")?;
    let mut expected_lineage = decode_lineage(&checkpoint.lineage)?;
    expected_lineage.push(edge);
    ensure!(
        decode_lineage(&p.lineage)? == expected_lineage,
        "later descendant finality full lineage binding"
    );
    let new_set = activation.activation.new_validator_set();
    let new_parameters = activation.activation.new_consensus_parameters();
    ensure!(
        p.target_set
            == new_set
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("later descendant new validator set: {e:?}"))?
            && p.target_parameters == new_parameters.canonical_bytes(),
        "later descendant finality authenticated configuration"
    );
    let parent = load_p(connection, p.parent.block_id().as_bytes())?
        .context("later descendant finality parent P missing")?;
    ensure!(
        p.parent_kind == 1
            && parent.status == 1
            && parent.target_head()? == p.parent
            && p.parent_p_digest == Some(parent.p_digest)
            && parent.lineage == p.lineage
            && parent
                .commit_sequence
                .is_some_and(|sequence| sequence < p.commit_sequence.unwrap_or(0)),
        "later descendant finality committed parent binding"
    );
    let parent_header = decode_header(&parent.header)?;
    ensure!(
        *parent_header.id().as_bytes() == p.consensus_parent_block
            && parent_header.height().get() == p.consensus_parent_height,
        "later descendant finality consensus parent binding"
    );
    let header = decode_header(&p.header)?;
    let expected = trnm_consensus_crypto::FinalityExpectationV0 {
        block_id: header.id(),
        height: header.height(),
        state_root: header.state_root(),
        receipts_root: header.receipts_root(),
        evidence_root: header.evidence_root(),
        parent_id: parent_header.id(),
        parent_height: parent_header.height(),
        parent_timestamp_ms: parent_header.timestamp_ms(),
    };
    let verified = trnm_consensus_crypto::decode_verify_finality_proof_strict_v0(
        trnm_consensus_crypto::POCO_THREE_CHAIN_PROOF_CLASS_V0,
        proof,
        new_set,
        new_parameters,
        expected,
        &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .map_err(|e| anyhow::anyhow!("later descendant strict finality: {e}"))?;
    ensure!(
        verified.proof().finalized_block().header() == &header,
        "later descendant proof header binding"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA.1).unwrap();
        connection
    }

    // SQLite creates the sized value. No proof blob is loaded into Rust by the
    // scalar budget screen, even in the aggregate-overflow negative.
    fn insert_sized(connection: &Connection, sequence: u64, bytes: usize) {
        let mut block = [0_u8; 32];
        block[..8].copy_from_slice(&sequence.to_be_bytes());
        connection
            .execute(
                "INSERT INTO native_later_epoch_descendant_finality_v1
                 VALUES (?1,zeroblob(32),?2,zeroblob(32),zeroblob(?3),zeroblob(32),zeroblob(32))",
                params![
                    block.as_slice(),
                    sequence.to_be_bytes().as_slice(),
                    bytes as i64
                ],
            )
            .unwrap();
    }

    #[test]
    fn later_descendant_finality_per_proof_bounds() {
        let limit = trnm_consensus_types::MAX_CEV0_ROOT_BYTES_V0;
        assert!(check_proof_bounds(&[]).is_err());
        check_proof_bounds(&[1]).unwrap();
        let mut proof = vec![0_u8; limit];
        check_proof_bounds(&proof).unwrap();
        proof.push(0);
        assert_eq!(
            check_proof_bounds(&proof).unwrap_err().to_string(),
            "later descendant finality proof budget"
        );
        drop(proof);

        let connection = ledger();
        insert_sized(&connection, 1, limit);
        assert_eq!(statistics(&connection).unwrap(), (1, limit));
        assert!(connection
            .execute(
                "UPDATE native_later_epoch_descendant_finality_v1 SET proof=zeroblob(0)",
                []
            )
            .is_err());
        assert!(connection
            .execute(
                "UPDATE native_later_epoch_descendant_finality_v1 SET proof=zeroblob(?1)",
                [limit as i64 + 1]
            )
            .is_err());
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        connection
            .execute(
                "UPDATE native_later_epoch_descendant_finality_v1 SET proof=zeroblob(?1)",
                [limit as i64 + 1],
            )
            .unwrap();
        assert_eq!(
            statistics(&connection).unwrap_err().to_string(),
            "later descendant finality SQL types or lengths"
        );
    }

    #[test]
    fn later_descendant_finality_non_blob_proofs_reject() {
        let connection = Connection::open_in_memory().unwrap();
        // The production STRICT BLOB column rejects these SQL writes. Relax
        // only this fixture column to exercise the independent cold type
        // screen as though malformed storage had bypassed that write gate.
        connection
            .execute_batch(&SCHEMA.1.replace(
                "proof BLOB NOT NULL CHECK(length(proof) BETWEEN 1 AND 8388608)",
                "proof ANY NOT NULL",
            ))
            .unwrap();
        insert_sized(&connection, 1, 1);
        for value in ["CAST(x'ff' AS TEXT)", "123", "123.5"] {
            connection
                .execute(
                    &format!("UPDATE native_later_epoch_descendant_finality_v1 SET proof={value}"),
                    [],
                )
                .unwrap();
            assert_eq!(
                statistics(&connection).unwrap_err().to_string(),
                "later descendant finality SQL types or lengths"
            );
        }
    }

    #[test]
    fn later_descendant_finality_count_and_prospective_bound() {
        let connection = ledger();
        for sequence in 1..MAX_P_ROWS as u64 {
            insert_sized(&connection, sequence, 1);
        }
        // Exactly one slot remains; prospective admission must allow it.
        check_capacity(&connection, &[1]).unwrap();
        insert_sized(&connection, MAX_P_ROWS as u64, 1);
        assert_eq!(statistics(&connection).unwrap(), (MAX_P_ROWS, MAX_P_ROWS));
        assert_eq!(
            check_capacity(&connection, &[1]).unwrap_err().to_string(),
            "later descendant finality capacity unavailable"
        );
        insert_sized(&connection, MAX_P_ROWS as u64 + 1, 1);
        assert_eq!(
            statistics(&connection).unwrap_err().to_string(),
            "later descendant finality count budget"
        );
    }

    #[test]
    fn later_descendant_finality_total_and_prospective_byte_bound() {
        let connection = ledger();
        let per_proof = trnm_consensus_types::MAX_CEV0_ROOT_BYTES_V0;
        assert_eq!(8 * per_proof, MAX_TOTAL_PROOF_BYTES);
        for sequence in 1..=8 {
            insert_sized(&connection, sequence, per_proof);
        }
        assert_eq!(statistics(&connection).unwrap(), (8, MAX_TOTAL_PROOF_BYTES));
        assert_eq!(
            check_capacity(&connection, &[1]).unwrap_err().to_string(),
            "later descendant finality capacity unavailable"
        );
        connection
            .execute(
                "UPDATE native_later_epoch_descendant_finality_v1 SET proof=zeroblob(?1)
                 WHERE commit_sequence=?2",
                params![per_proof as i64 - 1, 8_u64.to_be_bytes().as_slice()],
            )
            .unwrap();
        // The byte limit is inclusive; a two-byte append exceeds it.
        check_capacity(&connection, &[1]).unwrap();
        assert_eq!(
            check_capacity(&connection, &[1, 2])
                .unwrap_err()
                .to_string(),
            "later descendant finality capacity unavailable"
        );
        insert_sized(&connection, 9, 1);
        assert_eq!(statistics(&connection).unwrap(), (9, MAX_TOTAL_PROOF_BYTES));
        connection
            .execute(
                "UPDATE native_later_epoch_descendant_finality_v1 SET proof=zeroblob(?1)",
                [per_proof as i64],
            )
            .unwrap();
        // All nine individual proofs fit, but their aggregate exceeds 64 MiB.
        assert_eq!(
            statistics(&connection).unwrap_err().to_string(),
            "later descendant finality total proof budget"
        );
    }
}
