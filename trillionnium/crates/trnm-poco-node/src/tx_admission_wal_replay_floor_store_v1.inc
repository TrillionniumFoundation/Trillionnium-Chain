// Persisted nonce floors are rejection facts, never a signing/application
// capability. Only the existing sealed verifier can authorize floor updates.
// A local checksum detects corruption, not coherent rollback by the owner.

fn floor_bytes_v1<const N: usize>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<[u8; N]> {
    // Borrow the SQLite value and copy only its fixed field. An oversized row
    // never creates an attacker-sized Rust Vec allocation in this decoder.
    let value = row.get_ref(index)?.as_blob()?;
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn read_stored_replay_floor_v1(
    connection: &Connection,
    namespace: [u8; 32],
    signer: [u8; 32],
) -> Result<Option<TxAdmissionReplayFloorEvidenceV1>, TxAdmissionWalErrorV0> {
    let raw = connection
        .query_row(
            "SELECT reject_nonce_through,finalized_height,state_root,
                    finality_proof_digest,retention_policy_digest,commitment
             FROM tx_admission_replay_floor_v1 WHERE namespace = ?1 AND signer = ?2",
            params![namespace.as_slice(), signer.as_slice()],
            |row| {
                Ok((
                    u64::from_be_bytes(floor_bytes_v1::<8>(row, 0)?),
                    u64::from_be_bytes(floor_bytes_v1::<8>(row, 1)?),
                    floor_bytes_v1::<32>(row, 2)?,
                    floor_bytes_v1::<32>(row, 3)?,
                    floor_bytes_v1::<32>(row, 4)?,
                    floor_bytes_v1::<32>(row, 5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| TxAdmissionWalErrorV0::Malformed)?;
    let Some((nonce, height, root, proof, policy, commitment)) = raw else {
        return Ok(None);
    };
    let evidence = TxAdmissionReplayFloorEvidenceV1::new(
        namespace,
        CanonicalSignerId::from_bytes(signer).map_err(|_| TxAdmissionWalErrorV0::Malformed)?,
        nonce,
        Height::new(height),
        StateRoot::new(root),
        proof,
        policy,
    )?;
    if commitment != replay_floor_commitment_v1(&evidence) {
        return Err(TxAdmissionWalErrorV0::Malformed);
    }
    Ok(Some(evidence))
}

fn floor_overlaps_active_v1(
    connection: &Connection,
    evidence: &TxAdmissionReplayFloorEvidenceV1,
) -> Result<bool, TxAdmissionWalErrorV0> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pending_nonce
             WHERE namespace = ?1 AND signer = ?2 AND nonce <= ?3 AND state IN (0,1))",
            params![
                evidence.namespace.as_slice(),
                evidence.signer.as_slice(),
                evidence.reject_nonce_through.to_be_bytes().as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn validate_stored_replay_floors_v1(
    connection: &Connection,
    namespace: [u8; 32],
) -> Result<(), TxAdmissionWalErrorV0> {
    // The caller enforces the global rich+tombstone+floor inventory cap first.
    // Stream keys rather than retaining an unbounded list of signer records.
    let mut statement = connection
        .prepare(
            "SELECT namespace,signer FROM tx_admission_replay_floor_v1 ORDER BY namespace,signer",
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((floor_bytes_v1::<32>(row, 0)?, floor_bytes_v1::<32>(row, 1)?))
        })
        .map_err(sqlite_error)?;
    for row in rows {
        let (stored_namespace, signer) = row.map_err(|_| TxAdmissionWalErrorV0::Malformed)?;
        if stored_namespace != namespace {
            return Err(TxAdmissionWalErrorV0::NamespaceMismatch);
        }
        let evidence = read_stored_replay_floor_v1(connection, namespace, signer)?
            .ok_or(TxAdmissionWalErrorV0::Malformed)?;
        if floor_overlaps_active_v1(connection, &evidence)? {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
    }
    Ok(())
}

fn validate_replay_floor_successor_v1(
    connection: &Connection,
    evidence: &TxAdmissionReplayFloorEvidenceV1,
) -> Result<(), TxAdmissionWalErrorV0> {
    if floor_overlaps_active_v1(connection, evidence)? {
        // A floor is not a receipt for a live reservation or a way to resolve
        // an uncertain handoff. That existing lifecycle must finish first.
        return Err(TxAdmissionWalErrorV0::ReservationConflict);
    }
    if let Some(old) = read_stored_replay_floor_v1(connection, evidence.namespace, evidence.signer)?
    {
        if evidence.reject_nonce_through < old.reject_nonce_through
            || evidence.finalized_height < old.finalized_height
            || evidence.retention_policy_digest != old.retention_policy_digest
            || (evidence.finalized_height == old.finalized_height
                && evidence.state_root != old.state_root)
        {
            return Err(TxAdmissionWalErrorV0::CommitReceiptConflict);
        }
        // Same-height/root certificates can have distinct legitimate voter
        // subsets and proof digests. The live sealed verifier admits them;
        // persisted progress must not assume a unique certificate encoding.
    }
    Ok(())
}

fn persist_replay_floor_v1(
    connection: &Connection,
    floor: &VerifiedTxAdmissionReplayFloorV1,
) -> Result<(), TxAdmissionWalErrorV0> {
    let e = floor.evidence();
    connection
        .execute(
            "INSERT INTO tx_admission_replay_floor_v1
         (namespace,signer,reject_nonce_through,finalized_height,state_root,
          finality_proof_digest,retention_policy_digest,commitment)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
         ON CONFLICT(namespace,signer) DO UPDATE SET
          reject_nonce_through=excluded.reject_nonce_through,
          finalized_height=excluded.finalized_height,state_root=excluded.state_root,
          finality_proof_digest=excluded.finality_proof_digest,
          retention_policy_digest=excluded.retention_policy_digest,
          commitment=excluded.commitment",
            params![
                e.namespace.as_slice(),
                e.signer.as_slice(),
                e.reject_nonce_through.to_be_bytes().as_slice(),
                e.finalized_height.to_be_bytes().as_slice(),
                e.state_root.as_slice(),
                e.finality_proof_digest.as_slice(),
                e.retention_policy_digest.as_slice(),
                floor.commitment.as_slice(),
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static REPLAY_FLOOR_TEST_FAILURE_V1: RefCell<Option<(PathBuf, &'static str)>> = const { RefCell::new(None) };
}

#[cfg(test)]
fn replay_floor_test_cut_v1(path: &Path, cut: &str) -> Result<(), TxAdmissionWalErrorV0> {
    if std::env::var("TRNM_FLOOR_TEST_CUT").as_deref() == Ok(cut)
        && std::env::var_os("TRNM_FLOOR_TEST_PATH").as_deref() == Some(path.as_os_str())
    {
        std::process::exit(74);
    }
    REPLAY_FLOOR_TEST_FAILURE_V1.with(|failure| {
        let mut failure = failure.borrow_mut();
        if failure
            .as_ref()
            .is_some_and(|(p, c)| p == path && *c == cut)
        {
            failure.take();
            return Err(TxAdmissionWalErrorV0::Sqlite);
        }
        Ok(())
    })
}

#[cfg(test)]
#[path = "tx_admission_wal_replay_floor_store_tests_v1.rs"]
mod replay_floor_store_tests_v1;
