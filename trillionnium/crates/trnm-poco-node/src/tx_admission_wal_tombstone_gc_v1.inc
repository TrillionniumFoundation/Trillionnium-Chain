/// Compact terminal admission rows into immutable replay tombstones.
///
/// This boundary is candidate-only. Compaction never removes replay identity;
/// final deletion requires a separately verified application nonce floor.
#[allow(dead_code)]
pub const TX_ADMISSION_TOMBSTONE_COMPACTION_V1: bool = true;
/// A typed authenticated purge boundary exists for compact tombstones.
#[allow(dead_code)]
pub const TX_ADMISSION_TOMBSTONE_AUTHENTICATED_PURGE_V1: bool = true;
/// Neither compaction nor purge activates production transaction admission.
#[allow(dead_code)]
pub const TX_ADMISSION_TOMBSTONE_PRODUCTION_ACTIVATION_V1: bool = false;

/// Keep the candidate lifecycle truth executable at the Rust boundary.  This
/// intentionally does not mean that production admission is active: the
/// production flag must remain false until an external application/finality
/// owner installs the verifier and the node composition is enabled.
const fn tombstone_gc_candidate_contract_v1() -> bool {
    TX_ADMISSION_TOMBSTONE_COMPACTION_V1
        && TX_ADMISSION_TOMBSTONE_AUTHENTICATED_PURGE_V1
        && !TX_ADMISSION_TOMBSTONE_PRODUCTION_ACTIVATION_V1
}

const TOMBSTONE_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-node.tx-admission-tombstone.v1";
const REPLAY_FLOOR_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-node.tx-replay-floor.v1";
const MAX_TOMBSTONE_BATCH_V1: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxAdmissionTombstoneGcResultV1 {
    compacted: usize,
    purged: usize,
    retained_tombstones: usize,
}

impl TxAdmissionTombstoneGcResultV1 {
    pub const fn compacted(&self) -> usize {
        self.compacted
    }

    pub const fn purged(&self) -> usize {
        self.purged
    }

    pub const fn retained_tombstones(&self) -> usize {
        self.retained_tombstones
    }
}

/// Application/finality evidence that every nonce through one signer-local
/// floor is permanently rejected by the authoritative application state.
///
/// The value is inert until an owner-installed verifier accepts it. In
/// particular, a local clock or caller assertion cannot mint the private
/// [`VerifiedTxAdmissionReplayFloorV1`] token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxAdmissionReplayFloorEvidenceV1 {
    namespace: [u8; 32],
    signer: [u8; 32],
    reject_nonce_through: u64,
    finalized_height: u64,
    state_root: [u8; 32],
    finality_proof_digest: [u8; 32],
    retention_policy_digest: [u8; 32],
}

impl TxAdmissionReplayFloorEvidenceV1 {
    pub fn new(
        namespace: [u8; 32],
        signer: CanonicalSignerId,
        reject_nonce_through: u64,
        finalized_height: Height,
        state_root: StateRoot,
        finality_proof_digest: [u8; 32],
        retention_policy_digest: [u8; 32],
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        let signer = signer.as_bytes();
        let finalized_height = finalized_height.get();
        let state_root = *state_root.as_bytes();
        if namespace == [0; 32]
            || signer == [0; 32]
            || reject_nonce_through == 0
            || finalized_height == 0
            || state_root == [0; 32]
            || finality_proof_digest == [0; 32]
            || retention_policy_digest == [0; 32]
        {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        Ok(Self {
            namespace,
            signer,
            reject_nonce_through,
            finalized_height,
            state_root,
            finality_proof_digest,
            retention_policy_digest,
        })
    }

    pub const fn namespace(&self) -> [u8; 32] {
        self.namespace
    }

    pub fn signer_id(&self) -> CanonicalSignerId {
        CanonicalSignerId::from_bytes(self.signer)
            .expect("validated replay-floor signer must remain canonical")
    }

    pub const fn reject_nonce_through(&self) -> u64 {
        self.reject_nonce_through
    }

    pub const fn finalized_height(&self) -> Height {
        Height::new(self.finalized_height)
    }

    pub const fn state_root(&self) -> StateRoot {
        StateRoot::new(self.state_root)
    }

    pub const fn finality_proof_digest(&self) -> [u8; 32] {
        self.finality_proof_digest
    }

    pub const fn retention_policy_digest(&self) -> [u8; 32] {
        self.retention_policy_digest
    }

    pub fn verify_with<V: TxAdmissionReplayFloorVerifierV1 + ?Sized>(
        self,
        verifier: &V,
    ) -> Result<VerifiedTxAdmissionReplayFloorV1, TxAdmissionWalErrorV0> {
        verifier.verify_replay_floor_v1(&self)?;
        Ok(VerifiedTxAdmissionReplayFloorV1 {
            commitment: replay_floor_commitment_v1(&self),
            evidence: self,
        })
    }
}

pub trait TxAdmissionReplayFloorVerifierV1: fmt::Debug {
    fn verify_replay_floor_v1(
        &self,
        evidence: &TxAdmissionReplayFloorEvidenceV1,
    ) -> Result<(), TxAdmissionWalErrorV0>;
}

/// Private type-state proof required before compact tombstones may be removed.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedTxAdmissionReplayFloorV1 {
    evidence: TxAdmissionReplayFloorEvidenceV1,
    commitment: [u8; 32],
}

impl VerifiedTxAdmissionReplayFloorV1 {
    pub const fn evidence(&self) -> &TxAdmissionReplayFloorEvidenceV1 {
        &self.evidence
    }

    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

fn framed_digest_v1(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn replay_floor_commitment_v1(evidence: &TxAdmissionReplayFloorEvidenceV1) -> [u8; 32] {
    let nonce = evidence.reject_nonce_through.to_be_bytes();
    let height = evidence.finalized_height.to_be_bytes();
    framed_digest_v1(
        REPLAY_FLOOR_DIGEST_DOMAIN_V1,
        &[
            evidence.namespace.as_slice(),
            evidence.signer.as_slice(),
            nonce.as_slice(),
            height.as_slice(),
            evidence.state_root.as_slice(),
            evidence.finality_proof_digest.as_slice(),
            evidence.retention_policy_digest.as_slice(),
        ],
    )
}

fn tombstone_digest_v1(
    namespace: [u8; 32],
    signer: [u8; 32],
    nonce: u64,
    tx_digest: [u8; 32],
    terminal_state: i64,
    terminal_height: u64,
    receipt_commitment: [u8; 32],
) -> Result<[u8; 32], TxAdmissionWalErrorV0> {
    let state = u8::try_from(terminal_state).map_err(|_| TxAdmissionWalErrorV0::Malformed)?;
    let nonce = nonce.to_be_bytes();
    let height = terminal_height.to_be_bytes();
    Ok(framed_digest_v1(
        TOMBSTONE_DIGEST_DOMAIN_V1,
        &[
            namespace.as_slice(),
            signer.as_slice(),
            nonce.as_slice(),
            tx_digest.as_slice(),
            [state].as_slice(),
            height.as_slice(),
            receipt_commitment.as_slice(),
        ],
    ))
}

fn tombstone_exists_by_nonce_or_digest_v1(
    connection: &Connection,
    namespace: [u8; 32],
    signer: [u8; 32],
    nonce: u64,
    digest: [u8; 32],
) -> Result<bool, TxAdmissionWalErrorV0> {
    let nonce = nonce.to_be_bytes();
    let found: i64 = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM tx_admission_tombstone_v1
             WHERE namespace = ?1 AND ((signer = ?2 AND nonce = ?3) OR tx_digest = ?4))",
            params![
                namespace.as_slice(),
                signer.as_slice(),
                nonce.as_slice(),
                digest.as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    Ok(found != 0)
}

fn retained_tombstone_count_v1(
    connection: &Connection,
    namespace: [u8; 32],
) -> Result<usize, TxAdmissionWalErrorV0> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM tx_admission_tombstone_v1 WHERE namespace = ?1",
            params![namespace.as_slice()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    usize::try_from(count).map_err(|_| TxAdmissionWalErrorV0::Malformed)
}

fn validate_tombstone_rows_v1(
    connection: &Connection,
    namespace: [u8; 32],
) -> Result<(), TxAdmissionWalErrorV0> {
    let count = retained_tombstone_count_v1(connection, namespace)?;
    if count > MAX_RESERVATION_ROWS_V0 {
        return Err(TxAdmissionWalErrorV0::TooLarge);
    }
    let overlap: i64 = connection
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM tx_admission_tombstone_v1 t
               JOIN pending_nonce p
                 ON p.namespace = t.namespace AND p.signer = t.signer AND p.nonce = t.nonce
               WHERE t.namespace = ?1
             )",
            params![namespace.as_slice()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if overlap != 0 {
        return Err(TxAdmissionWalErrorV0::Malformed);
    }

    let mut statement = connection
        .prepare(
            "SELECT signer,nonce,tx_digest,terminal_state,terminal_height,
                    receipt_commitment,tombstone_digest
             FROM tx_admission_tombstone_v1
             WHERE namespace = ?1 ORDER BY signer ASC, nonce ASC",
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(params![namespace.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        })
        .map_err(sqlite_error)?;
    for row in rows {
        let (signer, nonce, digest, state, height, receipt, stored_digest) =
            row.map_err(sqlite_error)?;
        let signer = decode_fixed::<32>(signer)?;
        let nonce = u64::from_be_bytes(decode_fixed::<8>(nonce)?);
        let digest = decode_fixed::<32>(digest)?;
        let height = u64::from_be_bytes(decode_fixed::<8>(height)?);
        let receipt = decode_fixed::<32>(receipt)?;
        let stored_digest = decode_fixed::<32>(stored_digest)?;
        if signer == [0; 32] || nonce == 0 || digest == [0; 32] {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        match state {
            STATE_COMMITTED_V0 if height != 0 && receipt != [0; 32] => {}
            STATE_RELEASED_V0 if height == 0 && receipt == [0; 32] => {}
            _ => return Err(TxAdmissionWalErrorV0::Malformed),
        }
        if stored_digest
            != tombstone_digest_v1(namespace, signer, nonce, digest, state, height, receipt)?
        {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
    }
    Ok(())
}

impl SqlitePendingNonceAuthorityV0 {
    pub fn retained_tombstones_v1(&self) -> Result<usize, TxAdmissionWalErrorV0> {
        self.ensure_identity()?;
        let connection = self
            .connection
            .try_borrow()
            .map_err(|_| TxAdmissionWalErrorV0::Sqlite)?;
        let count = retained_tombstone_count_v1(&connection, self.namespace)?;
        drop(connection);
        self.ensure_identity()?;
        Ok(count)
    }

    /// Atomically replace rich terminal rows with compact replay tombstones.
    /// `Reserved` and `HandedOff` rows are never eligible.
    pub fn compact_terminal_rows_v1(
        &mut self,
        max_rows: usize,
    ) -> Result<TxAdmissionTombstoneGcResultV1, TxAdmissionWalErrorV0> {
        if !tombstone_gc_candidate_contract_v1() {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        if max_rows == 0 || max_rows > MAX_TOMBSTONE_BATCH_V1 {
            return Err(TxAdmissionWalErrorV0::TooLarge);
        }
        self.ensure_identity()?;
        let mut connection = self
            .connection
            .try_borrow_mut()
            .map_err(|_| TxAdmissionWalErrorV0::Sqlite)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let candidates = {
            let mut statement = transaction
                .prepare(
                    "SELECT signer,nonce,digest,state FROM pending_nonce
                     WHERE namespace = ?1 AND state IN (?2,?3)
                     ORDER BY signer ASC, nonce ASC LIMIT ?4",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map(
                    params![
                        self.namespace.as_slice(),
                        STATE_COMMITTED_V0,
                        STATE_RELEASED_V0,
                        i64::try_from(max_rows).map_err(|_| TxAdmissionWalErrorV0::TooLarge)?,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .map_err(sqlite_error)?;
            let mut candidates = Vec::new();
            for row in rows {
                let (signer, nonce, digest, state) = row.map_err(sqlite_error)?;
                candidates.push((
                    decode_fixed::<32>(signer)?,
                    u64::from_be_bytes(decode_fixed::<8>(nonce)?),
                    decode_fixed::<32>(digest)?,
                    state,
                ));
            }
            candidates
        };

        let mut compacted = 0usize;
        for (signer, nonce, digest, state) in candidates {
            let nonce_blob = nonce.to_be_bytes();
            let receipt = transaction
                .query_row(
                    "SELECT tx_digest,block_height,commitment FROM tx_commit_receipt_v0
                     WHERE namespace = ?1 AND signer = ?2 AND nonce = ?3",
                    params![
                        self.namespace.as_slice(),
                        signer.as_slice(),
                        nonce_blob.as_slice(),
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(sqlite_error)?;
            let (terminal_height, receipt_commitment) = match (state, receipt) {
                (STATE_COMMITTED_V0, Some((receipt_digest, height, commitment))) => {
                    let receipt_digest = decode_fixed::<32>(receipt_digest)?;
                    let height = u64::from_be_bytes(decode_fixed::<8>(height)?);
                    let commitment = decode_fixed::<32>(commitment)?;
                    if receipt_digest != digest || height == 0 || commitment == [0; 32] {
                        return Err(TxAdmissionWalErrorV0::CommitReceiptConflict);
                    }
                    (height, commitment)
                }
                (STATE_RELEASED_V0, None) => (0, [0; 32]),
                _ => return Err(TxAdmissionWalErrorV0::CommitReceiptConflict),
            };
            let tombstone_digest = tombstone_digest_v1(
                self.namespace,
                signer,
                nonce,
                digest,
                state,
                terminal_height,
                receipt_commitment,
            )?;
            let terminal_height_blob = terminal_height.to_be_bytes();
            transaction
                .execute(
                    "INSERT INTO tx_admission_tombstone_v1
                     (namespace,signer,nonce,tx_digest,terminal_state,terminal_height,
                      receipt_commitment,tombstone_digest)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![
                        self.namespace.as_slice(),
                        signer.as_slice(),
                        nonce_blob.as_slice(),
                        digest.as_slice(),
                        state,
                        terminal_height_blob.as_slice(),
                        receipt_commitment.as_slice(),
                        tombstone_digest.as_slice(),
                    ],
                )
                .map_err(|_| TxAdmissionWalErrorV0::Replay)?;
            if state == STATE_COMMITTED_V0 {
                let deleted = transaction
                    .execute(
                        "DELETE FROM tx_commit_receipt_v0
                         WHERE namespace = ?1 AND signer = ?2 AND nonce = ?3",
                        params![
                            self.namespace.as_slice(),
                            signer.as_slice(),
                            nonce_blob.as_slice(),
                        ],
                    )
                    .map_err(sqlite_error)?;
                if deleted != 1 {
                    return Err(TxAdmissionWalErrorV0::CommitReceiptConflict);
                }
            }
            let deleted = transaction
                .execute(
                    "DELETE FROM pending_nonce
                     WHERE namespace = ?1 AND signer = ?2 AND nonce = ?3 AND state = ?4",
                    params![
                        self.namespace.as_slice(),
                        signer.as_slice(),
                        nonce_blob.as_slice(),
                        state,
                    ],
                )
                .map_err(sqlite_error)?;
            if deleted != 1 {
                return Err(TxAdmissionWalErrorV0::ReservationConflict);
            }
            compacted = compacted
                .checked_add(1)
                .ok_or(TxAdmissionWalErrorV0::TooLarge)?;
        }
        transaction.commit().map_err(sqlite_error)?;
        drop(connection);
        self.ensure_identity()?;
        let retained_tombstones = self.retained_tombstones_v1()?;
        Ok(TxAdmissionTombstoneGcResultV1 {
            compacted,
            purged: 0,
            retained_tombstones,
        })
    }

    /// Delete compact tombstones only after an authenticated application nonce
    /// floor proves every removed nonce is permanently non-admissible.
    pub fn purge_tombstones_with_replay_floor_v1(
        &mut self,
        floor: &VerifiedTxAdmissionReplayFloorV1,
        max_rows: usize,
    ) -> Result<TxAdmissionTombstoneGcResultV1, TxAdmissionWalErrorV0> {
        if !tombstone_gc_candidate_contract_v1() {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        if max_rows == 0 || max_rows > MAX_TOMBSTONE_BATCH_V1 {
            return Err(TxAdmissionWalErrorV0::TooLarge);
        }
        let evidence = floor.evidence();
        if evidence.namespace != self.namespace
            || floor.commitment != replay_floor_commitment_v1(evidence)
        {
            return Err(TxAdmissionWalErrorV0::NamespaceMismatch);
        }
        self.ensure_identity()?;
        let mut connection = self
            .connection
            .try_borrow_mut()
            .map_err(|_| TxAdmissionWalErrorV0::Sqlite)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let floor_nonce = evidence.reject_nonce_through.to_be_bytes();
        let finalized_height = evidence.finalized_height.to_be_bytes();
        let candidates = {
            let mut statement = transaction
                .prepare(
                    "SELECT nonce,tombstone_digest FROM tx_admission_tombstone_v1
                     WHERE namespace = ?1 AND signer = ?2 AND nonce <= ?3
                       AND terminal_height <= ?4
                     ORDER BY nonce ASC LIMIT ?5",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map(
                    params![
                        self.namespace.as_slice(),
                        evidence.signer.as_slice(),
                        floor_nonce.as_slice(),
                        finalized_height.as_slice(),
                        i64::try_from(max_rows).map_err(|_| TxAdmissionWalErrorV0::TooLarge)?,
                    ],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .map_err(sqlite_error)?;
            let mut candidates = Vec::new();
            for row in rows {
                let (nonce, digest) = row.map_err(sqlite_error)?;
                candidates.push((decode_fixed::<8>(nonce)?, decode_fixed::<32>(digest)?));
            }
            candidates
        };
        let mut purged = 0usize;
        for (nonce, digest) in candidates {
            let deleted = transaction
                .execute(
                    "DELETE FROM tx_admission_tombstone_v1
                     WHERE namespace = ?1 AND signer = ?2 AND nonce = ?3
                       AND tombstone_digest = ?4",
                    params![
                        self.namespace.as_slice(),
                        evidence.signer.as_slice(),
                        nonce.as_slice(),
                        digest.as_slice(),
                    ],
                )
                .map_err(sqlite_error)?;
            if deleted != 1 {
                return Err(TxAdmissionWalErrorV0::ReservationConflict);
            }
            purged = purged
                .checked_add(1)
                .ok_or(TxAdmissionWalErrorV0::TooLarge)?;
        }
        transaction.commit().map_err(sqlite_error)?;
        drop(connection);
        self.ensure_identity()?;
        let retained_tombstones = self.retained_tombstones_v1()?;
        Ok(TxAdmissionTombstoneGcResultV1 {
            compacted: 0,
            purged,
            retained_tombstones,
        })
    }
}

impl NodeOwnedTxAdmissionBoundaryV0 {
    pub fn retained_tombstones_v1(&self) -> Result<usize, TxAdmissionWalErrorV0> {
        self.authority.retained_tombstones_v1()
    }

    pub fn compact_terminal_rows_v1(
        &mut self,
        max_rows: usize,
    ) -> Result<TxAdmissionTombstoneGcResultV1, TxAdmissionWalErrorV0> {
        self.authority.compact_terminal_rows_v1(max_rows)
    }

    pub fn purge_tombstones_with_replay_floor_v1(
        &mut self,
        floor: &VerifiedTxAdmissionReplayFloorV1,
        max_rows: usize,
    ) -> Result<TxAdmissionTombstoneGcResultV1, TxAdmissionWalErrorV0> {
        self.authority
            .purge_tombstones_with_replay_floor_v1(floor, max_rows)
    }
}

#[cfg(test)]
mod tombstone_gc_tests_v1 {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_PATH_V1: AtomicU64 = AtomicU64::new(1);

    #[derive(Debug)]
    struct AcceptFloorV1;

    impl TxAdmissionReplayFloorVerifierV1 for AcceptFloorV1 {
        fn verify_replay_floor_v1(
            &self,
            _evidence: &TxAdmissionReplayFloorEvidenceV1,
        ) -> Result<(), TxAdmissionWalErrorV0> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct RejectFloorV1;

    impl TxAdmissionReplayFloorVerifierV1 for RejectFloorV1 {
        fn verify_replay_floor_v1(
            &self,
            _evidence: &TxAdmissionReplayFloorEvidenceV1,
        ) -> Result<(), TxAdmissionWalErrorV0> {
            Err(TxAdmissionWalErrorV0::CommitReadbackUnavailable)
        }
    }

    fn temp_path_v1() -> PathBuf {
        let nonce = NEXT_PATH_V1.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "trnm-tx-tombstone-gc-{}-{nonce}.sqlite",
            std::process::id()
        ))
    }

    fn cleanup_v1(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
        if let Ok(lock) = lock_path_v0(path) {
            let _ = fs::remove_file(lock);
        }
    }

    fn insert_terminal_v1(
        authority: &SqlitePendingNonceAuthorityV0,
        signer: [u8; 32],
        nonce: u64,
        digest: [u8; 32],
        state: i64,
        height: u64,
        receipt_commitment: [u8; 32],
    ) {
        let connection = authority.connection.borrow_mut();
        connection
            .execute(
                "INSERT INTO pending_nonce
                 (namespace,signer,nonce,digest,body_digest,fee_limit,max_gas,max_bytes,state)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    authority.namespace.as_slice(),
                    signer.as_slice(),
                    nonce.to_be_bytes().as_slice(),
                    digest.as_slice(),
                    [0xA1u8; 32].as_slice(),
                    17u128.to_be_bytes().as_slice(),
                    10_000u64.to_be_bytes().as_slice(),
                    512u64.to_be_bytes().as_slice(),
                    state,
                ],
            )
            .unwrap();
        if state == STATE_COMMITTED_V0 {
            connection
                .execute(
                    "INSERT INTO tx_commit_receipt_v0
                     (namespace,signer,nonce,tx_digest,block_id,block_height,state_root,
                      receipt_digest,finality_proof_digest,commitment)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    params![
                        authority.namespace.as_slice(),
                        signer.as_slice(),
                        nonce.to_be_bytes().as_slice(),
                        digest.as_slice(),
                        [0xB1u8; 32].as_slice(),
                        height.to_be_bytes().as_slice(),
                        [0xB2u8; 32].as_slice(),
                        [0xB3u8; 32].as_slice(),
                        [0xB4u8; 32].as_slice(),
                        receipt_commitment.as_slice(),
                    ],
                )
                .unwrap();
        }
    }

    #[test]
    fn terminal_rows_compact_reopen_and_remain_replay_markers_v1() {
        let path = temp_path_v1();
        let namespace = [0x11; 32];
        let signer = [0x22; 32];
        let mut authority = SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap();
        insert_terminal_v1(
            &authority,
            signer,
            7,
            [0x31; 32],
            STATE_COMMITTED_V0,
            90,
            [0x41; 32],
        );
        insert_terminal_v1(
            &authority,
            signer,
            8,
            [0x32; 32],
            STATE_RELEASED_V0,
            0,
            [0; 32],
        );
        let result = authority.compact_terminal_rows_v1(16).unwrap();
        assert_eq!(result.compacted(), 2);
        assert_eq!(result.retained_tombstones(), 2);
        assert_eq!(authority.retained_rows().unwrap(), 2);
        {
            let connection = authority.connection.borrow();
            assert!(tombstone_exists_by_nonce_or_digest_v1(
                &connection,
                namespace,
                signer,
                7,
                [0x31; 32],
            )
            .unwrap());
            assert!(tombstone_exists_by_nonce_or_digest_v1(
                &connection,
                namespace,
                signer,
                8,
                [0x32; 32],
            )
            .unwrap());
        }
        drop(authority);
        let reopened = SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap();
        assert_eq!(reopened.retained_tombstones_v1().unwrap(), 2);
        assert_eq!(reopened.retained_rows().unwrap(), 2);
        drop(reopened);
        cleanup_v1(&path);
    }

    #[test]
    fn reserved_and_handed_off_rows_are_never_compacted_v1() {
        let path = temp_path_v1();
        let namespace = [0x51; 32];
        let signer = [0x52; 32];
        let mut authority = SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap();
        insert_terminal_v1(
            &authority,
            signer,
            1,
            [0x53; 32],
            STATE_RESERVED_V0,
            0,
            [0; 32],
        );
        insert_terminal_v1(
            &authority,
            signer,
            2,
            [0x54; 32],
            STATE_HANDED_OFF_V0,
            0,
            [0; 32],
        );
        let result = authority.compact_terminal_rows_v1(16).unwrap();
        assert_eq!(result.compacted(), 0);
        assert_eq!(authority.retained_tombstones_v1().unwrap(), 0);
        assert_eq!(authority.retained_rows().unwrap(), 2);
        drop(authority);
        cleanup_v1(&path);
    }

    #[test]
    fn only_verified_nonce_floor_can_purge_compact_tombstones_v1() {
        let path = temp_path_v1();
        let namespace = [0x61; 32];
        let signer = [0x62; 32];
        let signer_id = CanonicalSignerId::from_bytes(signer).unwrap();
        let mut authority = SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap();
        insert_terminal_v1(
            &authority,
            signer,
            3,
            [0x63; 32],
            STATE_COMMITTED_V0,
            44,
            [0x64; 32],
        );
        insert_terminal_v1(
            &authority,
            signer,
            4,
            [0x65; 32],
            STATE_RELEASED_V0,
            0,
            [0; 32],
        );
        authority.compact_terminal_rows_v1(16).unwrap();
        let evidence = TxAdmissionReplayFloorEvidenceV1::new(
            namespace,
            signer_id,
            4,
            Height::new(100),
            StateRoot::new([0x66; 32]),
            [0x67; 32],
            [0x68; 32],
        )
        .unwrap();
        assert_eq!(
            evidence.verify_with(&RejectFloorV1).unwrap_err(),
            TxAdmissionWalErrorV0::CommitReadbackUnavailable
        );
        assert_eq!(authority.retained_tombstones_v1().unwrap(), 2);
        let verified = evidence.verify_with(&AcceptFloorV1).unwrap();
        let result = authority
            .purge_tombstones_with_replay_floor_v1(&verified, 16)
            .unwrap();
        assert_eq!(result.purged(), 2);
        assert_eq!(result.retained_tombstones(), 0);
        assert_eq!(authority.retained_rows().unwrap(), 0);
        drop(authority);
        cleanup_v1(&path);
    }

    #[test]
    fn tombstone_digest_tamper_fails_closed_on_reopen_v1() {
        let path = temp_path_v1();
        let namespace = [0x71; 32];
        let signer = [0x72; 32];
        let mut authority = SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap();
        insert_terminal_v1(
            &authority,
            signer,
            9,
            [0x73; 32],
            STATE_RELEASED_V0,
            0,
            [0; 32],
        );
        authority.compact_terminal_rows_v1(1).unwrap();
        drop(authority);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE tx_admission_tombstone_v1 SET tombstone_digest = ?1",
                params![[0xFFu8; 32].as_slice()],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap_err(),
            TxAdmissionWalErrorV0::Malformed
        );
        cleanup_v1(&path);
    }
}
