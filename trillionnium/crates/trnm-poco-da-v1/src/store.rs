//! Durable local transaction-batch availability state machine.
//!
//! This module deliberately ends at a local candidate kernel. It does not
//! contain a network server, a validator vote path, or a production signer.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};

use crate::{
    codec::{checksum, strict_decode},
    error::{error, DaErrorCodeV1, DaErrorV1, DaResultV1},
    retrieval::{
        complete_response_v1, prepare_full_range_response_v1, verify_full_range_proof_v1,
        RetrievalProofV1, RetrievalRequestV1, RetrievalRequesterAuthorityV1,
        RetrievalResponseIntentV1, RetrievalResponseV1, VerifiedRetrievalProofV1,
    },
    types::{
        AvailabilityCertificateV1, BatchIdV1, DaAttestationBodyV1, DaAttestationV1,
        DaBatchAuthorV1, DaBatchEnvelopeV1, DaCommitteeDescriptorV1, DaObligationV1, DaPolicyV1,
        Hash32V1, UnsignedTransactionBatchV1,
    },
};

const STORE_SCHEMA_VERSION_V1: i64 = 2;
const META_SQL: &str = "CREATE TABLE da_metadata_v1 (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), schema_version INTEGER NOT NULL, scope_id BLOB NOT NULL CHECK (length(scope_id) = 32), store_id BLOB NOT NULL CHECK (length(store_id) = 32), config_hash BLOB NOT NULL CHECK (length(config_hash) = 32), sequence BLOB NOT NULL CHECK (length(sequence) = 8), queue_batches BLOB NOT NULL CHECK (length(queue_batches) = 8), queue_bytes BLOB NOT NULL CHECK (length(queue_bytes) = 8), attestation_high_watermark BLOB NOT NULL CHECK (length(attestation_high_watermark) = 8), row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32))";
const AUTHOR_SQL: &str = "CREATE TABLE da_author_state_v1 (author_id BLOB PRIMARY KEY, last_sequence BLOB NOT NULL CHECK (length(last_sequence) = 8), outstanding_batches BLOB NOT NULL CHECK (length(outstanding_batches) = 8), outstanding_bytes BLOB NOT NULL CHECK (length(outstanding_bytes) = 8))";
const BATCH_SQL: &str = "CREATE TABLE da_batches_v1 (batch_id BLOB PRIMARY KEY CHECK (length(batch_id) = 32), conflict_key BLOB NOT NULL UNIQUE CHECK (length(conflict_key) = 32), envelope BLOB NOT NULL, author BLOB NOT NULL, content BLOB, chunks BLOB, content_len BLOB NOT NULL CHECK (length(content_len) = 8), durable_manifest_checksum BLOB NOT NULL CHECK (length(durable_manifest_checksum) = 32), state INTEGER NOT NULL CHECK (state BETWEEN 0 AND 3), certificate BLOB, obligation BLOB, repair_revision BLOB NOT NULL CHECK (length(repair_revision) = 8), row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32))";
const ATTESTATION_SQL: &str = "CREATE TABLE da_attestations_v1 (conflict_key BLOB PRIMARY KEY CHECK (length(conflict_key) = 32), batch_id BLOB NOT NULL CHECK (length(batch_id) = 32), attestor_id BLOB NOT NULL CHECK (length(attestor_id) = 32), attestation_sequence BLOB NOT NULL CHECK (length(attestation_sequence) = 8), body BLOB NOT NULL, signature BLOB, row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32), UNIQUE(attestor_id, attestation_sequence))";
const TOMBSTONE_SQL: &str = "CREATE TABLE da_gc_tombstones_v1 (batch_id BLOB PRIMARY KEY CHECK (length(batch_id) = 32), finalized_height BLOB NOT NULL CHECK (length(finalized_height) = 8), row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32))";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum BatchAvailabilityStateV1 {
    Stored = 0,
    Unavailable = 1,
    Certified = 2,
    GarbageCollected = 3,
}

impl BatchAvailabilityStateV1 {
    fn from_i64(value: i64) -> DaResultV1<Self> {
        match value {
            0 => Ok(Self::Stored),
            1 => Ok(Self::Unavailable),
            2 => Ok(Self::Certified),
            3 => Ok(Self::GarbageCollected),
            _ => Err(error(
                DaErrorCodeV1::TamperDetected,
                "unknown persisted DA availability state",
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DaStoreConfigV1 {
    path: PathBuf,
    scope_id: Hash32V1,
    store_id: Hash32V1,
    committee: DaCommitteeDescriptorV1,
    policy: DaPolicyV1,
    local_attestor_id: Hash32V1,
    config_hash: Hash32V1,
}

impl DaStoreConfigV1 {
    pub fn new(
        path: impl Into<PathBuf>,
        scope_id: Hash32V1,
        store_id: Hash32V1,
        committee: DaCommitteeDescriptorV1,
        policy: DaPolicyV1,
        local_attestor_id: Hash32V1,
    ) -> DaResultV1<Self> {
        committee.validate()?;
        policy.validate(&committee)?;
        if committee.member(local_attestor_id).is_none() {
            return Err(error(
                DaErrorCodeV1::InvalidCommittee,
                "local attestor is not in the committed committee",
            ));
        }
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(error(
                DaErrorCodeV1::InvalidBounds,
                "DA store path must not be empty",
            ));
        }
        let committee_bytes = committee.canonical_bytes()?;
        let policy_bytes = policy.canonical_bytes()?;
        let config_hash = checksum(&[
            b"trnm.poco-ai.da-store-config.candidate.v1",
            scope_id.as_bytes(),
            store_id.as_bytes(),
            local_attestor_id.as_bytes(),
            &committee_bytes,
            &policy_bytes,
        ]);
        Ok(Self {
            path,
            scope_id,
            store_id,
            committee,
            policy,
            local_attestor_id,
            config_hash,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn scope_id(&self) -> Hash32V1 {
        self.scope_id
    }

    pub const fn store_id(&self) -> Hash32V1 {
        self.store_id
    }

    pub const fn local_attestor_id(&self) -> Hash32V1 {
        self.local_attestor_id
    }

    pub fn committee(&self) -> &DaCommitteeDescriptorV1 {
        &self.committee
    }

    pub fn policy(&self) -> &DaPolicyV1 {
        &self.policy
    }
}

#[derive(Debug)]
pub struct PocoDaStoreV1 {
    config: DaStoreConfigV1,
}

/// Exact local DA head observed through a fresh authenticated read-only open.
///
/// DA v1 currently has an attestation journal and monotonic store sequence,
/// but not a global application-style state tree.  The metadata and journal
/// roots below therefore bind this local candidate only; they are not a
/// whole-node checkpoint or anti-rollback authority.
#[derive(Debug, Eq, PartialEq)]
pub struct DaFreshReadbackV1 {
    context: crate::types::ProtocolContextV1,
    scope_id: Hash32V1,
    store_id: Hash32V1,
    store_schema_version: u16,
    sequence: u64,
    durable_metadata_root: Hash32V1,
    attestation_journal_tail_root: Hash32V1,
}

impl DaFreshReadbackV1 {
    pub const fn context(&self) -> &crate::types::ProtocolContextV1 {
        &self.context
    }

    pub const fn scope_id(&self) -> Hash32V1 {
        self.scope_id
    }

    pub const fn store_id(&self) -> Hash32V1 {
        self.store_id
    }

    pub const fn store_schema_version(&self) -> u16 {
        self.store_schema_version
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn durable_metadata_root(&self) -> Hash32V1 {
        self.durable_metadata_root
    }

    pub const fn attestation_journal_tail_root(&self) -> Hash32V1 {
        self.attestation_journal_tail_root
    }
}

/// One immutable SQLite snapshot containing both the complete local DA head
/// and one certified-batch projection.
///
/// Keeping these facts in one carrier prevents the caller from accidentally
/// joining a head from one read transaction with certificate facts from a
/// later transaction. It remains a local readback, not anti-rollback or
/// cross-store authority.
#[derive(Debug, Eq, PartialEq)]
pub struct DaCertifiedBatchFreshReadbackV1 {
    head: DaFreshReadbackV1,
    batch: CertifiedBatchFactsV1,
}

impl DaCertifiedBatchFreshReadbackV1 {
    pub const fn head(&self) -> &DaFreshReadbackV1 {
        &self.head
    }

    pub const fn batch(&self) -> CertifiedBatchFactsV1 {
        self.batch
    }
}

#[derive(Debug)]
pub struct DurableAttestationIntentV1 {
    store_id: Hash32V1,
    conflict_key: Hash32V1,
    body: DaAttestationBodyV1,
}

/// Linear proof that chain finality, all retention holds, and the external
/// whole-node checkpoint authorized one exact local deletion.
///
/// This candidate crate intentionally has no production constructor. The only
/// issuer is test-only, so downstream code cannot delete bytes until a later
/// Node/CAS tranche provides the real authority path.
#[derive(Debug)]
pub struct FinalizedGcPermitV1 {
    store_id: Hash32V1,
    batch_id: BatchIdV1,
    obligation_id: crate::types::DaObligationIdV1,
    obligation_version: u64,
    current_epoch: u64,
    finalized_height: u64,
    checkpoint_digest: Hash32V1,
}

impl DurableAttestationIntentV1 {
    pub fn body(&self) -> &DaAttestationBodyV1 {
        &self.body
    }

    pub fn signing_root(&self) -> DaResultV1<Hash32V1> {
        DaAttestationV1::signing_root(&self.body)
    }
}

#[derive(Debug)]
pub enum AttestationPreparationOutcomeV1 {
    Prepared(DurableAttestationIntentV1),
    Existing(DaAttestationV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchAdmissionOutcomeV1 {
    Inserted,
    Existing,
}

#[derive(Clone, Debug)]
pub struct CertifiedBatchV1 {
    batch_id: BatchIdV1,
    certificate: AvailabilityCertificateV1,
    obligation: DaObligationV1,
}

impl CertifiedBatchV1 {
    pub const fn batch_id(&self) -> BatchIdV1 {
        self.batch_id
    }

    pub fn certificate(&self) -> &AvailabilityCertificateV1 {
        &self.certificate
    }

    pub fn obligation(&self) -> &DaObligationV1 {
        &self.obligation
    }
}

/// Canonical identifier projection for a freshly confirmed certified batch.
///
/// The type is returned by the DA store; callers cannot silently reinterpret
/// another plane's 32-byte identifier as a DA certificate or obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertifiedBatchFactsV1 {
    batch_id: BatchIdV1,
    certificate_id: crate::types::AvailabilityCertificateIdV1,
    obligation_id: crate::types::DaObligationIdV1,
    obligation_version: u64,
    obligation_status: u8,
}

impl CertifiedBatchFactsV1 {
    pub const fn batch_id(&self) -> BatchIdV1 {
        self.batch_id
    }

    pub const fn certificate_id(&self) -> crate::types::AvailabilityCertificateIdV1 {
        self.certificate_id
    }

    pub const fn obligation_id(&self) -> crate::types::DaObligationIdV1 {
        self.obligation_id
    }

    pub const fn obligation_version(&self) -> u64 {
        self.obligation_version
    }

    pub const fn obligation_status(&self) -> u8 {
        self.obligation_status
    }
}

impl CertifiedBatchV1 {
    pub const fn facts(&self) -> CertifiedBatchFactsV1 {
        CertifiedBatchFactsV1 {
            batch_id: self.batch_id,
            certificate_id: self.obligation.certificate_id(),
            obligation_id: self.obligation.obligation_id(),
            obligation_version: self.obligation.version(),
            obligation_status: self.obligation.status(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LocalRetrievalV1 {
    batch_id: BatchIdV1,
    offset: u64,
    total_length: u64,
    bytes: Vec<u8>,
    certificate: AvailabilityCertificateV1,
}

impl LocalRetrievalV1 {
    pub const fn batch_id(&self) -> BatchIdV1 {
        self.batch_id
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub const fn total_length(&self) -> u64 {
        self.total_length
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn certificate(&self) -> &AvailabilityCertificateV1 {
        &self.certificate
    }
}

#[derive(Debug)]
struct BatchRowV1 {
    batch_id: BatchIdV1,
    conflict_key: Hash32V1,
    envelope: Vec<u8>,
    author: Vec<u8>,
    content: Option<Vec<u8>>,
    chunks: Option<Vec<u8>>,
    content_len: u64,
    durable_manifest_checksum: Hash32V1,
    state: BatchAvailabilityStateV1,
    certificate: Option<Vec<u8>>,
    obligation: Option<Vec<u8>>,
    repair_revision: u64,
    row_checksum: Hash32V1,
}

type MetadataRowRawV1 = (
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);
type BatchRowRawV1 = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
);
type AttestationRowRawV1 = (Vec<u8>, Option<Vec<u8>>, Vec<u8>);
type AttestationRowV1 = (Vec<u8>, Option<Vec<u8>>, Hash32V1);

impl PocoDaStoreV1 {
    pub fn open(config: DaStoreConfigV1) -> DaResultV1<Self> {
        if let Some(parent) = config.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|cause| {
                    error(
                        DaErrorCodeV1::StoreFailure,
                        format!("failed to create DA store parent: {cause}"),
                    )
                })?;
            }
        }
        reject_sidecars(&config.path)?;
        let existed = config.path.exists();
        if existed {
            let read_only = Connection::open_with_flags(
                &config.path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            verify_schema(&read_only)?;
            verify_metadata(&read_only, &config)?;
        }
        let connection = open_rw_raw(&config.path, !existed)?;
        if existed {
            verify_schema(&connection)?;
            verify_metadata(&connection, &config)?;
        }
        configure_rw(&connection)?;
        if existed {
            verify_schema(&connection)?;
            verify_metadata(&connection, &config)?;
        } else {
            create_schema(&connection, &config)?;
        }
        drop(connection);
        let store = Self { config };
        store.audit_all()?;
        Ok(store)
    }

    /// Open and fully audit an already-created store without creating a
    /// parent directory, database, schema, migration, or writable SQLite
    /// handle.
    ///
    /// The path must name a regular file directly. Missing paths, symlinks
    /// and non-regular filesystem objects are rejected before SQLite is
    /// opened.
    pub fn open_existing(config: DaStoreConfigV1) -> DaResultV1<Self> {
        require_existing_regular_store(&config.path)?;
        reject_sidecars(&config.path)?;
        let store = Self { config };
        store.audit_all()?;
        require_existing_regular_store(&store.config.path)?;
        reject_sidecars(&store.config.path)?;
        Ok(store)
    }

    pub fn config(&self) -> &DaStoreConfigV1 {
        &self.config
    }

    pub fn admit_batch(
        &self,
        batch: &UnsignedTransactionBatchV1,
        author: &DaBatchAuthorV1,
    ) -> DaResultV1<BatchAdmissionOutcomeV1> {
        batch.verify_exact(&self.config.committee, &self.config.policy)?;
        author.verify(batch.envelope())?;
        let authority = self
            .config
            .policy
            .authority(batch.envelope().author_id())
            .ok_or_else(|| {
                error(
                    DaErrorCodeV1::UnauthorizedAuthor,
                    "batch author is not committed in the DA policy",
                )
            })?;
        if authority.public_key() != author_public_key(author) {
            return Err(error(
                DaErrorCodeV1::UnauthorizedAuthor,
                "author signature key differs from committed authority",
            ));
        }
        let batch_id = batch.batch_id();
        let envelope = batch.envelope().canonical_bytes()?;
        let author_bytes = author.canonical_bytes()?;
        let content = batch.content_bytes().to_vec();
        let chunks = batch.chunks_bytes()?;
        let conflict_key = author_conflict_key(
            self.config.scope_id,
            batch.envelope().author_id(),
            batch.envelope().author_sequence(),
        );
        let content_len = u64::try_from(content.len()).map_err(|_| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "batch content length exceeds u64",
            )
        })?;
        let durable_manifest_checksum = durable_manifest_checksum(
            &self.config,
            batch_id,
            conflict_key,
            &envelope,
            &author_bytes,
            &content,
            &chunks,
            content_len,
        );

        let mut connection = self.open_rw_verified()?;
        let transaction = connection.transaction()?;
        if let Some(existing) = load_batch_by_conflict(&transaction, conflict_key)? {
            verify_batch_row_checksum(&self.config, &existing)?;
            if existing.batch_id == batch_id
                && existing.envelope == envelope
                && existing.author == author_bytes
                && existing.content.as_deref() == Some(content.as_slice())
                && existing.chunks.as_deref() == Some(chunks.as_slice())
            {
                transaction.rollback()?;
                self.confirm_batch_exact(batch_id)?;
                return Ok(BatchAdmissionOutcomeV1::Existing);
            }
            return Err(error(
                DaErrorCodeV1::SequenceConflict,
                "author sequence already binds a different batch",
            ));
        }

        let author_state = load_author_state(&transaction, batch.envelope().author_id())?;
        let expected_sequence = match author_state.as_ref() {
            Some(state) => state.0.checked_add(1).ok_or_else(|| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "author sequence overflow",
                )
            })?,
            None => authority.first_sequence(),
        };
        if batch.envelope().author_sequence() != expected_sequence
            || expected_sequence > authority.maximum_sequence()
        {
            return Err(error(
                DaErrorCodeV1::SequenceConflict,
                "batch is not the exact next author sequence",
            ));
        }
        let (_, outstanding_batches, outstanding_bytes) =
            author_state.unwrap_or((expected_sequence.saturating_sub(1), 0, 0));
        let next_outstanding_batches = outstanding_batches.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "author outstanding count overflow",
            )
        })?;
        let next_outstanding_bytes =
            outstanding_bytes.checked_add(content_len).ok_or_else(|| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "author outstanding bytes overflow",
                )
            })?;
        if next_outstanding_batches > u64::from(authority.max_outstanding_sequences())
            || next_outstanding_bytes > authority.max_author_bytes()
        {
            return Err(error(
                DaErrorCodeV1::QuotaExceeded,
                "author outstanding DA quota exceeded",
            ));
        }
        let metadata = load_metadata(&transaction, &self.config)?;
        let next_queue_batches = metadata
            .1
            .checked_add(1)
            .ok_or_else(|| error(DaErrorCodeV1::ArithmeticOverflow, "DA queue count overflow"))?;
        let next_queue_bytes = metadata
            .2
            .checked_add(content_len)
            .ok_or_else(|| error(DaErrorCodeV1::ArithmeticOverflow, "DA queue bytes overflow"))?;
        if next_queue_batches > u64::from(self.config.policy.max_queue_batches())
            || next_queue_bytes > self.config.policy.max_queue_bytes()
        {
            return Err(error(
                DaErrorCodeV1::QueueFull,
                "bounded DA queue capacity exceeded",
            ));
        }
        let next_sequence = metadata.0.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "DA store sequence overflow",
            )
        })?;
        let row_checksum = batch_row_checksum(
            &self.config,
            batch_id,
            conflict_key,
            &envelope,
            &author_bytes,
            Some(&content),
            Some(&chunks),
            content_len,
            durable_manifest_checksum,
            BatchAvailabilityStateV1::Stored,
            None,
            None,
            0,
        );
        transaction.execute(
            "INSERT INTO da_batches_v1 (batch_id, conflict_key, envelope, author, content, chunks, content_len, durable_manifest_checksum, state, certificate, obligation, repair_revision, row_checksum) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL, ?10, ?11)",
            params![
                batch_id.as_bytes().as_slice(),
                conflict_key.as_bytes().as_slice(),
                envelope,
                author_bytes,
                content,
                chunks,
                u64_bytes(content_len),
                durable_manifest_checksum.as_bytes().as_slice(),
                BatchAvailabilityStateV1::Stored as i64,
                u64_bytes(0),
                row_checksum.as_bytes().as_slice(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO da_author_state_v1 (author_id, last_sequence, outstanding_batches, outstanding_bytes) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(author_id) DO UPDATE SET last_sequence=excluded.last_sequence, outstanding_batches=excluded.outstanding_batches, outstanding_bytes=excluded.outstanding_bytes",
            params![
                batch.envelope().author_id(),
                u64_bytes(expected_sequence),
                u64_bytes(next_outstanding_batches),
                u64_bytes(next_outstanding_bytes),
            ],
        )?;
        write_metadata(
            &transaction,
            &self.config,
            next_sequence,
            next_queue_batches,
            next_queue_bytes,
            metadata.3,
        )?;
        transaction.commit()?;
        drop(connection);
        self.confirm_batch_exact(batch_id)?;
        Ok(BatchAdmissionOutcomeV1::Inserted)
    }

    pub fn prepare_attestation(
        &self,
        batch_id: BatchIdV1,
        attestation_sequence: u64,
    ) -> DaResultV1<AttestationPreparationOutcomeV1> {
        if attestation_sequence == 0 {
            return Err(error(
                DaErrorCodeV1::InvalidBounds,
                "attestation sequence must be positive",
            ));
        }
        let mut connection = self.open_rw_verified()?;
        let transaction = connection.transaction()?;
        let row = load_batch_by_id(&transaction, batch_id)?
            .ok_or_else(|| error(DaErrorCodeV1::NotFound, "batch is not stored locally"))?;
        let batch = verify_live_batch_row(&self.config, &row)?;
        if matches!(
            row.state,
            BatchAvailabilityStateV1::Unavailable | BatchAvailabilityStateV1::GarbageCollected
        ) {
            return Err(error(
                DaErrorCodeV1::InvalidState,
                "unavailable or garbage-collected batch cannot be attested",
            ));
        }
        let body = DaAttestationBodyV1::new(
            batch.envelope(),
            batch_id,
            self.config.local_attestor_id,
            attestation_sequence,
            row.durable_manifest_checksum,
        );
        let conflict_key = body.conflict_coordinate()?;
        if let Some((stored_body, signature, stored_checksum)) =
            load_attestation(&transaction, conflict_key)?
        {
            let expected = attestation_row_checksum(
                self.config.config_hash,
                conflict_key,
                batch_id,
                self.config.local_attestor_id,
                attestation_sequence,
                &stored_body,
                signature.as_deref(),
            );
            if expected != stored_checksum || stored_body != body.canonical_bytes()? {
                return Err(error(
                    DaErrorCodeV1::Conflict,
                    "attestation conflict coordinate binds different durable facts",
                ));
            }
            if let Some(signature) = signature {
                transaction.rollback()?;
                let existing =
                    DaAttestationV1::from_signature(&self.config.committee, body, signature)?;
                return Ok(AttestationPreparationOutcomeV1::Existing(existing));
            }
            transaction.rollback()?;
            return Ok(AttestationPreparationOutcomeV1::Prepared(
                DurableAttestationIntentV1 {
                    store_id: self.config.store_id,
                    conflict_key,
                    body,
                },
            ));
        }
        let metadata = load_metadata(&transaction, &self.config)?;
        let expected_sequence = metadata.3.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "attestation sequence overflow",
            )
        })?;
        if attestation_sequence != expected_sequence {
            return Err(error(
                DaErrorCodeV1::SequenceConflict,
                "attestation is not the exact next local sequence",
            ));
        }
        let body_bytes = body.canonical_bytes()?;
        let next_sequence = metadata.0.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "DA store sequence overflow",
            )
        })?;
        let row_checksum = attestation_row_checksum(
            self.config.config_hash,
            conflict_key,
            batch_id,
            self.config.local_attestor_id,
            attestation_sequence,
            &body_bytes,
            None,
        );
        transaction.execute(
            "INSERT INTO da_attestations_v1 (conflict_key, batch_id, attestor_id, attestation_sequence, body, signature, row_checksum) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
            params![
                conflict_key.as_bytes().as_slice(),
                batch_id.as_bytes().as_slice(),
                self.config.local_attestor_id.as_bytes().as_slice(),
                u64_bytes(attestation_sequence),
                body_bytes,
                row_checksum.as_bytes().as_slice(),
            ],
        )?;
        write_metadata(
            &transaction,
            &self.config,
            next_sequence,
            metadata.1,
            metadata.2,
            attestation_sequence,
        )?;
        transaction.commit()?;
        drop(connection);
        self.confirm_unsigned_attestation(conflict_key, &body)?;
        Ok(AttestationPreparationOutcomeV1::Prepared(
            DurableAttestationIntentV1 {
                store_id: self.config.store_id,
                conflict_key,
                body,
            },
        ))
    }

    pub fn complete_attestation(
        &self,
        intent: DurableAttestationIntentV1,
        signature: Vec<u8>,
    ) -> DaResultV1<DaAttestationV1> {
        if intent.store_id != self.config.store_id {
            return Err(error(
                DaErrorCodeV1::Conflict,
                "durable attestation intent belongs to a different store",
            ));
        }
        let attestation = DaAttestationV1::from_signature(
            &self.config.committee,
            intent.body.clone(),
            signature.clone(),
        )?;
        let mut connection = self.open_rw_verified()?;
        let transaction = connection.transaction()?;
        let (body, existing_signature, stored_checksum) =
            load_attestation(&transaction, intent.conflict_key)?.ok_or_else(|| {
                error(
                    DaErrorCodeV1::InvalidState,
                    "durable attestation intent is missing",
                )
            })?;
        let batch_row =
            load_batch_by_id(&transaction, intent.body.batch_id())?.ok_or_else(|| {
                error(
                    DaErrorCodeV1::TamperDetected,
                    "attestation completion references a missing batch",
                )
            })?;
        verify_live_batch_row(&self.config, &batch_row)?;
        if matches!(
            batch_row.state,
            BatchAvailabilityStateV1::Unavailable | BatchAvailabilityStateV1::GarbageCollected
        ) || intent.body.storage_record_checksum() != batch_row.durable_manifest_checksum
        {
            return Err(error(
                DaErrorCodeV1::InvalidState,
                "attestation completion requires the exact live durable manifest",
            ));
        }
        let body_bytes = intent.body.canonical_bytes()?;
        let expected_unsigned = attestation_row_checksum(
            self.config.config_hash,
            intent.conflict_key,
            intent.body.batch_id(),
            self.config.local_attestor_id,
            intent.body.attestation_sequence(),
            &body,
            existing_signature.as_deref(),
        );
        if body != body_bytes || expected_unsigned != stored_checksum {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "durable attestation intent readback mismatch",
            ));
        }
        if let Some(existing) = existing_signature {
            if existing == signature {
                transaction.rollback()?;
                return Ok(attestation);
            }
            return Err(error(
                DaErrorCodeV1::Conflict,
                "attestation coordinate already has a different signature",
            ));
        }
        let metadata = load_metadata(&transaction, &self.config)?;
        let next_sequence = metadata.0.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "DA store sequence overflow",
            )
        })?;
        let signed_checksum = attestation_row_checksum(
            self.config.config_hash,
            intent.conflict_key,
            intent.body.batch_id(),
            self.config.local_attestor_id,
            intent.body.attestation_sequence(),
            &body_bytes,
            Some(&signature),
        );
        transaction.execute(
            "UPDATE da_attestations_v1 SET signature=?1, row_checksum=?2 WHERE conflict_key=?3",
            params![
                signature,
                signed_checksum.as_bytes().as_slice(),
                intent.conflict_key.as_bytes().as_slice(),
            ],
        )?;
        write_metadata(
            &transaction,
            &self.config,
            next_sequence,
            metadata.1,
            metadata.2,
            metadata.3,
        )?;
        transaction.commit()?;
        drop(connection);
        self.confirm_signed_attestation(intent.conflict_key, &attestation)?;
        Ok(attestation)
    }

    pub fn admit_certificate(
        &self,
        certificate: &AvailabilityCertificateV1,
    ) -> DaResultV1<CertifiedBatchV1> {
        certificate.verify(&self.config.committee)?;
        let batch_id = certificate.envelope().batch_id()?;
        let certificate_bytes = certificate.canonical_bytes()?;
        let mut connection = self.open_rw_verified()?;
        let transaction = connection.transaction()?;
        let mut row = load_batch_by_id(&transaction, batch_id)?.ok_or_else(|| {
            error(
                DaErrorCodeV1::NotFound,
                "certificate batch is not stored locally",
            )
        })?;
        let batch = verify_live_batch_row(&self.config, &row)?;
        let stored_author: DaBatchAuthorV1 = strict_decode(&row.author)?;
        if batch.envelope() != certificate.envelope()
            || &stored_author != certificate.author()
            || row.state == BatchAvailabilityStateV1::Unavailable
            || row.state == BatchAvailabilityStateV1::GarbageCollected
        {
            return Err(error(
                DaErrorCodeV1::Conflict,
                "certificate does not exactly bind an available local batch",
            ));
        }
        if let Some(existing) = &row.certificate {
            if existing != &certificate_bytes {
                return Err(error(
                    DaErrorCodeV1::Conflict,
                    "batch already binds another certificate",
                ));
            }
            let obligation: DaObligationV1 =
                strict_decode(row.obligation.as_deref().ok_or_else(|| {
                    error(
                        DaErrorCodeV1::TamperDetected,
                        "certified batch is missing retention obligation",
                    )
                })?)?;
            obligation.validate()?;
            transaction.rollback()?;
            return Ok(CertifiedBatchV1 {
                batch_id,
                certificate: certificate.clone(),
                obligation,
            });
        }
        let obligation = DaObligationV1::certificate_minimum(
            batch_id,
            certificate.certificate_id(),
            certificate.envelope().retention_end_epoch(),
        )?;
        let obligation_bytes = obligation.canonical_bytes()?;
        let metadata = load_metadata(&transaction, &self.config)?;
        let next_queue_batches = metadata
            .1
            .checked_sub(1)
            .ok_or_else(|| error(DaErrorCodeV1::TamperDetected, "DA queue count underflow"))?;
        let next_queue_bytes = metadata
            .2
            .checked_sub(row.content_len)
            .ok_or_else(|| error(DaErrorCodeV1::TamperDetected, "DA queue bytes underflow"))?;
        decrement_author_outstanding(&transaction, batch.envelope().author_id(), row.content_len)?;
        row.state = BatchAvailabilityStateV1::Certified;
        row.certificate = Some(certificate_bytes);
        row.obligation = Some(obligation_bytes);
        row.row_checksum = batch_row_checksum_from_row(&self.config, &row);
        persist_batch_dynamic(&transaction, &row)?;
        let next_sequence = metadata.0.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "DA store sequence overflow",
            )
        })?;
        write_metadata(
            &transaction,
            &self.config,
            next_sequence,
            next_queue_batches,
            next_queue_bytes,
            metadata.3,
        )?;
        transaction.commit()?;
        drop(connection);
        let confirmed = self.certified_batch(batch_id)?;
        if confirmed.certificate != *certificate || confirmed.obligation != obligation {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "fresh certificate/obligation readback mismatch",
            ));
        }
        Ok(confirmed)
    }

    pub fn certified_batch(&self, batch_id: BatchIdV1) -> DaResultV1<CertifiedBatchV1> {
        let connection = self.open_ro_verified()?;
        self.certified_batch_from_connection(&connection, batch_id)
    }

    fn certified_batch_from_connection(
        &self,
        connection: &Connection,
        batch_id: BatchIdV1,
    ) -> DaResultV1<CertifiedBatchV1> {
        let row = load_batch_by_id(connection, batch_id)?
            .ok_or_else(|| error(DaErrorCodeV1::NotFound, "certified batch not found"))?;
        verify_batch_row_checksum(&self.config, &row)?;
        if row.state != BatchAvailabilityStateV1::Certified {
            return Err(error(
                DaErrorCodeV1::InvalidState,
                "batch is not locally certified",
            ));
        }
        let certificate: AvailabilityCertificateV1 =
            strict_decode(row.certificate.as_deref().ok_or_else(|| {
                error(
                    DaErrorCodeV1::TamperDetected,
                    "certified batch is missing certificate",
                )
            })?)?;
        certificate.verify(&self.config.committee)?;
        let obligation: DaObligationV1 =
            strict_decode(row.obligation.as_deref().ok_or_else(|| {
                error(
                    DaErrorCodeV1::TamperDetected,
                    "certified batch is missing obligation",
                )
            })?)?;
        obligation.validate()?;
        if certificate.envelope().batch_id()? != batch_id
            || obligation.batch_id() != batch_id
            || obligation.certificate_id() != certificate.certificate_id()
        {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "certificate/obligation binding mismatch",
            ));
        }
        Ok(CertifiedBatchV1 {
            batch_id,
            certificate,
            obligation,
        })
    }

    /// Reopen and authenticate the complete local DA store, then project its
    /// monotonic metadata and attestation-journal tail.
    pub fn fresh_readback(&self) -> DaResultV1<DaFreshReadbackV1> {
        let mut connection = self.open_ro_verified()?;
        let transaction = connection.transaction()?;
        let readback = self.fresh_readback_from_connection(&transaction)?;
        transaction.rollback()?;
        Ok(readback)
    }

    /// Read one certified batch and the complete DA head from one explicit
    /// read transaction. No writer can splice a different certificate row
    /// between these two projections within this sample.
    pub fn fresh_certified_batch_readback(
        &self,
        batch_id: BatchIdV1,
    ) -> DaResultV1<DaCertifiedBatchFreshReadbackV1> {
        let mut connection = self.open_ro_verified()?;
        let transaction = connection.transaction()?;
        let head = self.fresh_readback_from_connection(&transaction)?;
        let batch = self
            .certified_batch_from_connection(&transaction, batch_id)?
            .facts();
        transaction.rollback()?;
        Ok(DaCertifiedBatchFreshReadbackV1 { head, batch })
    }

    fn fresh_readback_from_connection(
        &self,
        connection: &Connection,
    ) -> DaResultV1<DaFreshReadbackV1> {
        self.audit_all_connection(connection)?;
        let (sequence, queue_batches, queue_bytes, attestation_high_watermark) =
            load_metadata(connection, &self.config)?;
        let durable_metadata_root = checksum(&[
            b"trnm.poco-ai.da-fresh-metadata-readback.candidate.v1",
            &STORE_SCHEMA_VERSION_V1.to_le_bytes(),
            self.config.scope_id.as_bytes(),
            self.config.store_id.as_bytes(),
            self.config.config_hash.as_bytes(),
            &u64_bytes(sequence),
            &u64_bytes(queue_batches),
            &u64_bytes(queue_bytes),
            &u64_bytes(attestation_high_watermark),
        ]);
        let attestation_journal_tail_root = checksum(&[
            b"trnm.poco-ai.da-attestation-journal-tail.candidate.v1",
            self.config.config_hash.as_bytes(),
            &u64_bytes(attestation_high_watermark),
        ]);
        Ok(DaFreshReadbackV1 {
            context: self.config.committee.context().clone(),
            scope_id: self.config.scope_id,
            store_id: self.config.store_id,
            store_schema_version: u16::try_from(STORE_SCHEMA_VERSION_V1).map_err(|_| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "DA schema version exceeds u16",
                )
            })?,
            sequence,
            durable_metadata_root,
            attestation_journal_tail_root,
        })
    }

    pub fn retrieve(
        &self,
        batch_id: BatchIdV1,
        offset: u64,
        length: u64,
    ) -> DaResultV1<LocalRetrievalV1> {
        if length == 0 {
            return Err(error(
                DaErrorCodeV1::InvalidRange,
                "retrieval length must be positive",
            ));
        }
        let connection = self.open_ro_verified()?;
        let row = load_batch_by_id(&connection, batch_id)?
            .ok_or_else(|| error(DaErrorCodeV1::NotFound, "retrieval batch not found"))?;
        verify_batch_row_checksum(&self.config, &row)?;
        if row.state != BatchAvailabilityStateV1::Certified {
            return Err(error(
                DaErrorCodeV1::InvalidState,
                "retrieval requires a certified local batch",
            ));
        }
        let batch = verify_live_batch_row(&self.config, &row)?;
        let content = batch.content_bytes();
        let end = offset
            .checked_add(length)
            .ok_or_else(|| error(DaErrorCodeV1::InvalidRange, "retrieval range overflow"))?;
        let total_length = u64::try_from(content.len()).map_err(|_| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "retrieval content length exceeds u64",
            )
        })?;
        if end > total_length {
            return Err(error(
                DaErrorCodeV1::InvalidRange,
                "retrieval range exceeds exact batch length",
            ));
        }
        let start = usize::try_from(offset).map_err(|_| {
            error(
                DaErrorCodeV1::InvalidRange,
                "retrieval offset exceeds usize",
            )
        })?;
        let end = usize::try_from(end)
            .map_err(|_| error(DaErrorCodeV1::InvalidRange, "retrieval end exceeds usize"))?;
        let certificate: AvailabilityCertificateV1 =
            strict_decode(row.certificate.as_deref().ok_or_else(|| {
                error(
                    DaErrorCodeV1::TamperDetected,
                    "certified retrieval is missing certificate",
                )
            })?)?;
        certificate.verify(&self.config.committee)?;
        Ok(LocalRetrievalV1 {
            batch_id,
            offset,
            total_length,
            bytes: content[start..end].to_vec(),
            certificate,
        })
    }

    /// Prepare one signed-response preimage from a freshly authenticated,
    /// locally certified complete batch.
    ///
    /// The returned carrier is bound to this exact scope/store/config and is
    /// linear. It is a transport-independent candidate, not a network service
    /// or a durable responder-signing journal.
    pub fn prepare_full_range_retrieval_response_v1(
        &self,
        request: &RetrievalRequestV1,
        requester_authority: &RetrievalRequesterAuthorityV1,
        response_height: u64,
    ) -> DaResultV1<RetrievalResponseIntentV1> {
        let connection = self.open_ro_verified()?;
        let row = load_batch_by_id(&connection, request.body().batch_id())?
            .ok_or_else(|| error(DaErrorCodeV1::NotFound, "retrieval batch not found"))?;
        verify_batch_row_checksum(&self.config, &row)?;
        if row.state != BatchAvailabilityStateV1::Certified {
            return Err(error(
                DaErrorCodeV1::InvalidState,
                "signed retrieval response requires a certified local batch",
            ));
        }
        let batch = verify_live_batch_row(&self.config, &row)?;
        let certificate: AvailabilityCertificateV1 =
            strict_decode(row.certificate.as_deref().ok_or_else(|| {
                error(
                    DaErrorCodeV1::TamperDetected,
                    "signed retrieval response is missing the local certificate",
                )
            })?)?;
        certificate.verify(&self.config.committee)?;
        let stored_author: DaBatchAuthorV1 = strict_decode(&row.author)?;
        if certificate.certificate_id() != request.body().certificate_id()
            || certificate.envelope() != batch.envelope()
            || certificate.author() != &stored_author
        {
            return Err(error(
                DaErrorCodeV1::Conflict,
                "retrieval request differs from the exact local certificate",
            ));
        }
        let responder = self
            .config
            .committee
            .member(self.config.local_attestor_id)
            .ok_or_else(|| {
                error(
                    DaErrorCodeV1::InvalidCommittee,
                    "local retrieval responder is absent from the committee",
                )
            })?;
        prepare_full_range_response_v1(
            self.config.scope_id,
            self.config.store_id,
            self.config.config_hash,
            request,
            requester_authority,
            response_height,
            &batch,
            &certificate,
            responder,
        )
    }

    /// Reauthenticate the exact response preimage immediately before a
    /// caller-supplied responder signature can escape this store.
    pub fn complete_full_range_retrieval_response_v1(
        &self,
        intent: RetrievalResponseIntentV1,
        signature: Vec<u8>,
    ) -> DaResultV1<RetrievalResponseV1> {
        if intent.scope_id != self.config.scope_id
            || intent.store_id != self.config.store_id
            || intent.config_hash != self.config.config_hash
        {
            return Err(error(
                DaErrorCodeV1::Conflict,
                "retrieval response intent belongs to a different store configuration",
            ));
        }
        let refreshed = self.prepare_full_range_retrieval_response_v1(
            &intent.request,
            &intent.requester_authority,
            intent.response_height(),
        )?;
        if !intent.exact_payload_eq(&refreshed) {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "retrieval response intent differs from fresh certified bytes",
            ));
        }
        complete_response_v1(intent, signature)
    }

    /// Verify one signed full-range proof against this store's immutable
    /// committee/policy/config and return a non-copyable repair carrier.
    pub fn verify_full_range_retrieval_proof_v1(
        &self,
        proof: &RetrievalProofV1,
        requester_authority: &RetrievalRequesterAuthorityV1,
        validation_height: u64,
    ) -> DaResultV1<VerifiedRetrievalProofV1> {
        verify_full_range_proof_v1(
            proof,
            &self.config.committee,
            &self.config.policy,
            requester_authority,
            validation_height,
            self.config.scope_id,
            self.config.store_id,
            self.config.config_hash,
        )
    }

    /// Consume an exact proof carrier to repair only the unavailable local row
    /// bound to the same certificate, then re-read every byte and certificate
    /// through the ordinary certified retrieval path. `current_height` is an
    /// explicit candidate input; only a later Node owner can make it an
    /// authoritative finalized-height source.
    pub fn repair_from_verified_retrieval_v1(
        &self,
        verified: VerifiedRetrievalProofV1,
        current_height: u64,
    ) -> DaResultV1<BatchAvailabilityStateV1> {
        if verified.scope_id != self.config.scope_id
            || verified.store_id != self.config.store_id
            || verified.config_hash != self.config.config_hash
        {
            return Err(error(
                DaErrorCodeV1::InvalidRepair,
                "verified retrieval proof belongs to a different store configuration",
            ));
        }
        if current_height < verified.verified_at_height
            || current_height > verified.fresh_until_height
        {
            return Err(error(
                DaErrorCodeV1::InvalidRange,
                "verified retrieval proof is future-dated or stale at repair height",
            ));
        }
        let batch_id = verified.batch.batch_id();
        let expected_certificate_id = verified.certificate_id;
        {
            let connection = self.open_ro_verified()?;
            let row = load_batch_by_id(&connection, batch_id)?
                .ok_or_else(|| error(DaErrorCodeV1::NotFound, "repair batch not found"))?;
            verify_batch_row_checksum(&self.config, &row)?;
            if row.state != BatchAvailabilityStateV1::Unavailable {
                return Err(error(
                    DaErrorCodeV1::InvalidRepair,
                    "proof-driven repair requires an unavailable local batch",
                ));
            }
            let certificate: AvailabilityCertificateV1 =
                strict_decode(row.certificate.as_deref().ok_or_else(|| {
                    error(
                        DaErrorCodeV1::InvalidRepair,
                        "proof-driven repair requires the exact local certificate",
                    )
                })?)?;
            certificate.verify(&self.config.committee)?;
            if certificate.certificate_id() != expected_certificate_id
                || certificate.envelope().batch_id()? != batch_id
            {
                return Err(error(
                    DaErrorCodeV1::InvalidRepair,
                    "retrieval proof certificate differs from the unavailable row",
                ));
            }
        }

        let expected_content = verified.batch.content_bytes().to_vec();
        let expected_length = verified.batch.envelope().uncompressed_bytes();
        let state = self.repair_batch(&verified.batch, &verified.author)?;
        if state != BatchAvailabilityStateV1::Certified {
            return Err(error(
                DaErrorCodeV1::InvalidRepair,
                "proof-driven repair did not restore certified state",
            ));
        }
        let fresh = self.retrieve(batch_id, 0, expected_length)?;
        if fresh.batch_id() != batch_id
            || fresh.offset() != 0
            || fresh.total_length() != expected_length
            || fresh.bytes() != expected_content.as_slice()
            || fresh.certificate().certificate_id() != expected_certificate_id
        {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "proof-driven repair fresh readback differs",
            ));
        }
        Ok(state)
    }

    pub fn audit_batch(&self, batch_id: BatchIdV1) -> DaResultV1<BatchAvailabilityStateV1> {
        let connection = self.open_ro_verified()?;
        let row = load_batch_by_id(&connection, batch_id)?
            .ok_or_else(|| error(DaErrorCodeV1::NotFound, "audit batch not found"))?;
        if row.state == BatchAvailabilityStateV1::GarbageCollected {
            verify_batch_row_checksum(&self.config, &row)?;
            return Ok(row.state);
        }
        if verify_live_batch_row(&self.config, &row).is_ok() {
            return Ok(row.state);
        }
        drop(connection);
        self.latch_unavailable(row)?;
        Ok(BatchAvailabilityStateV1::Unavailable)
    }

    pub fn repair_batch(
        &self,
        batch: &UnsignedTransactionBatchV1,
        author: &DaBatchAuthorV1,
    ) -> DaResultV1<BatchAvailabilityStateV1> {
        batch.verify_exact(&self.config.committee, &self.config.policy)?;
        author.verify(batch.envelope())?;
        let batch_id = batch.batch_id();
        let mut connection = self.open_rw_verified()?;
        let transaction = connection.transaction()?;
        let mut row = load_batch_by_id(&transaction, batch_id)?
            .ok_or_else(|| error(DaErrorCodeV1::NotFound, "repair batch not found"))?;
        if row.state != BatchAvailabilityStateV1::Unavailable {
            return Err(error(
                DaErrorCodeV1::InvalidRepair,
                "only an unavailable batch can be repaired",
            ));
        }
        let expected_conflict = author_conflict_key(
            self.config.scope_id,
            batch.envelope().author_id(),
            batch.envelope().author_sequence(),
        );
        if row.conflict_key != expected_conflict {
            return Err(error(
                DaErrorCodeV1::InvalidRepair,
                "repair changes the author conflict coordinate",
            ));
        }
        let authority = self
            .config
            .policy
            .authority(batch.envelope().author_id())
            .ok_or_else(|| {
                error(
                    DaErrorCodeV1::UnauthorizedAuthor,
                    "repair author is not committed",
                )
            })?;
        if authority.public_key() != author_public_key(author) {
            return Err(error(
                DaErrorCodeV1::UnauthorizedAuthor,
                "repair author key does not match authority",
            ));
        }
        let next_revision = row.repair_revision.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "repair revision overflow",
            )
        })?;
        let repaired_envelope = batch.envelope().canonical_bytes()?;
        let repaired_author = author.canonical_bytes()?;
        let repaired_content = batch.content_bytes().to_vec();
        let repaired_chunks = batch.chunks_bytes()?;
        let repaired_content_len = u64::try_from(repaired_content.len()).map_err(|_| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "repair content length exceeds u64",
            )
        })?;
        if durable_manifest_checksum(
            &self.config,
            row.batch_id,
            row.conflict_key,
            &repaired_envelope,
            &repaired_author,
            &repaired_content,
            &repaired_chunks,
            repaired_content_len,
        ) != row.durable_manifest_checksum
        {
            return Err(error(
                DaErrorCodeV1::InvalidRepair,
                "repair differs from the immutable durable manifest",
            ));
        }
        row.envelope = repaired_envelope;
        row.author = repaired_author;
        row.content = Some(repaired_content);
        row.chunks = Some(repaired_chunks);
        row.content_len = repaired_content_len;
        row.state = if row.certificate.is_some() {
            BatchAvailabilityStateV1::Certified
        } else {
            BatchAvailabilityStateV1::Stored
        };
        row.repair_revision = next_revision;
        row.row_checksum = batch_row_checksum_from_row(&self.config, &row);
        persist_batch_full(&transaction, &row)?;
        let metadata = load_metadata(&transaction, &self.config)?;
        let (queue_batches, queue_bytes) = if row.state == BatchAvailabilityStateV1::Certified {
            (
                metadata.1.checked_sub(1).ok_or_else(|| {
                    error(DaErrorCodeV1::TamperDetected, "repair queue underflow")
                })?,
                metadata.2.checked_sub(row.content_len).ok_or_else(|| {
                    error(DaErrorCodeV1::TamperDetected, "repair bytes underflow")
                })?,
            )
        } else {
            (metadata.1, metadata.2)
        };
        let next_sequence = metadata.0.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "DA store sequence overflow",
            )
        })?;
        write_metadata(
            &transaction,
            &self.config,
            next_sequence,
            queue_batches,
            queue_bytes,
            metadata.3,
        )?;
        transaction.commit()?;
        drop(connection);
        self.confirm_batch_exact(batch_id)?;
        Ok(row.state)
    }

    pub fn extend_retention(
        &self,
        batch_id: BatchIdV1,
        retain_until_epoch: u64,
        hold_until_height: u64,
    ) -> DaResultV1<DaObligationV1> {
        self.update_obligation(batch_id, |current| {
            current.extend(retain_until_epoch, hold_until_height)
        })
    }

    pub fn release_retention(
        &self,
        batch_id: BatchIdV1,
        current_epoch: u64,
        finalized_height: u64,
    ) -> DaResultV1<DaObligationV1> {
        self.update_obligation(batch_id, |current| {
            current.release(current_epoch, finalized_height)
        })
    }

    pub fn garbage_collect(&self, permit: FinalizedGcPermitV1) -> DaResultV1<DaObligationV1> {
        if permit.store_id != self.config.store_id {
            return Err(error(
                DaErrorCodeV1::Conflict,
                "GC permit belongs to a different store",
            ));
        }
        let batch_id = permit.batch_id;
        let mut connection = self.open_rw_verified()?;
        let transaction = connection.transaction()?;
        let mut row = load_batch_by_id(&transaction, batch_id)?
            .ok_or_else(|| error(DaErrorCodeV1::NotFound, "GC batch not found"))?;
        verify_batch_row_checksum(&self.config, &row)?;
        if row.state != BatchAvailabilityStateV1::Certified {
            return Err(error(
                DaErrorCodeV1::EarlyGarbageCollection,
                "GC requires a certified batch",
            ));
        }
        let obligation: DaObligationV1 =
            strict_decode(row.obligation.as_deref().ok_or_else(|| {
                error(
                    DaErrorCodeV1::TamperDetected,
                    "GC batch is missing obligation",
                )
            })?)?;
        obligation.validate()?;
        let expected_checkpoint = gc_checkpoint_digest(
            &self.config,
            batch_id,
            obligation.obligation_id(),
            obligation.version(),
            permit.current_epoch,
            permit.finalized_height,
        );
        if permit.obligation_id != obligation.obligation_id()
            || permit.obligation_version != obligation.version()
            || permit.checkpoint_digest != expected_checkpoint
        {
            return Err(error(
                DaErrorCodeV1::Conflict,
                "GC permit does not authorize the exact current obligation",
            ));
        }
        if permit.current_epoch <= obligation.retain_until_epoch()
            || permit.finalized_height <= obligation.hold_until_height()
        {
            return Err(error(
                DaErrorCodeV1::EarlyGarbageCollection,
                "GC bounds have not expired",
            ));
        }
        let obligation = obligation.garbage_collected(permit.finalized_height)?;
        row.obligation = Some(obligation.canonical_bytes()?);
        row.content = None;
        row.chunks = None;
        row.state = BatchAvailabilityStateV1::GarbageCollected;
        row.row_checksum = batch_row_checksum_from_row(&self.config, &row);
        persist_batch_full(&transaction, &row)?;
        let tombstone_checksum = checksum(&[
            b"trnm.poco-ai.da-gc-tombstone.candidate.v1",
            self.config.config_hash.as_bytes(),
            batch_id.as_bytes(),
            &u64_bytes(permit.finalized_height),
            row.row_checksum.as_bytes(),
        ]);
        transaction.execute(
            "INSERT INTO da_gc_tombstones_v1 (batch_id, finalized_height, row_checksum) VALUES (?1, ?2, ?3)",
            params![
                batch_id.as_bytes().as_slice(),
                u64_bytes(permit.finalized_height),
                tombstone_checksum.as_bytes().as_slice(),
            ],
        )?;
        let metadata = load_metadata(&transaction, &self.config)?;
        let next_sequence = metadata.0.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "DA store sequence overflow",
            )
        })?;
        write_metadata(
            &transaction,
            &self.config,
            next_sequence,
            metadata.1,
            metadata.2,
            metadata.3,
        )?;
        transaction.commit()?;
        drop(connection);
        self.confirm_gc(batch_id, permit.finalized_height, &obligation)?;
        Ok(obligation)
    }

    pub fn state(&self, batch_id: BatchIdV1) -> DaResultV1<BatchAvailabilityStateV1> {
        let connection = self.open_ro_verified()?;
        let row = load_batch_by_id(&connection, batch_id)?
            .ok_or_else(|| error(DaErrorCodeV1::NotFound, "batch state not found"))?;
        verify_batch_row_checksum(&self.config, &row)?;
        Ok(row.state)
    }

    fn update_obligation<F>(&self, batch_id: BatchIdV1, update: F) -> DaResultV1<DaObligationV1>
    where
        F: FnOnce(&DaObligationV1) -> DaResultV1<DaObligationV1>,
    {
        let mut connection = self.open_rw_verified()?;
        let transaction = connection.transaction()?;
        let mut row = load_batch_by_id(&transaction, batch_id)?
            .ok_or_else(|| error(DaErrorCodeV1::NotFound, "obligation batch not found"))?;
        verify_batch_row_checksum(&self.config, &row)?;
        if row.state != BatchAvailabilityStateV1::Certified {
            return Err(error(
                DaErrorCodeV1::InvalidState,
                "only a certified batch has an active obligation",
            ));
        }
        let current: DaObligationV1 =
            strict_decode(row.obligation.as_deref().ok_or_else(|| {
                error(
                    DaErrorCodeV1::TamperDetected,
                    "certified batch lacks obligation",
                )
            })?)?;
        current.validate()?;
        let next = update(&current)?;
        row.obligation = Some(next.canonical_bytes()?);
        row.row_checksum = batch_row_checksum_from_row(&self.config, &row);
        persist_batch_dynamic(&transaction, &row)?;
        let metadata = load_metadata(&transaction, &self.config)?;
        let next_sequence = metadata.0.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "DA store sequence overflow",
            )
        })?;
        write_metadata(
            &transaction,
            &self.config,
            next_sequence,
            metadata.1,
            metadata.2,
            metadata.3,
        )?;
        transaction.commit()?;
        drop(connection);
        let confirmed = self.certified_batch(batch_id)?.obligation;
        if confirmed != next {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "fresh obligation readback mismatch",
            ));
        }
        Ok(next)
    }

    fn latch_unavailable(&self, mut row: BatchRowV1) -> DaResultV1<()> {
        let mut connection = self.open_rw_verified()?;
        let transaction = connection.transaction()?;
        let fresh = load_batch_by_id(&transaction, row.batch_id)?
            .ok_or_else(|| error(DaErrorCodeV1::NotFound, "unavailable batch disappeared"))?;
        if fresh.state == BatchAvailabilityStateV1::GarbageCollected {
            return Err(error(
                DaErrorCodeV1::InvalidState,
                "garbage-collected batch cannot enter repair",
            ));
        }
        let metadata = load_metadata(&transaction, &self.config)?;
        let was_certified = fresh.state == BatchAvailabilityStateV1::Certified;
        let (queue_batches, queue_bytes) =
            if was_certified {
                let next_batches = metadata.1.checked_add(1).ok_or_else(|| {
                    error(DaErrorCodeV1::ArithmeticOverflow, "repair queue overflow")
                })?;
                let next_bytes = metadata.2.checked_add(fresh.content_len).ok_or_else(|| {
                    error(DaErrorCodeV1::ArithmeticOverflow, "repair bytes overflow")
                })?;
                if next_batches > u64::from(self.config.policy.max_queue_batches())
                    || next_bytes > self.config.policy.max_queue_bytes()
                {
                    return Err(error(
                        DaErrorCodeV1::QueueFull,
                        "bounded repair queue is full",
                    ));
                }
                (next_batches, next_bytes)
            } else {
                (metadata.1, metadata.2)
            };
        row = fresh;
        row.content = None;
        row.chunks = None;
        row.state = BatchAvailabilityStateV1::Unavailable;
        row.row_checksum = batch_row_checksum_from_row(&self.config, &row);
        persist_batch_full(&transaction, &row)?;
        let next_sequence = metadata.0.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "DA store sequence overflow",
            )
        })?;
        write_metadata(
            &transaction,
            &self.config,
            next_sequence,
            queue_batches,
            queue_bytes,
            metadata.3,
        )?;
        transaction.commit()?;
        drop(connection);
        if self.state(row.batch_id)? != BatchAvailabilityStateV1::Unavailable {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "unavailable latch fresh readback failed",
            ));
        }
        Ok(())
    }

    fn audit_all(&self) -> DaResultV1<()> {
        let connection = self.open_ro_verified()?;
        self.audit_all_connection(&connection)
    }

    fn audit_all_connection(&self, connection: &Connection) -> DaResultV1<()> {
        let mut statement =
            connection.prepare("SELECT batch_id FROM da_batches_v1 ORDER BY batch_id")?;
        let identifiers = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for bytes in identifiers {
            let id = BatchIdV1::from_hash(hash32(&bytes, "batch ID")?);
            let row = load_batch_by_id(connection, id)?.ok_or_else(|| {
                error(
                    DaErrorCodeV1::TamperDetected,
                    "enumerated batch disappeared",
                )
            })?;
            verify_batch_row_checksum(&self.config, &row)?;
            if !matches!(
                row.state,
                BatchAvailabilityStateV1::Unavailable | BatchAvailabilityStateV1::GarbageCollected
            ) {
                verify_live_batch_row(&self.config, &row)?;
            }
        }
        audit_attestation_rows(connection, &self.config)?;
        audit_tombstones(connection, &self.config)?;
        audit_accounting(connection, &self.config)?;
        Ok(())
    }

    fn confirm_batch_exact(&self, batch_id: BatchIdV1) -> DaResultV1<()> {
        let connection = self.open_ro_verified()?;
        let row = load_batch_by_id(&connection, batch_id)?.ok_or_else(|| {
            error(
                DaErrorCodeV1::TamperDetected,
                "committed batch missing on fresh connection",
            )
        })?;
        let batch = verify_live_batch_row(&self.config, &row)?;
        if batch.batch_id() != batch_id {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "fresh batch identity mismatch",
            ));
        }
        Ok(())
    }

    fn confirm_unsigned_attestation(
        &self,
        conflict_key: Hash32V1,
        body: &DaAttestationBodyV1,
    ) -> DaResultV1<()> {
        let connection = self.open_ro_verified()?;
        audit_attestation_rows(&connection, &self.config)?;
        let (stored_body, signature, stored_checksum) =
            load_attestation(&connection, conflict_key)?.ok_or_else(|| {
                error(
                    DaErrorCodeV1::TamperDetected,
                    "committed unsigned attestation missing",
                )
            })?;
        let body_bytes = body.canonical_bytes()?;
        let expected = attestation_row_checksum(
            self.config.config_hash,
            conflict_key,
            body.batch_id(),
            self.config.local_attestor_id,
            body.attestation_sequence(),
            &body_bytes,
            None,
        );
        if stored_body != body_bytes || signature.is_some() || stored_checksum != expected {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "unsigned attestation fresh readback mismatch",
            ));
        }
        Ok(())
    }

    fn confirm_signed_attestation(
        &self,
        conflict_key: Hash32V1,
        attestation: &DaAttestationV1,
    ) -> DaResultV1<()> {
        let connection = self.open_ro_verified()?;
        audit_attestation_rows(&connection, &self.config)?;
        let (body, signature, stored_checksum) = load_attestation(&connection, conflict_key)?
            .ok_or_else(|| {
                error(
                    DaErrorCodeV1::TamperDetected,
                    "committed signed attestation missing",
                )
            })?;
        let body_value: DaAttestationBodyV1 = strict_decode(&body)?;
        let signature = signature.ok_or_else(|| {
            error(
                DaErrorCodeV1::TamperDetected,
                "signed attestation lost signature",
            )
        })?;
        let rebuilt =
            DaAttestationV1::from_signature(&self.config.committee, body_value, signature.clone())?;
        let expected = attestation_row_checksum(
            self.config.config_hash,
            conflict_key,
            attestation.body().batch_id(),
            self.config.local_attestor_id,
            attestation.body().attestation_sequence(),
            &body,
            Some(&signature),
        );
        if rebuilt != *attestation || expected != stored_checksum {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "signed attestation fresh readback mismatch",
            ));
        }
        Ok(())
    }

    fn confirm_gc(
        &self,
        batch_id: BatchIdV1,
        finalized_height: u64,
        obligation: &DaObligationV1,
    ) -> DaResultV1<()> {
        let connection = self.open_ro_verified()?;
        let row = load_batch_by_id(&connection, batch_id)?
            .ok_or_else(|| error(DaErrorCodeV1::TamperDetected, "GC batch missing"))?;
        verify_batch_row_checksum(&self.config, &row)?;
        if row.state != BatchAvailabilityStateV1::GarbageCollected
            || row.content.is_some()
            || row.chunks.is_some()
            || strict_decode::<DaObligationV1>(row.obligation.as_deref().unwrap_or_default())?
                != *obligation
        {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "GC batch fresh readback mismatch",
            ));
        }
        let (height, stored_checksum): (Vec<u8>, Vec<u8>) = connection.query_row(
            "SELECT finalized_height, row_checksum FROM da_gc_tombstones_v1 WHERE batch_id=?1",
            params![batch_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let height = decode_u64(&height)?;
        let stored_checksum = hash32(&stored_checksum, "GC tombstone checksum")?;
        let expected = checksum(&[
            b"trnm.poco-ai.da-gc-tombstone.candidate.v1",
            self.config.config_hash.as_bytes(),
            batch_id.as_bytes(),
            &u64_bytes(finalized_height),
            row.row_checksum.as_bytes(),
        ]);
        if height != finalized_height || stored_checksum != expected {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "GC tombstone fresh readback mismatch",
            ));
        }
        Ok(())
    }

    fn open_rw_verified(&self) -> DaResultV1<Connection> {
        reject_sidecars(&self.config.path)?;
        let read_only = Connection::open_with_flags(
            &self.config.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        verify_schema(&read_only)?;
        verify_metadata(&read_only, &self.config)?;
        drop(read_only);
        let connection = open_rw_raw(&self.config.path, false)?;
        verify_schema(&connection)?;
        verify_metadata(&connection, &self.config)?;
        configure_rw(&connection)?;
        verify_schema(&connection)?;
        verify_metadata(&connection, &self.config)?;
        audit_attestation_rows(&connection, &self.config)?;
        Ok(connection)
    }

    fn open_ro_verified(&self) -> DaResultV1<Connection> {
        reject_sidecars(&self.config.path)?;
        let connection = Connection::open_with_flags(
            &self.config.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        verify_schema(&connection)?;
        verify_metadata(&connection, &self.config)?;
        Ok(connection)
    }

    #[cfg(test)]
    pub(crate) fn issue_gc_permit_for_test(
        &self,
        batch_id: BatchIdV1,
        current_epoch: u64,
        finalized_height: u64,
    ) -> DaResultV1<FinalizedGcPermitV1> {
        let connection = self.open_ro_verified()?;
        let row = load_batch_by_id(&connection, batch_id)?
            .ok_or_else(|| error(DaErrorCodeV1::NotFound, "GC permit batch not found"))?;
        verify_batch_row_checksum(&self.config, &row)?;
        let obligation: DaObligationV1 =
            strict_decode(row.obligation.as_deref().ok_or_else(|| {
                error(
                    DaErrorCodeV1::InvalidState,
                    "GC permit requires a retention obligation",
                )
            })?)?;
        obligation.validate()?;
        Ok(FinalizedGcPermitV1 {
            store_id: self.config.store_id,
            batch_id,
            obligation_id: obligation.obligation_id(),
            obligation_version: obligation.version(),
            current_epoch,
            finalized_height,
            checkpoint_digest: gc_checkpoint_digest(
                &self.config,
                batch_id,
                obligation.obligation_id(),
                obligation.version(),
                current_epoch,
                finalized_height,
            ),
        })
    }

    #[cfg(test)]
    pub(crate) fn corrupt_content_for_test(&self, batch_id: BatchIdV1) -> DaResultV1<()> {
        let connection = open_rw_raw(&self.config.path, false)?;
        connection.execute(
            "UPDATE da_batches_v1 SET content=?1 WHERE batch_id=?2",
            params![b"corrupt".as_slice(), batch_id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn rollback_submission_for_test(
        &self,
        batch: &UnsignedTransactionBatchV1,
    ) -> DaResultV1<()> {
        let mut connection = self.open_rw_verified()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO da_author_state_v1 (author_id, last_sequence, outstanding_batches, outstanding_bytes) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(author_id) DO UPDATE SET last_sequence=excluded.last_sequence",
            params![
                batch.envelope().author_id(),
                u64_bytes(batch.envelope().author_sequence()),
                u64_bytes(0),
                u64_bytes(0),
            ],
        )?;
        transaction.rollback()?;
        Ok(())
    }
}

fn author_public_key(author: &DaBatchAuthorV1) -> &[u8; 32] {
    author.public_key()
}

fn gc_checkpoint_digest(
    config: &DaStoreConfigV1,
    batch_id: BatchIdV1,
    obligation_id: crate::types::DaObligationIdV1,
    obligation_version: u64,
    current_epoch: u64,
    finalized_height: u64,
) -> Hash32V1 {
    checksum(&[
        b"trnm.poco-ai.da-gc-checkpoint-permit.candidate.v1",
        config.scope_id.as_bytes(),
        config.store_id.as_bytes(),
        config.config_hash.as_bytes(),
        batch_id.as_bytes(),
        obligation_id.as_bytes(),
        &u64_bytes(obligation_version),
        &u64_bytes(current_epoch),
        &u64_bytes(finalized_height),
    ])
}

fn open_rw_raw(path: &Path, allow_create: bool) -> DaResultV1<Connection> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if allow_create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    Ok(Connection::open_with_flags(path, flags)?)
}

fn configure_rw(connection: &Connection) -> DaResultV1<()> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    let mode: String = connection.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(error(
            DaErrorCodeV1::StoreFailure,
            "SQLite refused DELETE journal mode",
        ));
    }
    Ok(())
}

fn create_schema(connection: &Connection, config: &DaStoreConfigV1) -> DaResultV1<()> {
    connection.execute_batch(&format!(
        "BEGIN IMMEDIATE; {META_SQL}; {AUTHOR_SQL}; {BATCH_SQL}; {ATTESTATION_SQL}; {TOMBSTONE_SQL}; PRAGMA user_version={STORE_SCHEMA_VERSION_V1}; COMMIT;"
    ))?;
    let metadata_checksum = metadata_row_checksum(config, 0, 0, 0, 0);
    connection.execute(
        "INSERT INTO da_metadata_v1 (singleton, schema_version, scope_id, store_id, config_hash, sequence, queue_batches, queue_bytes, attestation_high_watermark, row_checksum) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            STORE_SCHEMA_VERSION_V1,
            config.scope_id.as_bytes().as_slice(),
            config.store_id.as_bytes().as_slice(),
            config.config_hash.as_bytes().as_slice(),
            u64_bytes(0),
            u64_bytes(0),
            u64_bytes(0),
            u64_bytes(0),
            metadata_checksum.as_bytes().as_slice(),
        ],
    )?;
    verify_schema(connection)?;
    verify_metadata(connection, config)
}

fn verify_schema(connection: &Connection) -> DaResultV1<()> {
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if user_version != STORE_SCHEMA_VERSION_V1 {
        return Err(error(
            DaErrorCodeV1::SchemaMismatch,
            "unexpected DA SQLite user_version; automatic migration is forbidden",
        ));
    }
    let mut statement = connection
        .prepare("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name")?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = vec![
        ("da_attestations_v1".to_owned(), ATTESTATION_SQL.to_owned()),
        ("da_author_state_v1".to_owned(), AUTHOR_SQL.to_owned()),
        ("da_batches_v1".to_owned(), BATCH_SQL.to_owned()),
        ("da_gc_tombstones_v1".to_owned(), TOMBSTONE_SQL.to_owned()),
        ("da_metadata_v1".to_owned(), META_SQL.to_owned()),
    ];
    if actual != expected {
        return Err(error(
            DaErrorCodeV1::SchemaMismatch,
            "DA SQLite schema differs from frozen candidate schema v1",
        ));
    }
    let extra_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view')",
        [],
        |row| row.get(0),
    )?;
    if extra_count != 0 {
        return Err(error(
            DaErrorCodeV1::SchemaMismatch,
            "DA store forbids triggers and views",
        ));
    }
    Ok(())
}

fn verify_metadata(connection: &Connection, config: &DaStoreConfigV1) -> DaResultV1<()> {
    let (
        schema,
        scope,
        store,
        config_hash,
        sequence,
        queue_batches,
        queue_bytes,
        attestation_high_watermark,
        stored_checksum,
    ): MetadataRowRawV1 = connection.query_row(
        "SELECT schema_version, scope_id, store_id, config_hash, sequence, queue_batches, queue_bytes, attestation_high_watermark, row_checksum FROM da_metadata_v1 WHERE singleton=1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
            ))
        },
    )?;
    if schema != STORE_SCHEMA_VERSION_V1
        || hash32(&scope, "scope ID")? != config.scope_id
        || hash32(&store, "store ID")? != config.store_id
        || hash32(&config_hash, "config hash")? != config.config_hash
    {
        return Err(error(
            DaErrorCodeV1::SchemaMismatch,
            "DA store metadata/config identity mismatch",
        ));
    }
    let sequence = decode_u64(&sequence)?;
    let queue_batches = decode_u64(&queue_batches)?;
    let queue_bytes = decode_u64(&queue_bytes)?;
    let attestation_high_watermark = decode_u64(&attestation_high_watermark)?;
    if hash32(&stored_checksum, "metadata row checksum")?
        != metadata_row_checksum(
            config,
            sequence,
            queue_batches,
            queue_bytes,
            attestation_high_watermark,
        )
    {
        return Err(error(
            DaErrorCodeV1::TamperDetected,
            "DA metadata row checksum mismatch",
        ));
    }
    Ok(())
}

fn load_metadata(
    connection: &Connection,
    config: &DaStoreConfigV1,
) -> DaResultV1<(u64, u64, u64, u64)> {
    verify_metadata(connection, config)?;
    let (sequence, queue_batches, queue_bytes, attestation_high_watermark): (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = connection.query_row(
        "SELECT sequence, queue_batches, queue_bytes, attestation_high_watermark FROM da_metadata_v1 WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok((
        decode_u64(&sequence)?,
        decode_u64(&queue_batches)?,
        decode_u64(&queue_bytes)?,
        decode_u64(&attestation_high_watermark)?,
    ))
}

fn write_metadata(
    transaction: &Transaction<'_>,
    config: &DaStoreConfigV1,
    sequence: u64,
    queue_batches: u64,
    queue_bytes: u64,
    attestation_high_watermark: u64,
) -> DaResultV1<()> {
    let row_checksum = metadata_row_checksum(
        config,
        sequence,
        queue_batches,
        queue_bytes,
        attestation_high_watermark,
    );
    if transaction.execute(
        "UPDATE da_metadata_v1 SET sequence=?1, queue_batches=?2, queue_bytes=?3, attestation_high_watermark=?4, row_checksum=?5 WHERE singleton=1",
        params![
            u64_bytes(sequence),
            u64_bytes(queue_batches),
            u64_bytes(queue_bytes),
            u64_bytes(attestation_high_watermark),
            row_checksum.as_bytes().as_slice(),
        ],
    )? != 1
    {
        return Err(error(
            DaErrorCodeV1::TamperDetected,
            "DA metadata singleton update failed",
        ));
    }
    Ok(())
}

fn metadata_row_checksum(
    config: &DaStoreConfigV1,
    sequence: u64,
    queue_batches: u64,
    queue_bytes: u64,
    attestation_high_watermark: u64,
) -> Hash32V1 {
    checksum(&[
        b"trnm.poco-ai.da-metadata-row.candidate.v1",
        &STORE_SCHEMA_VERSION_V1.to_le_bytes(),
        config.scope_id.as_bytes(),
        config.store_id.as_bytes(),
        config.config_hash.as_bytes(),
        &u64_bytes(sequence),
        &u64_bytes(queue_batches),
        &u64_bytes(queue_bytes),
        &u64_bytes(attestation_high_watermark),
    ])
}

fn load_author_state(
    connection: &Connection,
    author_id: &[u8],
) -> DaResultV1<Option<(u64, u64, u64)>> {
    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT last_sequence, outstanding_batches, outstanding_bytes FROM da_author_state_v1 WHERE author_id=?1",
            params![author_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    row.map(|(sequence, batches, bytes)| {
        Ok((
            decode_u64(&sequence)?,
            decode_u64(&batches)?,
            decode_u64(&bytes)?,
        ))
    })
    .transpose()
}

fn decrement_author_outstanding(
    transaction: &Transaction<'_>,
    author_id: &[u8],
    content_len: u64,
) -> DaResultV1<()> {
    let (last, batches, bytes) = load_author_state(transaction, author_id)?.ok_or_else(|| {
        error(
            DaErrorCodeV1::TamperDetected,
            "author accounting row is missing",
        )
    })?;
    let batches = batches.checked_sub(1).ok_or_else(|| {
        error(
            DaErrorCodeV1::TamperDetected,
            "author outstanding batch underflow",
        )
    })?;
    let bytes = bytes.checked_sub(content_len).ok_or_else(|| {
        error(
            DaErrorCodeV1::TamperDetected,
            "author outstanding byte underflow",
        )
    })?;
    transaction.execute(
        "UPDATE da_author_state_v1 SET last_sequence=?1, outstanding_batches=?2, outstanding_bytes=?3 WHERE author_id=?4",
        params![u64_bytes(last), u64_bytes(batches), u64_bytes(bytes), author_id],
    )?;
    Ok(())
}

fn load_batch_by_id(
    connection: &Connection,
    batch_id: BatchIdV1,
) -> DaResultV1<Option<BatchRowV1>> {
    load_batch(connection, "batch_id", batch_id.as_bytes())
}

fn load_batch_by_conflict(
    connection: &Connection,
    conflict_key: Hash32V1,
) -> DaResultV1<Option<BatchRowV1>> {
    load_batch(connection, "conflict_key", conflict_key.as_bytes())
}

fn load_batch(connection: &Connection, column: &str, key: &[u8]) -> DaResultV1<Option<BatchRowV1>> {
    if column != "batch_id" && column != "conflict_key" {
        return Err(error(
            DaErrorCodeV1::InvalidState,
            "invalid internal batch lookup column",
        ));
    }
    let sql = format!(
        "SELECT batch_id, conflict_key, envelope, author, content, chunks, content_len, durable_manifest_checksum, state, certificate, obligation, repair_revision, row_checksum FROM da_batches_v1 WHERE {column}=?1"
    );
    let raw: Option<BatchRowRawV1> = connection
        .query_row(&sql, params![key], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
            ))
        })
        .optional()?;
    raw.map(
        |(
            batch_id,
            conflict_key,
            envelope,
            author,
            content,
            chunks,
            content_len,
            durable_manifest_checksum,
            state,
            certificate,
            obligation,
            repair_revision,
            row_checksum,
        )| {
            Ok(BatchRowV1 {
                batch_id: BatchIdV1::from_hash(hash32(&batch_id, "batch ID")?),
                conflict_key: hash32(&conflict_key, "batch conflict key")?,
                envelope,
                author,
                content,
                chunks,
                content_len: decode_u64(&content_len)?,
                durable_manifest_checksum: hash32(
                    &durable_manifest_checksum,
                    "durable manifest checksum",
                )?,
                state: BatchAvailabilityStateV1::from_i64(state)?,
                certificate,
                obligation,
                repair_revision: decode_u64(&repair_revision)?,
                row_checksum: hash32(&row_checksum, "batch row checksum")?,
            })
        },
    )
    .transpose()
}

fn verify_batch_row_checksum(config: &DaStoreConfigV1, row: &BatchRowV1) -> DaResultV1<()> {
    if batch_row_checksum_from_row(config, row) != row.row_checksum {
        return Err(error(
            DaErrorCodeV1::TamperDetected,
            "DA batch row checksum mismatch",
        ));
    }
    Ok(())
}

fn verify_live_batch_row(
    config: &DaStoreConfigV1,
    row: &BatchRowV1,
) -> DaResultV1<UnsignedTransactionBatchV1> {
    verify_batch_row_checksum(config, row)?;
    let content = row.content.clone().ok_or_else(|| {
        error(
            DaErrorCodeV1::TamperDetected,
            "live DA batch is missing content",
        )
    })?;
    let chunks = row.chunks.as_deref().ok_or_else(|| {
        error(
            DaErrorCodeV1::TamperDetected,
            "live DA batch is missing chunks",
        )
    })?;
    if content.len() as u64 != row.content_len {
        return Err(error(
            DaErrorCodeV1::TamperDetected,
            "live DA content length mismatch",
        ));
    }
    let batch = UnsignedTransactionBatchV1::from_stored(
        &config.committee,
        &config.policy,
        &row.envelope,
        content,
        chunks,
    )?;
    let author: DaBatchAuthorV1 = strict_decode(&row.author)?;
    author.verify(batch.envelope())?;
    let authority = config
        .policy
        .authority(batch.envelope().author_id())
        .ok_or_else(|| {
            error(
                DaErrorCodeV1::UnauthorizedAuthor,
                "persisted author is absent from committed policy",
            )
        })?;
    if batch.batch_id() != row.batch_id
        || authority.public_key() != author_public_key(&author)
        || author_conflict_key(
            config.scope_id,
            batch.envelope().author_id(),
            batch.envelope().author_sequence(),
        ) != row.conflict_key
    {
        return Err(error(
            DaErrorCodeV1::TamperDetected,
            "live DA batch identity/conflict coordinate mismatch",
        ));
    }
    let expected_manifest = durable_manifest_checksum(
        config,
        row.batch_id,
        row.conflict_key,
        &row.envelope,
        &row.author,
        batch.content_bytes(),
        chunks,
        row.content_len,
    );
    if expected_manifest != row.durable_manifest_checksum {
        return Err(error(
            DaErrorCodeV1::TamperDetected,
            "live DA durable manifest checksum mismatch",
        ));
    }
    Ok(batch)
}

fn verify_envelope_row_minimum(
    config: &DaStoreConfigV1,
    row: &BatchRowV1,
) -> DaResultV1<DaBatchEnvelopeV1> {
    verify_batch_row_checksum(config, row)?;
    decode_envelope_row_minimum(config, row)
}

/// Decode and bind the immutable envelope/author columns without consulting
/// the row checksum.  `audit_batch` deliberately allows a content/checksum
/// drift to be latched into `Unavailable`; requiring the checksum here would
/// prevent that safety transition and leave a corrupted row permanently
/// unaudited.  Callers that require an intact row use
/// `verify_envelope_row_minimum`, which performs the checksum check first.
fn decode_envelope_row_minimum(
    config: &DaStoreConfigV1,
    row: &BatchRowV1,
) -> DaResultV1<DaBatchEnvelopeV1> {
    let envelope: DaBatchEnvelopeV1 = strict_decode(&row.envelope)?;
    envelope.validate_shape()?;
    let author: DaBatchAuthorV1 = strict_decode(&row.author)?;
    author.verify(&envelope)?;
    let authority = config
        .policy
        .authority(envelope.author_id())
        .ok_or_else(|| {
            error(
                DaErrorCodeV1::UnauthorizedAuthor,
                "persisted envelope author is absent from committed policy",
            )
        })?;
    if envelope.context() != config.committee.context()
        || envelope.epoch() != config.committee.epoch()
        || envelope.committee_id() != config.committee.committee_id()?
        || envelope.batch_id()? != row.batch_id
        || authority.public_key() != author_public_key(&author)
        || author_conflict_key(
            config.scope_id,
            envelope.author_id(),
            envelope.author_sequence(),
        ) != row.conflict_key
    {
        return Err(error(
            DaErrorCodeV1::TamperDetected,
            "persisted envelope/author/store context binding mismatch",
        ));
    }
    Ok(envelope)
}

fn persist_batch_dynamic(transaction: &Transaction<'_>, row: &BatchRowV1) -> DaResultV1<()> {
    transaction.execute(
        "UPDATE da_batches_v1 SET state=?1, certificate=?2, obligation=?3, repair_revision=?4, row_checksum=?5 WHERE batch_id=?6",
        params![
            row.state as i64,
            row.certificate,
            row.obligation,
            u64_bytes(row.repair_revision),
            row.row_checksum.as_bytes().as_slice(),
            row.batch_id.as_bytes().as_slice(),
        ],
    )?;
    Ok(())
}

fn persist_batch_full(transaction: &Transaction<'_>, row: &BatchRowV1) -> DaResultV1<()> {
    transaction.execute(
        "UPDATE da_batches_v1 SET envelope=?1, author=?2, content=?3, chunks=?4, content_len=?5, durable_manifest_checksum=?6, state=?7, certificate=?8, obligation=?9, repair_revision=?10, row_checksum=?11 WHERE batch_id=?12",
        params![
            row.envelope,
            row.author,
            row.content,
            row.chunks,
            u64_bytes(row.content_len),
            row.durable_manifest_checksum.as_bytes().as_slice(),
            row.state as i64,
            row.certificate,
            row.obligation,
            u64_bytes(row.repair_revision),
            row.row_checksum.as_bytes().as_slice(),
            row.batch_id.as_bytes().as_slice(),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn batch_row_checksum(
    config: &DaStoreConfigV1,
    batch_id: BatchIdV1,
    conflict_key: Hash32V1,
    envelope: &[u8],
    author: &[u8],
    content: Option<&[u8]>,
    chunks: Option<&[u8]>,
    content_len: u64,
    durable_manifest_checksum: Hash32V1,
    state: BatchAvailabilityStateV1,
    certificate: Option<&[u8]>,
    obligation: Option<&[u8]>,
    repair_revision: u64,
) -> Hash32V1 {
    checksum(&[
        b"trnm.poco-ai.da-batch-row.candidate.v1",
        config.config_hash.as_bytes(),
        batch_id.as_bytes(),
        conflict_key.as_bytes(),
        envelope,
        author,
        content.unwrap_or_default(),
        chunks.unwrap_or_default(),
        &u64_bytes(content_len),
        durable_manifest_checksum.as_bytes(),
        &(state as i64).to_le_bytes(),
        certificate.unwrap_or_default(),
        obligation.unwrap_or_default(),
        &u64_bytes(repair_revision),
    ])
}

fn batch_row_checksum_from_row(config: &DaStoreConfigV1, row: &BatchRowV1) -> Hash32V1 {
    batch_row_checksum(
        config,
        row.batch_id,
        row.conflict_key,
        &row.envelope,
        &row.author,
        row.content.as_deref(),
        row.chunks.as_deref(),
        row.content_len,
        row.durable_manifest_checksum,
        row.state,
        row.certificate.as_deref(),
        row.obligation.as_deref(),
        row.repair_revision,
    )
}

#[allow(clippy::too_many_arguments)]
fn durable_manifest_checksum(
    config: &DaStoreConfigV1,
    batch_id: BatchIdV1,
    conflict_key: Hash32V1,
    envelope: &[u8],
    author: &[u8],
    content: &[u8],
    chunks: &[u8],
    content_len: u64,
) -> Hash32V1 {
    checksum(&[
        b"trnm.poco-ai.da-durable-manifest.candidate.v1",
        config.config_hash.as_bytes(),
        batch_id.as_bytes(),
        conflict_key.as_bytes(),
        envelope,
        author,
        content,
        chunks,
        &u64_bytes(content_len),
    ])
}

fn load_attestation(
    connection: &Connection,
    conflict_key: Hash32V1,
) -> DaResultV1<Option<AttestationRowV1>> {
    let row: Option<AttestationRowRawV1> = connection
        .query_row(
            "SELECT body, signature, row_checksum FROM da_attestations_v1 WHERE conflict_key=?1",
            params![conflict_key.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    row.map(|(body, signature, checksum)| {
        Ok((body, signature, hash32(&checksum, "attestation checksum")?))
    })
    .transpose()
}

#[allow(clippy::too_many_arguments)]
fn attestation_row_checksum(
    config_hash: Hash32V1,
    conflict_key: Hash32V1,
    batch_id: BatchIdV1,
    attestor_id: Hash32V1,
    sequence: u64,
    body: &[u8],
    signature: Option<&[u8]>,
) -> Hash32V1 {
    checksum(&[
        b"trnm.poco-ai.da-attestation-row.candidate.v1",
        config_hash.as_bytes(),
        conflict_key.as_bytes(),
        batch_id.as_bytes(),
        attestor_id.as_bytes(),
        &u64_bytes(sequence),
        body,
        signature.unwrap_or_default(),
    ])
}

fn audit_attestation_rows(connection: &Connection, config: &DaStoreConfigV1) -> DaResultV1<()> {
    let mut statement = connection.prepare(
        "SELECT conflict_key, batch_id, attestor_id, attestation_sequence, body, signature, row_checksum FROM da_attestations_v1",
    )?;
    type JournalRowV1 = (
        Hash32V1,
        BatchIdV1,
        Hash32V1,
        u64,
        Vec<u8>,
        Option<Vec<u8>>,
        Hash32V1,
    );
    let mut rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        })?
        .map(|row| {
            let (conflict_key, batch_id, attestor_id, sequence, body, signature, checksum) = row?;
            Ok::<JournalRowV1, DaErrorV1>((
                hash32(&conflict_key, "attestation conflict key")?,
                BatchIdV1::from_hash(hash32(&batch_id, "batch ID")?),
                hash32(&attestor_id, "attestor ID")?,
                decode_u64(&sequence)?,
                body,
                signature,
                hash32(&checksum, "attestation checksum")?,
            ))
        })
        .collect::<DaResultV1<Vec<_>>>()?;
    rows.sort_by_key(|row| row.3);
    let mut last_sequence = 0u64;
    for (conflict_key, batch_id, attestor_id, sequence, body, signature, stored) in rows {
        let body_value: DaAttestationBodyV1 = strict_decode(&body)?;
        body_value.validate(&config.committee)?;
        if attestor_id != config.local_attestor_id
            || body_value.batch_id() != batch_id
            || body_value.attestor_id() != attestor_id
            || body_value.attestation_sequence() != sequence
            || body_value.conflict_coordinate()? != conflict_key
            || sequence
                != last_sequence.checked_add(1).ok_or_else(|| {
                    error(
                        DaErrorCodeV1::ArithmeticOverflow,
                        "attestation sequence audit overflow",
                    )
                })?
        {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "attestation journal sequence/binding mismatch",
            ));
        }
        let batch = load_batch_by_id(connection, batch_id)?.ok_or_else(|| {
            error(
                DaErrorCodeV1::TamperDetected,
                "attestation journal references a missing batch",
            )
        })?;
        // A content mutation is intentionally latched by `audit_batch`; the
        // row checksum may therefore already be stale while the immutable
        // envelope/author columns remain available for attestation binding.
        let envelope = decode_envelope_row_minimum(config, &batch)?;
        let expected_body = DaAttestationBodyV1::new(
            &envelope,
            batch_id,
            attestor_id,
            sequence,
            batch.durable_manifest_checksum,
        );
        if body_value != expected_body {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "attestation does not bind the exact persisted batch envelope/manifest",
            ));
        }
        if let Some(signature) = &signature {
            DaAttestationV1::from_signature(
                &config.committee,
                body_value.clone(),
                signature.clone(),
            )?;
        }
        let expected = attestation_row_checksum(
            config.config_hash,
            conflict_key,
            batch_id,
            attestor_id,
            sequence,
            &body,
            signature.as_deref(),
        );
        if expected != stored {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "attestation journal checksum mismatch",
            ));
        }
        last_sequence = sequence;
    }
    let high_watermark = load_metadata(connection, config)?.3;
    if last_sequence != high_watermark {
        return Err(error(
            DaErrorCodeV1::TamperDetected,
            "attestation journal tail differs from durable high-watermark",
        ));
    }
    Ok(())
}

fn audit_tombstones(connection: &Connection, config: &DaStoreConfigV1) -> DaResultV1<()> {
    let mut statement = connection.prepare(
        "SELECT batch_id, finalized_height, row_checksum FROM da_gc_tombstones_v1 ORDER BY batch_id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let batch_id = BatchIdV1::from_hash(hash32(&row.get::<_, Vec<u8>>(0)?, "batch ID")?);
        let finalized_height = decode_u64(&row.get::<_, Vec<u8>>(1)?)?;
        let stored = hash32(&row.get::<_, Vec<u8>>(2)?, "tombstone checksum")?;
        let batch = load_batch_by_id(connection, batch_id)?.ok_or_else(|| {
            error(
                DaErrorCodeV1::TamperDetected,
                "GC tombstone references missing batch",
            )
        })?;
        if batch.state != BatchAvailabilityStateV1::GarbageCollected {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "GC tombstone references live batch",
            ));
        }
        let expected = checksum(&[
            b"trnm.poco-ai.da-gc-tombstone.candidate.v1",
            config.config_hash.as_bytes(),
            batch_id.as_bytes(),
            &u64_bytes(finalized_height),
            batch.row_checksum.as_bytes(),
        ]);
        if expected != stored {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "GC tombstone checksum mismatch",
            ));
        }
    }
    Ok(())
}

fn audit_accounting(connection: &Connection, config: &DaStoreConfigV1) -> DaResultV1<()> {
    let metadata = load_metadata(connection, config)?;
    let mut statement =
        connection.prepare("SELECT batch_id FROM da_batches_v1 ORDER BY batch_id")?;
    let identifiers = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let mut queue_batches = 0u64;
    let mut queue_bytes = 0u64;
    let mut expected_authors: BTreeMap<Vec<u8>, (u64, u64, u64)> = BTreeMap::new();
    for raw_id in identifiers {
        let batch_id = BatchIdV1::from_hash(hash32(&raw_id, "accounting batch ID")?);
        let row = load_batch_by_id(connection, batch_id)?.ok_or_else(|| {
            error(
                DaErrorCodeV1::TamperDetected,
                "accounting batch disappeared",
            )
        })?;
        let envelope = verify_envelope_row_minimum(config, &row)?;
        let queued = matches!(
            row.state,
            BatchAvailabilityStateV1::Stored | BatchAvailabilityStateV1::Unavailable
        );
        if queued {
            queue_batches = queue_batches.checked_add(1).ok_or_else(|| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "queue audit count overflow",
                )
            })?;
            queue_bytes = queue_bytes.checked_add(row.content_len).ok_or_else(|| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "queue audit bytes overflow",
                )
            })?;
        }
        let entry = expected_authors
            .entry(envelope.author_id().to_vec())
            .or_insert((0, 0, 0));
        entry.0 = entry.0.max(envelope.author_sequence());
        if row.certificate.is_none() {
            entry.1 = entry.1.checked_add(1).ok_or_else(|| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "author audit count overflow",
                )
            })?;
            entry.2 = entry.2.checked_add(row.content_len).ok_or_else(|| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "author audit bytes overflow",
                )
            })?;
        }
    }
    if metadata.1 != queue_batches || metadata.2 != queue_bytes {
        return Err(error(
            DaErrorCodeV1::TamperDetected,
            "metadata queue accounting does not match durable batches",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT author_id, last_sequence, outstanding_batches, outstanding_bytes FROM da_author_state_v1 ORDER BY author_id",
    )?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if actual.len() != expected_authors.len() {
        return Err(error(
            DaErrorCodeV1::TamperDetected,
            "author accounting row count mismatch",
        ));
    }
    for (author_id, last, batches, bytes) in actual {
        let expected = expected_authors.get(&author_id).ok_or_else(|| {
            error(
                DaErrorCodeV1::TamperDetected,
                "unexpected author accounting row",
            )
        })?;
        if (
            decode_u64(&last)?,
            decode_u64(&batches)?,
            decode_u64(&bytes)?,
        ) != *expected
        {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "author accounting does not match durable batches",
            ));
        }
    }
    Ok(())
}

fn author_conflict_key(scope_id: Hash32V1, author_id: &[u8], sequence: u64) -> Hash32V1 {
    checksum(&[
        b"trnm.poco-ai.da-author-conflict-coordinate.candidate.v1",
        scope_id.as_bytes(),
        author_id,
        &u64_bytes(sequence),
    ])
}

fn hash32(bytes: &[u8], label: &str) -> DaResultV1<Hash32V1> {
    let value: [u8; 32] = bytes.try_into().map_err(|_| {
        error(
            DaErrorCodeV1::TamperDetected,
            format!("{label} is not 32 bytes"),
        )
    })?;
    Ok(Hash32V1::new(value))
}

fn u64_bytes(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

fn decode_u64(bytes: &[u8]) -> DaResultV1<u64> {
    let encoded: [u8; 8] = bytes.try_into().map_err(|_| {
        error(
            DaErrorCodeV1::TamperDetected,
            "persisted counter is not eight bytes",
        )
    })?;
    Ok(u64::from_le_bytes(encoded))
}

fn reject_sidecars(path: &Path) -> DaResultV1<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
        if sidecar.exists() {
            return Err(error(
                DaErrorCodeV1::StoreFailure,
                format!(
                    "unresolved SQLite sidecar is fail-closed: {}",
                    sidecar.display()
                ),
            ));
        }
    }
    Ok(())
}

fn require_existing_regular_store(path: &Path) -> DaResultV1<()> {
    let metadata = fs::symlink_metadata(path).map_err(|cause| {
        error(
            DaErrorCodeV1::StoreFailure,
            format!("existing DA store is unavailable: {cause}"),
        )
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(error(
            DaErrorCodeV1::StoreFailure,
            "existing DA store path must not be a symlink",
        ));
    }
    if !file_type.is_file() {
        return Err(error(
            DaErrorCodeV1::StoreFailure,
            "existing DA store path is not a regular file",
        ));
    }
    Ok(())
}
