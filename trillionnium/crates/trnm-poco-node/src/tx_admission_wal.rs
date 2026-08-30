//! Candidate node-owned durable pending-nonce admission authority.
//!
//! This module is deliberately feature-gated.  It is the first concrete
//! persistence boundary for the native PoCO transaction path, but it is not a
//! CheckTx implementation, an executor, a signer, or a broadcast loop.  The
//! default `trnm-poco-node` build does not compile this module and all package
//! production/activation flags remain false.
//!
//! The authority owns a SQLite database in WAL/FULL mode and an exclusive
//! sidecar lock.  A reservation row binds the complete key-free admission
//! metadata (`signer, nonce, tx digest, body digest, fee and resource limits`)
//! before the row is returned to the in-memory typed mempool.  Lifecycle
//! transitions are conditional and idempotent at the durable boundary:
//!
//! ```text
//! Reserved --handoff--> HandedOff --commit--> Committed
//!      \____________________release________________/  Released
//! ```
//!
//! A restart may retry an exact `Reserved` row.  A durable `HandedOff` row is
//! intentionally ambiguous because execution may have happened after the
//! handoff and before its commit acknowledgement; opening the authority then
//! fails closed.  A future node recovery owner must perform an application
//! readback before adding an explicit resolution API.  This module does not
//! guess, delete, or rewrite such rows.  In particular, this WAL rejects a
//! `HandedOff` -> `Released` transition: dropping a handoff token leaves the
//! durable ambiguity in place, and only authenticated receipt recovery may
//! resolve it.
//!
//! Once a terminal row has an authenticated native receipt (or an explicit
//! released state), the candidate tombstone-GC extension may compact it into a
//! digest-bound replay tombstone.  Physical purge still requires a private
//! application/finality nonce-floor token; no production admission or GC path
//! is enabled by this feature.

#![cfg(feature = "tx-admission-wal")]

use std::{
    cell::RefCell,
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    rc::Rc,
    time::Duration,
};

use fs2::FileExt;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_application_tx_builder_v0::{BuiltCanonicalTxAdmissionViewV0, BuiltCanonicalTxV0};
use trnm_consensus_types::{BlockId, FinalityProofV0, Height, StateRoot};
use trnm_mempool::{
    AdmissionReject, CanonicalSignerId, IngressClass, PendingNonceAdmission, PendingNonceAuthority,
    PendingNonceReservation, PendingNonceReservationState, SignedAdmissionHooks,
    SignedEnvelopeMetadata, SignedEnvelopeView, TypedAdmissionGate, TypedAdmitOutcome,
    DEFAULT_MAX_ADMISSION_BODY_BYTES,
};
use trnm_native_application::BlockIdV0;
use trnm_native_execution_v0::DurableNativeApplicationV0;

/// This is a runnable composition seam only.  It does not imply a node
/// runtime or a production admission path.
pub const TX_ADMISSION_WAL_RUNTIME_COMPOSITION_V0: bool = true;
pub const TX_ADMISSION_WAL_PRODUCTION_ACTIVATION_V0: bool = false;

/// The node-owned boundary composes the typed builder view, the in-memory
/// admission gate, and this durable nonce authority.  It intentionally does
/// not expose a CheckTx, signer, executor, RPC, or broadcast operation.
pub const TX_ADMISSION_BOUNDARY_RUNTIME_COMPOSITION_V0: bool = true;
pub const TX_ADMISSION_BOUNDARY_PRODUCTION_ACTIVATION_V0: bool = false;
pub const TX_ADMISSION_BOUNDARY_CHECKTX_V0: bool = false;
/// The candidate owner now exposes a real, signature-checked CheckTx seam.
/// This is deliberately distinct from the production activation flag above:
/// it still requires an explicit node owner, durable WAL, and later execution
/// readback before it can be considered a production contract.
#[allow(dead_code)]
pub const TX_ADMISSION_BOUNDARY_CHECKTX_CANDIDATE_V0: bool = true;
/// An explicit node-owned signer identity resolver is required for the
/// candidate CheckTx seam. The resolver is composition-only and does not
/// imply that a production account registry or signer runtime is wired.
pub const TX_ADMISSION_BOUNDARY_SIGNER_RESOLVER_V0: bool = true;
pub const TX_ADMISSION_BOUNDARY_SIGNER_RESOLVER_PRODUCTION_V0: bool = false;
/// A node-owned chain/time context seam is available for candidate CheckTx.
/// It is not yet wired to the authoritative block clock in a production node.
pub const TX_ADMISSION_BOUNDARY_CONTEXT_RESOLVER_V0: bool = true;
pub const TX_ADMISSION_BOUNDARY_CONTEXT_RESOLVER_PRODUCTION_V0: bool = false;
/// An explicit, authenticated restart-recovery seam exists for durable
/// `HandedOff` rows.  It only accepts exact metadata plus a receipt token
/// minted by [`NativeCommitReceiptEvidenceV0::verify_with`]; it is not a
/// production activation or an automatic ambiguity resolver.
pub const TX_ADMISSION_BOUNDARY_HANDOFF_RECOVERY_V0: bool = true;
pub const TX_ADMISSION_BOUNDARY_HANDOFF_RECOVERY_PRODUCTION_V0: bool = false;
pub const TX_ADMISSION_BOUNDARY_SIGNING_V0: bool = false;
pub const TX_ADMISSION_BOUNDARY_BROADCAST_V0: bool = false;
/// A typed application/finality readback boundary exists behind the candidate
/// feature. It is not wired into CheckTx, broadcast, or production startup.
#[allow(dead_code)]
pub const TX_ADMISSION_BOUNDARY_COMMIT_RECEIPT_V0: bool = true;
#[allow(dead_code)]
pub const TX_ADMISSION_BOUNDARY_COMMIT_RECEIPT_PRODUCTION_V0: bool = false;
/// The candidate now has a concrete native-application readback verifier. It
/// joins the exact admitted outer/inner envelope to a committed native P row,
/// state root, receipt commitment, and independently verified PoCO proof. It
/// remains composition-only until a production node owns the application and
/// finality proof lifetimes.
pub const TX_ADMISSION_BOUNDARY_NATIVE_READBACK_V0: bool = true;
pub const TX_ADMISSION_BOUNDARY_NATIVE_READBACK_PRODUCTION_V0: bool = false;

// Version 2 adds the authenticated replay-tombstone table.  There is no
// implicit in-place migration: an existing v1 file is rejected so replay
// history can never be lost during an upgrade.
const SCHEMA_VERSION_V0: i64 = 2;
const WAL_DOMAIN_V0: &[u8] = b"trnm.poco-node.tx-admission-wal.v0";
const LOCK_SUFFIX_V0: &str = ".tx-admission.lock.v0";
const MAX_RESERVATION_ROWS_V0: usize = 1_000_000;

const STATE_RESERVED_V0: i64 = 0;
const STATE_HANDED_OFF_V0: i64 = 1;
const STATE_COMMITTED_V0: i64 = 2;
const STATE_RELEASED_V0: i64 = 3;
const COMMIT_RECEIPT_DOMAIN_V0: &[u8] = b"trnm.poco-node.tx-commit-receipt.v0";

// Keep the durable WAL schema closed over the exact tables and constraints
// that the authority relies on.  SQLite strips `IF NOT EXISTS` from the
// stored SQL text, so the canonical form intentionally uses plain CREATE
// TABLE statements and is compared after whitespace normalization.
const SQLITE_SCHEMA_DDL_V0: &str = r#"
CREATE TABLE tx_admission_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL,
    namespace BLOB NOT NULL CHECK(length(namespace) = 32)
);
CREATE TABLE pending_nonce (
    namespace BLOB NOT NULL CHECK(length(namespace) = 32),
    signer BLOB NOT NULL CHECK(length(signer) = 32),
    nonce BLOB NOT NULL CHECK(length(nonce) = 8),
    digest BLOB NOT NULL CHECK(length(digest) = 32),
    body_digest BLOB NOT NULL CHECK(length(body_digest) = 32),
    fee_limit BLOB NOT NULL CHECK(length(fee_limit) = 16),
    max_gas BLOB NOT NULL CHECK(length(max_gas) = 8),
    max_bytes BLOB NOT NULL CHECK(length(max_bytes) = 8),
    state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3)),
    PRIMARY KEY(namespace, signer, nonce),
    UNIQUE(namespace, digest)
);
CREATE TABLE tx_commit_receipt_v0 (
    namespace BLOB NOT NULL CHECK(length(namespace) = 32),
    signer BLOB NOT NULL CHECK(length(signer) = 32),
    nonce BLOB NOT NULL CHECK(length(nonce) = 8),
    tx_digest BLOB NOT NULL CHECK(length(tx_digest) = 32),
    block_id BLOB NOT NULL CHECK(length(block_id) = 32),
    block_height BLOB NOT NULL CHECK(length(block_height) = 8),
    state_root BLOB NOT NULL CHECK(length(state_root) = 32),
    receipt_digest BLOB NOT NULL CHECK(length(receipt_digest) = 32),
    finality_proof_digest BLOB NOT NULL CHECK(length(finality_proof_digest) = 32),
    commitment BLOB NOT NULL CHECK(length(commitment) = 32),
    PRIMARY KEY(namespace, signer, nonce),
    UNIQUE(namespace, tx_digest)
);
CREATE TABLE tx_admission_tombstone_v1 (
    namespace BLOB NOT NULL CHECK(length(namespace) = 32),
    signer BLOB NOT NULL CHECK(length(signer) = 32),
    nonce BLOB NOT NULL CHECK(length(nonce) = 8),
    tx_digest BLOB NOT NULL CHECK(length(tx_digest) = 32),
    terminal_state INTEGER NOT NULL CHECK(terminal_state IN (2, 3)),
    terminal_height BLOB NOT NULL CHECK(length(terminal_height) = 8),
    receipt_commitment BLOB NOT NULL CHECK(length(receipt_commitment) = 32),
    tombstone_digest BLOB NOT NULL CHECK(length(tombstone_digest) = 32),
    PRIMARY KEY(namespace, signer, nonce),
    UNIQUE(namespace, tx_digest),
    UNIQUE(namespace, tombstone_digest)
);
"#;

type RawAdmissionRowV0 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);
type RawReceiptRowV0 = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

/// Coarse fail-closed errors for the candidate WAL.  The error text is not an
/// authority signal; callers should branch on the variant only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxAdmissionWalErrorV0 {
    Io,
    InvalidPath,
    InvalidNamespace,
    LockUnavailable,
    PathReplaced,
    Sqlite,
    SchemaMismatch,
    NamespaceMismatch,
    Malformed,
    TooLarge,
    Replay,
    ReservationConflict,
    AmbiguousHandoff,
    CommitReceiptMismatch,
    CommitReceiptConflict,
    CommitReadbackUnavailable,
    /// The caller attempted restart-handoff inspection or resolution through
    /// a boundary that was not opened with the explicit recovery constructor.
    HandoffRecoveryUnavailable,
}

impl fmt::Display for TxAdmissionWalErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io => "transaction admission WAL I/O failed",
            Self::InvalidPath => "transaction admission WAL path is invalid",
            Self::InvalidNamespace => "transaction admission WAL namespace is invalid",
            Self::LockUnavailable => "transaction admission WAL is already owned",
            Self::PathReplaced => "transaction admission WAL path identity changed",
            Self::Sqlite => "transaction admission WAL SQLite operation failed",
            Self::SchemaMismatch => "transaction admission WAL schema mismatch",
            Self::NamespaceMismatch => "transaction admission WAL namespace mismatch",
            Self::Malformed => "transaction admission WAL row is malformed",
            Self::TooLarge => "transaction admission WAL row bound exceeded",
            Self::Replay => "transaction admission nonce or digest is already used",
            Self::ReservationConflict => "transaction admission reservation state conflict",
            Self::AmbiguousHandoff => {
                "transaction admission WAL has an unresolved handed-off reservation"
            }
            Self::CommitReceiptMismatch => "transaction commit receipt does not match admission",
            Self::CommitReceiptConflict => "transaction commit receipt conflicts with durable row",
            Self::CommitReadbackUnavailable => {
                "transaction commit requires an authenticated application/finality readback"
            }
            Self::HandoffRecoveryUnavailable => {
                "transaction admission handoff recovery requires an explicit recovery owner"
            }
        })
    }
}

impl Error for TxAdmissionWalErrorV0 {}

impl From<io::Error> for TxAdmissionWalErrorV0 {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathIdentityV0 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

#[cfg(unix)]
impl PathIdentityV0 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn from_file(file: &File) -> Result<Self, TxAdmissionWalErrorV0> {
        let metadata = file.metadata().map_err(|_| TxAdmissionWalErrorV0::Io)?;
        Ok(Self::from_metadata(&metadata))
    }
}

#[cfg(not(unix))]
impl PathIdentityV0 {
    fn from_metadata(_metadata: &fs::Metadata) -> Self {
        Self {}
    }

    fn from_file(file: &File) -> Result<Self, TxAdmissionWalErrorV0> {
        file.metadata()
            .map_err(|_| TxAdmissionWalErrorV0::Io)
            .map(|_| Self {})
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdmissionRecordV0 {
    signer: [u8; 32],
    nonce: u64,
    digest: [u8; 32],
    body_digest: [u8; 32],
    fee_limit: u128,
    max_gas: u64,
    max_bytes: u64,
}

impl AdmissionRecordV0 {
    fn from_metadata(metadata: &SignedEnvelopeMetadata) -> Result<Self, TxAdmissionWalErrorV0> {
        let signer = metadata.signer_id().as_bytes();
        let digest = metadata.digest().as_bytes();
        if signer == [0; 32] || digest == [0; 32] || metadata.body().is_empty() {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        let body_digest = body_digest_v0(metadata.body());
        let limits = metadata.resource_limits();
        let body_len =
            u64::try_from(metadata.body().len()).map_err(|_| TxAdmissionWalErrorV0::TooLarge)?;
        if limits.max_gas == 0
            || limits.max_bytes == 0
            || body_len > limits.max_bytes
            || metadata.fee_limit() == 0
            || metadata.nonce() == 0
        {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        Ok(Self {
            signer,
            nonce: metadata.nonce(),
            digest,
            body_digest,
            fee_limit: metadata.fee_limit(),
            max_gas: limits.max_gas,
            max_bytes: limits.max_bytes,
        })
    }

    fn from_transaction(
        transaction: &BuiltCanonicalTxV0,
        signer: CanonicalSignerId,
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        let view = transaction.admission_view_v0(signer);
        view.validate_canonical()
            .map_err(|_| TxAdmissionWalErrorV0::Malformed)?;
        let digest = view.canonical_digest().as_bytes();
        let body = view.canonical_body();
        let body_len = u64::try_from(body.len()).map_err(|_| TxAdmissionWalErrorV0::TooLarge)?;
        let limits = view.resource_limits();
        let fee_limit = view.fee_limit();
        if digest == [0; 32]
            || signer.as_bytes() == [0; 32]
            || body.is_empty()
            || view.nonce() == 0
            || limits.max_gas == 0
            || limits.max_bytes == 0
            || body_len > limits.max_bytes
            || fee_limit == 0
        {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        Ok(Self {
            signer: signer.as_bytes(),
            nonce: view.nonce(),
            digest,
            body_digest: body_digest_v0(body),
            fee_limit,
            max_gas: limits.max_gas,
            max_bytes: limits.max_bytes,
        })
    }

    fn handoff_facts(self) -> Result<PendingNonceHandoffRecordV0, TxAdmissionWalErrorV0> {
        let signer = CanonicalSignerId::from_bytes(self.signer)
            .map_err(|_| TxAdmissionWalErrorV0::Malformed)?;
        Ok(PendingNonceHandoffRecordV0 {
            signer,
            nonce: self.nonce,
            digest: self.digest,
            body_digest: self.body_digest,
            fee_limit: self.fee_limit,
            max_gas: self.max_gas,
            max_bytes: self.max_bytes,
        })
    }
}

/// Candidate-only application/finality evidence for one admitted transaction.
/// The distinct consensus types prevent a legacy Comet AppHash or an
/// untyped height from being silently used as native commit evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeCommitReceiptEvidenceV0 {
    tx_digest: [u8; 32],
    block_id: BlockId,
    block_height: Height,
    state_root: StateRoot,
    /// The native execution receipt commitment at this transaction's exact
    /// block-body index (not an inferred transport or legacy AppHash value).
    receipt_digest: [u8; 32],
    finality_proof_digest: [u8; 32],
}

/// Persisted facts for a durable `HandedOff` reservation discovered during
/// process restart.  They are untrusted until a recovery owner matches every
/// field against an exact canonical transaction and an independently read-back
/// application receipt.  The record contains no executable capability and no
/// private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingNonceHandoffRecordV0 {
    signer: CanonicalSignerId,
    nonce: u64,
    digest: [u8; 32],
    body_digest: [u8; 32],
    fee_limit: u128,
    max_gas: u64,
    max_bytes: u64,
}

impl PendingNonceHandoffRecordV0 {
    pub const fn signer_id_v0(&self) -> CanonicalSignerId {
        self.signer
    }

    pub const fn nonce_v0(&self) -> u64 {
        self.nonce
    }

    pub const fn digest_v0(&self) -> [u8; 32] {
        self.digest
    }

    pub const fn body_digest_v0(&self) -> [u8; 32] {
        self.body_digest
    }

    pub const fn fee_limit_v0(&self) -> u128 {
        self.fee_limit
    }

    pub const fn max_gas_v0(&self) -> u64 {
        self.max_gas
    }

    pub const fn max_bytes_v0(&self) -> u64 {
        self.max_bytes
    }

    /// Verify that every persisted reservation field describes the supplied
    /// canonical transaction under the node-owned replay identity.  No
    /// database state is changed; this is the mandatory precondition for a
    /// restart recovery owner.
    pub fn validate_transaction_v0(
        &self,
        transaction: &BuiltCanonicalTxV0,
        signer: CanonicalSignerId,
    ) -> Result<(), TxAdmissionWalErrorV0> {
        let expected = AdmissionRecordV0::from_transaction(transaction, signer)?;
        if expected.handoff_facts()? == *self {
            Ok(())
        } else {
            Err(TxAdmissionWalErrorV0::CommitReceiptMismatch)
        }
    }
}

impl NativeCommitReceiptEvidenceV0 {
    /// Construct an unverified candidate statement. It becomes usable for a
    /// durable commit only after [`Self::verify_with`] returns the private
    /// type-state token.
    pub fn new(
        tx_digest: [u8; 32],
        block_id: BlockId,
        block_height: Height,
        state_root: StateRoot,
        receipt_digest: [u8; 32],
        finality_proof_digest: [u8; 32],
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        if tx_digest == [0; 32]
            || block_id.is_zero()
            || block_height.get() == 0
            || state_root.is_zero()
            || receipt_digest == [0; 32]
            || finality_proof_digest == [0; 32]
        {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        Ok(Self {
            tx_digest,
            block_id,
            block_height,
            state_root,
            receipt_digest,
            finality_proof_digest,
        })
    }

    pub const fn tx_digest(&self) -> [u8; 32] {
        self.tx_digest
    }

    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn block_height(&self) -> Height {
        self.block_height
    }

    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }

    pub const fn finality_proof_digest(&self) -> [u8; 32] {
        self.finality_proof_digest
    }

    fn canonical_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(COMMIT_RECEIPT_DOMAIN_V0);
        hasher.update(self.tx_digest);
        hasher.update(self.block_id.as_bytes());
        hasher.update(self.block_height.get().to_be_bytes());
        hasher.update(self.state_root.as_bytes());
        hasher.update(self.receipt_digest);
        hasher.update(self.finality_proof_digest);
        hasher.finalize().into()
    }

    /// Authenticate the statement against the exact admitted metadata and an
    /// importer/application-owned verifier. There is intentionally no default
    /// verifier: shape-valid bytes alone never authorize a durable commit.
    pub fn verify_with<V: NativeCommitReceiptVerifierV0>(
        &self,
        metadata: &SignedEnvelopeMetadata,
        verifier: &V,
    ) -> Result<VerifiedNativeCommitReceiptV0, TxAdmissionWalErrorV0> {
        if self.tx_digest != metadata.digest().as_bytes() {
            return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
        }
        verifier.verify_application_and_finality_v0(metadata, self)?;
        Ok(VerifiedNativeCommitReceiptV0 {
            evidence: *self,
            commitment: self.canonical_commitment(),
        })
    }
}

/// Explicit verifier boundary for the application store and native PoCO
/// finality proof. A production implementation must read back the exact
/// transaction/result from durable application state and independently verify
/// the finalized block/QC before returning `Ok(())`.
pub trait NativeCommitReceiptVerifierV0 {
    fn verify_application_and_finality_v0(
        &self,
        metadata: &SignedEnvelopeMetadata,
        evidence: &NativeCommitReceiptEvidenceV0,
    ) -> Result<(), TxAdmissionWalErrorV0>;
}

/// Concrete candidate verifier which joins one admitted builder transaction
/// to the durable native application readback and an independently verified
/// PoCO finality proof.
///
/// The application API intentionally exposes the native state root rather than
/// a legacy Comet `AppHash`.  The verifier therefore checks the exact native
/// committed head (`block_id`, height, and state root), the durable execution
/// artifact's exact outer transaction bytes, and the receipt commitment at the
/// matching transaction index.  `FinalityProofV0::id()` is bound separately so
/// a caller cannot substitute a proof with the same block coordinates.
///
/// This is a composition-only seam.  It does not own the application, create a
/// finality proof, sign, broadcast, or activate the node.  A production owner
/// must retain the application/proof lifetimes and still join this readback to
/// Core/Safety before resolving a WAL handoff.
pub struct DurableNativeCommitReceiptVerifierV0<'a> {
    application: &'a DurableNativeApplicationV0,
    finality_proof: &'a FinalityProofV0,
    authenticated_parent_timestamp_ms: u64,
    transaction: &'a BuiltCanonicalTxV0,
}

impl<'a> DurableNativeCommitReceiptVerifierV0<'a> {
    /// Bind the verifier to the exact builder output that was admitted.  The
    /// constructor performs no I/O; all durable checks occur inside the
    /// [`NativeCommitReceiptVerifierV0`] implementation immediately before a
    /// receipt token is minted.
    pub const fn new(
        application: &'a DurableNativeApplicationV0,
        finality_proof: &'a FinalityProofV0,
        authenticated_parent_timestamp_ms: u64,
        transaction: &'a BuiltCanonicalTxV0,
    ) -> Self {
        Self {
            application,
            finality_proof,
            authenticated_parent_timestamp_ms,
            transaction,
        }
    }
}

impl fmt::Debug for DurableNativeCommitReceiptVerifierV0<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableNativeCommitReceiptVerifierV0")
            .field("finality_proof_id", &self.finality_proof.id())
            .field(
                "transaction_digest",
                &self.transaction.protocol_tx_hash_v1(),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy)]
struct NativeCommitReadbackFactsV0<'a> {
    finalized_height: u64,
    finalized_block_id: [u8; 32],
    finalized_state_root: [u8; 32],
    executed_height: u64,
    executed_block_id: [u8; 32],
    executed_state_root: [u8; 32],
    outer_transactions: &'a [Vec<u8>],
    receipt_indices: &'a [u32],
    receipt_commitments: &'a [[u8; 32]],
}

fn validate_native_readback_binding_v0(
    metadata: &SignedEnvelopeMetadata,
    evidence: &NativeCommitReceiptEvidenceV0,
    transaction: &BuiltCanonicalTxV0,
    expected_finality_proof_digest: [u8; 32],
    facts: NativeCommitReadbackFactsV0<'_>,
) -> Result<(), TxAdmissionWalErrorV0> {
    // Re-check the immutable builder carrier here rather than relying on a
    // caller to preserve the same transaction between CheckTx and commit.
    // This closes the common "verified one envelope, committed another"
    // gap at the final readback boundary.
    if transaction.protocol_tx_hash_v1() != metadata.digest().as_bytes()
        || transaction.exact_inner_bytes() != metadata.body()
        || evidence.tx_digest != transaction.protocol_tx_hash_v1()
        || evidence.finality_proof_digest != expected_finality_proof_digest
    {
        return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
    }

    // The durable row and the authenticated application head must both
    // describe the exact target claimed by the receipt.  A read of a
    // committed sibling or a stale state root cannot mint a token.
    let expected_height = evidence.block_height.get();
    let expected_block_id = *evidence.block_id.as_bytes();
    let expected_state_root = *evidence.state_root.as_bytes();
    if facts.finalized_height != expected_height
        || facts.finalized_block_id != expected_block_id
        || facts.finalized_state_root != expected_state_root
        || facts.executed_height != expected_height
        || facts.executed_block_id != expected_block_id
        || facts.executed_state_root != expected_state_root
    {
        return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
    }

    // The durable decoder currently returns one receipt-index/commitment row
    // for every outer transaction. Keep that shape an authenticated
    // invariant at this boundary instead of accepting a prefix with an
    // ignored suffix (or a sparse index vector). A future application schema
    // change must update this join explicitly; silently accepting cardinality
    // drift would let a receipt be attributed to a different execution view.
    if facts.receipt_indices.len() != facts.outer_transactions.len()
        || facts.receipt_commitments.len() != facts.outer_transactions.len()
    {
        return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
    }
    // Authenticate the complete index vector, not just the index selected for
    // this transaction.  A malformed readback such as `[0, 0]` or `[0, 2]`
    // must not be accepted merely because the target happens to be at index
    // zero; otherwise a forged suffix could be hidden behind an apparently
    // valid receipt prefix.  The native schema's index is the canonical
    // zero-based body position for every receipt.
    if facts
        .receipt_indices
        .iter()
        .enumerate()
        .any(|(index, receipt_index)| u32::try_from(index) != Ok(*receipt_index))
    {
        return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
    }

    // The application stores exact outer envelope bytes.  Require exactly one
    // occurrence of the admitted bytes and use that position to bind the
    // per-transaction native receipt commitment.
    let mut matched_index = None;
    for (index, outer_bytes) in facts.outer_transactions.iter().enumerate() {
        if outer_bytes.as_slice() == transaction.exact_outer_bytes()
            && matched_index.replace(index).is_some()
        {
            return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
        }
    }
    let index = matched_index.ok_or(TxAdmissionWalErrorV0::CommitReceiptMismatch)?;
    if facts.receipt_indices.get(index).copied() != Some(index as u32)
        || facts
            .receipt_commitments
            .get(index)
            .is_none_or(|commitment| commitment != &evidence.receipt_digest)
    {
        return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
    }
    Ok(())
}

impl NativeCommitReceiptVerifierV0 for DurableNativeCommitReceiptVerifierV0<'_> {
    fn verify_application_and_finality_v0(
        &self,
        metadata: &SignedEnvelopeMetadata,
        evidence: &NativeCommitReceiptEvidenceV0,
    ) -> Result<(), TxAdmissionWalErrorV0> {
        let proof_id = self.finality_proof.id();
        let block_id = BlockIdV0::new(*evidence.block_id.as_bytes())
            .map_err(|_| TxAdmissionWalErrorV0::CommitReceiptMismatch)?;

        let read = self
            .application
            .read_finalized_by_block_id_with_proof_v0(
                block_id,
                self.finality_proof,
                self.authenticated_parent_timestamp_ms,
            )
            .map_err(|_| TxAdmissionWalErrorV0::CommitReadbackUnavailable)?;
        let finalized_head = read
            .finalized_head_v0()
            .map_err(|_| TxAdmissionWalErrorV0::CommitReadbackUnavailable)?;
        let receipt_indices = read
            .executed_v0()
            .receipts()
            .iter()
            .map(|receipt| receipt.transaction_index())
            .collect::<Vec<_>>();
        let receipt_commitments = read
            .receipt_commitments_v0()
            .iter()
            .map(|commitment| *commitment.as_bytes())
            .collect::<Vec<_>>();
        validate_native_readback_binding_v0(
            metadata,
            evidence,
            self.transaction,
            *proof_id.as_bytes(),
            NativeCommitReadbackFactsV0 {
                finalized_height: finalized_head.height().get(),
                finalized_block_id: *finalized_head.block_id().as_bytes(),
                finalized_state_root: *finalized_head.state_root().as_bytes(),
                executed_height: read.executed_v0().request().height().get(),
                executed_block_id: *read.executed_v0().request().block_id().as_bytes(),
                executed_state_root: *read
                    .executed_v0()
                    .request()
                    .expected()
                    .post_state_root()
                    .as_bytes(),
                outer_transactions: read.executed_v0().request().transactions(),
                receipt_indices: &receipt_indices,
                receipt_commitments: &receipt_commitments,
            },
        )
    }
}

/// Node-owned mapping from the authenticated transaction envelope to the
/// canonical replay identity used by the pending-nonce authority.
///
/// The resolver is intentionally installed when the node boundary is opened,
/// rather than supplied alongside each transaction. A caller-provided
/// CanonicalSignerId is therefore only an assertion checked against this
/// owner; it can never choose the WAL replay key. Implementations must read
/// an authenticated account/key registry (or an equivalent remote authority)
/// and must not trust an unverified request parameter.
pub trait CanonicalSignerIdentityResolverV0: fmt::Debug {
    fn resolve_canonical_signer_id_v0(
        &self,
        transaction: &BuiltCanonicalTxV0,
    ) -> Result<CanonicalSignerId, AdmissionReject>;
}

/// Node-owned admission context for the candidate CheckTx seam.
///
/// A production implementation must source both values from the authenticated
/// chain/runtime owner (for example the current committed block context), not
/// from an RPC argument or a local wall clock.  The trait is deliberately
/// composition-only until that owner is wired into the native node.
pub trait CanonicalAdmissionContextResolverV0: fmt::Debug {
    fn chain_id_v0(&self) -> &str;
    fn now_unix_ms_v0(&self) -> u64;
}

/// Type-state token returned only after the explicit verifier succeeds. The
/// token is still candidate-only: it does not activate a node or provide a
/// network/broadcast capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedNativeCommitReceiptV0 {
    evidence: NativeCommitReceiptEvidenceV0,
    commitment: [u8; 32],
}

impl VerifiedNativeCommitReceiptV0 {
    pub const fn evidence(&self) -> &NativeCommitReceiptEvidenceV0 {
        &self.evidence
    }

    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

/// Strict CheckTx hooks for the canonical builder carrier.
///
/// The builder has already produced byte-stable inner/outer envelopes, but a
/// node must still authenticate the exact envelope at ingress time.  Keeping
/// this check in the node owner closes the common gap where a caller validates
/// a builder result once and later admits a different time/chain context.  No
/// private key crosses this hook: `validate_at_strict` verifies the Ed25519
/// signature carried by the envelope.
#[derive(Debug, Clone)]
struct CanonicalCheckTxHooksV0 {
    chain_id: String,
    now_unix_ms: u64,
}

impl<'a> SignedAdmissionHooks<BuiltCanonicalTxAdmissionViewV0<'a>> for CanonicalCheckTxHooksV0 {
    fn verify_signature(
        &mut self,
        envelope: &BuiltCanonicalTxAdmissionViewV0<'a>,
        metadata: &SignedEnvelopeMetadata,
    ) -> Result<(), AdmissionReject> {
        let transaction = envelope.transaction();
        transaction
            .envelope()
            .validate_at_strict(&self.chain_id, self.now_unix_ms)
            .map_err(|_| AdmissionReject::SignatureRejected)?;
        if transaction.protocol_tx_hash_v1() != metadata.digest().as_bytes()
            || transaction.exact_inner_bytes() != metadata.body()
        {
            return Err(AdmissionReject::SignatureRejected);
        }
        Ok(())
    }

    fn recheck(&mut self, metadata: &SignedEnvelopeMetadata) -> Result<(), AdmissionReject> {
        if metadata.nonce() == 0
            || metadata.fee_limit() == 0
            || metadata.resource_limits().max_gas == 0
        {
            return Err(AdmissionReject::RecheckFailed);
        }
        Ok(())
    }
}

fn body_digest_v0(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(WAL_DOMAIN_V0);
    hasher.update(b"body\0");
    hasher.update((body.len() as u64).to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn lock_path_v0(path: &Path) -> Result<PathBuf, TxAdmissionWalErrorV0> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(TxAdmissionWalErrorV0::InvalidPath)?;
    Ok(path
        .parent()
        .ok_or(TxAdmissionWalErrorV0::InvalidPath)?
        .join(format!(".{name}{LOCK_SUFFIX_V0}")))
}

fn validate_parent_v0(path: &Path) -> Result<&Path, TxAdmissionWalErrorV0> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(TxAdmissionWalErrorV0::InvalidPath);
    }
    let parent = path.parent().ok_or(TxAdmissionWalErrorV0::InvalidPath)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| TxAdmissionWalErrorV0::InvalidPath)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(TxAdmissionWalErrorV0::InvalidPath);
    }
    let canonical = fs::canonicalize(parent).map_err(|_| TxAdmissionWalErrorV0::InvalidPath)?;
    if canonical != parent {
        return Err(TxAdmissionWalErrorV0::InvalidPath);
    }
    Ok(parent)
}

/// Validate the database path and report whether this invocation created the
/// file.  The creation bit is part of the schema fail-closed boundary: an
/// existing path with an empty/partial schema must never be mistaken for a
/// virgin database and silently repaired by `CREATE TABLE IF NOT EXISTS`.
fn ensure_regular_db_v0(path: &Path) -> Result<(PathIdentityV0, bool), TxAdmissionWalErrorV0> {
    validate_parent_v0(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || !is_private_mode_v0(&metadata)
            {
                return Err(TxAdmissionWalErrorV0::InvalidPath);
            }
            Ok((PathIdentityV0::from_metadata(&metadata), false))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).read(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
                options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            }
            let file = options.open(path).map_err(|_| TxAdmissionWalErrorV0::Io)?;
            file.sync_all().map_err(|_| TxAdmissionWalErrorV0::Io)?;
            drop(file);
            File::open(path.parent().ok_or(TxAdmissionWalErrorV0::InvalidPath)?)
                .map_err(|_| TxAdmissionWalErrorV0::Io)?
                .sync_data()
                .map_err(|_| TxAdmissionWalErrorV0::Io)?;
            let metadata = fs::symlink_metadata(path).map_err(|_| TxAdmissionWalErrorV0::Io)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || !is_private_mode_v0(&metadata)
            {
                return Err(TxAdmissionWalErrorV0::InvalidPath);
            }
            Ok((PathIdentityV0::from_metadata(&metadata), true))
        }
        Err(_) => Err(TxAdmissionWalErrorV0::Io),
    }
}

fn open_lock_v0(path: &Path) -> Result<(Rc<File>, PathBuf, PathIdentityV0), TxAdmissionWalErrorV0> {
    let lock_path = lock_path_v0(path)?;
    if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || !is_private_mode_v0(&metadata)
        {
            return Err(TxAdmissionWalErrorV0::InvalidPath);
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(&lock_path)
        .map_err(|_| TxAdmissionWalErrorV0::Io)?;
    file.try_lock_exclusive()
        .map_err(|_| TxAdmissionWalErrorV0::LockUnavailable)?;
    let lock_identity = PathIdentityV0::from_file(&file)?;
    ensure_identity_v0(&lock_path, lock_identity)?;
    Ok((Rc::new(file), lock_path, lock_identity))
}

#[cfg(unix)]
fn is_private_mode_v0(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn is_private_mode_v0(_metadata: &fs::Metadata) -> bool {
    true
}

fn ensure_identity_v0(path: &Path, expected: PathIdentityV0) -> Result<(), TxAdmissionWalErrorV0> {
    let metadata = fs::symlink_metadata(path).map_err(|_| TxAdmissionWalErrorV0::PathReplaced)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || PathIdentityV0::from_metadata(&metadata) != expected
    {
        return Err(TxAdmissionWalErrorV0::PathReplaced);
    }
    Ok(())
}

fn ensure_open_lock_identity_v0(
    path: &Path,
    expected: PathIdentityV0,
    lock: &File,
) -> Result<(), TxAdmissionWalErrorV0> {
    if PathIdentityV0::from_file(lock).map_err(|_| TxAdmissionWalErrorV0::PathReplaced)? != expected
    {
        return Err(TxAdmissionWalErrorV0::PathReplaced);
    }
    ensure_identity_v0(path, expected)
}

fn sqlite_error(_: rusqlite::Error) -> TxAdmissionWalErrorV0 {
    TxAdmissionWalErrorV0::Sqlite
}

/// Return every non-internal SQLite schema object in a deterministic form.
/// Auto-created indexes are intentionally excluded with SQLite's reserved
/// `sqlite_` prefix; any user-created index, trigger, view, or table remains
/// visible and therefore cannot silently extend the authority surface.
fn sqlite_schema_objects_v0(
    connection: &Connection,
) -> Result<BTreeMap<(String, String), String>, TxAdmissionWalErrorV0> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type ASC, name ASC",
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(sqlite_error)?;
    let mut objects = BTreeMap::new();
    for row in rows {
        let (kind, name, sql) = row.map_err(sqlite_error)?;
        let sql = sql
            .ok_or(TxAdmissionWalErrorV0::SchemaMismatch)?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if objects.insert((kind, name), sql).is_some() {
            return Err(TxAdmissionWalErrorV0::SchemaMismatch);
        }
    }
    Ok(objects)
}

fn canonical_sqlite_schema_objects_v0(
) -> Result<BTreeMap<(String, String), String>, TxAdmissionWalErrorV0> {
    let canonical = Connection::open_in_memory().map_err(sqlite_error)?;
    canonical
        .execute_batch(SQLITE_SCHEMA_DDL_V0)
        .map_err(sqlite_error)?;
    sqlite_schema_objects_v0(&canonical)
}

/// Refuse an existing WAL whose schema is not byte-for-byte equivalent in
/// SQLite's canonical schema catalog to the v0 authority schema.  Merely
/// issuing `CREATE TABLE IF NOT EXISTS` is insufficient: an attacker or
/// damaged restore could preserve the table name while removing the primary
/// key/unique constraints that make nonce and receipt lookup deterministic.
/// The comparison runs before any authority-row read or mutation.
fn validate_sqlite_schema_v0(connection: &Connection) -> Result<(), TxAdmissionWalErrorV0> {
    if sqlite_schema_objects_v0(connection)? != canonical_sqlite_schema_objects_v0()? {
        return Err(TxAdmissionWalErrorV0::SchemaMismatch);
    }
    Ok(())
}

fn map_insert_error_v0(error: rusqlite::Error) -> TxAdmissionWalErrorV0 {
    if error.sqlite_error_code() == Some(rusqlite::ffi::ErrorCode::ConstraintViolation) {
        TxAdmissionWalErrorV0::Replay
    } else {
        sqlite_error(error)
    }
}

fn to_blob_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn to_blob_u128(value: u128) -> [u8; 16] {
    value.to_be_bytes()
}

fn decode_fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], TxAdmissionWalErrorV0> {
    value
        .try_into()
        .map_err(|_| TxAdmissionWalErrorV0::Malformed)
}

fn decode_state(value: i64) -> Result<i64, TxAdmissionWalErrorV0> {
    match value {
        STATE_RESERVED_V0 | STATE_HANDED_OFF_V0 | STATE_COMMITTED_V0 | STATE_RELEASED_V0 => {
            Ok(value)
        }
        _ => Err(TxAdmissionWalErrorV0::Malformed),
    }
}

fn read_row_v0(
    connection: &Connection,
    namespace: [u8; 32],
    signer: [u8; 32],
    nonce: u64,
) -> Result<Option<(AdmissionRecordV0, i64)>, TxAdmissionWalErrorV0> {
    let nonce_blob = to_blob_u64(nonce);
    let raw: Option<RawAdmissionRowV0> = connection
        .query_row(
            "SELECT digest, body_digest, fee_limit, max_gas, max_bytes, state
             FROM pending_nonce
             WHERE namespace = ?1 AND signer = ?2 AND nonce = ?3",
            params![
                namespace.as_slice(),
                signer.as_slice(),
                nonce_blob.as_slice()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map_or(
        Ok(None),
        |(digest, body_digest, fee_limit, max_gas, max_bytes, state)| {
            Ok(Some((
                AdmissionRecordV0 {
                    signer,
                    nonce,
                    digest: decode_fixed::<32>(digest)?,
                    body_digest: decode_fixed::<32>(body_digest)?,
                    fee_limit: u128::from_be_bytes(decode_fixed::<16>(fee_limit)?),
                    max_gas: u64::from_be_bytes(decode_fixed::<8>(max_gas)?),
                    max_bytes: u64::from_be_bytes(decode_fixed::<8>(max_bytes)?),
                },
                decode_state(state)?,
            )))
        },
    )
}

fn validate_pending_rows_v0(
    connection: &Connection,
    namespace: [u8; 32],
) -> Result<(), TxAdmissionWalErrorV0> {
    let mut statement = connection
        .prepare(
            "SELECT signer, nonce FROM pending_nonce
             WHERE namespace = ?1
             ORDER BY nonce ASC, signer ASC",
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(params![namespace.as_slice()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(sqlite_error)?;
    let mut keys = Vec::new();
    for row in rows {
        let (signer, nonce) = row.map_err(sqlite_error)?;
        keys.push((decode_fixed::<32>(signer)?, decode_fixed::<8>(nonce)?));
    }
    drop(statement);
    for (signer, nonce) in keys {
        let nonce = u64::from_be_bytes(nonce);
        let Some((record, state)) = read_row_v0(connection, namespace, signer, nonce)? else {
            return Err(TxAdmissionWalErrorV0::Malformed);
        };
        // Reuse the same strict state decoder used by every lifecycle
        // transition, and reject impossible zero/empty reservation facts even
        // when an attacker has edited the SQLite row into a self-consistent
        // shape.
        decode_state(state)?;
        if record.signer == [0; 32]
            || record.nonce == 0
            || record.digest == [0; 32]
            || record.body_digest == [0; 32]
            || record.fee_limit == 0
            || record.max_gas == 0
            || record.max_bytes == 0
        {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
    }
    Ok(())
}

/// Audit every durable native commit receipt before exposing a reopened WAL
/// authority.  `pending_nonce.state=Committed` rows are intentionally allowed
/// to have no receipt: the older lifecycle API can commit a replay tombstone
/// without application readback.  The stronger receipt table, however, is
/// only written by the authenticated readback path and therefore must never
/// contain an orphan, a state-mismatched row, or a caller-substituted
/// commitment.  Keep this audit one-way so it preserves that existing
/// lifecycle while still refusing forged receipt evidence at restart.
fn validate_receipt_rows_v0(
    connection: &Connection,
    namespace: [u8; 32],
) -> Result<(), TxAdmissionWalErrorV0> {
    let row_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM tx_commit_receipt_v0 WHERE namespace = ?1",
            params![namespace.as_slice()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let row_count = usize::try_from(row_count).map_err(|_| TxAdmissionWalErrorV0::TooLarge)?;
    if row_count > MAX_RESERVATION_ROWS_V0 {
        return Err(TxAdmissionWalErrorV0::TooLarge);
    }

    let mut statement = connection
        .prepare(
            "SELECT signer, nonce, tx_digest, block_id, block_height, state_root,
                    receipt_digest, finality_proof_digest, commitment
             FROM tx_commit_receipt_v0
             WHERE namespace = ?1
             ORDER BY nonce ASC, signer ASC",
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(params![namespace.as_slice()], |row| {
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
        })
        .map_err(sqlite_error)?;

    for row in rows {
        let (
            signer,
            nonce,
            tx_digest,
            block_id,
            block_height,
            state_root,
            receipt_digest,
            finality_proof_digest,
            commitment,
        ): RawReceiptRowV0 = row.map_err(sqlite_error)?;
        let signer = decode_fixed::<32>(signer)?;
        let nonce = u64::from_be_bytes(decode_fixed::<8>(nonce)?);
        let tx_digest = decode_fixed::<32>(tx_digest)?;
        let block_id = decode_fixed::<32>(block_id)?;
        let block_height = u64::from_be_bytes(decode_fixed::<8>(block_height)?);
        let state_root = decode_fixed::<32>(state_root)?;
        let receipt_digest = decode_fixed::<32>(receipt_digest)?;
        let finality_proof_digest = decode_fixed::<32>(finality_proof_digest)?;
        let commitment = decode_fixed::<32>(commitment)?;

        // These checks are deliberately repeated even though the SQLite
        // schema carries CHECK(length(...)) clauses.  A copied/tampered
        // database can be opened with check constraints disabled, and restart
        // must not trust a merely self-consistent byte shape.
        if signer == [0; 32]
            || nonce == 0
            || tx_digest == [0; 32]
            || block_id == [0; 32]
            || block_height == 0
            || state_root == [0; 32]
            || receipt_digest == [0; 32]
            || finality_proof_digest == [0; 32]
            || commitment == [0; 32]
        {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }

        let Some((pending, state)) = read_row_v0(connection, namespace, signer, nonce)? else {
            return Err(TxAdmissionWalErrorV0::Malformed);
        };
        if state != STATE_COMMITTED_V0 || pending.digest != tx_digest {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }

        let evidence = NativeCommitReceiptEvidenceV0 {
            tx_digest,
            block_id: BlockId::new(block_id),
            block_height: Height::new(block_height),
            state_root: StateRoot::new(state_root),
            receipt_digest,
            finality_proof_digest,
        };
        if evidence.canonical_commitment() != commitment {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
    }
    drop(statement);
    Ok(())
}

fn read_state_by_digest_v0(
    connection: &Connection,
    namespace: [u8; 32],
    digest: [u8; 32],
) -> Result<Option<(Vec<u8>, i64)>, TxAdmissionWalErrorV0> {
    let raw: Option<(Vec<u8>, i64)> = connection
        .query_row(
            "SELECT nonce, state FROM pending_nonce
             WHERE namespace = ?1 AND digest = ?2",
            params![namespace.as_slice(), digest.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map_or(Ok(None), |(nonce, state)| {
        Ok(Some((nonce, decode_state(state)?)))
    })
}

fn row_matches_v0(row: AdmissionRecordV0, expected: AdmissionRecordV0) -> bool {
    row == expected
}

fn read_receipt_commitment_v0(
    connection: &Connection,
    namespace: [u8; 32],
    signer: [u8; 32],
    nonce: u64,
) -> Result<Option<[u8; 32]>, TxAdmissionWalErrorV0> {
    let nonce_blob = to_blob_u64(nonce);
    let raw: Option<Vec<u8>> = connection
        .query_row(
            "SELECT commitment FROM tx_commit_receipt_v0
             WHERE namespace = ?1 AND signer = ?2 AND nonce = ?3",
            params![
                namespace.as_slice(),
                signer.as_slice(),
                nonce_blob.as_slice()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map_or(Ok(None), |value| decode_fixed::<32>(value).map(Some))
}

/// A node-owned SQLite pending-nonce authority.
///
/// The authority is intentionally not `Clone` and its lock is held for its
/// entire lifetime (also by outstanding reservation tokens).  It is therefore
/// safe only as a single local owner; cross-process attempts fail at open.
pub struct SqlitePendingNonceAuthorityV0 {
    connection: Rc<RefCell<Connection>>,
    lock: Rc<File>,
    lock_path: PathBuf,
    lock_identity: PathIdentityV0,
    path: PathBuf,
    path_identity: PathIdentityV0,
    namespace: [u8; 32],
}

/// The candidate node-owned transaction-admission boundary.
///
/// A canonical builder supplies a [`SignedEnvelopeView`] (the current builder
/// crate exposes `BuiltCanonicalTxAdmissionViewV0`).  The node owner supplies
/// read-only signature/recheck hooks, and this boundary then performs the
/// following ordered, candidate-only operation:
///
/// ```text
/// typed builder view -> canonical metadata -> durable reserve
///     -> ready item -> handoff -> receipt-commit
/// ```
///
/// The returned [`PendingNonceAdmission`] owns the durable lifecycle token.
/// Dropping an item that is still `Reserved` attempts a durable release.  Once
/// `handoff` succeeds, execution is ambiguous until an authenticated receipt
/// commit (or explicit restart recovery); dropping that item cannot release the
/// row and therefore leaves startup fail-closed.  Callers should use `handoff`
/// followed by `commit`, or explicitly `release`/`cancel` before handoff.
///
/// This type is deliberately not a node runtime.  It does not call a signer,
/// execute a transaction, invoke CheckTx, publish an RPC result, or broadcast
/// bytes.  Its feature and package activation flags remain false.
#[derive(Debug)]
pub struct NodeOwnedTxAdmissionBoundaryV0 {
    gate: TypedAdmissionGate,
    authority: SqlitePendingNonceAuthorityV0,
    signer_resolver: Option<Box<dyn CanonicalSignerIdentityResolverV0>>,
    context_resolver: Option<Box<dyn CanonicalAdmissionContextResolverV0>>,
    /// Recovery inspection/resolution is a distinct owner mode.  Keep this
    /// bit on the live boundary rather than relying on a documentation-only
    /// constructor convention, so a normal admission owner cannot accidentally
    /// invoke the restart path.
    allow_handed_off_recovery: bool,
}

impl NodeOwnedTxAdmissionBoundaryV0 {
    /// Open the node-owned WAL and create an in-memory typed admission gate.
    ///
    /// `namespace` must be bound by the future chain/epoch owner; this method
    /// does not infer it from a transaction or a local path.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
        max_body_bytes: u64,
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        Self::open_inner(
            path,
            namespace,
            total_capacity,
            critical_reserve,
            max_body_bytes,
            None,
            None,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_inner(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
        max_body_bytes: u64,
        signer_resolver: Option<Box<dyn CanonicalSignerIdentityResolverV0>>,
        context_resolver: Option<Box<dyn CanonicalAdmissionContextResolverV0>>,
        allow_handed_off: bool,
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        Ok(Self {
            gate: TypedAdmissionGate::new(total_capacity, critical_reserve, max_body_bytes),
            authority: SqlitePendingNonceAuthorityV0::open_with_handoff_policy(
                path,
                namespace,
                allow_handed_off,
            )?,
            signer_resolver,
            context_resolver,
            allow_handed_off_recovery: allow_handed_off,
        })
    }

    /// Open a boundary with the immutable signer/account resolver owned by the
    /// node admission authority. Candidate CheckTx calls fail closed until
    /// this constructor is used; generic typed admission remains available via
    /// admit_signed_candidate.
    pub fn open_with_signer_resolver<R>(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
        max_body_bytes: u64,
        resolver: R,
    ) -> Result<Self, TxAdmissionWalErrorV0>
    where
        R: CanonicalSignerIdentityResolverV0 + 'static,
    {
        Self::open_inner(
            path,
            namespace,
            total_capacity,
            critical_reserve,
            max_body_bytes,
            Some(Box::new(resolver)),
            None,
            false,
        )
    }

    /// Open a candidate boundary with both node-owned signer identity and
    /// chain/time context authorities. This is the preferred composition seam;
    /// it still does not enable production CheckTx or signer effects.
    pub fn open_with_signer_and_context<R, C>(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
        max_body_bytes: u64,
        signer_resolver: R,
        context_resolver: C,
    ) -> Result<Self, TxAdmissionWalErrorV0>
    where
        R: CanonicalSignerIdentityResolverV0 + 'static,
        C: CanonicalAdmissionContextResolverV0 + 'static,
    {
        Self::open_inner(
            path,
            namespace,
            total_capacity,
            critical_reserve,
            max_body_bytes,
            Some(Box::new(signer_resolver)),
            Some(Box::new(context_resolver)),
            false,
        )
    }

    /// Open with the typed mempool's canonical default body bound.
    pub fn with_default_body_limit(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        Self::open(
            path,
            namespace,
            total_capacity,
            critical_reserve,
            DEFAULT_MAX_ADMISSION_BODY_BYTES,
        )
    }

    /// Open with the canonical builder body bound and an authority-owned
    /// signer/account resolver.
    pub fn with_default_body_limit_and_signer_resolver<R>(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
        resolver: R,
    ) -> Result<Self, TxAdmissionWalErrorV0>
    where
        R: CanonicalSignerIdentityResolverV0 + 'static,
    {
        Self::open_with_signer_resolver(
            path,
            namespace,
            total_capacity,
            critical_reserve,
            DEFAULT_MAX_ADMISSION_BODY_BYTES,
            resolver,
        )
    }

    /// Open with the canonical builder bound and node-owned signer/context
    /// authorities.
    pub fn with_default_body_limit_and_signer_and_context<R, C>(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
        signer_resolver: R,
        context_resolver: C,
    ) -> Result<Self, TxAdmissionWalErrorV0>
    where
        R: CanonicalSignerIdentityResolverV0 + 'static,
        C: CanonicalAdmissionContextResolverV0 + 'static,
    {
        Self::open_with_signer_and_context(
            path,
            namespace,
            total_capacity,
            critical_reserve,
            DEFAULT_MAX_ADMISSION_BODY_BYTES,
            signer_resolver,
            context_resolver,
        )
    }

    /// Candidate-only restart owner that permits inspection of unresolved WAL
    /// handoffs.  It does not resolve them automatically; the caller must use
    /// [`Self::recover_handed_off_with_native_readback`] with an exact
    /// application/proof join, or drop the owner and remain fail-closed.
    pub fn with_default_body_limit_and_signer_and_context_handoff_recovery<R, C>(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
        signer_resolver: R,
        context_resolver: C,
    ) -> Result<Self, TxAdmissionWalErrorV0>
    where
        R: CanonicalSignerIdentityResolverV0 + 'static,
        C: CanonicalAdmissionContextResolverV0 + 'static,
    {
        Self::open_inner(
            path,
            namespace,
            total_capacity,
            critical_reserve,
            DEFAULT_MAX_ADMISSION_BODY_BYTES,
            Some(Box::new(signer_resolver)),
            Some(Box::new(context_resolver)),
            true,
        )
    }

    pub const fn namespace(&self) -> [u8; 32] {
        self.authority.namespace()
    }

    /// Admit one already-authenticated canonical view into the candidate
    /// queue.  This is an admission-boundary operation, not CheckTx.
    pub fn admit_signed_candidate<E, H>(
        &mut self,
        envelope: &E,
        class: IngressClass,
        hooks: &mut H,
    ) -> TypedAdmitOutcome
    where
        E: SignedEnvelopeView + ?Sized,
        H: SignedAdmissionHooks<E>,
    {
        if self.authority.has_unresolved_handoff_v0().unwrap_or(true) {
            return TypedAdmitOutcome::Rejected(AdmissionReject::InconsistentState);
        }
        self.gate
            .admit_signed_with_pending_nonce(envelope, class, hooks, &mut self.authority)
    }

    fn resolve_signer_id_v0(
        &self,
        transaction: &BuiltCanonicalTxV0,
    ) -> Result<CanonicalSignerId, AdmissionReject> {
        self.signer_resolver
            .as_ref()
            .ok_or(AdmissionReject::SignerIdentityUnavailable)?
            .resolve_canonical_signer_id_v0(transaction)
    }

    fn check_tx_candidate_resolved_v0(
        &mut self,
        transaction: &BuiltCanonicalTxV0,
        signer_id: CanonicalSignerId,
        class: IngressClass,
        chain_id: &str,
        now_unix_ms: u64,
    ) -> TypedAdmitOutcome {
        let view = transaction.admission_view_v0(signer_id);
        let mut hooks = CanonicalCheckTxHooksV0 {
            chain_id: chain_id.to_owned(),
            now_unix_ms,
        };
        self.admit_signed_candidate(&view, class, &mut hooks)
    }

    /// Run the concrete candidate CheckTx path for one builder-produced
    /// canonical transaction using the resolver installed by the node owner.
    /// No caller-supplied signer identity is accepted by this API.
    pub fn check_tx_candidate_with_resolver(
        &mut self,
        transaction: &BuiltCanonicalTxV0,
        class: IngressClass,
        chain_id: &str,
        now_unix_ms: u64,
    ) -> TypedAdmitOutcome {
        if self.authority.has_unresolved_handoff_v0().unwrap_or(true) {
            return TypedAdmitOutcome::Rejected(AdmissionReject::InconsistentState);
        }
        let signer_id = match self.resolve_signer_id_v0(transaction) {
            Ok(signer_id) => signer_id,
            Err(reason) => return TypedAdmitOutcome::Rejected(reason),
        };
        self.check_tx_candidate_resolved_v0(transaction, signer_id, class, chain_id, now_unix_ms)
    }

    /// Candidate CheckTx using both authorities installed at boundary open.
    /// No caller-supplied signer, chain ID, or timestamp can select the
    /// replay key or validation context on this path.
    pub fn check_tx_candidate_with_authorities(
        &mut self,
        transaction: &BuiltCanonicalTxV0,
        class: IngressClass,
    ) -> TypedAdmitOutcome {
        if self.authority.has_unresolved_handoff_v0().unwrap_or(true) {
            return TypedAdmitOutcome::Rejected(AdmissionReject::InconsistentState);
        }
        let signer_id = match self.resolve_signer_id_v0(transaction) {
            Ok(signer_id) => signer_id,
            Err(reason) => return TypedAdmitOutcome::Rejected(reason),
        };
        let (chain_id, now_unix_ms) = match self.context_resolver.as_ref() {
            Some(context) => (context.chain_id_v0().to_owned(), context.now_unix_ms_v0()),
            None => return TypedAdmitOutcome::Rejected(AdmissionReject::RecheckUnavailable),
        };
        self.check_tx_candidate_resolved_v0(transaction, signer_id, class, &chain_id, now_unix_ms)
    }

    /// Reconcile one unresolved durable handoff after a restart.  The caller
    /// must have opened this boundary with the explicit handoff-recovery
    /// constructor; this method never releases or guesses a row.  It rebuilds
    /// key-free metadata from the exact canonical transaction, reruns the
    /// node-owned signature/context checks, verifies the native application
    /// and PoCO proof readback, and only then advances the durable row.
    pub fn recover_handed_off_with_native_readback(
        &mut self,
        transaction: &BuiltCanonicalTxV0,
        evidence: NativeCommitReceiptEvidenceV0,
        application: &DurableNativeApplicationV0,
        finality_proof: &FinalityProofV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<(), AdmissionReject> {
        if !self.allow_handed_off_recovery {
            return Err(AdmissionReject::InconsistentState);
        }
        let signer_id = self.resolve_signer_id_v0(transaction)?;
        let view = transaction.admission_view_v0(signer_id);
        let metadata = self
            .gate
            .canonical_metadata_v0(&view)
            .map_err(|_| AdmissionReject::CanonicalValidationFailed)?;
        let (chain_id, now_unix_ms) = self
            .context_resolver
            .as_ref()
            .map(|context| (context.chain_id_v0().to_owned(), context.now_unix_ms_v0()))
            .ok_or(AdmissionReject::RecheckUnavailable)?;
        let mut hooks = CanonicalCheckTxHooksV0 {
            chain_id,
            now_unix_ms,
        };
        hooks.verify_signature(&view, &metadata)?;
        hooks.recheck(&metadata)?;
        let verifier = DurableNativeCommitReceiptVerifierV0::new(
            application,
            finality_proof,
            authenticated_parent_timestamp_ms,
            transaction,
        );
        let verified = evidence
            .verify_with(&metadata, &verifier)
            .map_err(map_reject_v0)?;
        self.authority
            .commit_handed_off_with_receipt(&metadata, &verified)
            .map_err(map_reject_v0)
    }

    /// Compatibility assertion for callers migrating from the old API. The
    /// supplied identity is never used as authority: it must equal the
    /// resolver-owned result or the candidate is rejected before WAL access.
    ///
    /// The operation authenticates the exact signed outer envelope against the
    /// supplied chain/time context, re-checks the builder's inner bytes and
    /// protocol hash, and only then reserves `(canonical signer, nonce)` in the
    /// durable WAL.  It therefore closes the builder -> signature-check ->
    /// pending-nonce boundary without pretending to execute or broadcast the
    /// transaction.  `TX_ADMISSION_BOUNDARY_CHECKTX_V0` remains false because
    /// this is still an explicitly feature-gated candidate owner.
    pub fn check_tx_candidate(
        &mut self,
        transaction: &BuiltCanonicalTxV0,
        signer_id: CanonicalSignerId,
        class: IngressClass,
        chain_id: &str,
        now_unix_ms: u64,
    ) -> TypedAdmitOutcome {
        if self.authority.has_unresolved_handoff_v0().unwrap_or(true) {
            return TypedAdmitOutcome::Rejected(AdmissionReject::InconsistentState);
        }
        let resolved = match self.resolve_signer_id_v0(transaction) {
            Ok(resolved) => resolved,
            Err(reason) => return TypedAdmitOutcome::Rejected(reason),
        };
        if resolved != signer_id {
            return TypedAdmitOutcome::Rejected(AdmissionReject::CanonicalValidationFailed);
        }
        self.check_tx_candidate_resolved_v0(transaction, resolved, class, chain_id, now_unix_ms)
    }

    /// Return the next item with its node-owned handoff/commit/release token.
    ///
    /// For this WAL implementation, `release` is valid only before handoff.
    /// Once a row is `HandedOff`, explicit release and token drop leave the
    /// durable ambiguity intact; [`Self::commit_candidate_with_receipt`] or
    /// the restart recovery entry point must provide authenticated readback.
    pub fn pop_ready_with_lifecycle(&mut self) -> Option<PendingNonceAdmission> {
        self.gate.pop_ready_with_lifecycle()
    }

    /// Commit a handed-off candidate only after an application/finality
    /// verifier has produced the private receipt token. The durable receipt
    /// write and WAL state transition are one SQLite transaction; resolving
    /// the erased in-memory token afterwards is a separate fail-closed step.
    pub fn commit_candidate_with_receipt(
        &mut self,
        admission: &mut PendingNonceAdmission,
        receipt: &VerifiedNativeCommitReceiptV0,
    ) -> Result<(), AdmissionReject> {
        // `PendingNonceAdmission` is intentionally opaque, but it can still
        // be passed across two local boundary values. Require the
        // process-local authority binding before touching this WAL; otherwise
        // boundary A could persist a receipt while boundary B commits the
        // token's reservation, leaving split durable state.
        if admission.owner_binding() != Some(self.authority.owner_binding()) {
            return Err(AdmissionReject::InconsistentState);
        }
        if admission.reservation_state()? != PendingNonceReservationState::HandedOff {
            return Err(AdmissionReject::ReservationStateConflict);
        }
        self.authority
            .commit_handed_off_with_receipt(admission.metadata(), receipt)
            .map_err(map_reject_v0)?;
        admission.commit()
    }

    /// Candidate-only convenience seam for the complete native readback
    /// boundary.  The caller supplies the exact builder transaction, durable
    /// native application owner, and independently carried finality proof;
    /// this method performs readback/authentication first and only then
    /// advances the WAL row and in-memory lifecycle token.
    pub fn commit_candidate_with_native_readback(
        &mut self,
        admission: &mut PendingNonceAdmission,
        transaction: &BuiltCanonicalTxV0,
        evidence: NativeCommitReceiptEvidenceV0,
        application: &DurableNativeApplicationV0,
        finality_proof: &FinalityProofV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<(), AdmissionReject> {
        let verifier = DurableNativeCommitReceiptVerifierV0::new(
            application,
            finality_proof,
            authenticated_parent_timestamp_ms,
            transaction,
        );
        let verified = evidence
            .verify_with(admission.metadata(), &verifier)
            .map_err(map_reject_v0)?;
        self.commit_candidate_with_receipt(admission, &verified)
    }

    pub fn queued_counts(&self) -> (usize, usize, usize) {
        self.gate.queued_counts()
    }

    /// Enumerate unresolved durable handoffs while this owner retains the WAL
    /// lock.  The facts are inspection-only and must be matched to an exact
    /// application/proof readback before calling the recovery method.
    pub fn handed_off_records_v0(
        &self,
    ) -> Result<Vec<PendingNonceHandoffRecordV0>, TxAdmissionWalErrorV0> {
        if !self.allow_handed_off_recovery {
            return Err(TxAdmissionWalErrorV0::HandoffRecoveryUnavailable);
        }
        self.authority.handed_off_records_v0()
    }

    /// Retained rows include committed/released replay tombstones.  No GC API
    /// is exposed until an authenticated retention policy exists.
    pub fn retained_rows(&self) -> Result<usize, TxAdmissionWalErrorV0> {
        self.authority.retained_rows()
    }
}

impl fmt::Debug for SqlitePendingNonceAuthorityV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqlitePendingNonceAuthorityV0")
            .field("path", &self.path)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl SqlitePendingNonceAuthorityV0 {
    /// Open or initialize a namespace-bound WAL database.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        Self::open_with_handoff_policy(path, namespace, false)
    }

    /// Resolve one durable `HandedOff` row after a process restart.
    ///
    /// Ordinary [`Self::open`] intentionally refuses to start when a handoff
    /// is unresolved.  This explicit recovery entry point temporarily opens
    /// the same sidecar-locked authority, checks the exact authenticated
    /// metadata against the durable row, and persists the already verified
    /// application/finality receipt and `Committed` transition in one SQLite
    /// transaction.  It never guesses, deletes, or rewrites a row, and it
    /// cannot be used with an unverified receipt token.
    ///
    /// The caller must obtain `metadata` from the authenticated transaction
    /// owner (for example a durable signed-envelope journal) and must run
    /// [`NativeCommitReceiptEvidenceV0::verify_with`] against that metadata
    /// before calling this method.  A mismatched metadata/receipt pair leaves
    /// the ambiguity intact and ordinary startup remains fail-closed.
    pub fn recover_handed_off_with_receipt(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        metadata: &SignedEnvelopeMetadata,
        receipt: &VerifiedNativeCommitReceiptV0,
    ) -> Result<(), TxAdmissionWalErrorV0> {
        let mut authority = Self::open_with_handoff_policy(path, namespace, true)?;
        authority.commit_handed_off_with_receipt(metadata, receipt)
    }

    /// Inspect every unresolved handoff while holding the same exclusive
    /// sidecar lock used by the live authority.  The returned facts are a
    /// bounded, key-free inventory only; they do not resolve, release, or
    /// mutate any row.  A restart owner must match the complete record to an
    /// exact canonical transaction and authenticated application readback.
    pub fn inspect_handed_off_v0(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
    ) -> Result<Vec<PendingNonceHandoffRecordV0>, TxAdmissionWalErrorV0> {
        let authority = Self::open_with_handoff_policy(path, namespace, true)?;
        authority.handed_off_records_v0()
    }

    fn open_with_handoff_policy(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        allow_handed_off: bool,
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        if namespace == [0; 32] {
            return Err(TxAdmissionWalErrorV0::InvalidNamespace);
        }
        let path = path.as_ref().to_path_buf();
        let (path_identity, created_new) = ensure_regular_db_v0(&path)?;
        let (lock, lock_path, lock_identity) = open_lock_v0(&path)?;
        ensure_identity_v0(&path, path_identity)?;
        ensure_open_lock_identity_v0(&lock_path, lock_identity, &lock)?;
        let connection = Connection::open(&path).map_err(sqlite_error)?;
        // The first identity check protects the name-to-inode transition around
        // SQLite open. A second fence below catches a replacement which raced
        // that open before any schema/WAL write is attempted.
        ensure_identity_v0(&path, path_identity)?;
        ensure_open_lock_identity_v0(&lock_path, lock_identity, &lock)?;
        connection
            .busy_timeout(Duration::from_millis(750))
            .map_err(sqlite_error)?;
        // Audit the catalog before enabling WAL or issuing any CREATE. An
        // existing path with one authority table missing is not a fresh
        // database; silently recreating that table would erase replay
        // tombstones and permit nonce reuse. Only the file created by this
        // invocation may start with an empty user schema.
        let pre_schema = sqlite_schema_objects_v0(&connection)?;
        let canonical_schema = canonical_sqlite_schema_objects_v0()?;
        let pre_user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        if created_new {
            if !pre_schema.is_empty() || pre_user_version != 0 {
                return Err(TxAdmissionWalErrorV0::SchemaMismatch);
            }
        } else if pre_schema != canonical_schema || pre_user_version != SCHEMA_VERSION_V0 {
            return Err(TxAdmissionWalErrorV0::SchemaMismatch);
        }
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA wal_autocheckpoint = 1;",
            )
            .map_err(sqlite_error)?;
        if created_new {
            connection
                .execute_batch(SQLITE_SCHEMA_DDL_V0)
                .map_err(sqlite_error)?;
            connection
                .execute_batch("PRAGMA user_version = 2;")
                .map_err(sqlite_error)?;
        }
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        if !journal_mode.eq_ignore_ascii_case("wal") || synchronous != 2 {
            return Err(TxAdmissionWalErrorV0::Sqlite);
        }
        ensure_identity_v0(&path, path_identity)?;
        ensure_open_lock_identity_v0(&lock_path, lock_identity, &lock)?;
        // Recheck after initialization to bind the exact schema that will be
        // used by all subsequent authority-row reads and mutations.
        validate_sqlite_schema_v0(&connection)?;
        let persisted: Option<(i64, Vec<u8>)> = connection
            .query_row(
                "SELECT schema_version, namespace FROM tx_admission_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        match persisted {
            Some((schema, stored_namespace)) => {
                if schema != SCHEMA_VERSION_V0 {
                    return Err(TxAdmissionWalErrorV0::SchemaMismatch);
                }
                if stored_namespace.as_slice() != namespace {
                    return Err(TxAdmissionWalErrorV0::NamespaceMismatch);
                }
            }
            None if !created_new => {
                // An initialized path must retain its singleton metadata. A
                // missing row is corruption, not an invitation to mint a new
                // namespace over old nonce/receipt state.
                return Err(TxAdmissionWalErrorV0::SchemaMismatch);
            }
            None => {
                connection
                    .execute(
                        "INSERT INTO tx_admission_meta(singleton, schema_version, namespace)
                         VALUES (1, ?1, ?2)",
                        params![SCHEMA_VERSION_V0, namespace.as_slice()],
                    )
                    .map_err(sqlite_error)?;
                // The metadata insert is part of the same FULL-synchronous
                // SQLite transaction boundary as subsequent reservations. Do
                // not issue a standalone checkpoint here: `execute_batch`
                // rejects PRAGMAs which return rows, and SQLite owns WAL
                // checkpoint scheduling after this point.
            }
        }
        // Bound the inventory before the validator allocates a key vector or
        // decodes any attacker-controlled rows.  A copied SQLite file can be
        // much larger than the live admission capacity; checking the count
        // first keeps restart cost fail-closed and memory-bounded.
        let row_count: i64 = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM pending_nonce WHERE namespace = ?1)
                 + (SELECT COUNT(*) FROM tx_admission_tombstone_v1 WHERE namespace = ?1)",
                params![namespace.as_slice()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let row_count = usize::try_from(row_count).map_err(|_| TxAdmissionWalErrorV0::TooLarge)?;
        if row_count > MAX_RESERVATION_ROWS_V0 {
            return Err(TxAdmissionWalErrorV0::TooLarge);
        }
        validate_pending_rows_v0(&connection, namespace)?;
        validate_receipt_rows_v0(&connection, namespace)?;
        validate_tombstone_rows_v1(&connection, namespace)?;
        let handed_off: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pending_nonce WHERE namespace = ?1 AND state = ?2",
                params![namespace.as_slice(), STATE_HANDED_OFF_V0],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if handed_off != 0 && !allow_handed_off {
            return Err(TxAdmissionWalErrorV0::AmbiguousHandoff);
        }
        ensure_identity_v0(&path, path_identity)?;
        ensure_open_lock_identity_v0(&lock_path, lock_identity, &lock)?;
        Ok(Self {
            connection: Rc::new(RefCell::new(connection)),
            lock,
            lock_path,
            lock_identity,
            path,
            path_identity,
            namespace,
        })
    }

    pub const fn namespace(&self) -> [u8; 32] {
        self.namespace
    }

    /// Opaque process-local identity for this live SQLite authority. It is
    /// used only to prevent a lifecycle token from being committed through a
    /// different boundary instance; it is not a persisted or consensus ID.
    fn owner_binding(&self) -> u64 {
        Rc::as_ptr(&self.connection) as usize as u64
    }

    /// Number of rich pending rows plus compact replay tombstones retained for
    /// this namespace.  A tombstone remains replay-authoritative until an
    /// authenticated application/finality nonce-floor token permits purge.
    pub fn retained_rows(&self) -> Result<usize, TxAdmissionWalErrorV0> {
        self.ensure_identity()?;
        let connection = self
            .connection
            .try_borrow()
            .map_err(|_| TxAdmissionWalErrorV0::Sqlite)?;
        let count: i64 = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM pending_nonce WHERE namespace = ?1)
                 + (SELECT COUNT(*) FROM tx_admission_tombstone_v1 WHERE namespace = ?1)",
                params![self.namespace.as_slice()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        drop(connection);
        self.ensure_identity()?;
        usize::try_from(count).map_err(|_| TxAdmissionWalErrorV0::Malformed)
    }

    /// Inspect unresolved rows through this already-open authority.  Keeping
    /// the lock live across inspection prevents a second process from racing
    /// the recovery owner between enumeration and its authenticated commit.
    pub fn handed_off_records_v0(
        &self,
    ) -> Result<Vec<PendingNonceHandoffRecordV0>, TxAdmissionWalErrorV0> {
        self.ensure_identity()?;
        let connection = self
            .connection
            .try_borrow()
            .map_err(|_| TxAdmissionWalErrorV0::Sqlite)?;
        let mut statement = connection
            .prepare(
                "SELECT signer, nonce FROM pending_nonce
                 WHERE namespace = ?1 AND state = ?2
                 ORDER BY nonce ASC, signer ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![self.namespace.as_slice(), STATE_HANDED_OFF_V0],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(sqlite_error)?;
        let mut records = Vec::new();
        for row in rows {
            let (signer, nonce) = row.map_err(sqlite_error)?;
            let signer = decode_fixed::<32>(signer)?;
            let nonce = u64::from_be_bytes(decode_fixed::<8>(nonce)?);
            let Some((record, state)) = read_row_v0(&connection, self.namespace, signer, nonce)?
            else {
                return Err(TxAdmissionWalErrorV0::Malformed);
            };
            if state != STATE_HANDED_OFF_V0 {
                return Err(TxAdmissionWalErrorV0::Malformed);
            }
            records.push(record.handoff_facts()?);
        }
        drop(statement);
        drop(connection);
        self.ensure_identity()?;
        Ok(records)
    }

    fn has_unresolved_handoff_v0(&self) -> Result<bool, TxAdmissionWalErrorV0> {
        self.ensure_identity()?;
        let connection = self
            .connection
            .try_borrow()
            .map_err(|_| TxAdmissionWalErrorV0::Sqlite)?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pending_nonce
                 WHERE namespace = ?1 AND state = ?2",
                params![self.namespace.as_slice(), STATE_HANDED_OFF_V0],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        drop(connection);
        self.ensure_identity()?;
        Ok(count != 0)
    }

    fn ensure_identity(&self) -> Result<(), TxAdmissionWalErrorV0> {
        ensure_identity_v0(&self.path, self.path_identity)?;
        ensure_open_lock_identity_v0(&self.lock_path, self.lock_identity, &self.lock)
    }

    fn reserve_record<E: ?Sized>(
        &mut self,
        _envelope: &E,
        metadata: &SignedEnvelopeMetadata,
    ) -> Result<SqlitePendingNonceReservationV0, TxAdmissionWalErrorV0> {
        self.ensure_identity()?;
        let expected = AdmissionRecordV0::from_metadata(metadata)?;
        let mut connection = self
            .connection
            .try_borrow_mut()
            .map_err(|_| TxAdmissionWalErrorV0::Sqlite)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some((existing, state)) = read_row_v0(
            &transaction,
            self.namespace,
            expected.signer,
            expected.nonce,
        )? {
            if !row_matches_v0(existing, expected) {
                return Err(TxAdmissionWalErrorV0::Replay);
            }
            if state != STATE_RESERVED_V0 {
                return Err(TxAdmissionWalErrorV0::Replay);
            }
            transaction.commit().map_err(sqlite_error)?;
            self.ensure_identity()?;
            return Ok(SqlitePendingNonceReservationV0 {
                connection: Rc::clone(&self.connection),
                _lock: Rc::clone(&self.lock),
                lock_path: self.lock_path.clone(),
                lock_identity: self.lock_identity,
                path: self.path.clone(),
                path_identity: self.path_identity,
                namespace: self.namespace,
                record: expected,
                state: STATE_RESERVED_V0,
            });
        }
        // A compact tombstone is just as authoritative as a rich pending
        // row.  Check both replay coordinates before allocating a new nonce
        // reservation so GC can never make an old transaction admissible.
        if tombstone_exists_by_nonce_or_digest_v1(
            &transaction,
            self.namespace,
            expected.signer,
            expected.nonce,
            expected.digest,
        )? {
            return Err(TxAdmissionWalErrorV0::Replay);
        }
        if read_state_by_digest_v0(&transaction, self.namespace, expected.digest)?.is_some() {
            return Err(TxAdmissionWalErrorV0::Replay);
        }
        let row_count: i64 = transaction
            .query_row(
                "SELECT (SELECT COUNT(*) FROM pending_nonce WHERE namespace = ?1)
                 + (SELECT COUNT(*) FROM tx_admission_tombstone_v1 WHERE namespace = ?1)",
                params![self.namespace.as_slice()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let row_count = usize::try_from(row_count).map_err(|_| TxAdmissionWalErrorV0::TooLarge)?;
        if row_count >= MAX_RESERVATION_ROWS_V0 {
            return Err(TxAdmissionWalErrorV0::TooLarge);
        }
        let nonce_blob = to_blob_u64(expected.nonce);
        let fee_blob = to_blob_u128(expected.fee_limit);
        let gas_blob = to_blob_u64(expected.max_gas);
        let bytes_blob = to_blob_u64(expected.max_bytes);
        transaction
            .execute(
                "INSERT INTO pending_nonce
                 (namespace, signer, nonce, digest, body_digest, fee_limit,
                  max_gas, max_bytes, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    self.namespace.as_slice(),
                    expected.signer.as_slice(),
                    nonce_blob.as_slice(),
                    expected.digest.as_slice(),
                    expected.body_digest.as_slice(),
                    fee_blob.as_slice(),
                    gas_blob.as_slice(),
                    bytes_blob.as_slice(),
                    STATE_RESERVED_V0,
                ],
            )
            .map_err(map_insert_error_v0)?;
        transaction.commit().map_err(sqlite_error)?;
        self.ensure_identity()?;
        Ok(SqlitePendingNonceReservationV0 {
            connection: Rc::clone(&self.connection),
            _lock: Rc::clone(&self.lock),
            lock_path: self.lock_path.clone(),
            lock_identity: self.lock_identity,
            path: self.path.clone(),
            path_identity: self.path_identity,
            namespace: self.namespace,
            record: expected,
            state: STATE_RESERVED_V0,
        })
    }

    /// Persist an authenticated application/finality readback and advance the
    /// exact handed-off row in one SQLite transaction. This method is a
    /// candidate boundary; it does not invoke execution, networking, signing,
    /// or broadcast. A caller must still resolve the in-memory admission token
    /// after this durable operation returns.
    pub fn commit_handed_off_with_receipt(
        &mut self,
        metadata: &SignedEnvelopeMetadata,
        receipt: &VerifiedNativeCommitReceiptV0,
    ) -> Result<(), TxAdmissionWalErrorV0> {
        self.ensure_identity()?;
        let expected = AdmissionRecordV0::from_metadata(metadata)?;
        if receipt.evidence.tx_digest != expected.digest {
            return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
        }
        let mut connection = self
            .connection
            .try_borrow_mut()
            .map_err(|_| TxAdmissionWalErrorV0::Sqlite)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let Some((existing, state)) = read_row_v0(
            &transaction,
            self.namespace,
            expected.signer,
            expected.nonce,
        )?
        else {
            return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
        };
        if !row_matches_v0(existing, expected) {
            return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
        }
        if state == STATE_COMMITTED_V0 {
            let Some(commitment) = read_receipt_commitment_v0(
                &transaction,
                self.namespace,
                expected.signer,
                expected.nonce,
            )?
            else {
                return Err(TxAdmissionWalErrorV0::CommitReceiptConflict);
            };
            if commitment != receipt.commitment {
                return Err(TxAdmissionWalErrorV0::CommitReceiptConflict);
            }
            transaction.commit().map_err(sqlite_error)?;
            self.ensure_identity()?;
            return Ok(());
        }
        if state != STATE_HANDED_OFF_V0 {
            return Err(TxAdmissionWalErrorV0::ReservationConflict);
        }
        if read_receipt_commitment_v0(
            &transaction,
            self.namespace,
            expected.signer,
            expected.nonce,
        )?
        .is_some()
        {
            return Err(TxAdmissionWalErrorV0::CommitReceiptConflict);
        }
        let evidence = receipt.evidence;
        let nonce_blob = to_blob_u64(expected.nonce);
        let height_blob = to_blob_u64(evidence.block_height.get());
        transaction
            .execute(
                "INSERT INTO tx_commit_receipt_v0
                 (namespace, signer, nonce, tx_digest, block_id, block_height,
                  state_root, receipt_digest, finality_proof_digest, commitment)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    self.namespace.as_slice(),
                    expected.signer.as_slice(),
                    nonce_blob.as_slice(),
                    evidence.tx_digest.as_slice(),
                    evidence.block_id.as_bytes(),
                    height_blob.as_slice(),
                    evidence.state_root.as_bytes(),
                    evidence.receipt_digest.as_slice(),
                    evidence.finality_proof_digest.as_slice(),
                    receipt.commitment.as_slice(),
                ],
            )
            .map_err(|error| match error.sqlite_error_code() {
                Some(rusqlite::ffi::ErrorCode::ConstraintViolation) => {
                    TxAdmissionWalErrorV0::CommitReceiptConflict
                }
                _ => sqlite_error(error),
            })?;
        let changed = transaction
            .execute(
                "UPDATE pending_nonce SET state = ?1
                 WHERE namespace = ?2 AND signer = ?3 AND nonce = ?4 AND state = ?5",
                params![
                    STATE_COMMITTED_V0,
                    self.namespace.as_slice(),
                    expected.signer.as_slice(),
                    nonce_blob.as_slice(),
                    STATE_HANDED_OFF_V0,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(TxAdmissionWalErrorV0::ReservationConflict);
        }
        transaction.commit().map_err(sqlite_error)?;
        self.ensure_identity()?;
        Ok(())
    }
}

impl<E: ?Sized> PendingNonceAuthority<E> for SqlitePendingNonceAuthorityV0 {
    fn reserve_pending_nonce(
        &mut self,
        envelope: &E,
        metadata: &SignedEnvelopeMetadata,
    ) -> Result<Box<dyn PendingNonceReservation>, AdmissionReject> {
        self.reserve_record(envelope, metadata)
            .map(|reservation| Box::new(reservation) as Box<dyn PendingNonceReservation>)
            .map_err(map_reject_v0)
    }
}

#[derive(Debug)]
struct SqlitePendingNonceReservationV0 {
    // The Rc lock keeps the single-owner file lock held while a token is live,
    // even if the authority value itself is dropped by the caller.
    connection: Rc<RefCell<Connection>>,
    // Retain the sidecar lock while this token is alive, even if the authority
    // value itself is moved or dropped by its caller.
    _lock: Rc<File>,
    lock_path: PathBuf,
    lock_identity: PathIdentityV0,
    path: PathBuf,
    path_identity: PathIdentityV0,
    namespace: [u8; 32],
    record: AdmissionRecordV0,
    state: i64,
}

impl SqlitePendingNonceReservationV0 {
    fn ensure_identity(&self) -> Result<(), AdmissionReject> {
        ensure_identity_v0(&self.path, self.path_identity)
            .and_then(|()| {
                ensure_open_lock_identity_v0(&self.lock_path, self.lock_identity, &self._lock)
            })
            .map_err(|_| AdmissionReject::InconsistentState)
    }

    fn transition(&mut self, target_state: i64) -> Result<(), AdmissionReject> {
        if self.state == target_state {
            return Ok(());
        }
        self.ensure_identity()?;
        let mut connection = self
            .connection
            .try_borrow_mut()
            .map_err(|_| AdmissionReject::InconsistentState)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AdmissionReject::InconsistentState)?;
        let Some((existing, state)) = read_row_v0(
            &transaction,
            self.namespace,
            self.record.signer,
            self.record.nonce,
        )
        .map_err(map_reject_v0)?
        else {
            return Err(AdmissionReject::InconsistentState);
        };
        if !row_matches_v0(existing, self.record) {
            return Err(AdmissionReject::InconsistentState);
        }
        let idempotent = matches!(
            (target_state, state),
            (STATE_HANDED_OFF_V0, STATE_HANDED_OFF_V0)
                | (STATE_COMMITTED_V0, STATE_COMMITTED_V0)
                | (STATE_RELEASED_V0, STATE_RELEASED_V0)
        );
        if !idempotent {
            let allowed = match target_state {
                STATE_HANDED_OFF_V0 => state == STATE_RESERVED_V0,
                STATE_COMMITTED_V0 => state == STATE_HANDED_OFF_V0,
                // A handed-off row is execution-ambiguous.  Only the
                // authenticated receipt recovery path may resolve it; a
                // drop/cancel must never turn it into a replay tombstone.
                STATE_RELEASED_V0 => state == STATE_RESERVED_V0,
                _ => false,
            };
            if !allowed {
                return Err(AdmissionReject::ReservationStateConflict);
            }
            let changed = transaction
                .execute(
                    "UPDATE pending_nonce SET state = ?1
                     WHERE namespace = ?2 AND signer = ?3 AND nonce = ?4 AND state = ?5",
                    params![
                        target_state,
                        self.namespace.as_slice(),
                        self.record.signer.as_slice(),
                        to_blob_u64(self.record.nonce).as_slice(),
                        state,
                    ],
                )
                .map_err(|_| AdmissionReject::InconsistentState)?;
            if changed != 1 {
                return Err(AdmissionReject::InconsistentState);
            }
        }
        transaction
            .commit()
            .map_err(|_| AdmissionReject::InconsistentState)?;
        self.ensure_identity()?;
        self.state = target_state;
        Ok(())
    }
}

impl PendingNonceReservation for SqlitePendingNonceReservationV0 {
    fn owner_binding(&self) -> Option<u64> {
        Some(Rc::as_ptr(&self.connection) as usize as u64)
    }

    fn handoff(&mut self) -> Result<(), AdmissionReject> {
        if self.state != STATE_RESERVED_V0 {
            return Err(AdmissionReject::ReservationStateConflict);
        }
        self.transition(STATE_HANDED_OFF_V0)
    }

    fn commit(&mut self) -> Result<(), AdmissionReject> {
        if self.state != STATE_HANDED_OFF_V0 {
            return Err(AdmissionReject::ReservationStateConflict);
        }
        self.transition(STATE_COMMITTED_V0)
    }

    fn release(&mut self) -> Result<(), AdmissionReject> {
        if self.state != STATE_RESERVED_V0 {
            return Err(AdmissionReject::ReservationStateConflict);
        }
        self.transition(STATE_RELEASED_V0)
    }
}

fn map_reject_v0(error: TxAdmissionWalErrorV0) -> AdmissionReject {
    match error {
        TxAdmissionWalErrorV0::Replay => AdmissionReject::Replay,
        TxAdmissionWalErrorV0::ReservationConflict => AdmissionReject::ReservationStateConflict,
        TxAdmissionWalErrorV0::AmbiguousHandoff => AdmissionReject::InconsistentState,
        TxAdmissionWalErrorV0::CommitReceiptMismatch
        | TxAdmissionWalErrorV0::CommitReceiptConflict
        | TxAdmissionWalErrorV0::CommitReadbackUnavailable
        | TxAdmissionWalErrorV0::HandoffRecoveryUnavailable => AdmissionReject::InconsistentState,
        TxAdmissionWalErrorV0::InvalidPath
        | TxAdmissionWalErrorV0::InvalidNamespace
        | TxAdmissionWalErrorV0::LockUnavailable
        | TxAdmissionWalErrorV0::PathReplaced
        | TxAdmissionWalErrorV0::Io
        | TxAdmissionWalErrorV0::Sqlite
        | TxAdmissionWalErrorV0::SchemaMismatch
        | TxAdmissionWalErrorV0::NamespaceMismatch
        | TxAdmissionWalErrorV0::Malformed
        | TxAdmissionWalErrorV0::TooLarge => AdmissionReject::InconsistentState,
    }
}

include!("tx_admission_wal_tombstone_gc_v1.inc");

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    use trnm_application_tx_builder_v0::{
        build_signed_canonical_tx_v0, ApplicationSignerV0, CanonicalTxBuildContextV0,
        TxBuilderLimitsV0,
    };
    use trnm_consensus_types::{
        BlockHeader, BlockKind, CertifiedHeaderV0, ChainId, ConsensusParametersV0,
        ConsensusPublicKey, Epoch, EvidenceRoot, GenesisHash, GenesisQcV0, PayloadDigest,
        ProtocolVersion, QcReferenceV0, QuorumCertificate, ReceiptsRoot, Signature64,
        SignatureBytes, StateRoot as ConsensusStateRoot, Validator, ValidatorId, ValidatorSet,
        View, Vote, VotingPower,
    };
    use trnm_finality_types::crypto::public_key_hex;
    use trnm_mempool::{
        CanonicalSignerId, CanonicalTxDigest, IngressClass, PendingNonceReservationState,
        ResourceLimits, SignedAdmissionHooks, SignedEnvelopeView, TypedAdmissionGate,
        TypedAdmitOutcome,
    };
    use trnm_native_application::{
        NativeApplicationCommitRequestV0, NativeApplicationGenesisRequestV0, NativeApplicationV0,
        NativeBlockExecutionRequestV0, NativeBlockExecutionResultV0,
        NativeExpectedBlockCommitmentsV0,
    };
    use trnm_native_execution_v0::{
        AuthorizedSignerV0, CanonicalLabNativeApplicationConfigInputsV0, NativeApplicationConfigV0,
        NativeBlockPreviewRequestV0,
    };
    use trnm_protocol::CanonicalCommandV1;

    static NEXT_PATH_V0: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct FixtureEnvelope {
        digest: CanonicalTxDigest,
        signer: CanonicalSignerId,
        body: Vec<u8>,
        nonce: u64,
    }

    impl SignedEnvelopeView for FixtureEnvelope {
        fn canonical_digest(&self) -> CanonicalTxDigest {
            self.digest
        }

        fn canonical_signer_id(&self) -> Result<CanonicalSignerId, AdmissionReject> {
            Ok(self.signer)
        }

        fn canonical_body(&self) -> &[u8] {
            &self.body
        }

        fn nonce(&self) -> u64 {
            self.nonce
        }

        fn fee_limit(&self) -> u128 {
            17
        }

        fn resource_limits(&self) -> ResourceLimits {
            ResourceLimits {
                max_gas: 10_000,
                max_bytes: self.body.len() as u64,
            }
        }

        fn validate_canonical(&self) -> Result<(), AdmissionReject> {
            Ok(())
        }
    }

    struct Hooks;

    impl SignedAdmissionHooks<FixtureEnvelope> for Hooks {
        fn verify_signature(
            &mut self,
            _envelope: &FixtureEnvelope,
            _metadata: &SignedEnvelopeMetadata,
        ) -> Result<(), AdmissionReject> {
            Ok(())
        }

        fn recheck(&mut self, _metadata: &SignedEnvelopeMetadata) -> Result<(), AdmissionReject> {
            Ok(())
        }
    }

    struct BuilderFixtureSigner {
        key: SigningKey,
        id: String,
        public_key: String,
    }

    impl ApplicationSignerV0 for BuilderFixtureSigner {
        fn signer_id(&self) -> &str {
            &self.id
        }

        fn signer_role(&self) -> &str {
            "account"
        }

        fn public_key_hex(&self) -> &str {
            &self.public_key
        }

        fn sign(&self, preimage: &[u8]) -> anyhow::Result<[u8; 64]> {
            Ok(self.key.sign(preimage).to_bytes())
        }
    }

    /// The native readback fixture uses the same deterministic envelope shape
    /// as the builder test, but marks the signer as an operator so the real
    /// native runtime will execute its `CreditAccount` command. This remains
    /// test-only key material; no production signer edge is enabled.
    struct NativeFixtureSigner {
        key: SigningKey,
        id: String,
        public_key: String,
    }

    impl ApplicationSignerV0 for NativeFixtureSigner {
        fn signer_id(&self) -> &str {
            &self.id
        }

        fn signer_role(&self) -> &str {
            "operator"
        }

        fn public_key_hex(&self) -> &str {
            &self.public_key
        }

        fn sign(&self, preimage: &[u8]) -> anyhow::Result<[u8; 64]> {
            Ok(self.key.sign(preimage).to_bytes())
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct BuilderFixtureSignerResolver {
        signer: CanonicalSignerId,
    }

    impl CanonicalSignerIdentityResolverV0 for BuilderFixtureSignerResolver {
        fn resolve_canonical_signer_id_v0(
            &self,
            transaction: &BuiltCanonicalTxV0,
        ) -> Result<CanonicalSignerId, AdmissionReject> {
            if transaction.envelope().signer_id != "did:trnm:alice" {
                return Err(AdmissionReject::SignerIdentityUnavailable);
            }
            Ok(self.signer)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct BuilderFixtureAdmissionContext {
        chain_id: &'static str,
        now_unix_ms: u64,
    }

    impl CanonicalAdmissionContextResolverV0 for BuilderFixtureAdmissionContext {
        fn chain_id_v0(&self) -> &str {
            self.chain_id
        }

        fn now_unix_ms_v0(&self) -> u64 {
            self.now_unix_ms
        }
    }

    struct AcceptingCommitVerifier;

    impl NativeCommitReceiptVerifierV0 for AcceptingCommitVerifier {
        fn verify_application_and_finality_v0(
            &self,
            _metadata: &SignedEnvelopeMetadata,
            evidence: &NativeCommitReceiptEvidenceV0,
        ) -> Result<(), TxAdmissionWalErrorV0> {
            if evidence.block_height.get() == 0 {
                return Err(TxAdmissionWalErrorV0::CommitReadbackUnavailable);
            }
            Ok(())
        }
    }

    struct RejectingCommitVerifier;

    impl NativeCommitReceiptVerifierV0 for RejectingCommitVerifier {
        fn verify_application_and_finality_v0(
            &self,
            _metadata: &SignedEnvelopeMetadata,
            _evidence: &NativeCommitReceiptEvidenceV0,
        ) -> Result<(), TxAdmissionWalErrorV0> {
            Err(TxAdmissionWalErrorV0::CommitReadbackUnavailable)
        }
    }

    fn fixture() -> FixtureEnvelope {
        FixtureEnvelope {
            digest: CanonicalTxDigest::from_bytes([0x11; 32]).unwrap(),
            signer: CanonicalSignerId::from_bytes([0x22; 32]).unwrap(),
            body: b"canonical-body".to_vec(),
            nonce: 7,
        }
    }

    fn builder_fixture_transaction() -> BuiltCanonicalTxV0 {
        let key = SigningKey::from_bytes(&[0x47; 32]);
        let signer = BuilderFixtureSigner {
            public_key: hex::encode(key.verifying_key().to_bytes()),
            key,
            id: "did:trnm:alice".to_owned(),
        };
        build_signed_canonical_tx_v0(
            CanonicalTxBuildContextV0 {
                chain_id: "trnm-devnet".to_owned(),
                sender: signer.id.clone(),
                command_id: None,
                nonce: 7,
                issued_at_unix_ms: 1_000,
                expires_at_unix_ms: 2_000,
                max_gas: 10_000,
                fee_limit: 17,
                limits: TxBuilderLimitsV0::candidate_v0(),
            },
            CanonicalCommandV1::CreditAccount {
                account: signer.id.clone(),
                amount: 1,
            },
            &signer,
        )
        .unwrap()
    }

    fn native_fixture_transaction() -> BuiltCanonicalTxV0 {
        let key = SigningKey::from_bytes(&[0x47; 32]);
        let signer = NativeFixtureSigner {
            public_key: hex::encode(key.verifying_key().to_bytes()),
            key,
            id: "did:operator:1".to_owned(),
        };
        build_signed_canonical_tx_v0(
            CanonicalTxBuildContextV0 {
                chain_id: "trnm-devnet".to_owned(),
                sender: signer.id.clone(),
                command_id: Some("durable-credit-1".to_owned()),
                nonce: 1,
                issued_at_unix_ms: 1_700_000_000_000,
                expires_at_unix_ms: 1_700_000_100_000,
                max_gas: 10_000,
                fee_limit: 17,
                limits: TxBuilderLimitsV0::candidate_v0(),
            },
            CanonicalCommandV1::CreditAccount {
                account: "did:client:1".to_owned(),
                amount: 10_000,
            },
            &signer,
        )
        .unwrap()
    }

    #[derive(Debug, Clone, Copy)]
    struct NativeFixtureSignerResolver {
        signer: CanonicalSignerId,
    }

    impl CanonicalSignerIdentityResolverV0 for NativeFixtureSignerResolver {
        fn resolve_canonical_signer_id_v0(
            &self,
            transaction: &BuiltCanonicalTxV0,
        ) -> Result<CanonicalSignerId, AdmissionReject> {
            if transaction.envelope().signer_id != "did:operator:1" {
                return Err(AdmissionReject::SignerIdentityUnavailable);
            }
            Ok(self.signer)
        }
    }

    fn native_fixture_validator_set(parameters: &ConsensusParametersV0) -> ValidatorSet {
        let validators = (0_u8..4)
            .map(|index| {
                let key = SigningKey::from_bytes(&[20 + index; 32]);
                Validator::new(
                    ValidatorId::from_bytes(format!("p2-validator-{index}").as_bytes()).unwrap(),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        ValidatorSet::new(
            GenesisHash::new([0xD0; 32]),
            ChainId::new("trnm-devnet").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap()
    }

    fn native_fixture_config() -> NativeApplicationConfigV0 {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validator_set = native_fixture_validator_set(&parameters);
        let application_key = SigningKey::from_bytes(&[0x47; 32]);
        let client_key = SigningKey::from_bytes(&[0x52; 32]);
        let application_signers = vec![
            AuthorizedSignerV0::new(
                "did:operator:1",
                "operator",
                public_key_hex(&application_key),
            )
            .unwrap(),
            AuthorizedSignerV0::new("did:client:1", "hepta", public_key_hex(&client_key)).unwrap(),
        ];
        NativeApplicationConfigV0::from_canonical_lab_inputs_v0(
            CanonicalLabNativeApplicationConfigInputsV0::new(
                "p2-native-readback-test",
                [0xD1; 32],
                [0xD2; 32],
                [0xD3; 32],
                [0xD4; 32],
                validator_set.validators()[0].id(),
                validator_set,
                parameters,
                application_signers,
                "did:operator:1",
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn native_fixture_genesis_request(
        config: &NativeApplicationConfigV0,
    ) -> NativeApplicationGenesisRequestV0 {
        NativeApplicationGenesisRequestV0::new(
            trnm_native_application::ChainIdV0::new(config.chain_id_v0()).unwrap(),
            trnm_native_application::GenesisHashV0::new(config.genesis_hash_v0()).unwrap(),
            trnm_native_application::Hash32V0::new(config.chain_descriptor_hash_v0()),
            trnm_native_application::Hash32V0::new(config.signer_policy_commitment_v0()),
            trnm_native_application::StateRootV0::new(config.initial_state_root()).unwrap(),
            config.initial_validator_set().clone(),
        )
        .unwrap()
    }

    /// Build a shape-valid but cryptographically unauthenticated three-chain
    /// for the exact executed header. The durable application must reject it
    /// before the WAL can mint a commit receipt; the proof object itself is
    /// intentionally not an authority.
    fn native_fixture_structural_proof(
        execution: &NativeBlockExecutionRequestV0,
        set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> FinalityProofV0 {
        fn qc_for(set: &ValidatorSet, header: &BlockHeader) -> QuorumCertificate {
            let votes = set
                .validators()
                .iter()
                .take(3)
                .map(|validator| {
                    Vote::new(
                        set.chain_id(),
                        set.protocol_version(),
                        set.epoch(),
                        header.view(),
                        header.height(),
                        header.id(),
                        set.id(),
                        validator.id(),
                        SignatureBytes::from_array([0x11; 64]),
                        set,
                    )
                    .unwrap()
                })
                .collect();
            QuorumCertificate::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                header.view(),
                header.height(),
                header.id(),
                set.id(),
                votes,
                set,
            )
            .unwrap()
        }

        fn certified(
            header: BlockHeader,
            justify: QcReferenceV0,
            qc: QuorumCertificate,
            set: &ValidatorSet,
            parameters: &ConsensusParametersV0,
            authenticated_parent_timestamp_ms: u64,
        ) -> CertifiedHeaderV0 {
            CertifiedHeaderV0::new(
                header,
                justify,
                None,
                None,
                Signature64::from_array([0x22; 64]),
                qc,
                set,
                None,
                parameters,
                authenticated_parent_timestamp_ms,
            )
            .unwrap()
        }

        let expected = execution.expected();
        let h1 = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(1),
            trnm_consensus_types::Height::new(1),
            BlockKind::Regular,
            BlockId::new(*execution.parent().block_id().as_bytes()),
            set.validators()[0].id(),
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new(*expected.payload_root().as_bytes()),
            ConsensusStateRoot::new(*expected.post_state_root().as_bytes()),
            ReceiptsRoot::new(*expected.receipts_root().as_bytes()),
            EvidenceRoot::new(*expected.evidence_root().as_bytes()),
            execution.timestamp_ms(),
            None,
        )
        .unwrap();
        let q1 = qc_for(set, &h1);
        let c1 = certified(
            h1.clone(),
            QcReferenceV0::genesis_anchor(
                GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).unwrap(),
            ),
            q1.clone(),
            set,
            parameters,
            authenticated_parent_timestamp_ms,
        );

        let h2 = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(2),
            trnm_consensus_types::Height::new(2),
            BlockKind::Regular,
            h1.id(),
            set.validators()[1].id(),
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new([0x61; 32]),
            ConsensusStateRoot::new([0x62; 32]),
            ReceiptsRoot::new([0x63; 32]),
            EvidenceRoot::new([0x64; 32]),
            execution.timestamp_ms() + 1,
            None,
        )
        .unwrap();
        let q2 = qc_for(set, &h2);
        let c2 = certified(
            h2.clone(),
            QcReferenceV0::ordinary(q1),
            q2.clone(),
            set,
            parameters,
            h1.timestamp_ms(),
        );

        let h3 = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(3),
            trnm_consensus_types::Height::new(3),
            BlockKind::Regular,
            h2.id(),
            set.validators()[2].id(),
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new([0x71; 32]),
            ConsensusStateRoot::new([0x72; 32]),
            ReceiptsRoot::new([0x73; 32]),
            EvidenceRoot::new([0x74; 32]),
            execution.timestamp_ms() + 2,
            None,
        )
        .unwrap();
        let q3 = qc_for(set, &h3);
        let c3 = certified(
            h3,
            QcReferenceV0::ordinary(q2),
            q3,
            set,
            parameters,
            h2.timestamp_ms(),
        );
        FinalityProofV0::new(
            c1,
            c2,
            c3,
            set,
            None,
            parameters,
            authenticated_parent_timestamp_ms,
        )
        .unwrap()
    }

    fn commit_evidence_for(envelope: &FixtureEnvelope) -> NativeCommitReceiptEvidenceV0 {
        NativeCommitReceiptEvidenceV0::new(
            envelope.digest.as_bytes(),
            BlockId::new([0x31; 32]),
            Height::new(12),
            StateRoot::new([0x32; 32]),
            [0x33; 32],
            [0x34; 32],
        )
        .unwrap()
    }

    fn temp_path() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = NEXT_PATH_V0.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "trnm-poco-tx-admission-{stamp}-{}-{id}.sqlite",
            std::process::id()
        ))
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        if let Ok(lock) = lock_path_v0(path) {
            let _ = fs::remove_file(lock);
        }
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
    }

    #[cfg(unix)]
    fn replace_lock_path_for_test(path: &Path) -> PathBuf {
        use std::os::unix::fs::OpenOptionsExt;

        let lock_path = lock_path_v0(path).unwrap();
        let moved_path = lock_path.with_file_name(format!(
            "{}.moved-{}",
            lock_path.file_name().unwrap().to_string_lossy(),
            NEXT_PATH_V0.fetch_add(1, Ordering::Relaxed)
        ));
        fs::rename(&lock_path, &moved_path).unwrap();
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        options.open(&lock_path).unwrap();
        moved_path
    }

    fn seed_row(path: &Path, namespace: [u8; 32], state: i64) {
        let authority = SqlitePendingNonceAuthorityV0::open(path, namespace).unwrap();
        let record = AdmissionRecordV0 {
            signer: [0x22; 32],
            nonce: 7,
            digest: [0x11; 32],
            body_digest: body_digest_v0(b"canonical-body"),
            fee_limit: 17,
            max_gas: 10_000,
            max_bytes: b"canonical-body".len() as u64,
        };
        let nonce_blob = to_blob_u64(record.nonce);
        let fee_blob = to_blob_u128(record.fee_limit);
        let gas_blob = to_blob_u64(record.max_gas);
        let bytes_blob = to_blob_u64(record.max_bytes);
        let connection = authority.connection.borrow();
        connection
            .execute(
                "INSERT INTO pending_nonce
                 (namespace, signer, nonce, digest, body_digest, fee_limit,
                  max_gas, max_bytes, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    namespace.as_slice(),
                    record.signer.as_slice(),
                    nonce_blob.as_slice(),
                    record.digest.as_slice(),
                    record.body_digest.as_slice(),
                    fee_blob.as_slice(),
                    gas_blob.as_slice(),
                    bytes_blob.as_slice(),
                    state,
                ],
            )
            .unwrap();
        drop(connection);
        drop(authority);
    }

    #[test]
    fn reserve_lifecycle_is_durable_and_idempotent() {
        let path = temp_path();
        let envelope = fixture();
        let mut authority = SqlitePendingNonceAuthorityV0::open(&path, [0x33; 32]).unwrap();
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let mut hooks = Hooks;
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &envelope,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = gate.pop_ready_with_lifecycle().unwrap();
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::Reserved)
        );
        ready.handoff().unwrap();
        ready.commit().unwrap();
        assert_eq!(authority.retained_rows().unwrap(), 1);
        drop(ready);
        drop(authority);

        let reopened = SqlitePendingNonceAuthorityV0::open(&path, [0x33; 32]).unwrap();
        assert_eq!(reopened.retained_rows().unwrap(), 1);
        drop(reopened);
        cleanup(&path);
    }

    #[test]
    fn receipt_rows_are_reaudited_against_committed_nonce_on_restart() {
        let path = temp_path();
        let namespace = [0xA8; 32];
        seed_row(&path, namespace, STATE_COMMITTED_V0);

        let evidence = NativeCommitReceiptEvidenceV0::new(
            [0x11; 32],
            BlockId::new([0x41; 32]),
            Height::new(3),
            StateRoot::new([0x42; 32]),
            [0x43; 32],
            [0x44; 32],
        )
        .unwrap();
        let commitment = evidence.canonical_commitment();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "INSERT INTO tx_commit_receipt_v0
                 (namespace, signer, nonce, tx_digest, block_id, block_height,
                  state_root, receipt_digest, finality_proof_digest, commitment)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    namespace.as_slice(),
                    [0x22u8; 32].as_slice(),
                    to_blob_u64(7).as_slice(),
                    evidence.tx_digest.as_slice(),
                    evidence.block_id.as_bytes(),
                    to_blob_u64(evidence.block_height.get()).as_slice(),
                    evidence.state_root.as_bytes(),
                    evidence.receipt_digest.as_slice(),
                    evidence.finality_proof_digest.as_slice(),
                    commitment.as_slice(),
                ],
            )
            .unwrap();
        drop(connection);

        // A valid receipt row is accepted and the older committed-without-
        // receipt lifecycle remains valid for the same namespace.
        let authority = SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap();
        drop(authority);

        // A receipt is only authoritative for a committed pending nonce.  A
        // rollback/mixed-state edit that leaves the receipt behind must fail
        // before the authority can hand out any reservation.
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE pending_nonce SET state = ?1
                 WHERE namespace = ?2 AND signer = ?3 AND nonce = ?4",
                params![
                    STATE_HANDED_OFF_V0,
                    namespace.as_slice(),
                    [0x22u8; 32].as_slice(),
                    to_blob_u64(7).as_slice(),
                ],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap_err(),
            TxAdmissionWalErrorV0::Malformed
        );

        // Restore the pending row so the independent commitment-tamper check
        // below remains isolated and deterministic.
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE pending_nonce SET state = ?1
                 WHERE namespace = ?2 AND signer = ?3 AND nonce = ?4",
                params![
                    STATE_COMMITTED_V0,
                    namespace.as_slice(),
                    [0x22u8; 32].as_slice(),
                    to_blob_u64(7).as_slice(),
                ],
            )
            .unwrap();
        drop(connection);

        // A self-consistent but substituted commitment must not survive a
        // restart.  This is the exact rollback/tamper boundary that the old
        // pending-row-only audit missed.
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE tx_commit_receipt_v0 SET commitment = ?1
                 WHERE namespace = ?2 AND signer = ?3 AND nonce = ?4",
                params![
                    [0xFEu8; 32].as_slice(),
                    namespace.as_slice(),
                    [0x22u8; 32].as_slice(),
                    to_blob_u64(7).as_slice(),
                ],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap_err(),
            TxAdmissionWalErrorV0::Malformed
        );
        cleanup(&path);
    }

    #[test]
    fn orphan_receipt_row_is_rejected_before_authority_open() {
        let path = temp_path();
        let namespace = [0xA9; 32];
        let authority = SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap();
        drop(authority);

        let evidence = NativeCommitReceiptEvidenceV0::new(
            [0x51; 32],
            BlockId::new([0x61; 32]),
            Height::new(1),
            StateRoot::new([0x62; 32]),
            [0x63; 32],
            [0x64; 32],
        )
        .unwrap();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "INSERT INTO tx_commit_receipt_v0
                 (namespace, signer, nonce, tx_digest, block_id, block_height,
                  state_root, receipt_digest, finality_proof_digest, commitment)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    namespace.as_slice(),
                    [0x71u8; 32].as_slice(),
                    to_blob_u64(9).as_slice(),
                    evidence.tx_digest.as_slice(),
                    evidence.block_id.as_bytes(),
                    to_blob_u64(evidence.block_height.get()).as_slice(),
                    evidence.state_root.as_bytes(),
                    evidence.receipt_digest.as_slice(),
                    evidence.finality_proof_digest.as_slice(),
                    evidence.canonical_commitment().as_slice(),
                ],
            )
            .unwrap();
        drop(connection);

        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap_err(),
            TxAdmissionWalErrorV0::Malformed
        );
        cleanup(&path);
    }

    #[test]
    fn schema_drift_without_pending_primary_or_digest_unique_is_rejected_before_open() {
        let path = temp_path();
        let namespace = [0xAA; 32];
        let authority = SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap();
        drop(authority);

        // Keep all queried column names but remove both constraints which make
        // `(namespace, signer, nonce)` and `(namespace, digest)` authoritative.
        // Without the schema audit, duplicate legal-looking rows would make
        // query_row-based replay decisions depend on SQLite row order.
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TABLE pending_nonce;
                 CREATE TABLE pending_nonce (
                     namespace BLOB NOT NULL,
                     signer BLOB NOT NULL,
                     nonce BLOB NOT NULL,
                     digest BLOB NOT NULL,
                     body_digest BLOB NOT NULL,
                     fee_limit BLOB NOT NULL,
                     max_gas BLOB NOT NULL,
                     max_bytes BLOB NOT NULL,
                     state INTEGER NOT NULL
                 );",
            )
            .unwrap();
        drop(connection);

        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap_err(),
            TxAdmissionWalErrorV0::SchemaMismatch
        );
        cleanup(&path);
    }

    #[test]
    fn injected_wal_schema_objects_are_rejected_before_open() {
        let path = temp_path();
        let namespace = [0xAB; 32];
        let authority = SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap();
        drop(authority);

        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE injected_wal_schema_v0(value INTEGER);
                 CREATE TRIGGER injected_wal_trigger_v0
                 AFTER INSERT ON pending_nonce
                 BEGIN SELECT 1; END;",
            )
            .unwrap();
        drop(connection);

        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap_err(),
            TxAdmissionWalErrorV0::SchemaMismatch
        );
        cleanup(&path);
    }

    #[test]
    fn missing_wal_authority_table_is_rejected_without_schema_repair() {
        // Each table is tested in a separate file so the assertion proves
        // that an existing path is never treated as virgin after one
        // authority object has been removed.
        for (index, (table, drop_sql)) in [
            ("tx_admission_meta", "DROP TABLE tx_admission_meta;"),
            ("pending_nonce", "DROP TABLE pending_nonce;"),
            ("tx_commit_receipt_v0", "DROP TABLE tx_commit_receipt_v0;"),
            (
                "tx_admission_tombstone_v1",
                "DROP TABLE tx_admission_tombstone_v1;",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let path = temp_path();
            let namespace = [0xAC + index as u8; 32];
            let authority = SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap();
            drop(authority);

            let connection = Connection::open(&path).unwrap();
            connection.execute_batch(drop_sql).unwrap();
            drop(connection);

            assert_eq!(
                SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap_err(),
                TxAdmissionWalErrorV0::SchemaMismatch,
                "removed {table} must not be recreated on restart"
            );
            let connection = Connection::open(&path).unwrap();
            let still_missing: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(still_missing, 0, "failed open must not repair {table}");
            cleanup(&path);
        }
    }

    #[test]
    fn exact_reserved_row_retries_after_restart_and_conflicts_fail_closed() {
        let path = temp_path();
        let envelope = fixture();
        seed_row(&path, [0x44; 32], STATE_RESERVED_V0);
        let mut authority = SqlitePendingNonceAuthorityV0::open(&path, [0x44; 32]).unwrap();
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let mut hooks = Hooks;
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &envelope,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = gate.pop_ready_with_lifecycle().unwrap();
        ready.handoff().unwrap();
        ready.commit().unwrap();

        let mut changed = fixture();
        changed.digest = CanonicalTxDigest::from_bytes([0x55; 32]).unwrap();
        let mut gate2 = TypedAdmissionGate::with_default_body_limit(2, 0);
        assert_eq!(
            gate2.admit_signed_with_pending_nonce(
                &changed,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::Replay)
        );
        cleanup(&path);
    }

    #[test]
    fn handed_off_restart_is_ambiguous_and_second_owner_is_locked() {
        let path = temp_path();
        seed_row(&path, [0x66; 32], STATE_HANDED_OFF_V0);
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, [0x66; 32]).unwrap_err(),
            TxAdmissionWalErrorV0::AmbiguousHandoff
        );
        cleanup(&path);
    }

    #[test]
    fn handed_off_release_and_drop_remain_ambiguous_until_receipt_recovery() {
        // An explicit release after handoff must fail before it can rewrite
        // the durable row into a replay tombstone.
        let explicit_path = temp_path();
        let explicit_namespace = [0x68; 32];
        {
            let envelope = fixture();
            let mut authority =
                SqlitePendingNonceAuthorityV0::open(&explicit_path, explicit_namespace).unwrap();
            let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
            let mut hooks = Hooks;
            assert_eq!(
                gate.admit_signed_with_pending_nonce(
                    &envelope,
                    IngressClass::Normal,
                    &mut hooks,
                    &mut authority,
                ),
                TypedAdmitOutcome::Accepted
            );
            let mut ready = gate.pop_ready_with_lifecycle().unwrap();
            ready.handoff().unwrap();
            assert_eq!(
                ready.release(),
                Err(AdmissionReject::ReservationStateConflict)
            );
            drop(ready);
            drop(gate);
            drop(authority);
        }
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&explicit_path, explicit_namespace).unwrap_err(),
            TxAdmissionWalErrorV0::AmbiguousHandoff
        );
        cleanup(&explicit_path);

        // Drop has the same fail-closed result: the generic mempool lease may
        // attempt release, but this WAL implementation leaves HandedOff in
        // place.  The authenticated receipt path is the only resolver.
        let recovery_path = temp_path();
        let recovery_namespace = [0x69; 32];
        let envelope = fixture();
        let metadata = {
            let mut authority =
                SqlitePendingNonceAuthorityV0::open(&recovery_path, recovery_namespace).unwrap();
            let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
            let mut hooks = Hooks;
            assert_eq!(
                gate.admit_signed_with_pending_nonce(
                    &envelope,
                    IngressClass::Normal,
                    &mut hooks,
                    &mut authority,
                ),
                TypedAdmitOutcome::Accepted
            );
            let mut ready = gate.pop_ready_with_lifecycle().unwrap();
            ready.handoff().unwrap();
            let metadata = ready.metadata().clone();
            drop(ready);
            drop(gate);
            drop(authority);
            metadata
        };
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&recovery_path, recovery_namespace).unwrap_err(),
            TxAdmissionWalErrorV0::AmbiguousHandoff
        );

        let verified = commit_evidence_for(&envelope)
            .verify_with(&metadata, &AcceptingCommitVerifier)
            .unwrap();
        SqlitePendingNonceAuthorityV0::recover_handed_off_with_receipt(
            &recovery_path,
            recovery_namespace,
            &metadata,
            &verified,
        )
        .unwrap();

        let reopened =
            SqlitePendingNonceAuthorityV0::open(&recovery_path, recovery_namespace).unwrap();
        let connection = reopened.connection.borrow();
        let state: i64 = connection
            .query_row(
                "SELECT state FROM pending_nonce
                 WHERE namespace = ?1 AND signer = ?2 AND nonce = ?3",
                params![
                    recovery_namespace.as_slice(),
                    metadata.signer_id().as_bytes().as_slice(),
                    to_blob_u64(metadata.nonce()).as_slice(),
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, STATE_COMMITTED_V0);
        let stored_commitment: Vec<u8> = connection
            .query_row(
                "SELECT commitment FROM tx_commit_receipt_v0
                 WHERE namespace = ?1 AND signer = ?2 AND nonce = ?3",
                params![
                    recovery_namespace.as_slice(),
                    metadata.signer_id().as_bytes().as_slice(),
                    to_blob_u64(metadata.nonce()).as_slice(),
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_commitment, verified.commitment().to_vec());
        drop(connection);
        drop(reopened);
        cleanup(&recovery_path);
    }

    #[test]
    fn authenticated_restart_recovery_resolves_only_the_exact_handed_off_row() {
        let path = temp_path();
        let namespace = [0x67; 32];
        let envelope = fixture();

        // Obtain the exact key-free metadata from the admission owner, then
        // emulate a process crash by converting the released row back to the
        // durable HandedOff state after all live SQLite/sidecar handles close.
        let metadata = {
            let mut authority = SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap();
            let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
            let mut hooks = Hooks;
            assert_eq!(
                gate.admit_signed_with_pending_nonce(
                    &envelope,
                    IngressClass::Normal,
                    &mut hooks,
                    &mut authority,
                ),
                TypedAdmitOutcome::Accepted
            );
            let ready = gate.pop_ready_with_lifecycle().unwrap();
            let metadata = ready.metadata().clone();
            drop(ready);
            drop(gate);
            drop(authority);
            metadata
        };
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE pending_nonce SET state = ?1
                 WHERE namespace = ?2 AND signer = ?3 AND nonce = ?4",
                params![
                    STATE_HANDED_OFF_V0,
                    namespace.as_slice(),
                    metadata.signer_id().as_bytes().as_slice(),
                    to_blob_u64(metadata.nonce()).as_slice(),
                ],
            )
            .unwrap();
        drop(connection);

        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap_err(),
            TxAdmissionWalErrorV0::AmbiguousHandoff
        );

        let evidence = commit_evidence_for(&envelope);
        let verified = evidence
            .verify_with(&metadata, &AcceptingCommitVerifier)
            .unwrap();

        // A verified receipt paired with metadata from another reservation is
        // rejected before any state transition; the ambiguity remains.
        let foreign_path = temp_path();
        let foreign_metadata = {
            let foreign_envelope = FixtureEnvelope {
                digest: CanonicalTxDigest::from_bytes([0x12; 32]).unwrap(),
                signer: CanonicalSignerId::from_bytes([0x23; 32]).unwrap(),
                body: b"foreign-body".to_vec(),
                nonce: 8,
            };
            let mut foreign_authority =
                SqlitePendingNonceAuthorityV0::open(&foreign_path, namespace).unwrap();
            let mut foreign_gate = TypedAdmissionGate::with_default_body_limit(2, 0);
            let mut foreign_hooks = Hooks;
            assert_eq!(
                foreign_gate.admit_signed_with_pending_nonce(
                    &foreign_envelope,
                    IngressClass::Normal,
                    &mut foreign_hooks,
                    &mut foreign_authority,
                ),
                TypedAdmitOutcome::Accepted
            );
            let foreign_ready = foreign_gate.pop_ready_with_lifecycle().unwrap();
            let metadata = foreign_ready.metadata().clone();
            drop(foreign_ready);
            drop(foreign_gate);
            drop(foreign_authority);
            metadata
        };
        assert_eq!(
            SqlitePendingNonceAuthorityV0::recover_handed_off_with_receipt(
                &path,
                namespace,
                &foreign_metadata,
                &verified,
            )
            .unwrap_err(),
            TxAdmissionWalErrorV0::CommitReceiptMismatch
        );
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap_err(),
            TxAdmissionWalErrorV0::AmbiguousHandoff
        );

        assert!(
            SqlitePendingNonceAuthorityV0::recover_handed_off_with_receipt(
                &path, namespace, &metadata, &verified,
            )
            .is_ok()
        );
        assert!(SqlitePendingNonceAuthorityV0::open(&path, namespace).is_ok());

        cleanup(&foreign_path);
        cleanup(&path);
    }

    #[test]
    fn wrong_namespace_and_concurrent_owner_are_rejected() {
        let path = temp_path();
        let authority = SqlitePendingNonceAuthorityV0::open(&path, [0x77; 32]).unwrap();
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, [0x78; 32]).unwrap_err(),
            TxAdmissionWalErrorV0::LockUnavailable
        );
        drop(authority);
        let authority = SqlitePendingNonceAuthorityV0::open(&path, [0x77; 32]).unwrap();
        drop(authority);
        // Namespace mismatch is observable after the first owner releases the
        // lock and does not rewrite the existing database.
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, [0x78; 32]).unwrap_err(),
            TxAdmissionWalErrorV0::NamespaceMismatch
        );
        cleanup(&path);
    }

    #[test]
    fn insert_error_mapping_only_treats_constraint_as_replay() {
        fn sqlite_failure(code: rusqlite::ffi::ErrorCode) -> rusqlite::Error {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code,
                    extended_code: 0,
                },
                None,
            )
        }

        assert_eq!(
            map_insert_error_v0(sqlite_failure(
                rusqlite::ffi::ErrorCode::ConstraintViolation
            )),
            TxAdmissionWalErrorV0::Replay
        );
        assert_eq!(
            map_insert_error_v0(sqlite_failure(rusqlite::ffi::ErrorCode::DatabaseBusy)),
            TxAdmissionWalErrorV0::Sqlite
        );
        assert_eq!(
            map_insert_error_v0(sqlite_failure(rusqlite::ffi::ErrorCode::SystemIoFailure)),
            TxAdmissionWalErrorV0::Sqlite
        );
        assert_eq!(
            map_insert_error_v0(rusqlite::Error::InvalidQuery),
            TxAdmissionWalErrorV0::Sqlite
        );
    }

    #[cfg(unix)]
    #[test]
    fn lock_path_replacement_fails_closed_for_authority_and_reservation() {
        let path = temp_path();
        let envelope = fixture();
        let mut authority = SqlitePendingNonceAuthorityV0::open(&path, [0xAB; 32]).unwrap();
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let mut hooks = Hooks;
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &envelope,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = gate.pop_ready_with_lifecycle().expect("ready candidate");
        let moved_path = replace_lock_path_for_test(&path);

        assert_eq!(
            ensure_open_lock_identity_v0(
                &lock_path_v0(&path).unwrap(),
                authority.lock_identity,
                &authority.lock,
            )
            .unwrap_err(),
            TxAdmissionWalErrorV0::PathReplaced
        );
        assert_eq!(
            authority.retained_rows().unwrap_err(),
            TxAdmissionWalErrorV0::PathReplaced
        );
        assert_eq!(
            ready.handoff().unwrap_err(),
            AdmissionReject::InconsistentState
        );

        drop(ready);
        drop(authority);
        cleanup(&path);
        let _ = fs::remove_file(moved_path);
    }

    #[test]
    fn node_owned_boundary_routes_typed_admission_and_lifecycle() {
        let path = temp_path();
        let envelope = fixture();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit(&path, [0x88; 32], 2, 0)
                .unwrap();
        let mut hooks = Hooks;

        const {
            assert!(TX_ADMISSION_BOUNDARY_RUNTIME_COMPOSITION_V0);
            assert!(!TX_ADMISSION_BOUNDARY_PRODUCTION_ACTIVATION_V0);
            assert!(!TX_ADMISSION_BOUNDARY_CHECKTX_V0);
            assert!(!TX_ADMISSION_BOUNDARY_SIGNING_V0);
            assert!(!TX_ADMISSION_BOUNDARY_BROADCAST_V0);
            assert!(TX_ADMISSION_BOUNDARY_COMMIT_RECEIPT_V0);
            assert!(!TX_ADMISSION_BOUNDARY_COMMIT_RECEIPT_PRODUCTION_V0);
            assert!(TX_ADMISSION_BOUNDARY_NATIVE_READBACK_V0);
            assert!(!TX_ADMISSION_BOUNDARY_NATIVE_READBACK_PRODUCTION_V0);
        }
        assert_eq!(boundary.namespace(), [0x88; 32]);
        // A normal admission owner cannot inspect or resolve restart handoffs;
        // that capability is reserved for the explicit recovery constructor.
        assert_eq!(
            boundary.handed_off_records_v0(),
            Err(TxAdmissionWalErrorV0::HandoffRecoveryUnavailable)
        );
        assert_eq!(
            boundary.admit_signed_candidate(&envelope, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        assert_eq!(boundary.queued_counts(), (1, 0, 1));

        let mut ready = boundary
            .pop_ready_with_lifecycle()
            .expect("ready candidate");
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::Reserved)
        );
        assert_eq!(
            ready.commit(),
            Err(AdmissionReject::ReservationStateConflict)
        );
        ready.handoff().unwrap();
        assert_eq!(
            ready.handoff(),
            Err(AdmissionReject::ReservationStateConflict)
        );
        ready.commit().unwrap();
        assert_eq!(
            ready.commit(),
            Err(AdmissionReject::ReservationStateConflict)
        );
        assert_eq!(boundary.retained_rows().unwrap(), 1);

        // A committed tombstone is a durable replay rejection, not a second
        // candidate admission.  The node boundary still has no broadcast or
        // application-commit readback behavior.
        assert_eq!(
            boundary.admit_signed_candidate(&envelope, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::Replay)
        );
        drop(ready);
        drop(boundary);
        cleanup(&path);
    }

    #[test]
    fn builder_check_tx_authenticates_before_wal_and_commit_receipt() {
        let path = temp_path();
        let transaction = builder_fixture_transaction();
        let signer_id = CanonicalSignerId::from_bytes([0xA5; 32]).unwrap();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &path,
                [0x8C; 32],
                2,
                0,
                BuilderFixtureSignerResolver { signer: signer_id },
            )
            .unwrap();

        const {
            assert!(TX_ADMISSION_BOUNDARY_CHECKTX_CANDIDATE_V0);
            assert!(!TX_ADMISSION_BOUNDARY_CHECKTX_V0);
            assert!(TX_ADMISSION_BOUNDARY_SIGNER_RESOLVER_V0);
            assert!(!TX_ADMISSION_BOUNDARY_SIGNER_RESOLVER_PRODUCTION_V0);
            assert!(!TX_ADMISSION_BOUNDARY_SIGNING_V0);
            assert!(!TX_ADMISSION_BOUNDARY_BROADCAST_V0);
        }
        assert_eq!(
            boundary.check_tx_candidate_with_resolver(
                &transaction,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = boundary.pop_ready_with_lifecycle().unwrap();
        assert_eq!(ready.metadata().nonce(), 7);
        ready.handoff().unwrap();
        let evidence = NativeCommitReceiptEvidenceV0::new(
            transaction.protocol_tx_hash_v1(),
            BlockId::new([0x51; 32]),
            Height::new(1),
            StateRoot::new([0x52; 32]),
            [0x53; 32],
            [0x54; 32],
        )
        .unwrap();
        let verified = evidence
            .verify_with(ready.metadata(), &AcceptingCommitVerifier)
            .unwrap();
        boundary
            .commit_candidate_with_receipt(&mut ready, &verified)
            .unwrap();
        assert_eq!(boundary.retained_rows().unwrap(), 1);
        drop(ready);
        drop(boundary);

        // A wrong chain context fails before the nonce authority is touched.
        let bad_path = temp_path();
        let mut bad_boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &bad_path,
                [0x8D; 32],
                2,
                0,
                BuilderFixtureSignerResolver { signer: signer_id },
            )
            .unwrap();
        assert_eq!(
            bad_boundary.check_tx_candidate_with_resolver(
                &transaction,
                IngressClass::Normal,
                "trnm-wrong-chain",
                1_000,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::SignatureRejected)
        );
        assert_eq!(bad_boundary.retained_rows().unwrap(), 0);
        drop(bad_boundary);
        cleanup(&bad_path);
        cleanup(&path);
    }

    #[test]
    fn builder_check_tx_can_use_only_node_owned_context() {
        let transaction = builder_fixture_transaction();
        let signer_id = CanonicalSignerId::from_bytes([0xA7; 32]).unwrap();
        let path = temp_path();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_and_context(
                &path,
                [0x90; 32],
                2,
                0,
                BuilderFixtureSignerResolver { signer: signer_id },
                BuilderFixtureAdmissionContext {
                    chain_id: "trnm-devnet",
                    now_unix_ms: 1_000,
                },
            )
            .unwrap();
        assert_eq!(
            boundary.check_tx_candidate_with_authorities(&transaction, IngressClass::Normal),
            TypedAdmitOutcome::Accepted
        );
        let ready = boundary.pop_ready_with_lifecycle().unwrap();
        drop(ready);
        drop(boundary);
        cleanup(&path);

        let path_without_context = temp_path();
        let mut without_context =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &path_without_context,
                [0x91; 32],
                2,
                0,
                BuilderFixtureSignerResolver { signer: signer_id },
            )
            .unwrap();
        assert_eq!(
            without_context.check_tx_candidate_with_authorities(&transaction, IngressClass::Normal),
            TypedAdmitOutcome::Rejected(AdmissionReject::RecheckUnavailable)
        );
        assert_eq!(without_context.retained_rows().unwrap(), 0);
        drop(without_context);
        cleanup(&path_without_context);
    }

    #[test]
    fn native_readback_binding_requires_exact_outer_state_and_receipt() {
        let transaction = builder_fixture_transaction();
        let signer_id = CanonicalSignerId::from_bytes([0xB7; 32]).unwrap();
        let path = temp_path();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &path,
                [0xB8; 32],
                2,
                0,
                BuilderFixtureSignerResolver { signer: signer_id },
            )
            .unwrap();
        assert_eq!(
            boundary.check_tx_candidate_with_resolver(
                &transaction,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Accepted
        );
        let ready = boundary.pop_ready_with_lifecycle().unwrap();
        let metadata = ready.metadata().clone();
        let block_id = [0xB9; 32];
        let state_root = [0xBA; 32];
        let receipt_digest = [0xBB; 32];
        let finality_proof_digest = [0xBC; 32];
        let evidence = NativeCommitReceiptEvidenceV0::new(
            transaction.protocol_tx_hash_v1(),
            BlockId::new(block_id),
            Height::new(7),
            StateRoot::new(state_root),
            receipt_digest,
            finality_proof_digest,
        )
        .unwrap();
        let outer_transactions = vec![transaction.exact_outer_bytes().to_vec()];
        let receipt_indices = vec![0_u32];
        let receipt_commitments = vec![receipt_digest];
        let facts = NativeCommitReadbackFactsV0 {
            finalized_height: 7,
            finalized_block_id: block_id,
            finalized_state_root: state_root,
            executed_height: 7,
            executed_block_id: block_id,
            executed_state_root: state_root,
            outer_transactions: &outer_transactions,
            receipt_indices: &receipt_indices,
            receipt_commitments: &receipt_commitments,
        };
        assert_eq!(
            validate_native_readback_binding_v0(
                &metadata,
                &evidence,
                &transaction,
                finality_proof_digest,
                facts,
            ),
            Ok(())
        );

        // A different outer envelope with the same metadata cannot be used to
        // claim that the admitted transaction was applied.
        let foreign_outer = vec![b"foreign-envelope".to_vec()];
        let foreign_facts = NativeCommitReadbackFactsV0 {
            outer_transactions: &foreign_outer,
            ..facts
        };
        assert_eq!(
            validate_native_readback_binding_v0(
                &metadata,
                &evidence,
                &transaction,
                finality_proof_digest,
                foreign_facts,
            ),
            Err(TxAdmissionWalErrorV0::CommitReceiptMismatch)
        );

        // A state-root or receipt-commitment substitution is equally
        // fail-closed even when the exact outer bytes are present.
        let wrong_root_facts = NativeCommitReadbackFactsV0 {
            finalized_state_root: [0xBD; 32],
            ..facts
        };
        assert_eq!(
            validate_native_readback_binding_v0(
                &metadata,
                &evidence,
                &transaction,
                finality_proof_digest,
                wrong_root_facts,
            ),
            Err(TxAdmissionWalErrorV0::CommitReceiptMismatch)
        );
        let wrong_receipt = vec![[0xBE; 32]];
        let wrong_receipt_facts = NativeCommitReadbackFactsV0 {
            receipt_commitments: &wrong_receipt,
            ..facts
        };
        assert_eq!(
            validate_native_readback_binding_v0(
                &metadata,
                &evidence,
                &transaction,
                finality_proof_digest,
                wrong_receipt_facts,
            ),
            Err(TxAdmissionWalErrorV0::CommitReceiptMismatch)
        );

        // A receipt/index prefix or suffix is not an authenticated execution
        // result. The native application currently emits exact parallel
        // vectors, so cardinality drift must reject before selecting index 0.
        let extra_receipt = vec![receipt_digest, [0xBF; 32]];
        let extra_receipt_facts = NativeCommitReadbackFactsV0 {
            receipt_commitments: &extra_receipt,
            ..facts
        };
        assert_eq!(
            validate_native_readback_binding_v0(
                &metadata,
                &evidence,
                &transaction,
                finality_proof_digest,
                extra_receipt_facts,
            ),
            Err(TxAdmissionWalErrorV0::CommitReceiptMismatch)
        );

        // A target at index zero must not hide a malformed duplicate/missing
        // index in the remainder of the durable receipt vector.
        let second_outer = b"another-canonical-envelope".to_vec();
        let two_outer_transactions = vec![transaction.exact_outer_bytes().to_vec(), second_outer];
        let duplicate_indices = vec![0_u32, 0_u32];
        let two_receipt_commitments = vec![receipt_digest, [0xC0; 32]];
        let duplicate_index_facts = NativeCommitReadbackFactsV0 {
            outer_transactions: &two_outer_transactions,
            receipt_indices: &duplicate_indices,
            receipt_commitments: &two_receipt_commitments,
            ..facts
        };
        assert_eq!(
            validate_native_readback_binding_v0(
                &metadata,
                &evidence,
                &transaction,
                finality_proof_digest,
                duplicate_index_facts,
            ),
            Err(TxAdmissionWalErrorV0::CommitReceiptMismatch)
        );
        drop(ready);
        drop(boundary);
        cleanup(&path);
    }

    #[test]
    fn native_readback_real_store_rejects_unauthenticated_finality_before_wal_commit() {
        let application_temp = tempfile::tempdir().unwrap();
        let application_path = application_temp.path().join("native-application.sqlite");
        let config = native_fixture_config();
        let set = config.validator_set_v0().clone();
        let parameters = *config.consensus_parameters_v0();
        let transaction = native_fixture_transaction();
        transaction
            .envelope()
            .validate_at_strict("trnm-devnet", 1_700_000_001_000)
            .expect("native fixture envelope must pass strict signature/context checks");
        let application = DurableNativeApplicationV0::open(&application_path, config).unwrap();
        let genesis = application
            .initialize(native_fixture_genesis_request(application.config_v0()))
            .unwrap();
        let timestamp_ms = 1_700_000_001_000;
        let preview_request = NativeBlockPreviewRequestV0::new(
            trnm_native_application::ChainIdV0::new(application.config_v0().chain_id_v0()).unwrap(),
            trnm_native_application::GenesisHashV0::new(application.config_v0().genesis_hash_v0())
                .unwrap(),
            genesis.head().clone(),
            trnm_native_application::HeightV0::new(1),
            timestamp_ms,
            genesis.active_validator_set_id(),
            vec![transaction.exact_outer_bytes().to_vec()],
        )
        .unwrap();
        let preview = application
            .preview_block_v0(&preview_request)
            .unwrap_or_else(|error| panic!("native fixture preview failed: {error:?}"));
        let execution = NativeBlockExecutionRequestV0::new(
            preview_request.chain_id().clone(),
            preview_request.genesis_hash(),
            preview_request.parent().clone(),
            trnm_native_application::BlockIdV0::new([0xD5; 32]).unwrap(),
            preview_request.height(),
            timestamp_ms,
            preview_request.active_validator_set_id(),
            preview_request.transactions().to_vec(),
            NativeExpectedBlockCommitmentsV0::new(
                preview.payload_root(),
                preview.post_state_root(),
                preview.receipts_root(),
                preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        let executed = match application.execute_block(execution.clone()).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("native fixture execution was not valid: {other:?}"),
        };
        let receipt_digest = *executed.receipts()[0].commitment().as_bytes();
        application
            .commit_block(NativeApplicationCommitRequestV0::new(executed))
            .unwrap();

        // The proof carries the exact committed header coordinates, but its
        // proposal/QC signatures are deliberately bogus. The concrete
        // DurableNativeApplication verifier must reject it, and the WAL row
        // must remain HandedOff rather than minting a durable receipt.
        let parent_timestamp_ms = timestamp_ms - 1_000;
        let proof =
            native_fixture_structural_proof(&execution, &set, &parameters, parent_timestamp_ms);
        let signer_id = CanonicalSignerId::from_bytes([0xD6; 32]).unwrap();
        let wal_path = temp_path();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &wal_path,
                [0xD7; 32],
                2,
                0,
                NativeFixtureSignerResolver { signer: signer_id },
            )
            .unwrap();
        assert_eq!(
            boundary.check_tx_candidate_with_resolver(
                &transaction,
                IngressClass::Normal,
                "trnm-devnet",
                1_700_000_001_000,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = boundary.pop_ready_with_lifecycle().unwrap();
        ready.handoff().unwrap();
        let evidence = NativeCommitReceiptEvidenceV0::new(
            transaction.protocol_tx_hash_v1(),
            BlockId::new([0xD5; 32]),
            Height::new(1),
            StateRoot::new(*execution.expected().post_state_root().as_bytes()),
            receipt_digest,
            *proof.id().as_bytes(),
        )
        .unwrap();
        assert_eq!(
            boundary.commit_candidate_with_native_readback(
                &mut ready,
                &transaction,
                evidence,
                &application,
                &proof,
                parent_timestamp_ms,
            ),
            Err(AdmissionReject::InconsistentState)
        );
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::HandedOff)
        );
        drop(ready);
        drop(boundary);
        drop(application);
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&wal_path, [0xD7; 32]).unwrap_err(),
            TxAdmissionWalErrorV0::AmbiguousHandoff
        );
        cleanup(&wal_path);
    }

    #[test]
    fn caller_supplied_signer_mismatch_cannot_choose_wal_replay_key() {
        let path = temp_path();
        let transaction = builder_fixture_transaction();
        let authority_signer = CanonicalSignerId::from_bytes([0xA5; 32]).unwrap();
        let caller_signer = CanonicalSignerId::from_bytes([0xA6; 32]).unwrap();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &path,
                [0x8F; 32],
                2,
                0,
                BuilderFixtureSignerResolver {
                    signer: authority_signer,
                },
            )
            .unwrap();

        assert_eq!(
            boundary.check_tx_candidate(
                &transaction,
                caller_signer,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::CanonicalValidationFailed)
        );
        assert_eq!(boundary.retained_rows().unwrap(), 0);

        assert_eq!(
            boundary.check_tx_candidate(
                &transaction,
                authority_signer,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = boundary.pop_ready_with_lifecycle().unwrap();
        ready.release().unwrap();
        drop(ready);
        drop(boundary);
        cleanup(&path);
    }

    #[test]
    fn candidate_checktx_without_authority_resolver_fails_before_wal() {
        let path = temp_path();
        let transaction = builder_fixture_transaction();
        let caller_signer = CanonicalSignerId::from_bytes([0xA5; 32]).unwrap();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit(&path, [0x90; 32], 2, 0)
                .unwrap();

        assert_eq!(
            boundary.check_tx_candidate_with_resolver(
                &transaction,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::SignerIdentityUnavailable)
        );
        assert_eq!(
            boundary.check_tx_candidate(
                &transaction,
                caller_signer,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::SignerIdentityUnavailable)
        );
        assert_eq!(boundary.retained_rows().unwrap(), 0);
        drop(boundary);
        cleanup(&path);
    }

    #[test]
    fn verified_commit_receipt_binds_and_persists_before_token_resolution() {
        let path = temp_path();
        let envelope = fixture();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit(&path, [0x8A; 32], 2, 0)
                .unwrap();
        let mut hooks = Hooks;
        assert_eq!(
            boundary.admit_signed_candidate(&envelope, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = boundary.pop_ready_with_lifecycle().unwrap();
        ready.handoff().unwrap();
        let evidence = commit_evidence_for(&envelope);
        let verified = evidence
            .verify_with(ready.metadata(), &AcceptingCommitVerifier)
            .unwrap();
        assert_ne!(verified.commitment(), [0; 32]);
        boundary
            .commit_candidate_with_receipt(&mut ready, &verified)
            .unwrap();
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::Committed)
        );
        assert_eq!(boundary.retained_rows().unwrap(), 1);
        drop(ready);
        drop(boundary);
        assert!(SqlitePendingNonceAuthorityV0::open(&path, [0x8A; 32]).is_ok());
        cleanup(&path);
    }

    #[test]
    fn commit_rejects_a_token_owned_by_another_boundary_instance() {
        let path_a = temp_path();
        let path_b = temp_path();
        let transaction = builder_fixture_transaction();
        let signer_id = CanonicalSignerId::from_bytes([0xA6; 32]).unwrap();
        let mut boundary_a =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &path_a,
                [0x8E; 32],
                2,
                0,
                BuilderFixtureSignerResolver { signer: signer_id },
            )
            .unwrap();
        let mut boundary_b =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &path_b,
                [0x8E; 32],
                2,
                0,
                BuilderFixtureSignerResolver { signer: signer_id },
            )
            .unwrap();
        assert_eq!(
            boundary_a.check_tx_candidate_with_resolver(
                &transaction,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = boundary_a.pop_ready_with_lifecycle().unwrap();
        ready.handoff().unwrap();
        let evidence = NativeCommitReceiptEvidenceV0::new(
            transaction.protocol_tx_hash_v1(),
            BlockId::new([0x61; 32]),
            Height::new(2),
            StateRoot::new([0x62; 32]),
            [0x63; 32],
            [0x64; 32],
        )
        .unwrap();
        let verified = evidence
            .verify_with(ready.metadata(), &AcceptingCommitVerifier)
            .unwrap();
        assert_eq!(
            boundary_b.commit_candidate_with_receipt(&mut ready, &verified),
            Err(AdmissionReject::InconsistentState)
        );
        assert_eq!(boundary_b.retained_rows().unwrap(), 0);
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::HandedOff)
        );
        drop(ready);
        drop(boundary_a);
        drop(boundary_b);
        cleanup(&path_a);
        cleanup(&path_b);
    }

    #[test]
    fn unverified_or_foreign_receipt_never_advances_handoff() {
        let path = temp_path();
        let envelope = fixture();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit(&path, [0x8B; 32], 2, 0)
                .unwrap();
        let mut hooks = Hooks;
        assert_eq!(
            boundary.admit_signed_candidate(&envelope, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = boundary.pop_ready_with_lifecycle().unwrap();
        ready.handoff().unwrap();
        let mut foreign = commit_evidence_for(&envelope);
        foreign.tx_digest = [0xFE; 32];
        assert_eq!(
            foreign.verify_with(ready.metadata(), &AcceptingCommitVerifier),
            Err(TxAdmissionWalErrorV0::CommitReceiptMismatch)
        );
        let rejected = NativeCommitReceiptEvidenceV0::new(
            envelope.digest.as_bytes(),
            BlockId::new([0x41; 32]),
            Height::new(13),
            StateRoot::new([0x42; 32]),
            [0x43; 32],
            [0x44; 32],
        )
        .unwrap()
        .verify_with(ready.metadata(), &RejectingCommitVerifier);
        assert_eq!(
            rejected,
            Err(TxAdmissionWalErrorV0::CommitReadbackUnavailable)
        );
        // The verifier rejection path above cannot produce a token; the
        // handed-off row remains unresolved and therefore blocks restart.
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::HandedOff)
        );
        drop(ready);
        drop(boundary);
        cleanup(&path);
    }

    #[test]
    fn node_owned_boundary_rejects_before_reserving_on_invalid_metadata() {
        let path = temp_path();
        let mut envelope = fixture();
        envelope.body.clear();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit(&path, [0x99; 32], 2, 0)
                .unwrap();
        let mut hooks = Hooks;
        assert_eq!(
            boundary.admit_signed_candidate(&envelope, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::EmptyBody)
        );
        assert_eq!(boundary.queued_counts(), (0, 0, 0));
        assert_eq!(boundary.retained_rows().unwrap(), 0);
        drop(boundary);
        cleanup(&path);
    }

    #[test]
    fn compact_tombstone_remains_replay_authoritative_for_new_admission() {
        let path = temp_path();
        let namespace = [0xA4; 32];
        let signer = [0x22u8; 32];
        let nonce = 7u64;
        let digest = [0x11u8; 32];
        let terminal_state = STATE_RELEASED_V0;
        let terminal_height = 0u64;
        let receipt_commitment = [0u8; 32];
        let tombstone_digest = tombstone_digest_v1(
            namespace,
            signer,
            nonce,
            digest,
            terminal_state,
            terminal_height,
            receipt_commitment,
        )
        .unwrap();
        let mut authority = SqlitePendingNonceAuthorityV0::open(&path, namespace).unwrap();
        {
            let connection = authority.connection.borrow();
            connection
                .execute(
                    "INSERT INTO tx_admission_tombstone_v1
                     (namespace,signer,nonce,tx_digest,terminal_state,terminal_height,
                      receipt_commitment,tombstone_digest)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![
                        namespace.as_slice(),
                        signer.as_slice(),
                        nonce.to_be_bytes().as_slice(),
                        digest.as_slice(),
                        terminal_state,
                        terminal_height.to_be_bytes().as_slice(),
                        receipt_commitment.as_slice(),
                        tombstone_digest.as_slice(),
                    ],
                )
                .unwrap();
        }
        assert_eq!(authority.retained_rows().unwrap(), 1);
        let envelope = fixture();
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let mut hooks = Hooks;
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &envelope,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::Replay)
        );
        assert_eq!(authority.retained_rows().unwrap(), 1);
        drop(authority);
        cleanup(&path);
    }
}
