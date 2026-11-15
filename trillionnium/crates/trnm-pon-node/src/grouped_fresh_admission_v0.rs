//! Independently pinned admission for a grouped/security-seal research fixture.
//!
//! This is not a W1 task codec, Node admission, genuine-demand certificate or
//! permission to execute Hepta effects. Native branch facts, real Ed25519
//! signatures and an immutable expected body are checked independently of the
//! received capsule. The dedicated journal records this one frozen research
//! policy only; it has no policy-update, reward or consensus authority.
use crate::Node;
use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs::File, fs::OpenOptions as FileOptions, path::Path, sync::Arc};
use trnm_crypto_primitives::{pon_grouped_fresh_seal_v0 as seal, verify_hex_strict};
use trnm_protocol::pon_wire::{hash, Hash};

pub const BODY_MAGIC: &[u8; 6] = b"PGAB\0\0";
pub const CAPSULE_MAGIC: &[u8; 6] = b"PGAC\0\0";
pub const CANDIDATE_MAGIC: &[u8; 6] = b"PGCE\0\0";
pub const BODY_BYTES: usize = 6 + 32 + 2 + 6 * 32 + 2 * 8 + 13 * 32 + 8 * 8;
pub const CAPSULE_BYTES: usize = 6 + BODY_BYTES + 2 * 64;
pub const CANDIDATE_BYTES: usize = 6 + BODY_BYTES + 8;
pub const MAX_NONCES: u64 = 4096;
pub const MAX_LIFETIME_NS: u64 = 3_600_000_000_000;
/// Receiver submissions per one frozen research journal, not a global quota.
pub const MAX_VERIFICATION_SUBMISSIONS: u64 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    Shape,
    Window,
    Nonce,
    NativeContext,
    ExpectedBody,
    ExternalPin,
    Signature,
    Journal,
    JournalContext,
    Replay,
    Reservation,
    ProductionBinding,
    VerificationBudget,
    VerificationPermit,
    VerificationBinding,
    Seal(seal::SealError),
}
pub type Result<T> = std::result::Result<T, AdmissionError>;

fn require(ok: bool, error: AdmissionError) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
pub fn sha256(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

/// Created only from the original Node's validated active branch. No wire
/// decoder or public field constructor can manufacture this snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBranch {
    network: Hash,
    parameters: Hash,
    genesis: Hash,
    parent: Hash,
    prior_state: Hash,
    target: Hash,
    height: u64,
    generation: u64,
}
impl NativeBranch {
    pub fn capture(node: &Node) -> Result<Self> {
        let (parent, generation, state) = node
            .read_active()
            .map_err(|_| AdmissionError::NativeContext)?;
        let settings = node.settings();
        let value = Self {
            network: settings.network(),
            parameters: settings.parameters(),
            genesis: settings.genesis(),
            parent,
            prior_state: settings
                .state_root(&state)
                .map_err(|_| AdmissionError::NativeContext)?,
            target: node
                .expected_target(parent)
                .map_err(|_| AdmissionError::NativeContext)?,
            height: node
                .parent_height(parent)
                .map_err(|_| AdmissionError::NativeContext)?
                .checked_add(1)
                .ok_or(AdmissionError::NativeContext)?,
            generation,
        };
        require(
            node.active().map_err(|_| AdmissionError::NativeContext)? == (parent, generation)
                && value.target != [0; 32],
            AdmissionError::NativeContext,
        )?;
        Ok(value)
    }
    fn hashes(&self) -> [Hash; 6] {
        [
            self.network,
            self.parameters,
            self.genesis,
            self.parent,
            self.prior_state,
            self.target,
        ]
    }
    pub fn target(&self) -> Hash {
        self.target
    }
    pub fn observation(&self) -> serde_json::Value {
        serde_json::json!({"network":hex::encode(self.network),"parameters":hex::encode(self.parameters),
            "genesis":hex::encode(self.genesis),"parent":hex::encode(self.parent),
            "prior_state":hex::encode(self.prior_state),"target":hex::encode(self.target),
            "height":self.height,"generation":self.generation})
    }
}

/// Untrusted requested scope. These values become usable only after the exact
/// outside policy and both role signatures have been checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsuleIntent {
    pub registry_id: Hash,
    pub registry_digest: Hash,
    pub previous_registry_digest: Hash,
    pub demand_id: Hash,
    pub source_record: Hash,
    pub authorization_scope: Hash,
    pub withdrawal_head: Hash,
    pub model_commitment: Hash,
    pub request_precommitment: Hash,
    pub batch_id: Hash,
    pub transactions_commitment: Hash,
    pub payee: Hash,
    pub operation_id: Hash,
    pub registry_sequence: u64,
    pub model_generation: u64,
    pub timestamp_ms: u64,
    pub not_before_ns: u64,
    pub expires_ns: u64,
    pub available_until_ns: u64,
    pub nonce_first: u64,
    pub nonce_count: u64,
}
impl CapsuleIntent {
    fn hashes(&self) -> [Hash; 13] {
        [
            self.registry_id,
            self.registry_digest,
            self.previous_registry_digest,
            self.demand_id,
            self.source_record,
            self.authorization_scope,
            self.withdrawal_head,
            self.model_commitment,
            self.request_precommitment,
            self.batch_id,
            self.transactions_commitment,
            self.payee,
            self.operation_id,
        ]
    }
    fn integers(&self) -> [u64; 8] {
        [
            self.registry_sequence,
            self.model_generation,
            self.timestamp_ms,
            self.not_before_ns,
            self.expires_ns,
            self.available_until_ns,
            self.nonce_first,
            self.nonce_count,
        ]
    }
    fn validate(&self) -> Result<()> {
        require(
            self.hashes()
                .iter()
                .enumerate()
                .all(|(i, h)| i == 2 || *h != [0; 32])
                && self.registry_sequence > 0
                && self.model_generation > 0
                && self.timestamp_ms > 0
                && (self.registry_sequence == 1) == (self.previous_registry_digest == [0; 32]),
            AdmissionError::Shape,
        )?;
        let lifetime = self
            .expires_ns
            .checked_sub(self.not_before_ns)
            .ok_or(AdmissionError::Window)?;
        require(
            self.not_before_ns > 0
                && (1..=MAX_LIFETIME_NS).contains(&lifetime)
                && self.available_until_ns >= self.expires_ns,
            AdmissionError::Window,
        )?;
        require(
            self.nonce_first > 0
                && (1..=MAX_NONCES).contains(&self.nonce_count)
                && self.nonce_first.checked_add(self.nonce_count - 1).is_some(),
            AdmissionError::Nonce,
        )
    }
}

/// Immutable expected body. The security/numeric profile is fixed by compiled
/// source; no request can supply another L, dtype, profile or target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsuleBody {
    branch: NativeBranch,
    intent: CapsuleIntent,
}
impl CapsuleBody {
    pub fn from_node(node: &Node, intent: CapsuleIntent) -> Result<Self> {
        intent.validate()?;
        Ok(Self {
            branch: NativeBranch::capture(node)?,
            intent,
        })
    }
    pub fn branch(&self) -> &NativeBranch {
        &self.branch
    }
    pub fn intent(&self) -> &CapsuleIntent {
        &self.intent
    }
    /// Fixed order; all integers are big endian. No JSON is signed or decoded.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BODY_BYTES);
        out.extend(BODY_MAGIC);
        out.extend(seal::profile_hash());
        out.extend(seal::STEPS.to_be_bytes());
        for h in self.branch.hashes() {
            out.extend(h);
        }
        out.extend(self.branch.height.to_be_bytes());
        out.extend(self.branch.generation.to_be_bytes());
        for h in self.intent.hashes() {
            out.extend(h);
        }
        for n in self.intent.integers() {
            out.extend(n.to_be_bytes());
        }
        debug_assert_eq!(out.len(), BODY_BYTES);
        out
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SigningRole {
    Requester = 1,
    Source = 2,
}
pub fn signing_message(body: &CapsuleBody, role: SigningRole) -> Hash {
    hash(
        b"pon-grouped-fresh-capsule-signature-v0",
        &[&[role as u8], &body.encode()],
    )
}
pub fn signed_capsule(body: &CapsuleBody, requester: [u8; 64], source: [u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CAPSULE_BYTES);
    out.extend(CAPSULE_MAGIC);
    out.extend(body.encode());
    out.extend(requester);
    out.extend(source);
    out
}

/// Supplied by the protected fixture/operator owner, never parsed from the
/// received capsule. Different fixture keys do not prove separate operators.
#[derive(Clone, Debug)]
pub struct PinnedAuthority {
    pub requester_key: Hash,
    pub source_key: Hash,
    pub latest_sequence: u64,
    pub latest_digest: Hash,
    pub expected_capsule_sha256: Hash,
    pub expected: CapsuleBody,
}
impl PinnedAuthority {
    pub fn policy_id(&self) -> Hash {
        hash(
            b"pon-grouped-fresh-external-policy-v0",
            &[
                &self.requester_key,
                &self.source_key,
                &self.latest_sequence.to_be_bytes(),
                &self.latest_digest,
                &self.expected_capsule_sha256,
                &self.expected.encode(),
            ],
        )
    }
}

#[derive(Debug)]
pub struct VerifiedAdmission {
    body: CapsuleBody,
    policy_id: Hash,
    capsule_sha256: Hash,
}
pub fn verify_capsule(
    raw: &[u8],
    external: &PinnedAuthority,
    node: &Node,
    now_ns: u64,
) -> Result<VerifiedAdmission> {
    require(
        raw.len() == CAPSULE_BYTES && raw.get(..6) == Some(CAPSULE_MAGIC.as_slice()),
        AdmissionError::Shape,
    )?;
    require(
        raw[6..6 + BODY_BYTES] == external.expected.encode(),
        AdmissionError::ExpectedBody,
    )?;
    require(
        external.requester_key != [0; 32]
            && external.source_key != [0; 32]
            && external.requester_key != external.source_key
            && external.latest_sequence == external.expected.intent.registry_sequence
            && external.latest_digest == external.expected.intent.registry_digest
            && sha256(raw) == external.expected_capsule_sha256,
        AdmissionError::ExternalPin,
    )?;
    for (index, key, role) in [
        (0, external.requester_key, SigningRole::Requester),
        (1, external.source_key, SigningRole::Source),
    ] {
        let at = 6 + BODY_BYTES + index * 64;
        verify_hex_strict(
            &hex::encode(key),
            &signing_message(&external.expected, role),
            &hex::encode(&raw[at..at + 64]),
        )
        .map_err(|_| AdmissionError::Signature)?;
    }
    let value = VerifiedAdmission {
        body: external.expected.clone(),
        policy_id: external.policy_id(),
        capsule_sha256: external.expected_capsule_sha256,
    };
    value.recheck(node, now_ns)?;
    Ok(value)
}
impl VerifiedAdmission {
    pub fn body(&self) -> &CapsuleBody {
        &self.body
    }
    pub fn policy_id(&self) -> Hash {
        self.policy_id
    }
    pub fn capsule_sha256(&self) -> Hash {
        self.capsule_sha256
    }
    pub fn recheck(&self, node: &Node, now_ns: u64) -> Result<()> {
        require(
            self.body.intent.not_before_ns <= now_ns && now_ns < self.body.intent.expires_ns,
            AdmissionError::Window,
        )?;
        require(
            NativeBranch::capture(node)? == self.body.branch,
            AdmissionError::NativeContext,
        )
    }
    pub fn candidate_bytes(&self, nonce: u64) -> Result<Vec<u8>> {
        require(
            nonce >= self.body.intent.nonce_first
                && nonce - self.body.intent.nonce_first < self.body.intent.nonce_count,
            AdmissionError::Nonce,
        )?;
        let mut bytes = Vec::with_capacity(CANDIDATE_BYTES);
        bytes.extend(CANDIDATE_MAGIC);
        bytes.extend(self.body.encode());
        bytes.extend(nonce.to_be_bytes());
        Ok(bytes)
    }
    pub fn challenge_for_nonce(&self, nonce: u64) -> Result<Hash> {
        Ok(hash(
            b"pon-grouped-fresh-challenge-v0",
            &[&self.candidate_bytes(nonce)?],
        ))
    }
    pub fn work_id(&self, nonce: u64) -> Result<Hash> {
        Ok(hash(
            b"pon-grouped-fresh-work-id-v0",
            &[&self.candidate_bytes(nonce)?],
        ))
    }
    pub fn chainwork_awarded(&self) -> u64 {
        0
    }
    /// An untrusted wire proof is checked without any producer reservation,
    /// cache, prior proof hash or ledger fact. The caller separately verifies
    /// the complete grouped product and its exact statement commitment.
    /// This mathematical verifier is deliberately unmetered. A research
    /// receiver uses ResearchLedger::verify_untrusted_with_permit so a fresh,
    /// durable fixed-budget submission is consumed before each full replay.
    pub fn verify_untrusted_seal(
        &self,
        nonce: u64,
        statement: Hash,
        proof: &[u8],
        node: &Node,
        mut now_ns: impl FnMut() -> Result<u64>,
    ) -> Result<SealObservation> {
        let before = now_ns()?;
        self.recheck(node, before)?;
        let challenge = self.challenge_for_nonce(nonce)?;
        let verified =
            seal::verify(challenge, statement, [0xff; 32], proof).map_err(AdmissionError::Seal)?;
        let after = now_ns()?;
        require(after >= before, AdmissionError::Window)?;
        self.recheck(node, after)?;
        let target = self.body.branch.target;
        Ok(SealObservation {
            schema: "pon-grouped-fresh-seal-observation-v0",
            work_id: hex::encode(self.work_id(nonce)?),
            challenge: hex::encode(challenge),
            statement: hex::encode(statement),
            ticket: hex::encode(verified.ticket()),
            target: hex::encode(target),
            step_count: verified.step_count(),
            target_hit: verified.ticket() <= target,
            first_record: false,
            journal_recorded: false,
            chainwork_awarded: 0,
            grouped_arithmetic_verified_by_this_api: false,
            external_demand_authenticated: false,
            production_activation: false,
        })
    }
}

/// This dedicated, held-file-lock SQLite journal pins one complete immutable
/// research policy. It rejects replacement policies instead of pretending to
/// implement a registry update/revocation protocol. Reservations survive a
/// restart, failure and Native branch reorganization. No Node DB is modified.
pub struct ResearchLedger {
    db: Connection,
    _held_file: File,
    policy_id: Hash,
    origin: Arc<()>,
}
#[derive(Clone, Copy, Debug)]
pub enum VerificationMode {
    Record = 1,
    Untrusted = 2,
}
/// Canonical untrusted request identity, not an admission or verification fact.
pub struct VerificationRequest {
    nonce: u64,
    statement: Hash,
    proof_sha256: Hash,
    capsule_sha256: Hash,
    mode: VerificationMode,
}
impl VerificationRequest {
    pub fn from_digests(
        nonce: u64,
        statement: Hash,
        proof_sha256: Hash,
        capsule_sha256: Hash,
        mode: VerificationMode,
    ) -> Self {
        Self {
            nonce,
            statement,
            proof_sha256,
            capsule_sha256,
            mode,
        }
    }
    pub fn fingerprint(&self) -> Hash {
        hash(
            b"pon-grouped-fresh-verifier-request-v0",
            &[
                &[self.mode as u8],
                &self.nonce.to_be_bytes(),
                &self.statement,
                &self.proof_sha256,
                &self.capsule_sha256,
            ],
        )
    }
}
/// Only a committed reservation creates this value. The carried ID is looked
/// up and spent atomically before replay; it is not a reusable signature fact.
#[derive(Debug)]
pub struct VerificationPermit {
    id: Hash,
    sequence: u64,
    request: Hash,
}
/// A consumed receiver reservation. Private fields and no Clone/Copy prevent a
/// receiver wrapper from replaying one successful claim as another call.
/// An opaque allocation binds it to the originating open ledger instance;
/// reopening invalidates already claimed in-memory tokens, without refunding
/// their durable reservations. Unclaimed IDs can still be claimed after reopen.
#[derive(Debug)]
pub struct ClaimedVerification {
    policy: Hash,
    request: Hash,
    origin: Arc<()>,
}
impl VerificationPermit {
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn observation(&self) -> serde_json::Value {
        serde_json::json!({"verification_permit":hex::encode(self.id),"sequence":self.sequence,
            "request_fingerprint":hex::encode(self.request),"fixed_submission_limit":MAX_VERIFICATION_SUBMISSIONS,
            "reservation_charged_durably":true,"scope":"one exact frozen research-policy journal, not cloned or global nodes"})
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct SealObservation {
    pub schema: &'static str,
    pub work_id: String,
    pub challenge: String,
    pub statement: String,
    pub ticket: String,
    pub target: String,
    pub step_count: u16,
    pub target_hit: bool,
    pub first_record: bool,
    pub journal_recorded: bool,
    pub chainwork_awarded: u64,
    pub grouped_arithmetic_verified_by_this_api: bool,
    pub external_demand_authenticated: bool,
    pub production_activation: bool,
}
impl ResearchLedger {
    pub fn create(path: &Path, admission: &VerifiedAdmission) -> Result<Self> {
        require(path.is_absolute(), AdmissionError::Journal)?;
        let file = FileOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| AdmissionError::Journal)?;
        file.try_lock_exclusive()
            .map_err(|_| AdmissionError::Journal)?;
        let db = Self::connection(path)?;
        db.execute_batch("PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;BEGIN IMMEDIATE;
            CREATE TABLE context(singleton INTEGER PRIMARY KEY CHECK(singleton=1),policy BLOB NOT NULL CHECK(length(policy)=32));
            CREATE TABLE attempts(work BLOB PRIMARY KEY CHECK(length(work)=32),candidate BLOB NOT NULL,nonce BLOB NOT NULL CHECK(length(nonce)=8),status TEXT NOT NULL CHECK(status IN ('reserved','produced','hit','miss')),statement BLOB,proof_sha BLOB,ticket BLOB);
            CREATE TABLE verification_submissions(sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 1 AND 256),permit BLOB UNIQUE NOT NULL CHECK(length(permit)=32),request BLOB NOT NULL CHECK(length(request)=32),spent INTEGER NOT NULL CHECK(spent IN (0,1)));")
            .map_err(|_| AdmissionError::Journal)?;
        db.execute(
            "INSERT INTO context VALUES(1,?)",
            [admission.policy_id.as_slice()],
        )
        .map_err(|_| AdmissionError::Journal)?;
        db.execute_batch("COMMIT")
            .map_err(|_| AdmissionError::Journal)?;
        Ok(Self {
            db,
            _held_file: file,
            policy_id: admission.policy_id,
            origin: Arc::new(()),
        })
    }
    fn connection(path: &Path) -> Result<Connection> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| AdmissionError::Journal)?;
        db.busy_timeout(std::time::Duration::ZERO)
            .map_err(|_| AdmissionError::Journal)?;
        Ok(db)
    }
    pub fn open(path: &Path, admission: &VerifiedAdmission) -> Result<Self> {
        require(path.is_absolute(), AdmissionError::Journal)?;
        let metadata = std::fs::symlink_metadata(path).map_err(|_| AdmissionError::Journal)?;
        require(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            AdmissionError::Journal,
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            require(metadata.nlink() == 1, AdmissionError::Journal)?;
        }
        let file = FileOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| AdmissionError::Journal)?;
        file.try_lock_exclusive()
            .map_err(|_| AdmissionError::Journal)?;
        let db = Self::connection(path)?;
        let stored: Vec<u8> = db
            .query_row("SELECT policy FROM context WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(|_| AdmissionError::Journal)?;
        require(
            stored == admission.policy_id,
            AdmissionError::JournalContext,
        )?;
        let (count, max): (u64, u64) = db
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM verification_submissions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| AdmissionError::Journal)?;
        require(
            count == max && count <= MAX_VERIFICATION_SUBMISSIONS,
            AdmissionError::Journal,
        )?;
        db.execute_batch("PRAGMA synchronous=FULL")
            .map_err(|_| AdmissionError::Journal)?;
        Ok(Self {
            db,
            _held_file: file,
            policy_id: admission.policy_id,
            origin: Arc::new(()),
        })
    }
    fn check(&self, admission: &VerifiedAdmission) -> Result<()> {
        require(
            self.policy_id == admission.policy_id,
            AdmissionError::JournalContext,
        )
    }
    /// Reserve before full grouped-reference or seal replay. Invalid, duplicate
    /// and abandoned submissions remain charged to this fixed K.
    pub fn reserve_verification(
        &mut self,
        admission: &VerifiedAdmission,
        request: &VerificationRequest,
        node: &Node,
        now_ns: u64,
    ) -> Result<VerificationPermit> {
        self.check(admission)?;
        admission.recheck(node, now_ns)?;
        admission.candidate_bytes(request.nonce)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AdmissionError::Journal)?;
        let (count, max): (u64, u64) = tx
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM verification_submissions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| AdmissionError::Journal)?;
        require(count == max, AdmissionError::Journal)?;
        require(
            count < MAX_VERIFICATION_SUBMISSIONS,
            AdmissionError::VerificationBudget,
        )?;
        let sequence = count + 1;
        let request = request.fingerprint();
        let id = hash(
            b"pon-grouped-fresh-verifier-permit-v0",
            &[&self.policy_id, &sequence.to_be_bytes(), &request],
        );
        tx.execute(
            "INSERT INTO verification_submissions VALUES(?,?,?,0)",
            params![sequence, id.as_slice(), request.as_slice()],
        )
        .map_err(|_| AdmissionError::Journal)?;
        tx.commit().map_err(|_| AdmissionError::Journal)?;
        Ok(VerificationPermit {
            id,
            sequence,
            request,
        })
    }
    /// Spend once before expensive replay. A wrong request burns an existing
    /// permit too; no rejection or error refunds the durable budget.
    pub fn claim_verification(
        &mut self,
        admission: &VerifiedAdmission,
        permit: Hash,
        request: &VerificationRequest,
    ) -> Result<ClaimedVerification> {
        self.check(admission)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AdmissionError::Journal)?;
        let row: Option<(Vec<u8>, bool)> = tx
            .query_row(
                "SELECT request,spent FROM verification_submissions WHERE permit=?",
                [permit.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| AdmissionError::Journal)?;
        let (expected, spent) = row.ok_or(AdmissionError::VerificationPermit)?;
        require(!spent, AdmissionError::VerificationPermit)?;
        require(
            tx.execute(
                "UPDATE verification_submissions SET spent=1 WHERE permit=? AND spent=0",
                [permit.as_slice()],
            )
            .map_err(|_| AdmissionError::Journal)?
                == 1,
            AdmissionError::Journal,
        )?;
        tx.commit().map_err(|_| AdmissionError::Journal)?;
        require(
            expected == request.fingerprint(),
            AdmissionError::VerificationBinding,
        )?;
        Ok(ClaimedVerification {
            policy: self.policy_id,
            request: request.fingerprint(),
            origin: Arc::clone(&self.origin),
        })
    }
    fn checked_claim(
        &self,
        claimed: ClaimedVerification,
        admission: &VerifiedAdmission,
        nonce: u64,
        statement: Hash,
        proof: &[u8],
        mode: VerificationMode,
    ) -> Result<()> {
        self.check(admission)?;
        let actual = VerificationRequest::from_digests(
            nonce,
            statement,
            sha256(proof),
            admission.capsule_sha256,
            mode,
        )
        .fingerprint();
        require(
            Arc::ptr_eq(&claimed.origin, &self.origin)
                && claimed.policy == self.policy_id
                && claimed.request == actual,
            AdmissionError::VerificationBinding,
        )
    }
    /// Metered untrusted receiver path. No producer record is consulted, but a
    /// distinct durable submission must already have been claimed exactly once.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_untrusted_with_permit(
        &self,
        claimed: ClaimedVerification,
        admission: &VerifiedAdmission,
        nonce: u64,
        statement: Hash,
        proof: &[u8],
        node: &Node,
        now_ns: impl FnMut() -> Result<u64>,
    ) -> Result<SealObservation> {
        self.checked_claim(
            claimed,
            admission,
            nonce,
            statement,
            proof,
            VerificationMode::Untrusted,
        )?;
        admission.verify_untrusted_seal(nonce, statement, proof, node, now_ns)
    }
    pub fn reserve(
        &mut self,
        admission: &VerifiedAdmission,
        nonce: u64,
        node: &Node,
        now_ns: u64,
    ) -> Result<Hash> {
        self.check(admission)?;
        admission.recheck(node, now_ns)?;
        let id = admission.work_id(nonce)?;
        let candidate = admission.candidate_bytes(nonce)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AdmissionError::Journal)?;
        let found: Option<Vec<u8>> = tx
            .query_row(
                "SELECT candidate FROM attempts WHERE work=?",
                [id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| AdmissionError::Journal)?;
        require(found.is_none(), AdmissionError::Replay)?;
        tx.execute(
            "INSERT INTO attempts(work,candidate,nonce,status) VALUES(?,?,?,'reserved')",
            params![id.as_slice(), candidate, nonce.to_be_bytes().as_slice()],
        )
        .map_err(|_| AdmissionError::Journal)?;
        tx.commit().map_err(|_| AdmissionError::Journal)?;
        Ok(id)
    }
    /// Retain production before threshold/authority/deadline acceptance. This
    /// records a claim, not a verified seal. Partial or killed production leaves
    /// its durable reservation and cannot acquire a replacement free attempt.
    pub fn produced(
        &mut self,
        admission: &VerifiedAdmission,
        nonce: u64,
        statement: Hash,
        proof: &[u8],
    ) -> Result<()> {
        self.check(admission)?;
        require(proof.len() == seal::PROOF_BYTES, AdmissionError::Shape)?;
        let id = admission.work_id(nonce)?;
        let ticket = &proof[proof.len() - 32..];
        require(self.db.execute("UPDATE attempts SET status='produced',statement=?,proof_sha=?,ticket=? WHERE work=? AND status='reserved'",
            params![statement.as_slice(),sha256(proof).as_slice(),ticket,id.as_slice()]).map_err(|_| AdmissionError::Journal)? == 1,AdmissionError::Reservation)
    }
    /// Full mathematical seal replay is paid even for a losing endpoint. The
    /// maximum target used for that check confers no authority: target_hit is
    /// compared separately with the independently pinned actual Node target.
    /// This API does not verify grouped arithmetic; the experiment must also
    /// run the independent full grouped reference before reporting correctness.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_record(
        &mut self,
        claimed: ClaimedVerification,
        admission: &VerifiedAdmission,
        nonce: u64,
        statement: Hash,
        proof: &[u8],
        node: &Node,
        mut now_ns: impl FnMut() -> Result<u64>,
    ) -> Result<SealObservation> {
        self.checked_claim(
            claimed,
            admission,
            nonce,
            statement,
            proof,
            VerificationMode::Record,
        )?;
        let started = now_ns()?;
        admission.recheck(node, started)?;
        let challenge = admission.challenge_for_nonce(nonce)?;
        let id = admission.work_id(nonce)?;
        let verified =
            seal::verify(challenge, statement, [0xff; 32], proof).map_err(AdmissionError::Seal)?;
        let completed = now_ns()?;
        require(completed >= started, AdmissionError::Window)?;
        admission.recheck(node, completed)?;
        let target = admission.body.branch.target;
        let hit = verified.ticket() <= target;
        let status = if hit { "hit" } else { "miss" };
        let candidate = admission.candidate_bytes(nonce)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AdmissionError::Journal)?;
        let row: (Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>) = tx
            .query_row(
                "SELECT candidate,status,statement,proof_sha,ticket FROM attempts WHERE work=?",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .map_err(|_| AdmissionError::Reservation)?;
        require(
            row.0 == candidate
                && row.2 == statement
                && row.3 == sha256(proof)
                && row.4 == verified.ticket(),
            AdmissionError::ProductionBinding,
        )?;
        let first = row.1 == "produced";
        require(first || row.1 == status, AdmissionError::ProductionBinding)?;
        if first {
            require(
                tx.execute(
                    "UPDATE attempts SET status=? WHERE work=? AND status='produced'",
                    params![status, id.as_slice()],
                )
                .map_err(|_| AdmissionError::Journal)?
                    == 1,
                AdmissionError::Journal,
            )?;
        }
        let committing = now_ns()?;
        require(committing >= completed, AdmissionError::Window)?;
        admission.recheck(node, committing)?;
        tx.commit().map_err(|_| AdmissionError::Journal)?;
        Ok(SealObservation {
            schema: "pon-grouped-fresh-seal-observation-v0",
            work_id: hex::encode(id),
            challenge: hex::encode(challenge),
            statement: hex::encode(statement),
            ticket: hex::encode(verified.ticket()),
            target: hex::encode(target),
            step_count: verified.step_count(),
            target_hit: hit,
            first_record: first,
            journal_recorded: true,
            chainwork_awarded: 0,
            grouped_arithmetic_verified_by_this_api: false,
            external_demand_authenticated: false,
            production_activation: false,
        })
    }
    pub fn observation(&self) -> Result<serde_json::Value> {
        let (reserved, spent): (u64, u64) = self
            .db
            .query_row(
                "SELECT COUNT(*),COALESCE(SUM(spent),0) FROM verification_submissions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| AdmissionError::Journal)?;
        let mut rows = self
            .db
            .prepare(
                "SELECT work,nonce,status,statement,proof_sha,ticket FROM attempts ORDER BY nonce",
            )
            .map_err(|_| AdmissionError::Journal)?;
        let values = rows.query_map([],|r| {
            let id:Vec<u8>=r.get(0)?; let nonce:Vec<u8>=r.get(1)?; let status:String=r.get(2)?;
            let statement:Option<Vec<u8>>=r.get(3)?; let proof:Option<Vec<u8>>=r.get(4)?; let ticket:Option<Vec<u8>>=r.get(5)?;
            Ok(serde_json::json!({"work_id":hex::encode(id),"nonce_be_hex":hex::encode(nonce),"status":status,
                "statement":statement.map(hex::encode),"proof_sha256":proof.map(hex::encode),"ticket":ticket.map(hex::encode)}))
        }).map_err(|_| AdmissionError::Journal)?.collect::<std::result::Result<Vec<_>,_>>().map_err(|_| AdmissionError::Journal)?;
        Ok(
            serde_json::json!({"schema":"pon-grouped-fresh-research-ledger-v0","policy_id":hex::encode(self.policy_id),"attempts":values,
            "verification_budget":{"fixed_limit":MAX_VERIFICATION_SUBMISSIONS,"reserved":reserved,"spent":spent,"remaining":MAX_VERIFICATION_SUBMISSIONS.checked_sub(reserved),
                "scope":"one exact frozen research-policy journal, not cloned or global nodes","nonce_window_is_submission_cap":false},
            "durable_within_exact_frozen_policy":true,"policy_updates_supported":false,"consensus_ancestry_ledger":false,
            "chainwork_awarded":0,"business_credit":0,"external_demand_authenticated":false,"production_activation":false}),
        )
    }
}
