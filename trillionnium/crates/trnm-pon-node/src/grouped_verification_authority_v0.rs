//! One explicitly trusted verification owner for a frozen research epoch.
//!
//! Registered receiver processes share this owner's durable budget; they do
//! not receive a reusable capability to run verification elsewhere. The owner
//! executes the original grouped reference and fresh seal itself, commits a
//! started record before replay, and never replays an indeterminate attempt.
//! This is not decentralized admission, anti-rollback storage, genuine demand,
//! a timing-safe oracle, consensus credit, or a production service. Cloning or
//! rolling back the owner, bypassing it, or admitting another owner invalidates
//! the aggregate-cap assumption. A local receiver limit alone does not suffice.
use crate::{grouped_fresh_admission_v0 as admission, Node};
use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions as FileOptions},
    path::Path,
    time::Instant,
};
use trnm_crypto_primitives::{
    hash_domain, pon_grouped_fresh_seal_v0 as seal, pon_routed_int257_grouped as grouped,
    verify_hex_strict,
};
use trnm_protocol::pon_wire::{hash, Hash};

pub const SCHEMA: &str = "pon-grouped-verification-authority-v0";
pub const MAX_PERMITS: u64 = 256;
pub const MAX_RECEIVERS: usize = 16;
pub const MAX_CANDIDATES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    Shape,
    MaterialBinding,
    AuthorizationScope,
    Context,
    Policy,
    Receiver,
    Signature,
    Candidate,
    CandidateClosed,
    EpochBudget,
    CandidateBudget,
    IdempotencyConflict,
    Journal,
    JournalBusy,
    JournalCorrupt,
}
pub type Result<T> = std::result::Result<T, AuthorityError>;

fn require(value: bool, error: AuthorityError) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(error)
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(h: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(h))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        if text.len() != 64
            || text
                .bytes()
                .any(|c| !matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(serde::de::Error::custom("canonical 32-byte lowercase hex"));
        }
        hex::decode(text)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("32 bytes"))
    }
}

#[derive(Clone)]
struct Candidate {
    nonce: u64,
    challenge: Hash,
    statement: Hash,
    context: grouped::Context,
    expected: grouped::Observation,
}

/// Immutable expected material. Statements are determined before any seal
/// query; each callback still independently verifies the supplied product.
pub struct FrozenRelation {
    admission: admission::VerifiedAdmission,
    model: grouped::PreparedModel,
    requests: Vec<grouped::Request>,
    candidates: BTreeMap<Hash, Candidate>,
    fingerprint: Hash,
}

/// Reconstruct the pre-challenge request commitment used by the existing
/// capsule. The mathematical profile remains exactly the original int257 one.
pub fn request_precommitment(
    prepared: &grouped::PreparedModel,
    requests: &[grouped::Request],
) -> Result<Hash> {
    require(
        requests.len() == usize::from(seal::BATCH_SIZE),
        AuthorityError::Shape,
    )?;
    let mut raw = (requests.len() as u64).to_be_bytes().to_vec();
    for r in requests {
        raw.extend_from_slice(&r.id);
        raw.extend_from_slice(&r.scope);
        raw.extend_from_slice(&r.arrival_ns.to_be_bytes());
        raw.extend_from_slice(&r.deadline_ns.to_be_bytes());
        for x in r.x {
            raw.extend_from_slice(&i64::from(x).to_be_bytes());
        }
    }
    Ok(hash_domain(
        "pon-grouped-preinput-audit-v0",
        &[
            b"pon-grouped-int257-lottery-audit-v0",
            seal::NUMERIC.as_bytes(),
            &prepared.commitment(),
            &raw,
        ],
    ))
}

impl FrozenRelation {
    pub fn prepare(
        admission: admission::VerifiedAdmission,
        model: grouped::Model,
        requests: Vec<grouped::Request>,
        node: &Node,
        now_ns: u64,
    ) -> Result<Self> {
        admission
            .recheck(node, now_ns)
            .map_err(|_| AuthorityError::Context)?;
        let intent = admission.body().intent();
        require(
            intent.nonce_count as usize <= MAX_CANDIDATES,
            AuthorityError::Shape,
        )?;
        let prepared = grouped::PreparedModel::new(model).map_err(|_| AuthorityError::Shape)?;
        require(
            prepared.commitment() == intent.model_commitment
                && request_precommitment(&prepared, &requests)? == intent.request_precommitment,
            AuthorityError::MaterialBinding,
        )?;
        require(
            requests
                .iter()
                .all(|r| r.scope == intent.authorization_scope),
            AuthorityError::AuthorizationScope,
        )?;
        let mut candidates = BTreeMap::new();
        let mut raw = Vec::new();
        for offset in 0..intent.nonce_count {
            let nonce = intent
                .nonce_first
                .checked_add(offset)
                .ok_or(AuthorityError::Shape)?;
            let challenge = admission
                .challenge_for_nonce(nonce)
                .map_err(|_| AuthorityError::Context)?;
            let context = grouped::Context {
                chain: node.settings().network(),
                parent: node.active().map_err(|_| AuthorityError::Context)?.0,
                challenge,
                batch_id: intent.batch_id,
            };
            let (batch, _) = prepared
                .prepare_batch(&context, &requests, now_ns)
                .map_err(|_| AuthorityError::Shape)?;
            let (expected, _) = prepared
                .observe_direct(&batch)
                .map_err(|_| AuthorityError::Shape)?;
            let id = admission
                .work_id(nonce)
                .map_err(|_| AuthorityError::Context)?;
            raw.extend_from_slice(&id);
            raw.extend_from_slice(&nonce.to_be_bytes());
            raw.extend_from_slice(&challenge);
            raw.extend_from_slice(&expected.statement_commitment);
            candidates.insert(
                id,
                Candidate {
                    nonce,
                    challenge,
                    statement: expected.statement_commitment,
                    context,
                    expected,
                },
            );
        }
        admission
            .recheck(node, now_ns)
            .map_err(|_| AuthorityError::Context)?;
        let fingerprint = hash(
            b"pon-grouped-owner-material-v0",
            &[
                &admission.policy_id(),
                &admission.body().branch().target(),
                &raw,
            ],
        );
        Ok(Self {
            admission,
            model: prepared,
            requests,
            candidates,
            fingerprint,
        })
    }
    pub fn fingerprint(&self) -> Hash {
        self.fingerprint
    }
    pub fn admission_policy(&self) -> Hash {
        self.admission.policy_id()
    }
    pub fn candidates(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.candidates
                .iter()
                .map(|(id, c)| {
                    serde_json::json!({
                        "candidate":hex::encode(id), "nonce":c.nonce,
                        "challenge":hex::encode(c.challenge), "statement":hex::encode(c.statement),
                        "target":hex::encode(self.admission.body().branch().target()),
                    })
                })
                .collect(),
        )
    }
    pub fn canonical_claim(&self, candidate: Hash) -> Result<grouped::Observation> {
        self.candidates
            .get(&candidate)
            .map(|c| c.expected.clone())
            .ok_or(AuthorityError::Candidate)
    }
    pub fn candidate_for_nonce(&self, nonce: u64) -> Result<Hash> {
        self.candidates
            .iter()
            .find_map(|(id, c)| (c.nonce == nonce).then_some(*id))
            .ok_or(AuthorityError::Candidate)
    }
    pub fn challenge(&self, candidate: Hash) -> Result<Hash> {
        self.candidates
            .get(&candidate)
            .map(|c| c.challenge)
            .ok_or(AuthorityError::Candidate)
    }
}

/// A fixed policy names one owner and one epoch. It is not an automatically
/// renewable quota and has no API for changing epoch, participants or limits.
#[derive(Clone, Debug)]
pub struct BudgetPolicy {
    authority: Hash,
    epoch: Hash,
    generation: u64,
    limit: u64,
    per_candidate: u64,
    receivers: BTreeSet<Hash>,
    candidates: BTreeSet<Hash>,
    relation: Hash,
    id: Hash,
}
impl BudgetPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority: Hash,
        epoch: Hash,
        generation: u64,
        limit: u64,
        per_candidate: u64,
        receivers: Vec<Hash>,
        relation: &FrozenRelation,
    ) -> Result<Self> {
        let count = receivers.len();
        let receivers: BTreeSet<_> = receivers.into_iter().collect();
        require(
            authority != [0; 32]
                && epoch != [0; 32]
                && generation > 0
                && (1..=MAX_PERMITS).contains(&limit)
                && (1..=limit).contains(&per_candidate)
                && (1..=MAX_RECEIVERS).contains(&count)
                && count == receivers.len()
                && !receivers.contains(&[0; 32])
                && !receivers.contains(&authority),
            AuthorityError::Policy,
        )?;
        let mut raw = Vec::new();
        for x in &receivers {
            raw.extend_from_slice(x);
        }
        let id = hash(
            b"pon-grouped-verifier-authority-policy-v0",
            &[
                &authority,
                &epoch,
                &generation.to_be_bytes(),
                &limit.to_be_bytes(),
                &per_candidate.to_be_bytes(),
                &relation.fingerprint,
                &raw,
            ],
        );
        Ok(Self {
            authority,
            epoch,
            generation,
            limit,
            per_candidate,
            receivers,
            candidates: relation.candidates.keys().copied().collect(),
            relation: relation.fingerprint,
            id,
        })
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn authority(&self) -> Hash {
        self.authority
    }
    pub fn observation(&self) -> serde_json::Value {
        serde_json::json!({"schema":SCHEMA,"authority":hex::encode(self.authority),
            "epoch":hex::encode(self.epoch),"generation":self.generation,"policy":hex::encode(self.id),
            "relation":hex::encode(self.relation),"aggregate_limit":self.limit,
            "per_candidate_limit":self.per_candidate,
            "receivers":self.receivers.iter().map(hex::encode).collect::<Vec<_>>(),
            "candidate_count":self.candidates.len(),"scope":"one trusted owner with this exact immutable epoch",
            "global_public_network_cap":false,"anti_clone_or_rollback":false,
            "chainwork_awarded":0,"production_activation":false})
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Reserve = 1,
    Execute = 2,
}

/// Untrusted finite submission. Signatures bind action, exact policy, receiver,
/// operation id, candidate, all supplied product fields and every proof byte.
#[derive(Clone, Debug)]
pub struct Submission {
    pub receiver: Hash,
    pub request_id: Hash,
    pub candidate: Hash,
    pub claim: grouped::Observation,
    pub proof: Vec<u8>,
    pub signature: Vec<u8>,
}

fn claim_bytes(c: &grouped::Observation) -> Result<Vec<u8>> {
    let p = &c.product;
    let n = usize::from(seal::BATCH_SIZE);
    require(
        p.router_outputs.len() <= n
            && p.routes.len() <= n
            && p.logits.len() <= n
            && p.predictions.len() <= n
            && p.groups.iter().all(|g| g.len() <= n)
            && p.groups.iter().map(Vec::len).sum::<usize>() <= n,
        AuthorityError::Shape,
    )?;
    let mut raw = Vec::new();
    for h in [
        c.model_commitment,
        c.input_commitment,
        c.statement_commitment,
    ] {
        raw.extend_from_slice(&h);
    }
    for rows in [&p.router_outputs, &p.logits] {
        raw.extend_from_slice(&(rows.len() as u64).to_be_bytes());
        for r in rows {
            for x in r {
                raw.extend_from_slice(&x.to_be_bytes());
            }
        }
    }
    for rows in [
        &p.routes,
        &p.predictions,
        &p.groups[0],
        &p.groups[1],
        &p.groups[2],
    ] {
        raw.extend_from_slice(&(rows.len() as u64).to_be_bytes());
        for &x in rows {
            raw.extend_from_slice(&(x as u64).to_be_bytes());
        }
    }
    for x in [
        p.useful_dense_macs,
        p.padded_macs,
        p.nonempty_expert_groups as u64,
    ] {
        raw.extend_from_slice(&x.to_be_bytes());
    }
    Ok(raw)
}
impl Submission {
    pub fn fingerprint(&self, policy: &BudgetPolicy) -> Result<Hash> {
        self.fingerprint_for_policy_id(policy.id)
    }
    /// Client-side framing against an externally pinned policy digest. This
    /// helper grants no authority and does not validate the supplied pin.
    pub fn fingerprint_for_policy_id(&self, policy_id: Hash) -> Result<Hash> {
        require(
            self.request_id != [0; 32] && self.proof.len() <= seal::PROOF_BYTES,
            AuthorityError::Shape,
        )?;
        Ok(hash(
            b"pon-grouped-owner-submission-v0",
            &[
                &policy_id,
                &self.receiver,
                &self.request_id,
                &self.candidate,
                &claim_bytes(&self.claim)?,
                &self.proof,
            ],
        ))
    }
    pub fn signing_message(&self, policy: &BudgetPolicy, action: Action) -> Result<Hash> {
        self.signing_message_for_policy_id(policy.id, action)
    }
    pub fn signing_message_for_policy_id(&self, policy_id: Hash, action: Action) -> Result<Hash> {
        Ok(hash(
            b"pon-grouped-owner-receiver-signature-v0",
            &[&[action as u8], &self.fingerprint_for_policy_id(policy_id)?],
        ))
    }
    fn authenticate(&self, policy: &BudgetPolicy, action: Action) -> Result<Hash> {
        require(
            policy.receivers.contains(&self.receiver),
            AuthorityError::Receiver,
        )?;
        require(
            policy.candidates.contains(&self.candidate),
            AuthorityError::Candidate,
        )?;
        require(self.signature.len() == 64, AuthorityError::Signature)?;
        verify_hex_strict(
            &hex::encode(self.receiver),
            &self.signing_message(policy, action)?,
            &hex::encode(&self.signature),
        )
        .map_err(|_| AuthorityError::Signature)?;
        self.fingerprint(policy)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    VerifiedHit,
    VerifiedMiss,
    RelationRejected,
    ContextRejected,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayCost {
    pub full_cell_calls: u64,
    pub full_cell_verified: bool,
    pub seed_queries: u64,
    pub step_queries: u64,
    pub wall_ns: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: String,
    #[serde(with = "hex32")]
    pub policy: Hash,
    #[serde(with = "hex32")]
    pub authority: Hash,
    #[serde(with = "hex32")]
    pub epoch: Hash,
    pub generation: u64,
    pub sequence: u64,
    #[serde(with = "hex32")]
    pub receiver: Hash,
    #[serde(with = "hex32")]
    pub request_id: Hash,
    #[serde(with = "hex32")]
    pub candidate: Hash,
    #[serde(with = "hex32")]
    pub request_fingerprint: Hash,
    pub outcome: Outcome,
    pub endpoint: Option<String>,
    pub first_record: bool,
    pub cost: ReplayCost,
    pub chainwork_awarded: u64,
}
#[derive(Clone, Debug)]
pub enum SubmissionState {
    Reserved { sequence: u64 },
    Complete { receipt: Box<Receipt>, cached: bool },
    Unknown { sequence: u64 },
}
impl SubmissionState {
    pub fn observation(&self) -> serde_json::Value {
        match self {
            Self::Reserved { sequence } => {
                serde_json::json!({"state":"reserved","sequence":sequence,"reservation_charged":true})
            }
            Self::Complete { receipt, cached } => {
                serde_json::json!({"state":"complete","receipt":receipt,"cached":cached,
                "new_candidate_completion":!*cached && receipt.first_record,
                "cached_receipt_is_historical":cached,
                "cached_response_does_not_revalidate_context":cached,
                "new_chainwork_awarded":0,
                "new_full_cell_calls":if *cached {0} else {receipt.cost.full_cell_calls},
                "new_seed_queries":if *cached {0} else {receipt.cost.seed_queries},
                "new_step_queries":if *cached {0} else {receipt.cost.step_queries}})
            }
            Self::Unknown { sequence } => serde_json::json!({"state":"unknown","sequence":sequence,
                "retry_permitted":false,"refunded":false,"cell_calls_unknown_upper":1,
                "seed_queries_unknown_upper":1,"step_queries_unknown_upper":seal::STEPS}),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    Started,
    CellVerified,
    Seed,
    Step(u16),
}

pub struct VerificationAuthority {
    db: Connection,
    _held_file: File,
    policy: BudgetPolicy,
}
type StoredRow = (u64, Vec<u8>, Vec<u8>, String, Option<String>);

impl VerificationAuthority {
    fn held_file(path: &Path, create: bool) -> Result<File> {
        require(path.is_absolute(), AuthorityError::Journal)?;
        if !create {
            let m = std::fs::symlink_metadata(path).map_err(|_| AuthorityError::Journal)?;
            require(
                m.is_file() && !m.file_type().is_symlink(),
                AuthorityError::Journal,
            )?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                require(m.nlink() == 1, AuthorityError::Journal)?;
            }
        }
        let mut options = FileOptions::new();
        options.read(true).write(true).create_new(create);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path).map_err(|_| AuthorityError::Journal)?;
        file.try_lock_exclusive()
            .map_err(|_| AuthorityError::JournalBusy)?;
        Ok(file)
    }
    fn connection(path: &Path) -> Result<Connection> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| AuthorityError::Journal)?;
        db.busy_timeout(std::time::Duration::ZERO)
            .map_err(|_| AuthorityError::Journal)?;
        db.execute_batch("PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;")
            .map_err(|_| AuthorityError::Journal)?;
        Ok(db)
    }
    pub fn create(path: &Path, policy: BudgetPolicy) -> Result<Self> {
        let held = Self::held_file(path, true)?;
        let db = Self::connection(path)?;
        db.execute_batch("BEGIN IMMEDIATE;
          CREATE TABLE context(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema TEXT NOT NULL,policy BLOB NOT NULL CHECK(length(policy)=32),issued INTEGER NOT NULL CHECK(issued BETWEEN 0 AND 256));
          CREATE TABLE submissions(sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 1 AND 256),receiver BLOB NOT NULL CHECK(length(receiver)=32),request_id BLOB NOT NULL CHECK(length(request_id)=32),candidate BLOB NOT NULL CHECK(length(candidate)=32),fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),state TEXT NOT NULL CHECK(state IN ('reserved','started','complete','unknown')),receipt TEXT,UNIQUE(receiver,request_id));
          CREATE TABLE closed_candidates(candidate BLOB PRIMARY KEY CHECK(length(candidate)=32),sequence INTEGER UNIQUE NOT NULL,endpoint BLOB NOT NULL CHECK(length(endpoint)=32));")
            .map_err(|_| AuthorityError::Journal)?;
        db.execute(
            "INSERT INTO context VALUES(1,?,?,0)",
            params![SCHEMA, policy.id.as_slice()],
        )
        .map_err(|_| AuthorityError::Journal)?;
        db.execute_batch("COMMIT")
            .map_err(|_| AuthorityError::Journal)?;
        Ok(Self {
            db,
            _held_file: held,
            policy,
        })
    }
    pub fn open(path: &Path, policy: BudgetPolicy) -> Result<Self> {
        let held = Self::held_file(path, false)?;
        let db = Self::connection(path)?;
        let mut value = Self {
            db,
            _held_file: held,
            policy,
        };
        value.validate_journal()?;
        // No result was committed before the process disappeared. It is unsafe
        // to infer that work did not run, so these reservations cannot replay.
        value
            .db
            .execute(
                "UPDATE submissions SET state='unknown' WHERE state='started'",
                [],
            )
            .map_err(|_| AuthorityError::Journal)?;
        Ok(value)
    }
    fn validate_journal(&mut self) -> Result<()> {
        let integrity: String = self
            .db
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(|_| AuthorityError::JournalCorrupt)?;
        require(integrity == "ok", AuthorityError::JournalCorrupt)?;
        let (schema, policy, issued): (String, Vec<u8>, u64) = self
            .db
            .query_row(
                "SELECT schema,policy,issued FROM context WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|_| AuthorityError::JournalCorrupt)?;
        require(
            schema == SCHEMA && policy == self.policy.id,
            AuthorityError::Policy,
        )?;
        let (count, max): (u64, u64) = self
            .db
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM submissions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| AuthorityError::JournalCorrupt)?;
        require(
            count == issued && max == issued && issued <= self.policy.limit,
            AuthorityError::JournalCorrupt,
        )?;
        let mut counts = BTreeMap::<Hash, u64>::new();
        let mut complete = BTreeMap::<u64, Receipt>::new();
        let mut query=self.db.prepare("SELECT sequence,receiver,request_id,candidate,fingerprint,state,receipt FROM submissions ORDER BY sequence")
            .map_err(|_| AuthorityError::JournalCorrupt)?;
        let mut rows = query
            .query([])
            .map_err(|_| AuthorityError::JournalCorrupt)?;
        while let Some(row) = rows.next().map_err(|_| AuthorityError::JournalCorrupt)? {
            let seq: u64 = row.get(0).map_err(|_| AuthorityError::JournalCorrupt)?;
            let receiver = stored_hash(row.get(1).map_err(|_| AuthorityError::JournalCorrupt)?)?;
            let id = stored_hash(row.get(2).map_err(|_| AuthorityError::JournalCorrupt)?)?;
            let candidate = stored_hash(row.get(3).map_err(|_| AuthorityError::JournalCorrupt)?)?;
            let fingerprint = stored_hash(row.get(4).map_err(|_| AuthorityError::JournalCorrupt)?)?;
            let state: String = row.get(5).map_err(|_| AuthorityError::JournalCorrupt)?;
            let receipt: Option<String> = row.get(6).map_err(|_| AuthorityError::JournalCorrupt)?;
            require(
                self.policy.receivers.contains(&receiver)
                    && self.policy.candidates.contains(&candidate)
                    && id != [0; 32],
                AuthorityError::JournalCorrupt,
            )?;
            let count = counts.entry(candidate).or_default();
            *count += 1;
            require(
                *count <= self.policy.per_candidate,
                AuthorityError::JournalCorrupt,
            )?;
            require(
                (state == "complete") == receipt.is_some(),
                AuthorityError::JournalCorrupt,
            )?;
            if let Some(raw) = receipt {
                let receipt: Receipt =
                    serde_json::from_str(&raw).map_err(|_| AuthorityError::JournalCorrupt)?;
                self.validate_receipt(&receipt, seq, receiver, id, candidate, fingerprint)?;
                complete.insert(seq, receipt);
            }
        }
        drop(rows);
        drop(query);
        let mut query = self
            .db
            .prepare("SELECT candidate,sequence,endpoint FROM closed_candidates")
            .map_err(|_| AuthorityError::JournalCorrupt)?;
        let mut rows = query
            .query([])
            .map_err(|_| AuthorityError::JournalCorrupt)?;
        let mut closed = BTreeSet::new();
        while let Some(row) = rows.next().map_err(|_| AuthorityError::JournalCorrupt)? {
            let candidate = stored_hash(row.get(0).map_err(|_| AuthorityError::JournalCorrupt)?)?;
            let seq: u64 = row.get(1).map_err(|_| AuthorityError::JournalCorrupt)?;
            let endpoint = stored_hash(row.get(2).map_err(|_| AuthorityError::JournalCorrupt)?)?;
            let receipt = complete.get(&seq).ok_or(AuthorityError::JournalCorrupt)?;
            require(
                receipt.candidate == candidate
                    && receipt.first_record
                    && receipt.endpoint == Some(hex::encode(endpoint)),
                AuthorityError::JournalCorrupt,
            )?;
            closed.insert(seq);
        }
        require(
            complete
                .iter()
                .all(|(seq, r)| r.first_record == closed.contains(seq)),
            AuthorityError::JournalCorrupt,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn validate_receipt(
        &self,
        r: &Receipt,
        seq: u64,
        receiver: Hash,
        id: Hash,
        candidate: Hash,
        fingerprint: Hash,
    ) -> Result<()> {
        let good = matches!(r.outcome, Outcome::VerifiedHit | Outcome::VerifiedMiss);
        require(
            r.schema == SCHEMA
                && r.policy == self.policy.id
                && r.authority == self.policy.authority
                && r.epoch == self.policy.epoch
                && r.generation == self.policy.generation
                && r.sequence == seq
                && r.receiver == receiver
                && r.request_id == id
                && r.candidate == candidate
                && r.request_fingerprint == fingerprint
                && r.chainwork_awarded == 0
                && r.cost.full_cell_calls <= 1
                && r.cost.seed_queries <= 1
                && r.cost.step_queries <= u64::from(seal::STEPS)
                && (!r.cost.full_cell_verified || r.cost.full_cell_calls == 1)
                && (r.cost.step_queries == 0 || r.cost.seed_queries == 1)
                && (r.cost.seed_queries == 0 || r.cost.full_cell_verified)
                && r.first_record == good
                && r.endpoint.is_some() == good
                && (!good
                    || (r.cost.full_cell_verified
                        && r.cost.step_queries == u64::from(seal::STEPS)
                        && r.endpoint.as_ref().is_some_and(|v| {
                            v.len() == 64 && v.bytes().all(|b| matches!(b,b'0'..=b'9'|b'a'..=b'f'))
                        }))),
            AuthorityError::JournalCorrupt,
        )
    }
    fn prior(&self, s: &Submission, fingerprint: Hash) -> Result<Option<SubmissionState>> {
        let row:Option<StoredRow>=self.db.query_row(
            "SELECT sequence,candidate,fingerprint,state,receipt FROM submissions WHERE receiver=? AND request_id=?",
            params![s.receiver.as_slice(),s.request_id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))
            .optional().map_err(|_| AuthorityError::Journal)?;
        row.map(|(sequence, candidate, expected, state, raw)| {
            require(
                candidate == s.candidate && expected == fingerprint,
                AuthorityError::IdempotencyConflict,
            )?;
            match state.as_str() {
                "reserved" => Ok(SubmissionState::Reserved { sequence }),
                "started" | "unknown" => Ok(SubmissionState::Unknown { sequence }),
                "complete" => {
                    let receipt: Receipt =
                        serde_json::from_str(&raw.ok_or(AuthorityError::JournalCorrupt)?)
                            .map_err(|_| AuthorityError::JournalCorrupt)?;
                    self.validate_receipt(
                        &receipt,
                        sequence,
                        s.receiver,
                        s.request_id,
                        s.candidate,
                        fingerprint,
                    )?;
                    Ok(SubmissionState::Complete {
                        receipt: Box::new(receipt),
                        cached: true,
                    })
                }
                _ => Err(AuthorityError::JournalCorrupt),
            }
        })
        .transpose()
    }
    fn is_closed(&self, candidate: Hash) -> Result<bool> {
        self.db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM closed_candidates WHERE candidate=?)",
                [candidate.as_slice()],
                |r| r.get(0),
            )
            .map_err(|_| AuthorityError::Journal)
    }
    fn reserve_authenticated(
        &mut self,
        s: &Submission,
        fingerprint: Hash,
    ) -> Result<SubmissionState> {
        if let Some(old) = self.prior(s, fingerprint)? {
            return Ok(old);
        }
        require(
            !self.is_closed(s.candidate)?,
            AuthorityError::CandidateClosed,
        )?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthorityError::Journal)?;
        let issued: u64 = tx
            .query_row("SELECT issued FROM context WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(|_| AuthorityError::Journal)?;
        let (count, max): (u64, u64) = tx
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM submissions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| AuthorityError::Journal)?;
        require(
            issued == count && issued == max,
            AuthorityError::JournalCorrupt,
        )?;
        require(issued < self.policy.limit, AuthorityError::EpochBudget)?;
        let candidate_count: u64 = tx
            .query_row(
                "SELECT COUNT(*) FROM submissions WHERE candidate=?",
                [s.candidate.as_slice()],
                |r| r.get(0),
            )
            .map_err(|_| AuthorityError::Journal)?;
        require(
            candidate_count < self.policy.per_candidate,
            AuthorityError::CandidateBudget,
        )?;
        let sequence = issued + 1;
        tx.execute(
            "INSERT INTO submissions VALUES(?,?,?,?,?,'reserved',NULL)",
            params![
                sequence,
                s.receiver.as_slice(),
                s.request_id.as_slice(),
                s.candidate.as_slice(),
                fingerprint.as_slice()
            ],
        )
        .map_err(|_| AuthorityError::Journal)?;
        require(
            tx.execute(
                "UPDATE context SET issued=? WHERE singleton=1 AND issued=?",
                params![sequence, issued],
            )
            .map_err(|_| AuthorityError::Journal)?
                == 1,
            AuthorityError::JournalCorrupt,
        )?;
        tx.commit().map_err(|_| AuthorityError::Journal)?;
        Ok(SubmissionState::Reserved { sequence })
    }
    pub fn reserve(&mut self, s: &Submission) -> Result<SubmissionState> {
        let fingerprint = s.authenticate(&self.policy, Action::Reserve)?;
        self.reserve_authenticated(s, fingerprint)
    }
    /// Atomically burns and starts an authenticated reservation before any full
    /// Cell/seal replay. No transfer token leaves the owner. A completed retry
    /// is a cached result, and a crashed started attempt is never rerun.
    pub fn execute(
        &mut self,
        s: &Submission,
        relation: &FrozenRelation,
        node: &Node,
        mut now_ns: impl FnMut() -> u64,
        mut progress: impl FnMut(Progress) -> bool,
    ) -> Result<SubmissionState> {
        require(
            relation.fingerprint == self.policy.relation,
            AuthorityError::MaterialBinding,
        )?;
        let fingerprint = s.authenticate(&self.policy, Action::Execute)?;
        let sequence = match self.reserve_authenticated(s, fingerprint)? {
            SubmissionState::Reserved { sequence } => sequence,
            other => return Ok(other),
        };
        require(
            !self.is_closed(s.candidate)?,
            AuthorityError::CandidateClosed,
        )?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthorityError::Journal)?;
        require(
            tx.execute(
                "UPDATE submissions SET state='started' WHERE sequence=? AND state='reserved'",
                [sequence],
            )
            .map_err(|_| AuthorityError::Journal)?
                == 1,
            AuthorityError::JournalCorrupt,
        )?;
        tx.commit().map_err(|_| AuthorityError::Journal)?;
        let start = Instant::now();
        let mut cost = ReplayCost::default();
        let (outcome, endpoint) = replay(s, relation, node, &mut now_ns, &mut progress, &mut cost);
        cost.wall_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let good = matches!(outcome, Outcome::VerifiedHit | Outcome::VerifiedMiss);
        let receipt = Receipt {
            schema: SCHEMA.to_owned(),
            policy: self.policy.id,
            authority: self.policy.authority,
            epoch: self.policy.epoch,
            generation: self.policy.generation,
            sequence,
            receiver: s.receiver,
            request_id: s.request_id,
            candidate: s.candidate,
            request_fingerprint: fingerprint,
            outcome,
            endpoint: endpoint.map(hex::encode),
            first_record: good,
            cost,
            chainwork_awarded: 0,
        };
        self.validate_receipt(
            &receipt,
            sequence,
            s.receiver,
            s.request_id,
            s.candidate,
            fingerprint,
        )?;
        let raw = serde_json::to_string(&receipt).map_err(|_| AuthorityError::Journal)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthorityError::Journal)?;
        if good {
            tx.execute(
                "INSERT INTO closed_candidates VALUES(?,?,?)",
                params![
                    s.candidate.as_slice(),
                    sequence,
                    endpoint
                        .as_ref()
                        .ok_or(AuthorityError::JournalCorrupt)?
                        .as_slice()
                ],
            )
            .map_err(|_| AuthorityError::JournalCorrupt)?;
        }
        require(tx.execute("UPDATE submissions SET state='complete',receipt=? WHERE sequence=? AND state='started'",params![raw,sequence])
            .map_err(|_| AuthorityError::Journal)?==1,AuthorityError::JournalCorrupt)?;
        tx.commit().map_err(|_| AuthorityError::Journal)?;
        Ok(SubmissionState::Complete {
            receipt: Box::new(receipt),
            cached: false,
        })
    }
    pub fn snapshot(&self) -> Result<serde_json::Value> {
        let issued: u64 = self
            .db
            .query_row("SELECT issued FROM context WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(|_| AuthorityError::Journal)?;
        let mut states = BTreeMap::<String, u64>::new();
        let mut receivers = BTreeMap::<String, u64>::new();
        let mut rows_out = Vec::new();
        let mut known = ReplayCost::default();
        let mut verified_cell_calls = 0_u64;
        let mut unknown = 0_u64;
        let mut query=self.db.prepare("SELECT sequence,receiver,request_id,candidate,fingerprint,state,receipt FROM submissions ORDER BY sequence")
            .map_err(|_| AuthorityError::Journal)?;
        let mut rows = query.query([]).map_err(|_| AuthorityError::Journal)?;
        while let Some(row) = rows.next().map_err(|_| AuthorityError::Journal)? {
            let seq: u64 = row.get(0).map_err(|_| AuthorityError::Journal)?;
            let receiver: Vec<u8> = row.get(1).map_err(|_| AuthorityError::Journal)?;
            let request: Vec<u8> = row.get(2).map_err(|_| AuthorityError::Journal)?;
            let candidate: Vec<u8> = row.get(3).map_err(|_| AuthorityError::Journal)?;
            let fingerprint: Vec<u8> = row.get(4).map_err(|_| AuthorityError::Journal)?;
            let state: String = row.get(5).map_err(|_| AuthorityError::Journal)?;
            let raw: Option<String> = row.get(6).map_err(|_| AuthorityError::Journal)?;
            *states.entry(state.clone()).or_default() += 1;
            *receivers.entry(hex::encode(&receiver)).or_default() += 1;
            let receipt: Option<Receipt> = raw
                .map(|v| serde_json::from_str(&v))
                .transpose()
                .map_err(|_| AuthorityError::JournalCorrupt)?;
            if let Some(r) = &receipt {
                known.full_cell_calls += r.cost.full_cell_calls;
                verified_cell_calls += u64::from(r.cost.full_cell_verified);
                known.seed_queries += r.cost.seed_queries;
                known.step_queries += r.cost.step_queries;
                known.wall_ns = known.wall_ns.saturating_add(r.cost.wall_ns);
            }
            if state == "started" || state == "unknown" {
                unknown += 1;
            }
            rows_out.push(
                serde_json::json!({"sequence":seq,"receiver":hex::encode(receiver),
                "request_id":hex::encode(request),"candidate":hex::encode(candidate),
                "fingerprint":hex::encode(fingerprint),"state":state,"receipt":receipt}),
            );
        }
        Ok(
            serde_json::json!({"schema":SCHEMA,"policy":self.policy.observation(),
            "reserved":issued,"remaining":self.policy.limit.checked_sub(issued),"states":states,
            "per_receiver_reservations":receivers,"rows":rows_out,
            "full_cell_calls_known":known.full_cell_calls,"full_cell_calls_unknown_upper":unknown,
            "full_cell_verified_calls":verified_cell_calls,
            "incomplete_cell_calls":known.full_cell_calls-verified_cell_calls,
            "verified_cell_macs_known":verified_cell_calls*9*257*16,
            "incomplete_cell_macs_unknown_upper":(known.full_cell_calls-verified_cell_calls+unknown)*9*257*16,
            "seed_queries_known":known.seed_queries,"seed_queries_unknown_upper":unknown,
            "step_queries_known":known.step_queries,"step_queries_unknown_upper":unknown*u64::from(seal::STEPS),
            "epoch_step_query_upper":self.policy.limit*u64::from(seal::STEPS),
            "epoch_full_cell_call_upper":self.policy.limit,
            "full_cell_macs_per_complete_reference":9*grouped::DIM*usize::from(seal::BATCH_SIZE),
            "completed_replay_wall_ns_sum":known.wall_ns,"cost_scope":"only owner callback chain-step and full Cell calls; parsing/signatures/transport/preparation are additional measured costs",
            "verifier_side_channel_hidden":false,"global_public_network_cap":false,
            "chainwork_awarded":0,"production_activation":false}),
        )
    }
}

fn stored_hash(raw: Vec<u8>) -> Result<Hash> {
    raw.try_into().map_err(|_| AuthorityError::JournalCorrupt)
}

fn replay(
    s: &Submission,
    relation: &FrozenRelation,
    node: &Node,
    now: &mut impl FnMut() -> u64,
    progress: &mut impl FnMut(Progress) -> bool,
    cost: &mut ReplayCost,
) -> (Outcome, Option<Hash>) {
    if !progress(Progress::Started) {
        return (Outcome::Cancelled, None);
    }
    let before = now();
    if relation.admission.recheck(node, before).is_err() {
        return (Outcome::ContextRejected, None);
    }
    let Some(candidate) = relation.candidates.get(&s.candidate) else {
        return (Outcome::ContextRejected, None);
    };
    // Canonical statement is pre-pinned, including on unsuccessful submissions.
    if s.claim.statement_commitment != candidate.statement {
        return (Outcome::RelationRejected, None);
    }
    // Public framing checks can reject an impossible proof without doing Cell
    // arithmetic. A forged low endpoint still passes and requires full replay.
    if seal::precheck(
        candidate.challenge,
        candidate.statement,
        [0xff; 32],
        &s.proof,
    )
    .is_err()
    {
        return (Outcome::RelationRejected, None);
    }
    cost.full_cell_calls = 1;
    if relation
        .model
        .verify(&candidate.context, &relation.requests, before, &s.claim)
        .is_err()
    {
        return (Outcome::RelationRejected, None);
    }
    cost.full_cell_verified = true;
    if !progress(Progress::CellVerified) {
        return (Outcome::Cancelled, None);
    }
    let result = seal::verify_with_progress(
        candidate.challenge,
        candidate.statement,
        [0xff; 32],
        &s.proof,
        |p| {
            let p = match p {
                seal::Progress::Seed => {
                    cost.seed_queries += 1;
                    Progress::Seed
                }
                seal::Progress::Step(i) => {
                    cost.step_queries += 1;
                    Progress::Step(i)
                }
            };
            if progress(p) {
                Ok(())
            } else {
                Err(())
            }
        },
    );
    let verified = match result {
        Ok(v) => v,
        Err(seal::VerifyError::Cancelled(())) => return (Outcome::Cancelled, None),
        Err(seal::VerifyError::Relation(_)) => return (Outcome::RelationRejected, None),
    };
    let after = now();
    if after < before
        || relation.admission.recheck(node, after).is_err()
        || relation
            .requests
            .iter()
            .any(|r| after < r.arrival_ns || after >= r.deadline_ns)
    {
        return (Outcome::ContextRejected, None);
    }
    let endpoint = verified.ticket();
    let hit = endpoint <= relation.admission.body().branch().target();
    (
        if hit {
            Outcome::VerifiedHit
        } else {
            Outcome::VerifiedMiss
        },
        Some(endpoint),
    )
}
