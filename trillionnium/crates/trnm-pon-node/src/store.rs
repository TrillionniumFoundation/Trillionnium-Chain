//! M07/M08 native branch persistence and recovery using the existing M06 executor.
pub mod authenticated_migration;
pub(crate) mod authenticated_state;
pub mod capacity_observation;
pub mod evaluation_observation;
pub mod evaluation_round_observation;
mod history_page;
pub mod mempool;
pub(crate) mod native_authenticated;
mod operator_continuous_owner;
mod operator_mining_owner;
use crate::{
    consensus::{self, Work},
    development_public, ensure, maintenance, sequence_root, Error, Packet, Result, Settings,
};
use fs2::FileExt;
pub use history_page::HistoryPageReadCounters;
pub(crate) use operator_continuous_owner::PublicContinuousScope;
pub use operator_continuous_owner::{
    ContinuousSearchRequest, OwnedContinuousLeaseResult, OwnedContinuousPoolResult,
};
pub use operator_mining_owner::{MiningEpochCancellation, OwnedMutationResult, OwnedSearchResult};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use serde_json::Value;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use trnm_crypto_primitives::pon_work;
use trnm_crypto_primitives::qualified_work_task::{
    derive_matrices, verify_development_statement, DevelopmentTaskAdmission, TaskMaterial,
};
use trnm_mvcc_fee::checkpoint_tile_policy_v1::PROFILE as CHECKPOINT_TASK_PROFILE;
use trnm_mvcc_fee::continuity_v1::{self, PROFILE as CONTINUITY_TASK_PROFILE};
use trnm_mvcc_fee::pon_commitment::{
    self, CacheLimits, CheckedCommitment, CommitmentObservation, ExecutionRequest,
    PreparedCommitment,
};
use trnm_mvcc_fee::pon_executor::SIGNED_TASK_PROFILE;
use trnm_mvcc_fee::pon_executor::{
    root, ExecutionControl, ExecutionError, ExecutionProgress, State,
};
use trnm_mvcc_fee::qualified_task_lifecycle;
use trnm_protocol::pon_wire::{hash, Hash, Header, HEADER_BYTES};
use trnm_protocol::qualified_work_task::lifecycle_v2::PROFILE as LIFECYCLE_TASK_PROFILE;
use trnm_protocol::qualified_work_task::lifecycle_v3::PROFILE as ATOMIC_TASK_PROFILE;
use trnm_protocol::qualified_work_task::lifecycle_v4::PROFILE as OVERLAP_TASK_PROFILE;
use trnm_protocol::qualified_work_task::{
    QualifiedWorkTask, SignedQualifiedWorkTask, TaskPurpose, SIGNED_TASK_BYTES,
};
use trnm_transport::{
    AuthenticatedPeerFrameV0, CandidateP2pAdmissionV0, IoDigest32V0, PeerFrameSourceV0,
    PeerReplayRecoverySourceV0, PeerReplayStateV0, PeerSessionIdentityV0,
};
const BASE_DDL:&str="CREATE TABLE metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL);
CREATE TABLE blocks(id BLOB PRIMARY KEY,parent BLOB,height INTEGER NOT NULL,chainwork BLOB NOT NULL,packet BLOB,state_root BLOB NOT NULL);
CREATE INDEX work_order ON blocks(chainwork DESC,height,id);
CREATE TABLE deltas(block BLOB NOT NULL,key TEXT NOT NULL,before BLOB,after BLOB,PRIMARY KEY(block,key));
CREATE TABLE active(singleton INTEGER PRIMARY KEY CHECK(singleton=1),tip BLOB NOT NULL,generation INTEGER NOT NULL,state_slot INTEGER NOT NULL);
CREATE TABLE kv(slot INTEGER NOT NULL,key TEXT NOT NULL,value BLOB NOT NULL,PRIMARY KEY(slot,key));
CREATE TABLE reorg(singleton INTEGER PRIMARY KEY CHECK(singleton=1),old_tip BLOB NOT NULL,new_tip BLOB NOT NULL,generation INTEGER NOT NULL,cursor INTEGER NOT NULL,done INTEGER NOT NULL);
CREATE TABLE steps(ordinal INTEGER PRIMARY KEY,kind INTEGER NOT NULL,block BLOB NOT NULL);
CREATE TABLE events(generation INTEGER NOT NULL,ordinal INTEGER NOT NULL,kind INTEGER NOT NULL,block BLOB NOT NULL,PRIMARY KEY(generation,ordinal));
CREATE TABLE snapshots(block BLOB PRIMARY KEY,state BLOB NOT NULL);
CREATE TABLE local_pool_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),context BLOB NOT NULL CHECK(length(context)=32),limits BLOB NOT NULL,gc_groups BLOB NOT NULL DEFAULT X'0000000000000000' CHECK(length(gc_groups)=8),gc_records BLOB NOT NULL DEFAULT X'0000000000000000' CHECK(length(gc_records)=8),gc_bytes BLOB NOT NULL DEFAULT X'0000000000000000' CHECK(length(gc_bytes)=8),gc_head BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' CHECK(length(gc_head)=32),checked_parent BLOB,checked_generation INTEGER,CHECK((checked_parent IS NULL AND checked_generation IS NULL) OR (length(checked_parent)=32 AND checked_generation>=0)));
CREATE TABLE local_pool_groups(ordinal INTEGER PRIMARY KEY AUTOINCREMENT,id BLOB UNIQUE NOT NULL CHECK(length(id)=32),status INTEGER NOT NULL CHECK(status IN (0,1,2,3)),reason TEXT NOT NULL);
CREATE TABLE local_pool_rows(group_id BLOB NOT NULL,position INTEGER NOT NULL CHECK(position>=0 AND position<16),digest BLOB UNIQUE NOT NULL CHECK(length(digest)=32),sender BLOB NOT NULL CHECK(length(sender)=32),nonce BLOB NOT NULL CHECK(length(nonce)=8),expiry BLOB NOT NULL CHECK(length(expiry)=8),fee_limit BLOB NOT NULL CHECK(length(fee_limit)=8),raw BLOB NOT NULL CHECK(length(raw)>0 AND length(raw)<=2048),PRIMARY KEY(group_id,position),FOREIGN KEY(group_id) REFERENCES local_pool_groups(id) ON DELETE CASCADE);
CREATE TABLE local_pool_removals(ordinal INTEGER PRIMARY KEY AUTOINCREMENT,id BLOB UNIQUE NOT NULL CHECK(length(id)=32),group_id BLOB NOT NULL CHECK(length(group_id)=32),reason TEXT NOT NULL);
CREATE TABLE peer_replay(session_id BLOB PRIMARY KEY,chain_id BLOB NOT NULL,protocol_digest BLOB NOT NULL,peer_id BLOB NOT NULL,profile_digest BLOB NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),highest_ack INTEGER NOT NULL CHECK(highest_ack>=0),pending_nonce INTEGER,pending_digest BLOB,pending_bytes INTEGER, CHECK((pending_nonce IS NULL AND pending_digest IS NULL AND pending_bytes IS NULL) OR (pending_nonce IS NOT NULL AND pending_nonce>0 AND pending_digest IS NOT NULL AND pending_bytes>0)));
CREATE TABLE peer_request_audit(session_id BLOB NOT NULL,nonce INTEGER NOT NULL CHECK(nonce>0),payload_digest BLOB NOT NULL,payload BLOB,response_digest BLOB,response BLOB,status INTEGER NOT NULL CHECK(status IN (0,1,2)),PRIMARY KEY(session_id,nonce),FOREIGN KEY(session_id) REFERENCES peer_replay(session_id));
CREATE TABLE peer_outbox(session_id BLOB PRIMARY KEY,chain_id BLOB NOT NULL,protocol_digest BLOB NOT NULL,peer_id BLOB NOT NULL,profile_digest BLOB NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),highest_ack INTEGER NOT NULL CHECK(highest_ack>=0),pending_nonce INTEGER,pending_digest BLOB,pending_bytes INTEGER,pending_payload BLOB,pending_wire BLOB,pending_wire_digest BLOB,CHECK((pending_nonce IS NULL AND pending_digest IS NULL AND pending_bytes IS NULL AND pending_payload IS NULL AND pending_wire IS NULL AND pending_wire_digest IS NULL) OR (pending_nonce IS NOT NULL AND pending_nonce>0 AND pending_digest IS NOT NULL AND pending_bytes>0 AND pending_payload IS NOT NULL AND pending_wire IS NOT NULL AND pending_wire_digest IS NOT NULL)));";
fn ddl() -> String {
    format!("{}{}", BASE_DDL, crate::ancestry_index::DDL)
}
fn bytes32(bytes: Vec<u8>) -> Result<Hash> {
    bytes.try_into().map_err(|_| "STORAGE_HASH".into())
}
fn bytes64(bytes: Vec<u8>) -> Result<[u8; 64]> {
    bytes.try_into().map_err(|_| "STORAGE_WORK".into())
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}
pub(crate) type Delta = (String, Option<Vec<u8>>, Option<Vec<u8>>);
type ReorgRow = (Vec<u8>, Vec<u8>, u64, u64, u64);
type Hook<'a> = dyn FnMut(&str) -> Result<()> + 'a;
type ReplayRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    u64,
    u64,
    Option<u64>,
    Option<Vec<u8>>,
    Option<u64>,
);
const AUTH_RESPONSE_RETENTION: u64 = 16;

/// Parent authority for one owner operation only. Never retained by Node or proof
/// search; the successor is separately checked by M06 and consume_output.
pub(crate) enum ParentTaskEligibility {
    Legacy,
    ConsensusMaintenance,
    Signed(Box<QualifiedWorkTask>),
    Lifecycle(Box<qualified_task_lifecycle::EligibleLifecycleTask>),
}
impl ParentTaskEligibility {
    fn manifest(&self) -> Option<&QualifiedWorkTask> {
        match self {
            Self::Legacy | Self::ConsensusMaintenance => None,
            Self::Signed(manifest) => Some(manifest),
            Self::Lifecycle(eligible) => Some(eligible.manifest()),
        }
    }
}

fn json_value(value: String) -> Value {
    Value::String(value)
}
fn record_task_output(
    state: &mut State,
    manifest: &QualifiedWorkTask,
    product: &[u8],
) -> Result<bool> {
    if manifest.purpose == TaskPurpose::Maintenance {
        return Ok(false);
    }
    ensure(product.len() == pon_work::CELLS * 4, "TASK_OUTPUT")?;
    let key = format!("work-output:{}", hex::encode(manifest.output_meter));
    let digest = hex::encode(hash(b"qualified-task-product-v1", &[product]));
    if let Some(prior) = state.get(&key) {
        ensure(
            prior["product"] == digest && prior["arithmetic_output_count"] == 1,
            "TASK_OUTPUT",
        )?;
        Ok(false)
    } else {
        state.insert(key,serde_json::json!({"product":digest,"arithmetic_output_count":1,"matrix_task":hex::encode(manifest.matrix_task),"scope":"source-attested-fixed-contraction-not-model-value"}));
        Ok(true)
    }
}

#[derive(Debug)]
pub(crate) enum AuthenticatedReplayDecision {
    Execute,
    Cached(Vec<u8>),
}

struct ReplayRecovery<'a> {
    db: &'a Connection,
}
impl PeerReplayRecoverySourceV0 for ReplayRecovery<'_> {
    type Error = Error;

    fn verify_recovery(&mut self, state: &PeerReplayStateV0) -> Result<()> {
        let session = state.session().session_id().bytes();
        let completed: u64 = self.db.query_row(
            "SELECT COUNT(*) FROM peer_request_audit WHERE session_id=? AND nonce<=? AND status IN (1,2)",
            params![session.as_slice(), state.highest_acknowledged_nonce()],
            |row| row.get(0),
        )?;
        ensure(
            completed == state.highest_acknowledged_nonce(),
            "AUTH_REPLAY_GAP",
        )?;
        match state.pending() {
            Some(frame) => {
                let row: Option<(Vec<u8>, Option<Vec<u8>>, u64)> = self
                    .db
                    .query_row(
                        "SELECT payload_digest,payload,status FROM peer_request_audit WHERE session_id=? AND nonce=?",
                        params![session.as_slice(), frame.replay_nonce()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                let (digest, payload, status) = row.ok_or("AUTH_PENDING_AUDIT")?;
                ensure(
                    status == 0
                        && bytes32(digest)? == frame.payload_digest().bytes()
                        && payload.as_ref().is_some_and(|v| {
                            v.len() == frame.payload_bytes()
                                && crate::authenticated_payload_digest(v)
                                    == frame.payload_digest().bytes()
                        }),
                    "AUTH_PENDING_AUDIT",
                )?;
            }
            None => {
                let pending: u64 = self.db.query_row(
                    "SELECT COUNT(*) FROM peer_request_audit WHERE session_id=? AND status=0",
                    [session.as_slice()],
                    |row| row.get(0),
                )?;
                ensure(pending == 0, "AUTH_PENDING_AUDIT")?;
            }
        }
        let future: u64 = self.db.query_row(
            "SELECT COUNT(*) FROM peer_request_audit WHERE session_id=? AND nonce>?",
            params![
                session.as_slice(),
                state
                    .pending()
                    .map_or(state.highest_acknowledged_nonce(), |v| v.replay_nonce())
            ],
            |row| row.get(0),
        )?;
        ensure(future == 0, "AUTH_REPLAY_FUTURE")
    }
}

struct ExactFrameSource<'a> {
    payload: &'a [u8],
}
impl PeerFrameSourceV0 for ExactFrameSource<'_> {
    type Error = Error;

    fn verify_frame(
        &mut self,
        _state: PeerReplayStateV0,
        frame: &AuthenticatedPeerFrameV0,
    ) -> Result<()> {
        ensure(
            frame.payload_bytes() == self.payload.len()
                && frame.payload_digest().bytes()
                    == crate::authenticated_payload_digest(self.payload),
            "AUTH_PAYLOAD",
        )
    }
}

struct OutboxRecovery<'a> {
    db: &'a Connection,
}
impl PeerReplayRecoverySourceV0 for OutboxRecovery<'_> {
    type Error = Error;

    fn verify_recovery(&mut self, state: &PeerReplayStateV0) -> Result<()> {
        let session = state.session().session_id().bytes();
        match state.pending() {
            Some(frame) => {
                let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = self
                    .db
                    .query_row(
                        "SELECT pending_payload,pending_wire,pending_wire_digest FROM peer_outbox WHERE session_id=?",
                        [session.as_slice()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                let (payload, wire, wire_digest) = row.ok_or("AUTH_OUTBOX_PENDING")?;
                ensure(
                    payload.len() == frame.payload_bytes()
                        && crate::authenticated_payload_digest(&payload)
                            == frame.payload_digest().bytes()
                        && !wire.is_empty()
                        && wire.len() <= 2 * 1024 * 1024
                        && bytes32(wire_digest)? == hash(b"native-authenticated-wire-v1", &[&wire]),
                    "AUTH_OUTBOX_PENDING",
                )
            }
            None => Ok(()),
        }
    }
}

fn cut(hook: &mut Option<&mut Hook<'_>>, name: &str) -> Result<()> {
    if let Some(h) = hook.as_mut() {
        h(name)?;
    }
    Ok(())
}
fn schema(db: &Connection) -> Result<BTreeMap<String, String>> {
    let mut stmt =
        db.prepare("SELECT type||':'||name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")?;
    let pairs = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = BTreeMap::new();
    for pair in pairs {
        let (key, text) = pair?;
        out.insert(key, text.split_whitespace().collect::<Vec<_>>().join(" "));
    }
    Ok(out)
}
fn plain(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) => ensure(
            m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1,
            "NAMESPACE",
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
#[derive(Clone)]
struct Record {
    parent: Option<Hash>,
    height: u64,
    work: Work,
    root: Hash,
}
struct StoredHeaderLink {
    header: Header,
    record: Record,
    parent_work: Work,
}
struct HeaderProjection {
    parent: Option<Vec<u8>>,
    height: u64,
    work: Vec<u8>,
    root: Vec<u8>,
    prefix: Option<Vec<u8>>,
    trace: Option<Vec<u8>>,
    length: Option<usize>,
    parent_height: Option<u64>,
    parent_work: Option<Vec<u8>>,
    parent_parent: Option<Vec<u8>>,
    parent_root: Option<Vec<u8>>,
}
impl HeaderProjection {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            parent: row.get(0)?,
            height: row.get(1)?,
            work: row.get(2)?,
            root: row.get(3)?,
            prefix: row.get(4)?,
            trace: row.get(5)?,
            length: row.get(6)?,
            parent_height: row.get(7)?,
            parent_work: row.get(8)?,
            parent_parent: row.get(9)?,
            parent_root: row.get(10)?,
        })
    }
}
const HISTORY_HEADER_BATCH: u64 = 64;

/// Local SQL projection counters, not a work, state or confirmation certificate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistoryReadCounters {
    pub header_link_queries: u64,
    /// Header and trace bytes returned to Rust; excludes SQLite page reads.
    pub header_trace_bytes: u64,
}
/// Owns the exact packet whose work was actually verified. Not state or clock authority.
/// Private fields prevent replacing the header/body/proof after verification.
pub(crate) struct WorkCheckedPacket {
    packet: Packet,
    work: pon_work::VerifiedWork,
    owner_permit: Option<OwnerPacketPermit>,
}
impl WorkCheckedPacket {
    pub(crate) fn verify(packet: Packet) -> Result<Self> {
        let h = &packet.header;
        let work = pon_work::verify(h.challenge(), h.work_task, h.target, &packet.proof)
            .map_err(|e| Error::from(format!("WORK:{e:?}")))?;
        Ok(Self {
            packet,
            work,
            owner_permit: None,
        })
    }
    pub(crate) fn verify_with_progress(
        packet: Packet,
        progress: &mut impl FnMut(pon_work::VerificationProgress) -> Result<()>,
    ) -> Result<Self> {
        let h = &packet.header;
        let work = pon_work::verify_with_progress(
            h.challenge(),
            h.work_task,
            h.target,
            &packet.proof,
            progress,
        )
        .map_err(|error| match error {
            pon_work::VerificationError::Relation(error) => Error::from(format!("WORK:{error:?}")),
            pon_work::VerificationError::Cancelled(error) => error,
        })?;
        Ok(Self {
            packet,
            work,
            owner_permit: None,
        })
    }
}

fn local_execution_error(error: ExecutionError<Error>) -> Error {
    match error {
        ExecutionError::Relation(error) => error.into(),
        ExecutionError::Cancelled(error) => error,
    }
}

/// Cancellation stages for the complete checked native account proof query.
/// Individual State commitment/hash primitives remain bounded single stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAccountProofProgress {
    BeforeRead,
    StateReplay,
    StateVerification,
    Proof(crate::account_archive_prototype::multiproof::MultiproofProgress),
    BeforeOutput,
}

enum NativeAccountProofFailure {
    Archive(crate::account_archive_prototype::ArchiveError),
    Control(Error),
}
impl From<crate::account_archive_prototype::ArchiveError> for NativeAccountProofFailure {
    fn from(error: crate::account_archive_prototype::ArchiveError) -> Self {
        Self::Archive(error)
    }
}
impl NativeAccountProofFailure {
    fn into_error(self) -> Error {
        use crate::account_archive_prototype::ArchiveError;
        match self {
            Self::Control(error) => error,
            Self::Archive(error) => {
                let is_local = matches!(
                    error,
                    ArchiveError::DataUnavailable
                        | ArchiveError::CorruptRecord
                        | ArchiveError::Storage(_)
                );
                let error = Error::from(format!("NATIVE_ACCOUNT_PROOF:{error:?}"));
                if is_local {
                    error.local_integrity()
                } else {
                    error
                }
            }
        }
    }
}

/// One private native namespace; no reference subprocess or remote state setter exists.
pub struct Node {
    db: Connection,
    owner: File,
    directory: PathBuf,
    directory_id: (u64, u64),
    database_id: (u64, u64),
    settings: Settings,
    workers: usize,
    state_backend: StateBackend,
    // One derived snapshot only; State always comes from actual KV/snapshot/deltas.
    commitment_cache: RefCell<Option<ActiveCommitment>>,
    commitment_observation: RefCell<Option<CommitmentObservation>>,
    history_read_counters: Cell<HistoryReadCounters>,
    history_page_read_counters: Cell<HistoryPageReadCounters>,
    owner_policy: Option<OwnerPolicy>,
    mining_owner: Option<operator_mining_owner::MiningOwner>,
    continuous_owner: Option<operator_continuous_owner::ContinuousOwner>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StateBackend {
    Legacy,
    AuthenticatedV1,
}
impl StateBackend {
    fn ddl(self) -> String {
        match self {
            Self::Legacy => ddl(),
            Self::AuthenticatedV1 => format!("{}{}", ddl(), native_authenticated::DDL),
        }
    }
    fn schema_id(self) -> Hash {
        let domain: &[u8] = match self {
            Self::Legacy => b"native-branch-schema-v2",
            Self::AuthenticatedV1 => b"native-authenticated-branch-schema-v1",
        };
        hash(domain, &[self.ddl().as_bytes()])
    }
}
struct NativeOwners {
    policy: Option<OwnerPolicy>,
    mining: Option<operator_mining_owner::MiningOwner>,
    continuous: Option<operator_continuous_owner::ContinuousOwner>,
}
struct OwnerPolicy {
    pool_policies: Vec<std::sync::Arc<crate::operator_task_policy::pool::VerifiedPoolPolicy>>,
    epoch: std::sync::Arc<std::sync::atomic::AtomicU64>,
    outside_keys: (String, String),
    policy: std::sync::Arc<crate::operator_task_policy::VerifiedPolicy>,
    required_marker: Vec<u8>,
    journal: RefCell<crate::operator_task_policy::Journal>,
    unavailable: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
pub(crate) struct OwnerPacketPermit {
    epoch: std::sync::Arc<std::sync::atomic::AtomicU64>,
    expected_epoch: u64,
    policy: std::sync::Arc<crate::operator_task_policy::VerifiedPolicy>,
    unavailable: std::sync::Arc<std::sync::atomic::AtomicBool>,
    facts: crate::operator_task_policy::NativeFacts,
    reservation: crate::operator_task_policy::Reservation,
}
pub(crate) struct OwnerPoolPermit {
    facts: crate::operator_task_policy::pool::PoolFacts,
    authentication: OwnerPoolAuthentication,
}
enum OwnerPoolAuthentication {
    Legacy {
        policy: std::sync::Arc<crate::operator_task_policy::pool::VerifiedPoolPolicy>,
        unavailable: std::sync::Arc<std::sync::atomic::AtomicBool>,
        epoch: std::sync::Arc<std::sync::atomic::AtomicU64>,
        expected_epoch: u64,
        reservation: crate::operator_task_policy::pool::PoolReservation,
    },
    Continuous(operator_continuous_owner::ContinuousPoolCheckpoint),
}
impl OwnerPoolPermit {
    fn progress(&self) -> Result<()> {
        match &self.authentication {
            OwnerPoolAuthentication::Legacy {
                policy,
                unavailable,
                epoch,
                expected_epoch,
                ..
            } => {
                ensure(
                    !unavailable.load(std::sync::atomic::Ordering::Acquire),
                    "OWNER_TASK_UNAVAILABLE",
                )?;
                ensure(
                    epoch.load(std::sync::atomic::Ordering::Acquire) == *expected_epoch,
                    "OWNER_TASK_VIEW_CHANGED",
                )?;
                policy
                    .check(
                        &self.facts,
                        crate::operator_task_policy::now_ns().map_err(owner_error)?,
                    )
                    .map_err(owner_error)
            }
            OwnerPoolAuthentication::Continuous(checkpoint) => checkpoint.check(),
        }
    }
    fn check_prefix(&self, raws: &[Vec<u8>]) -> Result<()> {
        self.progress()?;
        match &self.authentication {
            OwnerPoolAuthentication::Legacy { policy, .. } => {
                policy.check_prefix_commands(raws).map_err(owner_error)
            }
            OwnerPoolAuthentication::Continuous(checkpoint) => checkpoint.check_prefix(raws),
        }
    }
}
fn owner_marker_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path.join("owner-task-policy.required")) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn authenticated_migration_pending(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path.join("authenticated-migration.pending")) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn owner_error(error: crate::operator_task_policy::PolicyError) -> Error {
    Error::from(format!("OWNER_TASK_POLICY:{error:?}"))
}
impl OwnerPacketPermit {
    fn progress(&self) -> Result<()> {
        ensure(
            self.epoch.load(std::sync::atomic::Ordering::Acquire) == self.expected_epoch,
            "OWNER_TASK_VIEW_CHANGED",
        )?;
        ensure(
            !self.unavailable.load(std::sync::atomic::Ordering::Acquire),
            "OWNER_TASK_UNAVAILABLE",
        )?;
        self.policy
            .check(
                &self.facts,
                crate::operator_task_policy::now_ns().map_err(owner_error)?,
            )
            .map_err(owner_error)
    }
}
struct ActiveCommitment {
    tip: Hash,
    generation: u64,
    slot: u64,
    snapshot: CheckedCommitment,
}
#[derive(Clone, Debug)]
pub struct DerivedCommitmentStatus {
    pub cache_root: Option<Hash>,
    pub cache_keys: usize,
    /// Conservative software charge, not process RSS.
    pub software_charge_bytes: usize,
    pub last: Option<CommitmentObservation>,
}
#[derive(Debug, Serialize)]
pub struct Observation {
    pub transaction: String,
    pub genesis: String,
    pub policy: String,
    pub required_work_delta: String,
    pub network: String,
    pub parameters: String,
    pub included_block: String,
    pub observed_tip: String,
    pub included_height: u64,
    pub observed_height: u64,
    pub depth: Option<u64>,
    pub work_delta: Option<String>,
    pub active_generation: u64,
    pub observed_now: u64,
    pub confirmed: bool,
    pub reorged: bool,
    pub finalized: bool,
    pub execution_authority: bool,
}
/// Bounded results under one locally reobserved generation, not a finality certificate.
#[derive(Debug, Serialize)]
pub struct ConfirmationBatch {
    pub observations: Vec<Observation>,
    pub ancestry_checked: u64,
    pub distinct_bodies_checked: usize,
}
impl Node {
    pub fn open(path: &Path, settings: Settings, workers: usize) -> Result<Self> {
        Self::open_with_fault(path, settings, workers, None)
    }
    pub fn open_with_fault(
        path: &Path,
        settings: Settings,
        workers: usize,
        hook: Option<&mut Hook<'_>>,
    ) -> Result<Self> {
        // The legacy opener is never a fallback for a required-policy namespace.
        ensure(!owner_marker_present(path)?, "OWNER_TASK_POLICY_REQUIRED")?;
        Self::open_inner(path, settings, workers, hook, None, None, None)
    }
    /// Explicit fresh storage namespace. Consensus profiles and header root bytes
    /// are unchanged; complete native state and authenticated account nodes are
    /// now mandatory components of the same persistent Node transaction.
    pub fn open_with_authenticated_state(
        path: &Path,
        settings: Settings,
        workers: usize,
    ) -> Result<Self> {
        Self::open_with_authenticated_state_and_fault(path, settings, workers, None)
    }
    pub fn open_with_authenticated_state_and_fault(
        path: &Path,
        settings: Settings,
        workers: usize,
        hook: Option<&mut Hook<'_>>,
    ) -> Result<Self> {
        ensure(!owner_marker_present(path)?, "OWNER_TASK_POLICY_REQUIRED")?;
        Self::open_selected(
            path,
            settings,
            workers,
            hook,
            NativeOwners {
                policy: None,
                mining: None,
                continuous: None,
            },
            StateBackend::AuthenticatedV1,
        )
    }
    /// Explicit local operator policy; neither permissionless nor consensus authority.
    /// Inputs must be supplied from protected operator configuration, not a Request.
    pub fn open_with_operator_task_policy(
        path: &Path,
        settings: Settings,
        workers: usize,
        inputs: crate::operator_task_policy::RestrictedNodeInputs,
    ) -> Result<Self> {
        let policy = crate::operator_task_policy::authenticate(
            &inputs.raw_policy,
            &inputs.authority,
            crate::operator_task_policy::now_ns().map_err(owner_error)?,
        )
        .map_err(owner_error)?;
        ensure(
            policy.context().network == hex::encode(settings.network())
                && policy.context().parameters == hex::encode(settings.parameters()),
            "OWNER_TASK_CONTEXT",
        )?;
        ensure(
            inputs.pool_permissions.len() <= 64,
            "OWNER_POOL_PERMISSION_LIMIT",
        )?;
        let mut pool_policies = Vec::new();
        for permission in &inputs.pool_permissions {
            let verified = crate::operator_task_policy::pool::authenticate_pool(
                permission,
                &inputs.authority,
                &policy,
                crate::operator_task_policy::now_ns().map_err(owner_error)?,
            )
            .map_err(owner_error)?;
            ensure(
                !pool_policies.iter().any(
                    |p: &std::sync::Arc<crate::operator_task_policy::pool::VerifiedPoolPolicy>| {
                        p.same_operation(&verified)
                    },
                ),
                "OWNER_POOL_DUPLICATE_PERMISSION",
            )?;
            pool_policies.push(std::sync::Arc::new(verified));
        }
        crate::operator_task_policy::verify_catalog(&inputs, &policy).map_err(owner_error)?;
        let expected_marker = policy.marker(&inputs.journal_path).map_err(owner_error)?;
        let journal = crate::operator_task_policy::Journal::open(
            &inputs.journal_path,
            inputs.expected_uid,
            &policy,
        )
        .map_err(owner_error)?;
        if !path.try_exists()? {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let meta = fs::symlink_metadata(path)?;
        ensure(
            meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.uid() == inputs.expected_uid
                && meta.mode() & 0o7777 == 0o700,
            "OWNER_TASK_NAMESPACE",
        )?;
        let marker = path.join("owner-task-policy.required");
        if marker.try_exists()? {
            plain(&marker)?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&marker)?;
            let m = file.metadata()?;
            ensure(
                m.is_file()
                    && m.nlink() == 1
                    && m.uid() == inputs.expected_uid
                    && m.mode() & 0o7777 == 0o600
                    && m.len() == expected_marker.len() as u64,
                "OWNER_TASK_NAMESPACE",
            )?;
            let mut bytes = Vec::new();
            std::io::Read::take(file, expected_marker.len() as u64 + 1).read_to_end(&mut bytes)?;
            ensure(bytes == expected_marker, "OWNER_TASK_NAMESPACE")?;
        } else {
            // No silent migration of an already unrestricted or partially initialized store.
            ensure(
                fs::read_dir(path)?.next().is_none(),
                "OWNER_TASK_FRESH_NAMESPACE_REQUIRED",
            )?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&marker)?;
            file.write_all(&expected_marker)?;
            file.sync_all()?;
            sync_dir(path)?;
        }
        let owner = OwnerPolicy {
            pool_policies,
            epoch: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
            outside_keys: (
                inputs.authority.registry_key.clone(),
                inputs.authority.task_key.clone(),
            ),
            policy: std::sync::Arc::new(policy),
            required_marker: expected_marker,
            journal: RefCell::new(journal),
            unavailable: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        Self::open_inner(path, settings, workers, None, Some(owner), None, None)
    }
    fn open_inner(
        path: &Path,
        settings: Settings,
        workers: usize,
        hook: Option<&mut Hook<'_>>,
        owner_policy: Option<OwnerPolicy>,
        mining_owner: Option<operator_mining_owner::MiningOwner>,
        continuous_owner: Option<operator_continuous_owner::ContinuousOwner>,
    ) -> Result<Self> {
        Self::open_selected(
            path,
            settings,
            workers,
            hook,
            NativeOwners {
                policy: owner_policy,
                mining: mining_owner,
                continuous: continuous_owner,
            },
            StateBackend::Legacy,
        )
    }
    fn open_selected(
        path: &Path,
        settings: Settings,
        workers: usize,
        mut hook: Option<&mut Hook<'_>>,
        owners: NativeOwners,
        state_backend: StateBackend,
    ) -> Result<Self> {
        ensure(
            !authenticated_migration_pending(path)?,
            "NATIVE_STATE_MIGRATION_PENDING",
        )?;
        let NativeOwners {
            policy: owner_policy,
            mining: mining_owner,
            continuous: continuous_owner,
        } = owners;
        ensure(
            usize::from(owner_policy.is_some())
                + usize::from(mining_owner.is_some())
                + usize::from(continuous_owner.is_some())
                <= 1,
            "OWNER_MODE_AMBIGUOUS",
        )?;
        let required_owner_marker = owner_policy
            .as_ref()
            .map(|p| p.required_marker.as_slice())
            .or_else(|| mining_owner.as_ref().map(|p| p.marker.as_slice()))
            .or_else(|| continuous_owner.as_ref().map(|p| p.marker.as_slice()));
        ensure([1, 2, 4, 8].contains(&workers), "WORKERS")?;
        settings.replay_checkpoint_tile_material()?;
        if !path.exists() {
            fs::create_dir_all(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let metadata = fs::symlink_metadata(path)?;
        ensure(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "NAMESPACE",
        )?;
        let directory = path.canonicalize()?;
        let dbpath = directory.join("native.sqlite");
        let marker = directory.join("initializing.json");
        let lock = directory.join("owner.lock");
        for p in [
            &dbpath,
            &marker,
            &lock,
            &directory.join("native.sqlite-wal"),
            &directory.join("native.sqlite-shm"),
        ] {
            plain(p)?;
        }
        let owner = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock)?;
        owner
            .try_lock_exclusive()
            .map_err(|_| Error::from("WRITER_BUSY"))?;
        let ddl = state_backend.ddl();
        let schema_id = state_backend.schema_id();
        let expected = canonical(
            &serde_json::json!({"schema":hex::encode(schema_id),"parameters":hex::encode(settings.parameters()),"genesis":hex::encode(settings.genesis())}),
        )?;
        if !dbpath.exists() && !marker.exists() {
            for entry in fs::read_dir(&directory)? {
                let name = entry?.file_name();
                ensure(
                    name == "owner.lock"
                        || (required_owner_marker.is_some()
                            && name == "owner-task-policy.required"),
                    "NAMESPACE_NOT_EMPTY",
                )?;
            }
            let mut intent = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&marker)?;
            intent.write_all(&expected)?;
            intent.sync_all()?;
            sync_dir(&directory)?;
            cut(&mut hook, "init-intent")?;
        }
        let intent = marker.exists();
        if intent {
            ensure(fs::read(&marker)? == expected, "INITIALIZATION_CONTEXT")?;
        }
        let expected_db = Connection::open_in_memory()?;
        expected_db.execute_batch(&ddl)?;
        let expected_schema = schema(&expected_db)?;
        let mut initialized = false;
        let mut prior_inode = None;
        if dbpath.exists() {
            let m = fs::metadata(&dbpath)?;
            prior_inode = Some((m.dev(), m.ino()));
            let probe = Connection::open_with_flags(
                &dbpath,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            let current = schema(&probe)?;
            if current.is_empty() {
                ensure(intent, "INITIALIZATION_INTENT_REQUIRED")?;
            } else {
                ensure(current == expected_schema, "SCHEMA")?;
                let required: Option<Vec<u8>> = probe
                    .query_row(
                        "SELECT value FROM metadata WHERE key='operator_task_policy'",
                        [],
                        |r| r.get(0),
                    )
                    .optional()?;
                ensure(
                    required.as_deref() == required_owner_marker,
                    "OWNER_TASK_POLICY_REQUIRED",
                )?;
                for (key, value) in [
                    ("schema", schema_id),
                    ("parameters", settings.parameters()),
                    ("genesis", settings.genesis()),
                ] {
                    let recorded: Option<Vec<u8>> = probe
                        .query_row("SELECT value FROM metadata WHERE key=?", [key], |r| {
                            r.get(0)
                        })
                        .optional()?;
                    ensure(
                        recorded.as_deref() == Some(value.as_slice()),
                        "STORAGE_CONTEXT",
                    )?;
                }
                initialized = true;
            }
        }
        for p in [
            &dbpath,
            &directory.join("native.sqlite-wal"),
            &directory.join("native.sqlite-shm"),
        ] {
            plain(p)?;
        }
        let mut db = Connection::open(&dbpath)?;
        let dm = fs::metadata(&dbpath)?;
        if let Some(previous) = prior_inode {
            ensure(previous == (dm.dev(), dm.ino()), "NAMESPACE_CHANGED")?;
        }
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        if !initialized {
            ensure(intent, "INITIALIZATION_INTENT_REQUIRED")?;
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch(&ddl)?;
            cut(&mut hook, "init-schema")?;
            for (key, value) in [
                ("schema", schema_id),
                ("parameters", settings.parameters()),
                ("genesis", settings.genesis()),
            ] {
                tx.execute(
                    "INSERT INTO metadata VALUES(?,?)",
                    params![key, value.as_slice()],
                )?;
            }
            if let Some(marker) = required_owner_marker {
                tx.execute(
                    "INSERT INTO metadata VALUES('operator_task_policy',?)",
                    [marker],
                )?;
            }
            tx.execute(
                "INSERT INTO blocks VALUES(?,NULL,0,?,NULL,?)",
                params![
                    settings.genesis.as_slice(),
                    [0u8; 64].as_slice(),
                    root(&settings.initial)?.as_slice()
                ],
            )?;
            tx.execute(
                "INSERT INTO active VALUES(1,?,0,0)",
                [settings.genesis.as_slice()],
            )?;
            for (key, value) in &settings.initial {
                tx.execute(
                    "INSERT INTO kv VALUES(0,?,?)",
                    params![key, canonical(value)?],
                )?;
            }
            tx.execute(
                "INSERT INTO snapshots VALUES(?,?)",
                params![settings.genesis.as_slice(), canonical(&settings.initial)?],
            )?;
            if state_backend == StateBackend::AuthenticatedV1 {
                native_authenticated::seed(&tx, &settings)?;
            }
            cut(&mut hook, "init-before-commit")?;
            tx.commit()?;
            cut(&mut hook, "init-committed")?;
        }
        if intent {
            fs::remove_file(marker)?;
            sync_dir(&directory)?;
        }
        let mut node = Self {
            db,
            owner,
            directory,
            directory_id: (metadata.dev(), metadata.ino()),
            database_id: (dm.dev(), dm.ino()),
            settings,
            workers,
            state_backend,
            commitment_cache: RefCell::new(None),
            commitment_observation: RefCell::new(None),
            history_read_counters: Cell::new(HistoryReadCounters::default()),
            history_page_read_counters: Cell::new(HistoryPageReadCounters::default()),
            owner_policy,
            mining_owner,
            continuous_owner,
        };
        node.read_active()?;
        if node.state_backend == StateBackend::AuthenticatedV1 {
            native_authenticated::verify_history(
                &node.db,
                &node.settings,
                node.active()?.0,
                &mut || Ok(()),
            )?;
        }
        node.validate_authenticated_replay()?;
        node.validate_authenticated_outbox()?;
        node.recover()?;
        node.read_active()?;
        crate::ancestry_index::validate_tip(&node.db, node.ancestry_context(), node.active()?.0)?;
        Ok(node)
    }
    fn ancestry_context(&self) -> crate::ancestry_index::Context {
        crate::ancestry_index::Context {
            network: self.settings.network(),
            parameters: self.settings.parameters(),
            genesis: self.settings.genesis(),
        }
    }
    pub fn settings(&self) -> &Settings {
        &self.settings
    }
    /// Export a compact point proof from the actual integrated native tree in
    /// one SQLite read snapshot. Supplied reports cannot choose its root or
    /// account bytes. The complete State is still checked before this query.
    pub fn authenticated_account_multiproof(
        &self,
        block: Hash,
        owners: &[Hash],
    ) -> Result<(
        crate::account_archive_prototype::Checkpoint,
        crate::account_archive_prototype::multiproof::Multiproof,
        crate::account_archive_prototype::multiproof::ConstructionObservation,
    )> {
        self.authenticated_account_multiproof_with_progress(block, owners, &|_| Ok(()))
    }
    /// Reject oversized/duplicate requests before storage access, then retain a
    /// single read transaction through full-State replay and proof construction.
    /// Cancellation returns the caller's original error and releases the snapshot.
    pub fn authenticated_account_multiproof_with_progress(
        &self,
        block: Hash,
        owners: &[Hash],
        progress: &(impl Fn(NativeAccountProofProgress) -> Result<()> + ?Sized),
    ) -> Result<(
        crate::account_archive_prototype::Checkpoint,
        crate::account_archive_prototype::multiproof::Multiproof,
        crate::account_archive_prototype::multiproof::ConstructionObservation,
    )> {
        use crate::account_archive_prototype::{multiproof, ArchiveError};
        ensure(
            self.state_backend == StateBackend::AuthenticatedV1,
            "NATIVE_STATE_BACKEND_REQUIRED",
        )?;
        if owners.len() > multiproof::MAX_ACCOUNTS {
            return Err(NativeAccountProofFailure::Archive(ArchiveError::Budget).into_error());
        }
        if owners
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != owners.len()
        {
            return Err(
                NativeAccountProofFailure::Archive(ArchiveError::InvalidWitness).into_error(),
            );
        }
        progress(NativeAccountProofProgress::BeforeRead)?;
        self.namespace()?;
        let tx = self.db.unchecked_transaction()?;
        self.storage_context()?;
        let state = self.state_at_with_progress(block, &mut || {
            progress(NativeAccountProofProgress::StateReplay)
        })?;
        native_authenticated::verify_state(&tx, &self.settings, block, &state, &mut || {
            progress(NativeAccountProofProgress::StateVerification)
        })?;
        let record = native_authenticated::load(&tx, block)?;
        let context = crate::account_archive_prototype::Context {
            network: self.settings.network(),
            parameters: self.settings.parameters(),
            genesis: self.settings.genesis(),
        };
        let checkpoint = crate::account_archive_prototype::native_store::query_checkpoint(
            &tx,
            context,
            block,
            record.height,
            record.state.state_root,
            &record.accounts,
        )?;
        let (proof, observation) =
            multiproof::from_native_database(&tx, &checkpoint, owners, &|point| {
                progress(NativeAccountProofProgress::Proof(point))
                    .map_err(NativeAccountProofFailure::Control)
            })
            .map_err(NativeAccountProofFailure::into_error)?;
        progress(NativeAccountProofProgress::BeforeOutput)?;
        tx.commit()?;
        Ok((checkpoint, proof, observation))
    }
    fn decode_replay_row(row: ReplayRow) -> Result<PeerReplayStateV0> {
        let chain = IoDigest32V0::new(bytes32(row.0)?)
            .map_err(|e| Error::local_replay_source("AUTH_REPLAY", e))?;
        let protocol = IoDigest32V0::new(bytes32(row.1)?)
            .map_err(|e| Error::local_replay_source("AUTH_REPLAY", e))?;
        let peer = IoDigest32V0::new(bytes32(row.2)?)
            .map_err(|e| Error::local_replay_source("AUTH_REPLAY", e))?;
        let session_id = IoDigest32V0::new(bytes32(row.3)?)
            .map_err(|e| Error::local_replay_source("AUTH_REPLAY", e))?;
        let profile = IoDigest32V0::new(bytes32(row.4)?)
            .map_err(|e| Error::local_replay_source("AUTH_REPLAY", e))?;
        let session = PeerSessionIdentityV0::new(chain, protocol, peer, session_id, profile, row.5)
            .map_err(|e| Error::local_replay_source("AUTH_REPLAY", e))?;
        let pending = match (row.7, row.8, row.9) {
            (None, None, None) => None,
            (Some(nonce), Some(digest), Some(bytes)) => Some(
                AuthenticatedPeerFrameV0::new(
                    session,
                    nonce,
                    IoDigest32V0::new(bytes32(digest)?)
                        .map_err(|e| Error::local_replay_source("AUTH_REPLAY", e))?,
                    usize::try_from(bytes)
                        .map_err(|_| Error::from("AUTH_REPLAY_SIZE").local_integrity())?,
                )
                .map_err(|e| Error::local_replay_source("AUTH_REPLAY", e))?,
            ),
            _ => return Err(Error::from("AUTH_PENDING_AUDIT").local_integrity()),
        };
        PeerReplayStateV0::new(session, row.6, pending)
            .map_err(|e| Error::local_replay_source("AUTH_REPLAY", e))
    }

    fn authenticated_replay_state(
        &self,
        session: PeerSessionIdentityV0,
    ) -> Result<Option<PeerReplayStateV0>> {
        let id = session.session_id().bytes();
        let row = self
            .db
            .query_row(
                "SELECT chain_id,protocol_digest,peer_id,session_id,profile_digest,generation,highest_ack,pending_nonce,pending_digest,pending_bytes FROM peer_replay WHERE session_id=?",
                [id.as_slice()],
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
                        row.get(9)?,
                    ))
                },
            )
            .optional()?;
        row.map(Self::decode_replay_row)
            .transpose()
            .and_then(|state| {
                if state.as_ref().is_some_and(|v| v.session() != session) {
                    Err("AUTH_SESSION_COLLISION".into())
                } else {
                    Ok(state)
                }
            })
    }

    fn validate_authenticated_replay(&self) -> Result<()> {
        let mut stmt = self.db.prepare(
            "SELECT chain_id,protocol_digest,peer_id,session_id,profile_digest,generation,highest_ack,pending_nonce,pending_digest,pending_bytes FROM peer_replay ORDER BY session_id",
        )?;
        let rows = stmt
            .query_map([], |row| {
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
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        for row in rows {
            let state = Self::decode_replay_row(row)?;
            ensure(
                state.session().chain_id().bytes() == self.settings.genesis()
                    && state.session().protocol_digest().bytes() == self.settings.parameters()
                    && state.session().profile_digest().bytes()
                        == crate::authenticated_profile_digest(),
                "AUTH_REPLAY_CONTEXT",
            )
            .map_err(Error::local_integrity)?;
            CandidateP2pAdmissionV0::recover_verified(state, &mut ReplayRecovery { db: &self.db })
                .map_err(|e| Error::local_replay_source("AUTH_RECOVERY", e))?;
        }
        Ok(())
    }

    fn authenticated_outbox_state(
        &self,
        session: PeerSessionIdentityV0,
    ) -> Result<Option<PeerReplayStateV0>> {
        let id = session.session_id().bytes();
        let row = self
            .db
            .query_row(
                "SELECT chain_id,protocol_digest,peer_id,session_id,profile_digest,generation,highest_ack,pending_nonce,pending_digest,pending_bytes FROM peer_outbox WHERE session_id=?",
                [id.as_slice()],
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
                        row.get(9)?,
                    ))
                },
            )
            .optional()?;
        row.map(Self::decode_replay_row)
            .transpose()
            .and_then(|state| {
                if state
                    .as_ref()
                    .is_some_and(|value| value.session() != session)
                {
                    Err("AUTH_OUTBOX_SESSION_COLLISION".into())
                } else {
                    Ok(state)
                }
            })
    }

    fn validate_authenticated_outbox(&self) -> Result<()> {
        let mut stmt = self.db.prepare(
            "SELECT chain_id,protocol_digest,peer_id,session_id,profile_digest,generation,highest_ack,pending_nonce,pending_digest,pending_bytes FROM peer_outbox ORDER BY session_id",
        )?;
        let rows = stmt
            .query_map([], |row| {
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
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        for row in rows {
            let state = Self::decode_replay_row(row)?;
            ensure(
                state.session().chain_id().bytes() == self.settings.genesis()
                    && state.session().protocol_digest().bytes() == self.settings.parameters()
                    && state.session().profile_digest().bytes()
                        == crate::authenticated_profile_digest(),
                "AUTH_OUTBOX_CONTEXT",
            )
            .map_err(Error::local_integrity)?;
            CandidateP2pAdmissionV0::recover_verified(state, &mut OutboxRecovery { db: &self.db })
                .map_err(|error| Error::local_replay_source("AUTH_OUTBOX_RECOVERY", error))?;
        }
        Ok(())
    }

    pub(crate) fn authenticated_outbound_reservation(
        &self,
        session: PeerSessionIdentityV0,
    ) -> Result<(u64, Option<Vec<u8>>)> {
        ensure(
            session.chain_id().bytes() == self.settings.genesis()
                && session.protocol_digest().bytes() == self.settings.parameters()
                && session.profile_digest().bytes() == crate::authenticated_profile_digest(),
            "AUTH_OUTBOX_CONTEXT",
        )?;
        let state = self.authenticated_outbox_state(session)?.unwrap_or(
            PeerReplayStateV0::new(session, 0, None)
                .map_err(|error| Error::peer_admission_source("AUTH_OUTBOX", error))?,
        );
        CandidateP2pAdmissionV0::recover_verified(state, &mut OutboxRecovery { db: &self.db })
            .map_err(|error| Error::local_replay_source("AUTH_OUTBOX_RECOVERY", error))?;
        if let Some(frame) = state.pending() {
            let wire: Vec<u8> = self.db.query_row(
                "SELECT pending_wire FROM peer_outbox WHERE session_id=?",
                [session.session_id().bytes().as_slice()],
                |row| row.get(0),
            )?;
            return Ok((frame.replay_nonce(), Some(wire)));
        }
        Ok((
            state
                .highest_acknowledged_nonce()
                .checked_add(1)
                .ok_or("AUTH_OUTBOX_OVERFLOW")?,
            None,
        ))
    }

    pub(crate) fn reserve_authenticated_outbound(
        &mut self,
        frame: AuthenticatedPeerFrameV0,
        payload: &[u8],
        wire: &[u8],
    ) -> Result<Vec<u8>> {
        self.ready()?;
        self.namespace()?;
        ensure(
            !wire.is_empty() && wire.len() <= 2 * 1024 * 1024,
            "AUTH_OUTBOX_WIRE",
        )?;
        let session = frame.session();
        ensure(
            session.chain_id().bytes() == self.settings.genesis()
                && session.protocol_digest().bytes() == self.settings.parameters()
                && session.profile_digest().bytes() == crate::authenticated_profile_digest(),
            "AUTH_OUTBOX_CONTEXT",
        )?;
        let state = self.authenticated_outbox_state(session)?.unwrap_or(
            PeerReplayStateV0::new(session, 0, None)
                .map_err(|error| Error::peer_admission_source("AUTH_OUTBOX", error))?,
        );
        let mut admission =
            CandidateP2pAdmissionV0::recover_verified(state, &mut OutboxRecovery { db: &self.db })
                .map_err(|error| Error::local_replay_source("AUTH_OUTBOX_RECOVERY", error))?;
        let verified = admission
            .verify_frame(frame, &mut ExactFrameSource { payload })
            .map_err(|error| Error::peer_frame_source("AUTH_OUTBOX_FRAME", error))?;
        admission
            .admit_verified(verified)
            .map_err(|error| Error::peer_admission_source("AUTH_OUTBOX", error))?;
        if state.pending().is_some() {
            let stored: Vec<u8> = self.db.query_row(
                "SELECT pending_wire FROM peer_outbox WHERE session_id=?",
                [session.session_id().bytes().as_slice()],
                |row| row.get(0),
            )?;
            ensure(stored == wire, "AUTH_OUTBOX_CONFLICT")?;
            return Ok(stored);
        }
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "INSERT INTO peer_outbox(session_id,chain_id,protocol_digest,peer_id,profile_digest,generation,highest_ack,pending_nonce,pending_digest,pending_bytes,pending_payload,pending_wire,pending_wire_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET pending_nonce=excluded.pending_nonce,pending_digest=excluded.pending_digest,pending_bytes=excluded.pending_bytes,pending_payload=excluded.pending_payload,pending_wire=excluded.pending_wire,pending_wire_digest=excluded.pending_wire_digest",
            params![
                session.session_id().bytes().as_slice(),
                session.chain_id().bytes().as_slice(),
                session.protocol_digest().bytes().as_slice(),
                session.peer_id().bytes().as_slice(),
                session.profile_digest().bytes().as_slice(),
                session.generation(),
                state.highest_acknowledged_nonce(),
                frame.replay_nonce(),
                frame.payload_digest().bytes().as_slice(),
                frame.payload_bytes() as u64,
                payload,
                wire,
                hash(b"native-authenticated-wire-v1", &[wire]).as_slice(),
            ],
        )?;
        ensure(changed == 1, "AUTH_OUTBOX_STATE").map_err(Error::local_integrity)?;
        tx.commit()?;
        Ok(wire.to_vec())
    }

    pub(crate) fn finish_authenticated_outbound(
        &mut self,
        frame: AuthenticatedPeerFrameV0,
    ) -> Result<()> {
        let state = self
            .authenticated_outbox_state(frame.session())?
            .ok_or("AUTH_OUTBOX_STATE")?;
        if state.highest_acknowledged_nonce() >= frame.replay_nonce() {
            return Ok(());
        }
        let mut admission =
            CandidateP2pAdmissionV0::recover_verified(state, &mut OutboxRecovery { db: &self.db })
                .map_err(|error| Error::local_replay_source("AUTH_OUTBOX_RECOVERY", error))?;
        let next = admission
            .acknowledge(frame)
            .map_err(|error| Error::peer_admission_source("AUTH_OUTBOX", error))?;
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE peer_outbox SET highest_ack=?,pending_nonce=NULL,pending_digest=NULL,pending_bytes=NULL,pending_payload=NULL,pending_wire=NULL,pending_wire_digest=NULL WHERE session_id=? AND pending_nonce=? AND pending_digest=?",
            params![
                next.highest_acknowledged_nonce(),
                frame.session().session_id().bytes().as_slice(),
                frame.replay_nonce(),
                frame.payload_digest().bytes().as_slice(),
            ],
        )?;
        ensure(changed == 1, "AUTH_OUTBOX_STATE").map_err(Error::local_integrity)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn begin_authenticated_request(
        &mut self,
        frame: AuthenticatedPeerFrameV0,
        payload: &[u8],
    ) -> Result<AuthenticatedReplayDecision> {
        self.ready()?;
        self.namespace()?;
        let session = frame.session();
        ensure(
            session.chain_id().bytes() == self.settings.genesis()
                && session.protocol_digest().bytes() == self.settings.parameters()
                && session.profile_digest().bytes() == crate::authenticated_profile_digest()
                && session.generation() <= i64::MAX as u64
                && frame.replay_nonce() <= i64::MAX as u64,
            "AUTH_REPLAY_CONTEXT",
        )?;
        let existing = self.authenticated_replay_state(session)?;
        let state = existing.unwrap_or(
            PeerReplayStateV0::new(session, 0, None)
                .map_err(|e| Error::peer_admission_source("AUTH_REPLAY", e))?,
        );
        CandidateP2pAdmissionV0::recover_verified(state, &mut ReplayRecovery { db: &self.db })
            .map_err(|e| Error::local_replay_source("AUTH_RECOVERY", e))?;
        let session_id = session.session_id().bytes();
        if frame.replay_nonce() <= state.highest_acknowledged_nonce() {
            let audit: Option<(Vec<u8>, u64, Option<Vec<u8>>)> = self
                .db
                .query_row(
                    "SELECT payload_digest,status,response FROM peer_request_audit WHERE session_id=? AND nonce=?",
                    params![session_id.as_slice(), frame.replay_nonce()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let (digest, status, response) =
                audit.ok_or_else(|| Error::from("AUTH_REPLAY_GAP").local_integrity())?;
            ensure(
                bytes32(digest)? == frame.payload_digest().bytes(),
                "AUTH_CONFLICTING_REPLAY",
            )?;
            return match (status, response) {
                (1, Some(bytes)) => Ok(AuthenticatedReplayDecision::Cached(bytes)),
                (2, None) => Err("AUTH_REPLAY_RETIRED".into()),
                _ => Err(Error::from("AUTH_REPLAY_AUDIT").local_integrity()),
            };
        }
        let mut admission =
            CandidateP2pAdmissionV0::recover_verified(state, &mut ReplayRecovery { db: &self.db })
                .map_err(|e| Error::local_replay_source("AUTH_RECOVERY", e))?;
        let verified = admission
            .verify_frame(frame, &mut ExactFrameSource { payload })
            .map_err(|e| Error::peer_frame_source("AUTH_FRAME", e))?;
        admission
            .admit_verified(verified)
            .map_err(|e| Error::peer_admission_source("AUTH_REPLAY", e))?;
        if state.pending().is_some() {
            return Ok(AuthenticatedReplayDecision::Execute);
        }
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "INSERT INTO peer_replay(session_id,chain_id,protocol_digest,peer_id,profile_digest,generation,highest_ack,pending_nonce,pending_digest,pending_bytes) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET pending_nonce=excluded.pending_nonce,pending_digest=excluded.pending_digest,pending_bytes=excluded.pending_bytes",
            params![
                session_id.as_slice(),
                session.chain_id().bytes().as_slice(),
                session.protocol_digest().bytes().as_slice(),
                session.peer_id().bytes().as_slice(),
                session.profile_digest().bytes().as_slice(),
                session.generation(),
                state.highest_acknowledged_nonce(),
                frame.replay_nonce(),
                frame.payload_digest().bytes().as_slice(),
                frame.payload_bytes() as u64,
            ],
        )?;
        ensure(changed == 1, "AUTH_REPLAY_STATE").map_err(Error::local_integrity)?;
        let changed = tx.execute(
            "INSERT INTO peer_request_audit(session_id,nonce,payload_digest,payload,response_digest,response,status) VALUES(?,?,?,?,NULL,NULL,0)",
            params![
                session_id.as_slice(),
                frame.replay_nonce(),
                frame.payload_digest().bytes().as_slice(),
                payload,
            ],
        )?;
        ensure(changed == 1, "AUTH_REPLAY_AUDIT").map_err(Error::local_integrity)?;
        tx.commit()?;
        Ok(AuthenticatedReplayDecision::Execute)
    }

    pub(crate) fn finish_authenticated_request(
        &mut self,
        frame: AuthenticatedPeerFrameV0,
        response: &[u8],
    ) -> Result<()> {
        ensure(
            !response.is_empty() && response.len() <= 2 * 1024 * 1024,
            "AUTH_RESPONSE",
        )?;
        let state = self
            .authenticated_replay_state(frame.session())?
            .ok_or("AUTH_REPLAY_STATE")?;
        CandidateP2pAdmissionV0::recover_verified(state, &mut ReplayRecovery { db: &self.db })
            .map_err(|e| Error::local_replay_source("AUTH_RECOVERY", e))?;
        let session = frame.session().session_id().bytes();
        let response_digest = hash(b"native-authenticated-response-v1", &[response]);
        if state.highest_acknowledged_nonce() >= frame.replay_nonce() {
            let audit: Option<(Vec<u8>, u64, Option<Vec<u8>>)> = self
                .db
                .query_row(
                    "SELECT response_digest,status,response FROM peer_request_audit WHERE session_id=? AND nonce=?",
                    params![session.as_slice(), frame.replay_nonce()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let (digest, status, retained) =
                audit.ok_or_else(|| Error::from("AUTH_REPLAY_GAP").local_integrity())?;
            ensure(
                bytes32(digest)? == response_digest,
                "AUTH_RESPONSE_CONFLICT",
            )?;
            ensure(
                (status == 1 && retained.as_deref() == Some(response))
                    || (status == 2 && retained.is_none()),
                "AUTH_RESPONSE_CONFLICT",
            )?;
            return Ok(());
        }
        let mut admission =
            CandidateP2pAdmissionV0::recover_verified(state, &mut ReplayRecovery { db: &self.db })
                .map_err(|e| Error::local_replay_source("AUTH_RECOVERY", e))?;
        let next = admission
            .acknowledge(frame)
            .map_err(|e| Error::peer_admission_source("AUTH_REPLAY", e))?;
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE peer_request_audit SET payload=NULL,response_digest=?,response=?,status=1 WHERE session_id=? AND nonce=? AND status=0 AND payload_digest=?",
            params![
                response_digest.as_slice(),
                response,
                session.as_slice(),
                frame.replay_nonce(),
                frame.payload_digest().bytes().as_slice(),
            ],
        )?;
        ensure(changed == 1, "AUTH_REPLAY_AUDIT").map_err(Error::local_integrity)?;
        let changed = tx.execute(
            "UPDATE peer_replay SET highest_ack=?,pending_nonce=NULL,pending_digest=NULL,pending_bytes=NULL WHERE session_id=?",
            params![next.highest_acknowledged_nonce(), session.as_slice()],
        )?;
        ensure(changed == 1, "AUTH_REPLAY_STATE").map_err(Error::local_integrity)?;
        let retire = next
            .highest_acknowledged_nonce()
            .saturating_sub(AUTH_RESPONSE_RETENTION);
        if retire > 0 {
            tx.execute(
                "UPDATE peer_request_audit SET response=NULL,status=2 WHERE session_id=? AND nonce<=? AND status=1",
                params![session.as_slice(), retire],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn authenticated_outbox_counts(&self) -> Result<(u64, u64)> {
        Ok((
            self.db
                .query_row("SELECT COUNT(*) FROM peer_outbox", [], |row| row.get(0))?,
            self.db.query_row(
                "SELECT COUNT(*) FROM peer_outbox WHERE pending_nonce IS NOT NULL",
                [],
                |row| row.get(0),
            )?,
        ))
    }

    pub(crate) fn authenticated_replay_counts(&self) -> Result<(u64, u64, u64)> {
        Ok((
            self.db
                .query_row("SELECT COUNT(*) FROM peer_replay", [], |row| row.get(0))?,
            self.db.query_row(
                "SELECT COUNT(*) FROM peer_replay WHERE pending_nonce IS NOT NULL",
                [],
                |row| row.get(0),
            )?,
            self.db
                .query_row("SELECT COUNT(*) FROM peer_request_audit", [], |row| {
                    row.get(0)
                })?,
        ))
    }
    fn namespace(&self) -> Result<()> {
        ensure(
            !authenticated_migration_pending(&self.directory)?,
            "NATIVE_STATE_MIGRATION_PENDING",
        )?;
        let meta = fs::symlink_metadata(&self.directory)?;
        ensure(
            meta.is_dir() && (meta.dev(), meta.ino()) == self.directory_id,
            "NAMESPACE_CHANGED",
        )?;
        for name in [
            "native.sqlite",
            "native.sqlite-wal",
            "native.sqlite-shm",
            "owner.lock",
        ] {
            plain(&self.directory.join(name))?;
        }
        let dm = fs::metadata(self.directory.join("native.sqlite"))?;
        ensure(
            (dm.dev(), dm.ino()) == self.database_id,
            "DATABASE_REPLACED",
        )?;
        let actual = fs::metadata(self.directory.join("owner.lock"))?;
        let held = self.owner.metadata()?;
        ensure(
            (actual.dev(), actual.ino()) == (held.dev(), held.ino()),
            "OWNER_REPLACED",
        )
    }
    fn storage_context(&self) -> Result<()> {
        for (key, expected) in [
            ("schema", self.state_backend.schema_id()),
            ("parameters", self.settings.parameters()),
            ("genesis", self.settings.genesis()),
        ] {
            let actual: Option<Vec<u8>> = self
                .db
                .query_row("SELECT value FROM metadata WHERE key=?", [key], |row| {
                    row.get(0)
                })
                .optional()?;
            ensure(
                actual.as_deref() == Some(expected.as_slice()),
                "STORAGE_CONTEXT",
            )
            .map_err(Error::local_integrity)?;
        }
        Ok(())
    }
    fn check_persisted_state(
        &self,
        id: Hash,
        state: &State,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let record = self.record(id).map_err(Error::local_integrity)?;
        continuity_v1::check_state(state, record.height, &self.settings.app)
            .map_err(|error| Error::from(error).local_integrity())?;
        ensure(root(state)? == record.root, "ROOT").map_err(Error::local_integrity)?;
        if self.state_backend == StateBackend::AuthenticatedV1 {
            native_authenticated::verify_state(&self.db, &self.settings, id, state, progress)?;
        }
        Ok(())
    }
    /// Check actual data after the last transactional write. A post-COMMIT
    /// observation cannot repair a suppressed write or a trigger-corrupted slot.
    fn check_active_before_commit(&self) -> Result<()> {
        self.namespace()?;
        self.storage_context()?;
        let count: u64 = self
            .db
            .query_row("SELECT COUNT(*) FROM active", [], |row| row.get(0))?;
        ensure(count == 1, "GENERATION").map_err(Error::local_integrity)?;
        let selected = self.active()?;
        let slot = self.slot()?;
        let state = self.slot_state(slot)?;
        self.check_persisted_state(selected.0, &state, &mut || Ok(()))?;
        crate::ancestry_index::validate_tip(&self.db, self.ancestry_context(), selected.0)
            .map_err(Error::local_integrity)?;
        if self.state_backend == StateBackend::AuthenticatedV1 {
            native_authenticated::verify_history(
                &self.db,
                &self.settings,
                selected.0,
                &mut || Ok(()),
            )?;
        }
        ensure(
            self.active()? == selected && self.slot()? == slot,
            "GENERATION",
        )
        .map_err(Error::local_integrity)
    }
    fn record(&self, id: Hash) -> Result<Record> {
        let row = self
            .db
            .query_row(
                "SELECT parent,height,chainwork,state_root FROM blocks WHERE id=?",
                [id.as_slice()],
                |r| {
                    Ok((
                        r.get::<_, Option<Vec<u8>>>(0)?,
                        r.get::<_, u64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or("UNKNOWN_PARENT")?;
        Ok(Record {
            parent: row.0.map(bytes32).transpose()?,
            height: row.1,
            work: Work::from_bytes(bytes64(row.2)?),
            root: bytes32(row.3)?,
        })
    }
    pub fn active(&self) -> Result<(Hash, u64)> {
        let (tip, g) = self.db.query_row(
            "SELECT tip,generation FROM active WHERE singleton=1",
            [],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, u64>(1)?)),
        )?;
        Ok((bytes32(tip)?, g))
    }
    pub fn next_nonce(&self, sender: Hash) -> Result<u64> {
        let state = self.state_at(self.active()?.0)?;
        let key = format!("account:{}", hex::encode(sender));
        let current = match state.get(&key) {
            None => 0,
            Some(account) => account
                .get("nonce")
                .and_then(serde_json::Value::as_u64)
                .ok_or("STATE_NONCE")?,
        };
        current
            .checked_add(1)
            .ok_or_else(|| "NONCE_OVERFLOW".into())
    }
    fn slot(&self) -> Result<u64> {
        Ok(self
            .db
            .query_row("SELECT state_slot FROM active WHERE singleton=1", [], |r| {
                r.get(0)
            })?)
    }
    fn slot_state(&self, slot: u64) -> Result<State> {
        self.slot_state_with_progress(slot, &mut || Ok(()))
    }
    fn slot_state_with_progress(
        &self,
        slot: u64,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<State> {
        progress()?;
        let mut stmt = self
            .db
            .prepare("SELECT key,value FROM kv WHERE slot=? ORDER BY key")?;
        let values = stmt.query_map([slot], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut state = State::new();
        for (index, row) in values.enumerate() {
            if index.is_multiple_of(256) {
                progress()?;
            }
            let (key, bytes) = row?;
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|error| Error::from(error).local_integrity())?;
            ensure(canonical(&value)? == bytes, "STATE_BYTES").map_err(Error::local_integrity)?;
            state.insert(key, value);
        }
        progress()?;
        Ok(state)
    }
    fn invalidate_commitment(&self) {
        *self.commitment_cache.borrow_mut() = None;
    }
    /// Local calculation observation only, never a state/confirmation authority.
    pub fn derived_commitment_status(&self) -> DerivedCommitmentStatus {
        let cache = self.commitment_cache.borrow();
        DerivedCommitmentStatus {
            cache_root: cache.as_ref().map(|c| c.snapshot.root()),
            cache_keys: cache.as_ref().map_or(0, |c| c.snapshot.keys()),
            software_charge_bytes: cache
                .as_ref()
                .map_or(0, |c| c.snapshot.retained_charge_bytes()),
            last: self.commitment_observation.borrow().clone(),
        }
    }
    fn checked_commitment(
        &self,
        actual: &State,
        expected: Hash,
        prior: Option<&CheckedCommitment>,
    ) -> Result<PreparedCommitment> {
        let result =
            pon_commitment::checked_snapshot(actual, expected, prior, CacheLimits::default());
        match result {
            Ok(prepared) => {
                *self.commitment_observation.borrow_mut() = Some(prepared.observation.clone());
                Ok(prepared)
            }
            Err("COMMITMENT_ROOT") => {
                self.invalidate_commitment();
                Err(Error::from("ROOT").local_integrity())
            }
            Err(error) => Err(Error::from(error).local_integrity()),
        }
    }
    fn cached_parent(&self, parent: Hash) -> Result<Option<CheckedCommitment>> {
        let (tip, generation) = self.active()?;
        let slot = self.slot()?;
        Ok(self
            .commitment_cache
            .borrow()
            .as_ref()
            .filter(|cache| {
                parent == tip
                    && cache.tip == tip
                    && cache.generation == generation
                    && cache.slot == slot
            })
            .map(|cache| cache.snapshot.clone()))
    }
    fn publish_commitment(
        &self,
        tip: Hash,
        generation: u64,
        slot: u64,
        prepared: PreparedCommitment,
    ) {
        *self.commitment_observation.borrow_mut() = Some(prepared.observation);
        *self.commitment_cache.borrow_mut() = prepared.snapshot.map(|snapshot| ActiveCommitment {
            tip,
            generation,
            slot,
            snapshot,
        });
    }
    fn execute_derived(
        &self,
        actual: &State,
        parent: Hash,
        transactions: &[Vec<u8>],
        height: u64,
        miner: Hash,
        workers: usize,
    ) -> Result<trnm_mvcc_fee::pon_commitment::StagedOutput> {
        self.execute_derived_with_progress(
            actual,
            ExecutionRequest {
                transactions,
                height,
                miner,
                parent_id: parent,
                workers,
            },
            &|_| Ok(()),
        )
    }
    fn execute_derived_with_progress(
        &self,
        actual: &State,
        block: ExecutionRequest<'_>,
        progress: &(impl Fn(ExecutionProgress) -> Result<()> + Sync),
    ) -> Result<trnm_mvcc_fee::pon_commitment::StagedOutput> {
        self.execute_derived_with_control(actual, block, &ExecutionControl::new(progress, &()))
    }
    fn execute_derived_with_control(
        &self,
        actual: &State,
        block: ExecutionRequest<'_>,
        control: &ExecutionControl<'_, Error>,
    ) -> Result<trnm_mvcc_fee::pon_commitment::StagedOutput> {
        self.owner_preview_available()?;
        self.execute_derived_core(actual, block, control, None)
    }
    fn execute_derived_core(
        &self,
        actual: &State,
        block: ExecutionRequest<'_>,
        control: &ExecutionControl<'_, Error>,
        owner_permit: Option<&OwnerPacketPermit>,
    ) -> Result<trnm_mvcc_fee::pon_commitment::StagedOutput> {
        ensure(
            self.owner_policy.is_some() == owner_permit.is_some(),
            "OWNER_TASK_PERMIT_REQUIRED",
        )?;
        if let Some(permit) = owner_permit {
            permit.progress()?;
        }
        self.continuous_execution_gate(&block)?;
        self.mining_execution_gate(&block)?;
        let mining_progress = self.mining_progress_snapshot()?;
        let continuous_progress = self.continuous_progress_snapshot()?;
        let guarded_mining_progress = |point| -> Result<()> {
            (control.progress)(point)?;
            if let Some(p) = &continuous_progress {
                p.check()?;
            }
            if let Some(p) = &mining_progress {
                p.check()?;
            }
            Ok(())
        };
        let mining_control =
            ExecutionControl::new(&guarded_mining_progress, control.worker_accounting);
        let control = &mining_control;
        let progress = control.progress;
        progress(ExecutionProgress::BeforeParentBinding)?;
        let parent = block.parent_id;
        let prior = self.cached_parent(parent)?;
        // Always encode/compare the actual supplied parent with its admitted root.
        // This also explicitly reseeds unknown/inactive/fork contexts.
        let checked = self.checked_commitment(actual, self.record(parent)?.root, prior.as_ref())?;
        let request = || ExecutionRequest {
            transactions: block.transactions,
            height: block.height,
            miner: block.miner,
            parent_id: parent,
            workers: block.workers,
        };
        let result = pon_commitment::execute_checked_with_control(
            actual,
            checked.root,
            checked.snapshot.as_ref(),
            request(),
            &self.settings.app,
            CacheLimits::default(),
            control,
        );
        match result {
            Ok(output) => {
                *self.commitment_observation.borrow_mut() =
                    Some(output.commitment.observation.clone());
                Ok(output)
            }
            Err(ExecutionError::Relation("COMMITMENT_PARENT" | "COMMITMENT_ROOT")) => {
                // A wrong internal snapshot cannot reject an otherwise valid
                // ledger state; the full actual-root path still checks context.
                self.invalidate_commitment();
                pon_commitment::execute_checked_with_control(
                    actual,
                    self.record(parent)?.root,
                    None,
                    request(),
                    &self.settings.app,
                    CacheLimits::default(),
                    control,
                )
                .map_err(local_execution_error)
            }
            Err(error) => Err(local_execution_error(error)),
        }
    }
    fn derive_successor(
        &self,
        actual: &State,
        prior: Option<&CheckedCommitment>,
    ) -> Result<PreparedCommitment> {
        let prepared = pon_commitment::derive_snapshot(actual, prior, CacheLimits::default())?;
        *self.commitment_observation.borrow_mut() = Some(prepared.observation.clone());
        Ok(prepared)
    }
    pub fn read_active(&self) -> Result<(Hash, u64, State)> {
        self.read_active_with_progress(&mut || Ok(()))
    }
    /// Rechecks actual KV bytes and root, with cancellation at most 256 rows apart.
    /// Root arithmetic is still bounded by the state limit and checked as one stage.
    pub fn read_active_with_progress(
        &self,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<(Hash, u64, State)> {
        progress()?;
        self.namespace()?;
        let (tip, generation) = self.active()?;
        let slot = self.slot()?;
        let state = self.slot_state_with_progress(slot, progress)?;
        continuity_v1::check_state(
            &state,
            self.record(tip).map_err(Error::local_integrity)?.height,
            &self.settings.app,
        )
        .map_err(|error| Error::from(error).local_integrity())?;
        let prior = self.cached_parent(tip)?;
        progress()?;
        let prepared = self.checked_commitment(
            &state,
            self.record(tip).map_err(Error::local_integrity)?.root,
            prior.as_ref(),
        )?;
        if self.state_backend == StateBackend::AuthenticatedV1 {
            native_authenticated::verify_state(&self.db, &self.settings, tip, &state, progress)?;
        }
        progress()?;
        ensure(
            self.active()? == (tip, generation) && self.slot()? == slot,
            "STALE_VIEW",
        )?;
        self.publish_commitment(tip, generation, slot, prepared);
        Ok((tip, generation, state))
    }
    fn ready(&self) -> Result<()> {
        self.namespace()?;
        let done: Option<bool> = self
            .db
            .query_row("SELECT done FROM reorg WHERE singleton=1", [], |r| r.get(0))
            .optional()?;
        ensure(done != Some(false), "REORG_IN_PROGRESS")
    }
    pub fn packet(&self, id: Hash) -> Result<Packet> {
        let row = self.record(id)?;
        let raw: Option<Vec<u8>> = self.db.query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [id.as_slice()],
            |r| r.get(0),
        )?;
        let raw = raw.ok_or_else(|| {
            let error = Error::from("GENESIS_HAS_NO_PACKET");
            if id == self.settings.genesis() {
                error
            } else {
                error.local_integrity()
            }
        })?;
        let packet = Packet::decode(&raw).map_err(Error::local_integrity)?;
        ensure(
            packet.id()? == id
                && Some(packet.header.parent) == row.parent
                && packet.header.height == row.height
                && packet.header.state == row.root,
            "STORAGE_PACKET",
        )?;
        Ok(packet)
    }
    /// Reuses only a prepared SQL statement, never a previous clock or ancestry verdict.
    /// The JOIN checks the parent in the same SQLite statement as the bounded header.
    fn stored_header_link(&self, id: Hash) -> Result<StoredHeaderLink> {
        let mut statement = self.db.prepare_cached(
            "SELECT b.parent,b.height,b.chainwork,b.state_root,substr(b.packet,1,?),
             substr(b.packet,-32),length(b.packet),p.height,p.chainwork,p.parent,p.state_root
             FROM blocks b LEFT JOIN blocks p ON p.id=b.parent WHERE b.id=?",
        )?;
        self.count_header_query();
        let projection = statement
            .query_row(params![HEADER_BYTES, id.as_slice()], HeaderProjection::read)
            .optional()?
            .ok_or("UNKNOWN_PARENT")?;
        self.check_header_projection(id, projection)
    }
    fn count_header_query(&self) {
        let mut counters = self.history_read_counters.get();
        counters.header_link_queries = counters.header_link_queries.saturating_add(1);
        self.history_read_counters.set(counters);
    }
    fn check_header_projection(
        &self,
        id: Hash,
        projection: HeaderProjection,
    ) -> Result<StoredHeaderLink> {
        // A projection exists only after the SQL owner found the requested row.
        // All failures below describe retained local data, not a new peer packet.
        (|| {
            let row = Record {
                parent: projection.parent.map(bytes32).transpose()?,
                height: projection.height,
                work: Work::from_bytes(bytes64(projection.work)?),
                root: bytes32(projection.root)?,
            };
            ensure(
                (HEADER_BYTES + 2 + pon_work::PROOF_BYTES..=1_048_576)
                    .contains(&projection.length.ok_or("GENESIS_HAS_NO_PACKET")?),
                "PACKET_LIMIT",
            )?;
            let prefix = projection.prefix.ok_or("GENESIS_HAS_NO_PACKET")?;
            let trace = projection.trace.ok_or("GENESIS_HAS_NO_PACKET")?;
            let mut counters = self.history_read_counters.get();
            counters.header_trace_bytes = counters
                .header_trace_bytes
                .saturating_add((prefix.len() + trace.len()) as u64);
            self.history_read_counters.set(counters);
            let header = Header::decode(&prefix).map_err(|_| Error::from("HEADER_CODEC"))?;
            let trace = bytes32(trace)?;
            ensure(
                header.block_id(trace) == id
                    && Some(header.parent) == row.parent
                    && header.height == row.height
                    && header.state == row.root,
                "STORAGE_PACKET",
            )?;
            ensure(
                projection
                    .parent_height
                    .ok_or("UNKNOWN_PARENT")?
                    .checked_add(1)
                    == Some(row.height),
                "ANCESTRY_HEIGHT",
            )?;
            let parent_work =
                Work::from_bytes(bytes64(projection.parent_work.ok_or("UNKNOWN_PARENT")?)?);
            // Preserve the complete parent-record shape checks, including at genesis
            // where the ancestry loop stops without reading another header.
            let _ = projection.parent_parent.map(bytes32).transpose()?;
            let _ = bytes32(projection.parent_root.ok_or("UNKNOWN_PARENT")?)?;
            Ok(StoredHeaderLink {
                header,
                record: row,
                parent_work,
            })
        })()
        .map_err(Error::local_integrity)
    }
    /// A bounded read of actual rows, with the same ordered per-link checks as a
    /// single projection. No successful verdict or ancestry list survives the call.
    /// LIMIT bounds even corrupt cycles; ORDER BY makes validation order explicit.
    fn visit_header_batch(
        &self,
        start: Hash,
        visit: &mut impl FnMut(Hash, StoredHeaderLink) -> Result<()>,
    ) -> Result<(Hash, u64)> {
        if start == self.settings.genesis() {
            return Ok((start, 0));
        }
        let mut statement = self.db.prepare_cached(
            "WITH RECURSIVE ancestry(id,parent,ordinal) AS (
                 SELECT id,parent,0 FROM blocks WHERE id=?1 AND id!=?2
                 UNION ALL
                 SELECT b.id,b.parent,a.ordinal+1
                 FROM ancestry a JOIN blocks b ON b.id=a.parent
                 WHERE b.id!=?2 LIMIT ?3
             )
             SELECT b.parent,b.height,b.chainwork,b.state_root,substr(b.packet,1,?4),
                 substr(b.packet,-32),length(b.packet),p.height,p.chainwork,p.parent,
                 p.state_root,b.id,a.ordinal
             FROM ancestry a JOIN blocks b ON b.id=a.id
             LEFT JOIN blocks p ON p.id=b.parent ORDER BY a.ordinal",
        )?;
        self.count_header_query();
        let mut rows = statement.query(params![
            start.as_slice(),
            self.settings.genesis().as_slice(),
            HISTORY_HEADER_BATCH,
            HEADER_BYTES,
        ])?;
        let mut current = start;
        let mut checked = 0_u64;
        while let Some(row) = rows.next()? {
            let id = bytes32(row.get(11)?)?;
            ensure(
                checked < HISTORY_HEADER_BATCH
                    && row.get::<_, u64>(12)? == checked
                    && id == current,
                "ANCESTRY_HEIGHT",
            )
            .map_err(Error::local_integrity)?;
            let link = self.check_header_projection(id, HeaderProjection::read(row)?)?;
            current = link.header.parent;
            visit(id, link)?;
            checked = checked.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
        }
        let complete = ensure(
            checked == HISTORY_HEADER_BATCH || current == self.settings.genesis(),
            "UNKNOWN_PARENT",
        );
        // An absent caller locator is stale context. Once a retained row was
        // observed, a missing internal ancestor is a local integrity failure.
        if checked == 0 {
            complete?;
        } else {
            complete.map_err(Error::local_integrity)?;
        }
        Ok((current, checked))
    }
    /// Reads only the committed header and trace of an already admitted local block.
    /// This does not verify new work or replace inclusion-body validation.
    fn stored_header(&self, id: Hash) -> Result<Header> {
        Ok(self.stored_header_link(id)?.header)
    }
    pub fn history_read_counters(&self) -> HistoryReadCounters {
        self.history_read_counters.get()
    }

    fn parent(&self, id: Hash) -> Result<Hash> {
        let row = self.record(id)?;
        let parent = row
            .parent
            .ok_or_else(|| Error::from("UNKNOWN_PARENT").local_integrity())?;
        ensure(
            self.record(parent)
                .map_err(Error::local_integrity)?
                .height
                .checked_add(1)
                == Some(row.height),
            "ANCESTRY_HEIGHT",
        )
        .map_err(Error::local_integrity)?;
        Ok(parent)
    }
    fn delta_rows(&self, id: Hash) -> Result<Vec<Delta>> {
        if self.state_backend == StateBackend::AuthenticatedV1 {
            return native_authenticated::deltas(&self.db, id);
        }
        let mut stmt = self
            .db
            .prepare("SELECT key,before,after FROM deltas WHERE block=? ORDER BY key")?;
        let rows = stmt.query_map([id.as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
    pub fn state_at(&self, tip: Hash) -> Result<State> {
        self.state_at_with_progress(tip, &mut || Ok(()))
    }
    fn state_at_with_progress(
        &self,
        tip: Hash,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<State> {
        progress()?;
        if tip == self.active()?.0 {
            return Ok(self.read_active_with_progress(progress)?.2);
        }
        let mut path = tempfile::tempfile()?;
        let mut count = 0u64;
        let mut cur = tip;
        let (mut state, mut commitment): (State, Option<CheckedCommitment>) = loop {
            progress()?;
            let row = self.record(cur)?;
            if let Some(bytes) = self
                .db
                .query_row(
                    "SELECT state FROM snapshots WHERE block=?",
                    [cur.as_slice()],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()?
            {
                let state: State = serde_json::from_slice(&bytes)
                    .map_err(|error| Error::from(error).local_integrity())?;
                ensure(canonical(&state)? == bytes, "STATE_BYTES")
                    .map_err(Error::local_integrity)?;
                continuity_v1::check_state(&state, row.height, &self.settings.app)
                    .map_err(|error| Error::from(error).local_integrity())?;
                let commitment = self.checked_commitment(&state, row.root, None)?.snapshot;
                if self.state_backend == StateBackend::AuthenticatedV1 {
                    native_authenticated::verify_state(
                        &self.db,
                        &self.settings,
                        cur,
                        &state,
                        progress,
                    )?;
                }
                break (state, commitment);
            }
            path.write_all(&cur)?;
            count = count.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
            cur = self.parent(cur)?;
        };
        for i in (0..count).rev() {
            progress()?;
            path.seek(SeekFrom::Start(i.checked_mul(32).ok_or("ANCESTRY_LIMIT")?))?;
            let mut id = [0; 32];
            path.read_exact(&mut id)?;
            for (index, (key, before, after)) in self.delta_rows(id)?.into_iter().enumerate() {
                if index.is_multiple_of(256) {
                    progress()?;
                }
                ensure(
                    state.get(&key).map(canonical).transpose()? == before,
                    "UNDO_ROOT",
                )
                .map_err(Error::local_integrity)?;
                if let Some(bytes) = after {
                    state.insert(
                        key,
                        serde_json::from_slice(&bytes)
                            .map_err(|error| Error::from(error).local_integrity())?,
                    );
                } else {
                    state.remove(&key);
                }
            }
            commitment = self
                .checked_commitment(&state, self.record(id)?.root, commitment.as_ref())?
                .snapshot;
            continuity_v1::check_state(&state, self.record(id)?.height, &self.settings.app)
                .map_err(|error| Error::from(error).local_integrity())?;
            if self.state_backend == StateBackend::AuthenticatedV1 {
                native_authenticated::verify_state(&self.db, &self.settings, id, &state, progress)?;
            }
        }
        progress()?;
        Ok(state)
    }
    fn recent(&self, mut parent: Hash) -> Result<Vec<(u64, Hash)>> {
        let mut out = Vec::new();
        let bound = self.settings.limit("retarget_interval")?.max(11);
        while parent != self.settings.genesis() && out.len() < (bound as usize) {
            let header = self.stored_header(parent)?;
            out.push((header.timestamp, header.target));
            parent = self.parent(parent)?;
        }
        if parent == self.settings.genesis() {
            out.push((
                self.settings.genesis_time(),
                self.settings.target("initial_target_hex")?,
            ));
        }
        Ok(out)
    }
    pub fn expected_target(&self, parent: Hash) -> Result<Hash> {
        let height = self.record(parent)?.height.checked_add(1).ok_or("HEIGHT")?;
        let recent = self.recent(parent)?;
        let interval = self.settings.limit("retarget_interval")?;
        let target = recent.first().ok_or("UNKNOWN_PARENT")?.1;
        if height % interval != 0 {
            return Ok(target);
        }
        let first = recent
            .get((interval - 1) as usize)
            .ok_or("UNKNOWN_PARENT")?
            .0;
        consensus::retarget(
            target,
            first,
            recent[0].0,
            interval,
            self.settings.limit("target_spacing_seconds")?,
            self.settings.target("pow_limit_hex")?,
        )
    }
    pub(crate) fn check_admission_context(
        &self,
        packet: &Packet,
        observed_now: u64,
    ) -> Result<Option<Hash>> {
        self.check_admission_context_for_permit(packet, observed_now, None)
    }
    fn check_admission_context_for_permit(
        &self,
        packet: &Packet,
        observed_now: u64,
        reserved: Option<&OwnerPacketPermit>,
    ) -> Result<Option<Hash>> {
        // Bounded full-packet identity precedes State/lease/context/Work work.
        self.precheck_owner_packet(packet)?;
        self.ready()?;
        let bytes = packet.encode()?;
        let h = &packet.header;
        let id = packet.id()?;
        ensure(
            h.network == self.settings.network() && h.parameters == self.settings.parameters(),
            "NETWORK",
        )?;
        let previous: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT packet FROM blocks WHERE id=?",
                [id.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(prior) = previous {
            ensure(prior == bytes, "DUPLICATE_CONTENT")?;
            // Immutable work can be cached; a previous caller's clock cannot.
            ensure(
                h.timestamp as u128
                    <= observed_now as u128 + self.settings.limit("future_skew_seconds")? as u128,
                "TIME_DEFERRED",
            )?;
            return Ok(Some(id));
        }
        if let Some(owner) = &self.owner_policy {
            if owner.journal.borrow().work_operation_is_used(&owner.policy) {
                // A reservation without a durable exact block is in-flight or
                // uncertain/failed, not another authorization to reconstruct State.
                let permit = reserved.ok_or("OWNER_TASK_OPERATION_USED")?;
                permit.progress()?;
                owner
                    .journal
                    .borrow()
                    .recheck_before_commit(
                        &owner.policy,
                        &permit.reservation,
                        &permit.facts,
                        crate::operator_task_policy::now_ns().map_err(owner_error)?,
                    )
                    .map_err(owner_error)?;
            }
        }
        let parent = self.record(h.parent)?;
        ensure(
            parent.height.checked_add(1) == Some(h.height) && h.height <= i64::MAX as u64,
            "HEIGHT",
        )?;
        ensure(h.target == self.expected_target(h.parent)?, "TARGET")?;
        let times: Vec<_> = self
            .recent(h.parent)?
            .iter()
            .take(11)
            .map(|p| p.0)
            .collect();
        consensus::check_time(
            h.timestamp,
            &times,
            observed_now,
            self.settings.limit("future_skew_seconds")?,
        )?;
        ensure(
            h.transactions == sequence_root("transactions", &packet.transactions),
            "ROOT",
        )?;
        // Signed task context/expiry/parent registration reject before full work replay.
        if let Some(manifest) = self.eligible_work_task(h.parent, h.work_task, h.height)? {
            // The fixed recipe's actual model and input artifacts are precisely the
            // proof's A/B bytes. An untrusted miner can bypass every local builder;
            // the validator must bind these commitments before transcript replay.
            let artifact_bytes = pon_work::CELLS * 4;
            ensure(
                packet.proof.len() == pon_work::PROOF_BYTES
                    && packet.proof.get(..4) == Some(b"PNW1"),
                "TASK_PROOF_MATERIAL",
            )?;
            let model = packet
                .proof
                .get(4..4 + artifact_bytes)
                .ok_or("TASK_PROOF_MATERIAL")?;
            let input = packet
                .proof
                .get(4 + artifact_bytes..4 + 2 * artifact_bytes)
                .ok_or("TASK_PROOF_MATERIAL")?;
            ensure(
                hash(b"artifact", &[model]) == manifest.model,
                "TASK_MODEL_BINDING",
            )?;
            ensure(
                hash(b"qualified-task-input-v1", &[input]) == manifest.input,
                "TASK_INPUT_BINDING",
            )?;
        }
        Ok(None)
    }
    pub fn admit(&mut self, packet: &Packet, observed_now: u64) -> Result<Hash> {
        if let Some(id) = self.check_admission_context(packet, observed_now)? {
            return Ok(id);
        }
        let permit = self.begin_owner_work(packet)?;
        let checked = self.attach_owner_work(WorkCheckedPacket::verify(packet.clone())?, permit)?;
        self.admit_work_checked(checked, observed_now)
    }
    fn precheck_owner_packet(&self, packet: &Packet) -> Result<()> {
        self.continuous_packet_gate(packet)?;
        self.mining_packet_gate(packet)?;
        if let Some(owner) = &self.owner_policy {
            ensure(
                !owner.unavailable.load(std::sync::atomic::Ordering::Acquire),
                "OWNER_TASK_UNAVAILABLE",
            )?;
            owner
                .policy
                .check_window(crate::operator_task_policy::now_ns().map_err(owner_error)?)
                .map_err(owner_error)?;
            owner
                .policy
                .check_packet(&crate::operator_task_policy::digest_bytes(
                    &packet.encode()?,
                ))
                .map_err(owner_error)?;
        }
        Ok(())
    }
    pub(crate) fn begin_owner_work(&self, packet: &Packet) -> Result<Option<OwnerPacketPermit>> {
        let Some(owner) = &self.owner_policy else {
            return Ok(None);
        };
        self.precheck_owner_packet(packet)?;
        let packet_sha256 = crate::operator_task_policy::digest_bytes(&packet.encode()?);
        owner
            .policy
            .check_packet(&packet_sha256)
            .map_err(owner_error)?;
        owner
            .policy
            .check_commands(&packet.transactions)
            .map_err(owner_error)?;
        let h = &packet.header;
        let manifest = self
            .eligible_work_task(h.parent, h.work_task, h.height)?
            .ok_or("OWNER_TASK_COMPLETE_REGISTRATION_REQUIRED")?;
        // Initial supported actual case is Maintenance with a complete lifecycle lease.
        ensure(
            manifest.purpose == TaskPurpose::Maintenance,
            "OWNER_TASK_PURPOSE_PENDING",
        )?;
        let lease = self.lifecycle_task_lease(h.parent, h.work_task, h.height)?;
        let lease = lease
            .encode()
            .map_err(|_| Error::from("OWNER_TASK_LEASE"))?;
        let size = pon_work::CELLS * 4;
        ensure(
            packet.proof.len() == pon_work::PROOF_BYTES && packet.proof.get(..4) == Some(b"PNW1"),
            "OWNER_TASK_PROOF",
        )?;
        let mut task = owner.policy.task().clone();
        task.purpose = "maintenance-tag1".into();
        task.native_task = hex::encode(h.work_task);
        task.lease_sha256 = crate::operator_task_policy::digest_bytes(&lease);
        task.native_model = hex::encode(manifest.model);
        task.native_input = hex::encode(manifest.input);
        task.a_sha256 = crate::operator_task_policy::digest_bytes(&packet.proof[4..4 + size]);
        task.b_sha256 =
            crate::operator_task_policy::digest_bytes(&packet.proof[4 + size..4 + 2 * size]);
        task.dimension = 64;
        task.field_modulus = 4_294_967_291;
        task.encoding = "canonical-u32-le".into();
        let facts = crate::operator_task_policy::NativeFacts {
            network: hex::encode(h.network),
            parameters: hex::encode(h.parameters),
            parent: hex::encode(h.parent),
            task,
            packet_sha256,
            header_nonce: h.nonce,
        };
        let reservation = owner
            .journal
            .borrow_mut()
            .reserve(
                &owner.policy,
                &facts,
                crate::operator_task_policy::now_ns().map_err(owner_error)?,
            )
            .map_err(owner_error)?;
        Ok(Some(OwnerPacketPermit {
            epoch: std::sync::Arc::clone(&owner.epoch),
            expected_epoch: owner.epoch.load(std::sync::atomic::Ordering::Acquire),
            policy: std::sync::Arc::clone(&owner.policy),
            unavailable: std::sync::Arc::clone(&owner.unavailable),
            facts,
            reservation,
        }))
    }
    pub(crate) fn attach_owner_work(
        &self,
        mut checked: WorkCheckedPacket,
        permit: Option<OwnerPacketPermit>,
    ) -> Result<WorkCheckedPacket> {
        ensure(
            self.owner_policy.is_some() == permit.is_some(),
            "OWNER_TASK_PERMIT_REQUIRED",
        )?;
        if let Some(permit) = &permit {
            ensure(
                permit.facts.packet_sha256
                    == crate::operator_task_policy::digest_bytes(&checked.packet.encode()?),
                "OWNER_TASK_PACKET_CHANGED",
            )?;
            permit.progress()?;
        }
        checked.owner_permit = permit;
        Ok(checked)
    }
    /// Trusted operator-only typed refresh. There is deliberately no anonymous RPC
    /// or candidate-selected latest source. CLI may stop/reopen using the same protected
    /// loader; an embedding owner must supply the externally fixed full descriptor.
    pub fn refresh_operator_task_policy(
        &mut self,
        inputs: crate::operator_task_policy::RestrictedNodeInputs,
    ) -> Result<()> {
        let owner = self
            .owner_policy
            .as_ref()
            .ok_or("OWNER_TASK_POLICY_REQUIRED")?;
        ensure(
            inputs.expected_uid == rustix::process::geteuid().as_raw(),
            "OWNER_TASK_UID",
        )?;
        ensure(
            (
                inputs.authority.registry_key.as_str(),
                inputs.authority.task_key.as_str(),
            ) == (owner.outside_keys.0.as_str(), owner.outside_keys.1.as_str()),
            "OWNER_TASK_KEYS_CHANGED",
        )?;
        let policy = crate::operator_task_policy::authenticate(
            &inputs.raw_policy,
            &inputs.authority,
            crate::operator_task_policy::now_ns().map_err(owner_error)?,
        )
        .map_err(owner_error)?;
        let old = owner.policy.context();
        let new = policy.context();
        ensure(
            new.source_commit == old.source_commit
                && new.node_policy_source == old.node_policy_source
                && new.registry2_package == old.registry2_package
                && policy.marker(&inputs.journal_path).map_err(owner_error)?
                    == owner.required_marker,
            "OWNER_TASK_NAMESPACE",
        )?;
        ensure(
            policy.next_view_of(&owner.policy),
            "OWNER_TASK_NEXT_VIEW_REQUIRED",
        )?;
        ensure(
            inputs.pool_permissions.len() <= 64,
            "OWNER_POOL_PERMISSION_LIMIT",
        )?;
        let mut pool_policies = Vec::new();
        for permission in &inputs.pool_permissions {
            let p = crate::operator_task_policy::pool::authenticate_pool(
                permission,
                &inputs.authority,
                &policy,
                crate::operator_task_policy::now_ns().map_err(owner_error)?,
            )
            .map_err(owner_error)?;
            ensure(
                !pool_policies.iter().any(
                    |p0: &std::sync::Arc<crate::operator_task_policy::pool::VerifiedPoolPolicy>| {
                        p0.same_operation(&p)
                    },
                ),
                "OWNER_POOL_DUPLICATE_PERMISSION",
            )?;
            pool_policies.push(std::sync::Arc::new(p));
        }
        crate::operator_task_policy::verify_catalog(&inputs, &policy).map_err(owner_error)?;
        let next_epoch = owner
            .epoch
            .load(std::sync::atomic::Ordering::Acquire)
            .checked_add(1)
            .ok_or("OWNER_TASK_EPOCH_OVERFLOW")?;
        let advanced = owner.journal.borrow_mut().advance(&policy);
        if let Err(error) = advanced {
            owner
                .unavailable
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(owner_error(error));
        }
        // The durable anchor is now visible; invalidate outstanding old capabilities
        // before publishing new ones. No previously committed block is rewritten.
        owner
            .epoch
            .store(next_epoch, std::sync::atomic::Ordering::Release);
        let owner = self
            .owner_policy
            .as_mut()
            .ok_or("OWNER_TASK_POLICY_REQUIRED")?;
        owner.policy = std::sync::Arc::new(policy);
        owner.pool_policies = pool_policies;
        Ok(())
    }
    fn owner_pool_configured(&self) -> Result<()> {
        ensure(
            self.mining_owner.is_none(),
            "OWNER_MINING_POOL_PURPOSE_PENDING",
        )?;
        if self.continuous_owner.is_some() {
            return self.continuous_pool_configured();
        }
        if let Some(owner) = &self.owner_policy {
            ensure(
                !owner.pool_policies.is_empty(),
                "OWNER_POOL_EXACT_COMMAND_REQUIRED",
            )?;
        }
        Ok(())
    }
    fn begin_owner_pool(
        &self,
        command: &str,
        raws: &[Vec<u8>],
        context: Hash,
    ) -> Result<Option<OwnerPoolPermit>> {
        ensure(
            self.mining_owner.is_none(),
            "OWNER_MINING_POOL_PURPOSE_PENDING",
        )?;
        if self.continuous_owner.is_some() {
            return self
                .begin_continuous_pool_command(command, raws, context)
                .map(Some);
        }
        let Some(owner) = &self.owner_policy else {
            return Ok(None);
        };
        ensure(
            !owner.unavailable.load(std::sync::atomic::Ordering::Acquire),
            "OWNER_TASK_UNAVAILABLE",
        )?;
        owner
            .policy
            .check_window(crate::operator_task_policy::now_ns().map_err(owner_error)?)
            .map_err(owner_error)?;
        let payload = crate::operator_task_policy::pool::pool_payload_sha256(command, raws)
            .map_err(owner_error)?;
        let matches: Vec<_> = owner
            .pool_policies
            .iter()
            .filter(|p| p.matches(command, &payload))
            .collect();
        ensure(matches.len() == 1, "OWNER_POOL_EXACT_COMMAND_REQUIRED")?;
        let policy = std::sync::Arc::clone(matches[0]);
        ensure(
            !owner.journal.borrow().pool_operation_is_used(&policy),
            "OWNER_POOL_OPERATION_USED",
        )?;
        // Exact command equality precedes all parent-State/lease reconstruction.
        let (parent, generation) = self.active()?;
        policy
            .check_parent(&hex::encode(parent), generation, &hex::encode(context))
            .map_err(owner_error)?;
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let task =
            bytes32(hex::decode(policy.task()).map_err(|_| Error::from("OWNER_POOL_TASK_HEX"))?)?;
        let manifest = self
            .eligible_work_task(parent, task, height)?
            .ok_or("OWNER_TASK_COMPLETE_REGISTRATION_REQUIRED")?;
        ensure(
            manifest.purpose == TaskPurpose::Maintenance,
            "OWNER_TASK_PURPOSE_PENDING",
        )?;
        ensure(
            hex::encode(manifest.model) == owner.policy.task().native_model
                && hex::encode(manifest.input) == owner.policy.task().native_input,
            "OWNER_POOL_TASK_MATERIAL_CONTEXT",
        )?;
        let lease = self
            .lifecycle_task_lease(parent, task, height)?
            .encode()
            .map_err(|_| Error::from("OWNER_TASK_LEASE"))?;
        let facts = crate::operator_task_policy::pool::PoolFacts {
            parent: hex::encode(parent),
            generation,
            pool_context: hex::encode(context),
            registered_task: hex::encode(task),
            lease_sha256: crate::operator_task_policy::digest_bytes(&lease),
            command: command.into(),
            payload_sha256: payload,
        };
        policy
            .check(
                &facts,
                crate::operator_task_policy::now_ns().map_err(owner_error)?,
            )
            .map_err(owner_error)?;
        let reservation = owner
            .journal
            .borrow_mut()
            .reserve_pool(
                &policy,
                &facts,
                crate::operator_task_policy::now_ns().map_err(owner_error)?,
            )
            .map_err(owner_error)?;
        Ok(Some(OwnerPoolPermit {
            facts,
            authentication: OwnerPoolAuthentication::Legacy {
                policy,
                unavailable: std::sync::Arc::clone(&owner.unavailable),
                epoch: std::sync::Arc::clone(&owner.epoch),
                expected_epoch: owner.epoch.load(std::sync::atomic::Ordering::Acquire),
                reservation,
            },
        }))
    }
    fn recheck_owner_pool(&self, permit: Option<&OwnerPoolPermit>) -> Result<()> {
        ensure(
            self.mining_owner.is_none(),
            "OWNER_MINING_POOL_PURPOSE_PENDING",
        )?;
        if self.continuous_owner.is_some() {
            let permit = permit.ok_or("OWNER_CONTINUOUS_POOL_PERMIT_REQUIRED")?;
            ensure(
                matches!(
                    &permit.authentication,
                    OwnerPoolAuthentication::Continuous(_)
                ),
                "OWNER_CONTINUOUS_POOL_PERMIT_REQUIRED",
            )?;
            permit.progress()?;
            ensure(
                self.active()?
                    == (
                        bytes32(
                            hex::decode(&permit.facts.parent)
                                .map_err(|_| "OWNER_POOL_PARENT_HEX")?,
                        )?,
                        permit.facts.generation,
                    ),
                "OWNER_POOL_PARENT_CHANGED",
            )?;
            return Ok(());
        }
        ensure(
            self.owner_policy.is_some() == permit.is_some(),
            "OWNER_POOL_PERMIT_REQUIRED",
        )?;
        if let (Some(owner), Some(permit)) = (&self.owner_policy, permit) {
            permit.progress()?;
            let OwnerPoolAuthentication::Legacy {
                policy,
                reservation,
                ..
            } = &permit.authentication
            else {
                return Err("OWNER_POOL_PERMIT_REQUIRED".into());
            };
            owner
                .journal
                .borrow()
                .recheck_pool(
                    policy,
                    reservation,
                    &permit.facts,
                    crate::operator_task_policy::now_ns().map_err(owner_error)?,
                )
                .map_err(owner_error)?;
            ensure(
                self.active()?
                    == (
                        bytes32(
                            hex::decode(&permit.facts.parent)
                                .map_err(|_| Error::from("OWNER_POOL_PARENT_HEX"))?,
                        )?,
                        permit.facts.generation,
                    ),
                "OWNER_POOL_PARENT_CHANGED",
            )?;
        }
        Ok(())
    }
    fn check_owner_pool_retained(
        &self,
        permit: Option<&OwnerPoolPermit>,
        raws: &[Vec<u8>],
    ) -> Result<()> {
        self.recheck_owner_pool(permit)?;
        if self.continuous_owner.is_some() {
            let Some(OwnerPoolPermit {
                authentication: OwnerPoolAuthentication::Continuous(checkpoint),
                ..
            }) = permit
            else {
                return Err("OWNER_CONTINUOUS_POOL_PERMIT_REQUIRED".into());
            };
            return checkpoint.check_retained(raws);
        }
        if let (Some(owner), Some(permit)) = (&self.owner_policy, permit) {
            let payload =
                crate::operator_task_policy::pool::pool_payload_sha256("submit-bundle", raws)
                    .map_err(owner_error)?;
            let OwnerPoolAuthentication::Legacy { policy, .. } = &permit.authentication else {
                return Err("OWNER_POOL_PERMIT_REQUIRED".into());
            };
            owner
                .journal
                .borrow()
                .prefix_group_authorized(policy, &payload)
                .map_err(owner_error)?;
        }
        Ok(())
    }
    fn owner_preview_available(&self) -> Result<()> {
        self.continuous_preview_gate()?;
        self.mining_preview_gate()?;
        ensure(
            self.owner_policy.is_none(),
            "OWNER_TASK_POOL_PREVIEW_PENDING",
        )
    }
    /// Existing Native success is not rewritten if accounting fails after commit.
    pub fn operator_task_accounting_unknown(&mut self) -> Result<()> {
        if let Some(owner) = &self.owner_policy {
            owner
                .unavailable
                .store(true, std::sync::atomic::Ordering::Release);
            owner
                .journal
                .borrow_mut()
                .mark_unavailable()
                .map_err(owner_error)?;
        }
        Ok(())
    }
    /// Work is reusable only for the owned packet; branch/state/clock checks run again.
    pub(crate) fn admit_work_checked(
        &mut self,
        checked: WorkCheckedPacket,
        observed_now: u64,
    ) -> Result<Hash> {
        self.admit_work_checked_with_progress(checked, observed_now, &|_| Ok(()))
    }
    pub(crate) fn admit_work_checked_with_progress(
        &mut self,
        checked: WorkCheckedPacket,
        observed_now: u64,
        progress: &(impl Fn(ExecutionProgress) -> Result<()> + Sync),
    ) -> Result<Hash> {
        self.admit_work_checked_with_control(
            checked,
            observed_now,
            &ExecutionControl::new(progress, &()),
        )
    }
    pub(crate) fn admit_work_checked_with_control(
        &mut self,
        checked: WorkCheckedPacket,
        observed_now: u64,
        control: &ExecutionControl<'_, Error>,
    ) -> Result<Hash> {
        let WorkCheckedPacket {
            packet,
            work: verified_work,
            owner_permit,
        } = checked;
        if let Some(id) =
            self.check_admission_context_for_permit(&packet, observed_now, owner_permit.as_ref())?
        {
            return Ok(id);
        }
        ensure(
            self.owner_policy.is_some() == owner_permit.is_some(),
            "OWNER_TASK_PERMIT_REQUIRED",
        )?;
        if let (Some(owner), Some(permit)) = (&self.owner_policy, &owner_permit) {
            ensure(
                std::sync::Arc::ptr_eq(&owner.policy, &permit.policy),
                "OWNER_TASK_STALE_POLICY",
            )?;
            ensure(
                permit.facts.packet_sha256
                    == crate::operator_task_policy::digest_bytes(&packet.encode()?),
                "OWNER_TASK_PACKET_CHANGED",
            )?;
            owner
                .journal
                .borrow()
                .recheck_before_commit(
                    &owner.policy,
                    &permit.reservation,
                    &permit.facts,
                    crate::operator_task_policy::now_ns().map_err(owner_error)?,
                )
                .map_err(owner_error)?;
        }
        // Only immutable permit/atomic flags are consulted while M06 or SQL run.
        // No journal mutex/RefCell guard or filesystem write is held across either.
        let mining_progress = self.mining_progress_snapshot()?;
        let continuous_progress = self.continuous_progress_snapshot()?;
        let guarded_progress = |point: ExecutionProgress| -> Result<()> {
            (control.progress)(point)?;
            if let Some(p) = &continuous_progress {
                p.check()?;
            }
            if let Some(p) = &mining_progress {
                p.check()?;
            }
            if let Some(permit) = &owner_permit {
                permit.progress()?;
            }
            Ok(())
        };
        let guarded_control = ExecutionControl::new(&guarded_progress, control.worker_accounting);
        let control = &guarded_control;
        let progress = control.progress;
        let bytes = packet.encode()?;
        let h = &packet.header;
        let id = packet.id()?;
        let parent = self.record(h.parent)?;
        let prior = self.state_at(h.parent)?;
        let registered_task = self.eligible_work_task_from_state(&prior, h.work_task, h.height)?;
        let executed = self.execute_derived_core(
            &prior,
            ExecutionRequest {
                transactions: &packet.transactions,
                height: h.height,
                miner: h.miner,
                parent_id: h.parent,
                workers: self.workers,
            },
            control,
            owner_permit.as_ref(),
        )?;
        let mut output = executed.output;
        let commitment = executed.commitment;
        if registered_task.manifest().is_some() {
            let product: Vec<u8> = verified_work
                .product()
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect();
            if self.record_task_output(h.height, &mut output.state, &registered_task, &product)? {
                output.root = self
                    .derive_successor(&output.state, commitment.snapshot.as_ref())?
                    .root;
            }
        }
        ensure(
            h.state == output.root && h.receipts == sequence_root("receipts", &output.receipts),
            "ROOT",
        )?;
        let work = parent
            .work
            .checked_add(consensus::required_work(h.target)?)?;
        let mut keys: std::collections::BTreeSet<_> = prior.keys().collect();
        keys.extend(output.state.keys());
        let index_context = self.ancestry_context();
        progress(ExecutionProgress::BeforePersistence)?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        ensure(
            tx.execute(
                "INSERT INTO blocks VALUES(?,?,?,?,?,?)",
                params![
                    id.as_slice(),
                    h.parent.as_slice(),
                    h.height,
                    work.bytes().as_slice(),
                    &bytes,
                    h.state.as_slice()
                ],
            )? == 1,
            "STORAGE_WRITE",
        )
        .map_err(Error::local_integrity)?;
        let inserted_ancestry = crate::ancestry_index::insert(&tx, index_context, id)?;
        let mut expected_deltas = Vec::new();
        {
            let mut insert = tx.prepare_cached("INSERT INTO deltas VALUES(?,?,?,?)")?;
            for (index, key) in keys.into_iter().enumerate() {
                progress(ExecutionProgress::PersistenceDelta { index })?;
                let before = prior.get(key).map(canonical).transpose()?;
                let after = output.state.get(key).map(canonical).transpose()?;
                if before != after {
                    ensure(
                        insert.execute(params![id.as_slice(), key, &before, &after])? == 1,
                        "STORAGE_WRITE",
                    )
                    .map_err(Error::local_integrity)?;
                    expected_deltas.push((key.clone(), before, after));
                }
            }
        }
        if h.height.is_multiple_of(128) {
            ensure(
                tx.execute(
                    "INSERT INTO snapshots VALUES(?,?)",
                    params![id.as_slice(), canonical(&output.state)?],
                )? == 1,
                "STORAGE_WRITE",
            )
            .map_err(Error::local_integrity)?;
            tx.execute("DELETE FROM snapshots WHERE block!=? AND block NOT IN (SELECT snapshots.block FROM snapshots JOIN blocks ON blocks.id=snapshots.block ORDER BY blocks.height DESC,blocks.id LIMIT 64)",[self.settings.genesis.as_slice()])?;
        }
        if self.state_backend == StateBackend::AuthenticatedV1 {
            native_authenticated::publish(
                &tx,
                &self.settings,
                h.parent,
                id,
                &prior,
                &output.state,
                &mut || progress(ExecutionProgress::BeforeDurableCommit),
            )?;
        }
        // Re-read after every write/trigger, while rollback can still remove the
        // whole block. A snapshot cannot conceal an omitted canonical delta.
        ensure(
            self.delta_rows(id)? == expected_deltas && self.packet(id)?.encode()? == bytes,
            "STORAGE_WRITE",
        )
        .map_err(Error::local_integrity)?;
        ensure(
            self.state_at(h.parent)? == prior && self.state_at(id)? == output.state,
            "STORAGE_WRITE",
        )
        .map_err(Error::local_integrity)?;
        crate::ancestry_index::verify_inserted(&tx, index_context, &inserted_ancestry)
            .map_err(Error::local_integrity)?;
        self.check_active_before_commit()?;
        progress(ExecutionProgress::BeforeDurableCommit)?;
        tx.commit()?;
        // No cancellation fence after commit: the native durable fact stays true.
        Ok(id)
    }
    pub fn make(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        max_attempts: u64,
    ) -> Result<Packet> {
        ensure(
            self.settings.task_profile() == trnm_mvcc_fee::pon_executor::LEGACY_TASK_PROFILE,
            "EXPLICIT_TASK_REQUIRED",
        )?;
        let (a, b) = maintenance();
        self.make_from_matrices(parent, transactions, miner, timestamp, max_attempts, &a, &b)
    }
    /// Explicit genesis-maintenance choice; never substitutes for rejected signed
    /// work. Admission and proof verification still use the original Node owner.
    pub fn make_consensus_maintenance(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        max_attempts: u64,
    ) -> Result<Packet> {
        ensure(
            continuity_v1::enabled(&self.settings.app),
            "CONTINUITY_PROFILE",
        )?;
        let (a, b) = continuity_v1::maintenance_matrices();
        self.make_from_matrices(parent, transactions, miner, timestamp, max_attempts, &a, &b)
    }
    pub fn parent_height(&self, parent: Hash) -> Result<u64> {
        Ok(self.record(parent)?.height)
    }
    pub fn lifecycle_task_lease(
        &self,
        parent: Hash,
        task: Hash,
        height: u64,
    ) -> Result<trnm_protocol::qualified_work_task::lifecycle_v2::DemandLeaseV2> {
        Ok(qualified_task_lifecycle::eligible_task(
            &self.state_at(parent)?,
            task,
            height,
            &self.settings.app,
        )?
        .lease()
        .clone())
    }
    /// Explicit material-bound development route; no implicit maintenance or arbitrary
    /// unsigned source/context can authorize a task in the parent's branch state.
    #[allow(clippy::too_many_arguments)]
    pub fn make_with_task(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        max_attempts: u64,
        admission: &DevelopmentTaskAdmission,
        material: TaskMaterial<'_>,
    ) -> Result<Packet> {
        self.prepare_with_task(
            parent,
            transactions,
            miner,
            timestamp,
            max_attempts,
            admission,
            material,
        )?
        .search(max_attempts)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_with_task(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        max_attempts: u64,
        admission: &DevelopmentTaskAdmission,
        material: TaskMaterial<'_>,
    ) -> Result<crate::mining::PreparedCandidate> {
        ensure(
            matches!(
                self.settings.task_profile(),
                SIGNED_TASK_PROFILE
                    | LIFECYCLE_TASK_PROFILE
                    | ATOMIC_TASK_PROFILE
                    | OVERLAP_TASK_PROFILE
                    | CONTINUITY_TASK_PROFILE
                    | CHECKPOINT_TASK_PROFILE
            ),
            "WORK_TASK_PROFILE",
        )?;
        self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let actual = self.state_at(parent)?;
        self.prepare_with_task_from_parent(
            parent,
            transactions,
            miner,
            timestamp,
            max_attempts,
            admission,
            material,
            &actual,
            None,
        )
    }
    /// The registered-material route supplies its first actual parent read. Its
    /// lifecycle eligibility was checked before source admission; V1 eligibility
    /// remains after source admission, preserving the original error order.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_with_task_from_parent(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        max_attempts: u64,
        admission: &DevelopmentTaskAdmission,
        material: TaskMaterial<'_>,
        actual: &State,
        eligibility: Option<ParentTaskEligibility>,
    ) -> Result<crate::mining::PreparedCandidate> {
        ensure(
            matches!(
                self.settings.task_profile(),
                SIGNED_TASK_PROFILE
                    | LIFECYCLE_TASK_PROFILE
                    | ATOMIC_TASK_PROFILE
                    | OVERLAP_TASK_PROFILE
                    | CONTINUITY_TASK_PROFILE
                    | CHECKPOINT_TASK_PROFILE
            ),
            "WORK_TASK_PROFILE",
        )?;
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let eligible = match eligibility {
            Some(eligible) => eligible,
            None => self.eligible_work_task_from_state(actual, admission.matrix_task(), height)?,
        };
        let signed = eligible.manifest().ok_or("TASK_MANIFEST")?;
        let statement_id = match &eligible {
            ParentTaskEligibility::Lifecycle(task) => task.statement_id(),
            _ => signed.id().map_err(|_| Error::from("TASK_MANIFEST"))?,
        };
        ensure(
            statement_id == admission.manifest_id(),
            "TASK_ADMISSION_CONTEXT",
        )?;
        ensure(
            hash(b"artifact", &[material.model]) == signed.model
                && hash(b"qualified-task-input-v1", &[material.input]) == signed.input,
            "TASK_MATERIAL",
        )?;
        let (a, b) = derive_matrices(material.model, material.input)
            .map_err(|e| Error::from(format!("TASK_MATERIAL:{e:?}")))?;
        ensure(material.a == a && material.b == b, "TASK_MATRIX_BINDING")?;
        ensure(
            pon_work::task_id(&a, &b).map_err(|_| Error::from("WORK_TASK"))? == signed.matrix_task,
            "TASK_MATRIX_BINDING",
        )?;
        ensure((1..=4096).contains(&max_attempts), "WORK_BUDGET")?;
        self.prepare_from_checked_parent(
            parent,
            transactions,
            miner,
            timestamp,
            &a,
            &b,
            actual,
            &eligible,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_with_task_from_parent_controlled(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        max_attempts: u64,
        admission: &DevelopmentTaskAdmission,
        material: TaskMaterial<'_>,
        actual: &State,
        eligibility: Option<ParentTaskEligibility>,
        control: &ExecutionControl<'_, Error>,
    ) -> Result<crate::mining::PreparedCandidate> {
        ensure(
            matches!(
                self.settings.task_profile(),
                SIGNED_TASK_PROFILE
                    | LIFECYCLE_TASK_PROFILE
                    | ATOMIC_TASK_PROFILE
                    | OVERLAP_TASK_PROFILE
                    | CONTINUITY_TASK_PROFILE
                    | CHECKPOINT_TASK_PROFILE
            ),
            "WORK_TASK_PROFILE",
        )?;
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let eligible = match eligibility {
            Some(eligible) => eligible,
            None => self.eligible_work_task_from_state(actual, admission.matrix_task(), height)?,
        };
        let signed = eligible.manifest().ok_or("TASK_MANIFEST")?;
        let statement_id = match &eligible {
            ParentTaskEligibility::Lifecycle(task) => task.statement_id(),
            _ => signed.id().map_err(|_| Error::from("TASK_MANIFEST"))?,
        };
        ensure(
            statement_id == admission.manifest_id(),
            "TASK_ADMISSION_CONTEXT",
        )?;
        ensure(
            hash(b"artifact", &[material.model]) == signed.model
                && hash(b"qualified-task-input-v1", &[material.input]) == signed.input,
            "TASK_MATERIAL",
        )?;
        let (a, b) = derive_matrices(material.model, material.input)
            .map_err(|e| Error::from(format!("TASK_MATERIAL:{e:?}")))?;
        ensure(material.a == a && material.b == b, "TASK_MATRIX_BINDING")?;
        ensure(
            pon_work::task_id(&a, &b).map_err(|_| Error::from("WORK_TASK"))? == signed.matrix_task,
            "TASK_MATRIX_BINDING",
        )?;
        ensure((1..=4096).contains(&max_attempts), "WORK_BUDGET")?;
        self.prepare_from_checked_parent_controlled(
            parent,
            transactions,
            miner,
            timestamp,
            &a,
            &b,
            actual,
            &eligible,
            control,
        )
    }
    fn eligible_work_task(
        &self,
        parent: Hash,
        task: Hash,
        height: u64,
    ) -> Result<Option<QualifiedWorkTask>> {
        Ok(self
            .eligible_work_task_from_state(&self.state_at(parent)?, task, height)?
            .manifest()
            .cloned())
    }
    fn eligible_work_task_from_state(
        &self,
        state: &State,
        task: Hash,
        height: u64,
    ) -> Result<ParentTaskEligibility> {
        if continuity_v1::enabled(&self.settings.app) && task == continuity_v1::maintenance_task()?
        {
            continuity_v1::check_maintenance(state, task, &self.settings.app)?;
            return Ok(ParentTaskEligibility::ConsensusMaintenance);
        }
        if matches!(
            self.settings.task_profile(),
            LIFECYCLE_TASK_PROFILE
                | ATOMIC_TASK_PROFILE
                | OVERLAP_TASK_PROFILE
                | CONTINUITY_TASK_PROFILE
                | CHECKPOINT_TASK_PROFILE
        ) {
            let eligible =
                qualified_task_lifecycle::eligible_task(state, task, height, &self.settings.app)?;
            return Ok(ParentTaskEligibility::Lifecycle(Box::new(eligible)));
        }
        let registered = state
            .get(&format!("work:{}", hex::encode(task)))
            .ok_or("TASK")?;
        if self.settings.task_profile() != SIGNED_TASK_PROFILE {
            ensure(registered == &Value::Bool(true), "TASK")?;
            return Ok(ParentTaskEligibility::Legacy);
        }
        ensure(
            registered["schema"] == "qualified-work-registration-v1",
            "TASK_MANIFEST",
        )?;
        ensure(
            registered["admitted_height"]
                .as_u64()
                .ok_or("TASK_MANIFEST")?
                < height,
            "TASK_PARENT",
        )?;
        let text = registered["manifest"].as_str().ok_or("TASK_MANIFEST")?;
        ensure(text.len() == SIGNED_TASK_BYTES * 2, "TASK_MANIFEST")?;
        let bytes = hex::decode(text).map_err(|_| Error::from("TASK_MANIFEST"))?;
        ensure(hex::encode(&bytes) == text, "TASK_MANIFEST")?;
        let signed =
            SignedQualifiedWorkTask::decode(&bytes).map_err(|_| Error::from("TASK_MANIFEST"))?;
        ensure(signed.manifest.matrix_task == task, "TASK")?;
        let context = self
            .settings
            .qualified_task_context(signed.manifest.demand_id, height)?;
        let verified = verify_development_statement(&bytes, &context)
            .map_err(|e| Error::from(format!("TASK_STATEMENT:{e:?}")))?;
        ensure(
            registered["manifest_id"] == hex::encode(verified.manifest_id()),
            "TASK_MANIFEST",
        )?;
        ensure(
            state.get(&format!("work-withdrawal:{}", hex::encode(context.source)))
                == Some(&json_value(hex::encode(context.withdrawal_head))),
            "TASK_WITHDRAWAL",
        )?;
        let demand = state
            .get(&format!(
                "work-demand-registry:{}",
                hex::encode(context.demand_id)
            ))
            .ok_or("TASK_DEMAND")?;
        ensure(
            demand["purpose"].as_u64() == Some(signed.manifest.purpose as u64),
            "TASK_PURPOSE",
        )?;
        ensure(
            state.get(&format!("work-demand:{}", hex::encode(context.demand_id)))
                == Some(&json_value(hex::encode(verified.manifest_id()))),
            "TASK_DEMAND",
        )?;
        let source_nonce = state
            .get(&format!("work-source:{}", hex::encode(context.source)))
            .and_then(Value::as_u64)
            .ok_or("TASK_SOURCE_NONCE")?;
        ensure(
            source_nonce >= signed.manifest.demand_nonce,
            "TASK_SOURCE_NONCE",
        )?;
        Ok(ParentTaskEligibility::Signed(Box::new(signed.manifest)))
    }
    #[allow(clippy::too_many_arguments)]
    fn make_from_matrices(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        max_attempts: u64,
        a: &[u32],
        b: &[u32],
    ) -> Result<Packet> {
        ensure((1..=4096).contains(&max_attempts), "WORK_BUDGET")?;
        self.prepare_from_matrices(parent, transactions, miner, timestamp, a, b)?
            .search(max_attempts)
    }
    pub(crate) fn prepare_from_matrices(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        a: &[u32],
        b: &[u32],
    ) -> Result<crate::mining::PreparedCandidate> {
        self.ready()?;
        let height = self.record(parent)?.height.checked_add(1).ok_or("HEIGHT")?;
        let task = pon_work::task_id(a, b).map_err(|_| Error::from("WORK_TASK"))?;
        let actual = self.state_at(parent)?;
        let registered_task = self.eligible_work_task_from_state(&actual, task, height)?;
        self.prepare_from_checked_parent(
            parent,
            transactions,
            miner,
            timestamp,
            a,
            b,
            &actual,
            &registered_task,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_from_checked_parent(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        a: &[u32],
        b: &[u32],
        actual: &State,
        registered_task: &ParentTaskEligibility,
    ) -> Result<crate::mining::PreparedCandidate> {
        self.ready()?;
        let height = self.record(parent)?.height.checked_add(1).ok_or("HEIGHT")?;
        let task = pon_work::task_id(a, b).map_err(|_| Error::from("WORK_TASK"))?;
        let executed =
            self.execute_derived(actual, parent, &transactions, height, miner, self.workers)?;
        let mut output = executed.output;
        let commitment = executed.commitment;
        let prepared =
            pon_work::PreparedTask::new(a, b).map_err(|e| Error::from(format!("WORK:{e:?}")))?;
        if registered_task.manifest().is_some()
            && self.record_task_output(
                height,
                &mut output.state,
                registered_task,
                prepared.product_bytes(),
            )?
        {
            output.root = self
                .derive_successor(&output.state, commitment.snapshot.as_ref())?
                .root;
        }
        let header = Header {
            network: self.settings.network(),
            parameters: self.settings.parameters(),
            parent,
            height,
            timestamp,
            target: self.expected_target(parent)?,
            miner,
            transactions: sequence_root("transactions", &transactions),
            state: output.root,
            receipts: sequence_root("receipts", &output.receipts),
            work_task: task,
            nonce: 0,
        };
        Ok(crate::mining::PreparedCandidate {
            header,
            transactions,
            prepared,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_from_checked_parent_controlled(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        a: &[u32],
        b: &[u32],
        actual: &State,
        registered_task: &ParentTaskEligibility,
        control: &ExecutionControl<'_, Error>,
    ) -> Result<crate::mining::PreparedCandidate> {
        self.ready()?;
        let height = self.record(parent)?.height.checked_add(1).ok_or("HEIGHT")?;
        let task = pon_work::task_id(a, b).map_err(|_| Error::from("WORK_TASK"))?;
        let executed = self.execute_derived_with_control(
            actual,
            ExecutionRequest {
                transactions: &transactions,
                height,
                miner,
                parent_id: parent,
                workers: self.workers,
            },
            control,
        )?;
        let mut output = executed.output;
        let commitment = executed.commitment;
        let prepared =
            pon_work::PreparedTask::new(a, b).map_err(|e| Error::from(format!("WORK:{e:?}")))?;
        if registered_task.manifest().is_some()
            && self.record_task_output(
                height,
                &mut output.state,
                registered_task,
                prepared.product_bytes(),
            )?
        {
            output.root = self
                .derive_successor(&output.state, commitment.snapshot.as_ref())?
                .root;
        }
        let header = Header {
            network: self.settings.network(),
            parameters: self.settings.parameters(),
            parent,
            height,
            timestamp,
            target: self.expected_target(parent)?,
            miner,
            transactions: sequence_root("transactions", &transactions),
            state: output.root,
            receipts: sequence_root("receipts", &output.receipts),
            work_task: task,
            nonce: 0,
        };
        Ok(crate::mining::PreparedCandidate {
            header,
            transactions,
            prepared,
        })
    }
    fn record_task_output(
        &self,
        height: u64,
        state: &mut State,
        eligible: &ParentTaskEligibility,
        product: &[u8],
    ) -> Result<bool> {
        match eligible {
            ParentTaskEligibility::Lifecycle(task) => {
                ensure(product.len() == pon_work::CELLS * 4, "TASK_OUTPUT")?;
                Ok(qualified_task_lifecycle::consume_output(
                    state,
                    task,
                    hash(b"qualified-task-product-v1", &[product]),
                    height,
                )?)
            }
            ParentTaskEligibility::Signed(manifest) => record_task_output(state, manifest, product),
            ParentTaskEligibility::Legacy | ParentTaskEligibility::ConsensusMaintenance => {
                Ok(false)
            }
        }
    }
    pub fn mine(
        &mut self,
        transactions: Vec<Vec<u8>>,
        timestamp: u64,
        observed_now: u64,
    ) -> Result<Packet> {
        let packet = self.make(
            self.active()?.0,
            transactions,
            development_public(0)?,
            timestamp,
            4096,
        )?;
        let id = self.admit(&packet, observed_now)?;
        self.activate_observed(id, observed_now)?;
        Ok(packet)
    }
    fn atomic<T>(&self, run: impl FnOnce() -> Result<T>) -> Result<T> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let result = run()?;
        self.check_active_before_commit()?;
        self.continuous_scope_checkpoint()?;
        self.mining_scope_checkpoint()?;
        tx.commit()?;
        Ok(result)
    }
    fn apply_delta(&self, id: Hash, slot: u64, detach: bool) -> Result<()> {
        let mut read = self
            .db
            .prepare_cached("SELECT value FROM kv WHERE slot=? AND key=?")?;
        let mut write = self
            .db
            .prepare_cached("INSERT OR REPLACE INTO kv VALUES(?,?,?)")?;
        let mut delete = self
            .db
            .prepare_cached("DELETE FROM kv WHERE slot=? AND key=?")?;
        for (key, before, after) in self.delta_rows(id)? {
            let (expected, new) = if detach {
                (after, before)
            } else {
                (before, after)
            };
            let actual: Option<Vec<u8>> = read
                .query_row(params![slot, &key], |r| r.get(0))
                .optional()?;
            ensure(actual == expected, "UNDO_ROOT").map_err(Error::local_integrity)?;
            if let Some(value) = new {
                ensure(
                    write.execute(params![slot, key, value])? == 1,
                    "STORAGE_WRITE",
                )
                .map_err(Error::local_integrity)?;
            } else {
                ensure(delete.execute(params![slot, key])? == 1, "STORAGE_WRITE")
                    .map_err(Error::local_integrity)?;
            }
        }
        Ok(())
    }
    pub fn activate(&mut self, target: Hash) -> Result<Hash> {
        self.activate_with_fault(target, None)
    }
    pub fn activate_with_fault(
        &mut self,
        target: Hash,
        mut hook: Option<&mut Hook<'_>>,
    ) -> Result<Hash> {
        self.continuous_activation_gate(target)?;
        self.mining_activation_gate(target)?;
        self.namespace()?;
        self.resume_intent(&mut hook)?;
        let (old, g) = self.active()?;
        if self.record(target)?.work <= self.record(old)?.work {
            return Ok(old);
        }
        let next = g
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or("GENERATION")?;
        if self.record(target)?.parent == Some(old) && hook.is_none() {
            let slot = self.slot()?;
            let prior = self.cached_parent(old)?;
            let mut staged = None;
            self.atomic(|| {
                self.apply_delta(target, slot, false)?;
                let state = self.slot_state(slot)?;
                continuity_v1::check_state(&state, self.record(target)?.height, &self.settings.app)
                    .map_err(|error| Error::from(error).local_integrity())?;
                staged = Some(self.checked_commitment(
                    &state,
                    self.record(target)?.root,
                    prior.as_ref(),
                )?);
                ensure(
                    self.db.execute(
                        "UPDATE active SET tip=?,generation=? WHERE singleton=1",
                        params![target.as_slice(), next],
                    )? == 1,
                    "STORAGE_WRITE",
                )
                .map_err(Error::local_integrity)?;
                ensure(
                    self.db.execute(
                        "INSERT INTO events VALUES(?,0,1,?)",
                        params![next, target.as_slice()],
                    )? == 1,
                    "STORAGE_WRITE",
                )
                .map_err(Error::local_integrity)?;
                ensure(
                    self.active()? == (target, next) && self.slot()? == slot,
                    "GENERATION",
                )
                .map_err(Error::local_integrity)?;
                self.check_events(next, &[(0, 1, target)])?;
                Ok(())
            })?;
            ensure(
                self.active()? == (target, next) && self.slot()? == slot,
                "GENERATION",
            )
            .map_err(Error::local_integrity)?;
            self.publish_commitment(target, next, slot, staged.ok_or("ROOT")?);
            return Ok(target);
        }
        // Reorganizations retain the independent full-root path and reseed only
        // after actual durable publication/recovery, never from a stale preview.
        self.invalidate_commitment();
        self.atomic(|| {
            self.db.execute("DELETE FROM kv WHERE slot=?", [next])?;
            self.db.execute(
                "INSERT INTO kv SELECT ?,key,value FROM kv WHERE slot=?",
                params![next, self.slot()?],
            )?;
            self.db.execute("DELETE FROM steps", [])?;
            let mut left = old;
            let mut right = target;
            let mut detached = 0i64;
            let mut attached = 0i64;
            while left != right {
                if self.record(left)?.height >= self.record(right)?.height {
                    self.db.execute(
                        "INSERT INTO steps VALUES(?,0,?)",
                        params![detached, left.as_slice()],
                    )?;
                    detached = detached.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
                    left = self.parent(left)?;
                } else {
                    attached = attached.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
                    self.db.execute(
                        "INSERT INTO steps VALUES(?,1,?)",
                        params![-attached, right.as_slice()],
                    )?;
                    right = self.parent(right)?;
                }
            }
            let count = detached.checked_add(attached).ok_or("ANCESTRY_LIMIT")?;
            self.db.execute(
                "UPDATE steps SET ordinal=?+ordinal WHERE ordinal<0",
                [count],
            )?;
            self.db.execute(
                "INSERT OR REPLACE INTO reorg VALUES(1,?,?,?,0,0)",
                params![old.as_slice(), target.as_slice(), next],
            )?;
            ensure(
                self.active()? == (old, g) && self.check_steps(old, target, 0)? == count as u64,
                "REORG_STEPS",
            )
            .map_err(Error::local_integrity)?;
            self.check_reorg_row(old, target, next, 0, 0)?;
            self.check_persisted_state(old, &self.slot_state(next)?, &mut || Ok(()))?;
            Ok(())
        })?;
        cut(&mut hook, "intent")?;
        self.resume_intent(&mut hook)
    }
    fn check_steps(&self, old: Hash, target: Hash, cursor: u64) -> Result<u64> {
        let mut stmt = self
            .db
            .prepare("SELECT ordinal,kind,block FROM steps ORDER BY ordinal")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, u64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut current = old;
        let mut count = 0u64;
        let mut attaching = false;
        for row in rows {
            let (ordinal, kind, bytes) = row?;
            let id = bytes32(bytes)?;
            ensure(ordinal == count, "REORG_STEPS").map_err(Error::local_integrity)?;
            match kind {
                0 => {
                    ensure(!attaching && id == current, "REORG_STEPS")
                        .map_err(Error::local_integrity)?;
                    current = self.parent(id)?;
                }
                1 => {
                    attaching = true;
                    ensure(self.parent(id)? == current, "REORG_STEPS")
                        .map_err(Error::local_integrity)?;
                    current = id;
                }
                _ => return Err(Error::from("REORG_STEPS").local_integrity()),
            }
            count = count.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
        }
        ensure(current == target && cursor <= count, "REORG_STEPS")
            .map_err(Error::local_integrity)?;
        Ok(count)
    }
    fn check_reorg_row(
        &self,
        old: Hash,
        target: Hash,
        generation: u64,
        cursor: u64,
        done: u64,
    ) -> Result<()> {
        let rows: Vec<ReorgRow> = self
            .db
            .prepare("SELECT old_tip,new_tip,generation,cursor,done FROM reorg ORDER BY singleton")?
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?
            .collect::<std::result::Result<_, _>>()?;
        ensure(
            rows == vec![(old.to_vec(), target.to_vec(), generation, cursor, done)],
            "REORG_STEPS",
        )
        .map_err(Error::local_integrity)
    }
    fn check_events(&self, generation: u64, expected: &[(u64, u64, Hash)]) -> Result<()> {
        let rows: Vec<(u64, u64, Vec<u8>)> = self
            .db
            .prepare("SELECT ordinal,kind,block FROM events WHERE generation=? ORDER BY ordinal")?
            .query_map([generation], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        let expected: Vec<_> = expected
            .iter()
            .map(|(ordinal, kind, id)| (*ordinal, *kind, id.to_vec()))
            .collect();
        ensure(rows == expected, "REORG_EVENTS").map_err(Error::local_integrity)
    }
    fn resume_intent(&mut self, hook: &mut Option<&mut Hook<'_>>) -> Result<Hash> {
        let row = self
            .db
            .query_row(
                "SELECT old_tip,new_tip,generation,cursor,done FROM reorg WHERE singleton=1",
                [],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, u64>(2)?,
                        r.get::<_, u64>(3)?,
                        r.get::<_, u64>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((old, target, g, position, done)) = row else {
            return Ok(self.active()?.0);
        };
        ensure(done <= 1, "REORG_STEPS").map_err(Error::local_integrity)?;
        if done == 1 {
            return Ok(self.active()?.0);
        }
        self.invalidate_commitment();
        let old = bytes32(old)?;
        let target = bytes32(target)?;
        ensure(g > 0 && self.active()? == (old, g - 1), "GENERATION")
            .map_err(Error::local_integrity)?;
        let count = self
            .check_steps(old, target, position)
            .map_err(Error::local_integrity)?;
        for index in position..count {
            let (kind, bytes) = self.db.query_row(
                "SELECT kind,block FROM steps WHERE ordinal=?",
                [index],
                |r| Ok((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )?;
            let id = bytes32(bytes)?;
            self.atomic(|| {
                self.apply_delta(id, g, kind == 0)?;
                ensure(
                    self.db
                        .execute("UPDATE reorg SET cursor=? WHERE singleton=1", [index + 1])?
                        == 1,
                    "STORAGE_WRITE",
                )
                .map_err(Error::local_integrity)?;
                self.check_reorg_row(old, target, g, index + 1, 0)?;
                let resulting = if kind == 0 { self.parent(id)? } else { id };
                self.check_persisted_state(resulting, &self.slot_state(g)?, &mut || Ok(()))?;
                Ok(())
            })?;
            cut(
                hook,
                &format!("{}:{index}", if kind == 0 { "detach" } else { "attach" }),
            )?;
        }
        let state = self.slot_state(g)?;
        continuity_v1::check_state(&state, self.record(target)?.height, &self.settings.app)
            .map_err(|error| Error::from(error).local_integrity())?;
        ensure(root(&state)? == self.record(target)?.root, "ROOT")
            .map_err(Error::local_integrity)?;
        cut(hook, "before-publish")?;
        self.atomic(|| {
            let expected: Vec<(u64, u64, Hash)> = self
                .db
                .prepare("SELECT ordinal,kind,block FROM steps ORDER BY ordinal")?
                .query_map([], |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })?
                .map(|row| {
                    let (ordinal, kind, id) = row?;
                    Ok((ordinal, kind, bytes32(id)?))
                })
                .collect::<Result<_>>()?;
            ensure(
                self.db.execute(
                    "UPDATE active SET tip=?,generation=?,state_slot=? WHERE singleton=1",
                    params![target.as_slice(), g, g],
                )? == 1,
                "STORAGE_WRITE",
            )
            .map_err(Error::local_integrity)?;
            ensure(
                self.db.execute(
                    "INSERT INTO events SELECT ?,ordinal,kind,block FROM steps ORDER BY ordinal",
                    [g],
                )? == expected.len(),
                "STORAGE_WRITE",
            )
            .map_err(Error::local_integrity)?;
            ensure(
                self.db
                    .execute("UPDATE reorg SET done=1 WHERE singleton=1", [])?
                    == 1,
                "STORAGE_WRITE",
            )
            .map_err(Error::local_integrity)?;
            self.db.execute("DELETE FROM kv WHERE slot!=?", [g])?;
            ensure(
                self.active()? == (target, g) && self.slot()? == g,
                "GENERATION",
            )
            .map_err(Error::local_integrity)?;
            self.check_reorg_row(old, target, g, count, 1)?;
            self.check_events(g, &expected)?;
            self.check_persisted_state(target, &self.slot_state(g)?, &mut || Ok(()))?;
            Ok(())
        })?;
        cut(hook, "published")?;
        Ok(target)
    }
    pub fn recover(&mut self) -> Result<Hash> {
        if let Some(tip) = self.continuous_recovery_unchanged()? {
            return Ok(tip);
        }
        if let Some(tip) = self.mining_recovery_unchanged()? {
            return Ok(tip);
        }
        self.invalidate_commitment();
        self.namespace()?;
        self.resume_intent(&mut None)?;
        let best: Vec<u8> = self.db.query_row(
            "SELECT id FROM blocks ORDER BY chainwork DESC,height,id LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        self.activate(bytes32(best)?)
    }
    pub fn check_observed_history(&self, tip: Hash, observed_now: u64) -> Result<()> {
        let bound = observed_now as u128 + self.settings.limit("future_skew_seconds")? as u128;
        let mut current = tip;
        while current != self.settings.genesis() {
            (current, _) = self.visit_header_batch(current, &mut |_, link| {
                ensure(link.header.timestamp as u128 <= bound, "TIME_DEFERRED")
            })?;
        }
        Ok(())
    }
    pub fn activate_observed(&mut self, tip: Hash, observed_now: u64) -> Result<Hash> {
        self.continuous_activation_gate(tip)?;
        self.mining_activation_gate(tip)?;
        self.check_observed_history(tip, observed_now)?;
        self.activate(tip)
    }
    pub fn confirmation(
        &self,
        transaction: Hash,
        included: Hash,
        observed_now: u64,
    ) -> Result<Observation> {
        self.confirmations(&[(transaction, included)], observed_now)?
            .observations
            .into_iter()
            .next()
            .ok_or_else(|| "EMPTY_CONFIRMATION".into())
    }
    pub fn confirmations(
        &self,
        queries: &[(Hash, Hash)],
        observed_now: u64,
    ) -> Result<ConfirmationBatch> {
        self.confirmations_with_progress(queries, observed_now, &mut |_| Ok(()))
    }
    /// Cancellation produces no partial batch and never stores a reusable clock verdict.
    pub fn confirmations_with_progress(
        &self,
        queries: &[(Hash, Hash)],
        observed_now: u64,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<ConfirmationBatch> {
        use std::collections::BTreeSet;
        ensure((1..=256).contains(&queries.len()), "CONFIRMATION_LIMIT")?;
        let unique: BTreeSet<_> = queries.iter().copied().collect();
        ensure(unique.len() == queries.len(), "DUPLICATE_QUERY")?;
        progress(0)?;
        self.ready()?;
        let (tip, generation, _) = self.read_active_with_progress(&mut || progress(0))?;
        let mut included = BTreeMap::new();
        for (transaction, block) in queries {
            if !included.contains_key(block) {
                let row = self.record(*block)?;
                let packet = self.packet(*block)?;
                ensure(
                    packet.header.transactions
                        == sequence_root("transactions", &packet.transactions),
                    "ROOT",
                )?;
                let members: BTreeSet<_> = packet
                    .transactions
                    .iter()
                    .map(|raw| hash(b"tx-id", &[raw]))
                    .collect();
                included.insert(*block, (row, packet.header.target, members));
            }
            ensure(included[block].2.contains(transaction), "MEMBERSHIP")?;
        }
        let observed = self.record(tip)?;
        let mut current = tip;
        let mut found = BTreeSet::new();
        let mut checked = 0u64;
        let bound = observed_now as u128 + self.settings.limit("future_skew_seconds")? as u128;
        while current != self.settings.genesis() {
            // The prior query has ended before cancellation or caller code runs.
            progress(checked)?;
            let (parent, count) = self.visit_header_batch(current, &mut |id, link| {
                if included.contains_key(&id) {
                    found.insert(id);
                }
                ensure(link.header.timestamp as u128 <= bound, "TIME_DEFERRED")
            })?;
            current = parent;
            checked = checked.checked_add(count).ok_or("ANCESTRY_LIMIT")?;
        }
        let depth_required = self.settings.limit("confirmation_depth")?;
        let multiplier = self.settings.limit("confirmation_work_multiplier")?;
        let mut observations = Vec::with_capacity(queries.len());
        for (transaction, block) in queries {
            let (row, target, _) = &included[block];
            let present = found.contains(block);
            let delta = present
                .then(|| observed.work.checked_sub(row.work))
                .transpose()?;
            let depth = present
                .then(|| observed.height.checked_sub(row.height).ok_or("HEIGHT"))
                .transpose()?;
            let threshold = consensus::required_work(*target)?.mul_small(multiplier)?;
            observations.push(Observation {
                transaction: hex::encode(transaction),
                genesis: hex::encode(self.settings.genesis()),
                policy: "installed-depth-and-required-work".into(),
                required_work_delta: hex::encode(threshold.bytes()),
                network: hex::encode(self.settings.network()),
                parameters: hex::encode(self.settings.parameters()),
                included_block: hex::encode(block),
                observed_tip: hex::encode(tip),
                included_height: row.height,
                observed_height: observed.height,
                depth,
                work_delta: delta.map(|w| hex::encode(w.bytes())),
                active_generation: generation,
                observed_now,
                confirmed: depth.is_some_and(|d| d >= depth_required)
                    && delta.is_some_and(|w| w >= threshold),
                reorged: !present,
                finalized: false,
                execution_authority: false,
            });
        }
        progress(checked)?;
        ensure(self.active()? == (tip, generation), "STALE_VIEW")?;
        Ok(ConfirmationBatch {
            observations,
            ancestry_checked: checked,
            distinct_bodies_checked: included.len(),
        })
    }
    /// Bounded public-read metadata. The state root is the admitted header's
    /// commitment, not a fresh scan or audit of the active key/value state.
    pub(crate) fn public_head_metadata(&self) -> Result<Value> {
        self.ready()?;
        let (tip, generation) = self.active()?;
        let row = self.record(tip)?;
        Ok(serde_json::json!({
            "network":hex::encode(self.settings.network()),
            "parameters":hex::encode(self.settings.parameters()),
            "genesis":hex::encode(self.settings.genesis()),
            "tip":hex::encode(tip),"height":row.height,
            "chainwork_hex":hex::encode(row.work.bytes()),
            "state_root":hex::encode(row.root),"generation":generation,
            "context_matches":true,
            "commitment_scope":"admitted-active-header; no fresh key/value audit",
            "production_activation":false
        }))
    }
    /// One public history packet, with exact ancestry and pre-allocation bounds.
    /// No unbounded tempfile spool or multi-packet JSON value is constructed.
    pub(crate) fn public_history_packet(
        &self,
        tip: Hash,
        after: Hash,
        maximum_steps: u64,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<Vec<Packet>> {
        progress(0)?;
        self.ready()?;
        let lookup = crate::ancestry_index::next(
            &self.db,
            self.ancestry_context(),
            tip,
            after,
            maximum_steps,
            progress,
        )?;
        let Some(id) = lookup.next else {
            return Ok(Vec::new());
        };
        progress(lookup.sql_lookups + 1)?;
        // Query the scalar length before materializing a possibly damaged BLOB.
        let maximum = 1_048_576;
        let length: Option<usize> = self.db.query_row(
            "SELECT length(packet) FROM blocks WHERE id=?",
            [id.as_slice()],
            |r| r.get(0),
        )?;
        ensure(
            length.is_some_and(|n| n > 0 && n <= maximum),
            "PUBLIC_HISTORY_BYTES",
        )
        .map_err(Error::local_integrity)?;
        progress(lookup.sql_lookups + 2)?;
        let raw: Vec<u8> = self.db.query_row(
            "SELECT packet FROM blocks WHERE id=? AND length(packet)<=?",
            params![id.as_slice(), maximum],
            |r| r.get(0),
        )?;
        let packet = Packet::decode(&raw).map_err(Error::local_integrity)?;
        ensure(
            packet.id()? == id
                && packet.header.parent == after
                && packet.header.height == lookup.height,
            "STORAGE_PACKET",
        )?;
        Ok(vec![packet])
    }
    pub fn stats(&self) -> Result<Value> {
        let (tip, g, state) = self.read_active()?;
        let row = self.record(tip)?;
        let blocks: u64 = self
            .db
            .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))?;
        let events: u64 = self
            .db
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        let (authenticated_sessions, authenticated_pending, authenticated_audit_rows) =
            self.authenticated_replay_counts()?;
        let (authenticated_outbox_sessions, authenticated_outbox_pending) =
            self.authenticated_outbox_counts()?;
        Ok(
            serde_json::json!({"network":hex::encode(self.settings.network()),"parameters":hex::encode(self.settings.parameters()),"genesis":hex::encode(self.settings.genesis()),"tip":hex::encode(tip),"height":row.height,"chainwork_hex":hex::encode(row.work.bytes()),"state_root":hex::encode(root(&state)?),"generation":g,"state_keys":state.len(),"stored_blocks":blocks,"events":events,"authenticated_sessions":authenticated_sessions,"authenticated_pending":authenticated_pending,"authenticated_audit_rows":authenticated_audit_rows,"authenticated_outbox_sessions":authenticated_outbox_sessions,"authenticated_outbox_pending":authenticated_outbox_pending,"production_activation":false}),
        )
    }
}

#[cfg(test)]
mod error_boundary_tests {
    use super::*;
    use crate::{ErrorCode, ErrorKind};
    use std::error::Error as _;

    fn packet(node: &Node, parent: Hash, timestamp: u64, miner: u64) -> Packet {
        node.make(
            parent,
            vec![],
            development_public(miner).unwrap(),
            timestamp,
            4096,
        )
        .unwrap()
    }
    fn local(error: Error, message: &str) {
        assert_eq!(error.to_string(), message);
        assert_eq!(error.kind(), ErrorKind::LocalStructure);
        assert!(error.requires_owner_stop());
    }

    fn replay_frame(settings: &Settings, nonce: u64, payload: &[u8]) -> AuthenticatedPeerFrameV0 {
        let session = PeerSessionIdentityV0::new(
            IoDigest32V0::new(settings.genesis()).unwrap(),
            IoDigest32V0::new(settings.parameters()).unwrap(),
            IoDigest32V0::new([71; 32]).unwrap(),
            IoDigest32V0::new([72; 32]).unwrap(),
            IoDigest32V0::new(crate::authenticated_profile_digest()).unwrap(),
            1,
        )
        .unwrap();
        AuthenticatedPeerFrameV0::new(
            session,
            nonce,
            IoDigest32V0::new(crate::authenticated_payload_digest(payload)).unwrap(),
            payload.len(),
        )
        .unwrap()
    }

    #[test]
    fn retained_completed_reply_shape_stops_and_exact_repair_restores_cached_replay() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let payload = b"completed journal request";
        let response = b"completed journal response";
        let frame = replay_frame(&settings, 1, payload);
        node.begin_authenticated_request(frame, payload).unwrap();
        node.finish_authenticated_request(frame, response).unwrap();
        let counts = node.authenticated_replay_counts().unwrap();

        for (status, damaged_response) in [(1_u64, None), (2_u64, Some(response.as_slice()))] {
            node.db
                .execute(
                    "UPDATE peer_request_audit SET status=?,response=? WHERE session_id=? AND nonce=1",
                    params![status, damaged_response, frame.session().session_id().bytes().as_slice()],
                )
                .unwrap();
            let error = node
                .begin_authenticated_request(frame, payload)
                .unwrap_err();
            assert!(error.is(ErrorCode::AuthReplayAudit));
            assert!(!Error::remote(error.to_string()).requires_owner_stop());
            assert!(!Error::from(error.to_string()).requires_owner_stop());
            local(error, "AUTH_REPLAY_AUDIT");
            assert_eq!(node.authenticated_replay_counts().unwrap(), counts);
        }
        node.db
            .execute(
                "UPDATE peer_request_audit SET status=1,response=? WHERE session_id=? AND nonce=1",
                params![
                    response.as_slice(),
                    frame.session().session_id().bytes().as_slice()
                ],
            )
            .unwrap();
        node.validate_authenticated_replay().unwrap();
        drop(node);
        let mut reopened = Node::open(directory.path(), settings, 1).unwrap();
        assert!(matches!(
            reopened.begin_authenticated_request(frame, payload).unwrap(),
            AuthenticatedReplayDecision::Cached(bytes) if bytes == response
        ));
        assert_eq!(reopened.authenticated_replay_counts().unwrap(), counts);
    }

    #[test]
    fn incoming_replay_payload_pending_and_ack_failures_keep_transport_enum_identity() {
        use trnm_transport::{PeerAdmissionErrorV0 as Peer, PeerFrameVerificationErrorV0};

        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let payload = b"real payload";
        let frame = replay_frame(&settings, 1, payload);
        let error = node
            .begin_authenticated_request(frame, b"bad payload")
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "AUTH_FRAME:peer frame source rejected: AUTH_PAYLOAD"
        );
        assert_eq!(error.kind(), ErrorKind::ProtocolInvalid);
        assert!(!error.requires_owner_stop());
        assert!(matches!(
            error.source().unwrap().downcast_ref::<PeerFrameVerificationErrorV0<Error>>(),
            Some(PeerFrameVerificationErrorV0::Source(source)) if source.is(ErrorCode::AuthPayload)
        ));
        assert_eq!(node.authenticated_replay_counts().unwrap(), (0, 0, 0));
        node.begin_authenticated_request(frame, payload).unwrap();
        let counts = node.authenticated_replay_counts().unwrap();
        let conflict = replay_frame(&settings, 1, b"new payload");
        let successor = replay_frame(&settings, 2, payload);
        for (candidate, bytes, cause, kind) in [
            (
                conflict,
                b"new payload".as_slice(),
                Peer::ConflictingReplay,
                ErrorKind::IdentityConflict,
            ),
            (
                successor,
                payload.as_slice(),
                Peer::PendingFrame,
                ErrorKind::Capacity,
            ),
        ] {
            let error = node
                .begin_authenticated_request(candidate, bytes)
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("AUTH_FRAME:peer frame boundary failed: {cause}")
            );
            assert_eq!(error.kind(), kind);
            assert!(!error.requires_owner_stop());
            assert!(matches!(
                error.source().unwrap().downcast_ref::<PeerFrameVerificationErrorV0<Error>>(),
                Some(PeerFrameVerificationErrorV0::Boundary(source)) if *source == cause
            ));
            assert_eq!(node.authenticated_replay_counts().unwrap(), counts);
        }
        let error = node
            .finish_authenticated_request(conflict, b"reply")
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("AUTH_REPLAY:{}", Peer::UnexpectedAcknowledgement)
        );
        assert_eq!(error.kind(), ErrorKind::IdentityConflict);
        assert_eq!(
            error.source().unwrap().downcast_ref::<Peer>(),
            Some(&Peer::UnexpectedAcknowledgement)
        );
        assert!(!error.requires_owner_stop());
        assert_eq!(
            node.authenticated_replay_state(frame.session())
                .unwrap()
                .unwrap()
                .pending(),
            Some(frame)
        );
        node.finish_authenticated_request(frame, b"reply").unwrap();

        node.reserve_authenticated_outbound(frame, payload, b"retained wire")
            .unwrap();
        let error = node
            .reserve_authenticated_outbound(conflict, b"new payload", b"other wire")
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "AUTH_OUTBOX_FRAME:peer frame boundary failed: {}",
                Peer::ConflictingReplay
            )
        );
        assert_eq!(error.kind(), ErrorKind::IdentityConflict);
        assert!(!error.requires_owner_stop());
        assert!(matches!(
            error
                .source()
                .unwrap()
                .downcast_ref::<PeerFrameVerificationErrorV0<Error>>(),
            Some(PeerFrameVerificationErrorV0::Boundary(
                Peer::ConflictingReplay
            ))
        ));
        let error = node.finish_authenticated_outbound(conflict).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::IdentityConflict);
        assert_eq!(
            error.source().unwrap().downcast_ref::<Peer>(),
            Some(&Peer::UnexpectedAcknowledgement)
        );
        assert!(!error.requires_owner_stop());
        assert_eq!(
            node.authenticated_outbound_reservation(frame.session())
                .unwrap(),
            (1, Some(b"retained wire".to_vec()))
        );
        node.finish_authenticated_outbound(frame).unwrap();
        assert_eq!(
            node.authenticated_outbound_reservation(frame.session())
                .unwrap(),
            (2, None)
        );
    }

    #[test]
    fn missing_caller_state_and_retired_replies_remain_nonfatal_stale_context() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let payload = b"bounded replay payload";
        let first = replay_frame(&settings, 1, payload);
        for (error, code) in [
            (
                node.finish_authenticated_request(first, b"reply")
                    .unwrap_err(),
                ErrorCode::AuthReplayState,
            ),
            (
                node.finish_authenticated_outbound(first).unwrap_err(),
                ErrorCode::AuthOutboxState,
            ),
        ] {
            assert!(error.is(code));
            assert_eq!(error.to_string(), code.as_str());
            assert_eq!(error.kind(), ErrorKind::StaleContext);
            assert!(!error.requires_owner_stop());
        }
        for nonce in 1..=AUTH_RESPONSE_RETENTION + 1 {
            let frame = replay_frame(&settings, nonce, payload);
            node.begin_authenticated_request(frame, payload).unwrap();
            node.finish_authenticated_request(frame, b"reply").unwrap();
        }
        let error = node
            .begin_authenticated_request(first, payload)
            .unwrap_err();
        assert!(error.is(ErrorCode::AuthReplayRetired));
        assert_eq!(error.to_string(), "AUTH_REPLAY_RETIRED");
        assert_eq!(error.kind(), ErrorKind::StaleContext);
        assert!(!error.requires_owner_stop());
        node.validate_authenticated_replay().unwrap();
        drop(node);
        let mut reopened = Node::open(directory.path(), settings, 1).unwrap();
        assert!(reopened
            .begin_authenticated_request(first, payload)
            .unwrap_err()
            .is(ErrorCode::AuthReplayRetired));
    }

    #[test]
    fn reservation_writes_cannot_report_success_without_complete_durable_state() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let payload = b"reservation payload";
        for nonce in 1..=2 {
            let frame = replay_frame(&settings, nonce, payload);
            let prior = node.authenticated_replay_state(frame.session()).unwrap();
            let counts = node.authenticated_replay_counts().unwrap();
            let replay_write = if nonce == 1 { "INSERT" } else { "UPDATE" };
            for (table, operation, code) in [
                ("peer_replay", replay_write, ErrorCode::AuthReplayState),
                ("peer_request_audit", "INSERT", ErrorCode::AuthReplayAudit),
            ] {
                node.db.execute_batch(&format!(
                    "CREATE TEMP TRIGGER omit_replay_reservation BEFORE {operation} ON {table} BEGIN SELECT RAISE(IGNORE); END;"
                )).unwrap();
                let error = node
                    .begin_authenticated_request(frame, payload)
                    .unwrap_err();
                assert!(error.is(code));
                local(error, code.as_str());
                assert_eq!(node.authenticated_replay_counts().unwrap(), counts);
                assert_eq!(
                    node.authenticated_replay_state(frame.session()).unwrap(),
                    prior
                );
                node.db
                    .execute_batch("DROP TRIGGER omit_replay_reservation;")
                    .unwrap();
            }
            node.begin_authenticated_request(frame, payload).unwrap();
            node.finish_authenticated_request(frame, b"reply").unwrap();

            let prior = node.authenticated_outbox_state(frame.session()).unwrap();
            let counts = node.authenticated_outbox_counts().unwrap();
            node.db.execute_batch(&format!(
                "CREATE TEMP TRIGGER omit_outbox_reservation BEFORE {replay_write} ON peer_outbox BEGIN SELECT RAISE(IGNORE); END;"
            )).unwrap();
            let error = node
                .reserve_authenticated_outbound(frame, payload, b"retained wire")
                .unwrap_err();
            assert!(error.is(ErrorCode::AuthOutboxState));
            local(error, "AUTH_OUTBOX_STATE");
            assert_eq!(node.authenticated_outbox_counts().unwrap(), counts);
            assert_eq!(
                node.authenticated_outbox_state(frame.session()).unwrap(),
                prior
            );
            node.db
                .execute_batch("DROP TRIGGER omit_outbox_reservation;")
                .unwrap();
            node.reserve_authenticated_outbound(frame, payload, b"retained wire")
                .unwrap();
            node.finish_authenticated_outbound(frame).unwrap();
        }
        drop(node);
        let mut reopened = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let frame = replay_frame(&settings, 2, payload);
        assert!(matches!(
            reopened.begin_authenticated_request(frame, payload).unwrap(),
            AuthenticatedReplayDecision::Cached(bytes) if bytes == b"reply"
        ));
        assert_eq!(reopened.authenticated_replay_counts().unwrap(), (1, 0, 2));
        assert_eq!(
            reopened
                .authenticated_outbound_reservation(frame.session())
                .unwrap(),
            (3, None)
        );
    }

    #[test]
    fn journal_transition_row_loss_is_local_and_rollback_preserves_exact_pending_frame() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let payload = b"pending payload";
        let frame = replay_frame(&settings, 1, payload);
        node.begin_authenticated_request(frame, payload).unwrap();
        // A test-owned SQLite trigger forces the already-validated conditional
        // transition to affect no row. The failed transaction must roll back.
        node.db.execute_batch("CREATE TEMP TRIGGER omit_replay_ack BEFORE UPDATE ON peer_request_audit BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        let error = node
            .finish_authenticated_request(frame, b"reply")
            .unwrap_err();
        assert!(error.is(ErrorCode::AuthReplayAudit));
        local(error, "AUTH_REPLAY_AUDIT");
        assert_eq!(
            node.authenticated_replay_state(frame.session())
                .unwrap()
                .unwrap()
                .pending(),
            Some(frame)
        );
        node.db
            .execute_batch("DROP TRIGGER omit_replay_ack;")
            .unwrap();
        node.db.execute_batch("CREATE TEMP TRIGGER omit_replay_frontier BEFORE UPDATE ON peer_replay BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        let error = node
            .finish_authenticated_request(frame, b"reply")
            .unwrap_err();
        assert!(error.is(ErrorCode::AuthReplayState));
        local(error, "AUTH_REPLAY_STATE");
        let status: u64 = node
            .db
            .query_row(
                "SELECT status FROM peer_request_audit WHERE session_id=? AND nonce=1",
                [frame.session().session_id().bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, 0, "the first acknowledgement update must roll back");
        assert_eq!(
            node.authenticated_replay_state(frame.session())
                .unwrap()
                .unwrap()
                .pending(),
            Some(frame)
        );
        node.db
            .execute_batch("DROP TRIGGER omit_replay_frontier;")
            .unwrap();
        node.finish_authenticated_request(frame, b"reply").unwrap();

        node.reserve_authenticated_outbound(frame, payload, b"retained wire")
            .unwrap();
        node.db.execute_batch("CREATE TEMP TRIGGER omit_outbox_ack BEFORE UPDATE ON peer_outbox BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        let error = node.finish_authenticated_outbound(frame).unwrap_err();
        assert!(error.is(ErrorCode::AuthOutboxState));
        local(error, "AUTH_OUTBOX_STATE");
        assert_eq!(
            node.authenticated_outbound_reservation(frame.session())
                .unwrap(),
            (1, Some(b"retained wire".to_vec()))
        );
        node.db
            .execute_batch("DROP TRIGGER omit_outbox_ack;")
            .unwrap();
        node.finish_authenticated_outbound(frame).unwrap();
        drop(node);
        let reopened = Node::open(directory.path(), settings, 1).unwrap();
        assert_eq!(
            reopened
                .authenticated_outbound_reservation(frame.session())
                .unwrap(),
            (2, None)
        );
        assert_eq!(reopened.authenticated_replay_counts().unwrap(), (1, 0, 1));
    }

    #[test]
    fn retained_header_corruption_and_unknown_caller_locator_have_different_origins() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let block = packet(&node, settings.genesis(), 11, 0);
        let id = node.admit(&block, 1000).unwrap();
        node.activate_observed(id, 1000).unwrap();
        let original = block.encode().unwrap();
        let mut damaged = original.clone();
        damaged[0] ^= 0xff;

        let incoming = Packet::decode(&damaged).unwrap_err();
        assert!(incoming.is(ErrorCode::HeaderCodec));
        assert_eq!(incoming.kind(), ErrorKind::ProtocolInvalid);
        assert!(!incoming.requires_owner_stop());
        node.db
            .execute(
                "UPDATE blocks SET packet=? WHERE id=?",
                params![damaged, id.as_slice()],
            )
            .unwrap();
        local(node.packet(id).unwrap_err(), "HEADER_CODEC");
        local(
            node.check_observed_history(id, 1000).unwrap_err(),
            "HEADER_CODEC",
        );
        node.db
            .execute(
                "UPDATE blocks SET packet=? WHERE id=?",
                params![original, id.as_slice()],
            )
            .unwrap();

        let absent = node.check_observed_history([93; 32], 1000).unwrap_err();
        assert!(absent.is(ErrorCode::UnknownParent));
        assert_eq!(absent.kind(), ErrorKind::StaleContext);
        assert!(!absent.requires_owner_stop());
        assert!(!node
            .packet(settings.genesis())
            .unwrap_err()
            .requires_owner_stop());
        let genesis = node.record(settings.genesis()).unwrap();
        node.db
            .execute(
                "UPDATE blocks SET height=9 WHERE id=?",
                [settings.genesis().as_slice()],
            )
            .unwrap();
        local(
            node.check_observed_history(id, 1000).unwrap_err(),
            "ANCESTRY_HEIGHT",
        );
        // Normal mutations cannot remove a referenced ancestor. Simulate damaged
        // retained storage only in this temporary database, then restore both the
        // exact row and its enforced foreign-key contract before reopening.
        node.db.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        node.db
            .execute(
                "DELETE FROM blocks WHERE id=?",
                [settings.genesis().as_slice()],
            )
            .unwrap();
        let missing = node.check_observed_history(id, 1000).unwrap_err();
        assert!(missing.is(ErrorCode::UnknownParent));
        local(missing, "UNKNOWN_PARENT");
        node.db
            .execute(
                "INSERT INTO blocks VALUES(?,?,?,?,?,?)",
                params![
                    settings.genesis().as_slice(),
                    Option::<Vec<u8>>::None,
                    genesis.height,
                    genesis.work.bytes().as_slice(),
                    Option::<Vec<u8>>::None,
                    genesis.root.as_slice(),
                ],
            )
            .unwrap();
        node.db.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        let violations: u64 = node
            .db
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(violations, 0);
        node.check_observed_history(id, 1000).unwrap();
        let before = node.read_active().unwrap();
        drop(node);
        assert_eq!(
            Node::open(directory.path(), settings, 1)
                .unwrap()
                .read_active()
                .unwrap(),
            before
        );
    }

    #[test]
    fn persisted_state_bytes_and_root_are_local_but_progress_errors_keep_their_identity() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let before = node.read_active().unwrap();
        let slot = node.slot().unwrap();
        let (key, bytes): (String, Vec<u8>) = node
            .db
            .query_row(
                "SELECT key,value FROM kv WHERE slot=? ORDER BY key LIMIT 1",
                [slot],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let mut noncanonical = bytes.clone();
        noncanonical.push(b' ');
        node.db
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![noncanonical, slot, key],
            )
            .unwrap();
        local(node.read_active().unwrap_err(), "STATE_BYTES");

        node.db
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![b"[".as_slice(), slot, key],
            )
            .unwrap();
        let error = node.read_active().unwrap_err();
        let source = serde_json::from_slice::<Value>(b"[").unwrap_err();
        assert_eq!(error.to_string(), format!("JSON: {source}"));
        assert!(error.source().unwrap().is::<serde_json::Error>());
        assert!(error.requires_owner_stop());

        node.db
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![b"null".as_slice(), slot, key],
            )
            .unwrap();
        local(node.read_active().unwrap_err(), "ROOT");
        node.db
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![bytes, slot, key],
            )
            .unwrap();
        for code in [
            ErrorCode::PublicRequestCancelled,
            ErrorCode::PublicMutationCpuBudget,
            ErrorCode::UnknownParent,
        ] {
            let mut calls = 0;
            let error = node
                .read_active_with_progress(&mut || {
                    calls += 1;
                    if calls == 2 {
                        Err(Error::new(code))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert!(error.is(code));
            assert!(!error.requires_owner_stop());
            assert_eq!(calls, 2);
        }
        assert_eq!(node.read_active().unwrap(), before);
    }

    #[test]
    fn retained_history_cancellation_and_clock_deferral_never_become_storage_failure() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let timestamp = settings.limit("future_skew_seconds").unwrap() + 100;
        let block = packet(&node, settings.genesis(), timestamp, 0);
        let id = node.admit(&block, timestamp).unwrap();
        for code in [
            ErrorCode::PublicRequestCancelled,
            ErrorCode::PublicMutationCpuBudget,
            ErrorCode::UnknownParent,
        ] {
            let mut visited = 0;
            let error = node
                .visit_header_batch(id, &mut |_, _| {
                    visited += 1;
                    Err(Error::new(code))
                })
                .unwrap_err();
            assert!(error.is(code));
            assert!(!error.requires_owner_stop());
            assert_eq!(visited, 1);
        }
        let error = node.check_observed_history(id, 0).unwrap_err();
        assert!(error.is(ErrorCode::TimeDeferred));
        assert_eq!(error.kind(), ErrorKind::StaleContext);
        assert!(!error.requires_owner_stop());
        node.check_observed_history(id, timestamp).unwrap();
    }

    #[test]
    fn durable_reorg_faults_stop_and_exact_repair_resumes_without_losing_hook_cancellation() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let left = packet(&node, settings.genesis(), 11, 0);
        let left_id = node.admit(&left, 1000).unwrap();
        node.activate_observed(left_id, 1000).unwrap();
        let right = packet(&node, settings.genesis(), 12, 1);
        let right_id = node.admit(&right, 1000).unwrap();
        let target = packet(&node, right_id, 22, 1);
        let target_id = node.admit(&target, 1000).unwrap();
        let expected = node.state_at(target_id).unwrap();
        let original_active = node.active().unwrap();
        let mut at_intent = 0;
        let error = node
            .activate_with_fault(
                target_id,
                Some(&mut |point| {
                    if point == "intent" {
                        at_intent += 1;
                        Err(Error::new(ErrorCode::PublicRequestCancelled))
                    } else {
                        Ok(())
                    }
                }),
            )
            .unwrap_err();
        assert!(error.is(ErrorCode::PublicRequestCancelled));
        assert!(!error.requires_owner_stop());
        assert_eq!(at_intent, 1);
        assert_eq!(node.active().unwrap(), original_active);

        let kind: u64 = node
            .db
            .query_row("SELECT kind FROM steps WHERE ordinal=0", [], |row| {
                row.get(0)
            })
            .unwrap();
        node.db
            .execute("UPDATE steps SET kind=9 WHERE ordinal=0", [])
            .unwrap();
        local(node.recover().unwrap_err(), "REORG_STEPS");
        node.db
            .execute("UPDATE steps SET kind=? WHERE ordinal=0", [kind])
            .unwrap();
        let generation: u64 = node
            .db
            .query_row(
                "SELECT generation FROM reorg WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        node.db
            .execute(
                "UPDATE reorg SET generation=? WHERE singleton=1",
                [generation + 1],
            )
            .unwrap();
        local(node.recover().unwrap_err(), "GENERATION");
        node.db
            .execute(
                "UPDATE reorg SET generation=? WHERE singleton=1",
                [generation],
            )
            .unwrap();

        let (key, prior): (String, Option<Vec<u8>>) = node
            .db
            .query_row(
                "SELECT key,before FROM deltas WHERE block=? ORDER BY key LIMIT 1",
                [right_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        node.db
            .execute(
                "UPDATE deltas SET before=? WHERE block=? AND key=?",
                params![b"false".as_slice(), right_id.as_slice(), key],
            )
            .unwrap();
        local(node.recover().unwrap_err(), "UNDO_ROOT");
        assert_eq!(node.active().unwrap(), original_active);
        node.db
            .execute(
                "UPDATE deltas SET before=? WHERE block=? AND key=?",
                params![prior, right_id.as_slice(), key],
            )
            .unwrap();
        assert_eq!(node.recover().unwrap(), target_id);
        assert_eq!(node.read_active().unwrap().2, expected);
        drop(node);
        let reopened = Node::open(directory.path(), settings, 1).unwrap();
        assert_eq!(reopened.active().unwrap().0, target_id);
        assert_eq!(reopened.read_active().unwrap().2, expected);
    }

    #[test]
    fn actual_replay_and_outbox_recovery_preserve_typed_local_sources() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        // Exercise the durable replay owner's typed input. Authentication of
        // signed wire frames remains covered by the existing ingress tests.
        let session = PeerSessionIdentityV0::new(
            IoDigest32V0::new(settings.genesis()).unwrap(),
            IoDigest32V0::new(settings.parameters()).unwrap(),
            IoDigest32V0::new([71; 32]).unwrap(),
            IoDigest32V0::new([72; 32]).unwrap(),
            IoDigest32V0::new(crate::authenticated_profile_digest()).unwrap(),
            1,
        )
        .unwrap();
        let payload = b"actual replay component payload";
        let frame = AuthenticatedPeerFrameV0::new(
            session,
            1,
            IoDigest32V0::new(crate::authenticated_payload_digest(payload)).unwrap(),
            payload.len(),
        )
        .unwrap();
        assert!(matches!(
            node.begin_authenticated_request(frame, payload).unwrap(),
            AuthenticatedReplayDecision::Execute
        ));
        node.db
            .execute(
                "UPDATE peer_replay SET chain_id=? WHERE session_id=?",
                params![
                    [0_u8; 32].as_slice(),
                    session.session_id().bytes().as_slice()
                ],
            )
            .unwrap();
        let error = node
            .begin_authenticated_request(frame, payload)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "AUTH_REPLAY:peer identity digest may not be zero"
        );
        assert!(error
            .source()
            .unwrap()
            .is::<trnm_transport::PeerAdmissionErrorV0>());
        assert!(error.requires_owner_stop());
        assert!(!Error::remote(error.to_string()).requires_owner_stop());
        node.db
            .execute(
                "UPDATE peer_replay SET chain_id=? WHERE session_id=?",
                params![
                    settings.genesis().as_slice(),
                    session.session_id().bytes().as_slice()
                ],
            )
            .unwrap();

        node.db
            .execute(
                "UPDATE peer_request_audit SET payload=? WHERE session_id=?",
                params![
                    b"damaged".as_slice(),
                    session.session_id().bytes().as_slice()
                ],
            )
            .unwrap();
        let error = node
            .begin_authenticated_request(frame, payload)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "AUTH_RECOVERY:peer recovery source rejected: AUTH_PENDING_AUDIT"
        );
        assert!(error
            .source()
            .unwrap()
            .is::<trnm_transport::PeerRecoveryErrorV0<Error>>());
        assert!(error.requires_owner_stop());
        node.db
            .execute(
                "UPDATE peer_request_audit SET payload=? WHERE session_id=?",
                params![payload.as_slice(), session.session_id().bytes().as_slice()],
            )
            .unwrap();
        let conflicting =
            AuthenticatedPeerFrameV0::new(session, 1, IoDigest32V0::new([81; 32]).unwrap(), 7)
                .unwrap();
        let refusal = node
            .begin_authenticated_request(conflicting, b"changed")
            .unwrap_err();
        assert_eq!(
            refusal.to_string(),
            "AUTH_FRAME:peer frame boundary failed: pending peer frame replay changed its payload"
        );
        assert!(!refusal.requires_owner_stop());
        node.finish_authenticated_request(frame, b"actual retained response")
            .unwrap();

        node.reserve_authenticated_outbound(frame, payload, b"retained outbound wire")
            .unwrap();
        node.db
            .execute(
                "UPDATE peer_outbox SET pending_payload=? WHERE session_id=?",
                params![
                    b"damaged".as_slice(),
                    session.session_id().bytes().as_slice()
                ],
            )
            .unwrap();
        let error = node
            .authenticated_outbound_reservation(session)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "AUTH_OUTBOX_RECOVERY:peer recovery source rejected: AUTH_OUTBOX_PENDING"
        );
        assert!(error
            .source()
            .unwrap()
            .is::<trnm_transport::PeerRecoveryErrorV0<Error>>());
        assert!(error.requires_owner_stop());
        node.db
            .execute(
                "UPDATE peer_outbox SET pending_payload=? WHERE session_id=?",
                params![payload.as_slice(), session.session_id().bytes().as_slice()],
            )
            .unwrap();
        drop(node);
        let mut reopened = Node::open(directory.path(), settings, 1).unwrap();
        assert!(matches!(
            reopened
                .begin_authenticated_request(frame, payload)
                .unwrap(),
            AuthenticatedReplayDecision::Cached(_)
        ));
        assert_eq!(
            reopened
                .authenticated_outbound_reservation(session)
                .unwrap(),
            (1, Some(b"retained outbound wire".to_vec()))
        );
    }
}

#[cfg(test)]
mod public_read_bounds_tests {
    use super::*;
    #[test]
    fn corrupt_packet_shapes_are_rejected_before_blob_load() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let genesis = settings.genesis();
        let row = node.record(genesis).unwrap();
        // Deliberately corrupt local rows test read boundaries, not consensus admission.
        node.db
            .execute(
                "INSERT INTO blocks VALUES(?,?,?,?,?,?)",
                params![
                    [1_u8; 32].as_slice(),
                    genesis.as_slice(),
                    4097_u64,
                    row.work.bytes().as_slice(),
                    Option::<Vec<u8>>::None,
                    row.root.as_slice()
                ],
            )
            .unwrap();
        let mut steps = Vec::new();
        let e = node
            .public_history_packet(
                [1; 32],
                genesis,
                crate::ancestry_index::READ_SQL_BUDGET,
                &mut |n| {
                    steps.push(n);
                    Ok(())
                },
            )
            .unwrap_err();
        assert_eq!(e.to_string(), "ANCESTRY_INDEX_PACKET_BYTES");
        assert_eq!(steps, vec![0, 1]);
        node.db
            .execute(
                "INSERT INTO blocks VALUES(?,?,?,?,?,?)",
                params![
                    [2_u8; 32].as_slice(),
                    genesis.as_slice(),
                    1_u64,
                    row.work.bytes().as_slice(),
                    vec![0_u8; 1_048_577],
                    row.root.as_slice()
                ],
            )
            .unwrap();
        let e = node
            .public_history_packet(
                [2; 32],
                genesis,
                crate::ancestry_index::READ_SQL_BUDGET,
                &mut |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(e.to_string(), "ANCESTRY_INDEX_PACKET_BYTES");
    }
}

#[cfg(test)]
mod native_ancestry_tests {
    use super::*;
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    use trnm_protocol::pon_wire::Envelope;
    fn transfer(node: &Node) -> Vec<u8> {
        let sender = development_public(0).unwrap();
        let mut payload = development_public(1).unwrap().to_vec();
        payload.extend(1_u64.to_le_bytes());
        let mut tx = Envelope {
            network: node.settings().network(),
            sender,
            nonce: node.next_nonce(sender).unwrap(),
            expiry: 1000,
            fee_limit: 1_000_000,
            tag: 1,
            payload,
            signature: [0; 64],
        };
        let key =
            signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
                .unwrap();
        tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
            .unwrap()
            .try_into()
            .unwrap();
        tx.encode().unwrap()
    }
    fn make(node: &Node, parent: Hash, height: u64, miner: u64, txs: Vec<Vec<u8>>) -> Packet {
        node.make(
            parent,
            txs,
            development_public(miner).unwrap(),
            1 + height * 10,
            4096,
        )
        .unwrap()
    }
    #[test]
    fn local_state_cancellation_rolls_back_all_packet_rows_and_reopens_original_state() {
        for cancel_at in [
            ExecutionProgress::AfterPrepare { index: 0 },
            ExecutionProgress::AfterApply { index: 0 },
            ExecutionProgress::AfterCommitment,
            ExecutionProgress::BeforePersistence,
            ExecutionProgress::PersistenceDelta { index: 0 },
            ExecutionProgress::BeforeDurableCommit,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let settings = Settings::development(Some(1)).unwrap();
            let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
            let packet = make(&node, settings.genesis(), 1, 0, vec![transfer(&node)]);
            let id = packet.id().unwrap();
            let before = node.read_active().unwrap();
            let sender = development_public(0).unwrap();
            let nonce = node.next_nonce(sender).unwrap();
            let tables = [
                "blocks",
                "deltas",
                "ancestry_jump",
                "snapshots",
                "kv",
                "events",
                "steps",
                "reorg",
            ];
            let counts = |owner: &Node| {
                tables
                    .iter()
                    .map(|table| {
                        owner
                            .db
                            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                                row.get::<_, u64>(0)
                            })
                            .unwrap()
                    })
                    .collect::<Vec<_>>()
            };
            let original_counts = counts(&node);
            let reached = std::sync::atomic::AtomicBool::new(false);
            let checked = WorkCheckedPacket::verify(packet).unwrap();
            let error = node
                .admit_work_checked_with_progress(checked, 1000, &|point| {
                    if point == cancel_at {
                        reached.store(true, std::sync::atomic::Ordering::Release);
                        Err("PUBLIC_REQUEST_CANCELLED".into())
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert_eq!(error.to_string(), "PUBLIC_REQUEST_CANCELLED");
            assert!(reached.load(std::sync::atomic::Ordering::Acquire));
            assert_eq!(counts(&node), original_counts);
            assert!(node.record(id).is_err());
            assert_eq!(node.read_active().unwrap(), before);
            assert_eq!(node.next_nonce(sender).unwrap(), nonce);
            drop(node);
            let reopened = Node::open(dir.path(), settings, 2).unwrap();
            assert_eq!(counts(&reopened), original_counts);
            assert_eq!(reopened.read_active().unwrap(), before);
            assert_eq!(reopened.next_nonce(sender).unwrap(), nonce);
            assert!(reopened.record(id).is_err());
        }
    }

    #[test]
    fn local_cancel_named_like_commitment_error_never_retries_full_preview() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        let before = node.read_active().unwrap();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let error = node
            .execute_derived_with_progress(
                &before.2,
                ExecutionRequest {
                    transactions: &[],
                    height: 1,
                    miner: development_public(0).unwrap(),
                    parent_id: settings.genesis(),
                    workers: 2,
                },
                &|point| {
                    if point == ExecutionProgress::BeforeOutput {
                        calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Err("COMMITMENT_ROOT".into())
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "COMMITMENT_ROOT");
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(node.read_active().unwrap(), before);
    }

    #[test]
    fn actual_work_index_abort_preserves_block_state_and_sender_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = Node::open(dir.path(), settings.clone(), 1).unwrap();
        let mut parent = settings.genesis();
        for height in 1..=3 {
            let packet = make(&node, parent, height, 0, vec![]);
            parent = node.admit(&packet, 1000).unwrap();
            node.activate_observed(parent, 1000).unwrap();
        }
        let before = node.read_active().unwrap();
        let sender = development_public(0).unwrap();
        let nonce = node.next_nonce(sender).unwrap();
        let packet = make(&node, parent, 4, 0, vec![transfer(&node)]);
        let id = packet.id().unwrap();
        // A real validated proof and signed transfer reach the write transaction.
        node.db.execute_batch("CREATE TRIGGER fail_index BEFORE INSERT ON ancestry_jump WHEN NEW.level=2 BEGIN SELECT RAISE(ABORT,'index fault');END;").unwrap();
        assert!(node.admit(&packet, 1000).is_err());
        assert_eq!(node.read_active().unwrap(), before);
        assert_eq!(node.next_nonce(sender).unwrap(), nonce);
        assert!(node.record(id).is_err());
        let rows: u64 = node
            .db
            .query_row(
                "SELECT COUNT(*) FROM ancestry_jump WHERE block=?",
                [id.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0);
        node.db.execute_batch("DROP TRIGGER fail_index").unwrap();
        assert_eq!(node.admit(&packet, 1000).unwrap(), id);
        node.activate_observed(id, 1000).unwrap();
        assert_eq!(node.next_nonce(sender).unwrap(), nonce + 1);
        drop(node);
        let node = Node::open(dir.path(), settings, 1).unwrap();
        assert_eq!(node.active().unwrap().0, id);
    }
    #[test]
    fn actual_native_forks_reopen_and_independent_validation_use_indexed_pages() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = Node::open(dir.path(), settings.clone(), 1).unwrap();
        let mut ids = vec![settings.genesis()];
        for height in 1..=8 {
            let packet = make(&node, *ids.last().unwrap(), height, 0, vec![]);
            let id = node.admit(&packet, 1000).unwrap();
            node.activate_observed(id, 1000).unwrap();
            ids.push(id);
        }
        let mut fork = vec![ids[3]];
        for height in 4..=9 {
            let packet = make(&node, *fork.last().unwrap(), height, 1, vec![]);
            fork.push(node.admit(&packet, 1000).unwrap());
        }
        let tip = *fork.last().unwrap();
        node.activate_observed(tip, 1000).unwrap();
        drop(node);
        let node = Node::open(dir.path(), settings.clone(), 1).unwrap();
        assert_eq!(node.active().unwrap().0, tip);
        let first = node
            .public_history_packet(
                tip,
                ids[3],
                crate::ancestry_index::READ_SQL_BUDGET,
                &mut |_| Ok(()),
            )
            .unwrap();
        assert_eq!(first[0].id().unwrap(), fork[1]);
        assert_eq!(
            node.public_history_packet(
                ids[8],
                fork[1],
                crate::ancestry_index::READ_SQL_BUDGET,
                &mut |_| Ok(())
            )
            .unwrap_err()
            .to_string(),
            "CURSOR"
        );
        let other = tempfile::tempdir().unwrap();
        let mut confirmer = Node::open(other.path(), settings.clone(), 1).unwrap();
        let mut after = settings.genesis();
        while after != tip {
            let page = node
                .public_history_packet(
                    tip,
                    after,
                    crate::ancestry_index::READ_SQL_BUDGET,
                    &mut |_| Ok(()),
                )
                .unwrap();
            assert_eq!(page.len(), 1);
            assert_eq!(page[0].header.parent, after);
            after = confirmer.admit(&page[0], 1000).unwrap();
        }
        confirmer.activate_observed(tip, 1000).unwrap();
        let confirmed = confirmer.read_active().unwrap();
        let expected = node.read_active().unwrap();
        assert_eq!(confirmed.0, expected.0);
        assert_eq!(confirmed.2, expected.2);
        assert_eq!(
            confirmer.stats().unwrap()["chainwork_hex"],
            node.stats().unwrap()["chainwork_hex"]
        );
        node.db
            .execute(
                "UPDATE ancestry_jump SET seal=? WHERE block=? AND level=3",
                params![[0_u8; 32].as_slice(), tip.as_slice()],
            )
            .unwrap();
        drop(node);
        assert_eq!(
            Node::open(dir.path(), settings, 1)
                .err()
                .unwrap()
                .to_string(),
            "ANCESTRY_INDEX_SEAL"
        );
    }
    #[test]
    fn previous_ddl_is_refused_without_migration_or_database_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("native.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(BASE_DDL).unwrap();
        drop(db);
        let before = fs::read(&path).unwrap();
        let error = Node::open(dir.path(), Settings::development(Some(1)).unwrap(), 1)
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "SCHEMA");
        assert_eq!(fs::read(path).unwrap(), before);
    }
}

#[cfg(test)]
#[path = "operator_task_store_tests.rs"]
mod operator_task_store_tests;

#[cfg(test)]
#[path = "continuity_tests.rs"]
mod continuity_tests;

#[cfg(test)]
#[path = "native_authenticated_tests.rs"]
mod native_authenticated_tests;

#[cfg(test)]
#[path = "native_ancestry_commit_tests.rs"]
mod native_ancestry_commit_tests;

#[cfg(test)]
#[path = "native_account_query_tests.rs"]
mod native_account_query_tests;
