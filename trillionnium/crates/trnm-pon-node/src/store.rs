//! M07/M08 native branch persistence and recovery using the existing M06 executor.
pub mod evaluation_observation;
pub mod evaluation_round_observation;
pub mod mempool;
use crate::{
    consensus::{self, Work},
    development_public, ensure, maintenance, sequence_root, Error, Packet, Result, Settings,
};
use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use serde_json::Value;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    cell::RefCell,
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
use trnm_mvcc_fee::pon_commitment::{
    self, CacheLimits, CheckedCommitment, CommitmentObservation, ExecutionRequest,
    PreparedCommitment,
};
use trnm_mvcc_fee::pon_executor::SIGNED_TASK_PROFILE;
use trnm_mvcc_fee::pon_executor::{root, State};
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
type Delta = (String, Option<Vec<u8>>, Option<Vec<u8>>);
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
    Signed(Box<QualifiedWorkTask>),
    Lifecycle(Box<qualified_task_lifecycle::EligibleLifecycleTask>),
}
impl ParentTaskEligibility {
    fn manifest(&self) -> Option<&QualifiedWorkTask> {
        match self {
            Self::Legacy => None,
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
/// Owns the exact packet whose work was actually verified. Not state or clock authority.
/// Private fields prevent replacing the header/body/proof after verification.
pub(crate) struct WorkCheckedPacket {
    packet: Packet,
    work: pon_work::VerifiedWork,
}
impl WorkCheckedPacket {
    pub(crate) fn verify(packet: Packet) -> Result<Self> {
        let h = &packet.header;
        let work = pon_work::verify(h.challenge(), h.work_task, h.target, &packet.proof)
            .map_err(|e| Error::from(format!("WORK:{e:?}")))?;
        Ok(Self { packet, work })
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
    // One derived snapshot only; State always comes from actual KV/snapshot/deltas.
    commitment_cache: RefCell<Option<ActiveCommitment>>,
    commitment_observation: RefCell<Option<CommitmentObservation>>,
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
        mut hook: Option<&mut Hook<'_>>,
    ) -> Result<Self> {
        ensure([1, 2, 4, 8].contains(&workers), "WORKERS")?;
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
        let ddl = ddl();
        let schema_id = hash(b"native-branch-schema-v2", &[ddl.as_bytes()]);
        let expected = canonical(
            &serde_json::json!({"schema":hex::encode(schema_id),"parameters":hex::encode(settings.parameters()),"genesis":hex::encode(settings.genesis())}),
        )?;
        if !dbpath.exists() && !marker.exists() {
            for entry in fs::read_dir(&directory)? {
                ensure(entry?.file_name() == "owner.lock", "NAMESPACE_NOT_EMPTY")?;
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
            commitment_cache: RefCell::new(None),
            commitment_observation: RefCell::new(None),
        };
        node.read_active()?;
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
    fn decode_replay_row(row: ReplayRow) -> Result<PeerReplayStateV0> {
        let chain = IoDigest32V0::new(bytes32(row.0)?)
            .map_err(|e| Error::from(format!("AUTH_REPLAY:{e}")))?;
        let protocol = IoDigest32V0::new(bytes32(row.1)?)
            .map_err(|e| Error::from(format!("AUTH_REPLAY:{e}")))?;
        let peer = IoDigest32V0::new(bytes32(row.2)?)
            .map_err(|e| Error::from(format!("AUTH_REPLAY:{e}")))?;
        let session_id = IoDigest32V0::new(bytes32(row.3)?)
            .map_err(|e| Error::from(format!("AUTH_REPLAY:{e}")))?;
        let profile = IoDigest32V0::new(bytes32(row.4)?)
            .map_err(|e| Error::from(format!("AUTH_REPLAY:{e}")))?;
        let session = PeerSessionIdentityV0::new(chain, protocol, peer, session_id, profile, row.5)
            .map_err(|e| Error::from(format!("AUTH_REPLAY:{e}")))?;
        let pending = match (row.7, row.8, row.9) {
            (None, None, None) => None,
            (Some(nonce), Some(digest), Some(bytes)) => Some(
                AuthenticatedPeerFrameV0::new(
                    session,
                    nonce,
                    IoDigest32V0::new(bytes32(digest)?)
                        .map_err(|e| Error::from(format!("AUTH_REPLAY:{e}")))?,
                    usize::try_from(bytes).map_err(|_| Error::from("AUTH_REPLAY_SIZE"))?,
                )
                .map_err(|e| Error::from(format!("AUTH_REPLAY:{e}")))?,
            ),
            _ => return Err("AUTH_PENDING_AUDIT".into()),
        };
        PeerReplayStateV0::new(session, row.6, pending)
            .map_err(|e| Error::from(format!("AUTH_REPLAY:{e}")))
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
            )?;
            CandidateP2pAdmissionV0::recover_verified(state, &mut ReplayRecovery { db: &self.db })
                .map_err(|e| Error::from(format!("AUTH_RECOVERY:{e}")))?;
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
            )?;
            CandidateP2pAdmissionV0::recover_verified(state, &mut OutboxRecovery { db: &self.db })
                .map_err(|error| Error::from(format!("AUTH_OUTBOX_RECOVERY:{error}")))?;
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
                .map_err(|error| Error::from(format!("AUTH_OUTBOX:{error}")))?,
        );
        CandidateP2pAdmissionV0::recover_verified(state, &mut OutboxRecovery { db: &self.db })
            .map_err(|error| Error::from(format!("AUTH_OUTBOX_RECOVERY:{error}")))?;
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
                .map_err(|error| Error::from(format!("AUTH_OUTBOX:{error}")))?,
        );
        let mut admission =
            CandidateP2pAdmissionV0::recover_verified(state, &mut OutboxRecovery { db: &self.db })
                .map_err(|error| Error::from(format!("AUTH_OUTBOX_RECOVERY:{error}")))?;
        let verified = admission
            .verify_frame(frame, &mut ExactFrameSource { payload })
            .map_err(|error| Error::from(format!("AUTH_OUTBOX_FRAME:{error}")))?;
        admission
            .admit_verified(verified)
            .map_err(|error| Error::from(format!("AUTH_OUTBOX:{error}")))?;
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
        tx.execute(
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
                .map_err(|error| Error::from(format!("AUTH_OUTBOX_RECOVERY:{error}")))?;
        let next = admission
            .acknowledge(frame)
            .map_err(|error| Error::from(format!("AUTH_OUTBOX:{error}")))?;
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
        ensure(changed == 1, "AUTH_OUTBOX_STATE")?;
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
                .map_err(|e| Error::from(format!("AUTH_REPLAY:{e}")))?,
        );
        CandidateP2pAdmissionV0::recover_verified(state, &mut ReplayRecovery { db: &self.db })
            .map_err(|e| Error::from(format!("AUTH_RECOVERY:{e}")))?;
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
            let (digest, status, response) = audit.ok_or("AUTH_REPLAY_GAP")?;
            ensure(
                bytes32(digest)? == frame.payload_digest().bytes(),
                "AUTH_CONFLICTING_REPLAY",
            )?;
            return match (status, response) {
                (1, Some(bytes)) => Ok(AuthenticatedReplayDecision::Cached(bytes)),
                (2, None) => Err("AUTH_REPLAY_RETIRED".into()),
                _ => Err("AUTH_REPLAY_AUDIT".into()),
            };
        }
        let mut admission =
            CandidateP2pAdmissionV0::recover_verified(state, &mut ReplayRecovery { db: &self.db })
                .map_err(|e| Error::from(format!("AUTH_RECOVERY:{e}")))?;
        let verified = admission
            .verify_frame(frame, &mut ExactFrameSource { payload })
            .map_err(|e| Error::from(format!("AUTH_FRAME:{e}")))?;
        admission
            .admit_verified(verified)
            .map_err(|e| Error::from(format!("AUTH_REPLAY:{e}")))?;
        if state.pending().is_some() {
            return Ok(AuthenticatedReplayDecision::Execute);
        }
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
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
        tx.execute(
            "INSERT INTO peer_request_audit(session_id,nonce,payload_digest,payload,response_digest,response,status) VALUES(?,?,?,?,NULL,NULL,0)",
            params![
                session_id.as_slice(),
                frame.replay_nonce(),
                frame.payload_digest().bytes().as_slice(),
                payload,
            ],
        )?;
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
            .map_err(|e| Error::from(format!("AUTH_RECOVERY:{e}")))?;
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
            let (digest, status, retained) = audit.ok_or("AUTH_REPLAY_GAP")?;
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
                .map_err(|e| Error::from(format!("AUTH_RECOVERY:{e}")))?;
        let next = admission
            .acknowledge(frame)
            .map_err(|e| Error::from(format!("AUTH_REPLAY:{e}")))?;
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
        ensure(changed == 1, "AUTH_REPLAY_AUDIT")?;
        tx.execute(
            "UPDATE peer_replay SET highest_ack=?,pending_nonce=NULL,pending_digest=NULL,pending_bytes=NULL WHERE session_id=?",
            params![next.highest_acknowledged_nonce(), session.as_slice()],
        )?;
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
        let mut stmt = self
            .db
            .prepare("SELECT key,value FROM kv WHERE slot=? ORDER BY key")?;
        let values = stmt.query_map([slot], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut state = State::new();
        for row in values {
            let (key, bytes) = row?;
            let value: Value = serde_json::from_slice(&bytes)?;
            ensure(canonical(&value)? == bytes, "STATE_BYTES")?;
            state.insert(key, value);
        }
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
                Err("ROOT".into())
            }
            Err(error) => Err(error.into()),
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
        let prior = self.cached_parent(parent)?;
        // Always encode/compare the actual supplied parent with its admitted root.
        // This also explicitly reseeds unknown/inactive/fork contexts.
        let checked = self.checked_commitment(actual, self.record(parent)?.root, prior.as_ref())?;
        let request = || ExecutionRequest {
            transactions,
            height,
            miner,
            parent_id: parent,
            workers,
        };
        let result = pon_commitment::execute_checked(
            actual,
            checked.root,
            checked.snapshot.as_ref(),
            request(),
            &self.settings.app,
            CacheLimits::default(),
        );
        match result {
            Ok(output) => {
                *self.commitment_observation.borrow_mut() =
                    Some(output.commitment.observation.clone());
                Ok(output)
            }
            Err("COMMITMENT_PARENT" | "COMMITMENT_ROOT") => {
                // A wrong internal snapshot cannot reject an otherwise valid
                // ledger state; the full actual-root path still checks context.
                self.invalidate_commitment();
                pon_commitment::execute_checked(
                    actual,
                    self.record(parent)?.root,
                    None,
                    request(),
                    &self.settings.app,
                    CacheLimits::default(),
                )
                .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
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
        self.namespace()?;
        let (tip, generation) = self.active()?;
        let slot = self.slot()?;
        let state = self.slot_state(slot)?;
        let prior = self.cached_parent(tip)?;
        let prepared = self.checked_commitment(&state, self.record(tip)?.root, prior.as_ref())?;
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
        let packet = Packet::decode(&raw.ok_or("GENESIS_HAS_NO_PACKET")?)?;
        ensure(
            packet.id()? == id
                && Some(packet.header.parent) == row.parent
                && packet.header.height == row.height
                && packet.header.state == row.root,
            "STORAGE_PACKET",
        )?;
        Ok(packet)
    }
    /// Reads only the committed header and trace of an already admitted local block.
    /// This does not verify new work or replace inclusion-body validation.
    fn stored_header(&self, id: Hash) -> Result<Header> {
        let row = self.record(id)?;
        let (prefix, trace, length): (Option<Vec<u8>>, Option<Vec<u8>>, Option<usize>) = self
            .db
            .query_row(
            "SELECT substr(packet,1,?),substr(packet,-32),length(packet) FROM blocks WHERE id=?",
            params![HEADER_BYTES, id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure(
            (HEADER_BYTES + 2 + pon_work::PROOF_BYTES..=1_048_576)
                .contains(&length.ok_or("GENESIS_HAS_NO_PACKET")?),
            "PACKET_LIMIT",
        )?;
        let header = Header::decode(&prefix.ok_or("GENESIS_HAS_NO_PACKET")?)
            .map_err(|_| Error::from("HEADER_CODEC"))?;
        let trace = bytes32(trace.ok_or("GENESIS_HAS_NO_PACKET")?)?;
        ensure(
            header.block_id(trace) == id
                && Some(header.parent) == row.parent
                && header.height == row.height
                && header.state == row.root,
            "STORAGE_PACKET",
        )?;
        Ok(header)
    }

    fn parent(&self, id: Hash) -> Result<Hash> {
        let row = self.record(id)?;
        let parent = row.parent.ok_or("UNKNOWN_PARENT")?;
        ensure(
            self.record(parent)?.height.checked_add(1) == Some(row.height),
            "ANCESTRY_HEIGHT",
        )?;
        Ok(parent)
    }
    fn delta_rows(&self, id: Hash) -> Result<Vec<Delta>> {
        let mut stmt = self
            .db
            .prepare("SELECT key,before,after FROM deltas WHERE block=? ORDER BY key")?;
        let rows = stmt.query_map([id.as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
    pub fn state_at(&self, tip: Hash) -> Result<State> {
        if tip == self.active()?.0 {
            return Ok(self.read_active()?.2);
        }
        let mut path = tempfile::tempfile()?;
        let mut count = 0u64;
        let mut cur = tip;
        let (mut state, mut commitment): (State, Option<CheckedCommitment>) = loop {
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
                let state: State = serde_json::from_slice(&bytes)?;
                let commitment = self.checked_commitment(&state, row.root, None)?.snapshot;
                break (state, commitment);
            }
            path.write_all(&cur)?;
            count = count.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
            cur = self.parent(cur)?;
        };
        for i in (0..count).rev() {
            path.seek(SeekFrom::Start(i.checked_mul(32).ok_or("ANCESTRY_LIMIT")?))?;
            let mut id = [0; 32];
            path.read_exact(&mut id)?;
            for (key, before, after) in self.delta_rows(id)? {
                ensure(
                    state.get(&key).map(canonical).transpose()? == before,
                    "UNDO_ROOT",
                )?;
                if let Some(bytes) = after {
                    state.insert(key, serde_json::from_slice(&bytes)?);
                } else {
                    state.remove(&key);
                }
            }
            commitment = self
                .checked_commitment(&state, self.record(id)?.root, commitment.as_ref())?
                .snapshot;
        }
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
        self.admit_work_checked(WorkCheckedPacket::verify(packet.clone())?, observed_now)
    }
    /// Work is reusable only for the owned packet; branch/state/clock checks run again.
    pub(crate) fn admit_work_checked(
        &mut self,
        checked: WorkCheckedPacket,
        observed_now: u64,
    ) -> Result<Hash> {
        let WorkCheckedPacket {
            packet,
            work: verified_work,
        } = checked;
        if let Some(id) = self.check_admission_context(&packet, observed_now)? {
            return Ok(id);
        }
        let bytes = packet.encode()?;
        let h = &packet.header;
        let id = packet.id()?;
        let parent = self.record(h.parent)?;
        let prior = self.state_at(h.parent)?;
        let registered_task = self.eligible_work_task_from_state(&prior, h.work_task, h.height)?;
        let executed = self.execute_derived(
            &prior,
            h.parent,
            &packet.transactions,
            h.height,
            h.miner,
            self.workers,
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
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO blocks VALUES(?,?,?,?,?,?)",
            params![
                id.as_slice(),
                h.parent.as_slice(),
                h.height,
                work.bytes().as_slice(),
                bytes,
                h.state.as_slice()
            ],
        )?;
        crate::ancestry_index::insert(&tx, index_context, id)?;
        for key in keys {
            let before = prior.get(key).map(canonical).transpose()?;
            let after = output.state.get(key).map(canonical).transpose()?;
            if before != after {
                tx.execute(
                    "INSERT INTO deltas VALUES(?,?,?,?)",
                    params![id.as_slice(), key, before, after],
                )?;
            }
        }
        if h.height.is_multiple_of(128) {
            tx.execute(
                "INSERT INTO snapshots VALUES(?,?)",
                params![id.as_slice(), canonical(&output.state)?],
            )?;
            tx.execute("DELETE FROM snapshots WHERE block!=? AND block NOT IN (SELECT snapshots.block FROM snapshots JOIN blocks ON blocks.id=snapshots.block ORDER BY blocks.height DESC,blocks.id LIMIT 64)",[self.settings.genesis.as_slice()])?;
        }
        tx.commit()?;
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
        if matches!(
            self.settings.task_profile(),
            LIFECYCLE_TASK_PROFILE | ATOMIC_TASK_PROFILE | OVERLAP_TASK_PROFILE
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
    fn prepare_from_checked_parent(
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
            ParentTaskEligibility::Legacy => Ok(false),
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
        tx.commit()?;
        Ok(result)
    }
    fn apply_delta(&self, id: Hash, slot: u64, detach: bool) -> Result<()> {
        for (key, before, after) in self.delta_rows(id)? {
            let (expected, new) = if detach {
                (after, before)
            } else {
                (before, after)
            };
            let actual: Option<Vec<u8>> = self
                .db
                .query_row(
                    "SELECT value FROM kv WHERE slot=? AND key=?",
                    params![slot, &key],
                    |r| r.get(0),
                )
                .optional()?;
            ensure(actual == expected, "UNDO_ROOT")?;
            if let Some(value) = new {
                self.db.execute(
                    "INSERT OR REPLACE INTO kv VALUES(?,?,?)",
                    params![slot, key, value],
                )?;
            } else {
                self.db
                    .execute("DELETE FROM kv WHERE slot=? AND key=?", params![slot, key])?;
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
                staged = Some(self.checked_commitment(
                    &self.slot_state(slot)?,
                    self.record(target)?.root,
                    prior.as_ref(),
                )?);
                self.db.execute(
                    "UPDATE active SET tip=?,generation=? WHERE singleton=1",
                    params![target.as_slice(), next],
                )?;
                self.db.execute(
                    "INSERT INTO events VALUES(?,0,1,?)",
                    params![next, target.as_slice()],
                )?;
                Ok(())
            })?;
            ensure(
                self.active()? == (target, next) && self.slot()? == slot,
                "GENERATION",
            )?;
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
            ensure(ordinal == count, "REORG_STEPS")?;
            match kind {
                0 => {
                    ensure(!attaching && id == current, "REORG_STEPS")?;
                    current = self.parent(id)?;
                }
                1 => {
                    attaching = true;
                    ensure(self.parent(id)? == current, "REORG_STEPS")?;
                    current = id;
                }
                _ => return Err("REORG_STEPS".into()),
            }
            count = count.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
        }
        ensure(current == target && cursor <= count, "REORG_STEPS")?;
        Ok(count)
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
        ensure(done <= 1, "REORG_STEPS")?;
        if done == 1 {
            return Ok(self.active()?.0);
        }
        self.invalidate_commitment();
        let old = bytes32(old)?;
        let target = bytes32(target)?;
        ensure(g > 0 && self.active()? == (old, g - 1), "GENERATION")?;
        let count = self.check_steps(old, target, position)?;
        for index in position..count {
            let (kind, bytes) = self.db.query_row(
                "SELECT kind,block FROM steps WHERE ordinal=?",
                [index],
                |r| Ok((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )?;
            let id = bytes32(bytes)?;
            self.atomic(|| {
                self.apply_delta(id, g, kind == 0)?;
                self.db
                    .execute("UPDATE reorg SET cursor=? WHERE singleton=1", [index + 1])?;
                Ok(())
            })?;
            cut(
                hook,
                &format!("{}:{index}", if kind == 0 { "detach" } else { "attach" }),
            )?;
        }
        ensure(
            root(&self.slot_state(g)?)? == self.record(target)?.root,
            "ROOT",
        )?;
        cut(hook, "before-publish")?;
        self.atomic(|| {
            self.db.execute(
                "UPDATE active SET tip=?,generation=?,state_slot=? WHERE singleton=1",
                params![target.as_slice(), g, g],
            )?;
            self.db.execute(
                "INSERT INTO events SELECT ?,ordinal,kind,block FROM steps ORDER BY ordinal",
                [g],
            )?;
            self.db
                .execute("UPDATE reorg SET done=1 WHERE singleton=1", [])?;
            self.db.execute("DELETE FROM kv WHERE slot!=?", [g])?;
            Ok(())
        })?;
        cut(hook, "published")?;
        Ok(target)
    }
    pub fn recover(&mut self) -> Result<Hash> {
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
            ensure(
                self.stored_header(current)?.timestamp as u128 <= bound,
                "TIME_DEFERRED",
            )?;
            current = self.parent(current)?;
        }
        Ok(())
    }
    pub fn activate_observed(&mut self, tip: Hash, observed_now: u64) -> Result<Hash> {
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
        let (tip, generation, _) = self.read_active()?;
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
            if checked.is_multiple_of(256) {
                progress(checked)?;
            }
            if included.contains_key(&current) {
                found.insert(current);
            }
            ensure(
                self.stored_header(current)?.timestamp as u128 <= bound,
                "TIME_DEFERRED",
            )?;
            current = self.parent(current)?;
            checked = checked.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
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
    pub fn history(&self, tip: Hash, after: Hash, limit: usize) -> Result<Vec<Packet>> {
        self.history_with_progress(tip, after, limit, &mut |_| Ok(()))
    }
    pub fn history_with_progress(
        &self,
        tip: Hash,
        after: Hash,
        limit: usize,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<Vec<Packet>> {
        progress(0)?;
        self.ready()?;
        ensure((1..=16).contains(&limit), "PAGE_LIMIT")?;
        ensure(
            self.record(after)?.height <= self.record(tip)?.height,
            "CURSOR",
        )?;
        let mut spool = tempfile::tempfile()?;
        let mut current = tip;
        let mut count = 0u64;
        while current != after {
            if count.is_multiple_of(256) {
                progress(count)?;
            }
            ensure(current != self.settings.genesis(), "CURSOR")?;
            spool.write_all(&current)?;
            count = count.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
            current = self.parent(current)?;
        }
        let mut packets = Vec::new();
        let mut bytes = 0usize;
        for i in (0..count).rev().take(limit) {
            spool.seek(SeekFrom::Start(i.checked_mul(32).ok_or("ANCESTRY_LIMIT")?))?;
            let mut id = [0; 32];
            spool.read_exact(&mut id)?;
            let packet = self.packet(id)?;
            let n = packet.encode()?.len();
            if bytes + n > 800_000 && !packets.is_empty() {
                break;
            }
            bytes += n;
            packets.push(packet);
        }
        progress(count)?;
        Ok(packets)
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
        )?;
        progress(lookup.sql_lookups + 2)?;
        let raw: Vec<u8> = self.db.query_row(
            "SELECT packet FROM blocks WHERE id=? AND length(packet)<=?",
            params![id.as_slice(), maximum],
            |r| r.get(0),
        )?;
        let packet = Packet::decode(&raw)?;
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
