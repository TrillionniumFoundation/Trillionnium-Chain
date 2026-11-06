//! Explicit development client journal for the existing pinned PQ native owner.
//!
//! This is a fresh client namespace, separate from Node admission and chain
//! State. Creation requires an independently selected fresh peer/policy whose
//! remote sequence has never been spent. Opening never enrolls a missing store,
//! adopts a different context, rewinds a cursor or renews a signed request.
//! The credential must have one outbound owner; other users of the same key can
//! strand this journal. There is no automatic parent recovery or history write.
//!
//! The audited PqServer/PqTlsServer emits a signed response only after its
//! terminal receipt and sequence commit, or from that committed receipt cache.
//! Authentication, resource and admission failures produce no signed response.
//! Both successful and refused *terminal* replies therefore consume a sequence;
//! a transport error, timeout, cancellation or history observation cannot do so.
//!
//! All original request bytes and terminal signatures are retained under fixed
//! bounds. Linux boot identity and CLOCK_BOOTTIME preserve an operation's local
//! budget over process reopen. A different boot, expired lease or cancellation
//! leaves an unresolved operation frozen; it never authorizes the next sequence.
//! This local SQLite journal has no independent rollback witness. A coherent
//! whole-store restore across restart, hostile same-uid storage, key custody,
//! production/WAN use and complete recovery/finality remain outside its claim.

use super::{
    outbound_request_digest, PqClient, PqNetworkPolicy, PqResponse, PreparedPqRequest, Request,
    VerifiedPqReply, MAX_WIRE, TPQ1_SIGNED_BYTES,
};
use crate::{ensure, Result};
use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::io::Read;
use std::{
    fs::{self, File, OpenOptions},
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use trnm_protocol::pon_wire::Hash;

pub const MAX_OUTBOUND_RECORDS: u64 = 64;
pub const MAX_OUTBOUND_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_OUTBOUND_ATTEMPTS: u64 = 8;
pub const MAX_OPERATION_LIFETIME: Duration = Duration::from_secs(60);
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
const BINDING_DOMAIN: &[u8] = b"TRNM/PQNetwork/durable-outbound/binding/v1\0";
const STATE_DOMAIN: &[u8] = b"TRNM/PQNetwork/durable-outbound/state/v1\0";
const META: &str = "CREATE TABLE pq_outbound_meta_v1(singleton INTEGER PRIMARY KEY CHECK(singleton=1),binding BLOB NOT NULL,highest_sequence INTEGER NOT NULL CHECK(highest_sequence>=0))";
const RECORD: &str = "CREATE TABLE pq_outbound_request_v1(sequence INTEGER PRIMARY KEY CHECK(sequence>0),operation BLOB NOT NULL CHECK(length(operation)=32),wire BLOB NOT NULL,boot_id BLOB NOT NULL CHECK(length(boot_id)=16),started_ns INTEGER NOT NULL CHECK(started_ns>=0),deadline_ns INTEGER NOT NULL CHECK(deadline_ns>started_ns),attempts INTEGER NOT NULL CHECK(attempts>=0 AND attempts<=8),cancelled INTEGER NOT NULL CHECK(cancelled IN(0,1)),response BLOB)";

enum Client {
    Plaintext(PqClient),
    #[cfg(feature = "pq-native-openssl")]
    Tls(super::tls::PqTlsClient),
}
impl Client {
    fn base(&self) -> &PqClient {
        match self {
            Self::Plaintext(client) => client,
            #[cfg(feature = "pq-native-openssl")]
            Self::Tls(client) => client.signing_client(),
        }
    }
    fn require_transport(&self) -> Result<()> {
        match self {
            Self::Plaintext(client) => client.policy.require_plaintext(),
            #[cfg(feature = "pq-native-openssl")]
            Self::Tls(client) => client.signing_client().policy.tls_pins().map(|_| ()),
        }
    }
    fn send(
        &self,
        address: SocketAddr,
        request: &PreparedPqRequest,
        deadline: Instant,
    ) -> Result<VerifiedPqReply> {
        match self {
            Self::Plaintext(client) => client.send_verified_until(address, request, deadline),
            #[cfg(feature = "pq-native-openssl")]
            Self::Tls(client) => client.send_verified_until(address, request, deadline),
        }
    }
}

/// Observations only; constructing or editing this value grants no send rights.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPqOperation {
    pub sequence: u64,
    pub operation: Hash,
    pub expires_at: u64,
    pub attempts: u64,
    pub cancelled: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PqOutboundStatus {
    pub completed_sequence: u64,
    pub records: u64,
    pub reserved_bytes: u64,
    pub pending: Option<PendingPqOperation>,
}

struct Record {
    sequence: u64,
    operation: Hash,
    wire: Vec<u8>,
    boot_id: [u8; 16],
    started_ns: u64,
    deadline_ns: u64,
    attempts: u64,
    cancelled: bool,
    response: Option<Vec<u8>>,
    expiry: u64,
}
impl Record {
    fn observation(&self) -> PendingPqOperation {
        PendingPqOperation {
            sequence: self.sequence,
            operation: self.operation,
            expires_at: self.expiry,
            attempts: self.attempts,
            cancelled: self.cancelled,
        }
    }
}
struct Snapshot {
    highest: u64,
    reserved_bytes: u64,
    records: Vec<Record>,
    digest: Hash,
}
impl Snapshot {
    fn pending(&self) -> Option<&Record> {
        self.records.last().filter(|row| row.response.is_none())
    }
}

/// One locked journal, one pinned destination, one owned signing client and at
/// most one unresolved sequence. It never accepts a public PqResponse as an ACK.
pub struct DurablePqOutbound {
    db: Connection,
    lock: File,
    path: PathBuf,
    identity: (u64, u64),
    parent_identity: (u64, u64),
    binding: Vec<u8>,
    client: Client,
    address: SocketAddr,
    known_digest: Hash,
    commit_uncertain: bool,
}

impl DurablePqOutbound {
    pub fn create_plaintext(path: &Path, address: SocketAddr, client: PqClient) -> Result<Self> {
        Self::open(path, address, Client::Plaintext(client), true)
    }
    pub fn open_plaintext(path: &Path, address: SocketAddr, client: PqClient) -> Result<Self> {
        Self::open(path, address, Client::Plaintext(client), false)
    }
    #[cfg(feature = "pq-native-openssl")]
    pub fn create_tls(
        path: &Path,
        address: SocketAddr,
        client: super::tls::PqTlsClient,
    ) -> Result<Self> {
        Self::open(path, address, Client::Tls(client), true)
    }
    #[cfg(feature = "pq-native-openssl")]
    pub fn open_tls(
        path: &Path,
        address: SocketAddr,
        client: super::tls::PqTlsClient,
    ) -> Result<Self> {
        Self::open(path, address, Client::Tls(client), false)
    }
    fn open(path: &Path, address: SocketAddr, client: Client, create: bool) -> Result<Self> {
        client.require_transport()?;
        ensure(address.ip().is_loopback(), "PQ_NETWORK_LOOPBACK_ONLY")?;
        if create {
            boot_clock()?;
        }
        let parent = path.parent().ok_or("PQ_OUTBOUND_PATH")?.canonicalize()?;
        let parent_meta = fs::symlink_metadata(&parent)?;
        ensure(
            parent_meta.is_dir()
                && parent_meta.uid() == rustix::process::geteuid().as_raw()
                && parent_meta.mode() & 0o022 == 0,
            "PQ_OUTBOUND_PARENT",
        )?;
        let path = parent.join(path.file_name().ok_or("PQ_OUTBOUND_PATH")?);
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        if create {
            options.create_new(true);
        }
        let lock = options.open(&path)?;
        lock.try_lock_exclusive().map_err(|_| "PQ_OUTBOUND_BUSY")?;
        let metadata = lock.metadata()?;
        ensure(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o077 == 0
                && metadata.len() <= MAX_FILE_BYTES,
            "PQ_OUTBOUND_STORAGE_IDENTITY",
        )?;
        let identity = file_identity(&metadata);
        ensure(
            file_identity(&fs::symlink_metadata(&path)?) == identity,
            "PQ_OUTBOUND_STORAGE_IDENTITY",
        )?;
        let binding = binding(client.base(), address);
        let mut db = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(Duration::ZERO)?;
        // These settings are connection-local. Existing files must pass the
        // exact schema/context audit before any persistent journal-mode change.
        db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL;")?;
        let page_size: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
        ensure(page_size == 4096, "PQ_OUTBOUND_PAGE_SIZE")?;
        if create {
            db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA max_page_count=8192;")?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(META)?;
            tx.execute_batch(RECORD)?;
            tx.execute("INSERT INTO pq_outbound_meta_v1 VALUES(1,?,0)", [&binding])?;
            tx.commit()?;
            lock.sync_all()?;
            File::open(&parent)?.sync_all()?;
        }
        let mut owner = Self {
            db,
            lock,
            path,
            identity,
            parent_identity: file_identity(&parent_meta),
            binding,
            client,
            address,
            known_digest: [0; 32],
            commit_uncertain: false,
        };
        owner.known_digest = owner.audit()?.digest;
        if !create {
            owner
                .db
                .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA max_page_count=8192;")?;
            owner.checked()?;
        }
        Ok(owner)
    }

    pub fn status(&self) -> Result<PqOutboundStatus> {
        let snapshot = self.checked()?;
        Ok(PqOutboundStatus {
            completed_sequence: snapshot.highest,
            records: snapshot.records.len() as u64,
            reserved_bytes: snapshot.reserved_bytes,
            pending: snapshot.pending().map(Record::observation),
        })
    }

    /// Allocate the next sequence and persist its original randomized signature
    /// before any connection. Neither a pending request nor a full journal can
    /// be replaced, cleared or re-signed with a longer expiry.
    pub fn prepare(
        &mut self,
        request: Request,
        expires_at: u64,
        lifetime: Duration,
    ) -> Result<PendingPqOperation> {
        ensure(
            !lifetime.is_zero() && lifetime <= MAX_OPERATION_LIFETIME,
            "PQ_OUTBOUND_LIFETIME",
        )?;
        let (boot_id, started_ns) = boot_clock()?;
        let deadline_ns = started_ns
            .checked_add(u64::try_from(lifetime.as_nanos()).map_err(|_| "PQ_OUTBOUND_LIFETIME")?)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or("PQ_OUTBOUND_LIFETIME")?;
        let snapshot = self.checked()?;
        ensure(snapshot.pending().is_none(), "PQ_OUTBOUND_UNRESOLVED")?;
        ensure(
            snapshot.records.len() < MAX_OUTBOUND_RECORDS as usize,
            "PQ_OUTBOUND_RECORD_LIMIT",
        )?;
        let sequence = snapshot
            .highest
            .checked_add(1)
            .ok_or("PQ_OUTBOUND_SEQUENCE")?;
        let prepared = self.client.base().prepare(sequence, expires_at, request)?;
        ensure(
            snapshot.reserved_bytes + prepared.wire().len() as u64 + MAX_WIRE as u64 + 160
                <= MAX_OUTBOUND_BYTES,
            "PQ_OUTBOUND_BYTE_LIMIT",
        )?;
        live_clock(boot_id, deadline_ns, expires_at)?;
        let operation = prepared.operation_id();
        self.mutate(|tx| {
            ensure(
                tx.execute(
                    "INSERT INTO pq_outbound_request_v1 VALUES(?,?,?,?,?,?,0,0,NULL)",
                    params![
                        sequence,
                        operation.as_slice(),
                        prepared.wire(),
                        boot_id.as_slice(),
                        started_ns,
                        deadline_ns
                    ],
                )? == 1,
                "PQ_OUTBOUND_STATE",
            )
        })?;
        // An overrun after durable prepare leaves that exact request pending.
        live_clock(boot_id, deadline_ns, expires_at)?;
        Ok(PendingPqOperation {
            sequence,
            operation,
            expires_at,
            attempts: 0,
            cancelled: false,
        })
    }

    /// Retry only the retained bytes. Caller deadline, original boot-clock
    /// budget, original signed expiry and the existing ten-second client cap
    /// all apply. Cancellation is cooperative around one bounded exchange; an
    /// already dispatched request may have completed remotely and stays owned.
    pub fn send_pending(
        &mut self,
        attempt_deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<VerifiedPqReply> {
        let snapshot = self.checked()?;
        let pending = snapshot.pending().ok_or("PQ_OUTBOUND_NO_PENDING")?;
        ensure(!pending.cancelled, "PQ_OUTBOUND_CANCELLED")?;
        if cancel.load(Ordering::Acquire) {
            self.mark_cancelled(pending.sequence)?;
            return Err("PQ_OUTBOUND_CANCELLED".into());
        }
        let anchor = Instant::now();
        let remaining = live_clock(pending.boot_id, pending.deadline_ns, pending.expiry)?;
        let until = attempt_deadline
            .min(anchor + remaining)
            .min(anchor + Duration::from_secs(10));
        super::check_live_request(until, Some(pending.expiry))?;
        ensure(
            pending.attempts < MAX_OUTBOUND_ATTEMPTS,
            "PQ_OUTBOUND_ATTEMPT_LIMIT",
        )?;
        // Historical audit cannot create live send authority. Recheck the exact
        // stored signature against current time in the original verifier.
        let prepared = PreparedPqRequest {
            verified: self
                .policy()
                .verify_request(&pending.wire, crate::ingress::now()?)?,
        };
        self.client.base().check_send(
            self.address,
            &prepared,
            until.saturating_duration_since(Instant::now()),
        )?;
        self.mutate(|tx| {
            ensure(
                tx.execute(
                    "UPDATE pq_outbound_request_v1 SET attempts=attempts+1 WHERE sequence=? AND attempts=? AND cancelled=0 AND response IS NULL",
                    params![pending.sequence, pending.attempts],
                )? == 1,
                "PQ_OUTBOUND_STATE",
            )
        })?;
        // No failed/uncertain local commit can release a socket operation.
        if cancel.load(Ordering::Acquire) {
            self.mark_cancelled(pending.sequence)?;
            return Err("PQ_OUTBOUND_CANCELLED".into());
        }
        live_clock(pending.boot_id, pending.deadline_ns, pending.expiry)?;
        super::check_live_request(until, Some(pending.expiry))?;
        let result = self.client.send(self.address, &prepared, until);
        if let Ok(reply) = &result {
            // Keep an authenticated terminal even if cancellation or a local
            // storage overrun happens afterwards. A late result is no timely ACK.
            self.record_verified_reply(reply)?;
        }
        if cancel.load(Ordering::Acquire) {
            self.mark_cancelled(pending.sequence)?;
            return Err("PQ_OUTBOUND_CANCELLED".into());
        }
        let reply = result?;
        super::check_live_request(until, Some(pending.expiry))?;
        live_clock(pending.boot_id, pending.deadline_ns, pending.expiry)?;
        Ok(reply)
    }

    pub fn cancel_pending(&mut self) -> Result<()> {
        let snapshot = self.checked()?;
        let pending = snapshot.pending().ok_or("PQ_OUTBOUND_NO_PENDING")?;
        self.mark_cancelled(pending.sequence)
    }

    /// Retain only a sealed verified receipt for this exact prepared wire.
    /// This records a terminal transport fact, including a refused operation;
    /// it does not grant a fresh send, success, finality or recovery authority.
    /// Historical JSON and arbitrary public PqResponse values are not accepted.
    ///
    /// ```compile_fail,E0308
    /// use trnm_pon_node::ingress::pq_network::{PqResponse, outbound::DurablePqOutbound};
    /// fn forged(owner: &mut DurablePqOutbound, response: PqResponse) {
    ///     owner.record_verified_reply(&response).unwrap();
    /// }
    /// ```
    pub fn record_verified_reply(&mut self, reply: &VerifiedPqReply) -> Result<()> {
        let snapshot = self.checked()?;
        let record = snapshot
            .records
            .iter()
            .find(|r| r.sequence == reply.sequence)
            .ok_or("PQ_OUTBOUND_REPLY_CONTEXT")?;
        ensure(
            reply.policy == self.policy().id()
                && reply.peer == self.client.base().signer.public_key_id()
                && reply.operation == record.operation
                && reply.request_wire_digest == outbound_request_digest(&record.wire)
                && record.attempts > 0,
            "PQ_OUTBOUND_REPLY_CONTEXT",
        )?;
        let retained = self.policy().verify_retained_request(&record.wire)?;
        self.policy()
            .verify_retained_response(reply.wire(), &retained)?;
        if let Some(original) = &record.response {
            return ensure(original == reply.wire(), "PQ_OUTBOUND_CONFLICTING_REPLY");
        }
        ensure(
            record.sequence == snapshot.highest + 1,
            "PQ_OUTBOUND_SEQUENCE",
        )?;
        self.mutate(|tx| {
            ensure(
                tx.execute(
                    "UPDATE pq_outbound_request_v1 SET response=? WHERE sequence=? AND response IS NULL AND attempts>0",
                    params![reply.wire(), record.sequence],
                )? == 1,
                "PQ_OUTBOUND_STATE",
            )?;
            ensure(
                tx.execute(
                    "UPDATE pq_outbound_meta_v1 SET highest_sequence=? WHERE singleton=1 AND highest_sequence=?",
                    params![record.sequence, snapshot.highest],
                )? == 1,
                "PQ_OUTBOUND_STATE",
            )
        })
    }

    /// A previously verified terminal observation, not a new live receipt.
    /// Reopen audits at the original signed expiry without renewing authority.
    pub fn retained_response(&self, sequence: u64) -> Result<Option<PqResponse>> {
        let snapshot = self.checked()?;
        let Some(record) = snapshot.records.iter().find(|r| r.sequence == sequence) else {
            return Ok(None);
        };
        record
            .response
            .as_ref()
            .map(|wire| {
                self.policy().verify_response_fields(
                    wire,
                    self.client.base().signer.public_key_id(),
                    record.sequence,
                    record.expiry,
                    record.operation,
                    record.expiry,
                )
            })
            .transpose()
    }

    fn mark_cancelled(&mut self, sequence: u64) -> Result<()> {
        let snapshot = self.checked()?;
        let row = snapshot
            .records
            .iter()
            .find(|r| r.sequence == sequence)
            .ok_or("PQ_OUTBOUND_STATE")?;
        if row.cancelled {
            return Ok(());
        }
        self.mutate(|tx| {
            ensure(
                tx.execute("UPDATE pq_outbound_request_v1 SET cancelled=1 WHERE sequence=? AND cancelled=0", [sequence])? == 1,
                "PQ_OUTBOUND_STATE",
            )
        })
    }
    fn policy(&self) -> &PqNetworkPolicy {
        &self.client.base().policy
    }
    fn checked(&self) -> Result<Snapshot> {
        ensure(!self.commit_uncertain, "PQ_OUTBOUND_COMMIT_UNCERTAIN")?;
        let snapshot = self.audit()?;
        ensure(
            snapshot.digest == self.known_digest,
            "PQ_OUTBOUND_STORAGE_CHANGED",
        )?;
        Ok(snapshot)
    }
    fn mutate(&mut self, change: impl FnOnce(&Transaction<'_>) -> Result<()>) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Every error from here latches the live owner. Cold reopen resolves only
        // the actual transactional state; it cannot assume a failed ACK rolled back.
        self.commit_uncertain = true;
        change(&tx)?;
        tx.commit()?;
        self.lock.sync_all()?;
        self.known_digest = self.audit()?.digest;
        self.commit_uncertain = false;
        Ok(())
    }
    fn check_identity(&self) -> Result<()> {
        let meta = fs::symlink_metadata(&self.path)?;
        let parent = fs::symlink_metadata(self.path.parent().ok_or("PQ_OUTBOUND_PATH")?)?;
        let uid = rustix::process::geteuid().as_raw();
        ensure(
            meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.uid() == uid
                && meta.nlink() == 1
                && meta.mode() & 0o077 == 0
                && meta.len() <= MAX_FILE_BYTES
                && file_identity(&meta) == self.identity
                && file_identity(&self.lock.metadata()?) == self.identity
                && parent.is_dir()
                && !parent.file_type().is_symlink()
                && parent.uid() == uid
                && parent.mode() & 0o022 == 0
                && file_identity(&parent) == self.parent_identity,
            "PQ_OUTBOUND_STORAGE_IDENTITY",
        )
    }
    fn audit(&self) -> Result<Snapshot> {
        self.check_identity()?;
        let count: u64 = self
            .db
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))?;
        ensure(count == 2, "PQ_OUTBOUND_SCHEMA")?;
        let valid: u64 = self.db.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND ((name='pq_outbound_meta_v1' AND tbl_name='pq_outbound_meta_v1' AND sql=?) OR (name='pq_outbound_request_v1' AND tbl_name='pq_outbound_request_v1' AND sql=?))",
            params![META, RECORD], |r| r.get(0),
        )?;
        ensure(valid == 2, "PQ_OUTBOUND_SCHEMA")?;
        let count: u64 =
            self.db
                .query_row("SELECT COUNT(*) FROM pq_outbound_meta_v1", [], |r| r.get(0))?;
        ensure(count == 1, "PQ_OUTBOUND_STATE")?;
        let valid: bool = self.db.query_row(
            "SELECT typeof(singleton)='integer' AND singleton=1 AND typeof(binding)='blob' AND length(binding)=? AND typeof(highest_sequence)='integer' AND highest_sequence>=0 AND highest_sequence<=64 FROM pq_outbound_meta_v1",
            [self.binding.len()], |r| r.get(0),
        )?;
        ensure(valid, "PQ_OUTBOUND_STATE")?;
        let (stored_binding, highest): (Vec<u8>, u64) = self.db.query_row(
            "SELECT binding,highest_sequence FROM pq_outbound_meta_v1 WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure(stored_binding == self.binding, "PQ_OUTBOUND_BINDING")?;
        let count: u64 =
            self.db
                .query_row("SELECT COUNT(*) FROM pq_outbound_request_v1", [], |r| {
                    r.get(0)
                })?;
        ensure(
            count <= MAX_OUTBOUND_RECORDS && (count == highest || count == highest + 1),
            "PQ_OUTBOUND_STATE",
        )?;
        // Reject width/type/aggregate violations before allocating retained blobs.
        let invalid: u64 = self.db.query_row(
            "SELECT COUNT(*) FROM pq_outbound_request_v1 WHERE NOT COALESCE(typeof(sequence)='integer' AND sequence>0 AND sequence<=64 AND typeof(operation)='blob' AND length(operation)=32 AND typeof(wire)='blob' AND length(wire)>=? AND length(wire)<=? AND typeof(boot_id)='blob' AND length(boot_id)=16 AND typeof(started_ns)='integer' AND started_ns>=0 AND typeof(deadline_ns)='integer' AND deadline_ns>started_ns AND deadline_ns-started_ns<=60000000000 AND typeof(attempts)='integer' AND attempts>=0 AND attempts<=8 AND typeof(cancelled)='integer' AND cancelled IN(0,1) AND ((sequence<=? AND attempts>0 AND typeof(response)='blob' AND length(response)>=? AND length(response)<=?) OR (sequence=? AND response IS NULL)),0)",
            params![8 + TPQ1_SIGNED_BYTES, MAX_WIRE, highest, 8 + TPQ1_SIGNED_BYTES, MAX_WIRE, highest + 1], |r| r.get(0),
        )?;
        ensure(invalid == 0, "PQ_OUTBOUND_STATE_WIDTH")?;
        let reserved_bytes: u64 = self.db.query_row(
            "SELECT COALESCE(SUM(length(wire)+COALESCE(length(response),2097152)+160),0)+? FROM pq_outbound_request_v1",
            [self.binding.len()], |r| r.get(0),
        )?;
        ensure(
            reserved_bytes <= MAX_OUTBOUND_BYTES,
            "PQ_OUTBOUND_BYTE_LIMIT",
        )?;
        let mut digest = Sha256::new();
        digest.update(STATE_DOMAIN);
        digest.update(&self.binding);
        digest.update(highest.to_be_bytes());
        let mut records = Vec::with_capacity(count as usize);
        let mut statement = self.db.prepare(
            "SELECT sequence,operation,wire,boot_id,started_ns,deadline_ns,attempts,cancelled,response FROM pq_outbound_request_v1 ORDER BY sequence",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let mut record = Record {
                sequence: row.get(0)?,
                operation: row.get(1)?,
                wire: row.get(2)?,
                boot_id: row.get(3)?,
                started_ns: row.get(4)?,
                deadline_ns: row.get(5)?,
                attempts: row.get(6)?,
                cancelled: row.get(7)?,
                response: row.get(8)?,
                expiry: 0,
            };
            ensure(
                record.sequence == records.len() as u64 + 1,
                "PQ_OUTBOUND_SEQUENCE",
            )?;
            let retained = self.policy().verify_retained_request(&record.wire)?;
            ensure(
                retained.peer() == self.client.base().signer.public_key_id()
                    && retained.sequence() == record.sequence
                    && retained.operation() == record.operation,
                "PQ_OUTBOUND_REQUEST_CONTEXT",
            )?;
            record.expiry = retained.expiry();
            if let Some(response) = &record.response {
                self.policy()
                    .verify_retained_response(response, &retained)?;
            }
            for field in [
                record.sequence,
                record.started_ns,
                record.deadline_ns,
                record.attempts,
                u64::from(record.cancelled),
                record.wire.len() as u64,
                record.response.as_ref().map_or(0, |r| r.len() as u64),
            ] {
                digest.update(field.to_be_bytes());
            }
            digest.update(record.operation);
            digest.update(record.boot_id);
            digest.update(&record.wire);
            if let Some(response) = &record.response {
                digest.update(response);
            }
            records.push(record);
        }
        Ok(Snapshot {
            highest,
            reserved_bytes,
            records,
            digest: digest.finalize().into(),
        })
    }
}

fn binding(client: &PqClient, address: SocketAddr) -> Vec<u8> {
    let mut bytes = BINDING_DOMAIN.to_vec();
    bytes.extend((client.policy.canonical().len() as u64).to_be_bytes());
    bytes.extend(client.policy.canonical());
    bytes.extend(client.signer.public_key_id());
    bytes.extend(address.to_string().as_bytes());
    bytes
}
fn file_identity(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

#[cfg(target_os = "linux")]
fn boot_clock() -> Result<([u8; 16], u64)> {
    let mut text = String::new();
    File::open("/proc/sys/kernel/random/boot_id")?
        .take(38)
        .read_to_string(&mut text)?;
    ensure(
        text.len() == 37 && text.ends_with('\n'),
        "PQ_OUTBOUND_BOOT_ID",
    )?;
    let raw = &text.as_bytes()[..36];
    ensure(
        [8, 13, 18, 23].into_iter().all(|i| raw[i] == b'-'),
        "PQ_OUTBOUND_BOOT_ID",
    )?;
    let compact: Vec<u8> = raw
        .iter()
        .enumerate()
        .filter(|(i, _)| ![8, 13, 18, 23].contains(i))
        .map(|(_, b)| *b)
        .collect();
    let boot: [u8; 16] = hex::decode(compact)
        .map_err(|_| "PQ_OUTBOUND_BOOT_ID")?
        .try_into()
        .map_err(|_| "PQ_OUTBOUND_BOOT_ID")?;
    let clock = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let ns = u64::try_from(clock.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(clock.tv_nsec)
                .ok()
                .and_then(|ns| seconds.checked_add(ns))
        })
        .filter(|ns| *ns <= i64::MAX as u64)
        .ok_or("PQ_OUTBOUND_BOOT_CLOCK")?;
    Ok((boot, ns))
}
#[cfg(not(target_os = "linux"))]
fn boot_clock() -> Result<([u8; 16], u64)> {
    Err("PQ_OUTBOUND_BOOT_CLOCK_UNAVAILABLE".into())
}
fn live_clock(boot: [u8; 16], deadline_ns: u64, expiry: u64) -> Result<Duration> {
    let (current_boot, now) = boot_clock()?;
    ensure(current_boot == boot, "PQ_OUTBOUND_BOOT_CHANGED_UNCONFIRMED")?;
    ensure(
        crate::ingress::now()? <= expiry,
        "PQ_NETWORK_EXPIRED_UNCONFIRMED",
    )?;
    ensure(now < deadline_ns, "PQ_OUTBOUND_DEADLINE_UNCONFIRMED")?;
    Ok(Duration::from_nanos(deadline_ns - now))
}

#[cfg(all(test, feature = "pq-native-openssl", target_os = "linux"))]
mod tests;
