//! Explicit native PNQ2 three-table rollback witness; not whole-node finality.
//! The Node binary, writer credential, pinned binding and independent service
//! must remain trusted outside a Node-database rollback. Current is not a lease.
//! This reconstructed source has a new identity; lost-source tests do not apply.

use crate::{ensure, Error, Result};
use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use rustix::net::{RecvFlags, SendFlags};
use sha2::{Digest, Sha512};
#[cfg(test)]
use std::io::Write;
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};
use trnm_protocol::pq_frame::{ml_dsa_65_key_id_from_spki, ML_DSA_65_SIGNATURE_BYTES};

const REQUEST_DOMAIN: &[u8] = b"TRNM/PNQ2/external-owner-witness/request/v1\0";
const REPLY_DOMAIN: &[u8] = b"TRNM/PNQ2/external-owner-witness/reply/v1\0";
const BINDING_DOMAIN: &[u8] = b"TRNM/PNQ2/external-owner-witness/binding/v1\0";
const REQUEST_BODY: usize = 245;
const REPLY_BODY: usize = 172;
const REQUEST_BYTES: usize = REQUEST_BODY + ML_DSA_65_SIGNATURE_BYTES;
const REPLY_BYTES: usize = REPLY_BODY + ML_DSA_65_SIGNATURE_BYTES;
const DDL: &str = "CREATE TABLE witness_v1(singleton INTEGER PRIMARY KEY CHECK(singleton=1),binding BLOB NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),root BLOB NOT NULL CHECK(length(root)=64),previous_sequence INTEGER NOT NULL CHECK(previous_sequence>=0),previous_root BLOB NOT NULL CHECK(length(previous_root)=64));";
pub const MAX_EXCHANGE: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub sequence: u64,
    pub root: [u8; 64],
}
impl Checkpoint {
    pub fn new(sequence: u64, root: [u8; 64]) -> Result<Self> {
        ensure(
            (1..=i64::MAX as u64).contains(&sequence) && root != [0; 64],
            "PQ_WITNESS_CHECKPOINT",
        )?;
        Ok(Self { sequence, root })
    }
    fn bytes(self) -> [u8; 72] {
        let mut out = [0; 72];
        out[..8].copy_from_slice(&self.sequence.to_be_bytes());
        out[8..].copy_from_slice(&self.root);
        out
    }
    fn decode(raw: &[u8]) -> Result<Self> {
        ensure(raw.len() == 72, "PQ_WITNESS_CHECKPOINT")?;
        Self::new(
            u64::from_be_bytes(raw[..8].try_into().map_err(|_| "PQ_WITNESS_CHECKPOINT")?),
            raw[8..].try_into().map_err(|_| "PQ_WITNESS_CHECKPOINT")?,
        )
    }
}

/// Full policy bytes and both canonical identities are pinned out of database.
pub struct WitnessBinding {
    canonical: Vec<u8>,
    policy_length: usize,
    id: [u8; 64],
    witness: PqNativeVerifier,
    writer: PqNativeVerifier,
}
impl WitnessBinding {
    pub fn new(
        policy: &crate::ingress::pq_network::PqNetworkPolicy,
        generation: u64,
        witness_spki: &[u8],
        writer_spki: &[u8],
    ) -> Result<Self> {
        ensure(
            (1..=i64::MAX as u64).contains(&generation),
            "PQ_WITNESS_GENERATION",
        )?;
        let witness_id = ml_dsa_65_key_id_from_spki(witness_spki).map_err(crypto)?;
        let writer_id = ml_dsa_65_key_id_from_spki(writer_spki).map_err(crypto)?;
        ensure(witness_id != writer_id, "PQ_WITNESS_IDENTITY_SEPARATION")?;
        let mut canonical = BINDING_DOMAIN.to_vec();
        canonical.extend(generation.to_be_bytes());
        canonical.extend((policy.canonical().len() as u64).to_be_bytes());
        canonical.extend(policy.canonical());
        canonical.extend(witness_spki);
        canonical.extend(writer_spki);
        Ok(Self {
            id: Sha512::digest(&canonical).into(),
            canonical,
            policy_length: policy.canonical().len(),
            witness: PqNativeVerifier::from_pinned_spki(witness_spki, witness_id)
                .map_err(crypto)?,
            writer: PqNativeVerifier::from_pinned_spki(writer_spki, writer_id).map_err(crypto)?,
        })
    }
    pub fn id(&self) -> [u8; 64] {
        self.id
    }
    pub(crate) fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    pub(crate) fn policy_length(&self) -> usize {
        self.policy_length
    }
    pub(crate) fn matches_policy(&self, policy: &[u8]) -> bool {
        let start = BINDING_DOMAIN.len() + 16;
        policy.len() == self.policy_length
            && self.canonical.get(start..start + policy.len()) == Some(policy)
    }
}
pub fn initial_network_checkpoint(
    policy: &crate::ingress::pq_network::PqNetworkPolicy,
    binding: &WitnessBinding,
) -> Result<Checkpoint> {
    crate::store::pq_rollback_witness::initial_checkpoint(policy, binding)
}
fn crypto(e: impl std::fmt::Debug) -> Error {
    Error::from(format!("PQ_WITNESS_CRYPTO:{e:?}"))
}
fn deadline(until: Instant) -> Result<Duration> {
    let left = until.saturating_duration_since(Instant::now());
    ensure(!left.is_zero(), "PQ_WITNESS_DEADLINE")?;
    Ok(left)
}
fn message(domain: &[u8], body: &[u8]) -> Vec<u8> {
    [domain, body].concat()
}
fn read_until(stream: &mut UnixStream, mut output: &mut [u8], until: Instant) -> Result<()> {
    while !output.is_empty() {
        deadline(until)?;
        // Per-call nonblocking I/O does not change O_NONBLOCK on this stream
        // or any try_clone alias. A socket timeout alone is not an absolute
        // limit for a syscall that continues making partial progress.
        match rustix::net::recv(&*stream, &mut *output, RecvFlags::DONTWAIT)
            .map_err(std::io::Error::from)
        {
            Ok((0, _)) => return Err("PQ_WITNESS_EOF".into()),
            Ok((n, _)) => output = &mut output[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(deadline(until)?.min(Duration::from_millis(1)));
            }
            Err(e) => return Err(e.into()),
        }
        // Preserve a complete receipt for authenticated late-CAS reconciliation.
        if !output.is_empty() {
            deadline(until)?;
        }
    }
    Ok(())
}
fn write_until(stream: &mut UnixStream, mut input: &[u8], until: Instant) -> Result<()> {
    let flags = SendFlags::DONTWAIT;
    #[cfg(not(any(target_vendor = "apple", target_os = "redox", target_os = "vita")))]
    let flags = flags | SendFlags::NOSIGNAL;
    while !input.is_empty() {
        deadline(until)?;
        match rustix::net::send(&*stream, input, flags).map_err(std::io::Error::from) {
            Ok(0) => return Err("PQ_WITNESS_WRITE_ZERO".into()),
            Ok(n) => input = &input[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(deadline(until)?.min(Duration::from_millis(1)));
            }
            Err(e) => return Err(e.into()),
        }
        deadline(until)?;
    }
    Ok(())
}
/// Transport supplies bytes, not trusted observations. Its implementation and
/// connection setup owner must enforce their declared absolute I/O bounds.
pub trait WitnessTransport: Send {
    fn exchange(&mut self, request: &[u8], until: Instant) -> Result<Vec<u8>>;
}
pub struct ConnectedWitnessTransport {
    stream: UnixStream,
}
impl ConnectedWitnessTransport {
    pub fn new(stream: UnixStream) -> Self {
        Self { stream }
    }
}
impl WitnessTransport for ConnectedWitnessTransport {
    fn exchange(&mut self, request: &[u8], until: Instant) -> Result<Vec<u8>> {
        ensure(request.len() == REQUEST_BYTES, "PQ_WITNESS_REQUEST_SIZE")?;
        write_until(&mut self.stream, request, until)?;
        let mut reply = vec![0; REPLY_BYTES];
        read_until(&mut self.stream, &mut reply, until)?;
        Ok(reply)
    }
}
pub struct WitnessClient {
    binding: WitnessBinding,
    writer: PqNativeSigningKey,
    transport: Box<dyn WitnessTransport>,
    unavailable: bool,
    #[cfg(test)]
    before_send: Option<Box<dyn FnMut(Instant) + Send>>,
}
impl WitnessClient {
    pub fn new(
        binding: WitnessBinding,
        writer: PqNativeSigningKey,
        transport: Box<dyn WitnessTransport>,
    ) -> Result<Self> {
        ensure(
            binding.writer.public_key_id() == writer.public_key_id(),
            "PQ_WITNESS_WRITER_PIN",
        )?;
        Ok(Self {
            binding,
            writer,
            transport,
            unavailable: false,
            #[cfg(test)]
            before_send: None,
        })
    }
    pub(crate) fn binding(&self) -> &WitnessBinding {
        &self.binding
    }
    pub(crate) fn available(&self) -> Result<()> {
        ensure(!self.unavailable, "PQ_WITNESS_UNAVAILABLE")
    }
    pub(crate) fn fail_closed(&mut self) {
        self.unavailable = true;
    }
    fn request(
        &mut self,
        previous: Option<Checkpoint>,
        next: Option<Checkpoint>,
        original: Option<Instant>,
    ) -> Result<Checkpoint> {
        self.available()?;
        let cap = Instant::now() + MAX_EXCHANGE;
        let until = original.map_or(cap, |v| v.min(cap));
        deadline(until)?;
        // Until transport entry no remote mutation or unread response exists.
        // A local preparation failure or cancellation must leave this client
        // usable; latching here would turn a short request into a service outage.
        let mut challenge = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut challenge)?;
        ensure(challenge != [0; 32], "PQ_WITNESS_CHALLENGE")?;
        let mut body = b"PWR1".to_vec();
        body.push(if previous.is_some() { 2 } else { 1 });
        body.extend(self.binding.id);
        body.extend(previous.map_or([0; 72], Checkpoint::bytes));
        body.extend(next.map_or([0; 72], Checkpoint::bytes));
        body.extend(challenge);
        body.extend(
            self.writer
                .sign_exact_message(&message(REQUEST_DOMAIN, &body))
                .map_err(crypto)?,
        );
        #[cfg(test)]
        if let Some(before_send) = self.before_send.as_mut() {
            before_send(until);
        }
        deadline(until)?;
        let result: Result<Checkpoint> = (|| {
            let reply = self.transport.exchange(&body, until)?;
            ensure(
                reply.len() == REPLY_BYTES
                    && &reply[..4] == b"PWS1"
                    && reply[4..68] == self.binding.id
                    && reply[140..172] == challenge,
                "PQ_WITNESS_REPLY_CONTEXT",
            )?;
            self.binding
                .witness
                .verify_exact_message(
                    &message(REPLY_DOMAIN, &reply[..REPLY_BODY]),
                    &reply[REPLY_BODY..],
                )
                .map_err(crypto)?;
            let observed = Checkpoint::decode(&reply[68..140])?;
            // Authenticated matching CAS success must be persisted locally even
            // if its verification completed after the live-use deadline.
            if next != Some(observed) {
                deadline(until)?;
            }
            Ok(observed)
        })();
        // Once exchange begins an error can leave an unread response or an
        // uncertain external CAS. This transport instance cannot be reused.
        if result.is_err() {
            self.fail_closed();
        }
        result
    }
    pub fn current(&mut self) -> Result<Checkpoint> {
        self.current_until(None)
    }
    pub(crate) fn current_until(&mut self, until: Option<Instant>) -> Result<Checkpoint> {
        self.request(None, None, until)
    }
    pub fn advance(&mut self, previous: Checkpoint, next: Checkpoint) -> Result<()> {
        self.advance_until(previous, next, None)
    }
    pub(crate) fn advance_until(
        &mut self,
        previous: Checkpoint,
        next: Checkpoint,
        until: Option<Instant>,
    ) -> Result<()> {
        ensure(
            previous.sequence.checked_add(1) == Some(next.sequence),
            "PQ_WITNESS_SEQUENCE",
        )?;
        if self.request(Some(previous), Some(next), until)? != next {
            self.fail_closed();
            return Err("PQ_WITNESS_CAS".into());
        }
        Ok(())
    }
}

/// Standalone native owner, not a public deployment or an independent-operator
/// qualification. The service key is not stored in this SQLite database.
pub struct DurableWitness {
    db: Connection,
    lock: File,
    path: PathBuf,
    identity: (u64, u64),
    parent_identity: (u64, u64),
    binding: WitnessBinding,
    signer: PqNativeSigningKey,
}
impl DurableWitness {
    pub fn register_new(
        path: &Path,
        binding: WitnessBinding,
        initial: Checkpoint,
        signer: PqNativeSigningKey,
    ) -> Result<Self> {
        Checkpoint::new(initial.sequence, initial.root)?;
        ensure(initial.sequence == 1, "PQ_WITNESS_REGISTRATION_SEQUENCE")?;
        ensure(
            signer.public_key_id() == binding.witness.public_key_id(),
            "PQ_WITNESS_SERVICE_PIN",
        )?;
        let path = storage_path(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        lock.try_lock_exclusive().map_err(|_| "PQ_WITNESS_BUSY")?;
        let identity = file_identity(&lock.metadata()?);
        let parent_identity =
            file_identity(&fs::metadata(path.parent().ok_or("PQ_WITNESS_PATH")?)?);
        let mut db = Self::connection(&path)?;
        ensure(
            file_identity(&fs::symlink_metadata(&path)?) == identity,
            "PQ_WITNESS_STORAGE_IDENTITY",
        )?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(DDL)?;
        tx.execute(
            "INSERT INTO witness_v1 VALUES(1,?,?,?,0,?)",
            params![
                binding.canonical(),
                initial.sequence,
                initial.root.as_slice(),
                [0_u8; 64].as_slice()
            ],
        )?;
        tx.commit()?;
        lock.sync_all()?;
        File::open(path.parent().ok_or("PQ_WITNESS_PATH")?)?.sync_all()?;
        let owner = Self {
            db,
            lock,
            path,
            identity,
            parent_identity,
            binding,
            signer,
        };
        owner.check_storage()?;
        Ok(owner)
    }
    pub fn open_existing(
        path: &Path,
        binding: WitnessBinding,
        signer: PqNativeSigningKey,
    ) -> Result<Self> {
        ensure(
            signer.public_key_id() == binding.witness.public_key_id(),
            "PQ_WITNESS_SERVICE_PIN",
        )?;
        let path = storage_path(path)?;
        let meta = fs::symlink_metadata(&path)?;
        ensure(
            meta.is_file() && !meta.file_type().is_symlink(),
            "PQ_WITNESS_PATH",
        )?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        lock.try_lock_exclusive().map_err(|_| "PQ_WITNESS_BUSY")?;
        let identity = file_identity(&lock.metadata()?);
        ensure(
            file_identity(&meta) == identity,
            "PQ_WITNESS_STORAGE_IDENTITY",
        )?;
        let parent_identity =
            file_identity(&fs::metadata(path.parent().ok_or("PQ_WITNESS_PATH")?)?);
        let db = Self::connection(&path)?;
        let owner = Self {
            db,
            lock,
            path,
            identity,
            parent_identity,
            binding,
            signer,
        };
        owner.read_head()?;
        Ok(owner)
    }
    fn connection(path: &Path) -> Result<Connection> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(Duration::ZERO)?;
        db.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;",
        )?;
        Ok(db)
    }
    fn read_head(&self) -> Result<Checkpoint> {
        self.check_storage()?;
        let (binding, seq, root): (Vec<u8>, u64, Vec<u8>) = self.db.query_row(
            "SELECT binding,sequence,root FROM witness_v1 WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure(binding == self.binding.canonical(), "PQ_WITNESS_BINDING")?;
        Checkpoint::new(seq, root.try_into().map_err(|_| "PQ_WITNESS_STATE")?)
    }
    pub fn handle(&mut self, request: &[u8], until: Instant) -> Result<Vec<u8>> {
        deadline(until)?;
        self.check_storage()?;
        ensure(
            request.len() == REQUEST_BYTES
                && &request[..4] == b"PWR1"
                && request[5..69] == self.binding.id
                && request[213..245] != [0; 32],
            "PQ_WITNESS_REQUEST_CONTEXT",
        )?;
        ensure(matches!(request[4], 1 | 2), "PQ_WITNESS_OPERATION")?;
        if request[4] == 1 {
            ensure(request[69..213] == [0; 144], "PQ_WITNESS_CURRENT_FIELDS")?;
        }
        self.binding
            .writer
            .verify_exact_message(
                &message(REQUEST_DOMAIN, &request[..REQUEST_BODY]),
                &request[REQUEST_BODY..],
            )
            .map_err(crypto)?;
        deadline(until)?;
        let head = if request[4] == 2 {
            let previous = Checkpoint::decode(&request[69..141])?;
            let next = Checkpoint::decode(&request[141..213])?;
            ensure(
                previous.sequence.checked_add(1) == Some(next.sequence),
                "PQ_WITNESS_SEQUENCE",
            )?;
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            validate_row(&tx, self.binding.canonical().len())?;
            let (binding,seq,root,old_seq,old_root):(Vec<u8>,u64,Vec<u8>,u64,Vec<u8>)=tx.query_row("SELECT binding,sequence,root,previous_sequence,previous_root FROM witness_v1 WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
            ensure(binding == self.binding.canonical(), "PQ_WITNESS_BINDING")?;
            let current = Checkpoint::new(seq, root.try_into().map_err(|_| "PQ_WITNESS_STATE")?)?;
            if current == next {
                ensure(
                    old_seq == previous.sequence && old_root == previous.root,
                    "PQ_WITNESS_RETRY_CONFLICT",
                )?;
            } else {
                ensure(current == previous, "PQ_WITNESS_CAS")?;
                ensure(tx.execute("UPDATE witness_v1 SET sequence=?,root=?,previous_sequence=?,previous_root=? WHERE singleton=1 AND sequence=? AND root=?",params![next.sequence,next.root.as_slice(),previous.sequence,previous.root.as_slice(),previous.sequence,previous.root.as_slice()])?==1,"PQ_WITNESS_CAS")?;
            }
            deadline(until)?;
            tx.commit()?;
            next
        } else {
            self.read_head()?
        };
        self.check_storage()?;
        let mut reply = b"PWS1".to_vec();
        reply.extend(self.binding.id);
        reply.extend(head.bytes());
        reply.extend(&request[213..245]);
        reply.extend(
            self.signer
                .sign_exact_message(&message(REPLY_DOMAIN, &reply))
                .map_err(crypto)?,
        );
        deadline(until)?;
        Ok(reply)
    }
    pub fn serve_one(&mut self, stream: &mut UnixStream, until: Instant) -> Result<()> {
        let mut request = vec![0; REQUEST_BYTES];
        read_until(stream, &mut request, until)?;
        let reply = self.handle(&request, until)?;
        write_until(stream, &reply, until)
    }
    pub fn storage_path(&self) -> &Path {
        &self.path
    }
    fn check_storage(&self) -> Result<()> {
        let parent = self.path.parent().ok_or("PQ_WITNESS_PATH")?;
        let meta = fs::symlink_metadata(&self.path)?;
        let parent_meta = fs::symlink_metadata(parent)?;
        let uid = rustix::process::geteuid().as_raw();
        ensure(
            meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.nlink() == 1
                && meta.uid() == uid
                && meta.mode() & 0o077 == 0
                && file_identity(&meta) == self.identity
                && file_identity(&self.lock.metadata()?) == self.identity
                && parent_meta.is_dir()
                && !parent_meta.file_type().is_symlink()
                && parent_meta.uid() == uid
                && parent_meta.mode() & 0o022 == 0
                && file_identity(&parent_meta) == self.parent_identity,
            "PQ_WITNESS_STORAGE_IDENTITY",
        )?;
        // This exact schema needs no implicit index or SQLite auxiliary table.
        // Check cardinality and byte widths in SQL, then compare scalars. Never
        // collect attacker-restored names or SQL text into unbounded Strings.
        let count: u64 = self
            .db
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))?;
        ensure(count == 1, "PQ_WITNESS_SCHEMA")?;
        let expected = DDL.trim_end_matches(';');
        let valid:bool=self.db.query_row("SELECT COALESCE(typeof(type)='text' AND length(CAST(type AS BLOB))=5 AND type='table' AND typeof(name)='text' AND length(CAST(name AS BLOB))=10 AND name='witness_v1' AND typeof(tbl_name)='text' AND length(CAST(tbl_name AS BLOB))=10 AND tbl_name='witness_v1' AND typeof(sql)='text' AND length(CAST(sql AS BLOB))=? AND sql=?,0) FROM sqlite_master",params![expected.len(),expected],|r|r.get(0))?;
        ensure(valid, "PQ_WITNESS_SCHEMA")?;
        validate_row(&self.db, self.binding.canonical().len())
    }
}
fn validate_row(db: &Connection, binding_length: usize) -> Result<()> {
    let count: u64 = db.query_row("SELECT COUNT(*) FROM witness_v1", [], |r| r.get(0))?;
    ensure(count == 1, "PQ_WITNESS_STATE")?;
    let valid:bool=db.query_row("SELECT typeof(singleton)='integer' AND singleton=1 AND typeof(binding)='blob' AND length(binding)=? AND typeof(sequence)='integer' AND sequence>0 AND typeof(root)='blob' AND length(root)=64 AND typeof(previous_sequence)='integer' AND previous_sequence>=0 AND typeof(previous_root)='blob' AND length(previous_root)=64 FROM witness_v1",[binding_length],|r|r.get(0))?;
    ensure(valid, "PQ_WITNESS_STATE_WIDTH")
}
fn file_identity(meta: &fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}
fn storage_path(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().ok_or("PQ_WITNESS_PATH")?.canonicalize()?;
    let meta = fs::metadata(&parent)?;
    ensure(
        meta.is_dir()
            && meta.mode() & 0o022 == 0
            && meta.uid() == rustix::process::geteuid().as_raw(),
        "PQ_WITNESS_PARENT",
    )?;
    Ok(parent.join(path.file_name().ok_or("PQ_WITNESS_PATH")?))
}

#[cfg(test)]
mod tests;
