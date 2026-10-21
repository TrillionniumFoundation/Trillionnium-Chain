//! M07/M08 native branch persistence and recovery using the existing M06 executor.
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
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_executor::{execute, root, State};
use trnm_protocol::pon_wire::{hash, Hash, Header};
const DDL:&str="CREATE TABLE metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL);
CREATE TABLE blocks(id BLOB PRIMARY KEY,parent BLOB,height INTEGER NOT NULL,chainwork BLOB NOT NULL,packet BLOB,state_root BLOB NOT NULL);
CREATE INDEX work_order ON blocks(chainwork DESC,height,id);
CREATE TABLE deltas(block BLOB NOT NULL,key TEXT NOT NULL,before BLOB,after BLOB,PRIMARY KEY(block,key));
CREATE TABLE active(singleton INTEGER PRIMARY KEY CHECK(singleton=1),tip BLOB NOT NULL,generation INTEGER NOT NULL,state_slot INTEGER NOT NULL);
CREATE TABLE kv(slot INTEGER NOT NULL,key TEXT NOT NULL,value BLOB NOT NULL,PRIMARY KEY(slot,key));
CREATE TABLE reorg(singleton INTEGER PRIMARY KEY CHECK(singleton=1),old_tip BLOB NOT NULL,new_tip BLOB NOT NULL,generation INTEGER NOT NULL,cursor INTEGER NOT NULL,done INTEGER NOT NULL);
CREATE TABLE steps(ordinal INTEGER PRIMARY KEY,kind INTEGER NOT NULL,block BLOB NOT NULL);
CREATE TABLE events(generation INTEGER NOT NULL,ordinal INTEGER NOT NULL,kind INTEGER NOT NULL,block BLOB NOT NULL,PRIMARY KEY(generation,ordinal));
CREATE TABLE snapshots(block BLOB PRIMARY KEY,state BLOB NOT NULL);";
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
    packet: Option<Vec<u8>>,
    root: Hash,
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
        let schema_id = hash(b"native-branch-schema-v1", &[DDL.as_bytes()]);
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
        expected_db.execute_batch(DDL)?;
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
            "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        if !initialized {
            ensure(intent, "INITIALIZATION_INTENT_REQUIRED")?;
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute_batch(DDL)?;
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
        };
        node.read_active()?;
        node.recover()?;
        Ok(node)
    }
    pub fn settings(&self) -> &Settings {
        &self.settings
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
                "SELECT parent,height,chainwork,packet,state_root FROM blocks WHERE id=?",
                [id.as_slice()],
                |r| {
                    Ok((
                        r.get::<_, Option<Vec<u8>>>(0)?,
                        r.get::<_, u64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Option<Vec<u8>>>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or("UNKNOWN_PARENT")?;
        Ok(Record {
            parent: row.0.map(bytes32).transpose()?,
            height: row.1,
            work: Work::from_bytes(bytes64(row.2)?),
            packet: row.3,
            root: bytes32(row.4)?,
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
    pub fn read_active(&self) -> Result<(Hash, u64, State)> {
        self.namespace()?;
        let (tip, generation) = self.active()?;
        let state = self.slot_state(self.slot()?)?;
        ensure(root(&state)? == self.record(tip)?.root, "ROOT")?;
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
        let packet = Packet::decode(&row.packet.ok_or("GENESIS_HAS_NO_PACKET")?)?;
        ensure(
            packet.id()? == id
                && Some(packet.header.parent) == row.parent
                && packet.header.height == row.height
                && packet.header.state == row.root,
            "STORAGE_PACKET",
        )?;
        Ok(packet)
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
        let mut state: State = loop {
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
                ensure(root(&state)? == row.root, "ROOT")?;
                break state;
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
            ensure(root(&state)? == self.record(id)?.root, "ROOT")?;
        }
        Ok(state)
    }
    fn recent(&self, mut parent: Hash) -> Result<Vec<(u64, Hash)>> {
        let mut out = Vec::new();
        let bound = self.settings.limit("retarget_interval")?.max(11);
        while parent != self.settings.genesis() && out.len() < (bound as usize) {
            let packet = self.packet(parent)?;
            out.push((packet.header.timestamp, packet.header.target));
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
    pub fn admit(&mut self, packet: &Packet, observed_now: u64) -> Result<Hash> {
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
            return Ok(id);
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
        pon_work::verify(h.challenge(), h.work_task, h.target, &packet.proof)
            .map_err(|e| Error::from(format!("WORK:{e:?}")))?;
        let prior = self.state_at(h.parent)?;
        ensure(
            prior.get(&format!("work:{}", hex::encode(h.work_task))) == Some(&Value::Bool(true)),
            "TASK",
        )?;
        let output = execute(
            &prior,
            &packet.transactions,
            h.height,
            h.miner,
            h.parent,
            self.workers,
            &self.settings.app,
        )?;
        ensure(
            h.state == output.root && h.receipts == sequence_root("receipts", &output.receipts),
            "ROOT",
        )?;
        let work = parent
            .work
            .checked_add(consensus::required_work(h.target)?)?;
        let mut keys: std::collections::BTreeSet<_> = prior.keys().collect();
        keys.extend(output.state.keys());
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
        self.ready()?;
        ensure((1..=4096).contains(&max_attempts), "WORK_BUDGET")?;
        let height = self.record(parent)?.height.checked_add(1).ok_or("HEIGHT")?;
        let output = execute(
            &self.state_at(parent)?,
            &transactions,
            height,
            miner,
            parent,
            self.workers,
            &self.settings.app,
        )?;
        let (a, b) = maintenance();
        let task = pon_work::task_id(&a, &b).map_err(|_| Error::from("WORK_TASK"))?;
        let mut header = Header {
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
        let prepared =
            pon_work::PreparedTask::new(&a, &b).map_err(|e| Error::from(format!("WORK:{e:?}")))?;
        for nonce in 0..max_attempts {
            header.nonce = nonce;
            let challenge = header.challenge();
            let proof = prepared
                .prove(challenge)
                .map_err(|e| Error::from(format!("WORK:{e:?}")))?;
            if hash(b"ticket", &[&challenge, &proof[proof.len() - 32..]]) <= header.target {
                return Ok(Packet {
                    header,
                    transactions,
                    proof,
                });
            }
        }
        Err("WORK_BUDGET".into())
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
            self.atomic(|| {
                self.apply_delta(target, slot, false)?;
                ensure(
                    root(&self.slot_state(slot)?)? == self.record(target)?.root,
                    "ROOT",
                )?;
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
            return Ok(target);
        }
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
                self.packet(current)?.header.timestamp as u128 <= bound,
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
        self.ready()?;
        let (tip, generation, _) = self.read_active()?;
        let row = self.record(included)?;
        let packet = self.packet(included)?;
        ensure(
            packet.header.transactions == sequence_root("transactions", &packet.transactions),
            "ROOT",
        )?;
        ensure(
            packet
                .transactions
                .iter()
                .any(|raw| hash(b"tx-id", &[raw]) == transaction),
            "MEMBERSHIP",
        )?;
        let observed = self.record(tip)?;
        let mut current = tip;
        let mut found = false;
        let bound = observed_now as u128 + self.settings.limit("future_skew_seconds")? as u128;
        while current != self.settings.genesis() {
            if current == included {
                found = true;
            }
            ensure(
                self.packet(current)?.header.timestamp as u128 <= bound,
                "TIME_DEFERRED",
            )?;
            current = self.parent(current)?;
        }
        let delta = if found {
            Some(observed.work.checked_sub(row.work)?)
        } else {
            None
        };
        let depth = if found {
            Some(observed.height.checked_sub(row.height).ok_or("HEIGHT")?)
        } else {
            None
        };
        let threshold = consensus::required_work(packet.header.target)?
            .mul_small(self.settings.limit("confirmation_work_multiplier")?)?;
        let confirmed = depth.is_some_and(|d| {
            d >= self
                .settings
                .limit("confirmation_depth")
                .unwrap_or(u64::MAX)
        }) && delta.is_some_and(|w| w >= threshold);
        ensure(self.active()? == (tip, generation), "STALE_VIEW")?;
        Ok(Observation {
            transaction: hex::encode(transaction),
            genesis: hex::encode(self.settings.genesis()),
            policy: "installed-depth-and-required-work".into(),
            required_work_delta: hex::encode(threshold.bytes()),
            network: hex::encode(self.settings.network()),
            parameters: hex::encode(self.settings.parameters()),
            included_block: hex::encode(included),
            observed_tip: hex::encode(tip),
            included_height: row.height,
            observed_height: observed.height,
            depth,
            work_delta: delta.map(|w| hex::encode(w.bytes())),
            active_generation: generation,
            observed_now,
            confirmed,
            reorged: !found,
            finalized: false,
            execution_authority: false,
        })
    }
    pub fn history(&self, tip: Hash, after: Hash, limit: usize) -> Result<Vec<Packet>> {
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
        Ok(packets)
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
        Ok(
            serde_json::json!({"network":hex::encode(self.settings.network()),"parameters":hex::encode(self.settings.parameters()),"genesis":hex::encode(self.settings.genesis()),"tip":hex::encode(tip),"height":row.height,"chainwork_hex":hex::encode(row.work.bytes()),"state_root":hex::encode(root(&state)?),"generation":g,"state_keys":state.len(),"stored_blocks":blocks,"events":events,"production_activation":false}),
        )
    }
}
