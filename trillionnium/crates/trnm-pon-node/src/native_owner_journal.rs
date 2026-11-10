//! Opt-in durable observation of one exclusively held native owner.
//!
//! The sidecar is deliberately not a second consensus transaction. A native
//! commit without a completed observation remains an unresolved intent after
//! restart. No clock, fresh-resource state, remote inventory or probability
//! authority is granted by this journal or by a matching caller-supplied pin.
use crate::{
    ensure, Error, Node, Observation, OwnerCensus, OwnerCensusLimits, Packet, Result, Settings,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;
use trnm_protocol::pon_wire::Hash;

const MAGIC: &[u8; 8] = b"PNOJ1\0\0\0";
const DOMAIN: &[u8] = b"pon-native-owner-journal-frame-v1\0";
const MAX_FRAME: usize = 4 * 1024 * 1024;
const MAX_RECORDS: u64 = 4096;
const MAX_JOURNAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

/// A supplied previous prefix pin. Its authenticity is a separate obligation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalCheckpoint {
    pub journal_id: String,
    pub sequence: u64,
    pub record_hash: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalBackend {
    Legacy,
    AuthenticatedV1,
}
impl JournalBackend {
    fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy-v2",
            Self::AuthenticatedV1 => "authenticated-v1",
        }
    }
}

/// Bounds on diagnostic work and sidecar storage, not physical cost estimates.
#[derive(Clone, Debug)]
pub struct NativeJournalOptions {
    pub backend: JournalBackend,
    pub workers: usize,
    pub observed_now: u64,
    pub census_limits: OwnerCensusLimits,
    pub maximum_records: u64,
    pub maximum_journal_bytes: u64,
    pub maximum_artifact_bytes: u64,
    pub expected_checkpoint: Option<JournalCheckpoint>,
}
impl Default for NativeJournalOptions {
    fn default() -> Self {
        Self {
            backend: JournalBackend::Legacy,
            workers: 1,
            observed_now: 100,
            census_limits: OwnerCensusLimits::default(),
            maximum_records: MAX_RECORDS,
            maximum_journal_bytes: MAX_JOURNAL_BYTES,
            maximum_artifact_bytes: MAX_ARTIFACT_BYTES,
            expected_checkpoint: None,
        }
    }
}

pub struct JournalMakeRequest {
    pub parent: Hash,
    pub transactions: Vec<Vec<u8>>,
    pub miner: Hash,
    pub timestamp: u64,
    pub max_attempts: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    sequence: u64,
    previous_hash: String,
    payload: Value,
}

#[derive(Clone, Debug)]
struct Intent {
    epoch: u64,
    operation: String,
    observed_now: u64,
    started_ns: u64,
    input: Value,
    before: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
struct SeenBlock {
    origin_class: String,
    first_seen_sequence: u64,
    first_seen_epoch: u64,
    required_work_hex: String,
    packet_sha256: String,
    native_relation_rechecked_by_census: bool,
}

#[derive(Clone, Debug, Serialize)]
struct RawSource {
    origin_class: String,
    first_sequence: u64,
    first_epoch: u64,
}

#[derive(Default)]
struct Replay {
    journal_id: String,
    header: Value,
    last_epoch: u64,
    active_epoch: Option<u64>,
    current_intent: Option<u64>,
    pending: BTreeMap<u64, Intent>,
    registry: BTreeMap<String, SeenBlock>,
    raw_sources: BTreeMap<String, RawSource>,
    last_census: Option<Value>,
    last_clock: Option<u64>,
    outside_lease_intervals: Vec<Value>,
    clock_regressions: Vec<Value>,
    completed_calls: u64,
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| "OWNER_JOURNAL_FIELDS".into())
}
fn number(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .ok_or_else(|| "OWNER_JOURNAL_FIELDS".into())
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn frame_hash(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(bytes);
    digest.finalize().into()
}
fn census_state(value: &Value) -> Value {
    let rows = value["rows"].as_array().map(|rows| {
        rows.iter()
            .map(|row| {
                let mut item = row.clone();
                if let Some(map) = item.as_object_mut() {
                    map.remove("ancestry_time_eligible");
                    map.remove("active_chain_member");
                }
                item
            })
            .collect::<Vec<_>>()
    });
    json!({"active_tip":value["active_tip"],"active_generation":value["active_generation"],
        "state_slot":value["state_slot"],"rows":rows})
}
fn native_result<T>(
    result: &Result<T>,
    describe: impl FnOnce(&T) -> Result<Value>,
) -> Result<Value> {
    match result {
        Ok(value) => Ok(json!({"ok":true,"value":describe(value)?})),
        Err(error) => Ok(json!({"ok":false,"error":error.to_string(),
            "error_kind":format!("{:?}",error.kind()),"requires_owner_stop":error.requires_owner_stop()})),
    }
}

impl Replay {
    fn note_raw(&mut self, digest: &str, origin: &str, sequence: u64, epoch: u64) -> Result<()> {
        crate::digest(digest)?;
        self.raw_sources
            .entry(digest.to_owned())
            .or_insert_with(|| RawSource {
                origin_class: origin.to_owned(),
                first_sequence: sequence,
                first_epoch: epoch,
            });
        Ok(())
    }
    fn observe_clock(&mut self, sequence: u64, epoch: u64, now: u64) {
        if self.last_clock.is_some_and(|old| now < old) {
            self.clock_regressions
                .push(json!({"sequence":sequence,"epoch":epoch,
                "previous_validation_now":self.last_clock,"validation_now":now}));
        }
        self.last_clock = Some(now);
    }
    fn see(
        &mut self,
        item: &Value,
        origin: &str,
        sequence: u64,
        epoch: u64,
        checked: bool,
    ) -> Result<()> {
        let id = text(item, "id")?;
        crate::digest(id)?;
        let weight = text(item, "required_work_hex")?;
        ensure(weight.len() == 128, "OWNER_JOURNAL_WEIGHT")?;
        let packet_sha = text(item, "packet_sha256")?;
        self.note_raw(packet_sha, origin, sequence, epoch)?;
        let source = self
            .raw_sources
            .get(packet_sha)
            .ok_or("OWNER_JOURNAL_ARTIFACT")?;
        if let Some(previous) = self.registry.get_mut(id) {
            ensure(
                previous.required_work_hex == weight && previous.packet_sha256 == packet_sha,
                "OWNER_JOURNAL_BLOCK_IDENTITY",
            )?;
            previous.native_relation_rechecked_by_census |= checked;
        } else {
            self.registry.insert(
                id.to_owned(),
                SeenBlock {
                    origin_class: source.origin_class.clone(),
                    first_seen_sequence: source.first_sequence,
                    first_seen_epoch: source.first_epoch,
                    required_work_hex: weight.to_owned(),
                    packet_sha256: packet_sha.to_owned(),
                    native_relation_rechecked_by_census: checked,
                },
            );
        }
        Ok(())
    }
    fn census(&mut self, value: &Value, origin: &str, sequence: u64, epoch: u64) -> Result<()> {
        ensure(
            text(value, "schema")? == "pon-native-owner-census-v1"
                && value["complete_for_all_admitted_rows_in_snapshot"] == true
                && value["local_candidate_relation_rechecked"] == true
                && value["exact_source_schema_rechecked"] == true,
            "OWNER_JOURNAL_CENSUS",
        )?;
        for key in ["network", "parameters", "genesis"] {
            ensure(
                value[key] == self.header["context"][key],
                "OWNER_JOURNAL_CONTEXT",
            )?;
        }
        ensure(
            value["state_backend"] == self.header["backend"],
            "OWNER_JOURNAL_BACKEND",
        )?;
        let rows = value["rows"].as_array().ok_or("OWNER_JOURNAL_CENSUS")?;
        ensure(
            !rows.is_empty() && rows.len() <= crate::MAX_CENSUS_BLOCKS,
            "OWNER_JOURNAL_CENSUS",
        )?;
        for row in rows {
            if row["parent"].is_null() {
                ensure(row["id"] == value["genesis"], "OWNER_JOURNAL_GENESIS")?;
            } else {
                ensure(
                    row["full_native_work_replayed"] == true
                        && row["full_native_application_replayed"] == true
                        && row["retained_state_and_deltas_equal"] == true,
                    "OWNER_JOURNAL_CENSUS",
                )?;
                self.see(row, origin, sequence, epoch, true)?;
            }
        }
        self.last_census = Some(value.clone());
        Ok(())
    }
    fn apply(&mut self, frame: &Frame) -> Result<()> {
        let p = &frame.payload;
        let kind = text(p, "kind")?;
        if frame.sequence == 0 {
            ensure(
                kind == "header" && text(p, "schema")? == "pon-native-owner-journal-v1",
                "OWNER_JOURNAL_HEADER",
            )?;
            self.journal_id = text(p, "journal_id")?.to_owned();
            crate::digest(&self.journal_id)?;
            self.header = p.clone();
            return Ok(());
        }
        let epoch = number(p, "epoch")?;
        match kind {
            "open_intent" => {
                ensure(
                    epoch
                        == self
                            .last_epoch
                            .checked_add(1)
                            .ok_or("OWNER_JOURNAL_EPOCH")?,
                    "OWNER_JOURNAL_EPOCH",
                )?;
                let expected: Vec<u64> = self.pending.keys().copied().collect();
                ensure(
                    p["prior_unresolved_intents"] == json!(expected),
                    "OWNER_JOURNAL_GAP_ERASURE",
                )?;
                for artifact in p["orphan_artifacts_at_open"]
                    .as_array()
                    .ok_or("OWNER_JOURNAL_ORPHANS")?
                {
                    self.note_raw(
                        text(artifact, "sha256")?,
                        "gap_or_recovery_discovery",
                        frame.sequence,
                        epoch,
                    )?;
                }
                if self.last_epoch != 0 {
                    self.outside_lease_intervals.push(json!({"from_epoch":self.last_epoch,
                        "to_epoch":epoch,"open_intent_sequence":frame.sequence,
                        "prior_lease_closed":self.active_epoch.is_none() && self.current_intent.is_none(),
                        "physical_elapsed_bound":null,"unobserved_operation_bound":null}));
                }
                self.last_epoch = epoch;
                self.active_epoch = None;
                self.current_intent = Some(frame.sequence);
                let now = number(p, "observed_now")?;
                self.observe_clock(frame.sequence, epoch, now);
                self.pending.insert(
                    frame.sequence,
                    Intent {
                        epoch,
                        operation: "open".to_owned(),
                        observed_now: now,
                        started_ns: 0,
                        input: Value::Null,
                        before: None,
                    },
                );
            }
            "open_observed" => {
                let intent = number(p, "intent_sequence")?;
                let pending = self.pending.get(&intent).ok_or("OWNER_JOURNAL_INTENT")?;
                ensure(
                    self.current_intent == Some(intent)
                        && pending.epoch == epoch
                        && pending.operation == "open"
                        && number(p, "observed_now")? == pending.observed_now,
                    "OWNER_JOURNAL_INTENT",
                )?;
                number(p, "elapsed_ns")?;
                self.census(
                    &p["census"],
                    if epoch == 1 {
                        "initial_carry_in"
                    } else {
                        "gap_or_recovery_discovery"
                    },
                    frame.sequence,
                    epoch,
                )?;
                self.pending.remove(&intent);
                self.current_intent = None;
                self.active_epoch = Some(epoch);
            }
            "intent" => {
                ensure(
                    self.active_epoch == Some(epoch) && self.current_intent.is_none(),
                    "OWNER_JOURNAL_PENDING",
                )?;
                let operation = text(p, "operation")?;
                ensure(
                    matches!(
                        operation,
                        "make" | "admit" | "activate_observed" | "confirmation" | "census"
                    ),
                    "OWNER_JOURNAL_OPERATION",
                )?;
                let now = number(p, "observed_now")?;
                self.observe_clock(frame.sequence, epoch, now);
                if operation == "admit" {
                    self.note_raw(
                        text(&p["input"]["artifact"], "sha256")?,
                        "external_input",
                        frame.sequence,
                        epoch,
                    )?;
                }
                self.pending.insert(
                    frame.sequence,
                    Intent {
                        epoch,
                        operation: operation.to_owned(),
                        observed_now: now,
                        started_ns: number(p, "elapsed_ns")?,
                        input: p["input"].clone(),
                        before: None,
                    },
                );
                self.current_intent = Some(frame.sequence);
            }
            "prepared" => {
                let intent = number(p, "intent_sequence")?;
                let previous = self.pending.get(&intent).ok_or("OWNER_JOURNAL_INTENT")?;
                ensure(
                    self.current_intent == Some(intent)
                        && self.active_epoch == Some(epoch)
                        && previous.epoch == epoch
                        && previous.before.is_none()
                        && number(p, "elapsed_ns")? >= previous.started_ns
                        && number(&p["census"], "observed_now")? == previous.observed_now,
                    "OWNER_JOURNAL_INTENT",
                )?;
                if let Some(old) = &self.last_census {
                    ensure(
                        census_state(old) == census_state(&p["census"]),
                        "OWNER_JOURNAL_UNOBSERVED_STATE_CHANGE",
                    )?;
                }
                self.census(
                    &p["census"],
                    "gap_or_recovery_discovery",
                    frame.sequence,
                    epoch,
                )?;
                self.pending
                    .get_mut(&intent)
                    .ok_or("OWNER_JOURNAL_INTENT")?
                    .before = Some(p["census"].clone());
            }
            "terminal" => {
                let intent = number(p, "intent_sequence")?;
                let previous = self
                    .pending
                    .get(&intent)
                    .ok_or("OWNER_JOURNAL_INTENT")?
                    .clone();
                ensure(
                    self.current_intent == Some(intent)
                        && self.active_epoch == Some(epoch)
                        && previous.epoch == epoch
                        && previous.before.is_some()
                        && p["operation"] == previous.operation
                        && number(p, "elapsed_ns")? >= previous.started_ns
                        && number(&p["census"], "observed_now")? == previous.observed_now,
                    "OWNER_JOURNAL_INTENT",
                )?;
                ensure(p["result"]["ok"].is_boolean(), "OWNER_JOURNAL_RESULT")?;
                if previous.operation == "make" && p["result"]["ok"] == true {
                    self.see(
                        &p["result"]["value"],
                        "recorded_local_production",
                        frame.sequence,
                        epoch,
                        false,
                    )?;
                }
                self.census(
                    &p["census"],
                    if previous.operation == "admit" {
                        "external_input"
                    } else {
                        "gap_or_recovery_discovery"
                    },
                    frame.sequence,
                    epoch,
                )?;
                self.pending.remove(&intent);
                self.current_intent = None;
                self.completed_calls = self
                    .completed_calls
                    .checked_add(1)
                    .ok_or("OWNER_JOURNAL_SEQUENCE")?;
            }
            "lease_end" => {
                ensure(
                    self.active_epoch == Some(epoch) && self.current_intent.is_none(),
                    "OWNER_JOURNAL_PENDING",
                )?;
                if let Some(old) = &self.last_census {
                    ensure(
                        census_state(old) == census_state(&p["census"]),
                        "OWNER_JOURNAL_UNOBSERVED_STATE_CHANGE",
                    )?;
                }
                self.observe_clock(frame.sequence, epoch, number(p, "observed_now")?);
                self.census(
                    &p["census"],
                    "gap_or_recovery_discovery",
                    frame.sequence,
                    epoch,
                )?;
                self.active_epoch = None;
            }
            _ => return Err("OWNER_JOURNAL_RECORD_KIND".into()),
        }
        Ok(())
    }
}

struct Sidecar {
    directory: PathBuf,
    directory_file: File,
    lock: File,
    file: File,
    identity: (u64, u64),
    length: u64,
    hashes: Vec<String>,
    replay: Replay,
    options: NativeJournalOptions,
    artifact_bytes: u64,
    artifact_hashes: BTreeMap<String, u64>,
    orphan_artifacts_at_open: Vec<Value>,
    supplied_checkpoint_matches: Option<bool>,
    lease_fenced: Cell<bool>,
}

fn directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::DirBuilder::new().mode(0o700).create(path)?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure(
        metadata.is_dir()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o022 == 0,
        "OWNER_JOURNAL_DIRECTORY",
    )
}
fn owner_file(path: &Path, file: &File, code: &'static str) -> Result<fs::Metadata> {
    let held = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure(
        held.is_file()
            && held.nlink() == 1
            && held.uid() == rustix::process::geteuid().as_raw()
            && held.mode() & 0o022 == 0
            && named.is_file()
            && (named.dev(), named.ino()) == (held.dev(), held.ino()),
        code,
    )?;
    Ok(held)
}
fn owner_lease(path: &Path, directory: &File, lock: &File) -> Result<()> {
    let held = directory.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure(
        held.is_dir()
            && held.uid() == rustix::process::geteuid().as_raw()
            && held.mode() & 0o022 == 0
            && named.is_dir()
            && (named.dev(), named.ino()) == (held.dev(), held.ino()),
        "OWNER_JOURNAL_DIRECTORY",
    )?;
    owner_file(&path.join("owner.lock"), lock, "OWNER_JOURNAL_LOCK")?;
    Ok(())
}
fn safe_absolute(path: &Path) -> Result<()> {
    ensure(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "OWNER_JOURNAL_PATH",
    )
}
fn read_packet_file(path: &Path, length: u64) -> Result<Vec<u8>> {
    ensure((1..=1_048_576).contains(&length), "OWNER_JOURNAL_ARTIFACT")?;
    // A cached artifact may have been replaced by a FIFO. Open without waiting
    // for its writer, then keep the descriptor-bound regular-file refusal.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure(
        metadata.is_file() && metadata.len() == length,
        "OWNER_JOURNAL_ARTIFACT",
    )?;
    let mut raw = Vec::with_capacity(length as usize);
    file.take(length + 1).read_to_end(&mut raw)?;
    ensure(raw.len() as u64 == length, "OWNER_JOURNAL_ARTIFACT")?;
    Ok(raw)
}
fn references(value: &Value, found: &mut BTreeMap<String, u64>) -> Result<()> {
    match value {
        Value::Object(map) => {
            if map.get("artifact_kind").and_then(Value::as_str) == Some("native-pnp1-packet") {
                let digest = text(value, "sha256")?;
                crate::digest(digest)?;
                let length = number(value, "bytes")?;
                ensure((1..=1_048_576).contains(&length), "OWNER_JOURNAL_ARTIFACT")?;
                if let Some(old) = found.insert(digest.to_owned(), length) {
                    ensure(old == length, "OWNER_JOURNAL_ARTIFACT")?;
                }
            }
            for child in map.values() {
                references(child, found)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                references(child, found)?;
            }
        }
        _ => (),
    }
    Ok(())
}

impl Sidecar {
    fn open(
        path: &Path,
        store: &Path,
        settings: &Settings,
        options: NativeJournalOptions,
    ) -> Result<Self> {
        safe_absolute(path)?;
        safe_absolute(store)?;
        ensure(
            !path.starts_with(store) && !store.starts_with(path),
            "OWNER_JOURNAL_SEPARATE_DIRECTORY",
        )?;
        ensure(
            (1..=MAX_RECORDS).contains(&options.maximum_records)
                && (4096..=MAX_JOURNAL_BYTES).contains(&options.maximum_journal_bytes)
                && (1..=MAX_ARTIFACT_BYTES).contains(&options.maximum_artifact_bytes),
            "OWNER_JOURNAL_LIMITS",
        )?;
        directory(path)?;
        let directory_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let flags = rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC;
        let mode = rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR;
        let lock = File::from(rustix::fs::openat(
            &directory_file,
            "owner.lock",
            flags,
            mode,
        )?);
        owner_lease(path, &directory_file, &lock)?;
        lock.try_lock_exclusive()
            .map_err(|_| Error::from("OWNER_JOURNAL_BUSY"))?;
        owner_lease(path, &directory_file, &lock)?;
        directory(&path.join("packets"))?;
        let mut file = File::from(rustix::fs::openat(
            &directory_file,
            "journal.pnoj1",
            flags | rustix::fs::OFlags::APPEND,
            mode,
        )?);
        owner_lease(path, &directory_file, &lock)?;
        let metadata = owner_file(&path.join("journal.pnoj1"), &file, "OWNER_JOURNAL_REPLACED")?;
        ensure(
            metadata.len() <= options.maximum_journal_bytes,
            "OWNER_JOURNAL_LENGTH",
        )?;
        let mut replay = Replay::default();
        let mut hashes = Vec::new();
        let mut artifact_hashes = BTreeMap::new();
        let mut length = metadata.len();
        if length == 0 {
            ensure(
                options.expected_checkpoint.is_none(),
                "OWNER_JOURNAL_CHECKPOINT_MISSING",
            )?;
            file.write_all(MAGIC)?;
            file.sync_all()?;
            directory_file.sync_all()?;
            length = MAGIC.len() as u64;
        } else {
            file.seek(SeekFrom::Start(0))?;
            let mut magic = [0; 8];
            file.read_exact(&mut magic)
                .map_err(|_| Error::from("OWNER_JOURNAL_TORN_TAIL"))?;
            ensure(&magic == MAGIC, "OWNER_JOURNAL_MAGIC")?;
            let mut position = 8_u64;
            while position < length {
                ensure(
                    (hashes.len() as u64) < options.maximum_records,
                    "OWNER_JOURNAL_RECORD_BUDGET",
                )?;
                let mut size = [0; 4];
                file.read_exact(&mut size)
                    .map_err(|_| Error::from("OWNER_JOURNAL_TORN_TAIL"))?;
                let size = u32::from_be_bytes(size) as usize;
                ensure(
                    (1..=MAX_FRAME).contains(&size),
                    "OWNER_JOURNAL_FRAME_LENGTH",
                )?;
                let end = position
                    .checked_add(4 + size as u64 + 32)
                    .ok_or("OWNER_JOURNAL_LENGTH")?;
                ensure(end <= length, "OWNER_JOURNAL_TORN_TAIL")?;
                let mut raw = vec![0; size];
                file.read_exact(&mut raw)?;
                let mut digest = [0; 32];
                file.read_exact(&mut digest)?;
                ensure(frame_hash(&raw) == digest, "OWNER_JOURNAL_HASH")?;
                let frame: Frame = serde_json::from_slice(&raw)?;
                let expected = hashes.last().cloned().unwrap_or_else(|| "00".repeat(32));
                ensure(
                    frame.sequence == hashes.len() as u64 && frame.previous_hash == expected,
                    "OWNER_JOURNAL_CHAIN",
                )?;
                replay.apply(&frame)?;
                references(&frame.payload, &mut artifact_hashes)?;
                hashes.push(hex::encode(digest));
                position = end;
            }
        }
        let referenced = artifact_hashes;
        let mut artifact_hashes = BTreeMap::new();
        let mut orphan_artifacts_at_open = Vec::new();
        let mut artifact_bytes = 0_u64;
        for entry in fs::read_dir(path.join("packets"))? {
            ensure(
                (artifact_hashes.len() as u64) < MAX_RECORDS,
                "OWNER_JOURNAL_ARTIFACT_BUDGET",
            )?;
            let entry = entry?;
            let filename = entry.file_name();
            let digest = filename
                .to_str()
                .and_then(|name| name.strip_suffix(".pnp1"))
                .ok_or("OWNER_JOURNAL_ARTIFACT")?;
            crate::digest(digest)?;
            let meta = fs::symlink_metadata(entry.path())?;
            ensure(
                meta.is_file() && !meta.file_type().is_symlink(),
                "OWNER_JOURNAL_ARTIFACT",
            )?;
            let length = meta.len();
            artifact_bytes = artifact_bytes
                .checked_add(length)
                .ok_or("OWNER_JOURNAL_ARTIFACT_BUDGET")?;
            ensure(
                artifact_bytes <= options.maximum_artifact_bytes,
                "OWNER_JOURNAL_ARTIFACT_BUDGET",
            )?;
            let raw = read_packet_file(&entry.path(), length)?;
            ensure(sha(&raw) == digest, "OWNER_JOURNAL_ARTIFACT")?;
            let packet = Packet::decode(&raw).map_err(|_| Error::from("OWNER_JOURNAL_ARTIFACT"))?;
            if !referenced.contains_key(digest) {
                orphan_artifacts_at_open.push(json!({"artifact_kind":"native-pnp1-packet",
                    "sha256":digest,"bytes":length,"id":hex::encode(packet.id()?),
                    "path":format!("packets/{digest}.pnp1")}));
            }
            artifact_hashes.insert(digest.to_owned(), length);
        }
        for (digest, length) in referenced {
            ensure(
                artifact_hashes.get(&digest) == Some(&length),
                "OWNER_JOURNAL_ARTIFACT",
            )?;
        }
        orphan_artifacts_at_open.sort_by(|a, b| a["sha256"].as_str().cmp(&b["sha256"].as_str()));
        let mut sidecar = Self {
            directory: path.to_owned(),
            directory_file,
            lock,
            file,
            identity: (metadata.dev(), metadata.ino()),
            length,
            hashes,
            replay,
            options,
            artifact_bytes,
            artifact_hashes,
            orphan_artifacts_at_open,
            supplied_checkpoint_matches: None,
            lease_fenced: Cell::new(false),
        };
        let context = json!({"network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),"genesis":hex::encode(settings.genesis())});
        if sidecar.hashes.is_empty() {
            let mut nonce = [0; 32];
            File::open("/dev/urandom")?.read_exact(&mut nonce)?;
            sidecar.append(json!({"kind":"header","schema":"pon-native-owner-journal-v1",
                "journal_id":hex::encode(nonce),"store_path":store.to_str().ok_or("OWNER_JOURNAL_PATH")?,
                "backend":sidecar.options.backend.name(),"context":context,
                "scope":"explicit wrapper native calls during exclusive owner leases only",
                "initial_resource_state_known":false,"initial_world_inventory_bound":null,
                "fresh_resource_state_attested":false,"physical_clock_authenticated":false,
                "history_before_first_open_known":false,"world_coverage_attested":false}))?;
        }
        ensure(
            sidecar.replay.header["store_path"] == store.to_str().ok_or("OWNER_JOURNAL_PATH")?
                && sidecar.replay.header["backend"] == sidecar.options.backend.name()
                && sidecar.replay.header["context"] == context,
            "OWNER_JOURNAL_CONTEXT",
        )?;
        if let Some(pin) = &sidecar.options.expected_checkpoint {
            ensure(
                pin.journal_id == sidecar.replay.journal_id
                    && sidecar.hashes.get(
                        usize::try_from(pin.sequence).map_err(|_| "OWNER_JOURNAL_CHECKPOINT")?,
                    ) == Some(&pin.record_hash),
                "OWNER_JOURNAL_CHECKPOINT",
            )?;
            sidecar.supplied_checkpoint_matches = Some(true);
        }
        Ok(sidecar)
    }
    fn guard(&self) -> Result<()> {
        // A live checkpoint requires the same held directory and lock, not just
        // the same journal bytes. Replacing the lock path or adding a hard-link
        // alias cannot leave this sidecar reporting an exclusive owner lease.
        // A detected loss stays terminal for this live owner even if the old
        // names are restored. This cannot detect an entire replace-and-restore
        // that happens between calls; the directory still needs trusted custody.
        ensure(!self.lease_fenced.get(), "OWNER_JOURNAL_REPLACED")?;
        let result = (|| {
            owner_lease(&self.directory, &self.directory_file, &self.lock)?;
            let actual = owner_file(
                &self.directory.join("journal.pnoj1"),
                &self.file,
                "OWNER_JOURNAL_REPLACED",
            )?;
            ensure(
                (actual.dev(), actual.ino()) == self.identity && actual.len() == self.length,
                "OWNER_JOURNAL_REPLACED",
            )
        })();
        if result.is_err() {
            self.lease_fenced.set(true);
        }
        result
    }
    fn append(&mut self, payload: Value) -> Result<u64> {
        self.guard()?;
        let frame = Frame {
            sequence: self.hashes.len() as u64,
            previous_hash: self
                .hashes
                .last()
                .cloned()
                .unwrap_or_else(|| "00".repeat(32)),
            payload,
        };
        let raw = serde_json::to_vec(&frame)?;
        ensure(
            raw.len() <= MAX_FRAME && frame.sequence < self.options.maximum_records,
            "OWNER_JOURNAL_RECORD_BUDGET",
        )?;
        let next_length = self
            .length
            .checked_add(4 + raw.len() as u64 + 32)
            .ok_or("OWNER_JOURNAL_LENGTH")?;
        ensure(
            next_length <= self.options.maximum_journal_bytes,
            "OWNER_JOURNAL_BYTE_BUDGET",
        )?;
        let digest = frame_hash(&raw);
        self.file.write_all(&(raw.len() as u32).to_be_bytes())?;
        self.file.write_all(&raw)?;
        self.file.write_all(&digest)?;
        self.file.sync_all()?;
        self.length = next_length;
        self.hashes.push(hex::encode(digest));
        // The durable record is retained even if internal semantic validation
        // refuses it. Such a sidecar cannot produce another successful receipt.
        self.replay.apply(&frame)?;
        Ok(frame.sequence)
    }
    fn artifact(&mut self, packet: &Packet) -> Result<Value> {
        self.guard()?;
        let raw = packet.encode()?;
        let digest = sha(&raw);
        let length = raw.len() as u64;
        let path = self
            .directory
            .join("packets")
            .join(format!("{digest}.pnp1"));
        if self.artifact_hashes.get(&digest) == Some(&length) {
            ensure(
                sha(&read_packet_file(&path, length)?) == digest,
                "OWNER_JOURNAL_ARTIFACT",
            )?;
        } else {
            let next = self
                .artifact_bytes
                .checked_add(length)
                .ok_or("OWNER_JOURNAL_ARTIFACT_BUDGET")?;
            ensure(
                next <= self.options.maximum_artifact_bytes,
                "OWNER_JOURNAL_ARTIFACT_BUDGET",
            )?;
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
            {
                Ok(mut file) => {
                    file.write_all(&raw)?;
                    file.sync_all()?;
                    File::open(self.directory.join("packets"))?.sync_all()?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let meta = fs::symlink_metadata(&path)?;
                    ensure(
                        meta.is_file()
                            && !meta.file_type().is_symlink()
                            && meta.len() == length
                            && sha(&read_packet_file(&path, length)?) == digest,
                        "OWNER_JOURNAL_ARTIFACT",
                    )?;
                }
                Err(error) => return Err(error.into()),
            }
            self.artifact_hashes.insert(digest.clone(), length);
            self.artifact_bytes = next;
        }
        Ok(
            json!({"artifact_kind":"native-pnp1-packet","sha256":digest,"bytes":length,
            "id":hex::encode(packet.id()?),"path":format!("packets/{digest}.pnp1")}),
        )
    }
    fn checkpoint(&self) -> Result<JournalCheckpoint> {
        self.guard()?;
        Ok(JournalCheckpoint {
            journal_id: self.replay.journal_id.clone(),
            sequence: self
                .hashes
                .len()
                .checked_sub(1)
                .ok_or("OWNER_JOURNAL_HEADER")? as u64,
            record_hash: self.hashes.last().ok_or("OWNER_JOURNAL_HEADER")?.clone(),
        })
    }
}

/// This type owns its Node and exposes no reference, callback or escape route to
/// it. All native business methods below require `&mut self` to serialize calls.
pub struct JournaledNativeOwner {
    node: Node,
    sidecar: Sidecar,
    epoch: u64,
    clock: Instant,
    blocked: bool,
}

impl JournaledNativeOwner {
    pub fn open(
        store: &Path,
        journal: &Path,
        settings: Settings,
        options: NativeJournalOptions,
    ) -> Result<Self> {
        let clock = Instant::now();
        let mut sidecar = Sidecar::open(journal, store, &settings, options)?;
        let epoch = sidecar
            .replay
            .last_epoch
            .checked_add(1)
            .ok_or("OWNER_JOURNAL_EPOCH")?;
        let prior: Vec<_> = sidecar.replay.pending.keys().copied().collect();
        let intent = sidecar.append(json!({"kind":"open_intent","epoch":epoch,
            "process_id":std::process::id(),"observed_now":sidecar.options.observed_now,
            "prior_unresolved_intents":prior,"expected_checkpoint":sidecar.options.expected_checkpoint,
            "orphan_artifacts_at_open":sidecar.orphan_artifacts_at_open,
            "clock_scope":"one process Instant epoch; no cross-epoch duration or physical clock attestation"}))?;
        // Original Node::open may execute native recovery. Never put its intent
        // after this call, or describe reopening as a read-only observation.
        let node = match sidecar.options.backend {
            JournalBackend::Legacy => Node::open(store, settings, sidecar.options.workers)?,
            JournalBackend::AuthenticatedV1 => {
                Node::open_with_authenticated_state(store, settings, sidecar.options.workers)?
            }
        };
        let mut owner = Self {
            node,
            sidecar,
            epoch,
            clock,
            blocked: true,
        };
        let now = owner.sidecar.options.observed_now;
        let (census, artifacts) = owner.capture(now)?;
        owner.sidecar.append(json!({"kind":"open_observed","epoch":epoch,"intent_sequence":intent,
            "elapsed_ns":owner.elapsed()?,"observed_now":now,"census":census,"artifacts":artifacts}))?;
        owner.blocked = false;
        Ok(owner)
    }
    fn elapsed(&self) -> Result<u64> {
        u64::try_from(self.clock.elapsed().as_nanos())
            .map_err(|_| "OWNER_JOURNAL_CLOCK_RANGE".into())
    }
    fn ready(&self) -> Result<()> {
        ensure(
            !self.blocked
                && self.sidecar.replay.current_intent.is_none()
                && self.sidecar.replay.active_epoch == Some(self.epoch),
            "OWNER_JOURNAL_UNRESOLVED",
        )?;
        self.sidecar.guard()
    }
    fn capture(&mut self, now: u64) -> Result<(Value, Vec<Value>)> {
        let observed = self
            .node
            .native_owner_census(now, self.sidecar.options.census_limits)?;
        let census = serde_json::to_value(observed)?;
        let rows = census["rows"].as_array().ok_or("OWNER_JOURNAL_CENSUS")?;
        let mut artifacts = Vec::new();
        for row in rows {
            if row["parent"].is_null() {
                continue;
            }
            let packet = self.node.packet(crate::digest(text(row, "id")?)?)?;
            let artifact = self.sidecar.artifact(&packet)?;
            ensure(
                artifact["sha256"] == row["packet_sha256"]
                    && artifact["bytes"] == row["packet_bytes"],
                "OWNER_JOURNAL_SNAPSHOT_PACKET",
            )?;
            artifacts.push(artifact);
        }
        Ok((census, artifacts))
    }
    fn begin(&mut self, operation: &str, now: u64, input: Value) -> Result<u64> {
        self.ready()?;
        self.blocked = true;
        let intent = self.sidecar.append(
            json!({"kind":"intent","epoch":self.epoch,"operation":operation,
            "observed_now":now,"elapsed_ns":self.elapsed()?,"input":input}),
        )?;
        let (census, artifacts) = self.capture(now)?;
        self.sidecar.append(
            json!({"kind":"prepared","epoch":self.epoch,"intent_sequence":intent,
            "elapsed_ns":self.elapsed()?,"census":census,"artifacts":artifacts}),
        )?;
        Ok(intent)
    }
    fn terminal(&mut self, intent: u64, operation: &str, now: u64, result: Value) -> Result<()> {
        let native_requires_stop = result["requires_owner_stop"] == true;
        let (census, artifacts) = self.capture(now)?;
        self.sidecar.append(
            json!({"kind":"terminal","epoch":self.epoch,"intent_sequence":intent,
            "operation":operation,"elapsed_ns":self.elapsed()?,"result":result,
            "census":census,"artifacts":artifacts}),
        )?;
        self.blocked = native_requires_stop;
        Ok(())
    }
    pub fn make(&mut self, request: JournalMakeRequest, observed_now: u64) -> Result<Packet> {
        let intent = self.begin("make",observed_now,json!({"parent":hex::encode(request.parent),
            "transactions":request.transactions.iter().map(hex::encode).collect::<Vec<_>>(),
            "miner":hex::encode(request.miner),"timestamp":request.timestamp,"max_attempts":request.max_attempts}))?;
        let result = self.node.make(
            request.parent,
            request.transactions,
            request.miner,
            request.timestamp,
            request.max_attempts,
        );
        let outcome = native_result(&result, |packet| {
            let artifact = self.sidecar.artifact(packet)?;
            Ok(
                json!({"id":hex::encode(packet.id()?),"parent":hex::encode(packet.header.parent),
                "height":packet.header.height,"target":hex::encode(packet.header.target),"timestamp":packet.header.timestamp,
                "required_work_hex":hex::encode(crate::consensus::required_work(packet.header.target)?.bytes()),
                "packet_sha256":artifact["sha256"],"proof_sha256":sha(&packet.proof),
                "packet_bytes":artifact["bytes"],"artifact":artifact}),
            )
        })?;
        self.terminal(intent, "make", observed_now, outcome)?;
        result
    }
    pub fn admit(&mut self, packet: &Packet, observed_now: u64) -> Result<Hash> {
        self.ready()?;
        let artifact = self.sidecar.artifact(packet)?;
        let intent = self.begin(
            "admit",
            observed_now,
            json!({"id":hex::encode(packet.id()?),"artifact":artifact}),
        )?;
        let result = self.node.admit(packet, observed_now);
        let outcome = native_result(&result, |id| Ok(json!({"id":hex::encode(id)})))?;
        self.terminal(intent, "admit", observed_now, outcome)?;
        result
    }
    pub fn activate_observed(&mut self, target: Hash, observed_now: u64) -> Result<Hash> {
        self.begin_activation(target, observed_now)?.finish()
    }
    /// Executes real native activation but deliberately leaves the journal's
    /// intent unresolved. Only `PendingActivation::finish` creates a receipt.
    pub fn begin_activation(
        &mut self,
        target: Hash,
        observed_now: u64,
    ) -> Result<PendingActivation<'_>> {
        let intent = self.begin(
            "activate_observed",
            observed_now,
            json!({"target":hex::encode(target)}),
        )?;
        let result = self.node.activate_observed(target, observed_now);
        Ok(PendingActivation {
            owner: self,
            intent,
            observed_now,
            result,
        })
    }
    pub fn confirmation(
        &mut self,
        transaction: Hash,
        included: Hash,
        observed_now: u64,
    ) -> Result<Observation> {
        let intent = self.begin(
            "confirmation",
            observed_now,
            json!({"transaction":hex::encode(transaction),"included":hex::encode(included)}),
        )?;
        let result = self.node.confirmation(transaction, included, observed_now);
        let outcome = native_result(&result, |value| Ok(serde_json::to_value(value)?))?;
        self.terminal(intent, "confirmation", observed_now, outcome)?;
        result
    }
    pub fn observe(&mut self, observed_now: u64) -> Result<OwnerCensus> {
        let intent = self.begin("census", observed_now, Value::Null)?;
        let result = self
            .node
            .native_owner_census(observed_now, self.sidecar.options.census_limits);
        let outcome = native_result(&result, |value| Ok(serde_json::to_value(value)?))?;
        self.terminal(intent, "census", observed_now, outcome)?;
        result
    }
    pub fn checkpoint(&self) -> Result<JournalCheckpoint> {
        self.sidecar.checkpoint()
    }
    /// A diagnostic projection, not independently authenticated execution.
    pub fn status(&self) -> Result<Value> {
        let checkpoint = self.checkpoint()?;
        let unresolved = self
            .sidecar
            .replay
            .pending
            .iter()
            .map(|(sequence, intent)| {
                json!({
            "intent_sequence":sequence,"epoch":intent.epoch,"operation":intent.operation,
            "input":intent.input,"prepared":intent.before.is_some()})
            })
            .collect::<Vec<_>>();
        Ok(
            json!({"schema":"pon-native-owner-journal-status-v1","checkpoint":checkpoint,
            "epoch":self.epoch,"blocked":self.blocked,"recorded_calls_completed":self.sidecar.replay.completed_calls,
            "unresolved_intents":unresolved,"outside_lease_intervals":self.sidecar.replay.outside_lease_intervals,
            "clock_regressions":self.sidecar.replay.clock_regressions,"registry":self.sidecar.replay.registry,
            "raw_artifact_sources":self.sidecar.replay.raw_sources,
            "orphan_artifacts_at_open":self.sidecar.orphan_artifacts_at_open,
            "last_census":self.sidecar.replay.last_census,
            "supplied_checkpoint_matches":self.sidecar.supplied_checkpoint_matches,
            "initial_resource_state_known":false,"initial_world_inventory_bound":null,
            "fresh_resource_state_attested":false,"native_runtime_attested":false,
            "trusted_history_anchor":false,"physical_clock_authenticated":false,"world_coverage_attested":false,
            "all_ever_native_api_calls_covered":false,"probabilistic_environment_bound":false,
            "six_successor_risk_qualified":false,"probability_bound":null}),
        )
    }
    /// End the covered lease while still holding Node. Its subsequent Drop and
    /// every interval until the next observed open are outside this lease.
    pub fn finish(mut self, observed_now: u64) -> Result<JournalCheckpoint> {
        self.ready()?;
        self.blocked = true;
        let (census, artifacts) = self.capture(observed_now)?;
        self.sidecar.append(
            json!({"kind":"lease_end","epoch":self.epoch,"observed_now":observed_now,
            "elapsed_ns":self.elapsed()?,"census":census,"artifacts":artifacts,
            "coverage_ends_before_native_owner_drop":true}),
        )?;
        self.sidecar.checkpoint()
    }
}

#[must_use = "Native effects may already be committed; finish is required for a completed journal observation"]
pub struct PendingActivation<'a> {
    owner: &'a mut JournaledNativeOwner,
    intent: u64,
    observed_now: u64,
    result: Result<Hash>,
}
impl PendingActivation<'_> {
    /// This reports only the live native return, never journal completeness.
    pub fn native_succeeded(&self) -> bool {
        self.result.is_ok()
    }
    pub fn intent_sequence(&self) -> u64 {
        self.intent
    }
    pub fn finish(self) -> Result<Hash> {
        let outcome = native_result(&self.result, |tip| Ok(json!({"selected":hex::encode(tip)})))?;
        self.owner
            .terminal(self.intent, "activate_observed", self.observed_now, outcome)?;
        self.result
    }
}
