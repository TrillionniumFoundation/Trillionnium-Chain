//! Persistent registration of local confirmation claims before native dispatch.
//!
//! Units are declared bookkeeping, not authenticated conditional probabilities.
//! This wrapper owns its journaled owner, charges a start before calling it, and
//! never refunds a failed, unconfirmed or interrupted call. Neither file proves
//! physical execution, latest-history retention or a network probability law.
use crate::native_owner_journal::{
    JournalCheckpoint, JournalMakeRequest, JournaledNativeOwner, NativeJournalOptions,
};
use crate::{ensure, Error, Observation, OwnerCensus, Packet, Result, Settings};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use trnm_protocol::pon_wire::Hash;

const MAGIC: &[u8; 8] = b"PNRL1\0\0\0";
const DOMAIN: &[u8] = b"pon-native-risk-ledger-frame-v1\0";
const NATIVE_MAGIC: &[u8; 8] = b"PNOJ1\0\0\0";
const NATIVE_DOMAIN: &[u8] = b"pon-native-owner-journal-frame-v1\0";
const MAX_RECORDS: u64 = 4096;
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FRAME: usize = 64 * 1024;
const MAX_DENOMINATOR: u64 = 1_000_000_000_000_000_000;

/// A supplied prefix expectation. Authentic and newest retention is external.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskLedgerCheckpoint {
    pub bank_id: String,
    pub sequence: u64,
    pub record_hash: String,
}

#[derive(Clone, Debug)]
pub struct RiskLedgerOptions {
    pub unit_denominator: u64,
    pub budget_units: u64,
    /// One declared common-law scope. Equality does not authenticate that law.
    pub law_scope_sha256: Hash,
    pub maximum_records: u64,
    pub maximum_bytes: u64,
    pub expected_checkpoint: Option<RiskLedgerCheckpoint>,
}
impl Default for RiskLedgerOptions {
    fn default() -> Self {
        Self {
            unit_denominator: 1_000_000,
            budget_units: 1_000,
            law_scope_sha256: [0; 32],
            maximum_records: MAX_RECORDS,
            maximum_bytes: MAX_BYTES,
            expected_checkpoint: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RiskConfirmationRequest {
    pub transaction: Hash,
    pub included: Hash,
    pub observed_now: u64,
    pub allowance_units: u64,
    pub law_scope_sha256: Hash,
    pub statement_sha256: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: String,
    bank_id: String,
    native_journal_id: String,
    native_journal_header_hash: String,
    native_journal_path: PathBuf,
    native_anchor: JournalCheckpoint,
    unit_denominator: u64,
    budget_units: u64,
    law_scope_sha256: String,
    actual_probability_law_authenticated: bool,
    native_conditional_risk_certified: bool,
    global_failure_probability: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseOpen {
    epoch: u64,
    native_owner_epoch: u64,
    native_checkpoint: JournalCheckpoint,
    prior_unresolved_starts: Vec<u64>,
    spent_units: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    epoch: u64,
    native_owner_epoch: u64,
    native_before: JournalCheckpoint,
    expected_native_intent_sequence: u64,
    transaction: String,
    included: String,
    observed_now: u64,
    allowance_units: u64,
    law_scope_sha256: String,
    statement_sha256: String,
    spent_units: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
    epoch: u64,
    start_sequence: u64,
    native_after: JournalCheckpoint,
    confirmation_wrapper_result: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseEnd {
    epoch: u64,
    native_checkpoint: JournalCheckpoint,
    spent_units: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Payload {
    Header(Header),
    LeaseOpen(LeaseOpen),
    Start(Start),
    Outcome(Outcome),
    LeaseEnd(LeaseEnd),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame<T> {
    sequence: u64,
    previous_hash: String,
    payload: T,
}

fn hash(domain: &[u8], raw: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(raw);
    hex::encode(digest.finalize())
}
fn absolute(path: &Path) -> Result<()> {
    ensure(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir)),
        "RISK_LEDGER_PATH",
    )
}
fn read_wire<T: for<'a> Deserialize<'a>>(
    file: &mut File,
    magic: &[u8; 8],
    domain: &[u8],
    maximum_bytes: u64,
    maximum_frame: usize,
) -> Result<(Vec<Frame<T>>, Vec<String>)> {
    let length = file.metadata()?.len();
    ensure((8..=maximum_bytes).contains(&length), "RISK_LEDGER_LENGTH")?;
    file.seek(SeekFrom::Start(0))?;
    let mut prefix = [0; 8];
    file.read_exact(&mut prefix)?;
    ensure(&prefix == magic, "RISK_LEDGER_MAGIC")?;
    let mut position = 8_u64;
    let mut records = Vec::new();
    let mut hashes = Vec::new();
    while position < length {
        ensure(
            (records.len() as u64) < MAX_RECORDS,
            "RISK_LEDGER_RECORD_BUDGET",
        )?;
        let mut size = [0; 4];
        file.read_exact(&mut size)
            .map_err(|_| Error::from("RISK_LEDGER_TORN_TAIL"))?;
        let size = u32::from_be_bytes(size) as usize;
        ensure(
            (1..=maximum_frame).contains(&size),
            "RISK_LEDGER_FRAME_LENGTH",
        )?;
        let end = position
            .checked_add(4 + size as u64 + 32)
            .ok_or("RISK_LEDGER_LENGTH")?;
        ensure(end <= length, "RISK_LEDGER_TORN_TAIL")?;
        let mut raw = vec![0; size];
        file.read_exact(&mut raw)?;
        let mut supplied = [0; 32];
        file.read_exact(&mut supplied)?;
        let digest = hash(domain, &raw);
        ensure(digest == hex::encode(supplied), "RISK_LEDGER_HASH")?;
        let frame: Frame<T> = serde_json::from_slice(&raw)?;
        ensure(
            frame.sequence == records.len() as u64
                && frame.previous_hash == hashes.last().cloned().unwrap_or_else(|| "00".repeat(32)),
            "RISK_LEDGER_CHAIN",
        )?;
        records.push(frame);
        hashes.push(digest);
        position = end;
    }
    Ok((records, hashes))
}

struct NativePrefix {
    frames: Vec<Frame<Value>>,
    hashes: Vec<String>,
    journal_id: String,
}
impl NativePrefix {
    fn read(directory: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(directory)?;
        ensure(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "RISK_LEDGER_NATIVE_PATH",
        )?;
        // Inspect a special file without waiting for a FIFO writer. The opened
        // descriptor must still be a regular file before any journal is read.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(directory.join("journal.pnoj1"))?;
        ensure(file.metadata()?.is_file(), "RISK_LEDGER_NATIVE_PATH")?;
        let (frames, hashes): (Vec<Frame<Value>>, _) = read_wire(
            &mut file,
            NATIVE_MAGIC,
            NATIVE_DOMAIN,
            128 * 1024 * 1024,
            4 * 1024 * 1024,
        )?;
        let header = &frames.first().ok_or("RISK_LEDGER_NATIVE_HEADER")?.payload;
        ensure(
            header["kind"] == "header" && header["schema"] == "pon-native-owner-journal-v1",
            "RISK_LEDGER_NATIVE_HEADER",
        )?;
        let journal_id = header["journal_id"]
            .as_str()
            .ok_or("RISK_LEDGER_NATIVE_HEADER")?
            .to_owned();
        crate::digest(&journal_id)?;
        Ok(Self {
            frames,
            hashes,
            journal_id,
        })
    }
    fn pin(&self, pin: &JournalCheckpoint) -> Result<()> {
        ensure(
            pin.journal_id == self.journal_id
                && self
                    .hashes
                    .get(usize::try_from(pin.sequence).map_err(|_| "RISK_LEDGER_NATIVE_PIN")?)
                    == Some(&pin.record_hash),
            "RISK_LEDGER_NATIVE_PIN",
        )
    }
    fn payload(&self, sequence: u64) -> Option<&Value> {
        usize::try_from(sequence)
            .ok()
            .and_then(|i| self.frames.get(i))
            .map(|frame| &frame.payload)
    }
}

#[derive(Clone, Default)]
struct Replay {
    header: Option<Header>,
    epoch: u64,
    native_epoch: u64,
    active: bool,
    current: Option<u64>,
    spent: u64,
    starts: BTreeMap<u64, Start>,
    outcomes: BTreeMap<u64, Outcome>,
    pending: BTreeSet<u64>,
    pins: Vec<JournalCheckpoint>,
    lease_pins: Vec<(JournalCheckpoint, u64, bool)>,
}
impl Replay {
    fn pin(&mut self, pin: &JournalCheckpoint) -> Result<()> {
        ensure(
            self.header
                .as_ref()
                .is_some_and(|h| h.native_journal_id == pin.journal_id),
            "RISK_LEDGER_NATIVE_ID",
        )?;
        crate::digest(&pin.record_hash)?;
        if let Some(last) = self.pins.last() {
            ensure(
                pin.sequence >= last.sequence
                    && (pin.sequence != last.sequence || pin.record_hash == last.record_hash),
                "RISK_LEDGER_NATIVE_ORDER",
            )?;
        }
        self.pins.push(pin.clone());
        Ok(())
    }
    fn apply(&mut self, sequence: u64, payload: &Payload) -> Result<()> {
        match payload {
            Payload::Header(header) => {
                ensure(
                    sequence == 0
                        && self.header.is_none()
                        && header.schema == "pon-native-risk-ledger-v1",
                    "RISK_LEDGER_HEADER",
                )?;
                for value in [
                    &header.bank_id,
                    &header.native_journal_id,
                    &header.native_journal_header_hash,
                    &header.law_scope_sha256,
                ] {
                    crate::digest(value)?;
                }
                absolute(&header.native_journal_path)?;
                ensure(
                    (1..=MAX_DENOMINATOR).contains(&header.unit_denominator)
                        && (1..=header.unit_denominator).contains(&header.budget_units)
                        && !header.actual_probability_law_authenticated
                        && !header.native_conditional_risk_certified
                        && header.global_failure_probability.is_none(),
                    "RISK_LEDGER_QUALIFICATION",
                )?;
                self.header = Some(header.clone());
                self.pin(&header.native_anchor)?;
            }
            Payload::LeaseOpen(open) => {
                ensure(
                    self.header.is_some()
                        && open.epoch == self.epoch.checked_add(1).ok_or("RISK_LEDGER_EPOCH")?
                        && open.native_owner_epoch > self.native_epoch
                        && open.spent_units == self.spent
                        && open.prior_unresolved_starts
                            == self.pending.iter().copied().collect::<Vec<_>>(),
                    "RISK_LEDGER_OPEN",
                )?;
                self.pin(&open.native_checkpoint)?;
                self.lease_pins.push((
                    open.native_checkpoint.clone(),
                    open.native_owner_epoch,
                    true,
                ));
                self.epoch = open.epoch;
                self.native_epoch = open.native_owner_epoch;
                self.active = true;
                // An old unfinished registration stays pending and spent. A new
                // lease cannot manufacture its outcome or replay its request.
                self.current = None;
            }
            Payload::Start(start) => {
                let header = self.header.as_ref().ok_or("RISK_LEDGER_HEADER")?;
                ensure(
                    self.active
                        && self.current.is_none()
                        && start.epoch == self.epoch
                        && start.native_owner_epoch == self.native_epoch,
                    "RISK_LEDGER_START_STATE",
                )?;
                ensure(
                    start.law_scope_sha256 == header.law_scope_sha256,
                    "RISK_LEDGER_SCOPE",
                )?;
                ensure(
                    start.allowance_units > 0
                        && start.spent_units
                            == self
                                .spent
                                .checked_add(start.allowance_units)
                                .ok_or("RISK_LEDGER_BUDGET")?
                        && start.spent_units <= header.budget_units,
                    "RISK_LEDGER_BUDGET",
                )?;
                for value in [&start.transaction, &start.included, &start.statement_sha256] {
                    crate::digest(value)?;
                }
                ensure(
                    start.expected_native_intent_sequence
                        == start
                            .native_before
                            .sequence
                            .checked_add(1)
                            .ok_or("RISK_LEDGER_NATIVE_ORDER")?
                        && self.starts.values().all(|s| {
                            s.expected_native_intent_sequence
                                != start.expected_native_intent_sequence
                        }),
                    "RISK_LEDGER_DUPLICATE_NATIVE_INTENT",
                )?;
                self.pin(&start.native_before)?;
                self.spent = start.spent_units;
                self.starts.insert(sequence, start.clone());
                self.pending.insert(sequence);
                self.current = Some(sequence);
            }
            Payload::Outcome(outcome) => {
                ensure(
                    self.active
                        && outcome.epoch == self.epoch
                        && self.current == Some(outcome.start_sequence)
                        && self.pending.contains(&outcome.start_sequence),
                    "RISK_LEDGER_OUTCOME_STATE",
                )?;
                valid_result(&outcome.confirmation_wrapper_result)?;
                self.pin(&outcome.native_after)?;
                self.outcomes
                    .insert(outcome.start_sequence, outcome.clone());
                self.pending.remove(&outcome.start_sequence);
                self.current = None;
            }
            Payload::LeaseEnd(end) => {
                ensure(
                    self.active
                        && self.current.is_none()
                        && end.epoch == self.epoch
                        && end.spent_units == self.spent,
                    "RISK_LEDGER_END",
                )?;
                self.pin(&end.native_checkpoint)?;
                self.lease_pins
                    .push((end.native_checkpoint.clone(), self.native_epoch, false));
                self.active = false;
            }
        }
        Ok(())
    }
    fn verify_native(&self, native: &NativePrefix) -> Result<()> {
        let header = self.header.as_ref().ok_or("RISK_LEDGER_HEADER")?;
        ensure(
            native.journal_id == header.native_journal_id
                && native.hashes.first() == Some(&header.native_journal_header_hash),
            "RISK_LEDGER_NATIVE_ID",
        )?;
        for pin in &self.pins {
            native.pin(pin)?;
        }
        for (pin, epoch, opening) in &self.lease_pins {
            let payload = native
                .payload(pin.sequence)
                .ok_or("RISK_LEDGER_NATIVE_PIN")?;
            ensure(
                payload["kind"]
                    == (if *opening {
                        "open_observed"
                    } else {
                        "lease_end"
                    })
                    && payload["epoch"] == *epoch,
                "RISK_LEDGER_LEASE_BINDING",
            )?;
        }
        let mut covered = BTreeSet::new();
        for (sequence, start) in &self.starts {
            // Match the recorded prefix to the state in which the privately
            // held journaled owner can accept a new call. A missing later
            // intent cannot turn a closed, busy or stopping owner into one.
            let before = native
                .payload(start.native_before.sequence)
                .ok_or("RISK_LEDGER_NATIVE_PIN")?;
            ensure(
                before["epoch"] == start.native_owner_epoch
                    && (before["kind"] == "open_observed"
                        || (before["kind"] == "terminal"
                            && (before["result"]["ok"] == true
                                || (before["result"]["ok"] == false
                                    && before["result"]["requires_owner_stop"] == false)))),
                "RISK_LEDGER_NATIVE_START_STATE",
            )?;
            let expected = start.expected_native_intent_sequence;
            let candidate = native.payload(expected);
            let invoked = candidate
                .is_some_and(|p| p["kind"] == "intent" && p["operation"] == "confirmation");
            if invoked {
                let p = candidate.ok_or("RISK_LEDGER_NATIVE_CALL")?;
                ensure(
                    p["epoch"] == start.native_owner_epoch
                        && p["observed_now"] == start.observed_now
                        && p["input"]
                            == json!({"transaction":start.transaction,"included":start.included}),
                    "RISK_LEDGER_NATIVE_CALL",
                )?;
                covered.insert(expected);
            } else if let Some(p) = candidate {
                // A pre-dispatch process cut can be followed only by a new
                // native opening, never by a different same-lease operation.
                ensure(
                    p["kind"] == "open_intent"
                        && p["epoch"]
                            .as_u64()
                            .is_some_and(|e| e > start.native_owner_epoch),
                    "RISK_LEDGER_NATIVE_CALL",
                )?;
            }
            if let Some(outcome) = self.outcomes.get(sequence) {
                let post = outcome.native_after.sequence;
                ensure(
                    post >= start.native_before.sequence && post <= expected + 2,
                    "RISK_LEDGER_OUTCOME_RANGE",
                )?;
                if post == expected + 2 {
                    ensure(invoked, "RISK_LEDGER_NATIVE_CALL")?;
                    let prepared = native
                        .payload(expected + 1)
                        .ok_or("RISK_LEDGER_NATIVE_CALL")?;
                    let terminal = native.payload(post).ok_or("RISK_LEDGER_NATIVE_CALL")?;
                    ensure(
                        prepared["kind"] == "prepared"
                            && prepared["intent_sequence"] == expected
                            && prepared["epoch"] == start.native_owner_epoch
                            && terminal["kind"] == "terminal"
                            && terminal["operation"] == "confirmation"
                            && terminal["intent_sequence"] == expected
                            && terminal["epoch"] == start.native_owner_epoch
                            && terminal["result"] == outcome.confirmation_wrapper_result,
                        "RISK_LEDGER_NATIVE_OUTCOME",
                    )?;
                } else {
                    ensure(
                        outcome.confirmation_wrapper_result["ok"] == false
                            && (invoked || post == start.native_before.sequence),
                        "RISK_LEDGER_INCOMPLETE_OUTCOME",
                    )?;
                }
            }
        }
        for frame in &native.frames {
            if frame.payload["kind"] == "intent" && frame.payload["operation"] == "confirmation" {
                ensure(
                    frame.sequence > header.native_anchor.sequence
                        && covered.contains(&frame.sequence),
                    "RISK_LEDGER_UNREGISTERED_CONFIRMATION",
                )?;
            }
        }
        Ok(())
    }
}

fn valid_result(value: &Value) -> Result<()> {
    let map = value.as_object().ok_or("RISK_LEDGER_RESULT")?;
    if value["ok"] == true {
        ensure(
            map.len() == 2 && map.contains_key("value"),
            "RISK_LEDGER_RESULT",
        )
    } else {
        ensure(
            value["ok"] == false
                && map.len() == 4
                && value["error"].is_string()
                && value["error_kind"].is_string()
                && value["requires_owner_stop"].is_boolean(),
            "RISK_LEDGER_RESULT",
        )
    }
}
fn result_value(result: &Result<Observation>) -> Result<Value> {
    match result {
        Ok(observation) => Ok(json!({"ok":true,"value":serde_json::to_value(observation)?})),
        Err(error) => Ok(json!({"ok":false,"error":error.to_string(),
            "error_kind":format!("{:?}",error.kind()),"requires_owner_stop":error.requires_owner_stop()})),
    }
}

struct Bank {
    directory: PathBuf,
    _lock: File,
    file: File,
    identity: (u64, u64),
    length: u64,
    hashes: Vec<String>,
    replay: Replay,
    options: RiskLedgerOptions,
}
impl Bank {
    fn open(directory: &Path, options: RiskLedgerOptions) -> Result<Self> {
        absolute(directory)?;
        ensure(
            (1..=MAX_DENOMINATOR).contains(&options.unit_denominator)
                && (1..=options.unit_denominator).contains(&options.budget_units)
                && (2..=MAX_RECORDS).contains(&options.maximum_records)
                && (1024..=MAX_BYTES).contains(&options.maximum_bytes),
            "RISK_LEDGER_LIMITS",
        )?;
        if !directory.exists() {
            fs::DirBuilder::new().mode(0o700).create(directory)?;
            File::open(directory.parent().ok_or("RISK_LEDGER_PATH")?)?.sync_all()?;
        }
        let meta = fs::symlink_metadata(directory)?;
        ensure(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "RISK_LEDGER_PATH",
        )?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("bank.lock"))?;
        ensure(
            lock.metadata()?.is_file() && lock.metadata()?.nlink() == 1,
            "RISK_LEDGER_LOCK",
        )?;
        lock.try_lock_exclusive()
            .map_err(|_| Error::from("RISK_LEDGER_BUSY"))?;
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("risk.pnrl1"))?;
        let metadata = file.metadata()?;
        ensure(
            metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= options.maximum_bytes,
            "RISK_LEDGER_LENGTH",
        )?;
        if metadata.len() == 0 {
            ensure(
                options.expected_checkpoint.is_none(),
                "RISK_LEDGER_CHECKPOINT_MISSING",
            )?;
            file.write_all(MAGIC)?;
            file.sync_all()?;
            File::open(directory)?.sync_all()?;
        }
        let (frames, hashes): (Vec<Frame<Payload>>, _) =
            read_wire(&mut file, MAGIC, DOMAIN, options.maximum_bytes, MAX_FRAME)?;
        ensure(
            frames.len() as u64 <= options.maximum_records,
            "RISK_LEDGER_RECORD_BUDGET",
        )?;
        let mut replay = Replay::default();
        for frame in &frames {
            replay.apply(frame.sequence, &frame.payload)?;
        }
        if let Some(header) = &replay.header {
            ensure(
                header.unit_denominator == options.unit_denominator
                    && header.budget_units == options.budget_units
                    && header.law_scope_sha256 == hex::encode(options.law_scope_sha256),
                "RISK_LEDGER_IMMUTABLE_BUDGET_SCOPE",
            )?;
        }
        if let Some(pin) = &options.expected_checkpoint {
            ensure(
                replay
                    .header
                    .as_ref()
                    .is_some_and(|h| h.bank_id == pin.bank_id)
                    && hashes
                        .get(usize::try_from(pin.sequence).map_err(|_| "RISK_LEDGER_CHECKPOINT")?)
                        == Some(&pin.record_hash),
                "RISK_LEDGER_CHECKPOINT",
            )?;
        }
        let length = file.metadata()?.len();
        Ok(Self {
            directory: directory.to_owned(),
            _lock: lock,
            file,
            identity: (metadata.dev(), metadata.ino()),
            length,
            hashes,
            replay,
            options,
        })
    }
    fn guard(&self) -> Result<()> {
        let opened = self.file.metadata()?;
        let named = fs::symlink_metadata(self.directory.join("risk.pnrl1"))?;
        ensure(
            named.is_file()
                && !named.file_type().is_symlink()
                && named.nlink() == 1
                && (opened.dev(), opened.ino()) == self.identity
                && (named.dev(), named.ino()) == self.identity
                && opened.len() == self.length,
            "RISK_LEDGER_REPLACED",
        )
    }
    fn append(&mut self, payload: Payload) -> Result<u64> {
        self.guard()?;
        let sequence = self.hashes.len() as u64;
        let mut replay = self.replay.clone();
        replay.apply(sequence, &payload)?;
        let frame = Frame {
            sequence,
            previous_hash: self
                .hashes
                .last()
                .cloned()
                .unwrap_or_else(|| "00".repeat(32)),
            payload,
        };
        let raw = serde_json::to_vec(&frame)?;
        let next = self
            .length
            .checked_add(4 + raw.len() as u64 + 32)
            .ok_or("RISK_LEDGER_LENGTH")?;
        ensure(
            raw.len() <= MAX_FRAME
                && sequence < self.options.maximum_records
                && next <= self.options.maximum_bytes,
            "RISK_LEDGER_STORAGE_BUDGET",
        )?;
        let digest = hash(DOMAIN, &raw);
        self.file.write_all(&(raw.len() as u32).to_be_bytes())?;
        self.file.write_all(&raw)?;
        self.file
            .write_all(&hex::decode(&digest).map_err(|_| "RISK_LEDGER_HASH")?)?;
        self.file.sync_all()?;
        self.length = next;
        self.hashes.push(digest);
        self.replay = replay;
        Ok(sequence)
    }
    fn checkpoint(&self) -> Result<RiskLedgerCheckpoint> {
        self.guard()?;
        Ok(RiskLedgerCheckpoint {
            bank_id: self
                .replay
                .header
                .as_ref()
                .ok_or("RISK_LEDGER_HEADER")?
                .bank_id
                .clone(),
            sequence: self
                .hashes
                .len()
                .checked_sub(1)
                .ok_or("RISK_LEDGER_HEADER")? as u64,
            record_hash: self.hashes.last().ok_or("RISK_LEDGER_HEADER")?.clone(),
        })
    }
}

/// Exclusive opt-in owner. No accessors or callbacks expose its inner owner.
pub struct NativeRiskOwner {
    owner: Option<JournaledNativeOwner>,
    bank: Bank,
    blocked: bool,
}
impl NativeRiskOwner {
    pub fn open(
        store: &Path,
        native_journal: &Path,
        risk_directory: &Path,
        settings: Settings,
        native_options: NativeJournalOptions,
        risk_options: RiskLedgerOptions,
    ) -> Result<Self> {
        for path in [store, native_journal, risk_directory] {
            absolute(path)?;
        }
        ensure(
            !risk_directory.starts_with(store)
                && !store.starts_with(risk_directory)
                && !risk_directory.starts_with(native_journal)
                && !native_journal.starts_with(risk_directory),
            "RISK_LEDGER_SEPARATE_DIRECTORY",
        )?;
        let mut bank = Bank::open(risk_directory, risk_options)?;
        if let Some(header) = &bank.replay.header {
            ensure(
                header.native_journal_path == native_journal,
                "RISK_LEDGER_NATIVE_PATH",
            )?;
            // Check a saved bank and its entire native prefix before allowing
            // Node::open to run native recovery, then recheck under its lock.
            bank.replay
                .verify_native(&NativePrefix::read(native_journal)?)?;
        }
        let owner = JournaledNativeOwner::open(store, native_journal, settings, native_options)?;
        let native = NativePrefix::read(native_journal)?;
        let checkpoint = owner.checkpoint()?;
        native.pin(&checkpoint)?;
        if bank.replay.header.is_none() {
            ensure(
                native.frames.iter().all(|f| {
                    f.payload["kind"] != "intent" || f.payload["operation"] != "confirmation"
                }),
                "RISK_LEDGER_PRIOR_CONFIRMATIONS",
            )?;
            let mut nonce = [0; 32];
            File::open("/dev/urandom")?.read_exact(&mut nonce)?;
            bank.append(Payload::Header(Header {
                schema: "pon-native-risk-ledger-v1".to_owned(),
                bank_id: hex::encode(nonce),
                native_journal_id: native.journal_id.clone(),
                native_journal_header_hash: native.hashes[0].clone(),
                native_journal_path: native_journal.to_owned(),
                native_anchor: checkpoint.clone(),
                unit_denominator: bank.options.unit_denominator,
                budget_units: bank.options.budget_units,
                law_scope_sha256: hex::encode(bank.options.law_scope_sha256),
                actual_probability_law_authenticated: false,
                native_conditional_risk_certified: false,
                global_failure_probability: None,
            }))?;
        }
        bank.replay.verify_native(&native)?;
        let epoch = bank
            .replay
            .epoch
            .checked_add(1)
            .ok_or("RISK_LEDGER_EPOCH")?;
        let native_epoch = owner.status()?["epoch"]
            .as_u64()
            .ok_or("RISK_LEDGER_NATIVE_EPOCH")?;
        bank.append(Payload::LeaseOpen(LeaseOpen {
            epoch,
            native_owner_epoch: native_epoch,
            native_checkpoint: checkpoint,
            prior_unresolved_starts: bank.replay.pending.iter().copied().collect(),
            spent_units: bank.replay.spent,
        }))?;
        Ok(Self {
            owner: Some(owner),
            bank,
            blocked: false,
        })
    }
    fn owner(&self) -> Result<&JournaledNativeOwner> {
        self.owner
            .as_ref()
            .ok_or_else(|| "RISK_LEDGER_OWNER_CLOSED".into())
    }
    fn owner_mut(&mut self) -> Result<&mut JournaledNativeOwner> {
        self.owner
            .as_mut()
            .ok_or_else(|| "RISK_LEDGER_OWNER_CLOSED".into())
    }
    fn ready(&self) -> Result<()> {
        ensure(
            !self.blocked && self.bank.replay.active && self.bank.replay.current.is_none(),
            "RISK_LEDGER_UNRESOLVED",
        )?;
        self.bank.guard()?;
        ensure(
            self.owner()?.status()?["blocked"] == false,
            "RISK_LEDGER_NATIVE_BLOCKED",
        )
    }
    pub fn make(&mut self, request: JournalMakeRequest, observed_now: u64) -> Result<Packet> {
        self.ready()?;
        self.owner_mut()?.make(request, observed_now)
    }
    pub fn admit(&mut self, packet: &Packet, observed_now: u64) -> Result<Hash> {
        self.ready()?;
        self.owner_mut()?.admit(packet, observed_now)
    }
    pub fn activate_observed(&mut self, target: Hash, observed_now: u64) -> Result<Hash> {
        self.ready()?;
        self.owner_mut()?.activate_observed(target, observed_now)
    }
    pub fn observe(&mut self, observed_now: u64) -> Result<OwnerCensus> {
        self.ready()?;
        self.owner_mut()?.observe(observed_now)
    }
    pub fn native_checkpoint(&self) -> Result<JournalCheckpoint> {
        self.owner()?.checkpoint()
    }
    pub fn checkpoint(&self) -> Result<RiskLedgerCheckpoint> {
        self.bank.checkpoint()
    }
    /// The returned handle does not invoke native confirmation. Dropping it
    /// leaves a charged start and blocks this lease. Reopening never replays it.
    pub fn start_confirmation(
        &mut self,
        request: RiskConfirmationRequest,
    ) -> Result<PendingRiskConfirmation<'_>> {
        self.ready()?;
        let before = self.owner()?.checkpoint()?;
        let native_epoch = self.owner()?.status()?["epoch"]
            .as_u64()
            .ok_or("RISK_LEDGER_NATIVE_EPOCH")?;
        let start = Start {
            epoch: self.bank.replay.epoch,
            native_owner_epoch: native_epoch,
            expected_native_intent_sequence: before
                .sequence
                .checked_add(1)
                .ok_or("RISK_LEDGER_NATIVE_ORDER")?,
            native_before: before,
            transaction: hex::encode(request.transaction),
            included: hex::encode(request.included),
            observed_now: request.observed_now,
            allowance_units: request.allowance_units,
            law_scope_sha256: hex::encode(request.law_scope_sha256),
            statement_sha256: hex::encode(request.statement_sha256),
            spent_units: self
                .bank
                .replay
                .spent
                .checked_add(request.allowance_units)
                .ok_or("RISK_LEDGER_BUDGET")?,
        };
        // append() validates scope and cap, writes the full start and fsyncs it
        // before the exclusive handle can dispatch the original native method.
        let payload = Payload::Start(start);
        // Pure semantic refusal has no effect and does not spend. After actual
        // publication begins, even an error may have written bytes: stop the
        // lease instead of inferring rollback or retrying an uncertain start.
        let mut candidate = self.bank.replay.clone();
        candidate.apply(self.bank.hashes.len() as u64, &payload)?;
        self.blocked = true;
        let sequence = self.bank.append(payload)?;
        Ok(PendingRiskConfirmation {
            owner: self,
            sequence,
            request,
        })
    }
    pub fn confirmation(&mut self, request: RiskConfirmationRequest) -> Result<Observation> {
        self.start_confirmation(request)?.execute()?.finish()
    }
    pub fn status(&self) -> Result<Value> {
        let header = self
            .bank
            .replay
            .header
            .as_ref()
            .ok_or("RISK_LEDGER_HEADER")?;
        let native_blocked = self.owner()?.status()?["blocked"]
            .as_bool()
            .ok_or("RISK_LEDGER_NATIVE_STATE")?;
        Ok(
            json!({"schema":"pon-native-risk-ledger-status-v1","checkpoint":self.checkpoint()?,
            "native_checkpoint":self.native_checkpoint()?,"epoch":self.bank.replay.epoch,"blocked":self.blocked || native_blocked,
            "bank_operation_blocked":self.blocked,"native_owner_blocked":native_blocked,
            "unit_denominator":header.unit_denominator,"budget_units":header.budget_units,
            "spent_units":self.bank.replay.spent,"remaining_units":header.budget_units-self.bank.replay.spent,
            "starts_registered":self.bank.replay.starts.len(),"outcomes_recorded":self.bank.replay.outcomes.len(),
            "unresolved_starts":self.bank.replay.pending.iter().copied().collect::<Vec<_>>(),
            "law_scope_sha256":header.law_scope_sha256,"actual_probability_law_authenticated":false,
            "physical_pre_registration_independently_attested":false,"trusted_history_anchor":false,
            "native_conditional_risk_certified":false,"global_failure_probability":null}),
        )
    }
    pub fn finish(
        mut self,
        observed_now: u64,
    ) -> Result<(RiskLedgerCheckpoint, JournalCheckpoint)> {
        self.ready()?;
        self.blocked = true;
        let native = self
            .owner
            .take()
            .ok_or("RISK_LEDGER_OWNER_CLOSED")?
            .finish(observed_now)?;
        self.bank.append(Payload::LeaseEnd(LeaseEnd {
            epoch: self.bank.replay.epoch,
            native_checkpoint: native.clone(),
            spent_units: self.bank.replay.spent,
        }))?;
        Ok((self.bank.checkpoint()?, native))
    }
}

#[must_use = "Registration is already spent; dropping leaves it pending and blocks this lease"]
pub struct PendingRiskConfirmation<'a> {
    owner: &'a mut NativeRiskOwner,
    sequence: u64,
    request: RiskConfirmationRequest,
}
impl<'a> PendingRiskConfirmation<'a> {
    pub fn registration_sequence(&self) -> u64 {
        self.sequence
    }
    pub fn execute(self) -> Result<PendingRiskOutcome<'a>> {
        let result = self.owner.owner_mut()?.confirmation(
            self.request.transaction,
            self.request.included,
            self.request.observed_now,
        );
        Ok(PendingRiskOutcome {
            owner: self.owner,
            sequence: self.sequence,
            result,
        })
    }
}

#[must_use = "Native confirmation was called; finish records its outcome without refunding its charge"]
pub struct PendingRiskOutcome<'a> {
    owner: &'a mut NativeRiskOwner,
    sequence: u64,
    result: Result<Observation>,
}
impl PendingRiskOutcome<'_> {
    /// A live wrapper return, not a durable risk outcome or a risk theorem.
    pub fn wrapper_succeeded(&self) -> bool {
        self.result.is_ok()
    }
    pub fn finish(self) -> Result<Observation> {
        let outcome = Outcome {
            epoch: self.owner.bank.replay.epoch,
            start_sequence: self.sequence,
            native_after: self.owner.owner()?.checkpoint()?,
            confirmation_wrapper_result: result_value(&self.result)?,
        };
        let mut candidate = self.owner.bank.replay.clone();
        candidate.apply(
            self.owner.bank.hashes.len() as u64,
            &Payload::Outcome(outcome.clone()),
        )?;
        let path = &candidate
            .header
            .as_ref()
            .ok_or("RISK_LEDGER_HEADER")?
            .native_journal_path;
        candidate.verify_native(&NativePrefix::read(path)?)?;
        self.owner.bank.append(Payload::Outcome(outcome))?;
        self.owner.blocked = self.owner.owner()?.status()?["blocked"] != false;
        self.result
    }
}
