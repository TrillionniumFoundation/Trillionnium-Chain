//! A complete bounded campaign, not a rollback oracle or execution permission.
//! Cold opening audits all referenced signed bytes. A prepared local snapshot
//! can only finish the exact recorded transition; it never initiates network I/O.
use super::files::{Blob, Files, MAX_BLOB, MAX_METADATA};
use super::PinnedPqRecoveryClient;
use crate::ingress::{
    pq_network::{PqResponseEvidence, PreparedPqRequest},
    Request,
};
use crate::public_submit::{
    SubmitRecoveryPlan, MAX_PARENT_PACKETS, MAX_RECOVERY_CALLS, MAX_RECOVERY_MILLISECONDS,
    MAX_SUBMIT_ATTEMPTS,
};
use crate::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};
use trnm_protocol::pon_wire::{hash, Hash};

const SCHEMA: &str = "pq-parent-recovery-campaign-v1";
const NS: u64 = 1_000_000_000;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Boot {
    id: String,
    device: u64,
    inode: u64,
}
fn stamp() -> Result<(Boot, u64)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/proc/sys/kernel/random/boot_id")?;
    ensure(file.metadata()?.is_file(), "PQ_RECOVERY_BOOT_ID")?;
    let mut raw = Vec::new();
    Read::by_ref(&mut file).take(129).read_to_end(&mut raw)?;
    ensure(
        raw.len() == 37
            && raw[36] == b'\n'
            && raw[..36].iter().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    *b == b'-'
                } else {
                    b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                }
            }),
        "PQ_RECOVERY_BOOT_ID",
    )?;
    let namespace = fs::metadata("/proc/self/ns/time")?;
    ensure(namespace.ino() != 0, "PQ_RECOVERY_TIME_NAMESPACE")?;
    let time = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let sec = u64::try_from(time.tv_sec).map_err(std::io::Error::other)?;
    let nanos = u64::try_from(time.tv_nsec).map_err(std::io::Error::other)?;
    ensure(nanos < NS, "PQ_RECOVERY_CLOCK")?;
    let now = sec
        .checked_mul(NS)
        .and_then(|s| s.checked_add(nanos))
        .ok_or("PQ_RECOVERY_CLOCK")?;
    Ok((
        Boot {
            id: String::from_utf8(raw).map_err(|_| "PQ_RECOVERY_BOOT_ID")?,
            device: namespace.dev(),
            inode: namespace.ino(),
        },
        now,
    ))
}
fn ns(value: Duration) -> Result<u64> {
    u64::try_from(value.as_nanos()).map_err(|_| "PQ_RECOVERY_CLOCK".into())
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Epoch {
    boot: Boot,
    created: u64,
    deadline: u64,
    budget: u64,
    submits: u8,
    calls: u8,
    parents: u8,
    retry_pause: u64,
}
impl Epoch {
    fn new(plan: &SubmitRecoveryPlan) -> Result<Self> {
        plan.validate()?;
        // Sample BOOTTIME first. Taking Instant remaining afterwards can only
        // shorten the persisted deadline, including time spent parsing/opening.
        let (boot, now) = stamp()?;
        let remaining = plan
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or("SUBMIT_RECOVERY_DEADLINE")?;
        let value = Self {
            boot,
            created: now,
            deadline: now.checked_add(ns(remaining)?).ok_or("PQ_RECOVERY_CLOCK")?,
            budget: ns(plan.deadline.duration_since(plan.started))?,
            submits: plan.max_submit_attempts,
            calls: plan.max_calls,
            parents: plan.max_parent_packets,
            retry_pause: ns(plan.retry_pause)?,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        ensure(
            self.budget >= 1_000_000
                && self.budget <= MAX_RECOVERY_MILLISECONDS * 1_000_000
                && self.deadline > self.created
                && self.deadline - self.created <= self.budget
                && (1..=MAX_SUBMIT_ATTEMPTS).contains(&self.submits)
                && (1..=MAX_RECOVERY_CALLS).contains(&self.calls)
                && self.parents <= MAX_PARENT_PACKETS
                && self.retry_pause <= NS,
            "SUBMIT_RECOVERY_LIMITS",
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    context: Hash,
    peer: Hash,
    policy: Hash,
    target: Hash,
    initial: u64,
}
impl Binding {
    fn new(client: &PinnedPqRecoveryClient<'_>, target: Hash, initial: u64) -> Result<Self> {
        ensure(
            (1..=i64::MAX as u64).contains(&initial),
            "PQ_NETWORK_SEQUENCE",
        )?;
        Ok(Self {
            context: client.context_id(),
            peer: client.peer_key_id(),
            policy: client.policy().id(),
            target,
            initial,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    request: Blob,
    wire: Blob,
    reply: Option<Blob>,
    sequence: u64,
    expiry: u64,
    operation: Hash,
    packet: Option<Hash>,
    attempts: u8,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    binding: Binding,
    epoch: Epoch,
    last_boot: u64,
    revision: u64,
    previous: Option<Hash>,
    reads: u8,
    parents: BTreeSet<Hash>,
    operations: Vec<Operation>,
    pending_fence: Option<PendingFence>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PendingFence {
    ExpiredUnconfirmed,
    LiveRestoreRejected,
}
pub(super) struct PendingMetadata {
    pub sequence: u64,
    pub expires_at: u64,
    pub operation: Hash,
    pub attempts: u8,
    pub packet_id: Option<Hash>,
    pub canonical_request_json: String,
}
pub(super) struct JournalStatus {
    pub used_calls: u8,
    pub per_packet_submit_counts: BTreeMap<Hash, u8>,
    pub planned_parent_count: usize,
}
pub(super) struct Journal {
    files: Files,
    record: Record,
    raw: Vec<u8>,
    fenced: Cell<bool>,
}
fn metadata_digest(raw: &[u8]) -> Hash {
    hash(b"pq-parent-journal-bytes-v1", &[raw])
}
fn parse(raw: &[u8]) -> Result<Record> {
    ensure(raw.len() <= MAX_METADATA, "PQ_RECOVERY_METADATA_LIMIT")?;
    let record: Record = serde_json::from_slice(raw)?;
    ensure(
        serde_json::to_vec(&record)? == raw,
        "PQ_RECOVERY_CANONICAL_METADATA",
    )?;
    shape(&record)?;
    Ok(record)
}
fn request(raw: &[u8], client: &PinnedPqRecoveryClient<'_>) -> Result<(Request, Option<Hash>)> {
    ensure(raw.len() <= MAX_BLOB, "PQ_RECOVERY_REQUEST_LIMIT")?;
    let body: Request = serde_json::from_slice(raw)?;
    ensure(
        serde_json::to_vec(&body)? == raw,
        "PQ_RECOVERY_CANONICAL_REQUEST",
    )?;
    ensure(
        matches!(&body, Request::Head | Request::Submit { .. }),
        "PQ_RECOVERY_NATIVE_OPERATION",
    )?;
    // Use the actual Node-selected codec, including NPQ6. This is identity
    // extraction only; it neither checks work nor grants packet admission.
    let packet = client.packet_id(&body)?;
    Ok((body, packet))
}
fn shape(record: &Record) -> Result<JournalStatus> {
    ensure(record.schema == SCHEMA, "PQ_RECOVERY_SCHEMA")?;
    record.epoch.validate()?;
    ensure(
        record.last_boot >= record.epoch.created
            && record.parents.len() <= record.epoch.parents as usize
            && record.operations.len() <= record.epoch.calls as usize
            && (1..=i64::MAX as u64).contains(&record.binding.initial),
        "PQ_RECOVERY_RECORD",
    )?;
    let mut calls = record.reads as usize;
    let mut closed = 0usize;
    let mut submits = BTreeMap::<Hash, u8>::new();
    for (i, op) in record.operations.iter().enumerate() {
        ensure(
            op.sequence == record.binding.initial + i as u64
                && op.sequence <= i64::MAX as u64
                && (op.reply.is_some() || i + 1 == record.operations.len())
                && (op.reply.is_none() || op.attempts > 0),
            "PQ_RECOVERY_SEQUENCE",
        )?;
        for blob in [&op.request, &op.wire].into_iter().chain(op.reply.as_ref()) {
            ensure(
                blob.bytes > 0 && blob.bytes as usize <= MAX_BLOB,
                "PQ_RECOVERY_BLOB_LIMIT",
            )?;
        }
        if let Some(id) = op.packet {
            ensure(
                id == record.binding.target || record.parents.contains(&id),
                "PQ_RECOVERY_PACKET_CONTEXT",
            )?;
            let count = submits.entry(id).or_default();
            *count = count
                .checked_add(op.attempts)
                .ok_or("SUBMIT_RECOVERY_ATTEMPT_LIMIT")?;
            ensure(
                *count <= record.epoch.submits,
                "SUBMIT_RECOVERY_ATTEMPT_LIMIT",
            )?;
        }
        calls += op.attempts as usize;
        closed += usize::from(op.reply.is_some());
    }
    ensure(
        calls <= record.epoch.calls as usize,
        "SUBMIT_RECOVERY_CALL_LIMIT",
    )?;
    ensure(
        record.pending_fence.is_none()
            || record
                .operations
                .last()
                .is_some_and(|op| op.reply.is_none()),
        "PQ_RECOVERY_FENCE_CONTEXT",
    )?;
    let revision = calls
        + record.parents.len()
        + record.operations.len()
        + closed
        + usize::from(record.pending_fence.is_some());
    ensure(
        record.revision == revision as u64 && (record.previous.is_none() == (revision == 0)),
        "PQ_RECOVERY_REVISION",
    )?;
    Ok(JournalStatus {
        used_calls: calls as u8,
        per_packet_submit_counts: submits,
        planned_parent_count: record.parents.len(),
    })
}
fn step(old: &Record, next: &Record, old_raw: &[u8]) -> Result<()> {
    ensure(
        next.binding == old.binding
            && next.epoch == old.epoch
            && next.schema == old.schema
            && next.last_boot >= old.last_boot
            && next.revision == old.revision + 1
            && next.previous == Some(metadata_digest(old_raw)),
        "PQ_RECOVERY_TRANSITION",
    )?;
    let same_usage = next.reads == old.reads && next.parents == old.parents;
    let append_parent = next.reads == old.reads
        && next.operations == old.operations
        && next.parents.len() == old.parents.len() + 1
        && old.parents.is_subset(&next.parents);
    let read = next.reads as u16 == old.reads as u16 + 1
        && next.parents == old.parents
        && next.operations == old.operations;
    let append = same_usage
        && next.operations.len() == old.operations.len() + 1
        && next.operations[..old.operations.len()] == old.operations
        && old.operations.last().is_none_or(|op| op.reply.is_some())
        && next
            .operations
            .last()
            .is_some_and(|op| op.attempts == 0 && op.reply.is_none());
    let mutate = if same_usage
        && !old.operations.is_empty()
        && old.operations.len() == next.operations.len()
    {
        let i = old.operations.len() - 1;
        let a = &old.operations[i];
        let b = &next.operations[i];
        next.operations[..i] == old.operations[..i]
            && a.request == b.request
            && a.wire == b.wire
            && a.sequence == b.sequence
            && a.expiry == b.expiry
            && a.operation == b.operation
            && a.packet == b.packet
            && a.reply.is_none()
            && ((b.reply.is_none() && b.attempts as u16 == a.attempts as u16 + 1)
                || (b.reply.is_some() && a.attempts > 0 && b.attempts == a.attempts))
    } else {
        false
    };
    let fence = old.pending_fence.is_none()
        && next.pending_fence.is_some()
        && same_usage
        && next.operations == old.operations;
    let ordinary = old.pending_fence.is_none()
        && next.pending_fence.is_none()
        && (append_parent || read || append || mutate);
    ensure(fence || ordinary, "PQ_RECOVERY_TRANSITION")?;
    shape(next)?;
    Ok(())
}
fn audit(files: &mut Files, record: &Record, client: &PinnedPqRecoveryClient<'_>) -> Result<()> {
    shape(record)?;
    for op in &record.operations {
        let body_raw = files.get(&op.request)?;
        let (body, packet) = request(&body_raw, client)?;
        ensure(packet == op.packet, "PQ_RECOVERY_PACKET_CONTEXT")?;
        let wire = files.get(&op.wire)?;
        ensure(
            client.audit_retained_request(&wire, &body)? == (op.sequence, op.expiry, op.operation),
            "PQ_RECOVERY_REQUEST_CONTEXT",
        )?;
        if let Some(reply) = &op.reply {
            client.audit_retained_reply(&wire, &files.get(reply)?)?;
        }
    }
    files.recheck()
}
fn epoch_now(record: &Record) -> Result<u64> {
    let (boot, now) = stamp()?;
    ensure(
        boot == record.epoch.boot && now >= record.last_boot,
        "PQ_RECOVERY_EPOCH_CONTEXT",
    )?;
    Ok(now)
}
impl Journal {
    pub fn initialize(
        path: &Path,
        client: &PinnedPqRecoveryClient<'_>,
        target: Hash,
        initial_sequence: u64,
        plan: &SubmitRecoveryPlan,
    ) -> Result<Self> {
        let epoch = Epoch::new(plan)?;
        let record = Record {
            schema: SCHEMA.into(),
            binding: Binding::new(client, target, initial_sequence)?,
            last_boot: epoch.created,
            epoch,
            revision: 0,
            previous: None,
            reads: 0,
            parents: BTreeSet::new(),
            operations: Vec::new(),
            pending_fence: None,
        };
        let raw = serde_json::to_vec(&record)?;
        let mut files = Files::acquire(path, true)?;
        files.prepare(&raw)?;
        files.publish()?;
        let journal = Self {
            files,
            record,
            raw,
            fenced: Cell::new(false),
        };
        journal.recovery_plan()?;
        Ok(journal)
    }
    pub fn open(
        path: &Path,
        client: &PinnedPqRecoveryClient<'_>,
        target: Hash,
        initial_sequence: u64,
    ) -> Result<Self> {
        let binding = Binding::new(client, target, initial_sequence)?;
        let mut files = Files::acquire(path, false)?;
        let (committed, prepared) = files.load()?;
        let selected = committed
            .as_ref()
            .or(prepared.as_ref())
            .ok_or("PQ_RECOVERY_EMPTY")?;
        let prior = parse(selected)?;
        ensure(prior.binding == binding, "PQ_RECOVERY_CONTEXT")?;
        let (record, raw) = if let Some(next_raw) = prepared.as_ref() {
            let next = parse(next_raw)?;
            ensure(next.binding == binding, "PQ_RECOVERY_CONTEXT")?;
            if let Some(old_raw) = committed.as_ref() {
                step(&prior, &next, old_raw)?;
            } else {
                ensure(next.revision == 0, "PQ_RECOVERY_INITIALIZATION")?;
            }
            (next, next_raw.clone())
        } else {
            (prior, selected.clone())
        };
        // step preserves every old immutable reference. Auditing this selected
        // complete record validates all old and newly retained signatures once,
        // without retaining an authorization or signature-result cache.
        audit(&mut files, &record, client)?;
        epoch_now(&record)?;
        if prepared.is_some() {
            files.publish()?;
        }
        epoch_now(&record)?;
        files.recheck()?;
        let journal = Self {
            files,
            record,
            raw,
            fenced: Cell::new(false),
        };
        // A durable fence is a historical conclusion. Its rejection does not
        // sample the wall clock, so a later backward step cannot reopen it.
        journal.healthy()?;
        Ok(journal)
    }
    fn healthy(&self) -> Result<()> {
        ensure(
            !self.fenced.get() && !self.files.is_fenced() && self.record.pending_fence.is_none(),
            "PQ_RECOVERY_FENCED",
        )
    }
    fn clock(&self) -> Result<u64> {
        self.healthy()?;
        let result = epoch_now(&self.record);
        if result.is_err() {
            self.fenced.set(true);
        }
        result
    }
    pub fn recovery_plan(&self) -> Result<SubmitRecoveryPlan> {
        // Anchor Instant before BOOTTIME and identity I/O. Cold reopening cannot
        // add that I/O interval back onto the original absolute deadline.
        let anchor = Instant::now();
        let now = self.clock()?;
        let remaining = self
            .record
            .epoch
            .deadline
            .checked_sub(now)
            .filter(|n| *n > 0)
            .ok_or("SUBMIT_RECOVERY_DEADLINE")?;
        let deadline = anchor
            .checked_add(Duration::from_nanos(remaining))
            .ok_or("PQ_RECOVERY_CLOCK")?;
        let started = deadline
            .checked_sub(Duration::from_nanos(self.record.epoch.budget))
            .ok_or("PQ_RECOVERY_CLOCK")?;
        let plan = SubmitRecoveryPlan {
            started,
            deadline,
            max_submit_attempts: self.record.epoch.submits,
            max_calls: self.record.epoch.calls,
            max_parent_packets: self.record.epoch.parents,
            retry_pause: Duration::from_nanos(self.record.epoch.retry_pause),
        };
        plan.validate()?;
        Ok(plan)
    }
    fn same_client(&self, client: &PinnedPqRecoveryClient<'_>) -> Result<()> {
        ensure(
            Binding::new(
                client,
                self.record.binding.target,
                self.record.binding.initial,
            )? == self.record.binding,
            "PQ_RECOVERY_CONTEXT",
        )
    }
    fn save(&mut self, mut next: Record) -> Result<()> {
        self.healthy()?;
        next.last_boot = self.clock()?;
        next.revision = self.record.revision + 1;
        next.previous = Some(metadata_digest(&self.raw));
        step(&self.record, &next, &self.raw)?;
        let raw = serde_json::to_vec(&next)?;
        let result = (|| {
            self.files.prepare(&raw)?;
            self.files.publish()
        })();
        if result.is_err() {
            self.fenced.set(true);
        }
        result?;
        self.record = next;
        self.raw = raw;
        Ok(())
    }
    fn fence_pending(&mut self, reason: PendingFence) -> Result<()> {
        let mut next = self.record.clone();
        next.pending_fence = Some(reason);
        let result = self.save(next);
        // A persistence failure is unknown and still closes this owner. Any
        // complete/truncated prepared fence remains for cold verification.
        self.fenced.set(true);
        result
    }
    /// Called only for the direct local send expiry error, never response.value.
    /// Bind that already-observed conclusion to the exact attempted request.
    /// Deliberately do not sample wall time again.
    pub(super) fn fence_expired_unconfirmed(&mut self, prepared: &PreparedPqRequest) -> Result<()> {
        self.healthy()?;
        let op = self
            .record
            .operations
            .last()
            .filter(|op| op.reply.is_none() && op.attempts > 0)
            .ok_or("PQ_RECOVERY_NO_ATTEMPT")?;
        ensure(
            (
                prepared.sequence(),
                prepared.expires_at(),
                prepared.operation_id(),
            ) == (op.sequence, op.expiry, op.operation),
            "PQ_RECOVERY_REQUEST_CONTEXT",
        )?;
        ensure(
            self.files.get(&op.wire)? == prepared.wire(),
            "PQ_RECOVERY_REQUEST_CONTEXT",
        )?;
        self.fence_pending(PendingFence::ExpiredUnconfirmed)
    }
    fn refuse_expired_pending(&mut self) -> Result<()> {
        self.healthy()?;
        let expiry = self
            .record
            .operations
            .last()
            .filter(|op| op.reply.is_none())
            .map(|op| op.expiry);
        if let Some(expiry) = expiry {
            if crate::ingress::now()? > expiry {
                self.fence_pending(PendingFence::ExpiredUnconfirmed)?;
                return Err("PQ_NETWORK_EXPIRED_UNCONFIRMED".into());
            }
        }
        Ok(())
    }
    /// Reobserve storage identity only; no deadline, permission or budget renewal.
    pub(super) fn recheck(&mut self) -> Result<()> {
        self.healthy()?;
        self.files.recheck()
    }
    pub fn cursor(&self) -> Result<u64> {
        self.healthy()?;
        Ok(self.record.binding.initial
            + self
                .record
                .operations
                .iter()
                .filter(|op| op.reply.is_some())
                .count() as u64)
    }
    pub fn status(&self) -> Result<JournalStatus> {
        self.healthy()?;
        shape(&self.record)
    }
    pub fn pending_request(&mut self) -> Result<Option<PendingMetadata>> {
        self.healthy()?;
        let Some(op) = self
            .record
            .operations
            .last()
            .filter(|op| op.reply.is_none())
        else {
            return Ok(None);
        };
        let raw = self.files.get(&op.request)?;
        Ok(Some(PendingMetadata {
            sequence: op.sequence,
            expires_at: op.expiry,
            operation: op.operation,
            attempts: op.attempts,
            packet_id: op.packet,
            canonical_request_json: String::from_utf8(raw)
                .map_err(|_| "PQ_RECOVERY_REQUEST_ENCODING")?,
        }))
    }
    pub fn prepare_or_restore(
        &mut self,
        client: &PinnedPqRecoveryClient<'_>,
        body: &Request,
        expiry: u64,
    ) -> Result<PreparedPqRequest> {
        self.refuse_expired_pending()?;
        self.recovery_plan()?;
        self.same_client(client)?;
        self.files.recheck()?;
        let body_raw = serde_json::to_vec(body)?;
        let (body, packet) = request(&body_raw, client)?;
        if let Some(op) = self
            .record
            .operations
            .last()
            .filter(|op| op.reply.is_none())
        {
            ensure(
                self.files.get(&op.request)? == body_raw,
                "PQ_RECOVERY_PENDING_REQUEST",
            )?;
            let wire = self.files.get(&op.wire)?;
            let expected = (op.sequence, op.expiry, op.operation);
            let prepared = match client.restore_prepared(&wire) {
                Ok(prepared) => prepared,
                Err(error) => {
                    // The live verifier may itself have observed expiry before
                    // a wall-clock step back. Never infer success from a later sample.
                    self.fence_pending(PendingFence::LiveRestoreRejected)?;
                    return Err(error);
                }
            };
            ensure(
                (
                    prepared.sequence(),
                    prepared.expires_at(),
                    prepared.operation_id(),
                ) == expected,
                "PQ_RECOVERY_REQUEST_CONTEXT",
            )?;
            self.files.recheck()?;
            self.refuse_expired_pending()?;
            self.recovery_plan()?;
            return Ok(prepared);
        }
        ensure(
            self.status()?.used_calls < self.record.epoch.calls
                && self.record.operations.len() < self.record.epoch.calls as usize,
            "SUBMIT_RECOVERY_CALL_LIMIT",
        )?;
        let prepared = client.prepare(self.cursor()?, expiry, body)?;
        let operation = Operation {
            request: self.files.put(&body_raw)?,
            wire: self.files.put(prepared.wire())?,
            reply: None,
            sequence: prepared.sequence(),
            expiry: prepared.expires_at(),
            operation: prepared.operation_id(),
            packet,
            attempts: 0,
        };
        let mut next = self.record.clone();
        next.operations.push(operation);
        self.save(next)?;
        self.refuse_expired_pending()?;
        self.recovery_plan()?;
        Ok(prepared)
    }
    pub fn record_attempt(&mut self) -> Result<()> {
        self.refuse_expired_pending()?;
        self.recovery_plan()?;
        let mut next = self.record.clone();
        let op = next
            .operations
            .last_mut()
            .filter(|op| op.reply.is_none())
            .ok_or("PQ_RECOVERY_NO_PENDING")?;
        // Pin the exact pending bytes under this File owner before reserving
        // another attempt; no historical response can discharge this step.
        self.files.get(&op.request)?;
        self.files.get(&op.wire)?;
        op.attempts = op
            .attempts
            .checked_add(1)
            .ok_or("SUBMIT_RECOVERY_CALL_LIMIT")?;
        self.save(next)?;
        self.refuse_expired_pending()?;
        self.recovery_plan().map(|_| ())
    }
    pub fn reserve_read(&mut self) -> Result<()> {
        self.refuse_expired_pending()?;
        self.recovery_plan()?;
        let mut next = self.record.clone();
        next.reads = next
            .reads
            .checked_add(1)
            .ok_or("SUBMIT_RECOVERY_CALL_LIMIT")?;
        self.save(next)?;
        self.recovery_plan().map(|_| ())
    }
    pub fn reserve_parent(&mut self, id: Hash) -> Result<()> {
        self.refuse_expired_pending()?;
        self.recovery_plan()?;
        self.files.recheck()?;
        if self.record.parents.contains(&id) {
            return Ok(());
        }
        let mut next = self.record.clone();
        next.parents.insert(id);
        self.save(next)?;
        self.recovery_plan().map(|_| ())
    }
    pub fn complete(
        &mut self,
        client: &PinnedPqRecoveryClient<'_>,
        evidence: &PqResponseEvidence,
    ) -> Result<()> {
        self.healthy()?;
        self.same_client(client)?;
        self.files.recheck()?;
        let op = self
            .record
            .operations
            .last()
            .filter(|op| op.reply.is_none() && op.attempts > 0)
            .ok_or("PQ_RECOVERY_NO_ATTEMPT")?;
        let wire = self.files.get(&op.wire)?;
        client.audit_retained_reply(&wire, evidence.wire())?;
        ensure(
            evidence.response().operation == hex::encode(op.operation),
            "PQ_RECOVERY_REPLY_CONTEXT",
        )?;
        let reply = self.files.put(evidence.wire())?;
        let mut next = self.record.clone();
        next.operations
            .last_mut()
            .ok_or("PQ_RECOVERY_NO_PENDING")?
            .reply = Some(reply);
        // Preserve an actual signed fact even after the campaign's deadline.
        // It does not renew that deadline or permit any new network operation.
        self.save(next)
    }
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
