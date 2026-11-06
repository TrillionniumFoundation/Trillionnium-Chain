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
