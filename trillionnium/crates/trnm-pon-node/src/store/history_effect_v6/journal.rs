//! Append-only predebit ledger. An unknown interval never becomes an exact
//! ServiceMutationCpuSettlement; reconciliation is a different retained event.
use super::*;
use policy::{Anchor, Budget, EffectMarker, Frontier, Identity, Operation, Purpose, Usage};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(super) mod publication;

const MAX_RECORD: u64 = 256 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CpuReceipt {
    pub schema: String,
    pub owner_cpu_ns: Option<u64>,
    pub scoped_worker_cpu_ns: Option<u64>,
    pub total_cpu_ns: Option<u64>,
    pub live_paid_cpu_ns: Option<u64>,
    pub residual_cpu_ns: Option<u64>,
    pub spawned_workers: u64,
    pub started_workers: u64,
    pub finished_workers: u64,
    pub known_workers: u64,
    pub live_refused: bool,
    pub accounting_unavailable: bool,
}
impl CpuReceipt {
    pub fn known(&self) -> bool {
        !self.accounting_unavailable
            && self.schema == "service-owner-scoped-thread-cpu-settlement-v1"
            && self
                .owner_cpu_ns
                .zip(self.scoped_worker_cpu_ns)
                .and_then(|(a, b)| a.checked_add(b))
                == self.total_cpu_ns
            && self
                .live_paid_cpu_ns
                .zip(self.residual_cpu_ns)
                .and_then(|(a, b)| a.checked_add(b))
                == self.total_cpu_ns
            && self.total_cpu_ns.is_some()
            && self.spawned_workers == self.started_workers
            && self.started_workers == self.finished_workers
            && self.finished_workers == self.known_workers
    }
}
impl From<&ServiceMutationCpuSettlement> for CpuReceipt {
    fn from(value: &ServiceMutationCpuSettlement) -> Self {
        Self {
            schema: value.schema.to_owned(),
            owner_cpu_ns: value.owner_cpu_ns,
            scoped_worker_cpu_ns: value.scoped_worker_cpu_ns,
            total_cpu_ns: value.total_cpu_ns,
            live_paid_cpu_ns: value.live_paid_cpu_ns,
            residual_cpu_ns: value.residual_cpu_ns,
            spawned_workers: value.spawned_workers,
            started_workers: value.started_workers,
            finished_workers: value.finished_workers,
            known_workers: value.known_workers,
            live_refused: value.live_refused,
            accounting_unavailable: value.accounting_unavailable,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Event {
    Budget {
        signed: Vec<u8>,
    },
    Intent {
        signed: Vec<u8>,
    },
    Settlement {
        operation: String,
        native_id: Option<String>,
        native_error: Option<String>,
        cpu: CpuReceipt,
        marker: Option<Box<EffectMarker>>,
        effect_readback_known: bool,
    },
    NotStarted {
        operation: String,
        original_error: String,
    },
    UnknownPrepaidReconciled {
        signed: Vec<u8>,
        closed_process: Vec<u8>,
    },
    CleanClose {
        frontier: Frontier,
    },
    SettledEpochReconciledV1 {
        signed: Vec<u8>,
        closed_process: Vec<u8>,
    },
    StartupNoNativeClosedV1 {
        signed: Vec<u8>,
        closed_process: Vec<u8>,
    },
}
impl Event {
    fn record_schema(&self) -> &'static str {
        match self {
            Self::SettledEpochReconciledV1 { .. } => epoch_recovery_v1::RECORD_SCHEMA,
            Self::StartupNoNativeClosedV1 { .. } => startup_no_native_v1::RECORD_SCHEMA,
            _ => "restricted-history-effect-record-v6",
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Frame {
    pub(super) schema: String,
    pub(super) identity_sha256: String,
    pub(super) sequence: u64,
    pub(super) previous: String,
    pub(super) at_ns: u64,
    pub(super) event: Event,
}
#[derive(Clone)]
pub(super) struct Pending {
    pub operation: Operation,
    pub intent_sha256: String,
    pub observed_receipt: Option<CpuReceipt>,
    pub budget_expires_ns: u64,
    pub envelope_sha256: String,
    pub intent_at_ns: u64,
}
#[derive(Clone)]
struct LastSettled {
    operation: Operation,
    intent_sha256: String,
    marker: Option<EffectMarker>,
    envelope_sha256: String,
    intent_at_ns: u64,
    cpu: CpuReceipt,
    native_id: Option<String>,
    native_error: Option<String>,
}
#[derive(Clone)]
struct State {
    anchor: Anchor,
    budget: Option<Budget>,
    budget_envelope: Option<String>,
    spent: Usage,
    nonces: u64,
    used: BTreeSet<String>,
    epochs: BTreeSet<String>,
    epoch: Option<String>,
    // Derived by replay, never taken from the last refused request. Only a
    // retained actual effect marker advances an already opened epoch frontier.
    epoch_frontier: Option<Frontier>,
    pending: Option<Pending>,
    known: u64,
    reconciled_unknown: u64,
    reconciled_settled_epochs: u64,
    closed_no_native_startups: u64,
    last_settled: Option<LastSettled>,
    markers: BTreeMap<String, EffectMarker>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            anchor: Anchor::empty(),
            budget: None,
            budget_envelope: None,
            spent: Usage::default(),
            nonces: 0,
            used: BTreeSet::new(),
            epochs: BTreeSet::new(),
            epoch: None,
            epoch_frontier: None,
            pending: None,
            known: 0,
            reconciled_unknown: 0,
            reconciled_settled_epochs: 0,
            closed_no_native_startups: 0,
            last_settled: None,
            markers: BTreeMap::new(),
        }
    }
}
impl State {
    fn apply(&mut self, event: &Event, identity: &Identity, at: u64) -> Result<()> {
        match event {
            Event::Budget { signed } => {
                ensure(self.pending.is_none(), "HISTORY_V6_PENDING_DEBT")?;
                let budget = policy::budget(signed, identity, at)?;
                ensure(
                    budget.body.outside_anchor == self.anchor,
                    "HISTORY_V6_OUTSIDE_ANCHOR",
                )?;
                let previous = self.budget.as_ref();
                ensure(
                    budget.body.sequence == previous.map_or(1, |b| b.sequence + 1)
                        && previous
                            .is_none_or(|b| b.lifetime_ceiling.fits(budget.body.lifetime_ceiling))
                        && self.spent.fits(budget.body.lifetime_ceiling),
                    "HISTORY_V6_BUDGET_ROLLBACK",
                )?;
                self.budget = Some(budget.body);
                self.budget_envelope = Some(budget.envelope_sha256);
            }
            Event::Intent { signed } => {
                ensure(self.pending.is_none(), "HISTORY_V6_PENDING_DEBT")?;
                let verified = policy::operation(signed, identity, at)?;
                let op = verified.body;
                let budget = self.budget.as_ref().ok_or("HISTORY_V6_BUDGET_REQUIRED")?;
                ensure(
                    budget.issued_ns <= at && at < budget.expires_ns,
                    "HISTORY_V6_BUDGET_EXPIRED",
                )?;
                ensure(
                    op.budget_id == budget.budget_id && op.outside_spent_anchor == self.anchor,
                    "HISTORY_V6_OUTSIDE_ANCHOR",
                )?;
                ensure(
                    !self.used.contains(&op.operation_id)
                        && op.request_nonce > self.nonces
                        && (budget.nonce_first..=budget.nonce_last).contains(&op.request_nonce),
                    "HISTORY_V6_REPLAY",
                )?;
                let spent = self.spent.add(op.allowance)?;
                ensure(
                    spent.fits(budget.lifetime_ceiling),
                    "HISTORY_V6_LIFETIME_BUDGET",
                )?;
                if op.purpose == Purpose::Startup {
                    ensure(
                        self.epoch.is_none() && !self.epochs.contains(&op.epoch),
                        "HISTORY_V6_UNCLOSED_EPOCH",
                    )?;
                    self.epoch = Some(op.epoch.clone());
                    self.epoch_frontier = Some(op.owner_frontier.clone());
                    self.epochs.insert(op.epoch.clone());
                    self.last_settled = None;
                } else {
                    ensure(self.epoch.as_ref() == Some(&op.epoch), "HISTORY_V6_EPOCH")?;
                }
                self.spent = spent;
                self.nonces = op.request_nonce;
                self.used.insert(op.operation_id.clone());
                self.pending = Some(Pending {
                    operation: op,
                    intent_sha256: verified.intent_sha256,
                    observed_receipt: None,
                    budget_expires_ns: budget.expires_ns,
                    envelope_sha256: policy::digest(signed),
                    intent_at_ns: at,
                });
            }
            Event::Settlement {
                operation,
                cpu,
                marker,
                native_id,
                native_error,
                effect_readback_known,
            } => {
                let pending = self.pending.as_mut().ok_or("HISTORY_V6_NO_PENDING")?;
                ensure(
                    &pending.operation.operation_id == operation
                        && pending.observed_receipt.is_none(),
                    "HISTORY_V6_REPLAY",
                )?;
                ensure(
                    native_id.is_none() || native_error.is_none(),
                    "HISTORY_V6_NATIVE_RESULT",
                )?;
                if let Some(id) = native_id {
                    policy::id(id, 32)?;
                }
                if let Some(marker) = marker {
                    check_marker(pending, marker)?;
                    ensure(
                        self.markers
                            .insert(operation.clone(), marker.as_ref().clone())
                            .is_none(),
                        "HISTORY_V6_REPLAY",
                    )?;
                }
                // Preserve any late native result even when CPU is unknown or
                // exceeds the signed ceiling. Such a scope stays unresolved.
                let effect_known = *effect_readback_known
                    && (!matches!(
                        pending.operation.purpose,
                        Purpose::Validation | Purpose::Activation
                    ) || native_id.as_ref() != Some(&pending.operation.target)
                        || marker.is_some());
                if effect_known
                    && cpu.known()
                    && cpu
                        .total_cpu_ns
                        .is_some_and(|v| v <= pending.operation.allowance.cpu_ns)
                {
                    if let Some(marker) = marker {
                        self.epoch_frontier = Some(marker.after.clone());
                    }
                    self.last_settled = Some(LastSettled {
                        operation: pending.operation.clone(),
                        intent_sha256: pending.intent_sha256.clone(),
                        marker: marker.as_deref().cloned(),
                        envelope_sha256: pending.envelope_sha256.clone(),
                        intent_at_ns: pending.intent_at_ns,
                        cpu: cpu.clone(),
                        native_id: native_id.clone(),
                        native_error: native_error.clone(),
                    });
                    self.pending = None;
                    self.known += 1;
                } else {
                    pending.observed_receipt = Some(cpu.clone());
                }
            }
            Event::NotStarted {
                operation,
                original_error,
            } => {
                let pending = self.pending.as_ref().ok_or("HISTORY_V6_NO_PENDING")?;
                ensure(
                    &pending.operation.operation_id == operation
                        && !original_error.is_empty()
                        && original_error.len() <= 1024
                        && pending.observed_receipt.is_none(),
                    "HISTORY_V6_REPLAY",
                )?;
                // This is a refusal before the original CPU interval exists;
                // no synthetic zero-valued receipt is emitted and no refund.
                if pending.operation.purpose == Purpose::Startup {
                    self.epoch = None;
                    self.epoch_frontier = None;
                    self.last_settled = None;
                }
                self.pending = None;
            }
            Event::UnknownPrepaidReconciled {
                signed,
                closed_process,
            } => {
                let recovery = policy::recovery(signed, closed_process, identity, at)?;
                self.check_recovery(&recovery)?;
                if let Some(marker) = &recovery.closed.marker {
                    if let Some(previous) = self
                        .markers
                        .insert(marker.operation_id.clone(), marker.clone())
                    {
                        ensure(previous == *marker, "HISTORY_V6_SQL_MARKER_BINDING")?;
                    }
                }
                self.nonces = recovery.body.request_nonce;
                self.pending = None;
                self.epoch = None;
                self.epoch_frontier = None;
                self.last_settled = None;
                self.reconciled_unknown += 1;
            }
            Event::CleanClose { frontier } => {
                frontier.validate()?;
                ensure(
                    self.pending.is_none() && self.epoch.is_some(),
                    "HISTORY_V6_PENDING_DEBT",
                )?;
                self.epoch = None;
                self.epoch_frontier = None;
                self.last_settled = None;
            }
            Event::SettledEpochReconciledV1 {
                signed,
                closed_process,
            } => {
                let verified =
                    epoch_recovery_v1::authenticate(signed, closed_process, identity, at)?;
                self.check_settled_epoch(&verified, at)?;
                self.spent = self.spent.add(verified.body.allowance)?;
                self.nonces = verified.body.request_nonce;
                self.used.insert(verified.body.reconciliation_id);
                self.epoch = None;
                self.epoch_frontier = None;
                self.last_settled = None;
                self.reconciled_settled_epochs += 1;
            }
            Event::StartupNoNativeClosedV1 {
                signed,
                closed_process,
            } => {
                let verified =
                    startup_no_native_v1::authenticate(signed, closed_process, identity, at)?;
                self.check_startup_no_native(&verified, at)?;
                self.spent = self.spent.add(verified.body.allowance)?;
                self.nonces = verified.body.request_nonce;
                self.used.insert(verified.body.reconciliation_id);
                self.epoch = None;
                self.epoch_frontier = None;
                self.last_settled = None;
                self.closed_no_native_startups += 1;
            }
        }
        Ok(())
    }
    fn check_recovery(&self, recovery: &policy::VerifiedRecovery) -> Result<()> {
        let pending = self.pending.as_ref().ok_or("HISTORY_V6_NO_PENDING")?;
        let op = &pending.operation;
        ensure(
            matches!(op.purpose, Purpose::Validation | Purpose::Activation),
            "HISTORY_V6_STARTUP_CRASH_UNQUALIFIED",
        )?;
        ensure(
            recovery.body.outside_anchor == self.anchor
                && recovery.body.pending_operation_id == op.operation_id
                && recovery.body.intent_sha256 == pending.intent_sha256
                && recovery.closed.epoch == op.epoch
                && recovery.body.request_nonce > self.nonces,
            "HISTORY_V6_RECOVERY_BINDING",
        )?;
        let budget = self.budget.as_ref().ok_or("HISTORY_V6_BUDGET_REQUIRED")?;
        ensure(
            (budget.nonce_first..=budget.nonce_last).contains(&recovery.body.request_nonce),
            "HISTORY_V6_REPLAY",
        )?;
        // The whole dead process is deliberately over-attributed to this ONE
        // pending scope. Unrelated unused reservations cannot cover overrun.
        ensure(
            recovery.closed.reported_cpu_upper_bound_ns <= op.allowance.cpu_ns,
            "HISTORY_V6_UNCOVERED_PROCESS_CPU",
        )?;
        if let Some(marker) = &recovery.closed.marker {
            check_marker(pending, marker)?;
            ensure(
                recovery.closed.actual_frontier == marker.after,
                "HISTORY_V6_RECOVERY_FRONTIER",
            )?;
        } else {
            ensure(
                recovery.closed.actual_frontier == op.owner_frontier,
                "HISTORY_V6_UNMARKED_EFFECT",
            )?;
        }
        Ok(())
    }
    fn check_settled_epoch(&self, verified: &epoch_recovery_v1::Verified, at: u64) -> Result<()> {
        ensure(self.pending.is_none(), "HISTORY_EPOCH_V1_PENDING_DEBT")?;
        let body = &verified.body;
        let last = self
            .last_settled
            .as_ref()
            .ok_or("HISTORY_EPOCH_V1_NO_SETTLEMENT")?;
        let frontier = self
            .epoch_frontier
            .as_ref()
            .ok_or("HISTORY_EPOCH_V1_NO_FRONTIER")?;
        ensure(
            self.epoch.as_ref() == Some(&body.epoch)
                && last.operation.epoch == body.epoch
                && last.operation.operation_id == body.last_operation_id
                && last.intent_sha256 == body.last_intent_sha256
                && last.marker == verified.closed.marker
                && *frontier == body.actual_frontier
                && self.anchor == body.outside_anchor,
            "HISTORY_EPOCH_V1_SETTLED_BINDING",
        )?;
        let budget = self.budget.as_ref().ok_or("HISTORY_V6_BUDGET_REQUIRED")?;
        ensure(
            // This NEW domain permits only post-exit accounting/epoch closure
            // after the old budget expires. It does not revive that budget's
            // Startup or effect authority; those old expiry checks stay intact.
            body.budget_id == budget.budget_id
                && budget.issued_ns <= at
                && body.request_nonce > self.nonces
                && (budget.nonce_first..=budget.nonce_last).contains(&body.request_nonce)
                && !self.used.contains(&body.reconciliation_id)
                && self
                    .spent
                    .add(body.allowance)?
                    .fits(budget.lifetime_ceiling),
            "HISTORY_EPOCH_V1_FRESH_ALLOWANCE",
        )
    }
    fn check_startup_no_native(
        &self,
        verified: &startup_no_native_v1::Verified,
        at: u64,
    ) -> Result<()> {
        ensure(self.pending.is_none(), "HISTORY_NO_NATIVE_PENDING_SCOPE")?;
        let last = self
            .last_settled
            .as_ref()
            .ok_or("HISTORY_NO_NATIVE_KNOWN_STARTUP_REQUIRED")?;
        let body = &verified.body;
        let closed = &verified.closed;
        let cpu = &last.cpu;
        ensure(
            self.epochs.len() == 1
                && self.used.len() == 1
                && self.known == 1
                && self.markers.is_empty()
                && self.reconciled_unknown == 0
                && self.reconciled_settled_epochs == 0
                && self.closed_no_native_startups == 0
                && last.operation.purpose == Purpose::Startup
                && last.marker.is_none()
                && last.native_id.is_none()
                && last.native_error.as_ref().is_some_and(|s| !s.is_empty())
                && cpu.known()
                && !cpu.live_refused
                && cpu.total_cpu_ns.is_some_and(|v| {
                    v > 0
                        && v <= last.operation.allowance.cpu_ns
                        && v <= closed.reported_cpu_upper_bound_ns
                })
                && cpu.spawned_workers == 0
                && cpu.started_workers == 0
                && cpu.finished_workers == 0
                && cpu.known_workers == 0
                && cpu.scoped_worker_cpu_ns == Some(0)
                && self.spent == last.operation.allowance
                && self.epoch.as_ref() == Some(&last.operation.epoch),
            "HISTORY_NO_NATIVE_SOLE_KNOWN_FAILED_STARTUP",
        )?;
        ensure(
            body.outside_anchor == self.anchor
                && body.startup_operation_id == last.operation.operation_id
                && body.startup_intent_sha256 == last.intent_sha256
                && body.signed_startup_sha256 == last.envelope_sha256
                && closed.startup_intent_at_ns == last.intent_at_ns
                && policy::encoded(&verified.startup)? == policy::encoded(&last.operation)?,
            "HISTORY_NO_NATIVE_ORIGINAL_STARTUP_BINDING",
        )?;
        let budget = self.budget.as_ref().ok_or("HISTORY_V6_BUDGET_REQUIRED")?;
        // This new administrative authority alone may close the known failed
        // epoch after the old budget expires; it grants no old work authority.
        ensure(
            body.budget_id == budget.budget_id
                && budget.issued_ns <= at
                && body.request_nonce > self.nonces
                && (budget.nonce_first..=budget.nonce_last).contains(&body.request_nonce)
                && !self.used.contains(&body.reconciliation_id)
                && self
                    .spent
                    .add(body.allowance)?
                    .fits(budget.lifetime_ceiling),
            "HISTORY_NO_NATIVE_FRESH_ALLOWANCE",
        )
    }
}
pub(super) fn check_marker(pending: &Pending, marker: &EffectMarker) -> Result<()> {
    let op = &pending.operation;
    ensure(
        marker.schema == "restricted-history-effect-sql-marker-v6"
            && marker.identity_sha256 == op.identity.digest()?
            && marker.owner == op.identity.owner
            && marker.store == op.identity.store
            && marker.epoch == op.epoch
            && marker.operation_id == op.operation_id
            && marker.purpose == op.purpose
            && marker.intent_sha256 == pending.intent_sha256
            && Some(&marker.packet_sha256) == op.packet_sha256.as_ref()
            && marker.target == op.target
            && marker.target_root == op.target_root
            && Some(&marker.validation_operation_id) == op.validation_operation_id.as_ref()
            && Some(&marker.activation_operation_id) == op.activation_operation_id.as_ref()
            && marker.before == op.owner_frontier,
        "HISTORY_V6_SQL_MARKER_BINDING",
    )?;
    let expected = if op.purpose == Purpose::Activation {
        Frontier {
            block: op.target.clone(),
            root: op.target_root.clone(),
            generation: op
                .owner_frontier
                .generation
                .checked_add(1)
                .ok_or("HISTORY_V6_GENERATION")?,
        }
    } else {
        op.owner_frontier.clone()
    };
    ensure(marker.after == expected, "HISTORY_V6_SQL_MARKER_FRONTIER")
}

pub(super) struct Journal {
    path: PathBuf,
    dir: File,
    lock: File,
    identity: Identity,
    expected_uid: u32,
    state: State,
}
impl Journal {
    pub fn open(
        path: &Path,
        expected_uid: u32,
        identity: &Identity,
        outside: &Anchor,
    ) -> Result<Self> {
        identity.validate()?;
        outside.validate()?;
        ensure(path.is_absolute(), "HISTORY_V6_JOURNAL_PATH")?;
        if !path.exists() {
            ensure(*outside == Anchor::empty(), "HISTORY_V6_JOURNAL_ROLLBACK")?;
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            sync_dir(path.parent().ok_or("HISTORY_V6_JOURNAL_PATH")?)?;
        }
        let journal = Self::lock_directory(path, expected_uid, identity, true)?;
        Self::replay(journal, outside)
    }
    pub fn open_existing(
        path: &Path,
        expected_uid: u32,
        identity: &Identity,
        outside: &Anchor,
    ) -> Result<Self> {
        outside.validate()?;
        let journal = Self::lock_directory(path, expected_uid, identity, false)?;
        Self::replay(journal, outside)
    }
    fn replay(mut journal: Self, outside: &Anchor) -> Result<Self> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&journal.path)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "HISTORY_V6_JOURNAL_FILE")?;
            if name == "owner.lock" {
                continue;
            }
            // Torn/orphan publication has no implied spent authority. It is
            // explicitly unqualified, never silently deleted or truncated.
            ensure(
                name.len() == 90 && name.ends_with(".json") && name.as_bytes()[20] == b'-',
                "HISTORY_V6_JOURNAL_TAIL_UNKNOWN",
            )?;
            ensure(records.len() < 4096, "HISTORY_V6_JOURNAL_CAPACITY")?;
            records.push((name, entry.path()));
        }
        ensure(records.len() <= 4096, "HISTORY_V6_JOURNAL_CAPACITY")?;
        records.sort();
        for (name, path) in records {
            let raw = journal.read_record(&path)?;
            let frame: Frame = serde_json::from_slice(&raw)?;
            ensure(
                policy::encoded(&frame)? == raw
                    && name == format!("{:020}-{}.json", frame.sequence, policy::digest(&raw)),
                "HISTORY_V6_JOURNAL_CANONICAL",
            )?;
            journal.apply_frame(frame, policy::digest(&raw))?;
        }
        ensure(
            journal.state.anchor == *outside,
            "HISTORY_V6_JOURNAL_ROLLBACK",
        )?;
        journal.ready()?;
        Ok(journal)
    }
    fn lock_directory(
        path: &Path,
        expected_uid: u32,
        identity: &Identity,
        create_lock: bool,
    ) -> Result<Self> {
        identity.validate()?;
        ensure(path.is_absolute(), "HISTORY_V6_JOURNAL_PATH")?;
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = dir.metadata()?;
        ensure(
            metadata.is_dir() && metadata.uid() == expected_uid && metadata.mode() & 0o077 == 0,
            "HISTORY_V6_JOURNAL_MODE",
        )?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(create_lock)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path.join("owner.lock"))?;
        lock.try_lock_exclusive()?;
        let journal = Self {
            path: path.to_path_buf(),
            dir,
            lock,
            identity: identity.clone(),
            expected_uid,
            state: State::default(),
        };
        journal.ready()?;
        Ok(journal)
    }
    fn read_record(&self, path: &Path) -> Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let m = file.metadata()?;
        ensure(
            m.is_file()
                && m.uid() == self.expected_uid
                && m.mode() & 0o077 == 0
                && m.nlink() == 1
                && m.len() <= MAX_RECORD,
            "HISTORY_V6_JOURNAL_RECORD",
        )?;
        let mut raw = Vec::new();
        file.take(MAX_RECORD + 1).read_to_end(&mut raw)?;
        ensure(raw.len() as u64 == m.len(), "HISTORY_V6_JOURNAL_CHANGED")?;
        Ok(raw)
    }
    pub fn ready(&self) -> Result<()> {
        let lock = self.lock.metadata()?;
        ensure(
            lock.is_file() && lock.nlink() == 1,
            "HISTORY_V6_JOURNAL_LOCK",
        )?;
        for (file, path) in [
            (&self.dir, self.path.clone()),
            (&self.lock, self.path.join("owner.lock")),
        ] {
            let held = file.metadata()?;
            let visible = fs::symlink_metadata(path)?;
            ensure(
                held.dev() == visible.dev()
                    && held.ino() == visible.ino()
                    && held.uid() == self.expected_uid
                    && held.mode() & 0o077 == 0
                    && !visible.file_type().is_symlink(),
                "HISTORY_V6_JOURNAL_CHANGED",
            )?;
        }
        Ok(())
    }
    fn apply_frame(&mut self, frame: Frame, digest: String) -> Result<()> {
        ensure(
            frame.schema == frame.event.record_schema()
                && frame.identity_sha256 == self.identity.digest()?
                && frame.sequence == self.state.anchor.sequence + 1
                && frame.sequence <= 4096
                && frame.previous == self.state.anchor.digest,
            "HISTORY_V6_JOURNAL_CHAIN",
        )?;
        self.state
            .apply(&frame.event, &self.identity, frame.at_ns)?;
        self.state.anchor = Anchor {
            sequence: frame.sequence,
            digest,
        };
        Ok(())
    }
    fn append(&mut self, event: Event) -> Result<()> {
        self.ready()?;
        let frame = Frame {
            schema: event.record_schema().into(),
            identity_sha256: self.identity.digest()?,
            sequence: self.state.anchor.sequence + 1,
            previous: self.state.anchor.digest.clone(),
            at_ns: policy::now()?,
            event,
        };
        ensure(frame.sequence <= 4096, "HISTORY_V6_JOURNAL_CAPACITY")?;
        let mut checked = self.state.clone();
        checked.apply(&frame.event, &self.identity, frame.at_ns)?;
        let raw = policy::encoded(&frame)?;
        ensure(
            raw.len() as u64 <= MAX_RECORD,
            "HISTORY_V6_JOURNAL_CAPACITY",
        )?;
        let digest = policy::digest(&raw);
        let temporary = self.path.join(format!("pending-{:020}", frame.sequence));
        let final_path = self
            .path
            .join(format!("{:020}-{digest}.json", frame.sequence));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(&raw)?;
        file.sync_all()?;
        #[cfg(all(test, target_os = "linux"))]
        super::tests::publication::append_cut(self, &frame, &raw, "file-synced");
        fs::hard_link(&temporary, &final_path)?;
        #[cfg(all(test, target_os = "linux"))]
        super::tests::publication::append_cut(self, &frame, &raw, "linked");
        self.dir.sync_all()?;
        #[cfg(all(test, target_os = "linux"))]
        super::tests::publication::append_cut(self, &frame, &raw, "final-synced");
        fs::remove_file(&temporary)?;
        #[cfg(all(test, target_os = "linux"))]
        super::tests::publication::append_cut(self, &frame, &raw, "unlinked");
        self.dir.sync_all()?;
        #[cfg(all(test, target_os = "linux"))]
        super::tests::publication::append_cut(self, &frame, &raw, "published");
        self.apply_frame(frame, digest)?;
        self.ready()
    }
    pub fn install_budget(&mut self, raw: &[u8]) -> Result<()> {
        let verified = policy::budget(raw, &self.identity, policy::now()?)?;
        if self.state.budget_envelope.as_ref() == Some(&verified.envelope_sha256) {
            return Ok(());
        }
        self.append(Event::Budget {
            signed: raw.to_vec(),
        })
    }
    pub fn reserve(&mut self, raw: &[u8]) -> Result<Pending> {
        self.append(Event::Intent {
            signed: raw.to_vec(),
        })?;
        self.pending()
            .cloned()
            .ok_or_else(|| "HISTORY_V6_NO_PENDING".into())
    }
    pub fn settle(
        &mut self,
        operation: &str,
        native: &Result<Hash>,
        cpu: &ServiceMutationCpuSettlement,
        marker: Option<EffectMarker>,
        effect_readback_known: bool,
    ) -> Result<()> {
        self.append(Event::Settlement {
            operation: operation.to_owned(),
            native_id: native.as_ref().ok().map(hex::encode),
            native_error: native.as_ref().err().map(ToString::to_string),
            cpu: CpuReceipt::from(cpu),
            marker: marker.map(Box::new),
            effect_readback_known,
        })
    }
    pub fn not_started(&mut self, operation: &str, error: &Error) -> Result<()> {
        self.append(Event::NotStarted {
            operation: operation.to_owned(),
            original_error: error.to_string(),
        })
    }
    pub fn reconcile(&mut self, input: &policy::RecoveryInput) -> Result<()> {
        self.append(Event::UnknownPrepaidReconciled {
            signed: input.signed.clone(),
            closed_process: input.closed_process.clone(),
        })
    }
    pub fn check_recovery(&self, recovery: &policy::VerifiedRecovery) -> Result<()> {
        self.state.check_recovery(recovery)
    }
    pub fn check_settled_epoch(
        &self,
        verified: &epoch_recovery_v1::Verified,
        at: u64,
    ) -> Result<()> {
        self.state.check_settled_epoch(verified, at)
    }
    pub fn reconcile_settled_epoch(&mut self, signed: &[u8], closed_process: &[u8]) -> Result<()> {
        self.append(Event::SettledEpochReconciledV1 {
            signed: signed.to_vec(),
            closed_process: closed_process.to_vec(),
        })
    }
    pub fn check_startup_no_native(
        &self,
        verified: &startup_no_native_v1::Verified,
        at: u64,
    ) -> Result<()> {
        self.state.check_startup_no_native(verified, at)
    }
    pub fn close_startup_no_native(&mut self, signed: &[u8], closed_process: &[u8]) -> Result<()> {
        self.append(Event::StartupNoNativeClosedV1 {
            signed: signed.to_vec(),
            closed_process: closed_process.to_vec(),
        })
    }
    pub fn close(&mut self, frontier: Frontier) -> Result<()> {
        self.append(Event::CleanClose { frontier })
    }
    pub fn anchor(&self) -> Anchor {
        self.state.anchor.clone()
    }
    pub fn pending(&self) -> Option<&Pending> {
        self.state.pending.as_ref()
    }
    pub fn markers(&self) -> &BTreeMap<String, EffectMarker> {
        &self.state.markers
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn work_nonce(&self, nonce: u64) -> Result<()> {
        let budget = self
            .state
            .budget
            .as_ref()
            .ok_or("HISTORY_V6_BUDGET_REQUIRED")?;
        ensure(
            (budget.work_nonce_first..=budget.work_nonce_last).contains(&nonce),
            "HISTORY_V6_WORK_NONCE",
        )
    }
    pub fn observation(&self) -> serde_json::Value {
        serde_json::json!({"schema":"restricted-history-effect-journal-observation-v6", "anchor":self.anchor(),
            "spent":self.state.spent,"used_operations":self.state.used.len(),"request_nonce":self.state.nonces,
            "pending":self.state.pending.as_ref().map(|p|&p.operation.operation_id), "epoch":self.state.epoch,
            "known_settlements":self.state.known,"unknown_prepaid_reconciliations":self.state.reconciled_unknown,
            "settled_epoch_reconciliations_v1":self.state.reconciled_settled_epochs,
            "startup_no_native_closures_v1":self.state.closed_no_native_startups})
    }
}
