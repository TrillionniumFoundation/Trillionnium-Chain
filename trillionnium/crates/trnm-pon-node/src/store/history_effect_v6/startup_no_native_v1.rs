//! A separately authorized closure of one known failed FIRST Startup, observed
//! from birth in a guardian-created empty namespace. This never resets Native,
//! fabricates NotStarted/CPU zero, or admits a partly initialized database.
use super::*;
use policy::{Anchor, Identity, Operation, Usage};
use serde::{Deserialize, Serialize};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt as _;

const DOMAIN: &[u8] = b"TRNM-HISTORY-STARTUP-NO-NATIVE-CLOSURE-V1";
pub(super) const RECORD_SCHEMA: &str = "restricted-history-startup-no-native-closure-record-v1";
pub(super) const NATIVE_NAME: &str = "native";
pub(super) const LEASE_NAME: &str = "startup-namespace.lock";
pub(super) const SELECTOR: &str =
    "store::history_effect_v6::tests::history_effect_v6_process_child_helper";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Pins {
    pub source_commit: String,
    pub executable_sha256: String,
    pub fixture_sha256: String,
    pub guardian_sha256: String,
    pub observer_sha256: String,
    pub process_guard_sha256: String,
    pub preparation_sha256: String,
}
impl Pins {
    pub(super) fn validate(&self) -> Result<()> {
        policy::id(&self.source_commit, 20)?;
        for value in [
            &self.executable_sha256,
            &self.fixture_sha256,
            &self.guardian_sha256,
            &self.observer_sha256,
            &self.process_guard_sha256,
            &self.preparation_sha256,
        ] {
            policy::id(value, 32)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u64,
    pub bytes: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}
impl FileIdentity {
    fn from_metadata(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            links: m.nlink(),
            bytes: m.len(),
            modified_seconds: m.mtime(),
            modified_nanoseconds: m.mtime_nsec(),
            changed_seconds: m.ctime(),
            changed_nanoseconds: m.ctime_nsec(),
        }
    }
    fn validate(&self, uid: u32, directory: bool) -> Result<()> {
        ensure(
            self.inode > 0
                && self.uid == uid
                && self.mode & 0o7777 == (if directory { 0o700 } else { 0o600 })
                && self.mode & libc::S_IFMT
                    == (if directory {
                        libc::S_IFDIR
                    } else {
                        libc::S_IFREG
                    })
                && (if directory {
                    matches!(self.links, 2 | 3)
                } else {
                    self.links == 1
                })
                && (0..1_000_000_000).contains(&self.modified_nanoseconds)
                && (0..1_000_000_000).contains(&self.changed_nanoseconds),
            "HISTORY_NO_NATIVE_FILE_IDENTITY",
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct NamespaceSnapshot {
    pub parent: FileIdentity,
    pub native: FileIdentity,
    pub lease: FileIdentity,
    pub parent_entries: Vec<String>,
    pub native_entries: Vec<String>,
    pub lease_sha256: String,
}
impl NamespaceSnapshot {
    pub(super) fn validate(&self, uid: u32) -> Result<()> {
        self.parent.validate(uid, true)?;
        self.native.validate(uid, true)?;
        self.lease.validate(uid, false)?;
        policy::id(&self.lease_sha256, 32)?;
        ensure(
            self.parent.links == 3
                && self.native.links == 2
                && self.parent_entries == [NATIVE_NAME, LEASE_NAME]
                && self.native_entries.is_empty()
                && self.lease.bytes > 0
                && self.lease.bytes <= 4096,
            "HISTORY_NO_NATIVE_COMPLETE_EMPTY_NAMESPACE",
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClosedProcess {
    pub schema: String,
    pub pins: Pins,
    pub namespace_parent: PathBuf,
    pub journal_path: PathBuf,
    pub expected_uid: u32,
    pub before: NamespaceSnapshot,
    pub after: NamespaceSnapshot,
    pub namespace_created_exclusively: bool,
    pub lease_held_from_preparation_through_reap: bool,
    pub namespace_prepared_ns: u64,
    pub signed_startup: Vec<u8>,
    pub startup_intent_at_ns: u64,
    pub intent_sha256: String,
    pub original_journal: Anchor,
    pub child_configuration_sha256: String,
    pub startup_configuration_sha256: String,
    pub process_spawn_before_ns: u64,
    pub process_reaped_after_ns: u64,
    pub owned_namespace_pid: u64,
    pub observed_visible_pid: u64,
    pub observed_starttime_ticks: u64,
    pub pidfd_identity_verified: bool,
    pub actual_wait4: bool,
    pub signal: i32,
    pub all_descendants_closed: bool,
    pub descendants: Vec<u64>,
    pub descendant_accounting_profile: String,
    pub fixture_selector: String,
    pub historical_process_tree_observed: bool,
    pub cpu_counter_profile: String,
    pub user_cpu_microseconds: u64,
    pub system_cpu_microseconds: u64,
    pub reported_user_seconds: String,
    pub reported_system_seconds: String,
    pub reported_cpu_upper_bound_ns: u64,
    pub physical_cost_qualified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Authorization {
    pub schema: String,
    pub identity: Identity,
    pub budget_id: String,
    pub reconciliation_id: String,
    pub request_nonce: u64,
    pub outside_anchor: Anchor,
    pub startup_operation_id: String,
    pub startup_intent_sha256: String,
    pub signed_startup_sha256: String,
    pub closed_process_sha256: String,
    pub namespace_parent: PathBuf,
    pub allowance: Usage,
    pub issued_ns: u64,
    pub expires_ns: u64,
}
pub(super) struct Verified {
    pub body: Authorization,
    pub closed: ClosedProcess,
    pub startup: Operation,
}
pub(super) fn message(role: u8, body: &Authorization) -> Result<Vec<u8>> {
    let raw = policy::encoded(body)?;
    ensure(
        raw.len() <= policy::MAX_ENVELOPE,
        "HISTORY_NO_NATIVE_ENVELOPE",
    )?;
    let mut message = DOMAIN.to_vec();
    message.extend([b'S', role]);
    message.extend((raw.len() as u32).to_le_bytes());
    message.extend(raw);
    Ok(message)
}
pub(super) fn authenticate(
    signed: &[u8],
    closed_raw: &[u8],
    identity: &Identity,
    at: u64,
) -> Result<Verified> {
    identity.validate()?;
    ensure(
        !signed.is_empty()
            && signed.len() <= policy::MAX_ENVELOPE
            && !closed_raw.is_empty()
            && closed_raw.len() <= policy::MAX_ENVELOPE,
        "HISTORY_NO_NATIVE_ENVELOPE",
    )?;
    let envelope: policy::Envelope<Authorization> = serde_json::from_slice(signed)?;
    for (role, key, signature) in [
        (1, &identity.registry_key, &envelope.registry_signature),
        (2, &identity.task_key, &envelope.task_signature),
    ] {
        trnm_crypto_primitives::verify_hex_strict(key, &message(role, &envelope.body)?, signature)
            .map_err(|_| "HISTORY_NO_NATIVE_SIGNATURE")?;
    }
    let body = envelope.body;
    ensure(
        body.schema == "restricted-history-startup-no-native-closure-authorization-v1"
            && body.identity == *identity
            && body.request_nonce > 0
            && body.allowance.operations == 1
            && body.allowance.cpu_ns > 0
            && body.allowance.material_bytes == 0
            && body.allowance.received_bytes == 0
            && body.namespace_parent.is_absolute()
            && body.issued_ns <= at
            && at < body.expires_ns
            && body.expires_ns - body.issued_ns <= 86_400_000_000_000,
        "HISTORY_NO_NATIVE_AUTHORIZATION",
    )?;
    for value in [
        &body.budget_id,
        &body.reconciliation_id,
        &body.startup_operation_id,
        &body.startup_intent_sha256,
        &body.signed_startup_sha256,
        &body.closed_process_sha256,
    ] {
        policy::id(value, 32)?;
    }
    body.outside_anchor.validate()?;
    ensure(
        policy::digest(closed_raw) == body.closed_process_sha256,
        "HISTORY_NO_NATIVE_CLOSED_DIGEST",
    )?;
    let closed: ClosedProcess = serde_json::from_slice(closed_raw)?;
    closed.pins.validate()?;
    closed.before.validate(closed.expected_uid)?;
    closed.after.validate(closed.expected_uid)?;
    for value in [
        &closed.intent_sha256,
        &closed.child_configuration_sha256,
        &closed.startup_configuration_sha256,
    ] {
        policy::id(value, 32)?;
    }
    let startup = policy::operation(
        &closed.signed_startup,
        identity,
        closed.startup_intent_at_ns,
    )?;
    let upper = closed
        .user_cpu_microseconds
        .checked_add(closed.system_cpu_microseconds)
        .and_then(|v| v.checked_add(2))
        .and_then(|v| v.checked_mul(1000))
        .ok_or("HISTORY_NO_NATIVE_CPU_BOUND")?;
    ensure(
        closed.schema == "actual-history-startup-no-native-closed-process-v1"
            && closed.pins.source_commit == identity.source_commit
            && closed.namespace_parent == body.namespace_parent
            && closed.journal_path.is_absolute()
            && !closed.journal_path.starts_with(&closed.namespace_parent)
            && closed.before == closed.after
            && closed.namespace_created_exclusively
            && closed.lease_held_from_preparation_through_reap
            && closed.namespace_prepared_ns > 0
            && closed.namespace_prepared_ns <= startup.body.issued_ns
            && startup.body.issued_ns <= closed.process_spawn_before_ns
            && closed.process_spawn_before_ns <= closed.startup_intent_at_ns
            && closed.startup_intent_at_ns < closed.process_reaped_after_ns
            && closed.process_reaped_after_ns <= body.issued_ns
            && closed.process_reaped_after_ns - closed.process_spawn_before_ns <= 90_000_000_000
            && startup.body.purpose == Purpose::Startup
            && startup.body.operation_id == body.startup_operation_id
            && startup.intent_sha256 == body.startup_intent_sha256
            && startup.intent_sha256 == closed.intent_sha256
            && policy::digest(&closed.signed_startup) == body.signed_startup_sha256
            && closed.original_journal == body.outside_anchor
            && closed.owned_namespace_pid > 0
            && closed.observed_visible_pid > 0
            && closed.observed_starttime_ticks > 0
            && closed.pidfd_identity_verified
            && closed.actual_wait4
            && closed.signal == 9
            && closed.all_descendants_closed
            && closed.descendants.is_empty()
            && !closed.historical_process_tree_observed
            && closed.descendant_accounting_profile
                == "source-bound-first-startup-empty-namespace-thread-only-v1"
            && closed.fixture_selector == SELECTOR
            && closed.cpu_counter_profile == "linux-wait4-timeval-quantized-v1"
            && closed.reported_cpu_upper_bound_ns == upper
            && upper <= body.allowance.cpu_ns
            && !closed.physical_cost_qualified,
        "HISTORY_NO_NATIVE_CLOSED_BINDING",
    )?;
    for (raw, units) in [
        (&closed.reported_user_seconds, closed.user_cpu_microseconds),
        (
            &closed.reported_system_seconds,
            closed.system_cpu_microseconds,
        ),
    ] {
        ensure(raw.len() <= 64, "HISTORY_NO_NATIVE_CPU_COUNTER")?;
        let value: f64 = raw.parse().map_err(|_| "HISTORY_NO_NATIVE_CPU_COUNTER")?;
        ensure(
            value.is_finite()
                && (0.0..=86_400.0).contains(&value)
                && (value * 1_000_000.0 - units as f64).abs() <= 0.001,
            "HISTORY_NO_NATIVE_CPU_COUNTER",
        )?;
    }
    Ok(Verified {
        body,
        closed,
        startup: startup.body,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    identity: Identity,
    journal_path: PathBuf,
    outside_latest_anchor: Anchor,
    expected_pins: Pins,
    namespace_parent: PathBuf,
    signed: Vec<u8>,
    closed_process: Vec<u8>,
}
pub struct ProtectedHistoryStartupNoNativeV1Input {
    config: Configuration,
    expected_uid: u32,
    _file: File,
}
impl ProtectedHistoryStartupNoNativeV1Input {
    pub fn load(path: &Path, expected_uid: u32, expected_sha256: &str) -> Result<Self> {
        let (raw, file) = policy::protected_file(path, expected_uid, expected_sha256)?;
        let config: Configuration = serde_json::from_slice(&raw)?;
        ensure(
            config.schema == "restricted-history-startup-no-native-closure-input-v1"
                && config.journal_path.is_absolute()
                && config.namespace_parent.is_absolute()
                && !config.journal_path.starts_with(&config.namespace_parent),
            "HISTORY_NO_NATIVE_CONFIGURATION",
        )?;
        config.identity.validate()?;
        config.expected_pins.validate()?;
        config.outside_latest_anchor.validate()?;
        ensure(
            config.expected_pins.source_commit == config.identity.source_commit,
            "HISTORY_NO_NATIVE_SOURCE_PIN",
        )?;
        Ok(Self {
            config,
            expected_uid,
            _file: file,
        })
    }
}

fn outside(config: &Configuration, uid: u32, verified: &Verified) -> Result<()> {
    ensure(
        verified.body.outside_anchor == config.outside_latest_anchor
            && verified.body.namespace_parent == config.namespace_parent
            && verified.closed.journal_path == config.journal_path
            && verified.closed.expected_uid == uid
            && verified.closed.pins == config.expected_pins,
        "HISTORY_NO_NATIVE_OUTSIDE_PINS",
    )
}
fn descriptor_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}
fn entries(file: &File) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for row in fs::read_dir(descriptor_path(file))? {
        ensure(names.len() < 3, "HISTORY_NO_NATIVE_NAMESPACE_NOT_EMPTY")?;
        names.push(
            row?.file_name()
                .into_string()
                .map_err(|_| "HISTORY_NO_NATIVE_NAMESPACE_NAME")?,
        );
    }
    names.sort();
    Ok(names)
}
fn visible(file: &File, name: &Path, expected: &FileIdentity) -> Result<()> {
    let held = FileIdentity::from_metadata(&file.metadata()?);
    let named = fs::symlink_metadata(name)?;
    ensure(
        !named.file_type().is_symlink()
            && held == *expected
            && FileIdentity::from_metadata(&named) == *expected,
        "HISTORY_NO_NATIVE_NAMESPACE_CHANGED",
    )
}
pub(super) struct HeldNamespace {
    parent: File,
    native: File,
    lease: File,
    path: PathBuf,
    expected: NamespaceSnapshot,
    identity_sha256: String,
    preparation_sha256: String,
    journal_path: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceLease {
    schema: String,
    namespace_parent: PathBuf,
    journal_path: PathBuf,
    identity_sha256: String,
    preparation_sha256: String,
    reservation_id: String,
}
impl HeldNamespace {
    pub(super) fn check(&self) -> Result<()> {
        visible(&self.parent, &self.path, &self.expected.parent)?;
        visible(
            &self.native,
            &descriptor_path(&self.parent).join(NATIVE_NAME),
            &self.expected.native,
        )?;
        visible(
            &self.lease,
            &descriptor_path(&self.parent).join(LEASE_NAME),
            &self.expected.lease,
        )?;
        ensure(
            entries(&self.parent)? == self.expected.parent_entries
                && entries(&self.native)?.is_empty(),
            "HISTORY_NO_NATIVE_NAMESPACE_NOT_EMPTY",
        )?;
        let mut raw = vec![0; self.expected.lease.bytes as usize];
        self.lease.read_exact_at(&mut raw, 0)?;
        ensure(
            policy::digest(&raw) == self.expected.lease_sha256,
            "HISTORY_NO_NATIVE_LEASE_CHANGED",
        )?;
        let lease: NamespaceLease = serde_json::from_slice(&raw)?;
        policy::id(&lease.reservation_id, 32)?;
        ensure(
            lease.schema == "actual-history-first-startup-namespace-lease-v1"
                && lease.namespace_parent == self.path
                && lease.journal_path == self.journal_path
                && lease.identity_sha256 == self.identity_sha256
                && lease.preparation_sha256 == self.preparation_sha256,
            "HISTORY_NO_NATIVE_LEASE_BINDING",
        )
    }
}
fn hold_namespace(config: &Configuration, uid: u32, verified: &Verified) -> Result<HeldNamespace> {
    outside(config, uid, verified)?;
    hold_bound_namespace(
        &config.namespace_parent,
        &config.journal_path,
        &config.identity,
        &config.expected_pins.preparation_sha256,
        verified.closed.before.clone(),
        uid,
    )
}

// Reuse the same descriptor, namespace and lease checks for separately signed
// lifecycle closure. The caller must authenticate its own proof and outside
// pins; this holder grants no work authority and never creates a file.
pub(super) fn hold_bound_namespace(
    namespace_parent: &Path,
    journal_path: &Path,
    identity: &Identity,
    preparation_sha256: &str,
    expected: NamespaceSnapshot,
    uid: u32,
) -> Result<HeldNamespace> {
    expected.validate(uid)?;
    let directory = |path: &Path| -> Result<File> {
        Ok(OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?)
    };
    let parent = directory(namespace_parent)?;
    visible(&parent, namespace_parent, &expected.parent)?;
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(descriptor_path(&parent).join(LEASE_NAME))?;
    visible(
        &lease,
        &descriptor_path(&parent).join(LEASE_NAME),
        &expected.lease,
    )?;
    lease.try_lock_exclusive()?;
    let native = directory(&descriptor_path(&parent).join(NATIVE_NAME))?;
    let held = HeldNamespace {
        parent,
        native,
        lease,
        path: namespace_parent.to_path_buf(),
        expected,
        identity_sha256: identity.digest()?,
        preparation_sha256: preparation_sha256.to_owned(),
        journal_path: journal_path.to_path_buf(),
    };
    held.check()?;
    Ok(held)
}

pub fn close_history_startup_no_native_v1(
    input: ProtectedHistoryStartupNoNativeV1Input,
) -> Result<Value> {
    let config = input.config;
    let verified = authenticate(
        &config.signed,
        &config.closed_process,
        &config.identity,
        policy::now()?,
    )?;
    outside(&config, input.expected_uid, &verified)?;
    let mut journal = journal::Journal::open_existing(
        &config.journal_path,
        input.expected_uid,
        &config.identity,
        &config.outside_latest_anchor,
    )?;
    journal.check_startup_no_native(&verified, policy::now()?)?;
    let held = hold_namespace(&config, input.expected_uid, &verified)?;
    let before = journal.observation();
    held.check()?;
    journal.close_startup_no_native(&config.signed, &config.closed_process)?;
    held.check()?;
    Ok(
        serde_json::json!({"schema":"restricted-history-startup-no-native-closure-result-v1",
        "before":before,"journal":journal.observation(),"closed_process":verified.closed,
        "additional_conservative_debit":verified.body.allowance,"original_cpu_receipt_preserved":true,
        "not_started_fabricated":false,"native_reset":false,"namespace_modified":false,
        "new_cpu_receipt_created":false,"new_cpu_epoch_created":false,"whole_history_p0_closed":false}),
    )
}
pub fn repair_history_startup_no_native_v1_publication(
    input: ProtectedHistoryStartupNoNativeV1Input,
    publication: ProtectedHistoryJournalPublicationV1Input,
) -> Result<Value> {
    let config = input.config;
    journal::publication::repair_with_validation(publication, |journal, frame| {
        let journal::Event::StartupNoNativeClosedV1 {
            signed,
            closed_process,
        } = &frame.event
        else {
            return Err("HISTORY_NO_NATIVE_PUBLICATION_EVENT".into());
        };
        ensure(
            frame.schema == RECORD_SCHEMA
                && signed == &config.signed
                && closed_process == &config.closed_process
                && journal.identity() == &config.identity
                && journal.path() == config.journal_path.as_path(),
            "HISTORY_NO_NATIVE_PUBLICATION_BINDING",
        )?;
        let verified = authenticate(signed, closed_process, &config.identity, frame.at_ns)?;
        outside(&config, input.expected_uid, &verified)?;
        journal.check_startup_no_native(&verified, frame.at_ns)?;
        hold_namespace(&config, input.expected_uid, &verified)
    })
}
