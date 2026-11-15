//! Explicit, finite local admission principal, independent of public-v3 r14.
//!
//! One descriptor-checked journal belongs to the original Node directory. Opening
//! never initializes or replenishes it. Reservations precede native dispatch;
//! unfinished records retain their entire execution and cleanup principal.
//! This is a trusted local owner API, not authentication of network entitlements,
//! a CPU meter, an external rollback anchor, or a physical service guarantee.
use crate::{ensure, Error, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use trnm_protocol::pon_wire::Hash;

pub const PROFILE_V1: &str = "pon-local-resource-owner-v1";
pub const JOURNAL_NAME: &str = "resource-owner-v1.journal";
const MAGIC: &[u8; 8] = b"PNRO1\0\0\0";
const FRAME_DOMAIN: &[u8] = b"pon-local-resource-owner-frame-v1\0";
const MAX_FRAME: usize = 4096;
const MAX_OPERATIONS: u32 = 1024;
const MAX_BYTES: u64 = 20 * 1024 * 1024;
const MAX_UNITS: u64 = 1 << 60;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcesV1 {
    pub cpu_ns: u64,
    pub io_bytes: u64,
}
impl ResourcesV1 {
    fn add(self, other: Self) -> Result<Self> {
        Ok(Self {
            cpu_ns: self
                .cpu_ns
                .checked_add(other.cpu_ns)
                .ok_or("RESOURCE_OWNER_OVERFLOW")?,
            io_bytes: self
                .io_bytes
                .checked_add(other.io_bytes)
                .ok_or("RESOURCE_OWNER_OVERFLOW")?,
        })
    }
    fn within(self, other: Self) -> bool {
        self.cpu_ns <= other.cpu_ns && self.io_bytes <= other.io_bytes
    }
    fn subtract(self, other: Self) -> Option<Self> {
        Some(Self {
            cpu_ns: self.cpu_ns.checked_sub(other.cpu_ns)?,
            io_bytes: self.io_bytes.checked_sub(other.io_bytes)?,
        })
    }
    fn validate(self) -> Result<()> {
        ensure(
            self.cpu_ns <= MAX_UNITS && self.io_bytes <= MAX_UNITS,
            "RESOURCE_OWNER_UNITS",
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassV1 {
    Bootstrap,
    Committed,
    Recovery,
}
impl ClassV1 {
    fn index(self) -> usize {
        match self {
            Self::Bootstrap => 0,
            Self::Committed => 1,
            Self::Recovery => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProfileV1 {
    pub owner_id: Hash,
    /// Fixed bootstrap / committed / recovery principal. No clock-based refill.
    pub grants: [ResourcesV1; 3],
    /// Terminal records also occupy their original class's replay slots.
    pub max_operations: [u32; 3],
    pub max_inflight: [u32; 3],
    /// Declared diagnostic bound, never spendable admission credit.
    pub overshoot: ResourcesV1,
}
impl ResourceProfileV1 {
    pub fn validate(&self) -> Result<()> {
        ensure(self.owner_id != [0; 32], "RESOURCE_OWNER_ID")?;
        let mut count = 0_u32;
        for i in 0..3 {
            self.grants[i].validate()?;
            ensure(
                self.grants[i].cpu_ns > 0 && self.grants[i].io_bytes > 0,
                "RESOURCE_OWNER_GRANT",
            )?;
            ensure(
                self.max_inflight[i] > 0
                    && self.max_inflight[i] <= 16
                    && self.max_operations[i] >= self.max_inflight[i],
                "RESOURCE_OWNER_SLOTS",
            )?;
            count = count
                .checked_add(self.max_operations[i])
                .ok_or("RESOURCE_OWNER_SLOTS")?;
        }
        ensure(count <= MAX_OPERATIONS, "RESOURCE_OWNER_SLOTS")?;
        self.overshoot.validate()?;
        ensure(
            self.overshoot.cpu_ns > 0,
            "RESOURCE_OWNER_OVERSHOOT_REQUIRED",
        )
    }
    pub fn id(&self) -> Result<Hash> {
        self.validate()?;
        Ok(digest(PROFILE_V1.as_bytes(), &serde_json::to_vec(self)?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationBindingV1 {
    pub operation_id: Hash,
    pub request_digest: Hash,
    pub parent_state: Hash,
    pub deadline_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequestV1 {
    pub binding: OperationBindingV1,
    pub class: ClassV1,
    pub execution: ResourcesV1,
    pub cleanup: ResourcesV1,
    /// Recovery is tied to an original unresolved operation, not a new free ID.
    pub recovery_of: Option<Hash>,
}
impl ResourceRequestV1 {
    fn total(&self) -> Result<ResourcesV1> {
        self.execution.add(self.cleanup)
    }
    fn validate(&self) -> Result<()> {
        ensure(
            self.binding.operation_id != [0; 32]
                && self.binding.request_digest != [0; 32]
                && self.binding.deadline_unix_ms > 0,
            "RESOURCE_OWNER_BINDING",
        )?;
        self.execution.validate()?;
        self.cleanup.validate()?;
        ensure(
            self.execution.cpu_ns > 0 && self.cleanup.cpu_ns > 0,
            "RESOURCE_OWNER_RESERVATION",
        )?;
        self.total()?.validate()?;
        ensure(
            (self.class == ClassV1::Recovery) == self.recovery_of.is_some(),
            "RESOURCE_OWNER_RECOVERY_LINK",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionV1 {
    pub worker_stopped: bool,
    pub effect_readback: bool,
    pub cleanup_complete: bool,
    pub receipt_digest: Hash,
}
impl CompletionV1 {
    fn validate(&self) -> Result<()> {
        ensure(
            self.worker_stopped
                && self.effect_readback
                && self.cleanup_complete
                && self.receipt_digest != [0; 32],
            "RESOURCE_OWNER_COMPLETION_REQUIRED",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "resources", rename_all = "snake_case")]
pub enum ChargeV1 {
    /// A trusted native adapter supplies a complete actual cost observation.
    Measured(ResourcesV1),
    /// Consume the complete original reservation; no unused principal is refunded.
    Conservative,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStateV1 {
    Reserved,
    Running,
    Settled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecordV1 {
    pub request: ResourceRequestV1,
    pub state: OperationStateV1,
    pub charge: Option<ChargeV1>,
    pub completion: Option<CompletionV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LaneSnapshotV1 {
    pub grant: ResourcesV1,
    pub charged: ResourcesV1,
    pub inflight_execution: ResourcesV1,
    pub inflight_cleanup: ResourcesV1,
    pub available: Option<ResourcesV1>,
    pub retained_operations: u32,
    pub unresolved_operations: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceSnapshotV1 {
    pub schema: String,
    pub profile_id: Hash,
    pub sequence: u64,
    pub record_hash: Hash,
    pub clock_floor_unix_ms: u64,
    pub lanes: [LaneSnapshotV1; 3],
    pub admission_fenced: bool,
    pub within_declared_accounting_bound: bool,
    pub physical_resource_bound_qualified: bool,
    pub honest_service_bound_qualified: bool,
}

#[derive(Clone, Debug)]
pub struct ResourceOwnerV1 {
    root: PathBuf,
    device: u64,
    inode: u64,
    profile: ResourceProfileV1,
}

pub enum AdmissionV1 {
    Fresh(ResourceReservationV1),
    /// Original status only. This is never a permission to dispatch again.
    Existing(OperationRecordV1),
}

/// Dropping this object performs no refund or clean-settlement write. The durable
/// outstanding reservation remains authoritative after unwinding/process loss.
pub struct ResourceReservationV1 {
    owner: ResourceOwnerV1,
    request: ResourceRequestV1,
    native_claimed: bool,
}
impl ResourceReservationV1 {
    pub fn request(&self) -> &ResourceRequestV1 {
        &self.request
    }
    pub fn claim(&mut self, now_unix_ms: u64) -> Result<()> {
        self.owner.claim(&self.request, now_unix_ms)?;
        self.native_claimed = true;
        Ok(())
    }
    pub fn profile_id(&self) -> Result<Hash> {
        self.owner.profile.id()
    }
    pub(crate) fn validate_running(&self, node: &Path, now_unix_ms: u64) -> Result<()> {
        ensure(
            self.native_claimed && node.canonicalize()? == self.owner.root,
            "RESOURCE_OWNER_NATIVE_CLAIM_REQUIRED",
        )?;
        ensure(
            now_unix_ms < self.request.binding.deadline_unix_ms,
            "RESOURCE_OWNER_DEADLINE",
        )?;
        let record = self
            .owner
            .observe(self.request.binding.operation_id)?
            .ok_or("RESOURCE_OWNER_OPERATION")?;
        ensure(
            record.request == self.request && record.state == OperationStateV1::Running,
            "RESOURCE_OWNER_NATIVE_CLAIM_REQUIRED",
        )
    }
    pub fn finish(self, completion: CompletionV1, charge: ChargeV1) -> Result<OperationRecordV1> {
        self.owner.settle(&self.request, completion, charge)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Event {
    Header {
        profile: ResourceProfileV1,
        device: u64,
        inode: u64,
    },
    Reserve {
        request: ResourceRequestV1,
        at_unix_ms: u64,
    },
    Claim {
        operation_id: Hash,
        at_unix_ms: u64,
    },
    Settle {
        operation_id: Hash,
        completion: CompletionV1,
        charge: ChargeV1,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    sequence: u64,
    previous: Hash,
    event: Event,
}

struct State {
    profile: ResourceProfileV1,
    device: u64,
    inode: u64,
    sequence: u64,
    hash: Hash,
    clock_floor: u64,
    operations: BTreeMap<Hash, OperationRecordV1>,
}
impl State {
    fn snapshot(&self) -> Result<ResourceSnapshotV1> {
        let mut lanes = std::array::from_fn(|i| LaneSnapshotV1 {
            grant: self.profile.grants[i],
            charged: ResourcesV1::default(),
            inflight_execution: ResourcesV1::default(),
            inflight_cleanup: ResourcesV1::default(),
            available: None,
            retained_operations: 0,
            unresolved_operations: 0,
        });
        let mut fenced = false;
        for record in self.operations.values() {
            let lane = &mut lanes[record.request.class.index()];
            lane.retained_operations += 1;
            if record.state == OperationStateV1::Settled {
                let used = match record.charge.as_ref().ok_or("RESOURCE_OWNER_JOURNAL")? {
                    ChargeV1::Measured(used) => *used,
                    ChargeV1::Conservative => record.request.total()?,
                };
                lane.charged = lane.charged.add(used)?;
                // Overshoot is retained as debt and fences new work; it never
                // becomes fresh positive credit or disappears on restart.
                fenced |= !used.within(record.request.total()?);
            } else {
                lane.unresolved_operations += 1;
                lane.inflight_execution = lane.inflight_execution.add(record.request.execution)?;
                lane.inflight_cleanup = lane.inflight_cleanup.add(record.request.cleanup)?;
            }
        }
        let mut total = ResourcesV1::default();
        let mut grant = ResourcesV1::default();
        for lane in &mut lanes {
            let committed = lane
                .charged
                .add(lane.inflight_execution)?
                .add(lane.inflight_cleanup)?;
            lane.available = lane.grant.subtract(committed);
            total = total.add(committed)?;
            grant = grant.add(lane.grant)?;
            fenced |= lane.available.is_none();
        }
        Ok(ResourceSnapshotV1 {
            schema: PROFILE_V1.to_owned(),
            profile_id: self.profile.id()?,
            sequence: self.sequence,
            record_hash: self.hash,
            lanes,
            clock_floor_unix_ms: self.clock_floor,
            admission_fenced: fenced,
            within_declared_accounting_bound: total.within(grant.add(self.profile.overshoot)?),
            physical_resource_bound_qualified: false,
            honest_service_bound_qualified: false,
        })
    }
    fn reserve(&mut self, request: &ResourceRequestV1) -> Result<()> {
        request.validate()?;
        ensure(
            !self.operations.contains_key(&request.binding.operation_id),
            "RESOURCE_OWNER_DUPLICATE",
        )?;
        if let Some(original) = request.recovery_of {
            let original = self
                .operations
                .get(&original)
                .ok_or("RESOURCE_OWNER_RECOVERY_LINK")?;
            ensure(
                original.state != OperationStateV1::Settled,
                "RESOURCE_OWNER_RECOVERY_LINK",
            )?;
        }
        let snapshot = self.snapshot()?;
        ensure(!snapshot.admission_fenced, "RESOURCE_OWNER_FENCED")?;
        let i = request.class.index();
        let lane = &snapshot.lanes[i];
        ensure(
            lane.retained_operations < self.profile.max_operations[i],
            "RESOURCE_OWNER_RECORD_LIMIT",
        )?;
        ensure(
            lane.unresolved_operations < self.profile.max_inflight[i],
            "RESOURCE_OWNER_INFLIGHT_LIMIT",
        )?;
        ensure(
            request
                .total()?
                .within(lane.available.ok_or("RESOURCE_OWNER_BUDGET")?),
            "RESOURCE_OWNER_BUDGET",
        )?;
        self.operations.insert(
            request.binding.operation_id,
            OperationRecordV1 {
                request: request.clone(),
                state: OperationStateV1::Reserved,
                charge: None,
                completion: None,
            },
        );
        Ok(())
    }
    fn apply(&mut self, event: &Event) -> Result<()> {
        match event {
            Event::Header { .. } => Err("RESOURCE_OWNER_DUPLICATE_HEADER".into()),
            Event::Reserve {
                request,
                at_unix_ms,
            } => {
                ensure(
                    *at_unix_ms >= self.clock_floor,
                    "RESOURCE_OWNER_CLOCK_ROLLBACK",
                )?;
                ensure(
                    *at_unix_ms < request.binding.deadline_unix_ms,
                    "RESOURCE_OWNER_DEADLINE",
                )?;
                self.reserve(request)?;
                self.clock_floor = *at_unix_ms;
                Ok(())
            }
            Event::Claim {
                operation_id,
                at_unix_ms,
            } => {
                ensure(
                    *at_unix_ms >= self.clock_floor,
                    "RESOURCE_OWNER_CLOCK_ROLLBACK",
                )?;
                let record = self
                    .operations
                    .get_mut(operation_id)
                    .ok_or("RESOURCE_OWNER_OPERATION")?;
                ensure(
                    record.state == OperationStateV1::Reserved,
                    "RESOURCE_OWNER_ALREADY_CLAIMED",
                )?;
                ensure(
                    *at_unix_ms < record.request.binding.deadline_unix_ms,
                    "RESOURCE_OWNER_DEADLINE",
                )?;
                record.state = OperationStateV1::Running;
                self.clock_floor = *at_unix_ms;
                Ok(())
            }
            Event::Settle {
                operation_id,
                completion,
                charge,
            } => {
                completion.validate()?;
                let record = self
                    .operations
                    .get_mut(operation_id)
                    .ok_or("RESOURCE_OWNER_OPERATION")?;
                // Reconciliation before dispatch is permitted only with full
                // conservative charging. No cost is inferred from absent work.
                ensure(
                    record.state == OperationStateV1::Running
                        || (record.state == OperationStateV1::Reserved
                            && *charge == ChargeV1::Conservative),
                    "RESOURCE_OWNER_SETTLEMENT_STATE",
                )?;
                if let ChargeV1::Measured(used) = charge {
                    used.validate()?;
                }
                record.state = OperationStateV1::Settled;
                record.charge = Some(charge.clone());
                record.completion = Some(completion.clone());
                self.snapshot()?;
                Ok(())
            }
        }
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
fn root_metadata(path: &Path) -> Result<(PathBuf, fs::Metadata)> {
    let root = path.canonicalize()?;
    let metadata = fs::symlink_metadata(&root)?;
    ensure(
        metadata.is_dir()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o022 == 0,
        "RESOURCE_OWNER_DIRECTORY",
    )?;
    let native = fs::symlink_metadata(root.join("native.sqlite"))?;
    ensure(
        native.is_file()
            && !native.file_type().is_symlink()
            && native.nlink() == 1
            && native.uid() == metadata.uid(),
        "RESOURCE_OWNER_EXISTING_NODE",
    )?;
    Ok((root, metadata))
}
fn same_file(file: &File, path: &Path) -> Result<()> {
    let opened = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure(
        opened.is_file()
            && named.is_file()
            && !named.file_type().is_symlink()
            && opened.dev() == named.dev()
            && opened.ino() == named.ino()
            && opened.nlink() == 1
            && opened.uid() == rustix::process::geteuid().as_raw()
            && opened.mode() & 0o077 == 0,
        "RESOURCE_OWNER_FILE_IDENTITY",
    )
}
fn read_state(file: &mut File) -> Result<State> {
    ensure(
        (8..=MAX_BYTES).contains(&file.metadata()?.len()),
        "RESOURCE_OWNER_JOURNAL_SIZE",
    )?;
    file.seek(SeekFrom::Start(0))?;
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    ensure(&magic == MAGIC, "RESOURCE_OWNER_JOURNAL_MAGIC")?;
    let mut sequence = 0_u64;
    let mut previous = [0; 32];
    let mut state: Option<State> = None;
    while file.stream_position()? < file.metadata()?.len() {
        ensure(
            sequence <= 3 * u64::from(MAX_OPERATIONS),
            "RESOURCE_OWNER_FRAME_LIMIT",
        )?;
        let mut size = [0; 4];
        file.read_exact(&mut size)
            .map_err(|_| Error::from("RESOURCE_OWNER_TORN_TAIL"))?;
        let size = u32::from_le_bytes(size) as usize;
        ensure((1..=MAX_FRAME).contains(&size), "RESOURCE_OWNER_FRAME_SIZE")?;
        let mut bytes = vec![0; size];
        file.read_exact(&mut bytes)
            .map_err(|_| Error::from("RESOURCE_OWNER_TORN_TAIL"))?;
        let mut observed = [0; 32];
        file.read_exact(&mut observed)
            .map_err(|_| Error::from("RESOURCE_OWNER_TORN_TAIL"))?;
        ensure(
            observed == digest(FRAME_DOMAIN, &bytes),
            "RESOURCE_OWNER_FRAME_HASH",
        )?;
        let frame: Frame = serde_json::from_slice(&bytes)?;
        ensure(
            frame.sequence == sequence && frame.previous == previous,
            "RESOURCE_OWNER_FRAME_CHAIN",
        )?;
        ensure(
            serde_json::to_vec(&frame)? == bytes,
            "RESOURCE_OWNER_FRAME_CANONICAL",
        )?;
        if let Some(state) = &mut state {
            state.apply(&frame.event)?;
        } else if let Event::Header {
            profile,
            device,
            inode,
        } = frame.event
        {
            profile.validate()?;
            state = Some(State {
                profile,
                device,
                inode,
                sequence: 0,
                hash: [0; 32],
                clock_floor: 0,
                operations: BTreeMap::new(),
            });
        } else {
            return Err("RESOURCE_OWNER_HEADER_REQUIRED".into());
        }
        previous = observed;
        sequence += 1;
    }
    let mut state = state.ok_or("RESOURCE_OWNER_HEADER_REQUIRED")?;
    state.sequence = sequence;
    state.hash = previous;
    Ok(state)
}
fn append(file: &mut File, sequence: u64, previous: Hash, event: Event) -> Result<Hash> {
    let bytes = serde_json::to_vec(&Frame {
        sequence,
        previous,
        event,
    })?;
    ensure(bytes.len() <= MAX_FRAME, "RESOURCE_OWNER_FRAME_SIZE")?;
    let size = file.seek(SeekFrom::End(0))?;
    ensure(
        size.checked_add(bytes.len() as u64 + 36)
            .is_some_and(|n| n <= MAX_BYTES),
        "RESOURCE_OWNER_JOURNAL_SIZE",
    )?;
    let hash = digest(FRAME_DOMAIN, &bytes);
    // No rollback on partial write: a torn suffix refuses all subsequent opens.
    file.write_all(&(bytes.len() as u32).to_le_bytes())?;
    file.write_all(&bytes)?;
    file.write_all(&hash)?;
    file.sync_all()?;
    Ok(hash)
}

impl ResourceOwnerV1 {
    /// Explicit local provisioning only. Existing, partial or unknown files are
    /// refused; no request path calls this method and no implicit reset exists.
    pub fn initialize(node: &Path, profile: &ResourceProfileV1) -> Result<Self> {
        profile.validate()?;
        let (root, metadata) = root_metadata(node)?;
        // Adoption shares the native lifetime lock. An already-open Node or a
        // cold snapshot cannot race a silent change of its admission profile.
        let lock_path = root.join("owner.lock");
        let native_lock = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&lock_path)?;
        native_lock
            .try_lock_exclusive()
            .map_err(|_| Error::from("RESOURCE_OWNER_NODE_BUSY"))?;
        let opened_lock = native_lock.metadata()?;
        let named_lock = fs::symlink_metadata(&lock_path)?;
        ensure(
            opened_lock.is_file()
                && !named_lock.file_type().is_symlink()
                && opened_lock.nlink() == 1
                && opened_lock.uid() == metadata.uid()
                && opened_lock.dev() == named_lock.dev()
                && opened_lock.ino() == named_lock.ino(),
            "RESOURCE_OWNER_NODE_LOCK",
        )?;
        let path = root.join(JOURNAL_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)?;
        file.try_lock_exclusive()
            .map_err(|_| Error::from("RESOURCE_OWNER_BUSY"))?;
        same_file(&file, &path)?;
        file.write_all(MAGIC)?;
        append(
            &mut file,
            0,
            [0; 32],
            Event::Header {
                profile: profile.clone(),
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        )?;
        same_file(&file, &path)?;
        File::open(&root)?.sync_all()?;
        drop(file);
        let owner = Self::open(&root, profile.id()?)?;
        drop(native_lock);
        Ok(owner)
    }
    pub fn is_present(node: &Path) -> Result<bool> {
        match fs::symlink_metadata(node.join(JOURNAL_NAME)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    pub fn open(node: &Path, expected_profile: Hash) -> Result<Self> {
        let (root, metadata) = root_metadata(node)?;
        let path = root.join(JOURNAL_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)?;
        file.try_lock_exclusive()
            .map_err(|_| Error::from("RESOURCE_OWNER_BUSY"))?;
        same_file(&file, &path)?;
        let state = read_state(&mut file)?;
        ensure(
            state.device == metadata.dev() && state.inode == metadata.ino(),
            "RESOURCE_OWNER_NODE_IDENTITY",
        )?;
        ensure(
            state.profile.id()? == expected_profile,
            "RESOURCE_OWNER_PROFILE",
        )?;
        same_file(&file, &path)?;
        Ok(Self {
            root,
            device: metadata.dev(),
            inode: metadata.ino(),
            profile: state.profile,
        })
    }
    pub fn profile(&self) -> &ResourceProfileV1 {
        &self.profile
    }
    pub fn node_path(&self) -> &Path {
        &self.root
    }
    fn locked(&self) -> Result<(File, State)> {
        let (root, metadata) = root_metadata(&self.root)?;
        ensure(
            root == self.root && metadata.dev() == self.device && metadata.ino() == self.inode,
            "RESOURCE_OWNER_NODE_IDENTITY",
        )?;
        let path = self.root.join(JOURNAL_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)?;
        file.try_lock_exclusive()
            .map_err(|_| Error::from("RESOURCE_OWNER_BUSY"))?;
        same_file(&file, &path)?;
        let state = read_state(&mut file)?;
        ensure(
            state.profile == self.profile
                && state.device == self.device
                && state.inode == self.inode,
            "RESOURCE_OWNER_PROFILE",
        )?;
        Ok((file, state))
    }
    fn persist(&self, file: &mut File, state: &mut State, event: Event) -> Result<()> {
        state.apply(&event)?;
        same_file(file, &self.root.join(JOURNAL_NAME))?;
        state.hash = append(file, state.sequence, state.hash, event)?;
        state.sequence += 1;
        same_file(file, &self.root.join(JOURNAL_NAME))?;
        Ok(())
    }
    pub fn snapshot(&self) -> Result<ResourceSnapshotV1> {
        self.locked()?.1.snapshot()
    }
    pub fn observe(&self, operation_id: Hash) -> Result<Option<OperationRecordV1>> {
        Ok(self.locked()?.1.operations.get(&operation_id).cloned())
    }
    pub fn reserve(&self, request: &ResourceRequestV1, now_unix_ms: u64) -> Result<AdmissionV1> {
        request.validate()?;
        let (mut file, mut state) = self.locked()?;
        if let Some(prior) = state.operations.get(&request.binding.operation_id) {
            ensure(prior.request == *request, "RESOURCE_OWNER_BINDING_CONFLICT")?;
            return Ok(AdmissionV1::Existing(prior.clone()));
        }
        ensure(
            now_unix_ms < request.binding.deadline_unix_ms,
            "RESOURCE_OWNER_DEADLINE",
        )?;
        self.persist(
            &mut file,
            &mut state,
            Event::Reserve {
                request: request.clone(),
                at_unix_ms: now_unix_ms,
            },
        )?;
        Ok(AdmissionV1::Fresh(ResourceReservationV1 {
            owner: self.clone(),
            request: request.clone(),
            native_claimed: false,
        }))
    }
    fn claim(&self, request: &ResourceRequestV1, now_unix_ms: u64) -> Result<()> {
        let (mut file, mut state) = self.locked()?;
        let prior = state
            .operations
            .get(&request.binding.operation_id)
            .ok_or("RESOURCE_OWNER_OPERATION")?;
        ensure(prior.request == *request, "RESOURCE_OWNER_BINDING_CONFLICT")?;
        ensure(
            now_unix_ms < request.binding.deadline_unix_ms,
            "RESOURCE_OWNER_DEADLINE",
        )?;
        ensure(!state.snapshot()?.admission_fenced, "RESOURCE_OWNER_FENCED")?;
        self.persist(
            &mut file,
            &mut state,
            Event::Claim {
                operation_id: request.binding.operation_id,
                at_unix_ms: now_unix_ms,
            },
        )
    }
    /// Used by a distinct native worker after the supervisor has durably reserved.
    /// Exactly one process can claim the original tuple. Re-entry is refused.
    pub fn claim_existing(
        &self,
        request: &ResourceRequestV1,
        now_unix_ms: u64,
    ) -> Result<ResourceReservationV1> {
        self.claim(request, now_unix_ms)?;
        Ok(ResourceReservationV1 {
            owner: self.clone(),
            request: request.clone(),
            native_claimed: true,
        })
    }
    fn settle(
        &self,
        request: &ResourceRequestV1,
        completion: CompletionV1,
        charge: ChargeV1,
    ) -> Result<OperationRecordV1> {
        completion.validate()?;
        let (mut file, mut state) = self.locked()?;
        let prior = state
            .operations
            .get(&request.binding.operation_id)
            .ok_or("RESOURCE_OWNER_OPERATION")?;
        ensure(prior.request == *request, "RESOURCE_OWNER_BINDING_CONFLICT")?;
        if prior.state == OperationStateV1::Settled {
            ensure(
                prior.completion.as_ref() == Some(&completion)
                    && prior.charge.as_ref() == Some(&charge),
                "RESOURCE_OWNER_SETTLEMENT_CONFLICT",
            )?;
            return Ok(prior.clone());
        }
        self.persist(
            &mut file,
            &mut state,
            Event::Settle {
                operation_id: request.binding.operation_id,
                completion,
                charge,
            },
        )?;
        Ok(state
            .operations
            .get(&request.binding.operation_id)
            .ok_or("RESOURCE_OWNER_OPERATION")?
            .clone())
    }
    /// Trusted local recovery after independently establishing stop/readback/
    /// cleanup. Unknown original cost consumes the FULL original reservation.
    pub fn reconcile_conservatively(
        &self,
        request: &ResourceRequestV1,
        completion: CompletionV1,
    ) -> Result<OperationRecordV1> {
        self.settle(request, completion, ChargeV1::Conservative)
    }
}

#[cfg(test)]
#[path = "resource_owner_v1_tests.rs"]
mod tests;
