//! CPS1: an immutable periodic full-version policy over the TCA3 owner.
//!
//! The policy is persisted and independently pinned; the cursor is reconstructed
//! from the complete TCA3 history, including retired duties. No second effect
//! ledger, free renewal, background thread or wall-clock lease extension exists.
//! TCA3 always retains a complete materialized TCV1 dependency set: a snapshot
//! never records a TCX1 recipe in place of its target bytes. The existing funded
//! owner performs original member copies; recovery here is target-only.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use sha2::{Digest, Sha256};

use super::{
    require, CellDigestV1, CellErrorV1, CellResultV1, CellVersionCatalogAnchorV3,
    CellVersionRetentionContractV3, CellVersionRetentionDutyV3, CellVersionRetentionReadbackV3,
    CellVersionRetentionStateV3, CellVersionRetentionStoreV3, CellVersionSnapshotLinkV3,
};

pub const CELL_PERIODIC_SNAPSHOT_POLICY_BYTES_V1: usize = 152;
pub const MAX_CELL_PERIODIC_SNAPSHOTS_V1: u32 = 127;
const POLICY_FILE: &str = "policy.cps1";

/// Finite cadence and original full-version anchor. Owner IDs are declarations;
/// an execution/funding owner must independently authenticate the policy pin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellPeriodicSnapshotPolicyV1 {
    pub responsible_owner: CellDigestV1,
    pub store_id: CellDigestV1,
    pub initial_operation: CellDigestV1,
    pub initial_contract: CellDigestV1,
    pub first_due_height: u64,
    pub interval_heights: u64,
    pub maximum_snapshots: u32,
}

impl CellPeriodicSnapshotPolicyV1 {
    pub fn validate(&self) -> CellResultV1<()> {
        require(
            [
                self.responsible_owner,
                self.store_id,
                self.initial_operation,
                self.initial_contract,
            ]
            .iter()
            .all(|value| *value != [0; 32]),
            "periodic snapshot identity",
        )?;
        require(
            self.first_due_height > 0
                && self.interval_heights > 0
                && (1..=MAX_CELL_PERIODIC_SNAPSHOTS_V1).contains(&self.maximum_snapshots),
            "periodic snapshot finite cadence",
        )?;
        self.due_height(self.maximum_snapshots)?;
        Ok(())
    }

    fn due_height(&self, ordinal: u32) -> CellResultV1<u64> {
        require(
            ordinal > 0 && ordinal <= self.maximum_snapshots,
            "periodic snapshot ordinal",
        )?;
        let height = self
            .interval_heights
            .checked_mul(u64::from(ordinal - 1))
            .and_then(|offset| self.first_due_height.checked_add(offset))
            .ok_or(CellErrorV1::Invalid("periodic snapshot cadence overflow"))?;
        require(
            height <= i64::MAX as u64,
            "periodic snapshot cadence overflow",
        )?;
        Ok(height)
    }

    pub fn encode(&self) -> CellResultV1<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(CELL_PERIODIC_SNAPSHOT_POLICY_BYTES_V1);
        bytes.extend(b"CPS1");
        bytes.extend(self.responsible_owner);
        bytes.extend(self.store_id);
        bytes.extend(self.initial_operation);
        bytes.extend(self.initial_contract);
        bytes.extend(self.first_due_height.to_be_bytes());
        bytes.extend(self.interval_heights.to_be_bytes());
        bytes.extend(self.maximum_snapshots.to_be_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            bytes.len() == CELL_PERIODIC_SNAPSHOT_POLICY_BYTES_V1 && &bytes[..4] == b"CPS1",
            "periodic snapshot policy namespace/length",
        )?;
        let array = |start: usize| -> CellDigestV1 {
            bytes[start..start + 32]
                .try_into()
                .expect("fixed policy length")
        };
        let result = Self {
            responsible_owner: array(4),
            store_id: array(36),
            initial_operation: array(68),
            initial_contract: array(100),
            first_due_height: u64::from_be_bytes(
                bytes[132..140].try_into().expect("fixed policy length"),
            ),
            interval_heights: u64::from_be_bytes(
                bytes[140..148].try_into().expect("fixed policy length"),
            ),
            maximum_snapshots: u32::from_be_bytes(
                bytes[148..152].try_into().expect("fixed policy length"),
            ),
        };
        result.validate()?;
        Ok(result)
    }

    pub fn commitment(&self) -> CellResultV1<CellDigestV1> {
        let mut digest = Sha256::new();
        digest.update(b"trnm.cell-periodic-snapshot-policy.v1\0");
        digest.update(self.encode()?);
        Ok(digest.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellPeriodicSnapshotDueV1 {
    pub ordinal: u32,
    pub due_height: u64,
    /// A late tick retains the original due height. This is not an on-time ACK.
    pub late_by_heights: u64,
    pub predecessor_operation: CellDigestV1,
    pub predecessor_contract: CellDigestV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CellPeriodicSnapshotProgressV1 {
    NotDue(CellPeriodicSnapshotDueV1),
    Due(CellPeriodicSnapshotDueV1),
    Pending {
        original_operation: CellDigestV1,
        due: CellPeriodicSnapshotDueV1,
    },
    Complete {
        snapshots: u32,
        last_operation: CellDigestV1,
    },
}

/// Reopenable finite scheduler. The complete immutable policy is on disk; all
/// progress is in the original TCA3 contract/event history. An inventory result
/// alone grants neither current custody, serving authority nor FinalUse.
pub struct CellPeriodicSnapshotOwnerV1 {
    directory: PathBuf,
    policy: CellPeriodicSnapshotPolicyV1,
    commitment: CellDigestV1,
}

fn checkpoint(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() < deadline, "periodic snapshot deadline")
}

fn check_directory(path: &Path) -> CellResultV1<()> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "periodic snapshot directory",
    )
}

fn read_policy(directory: &Path, deadline: Instant) -> CellResultV1<CellPeriodicSnapshotPolicyV1> {
    checkpoint(deadline)?;
    check_directory(directory)?;
    let path = directory.join(POLICY_FILE);
    let metadata = fs::symlink_metadata(&path)?;
    require(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() == CELL_PERIODIC_SNAPSHOT_POLICY_BYTES_V1 as u64,
        "periodic snapshot policy file",
    )?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(&path)?;
    let before = file.metadata()?;
    require(
        before.is_file() && before.len() == CELL_PERIODIC_SNAPSHOT_POLICY_BYTES_V1 as u64,
        "periodic snapshot policy file",
    )?;
    let mut bytes = Vec::with_capacity(CELL_PERIODIC_SNAPSHOT_POLICY_BYTES_V1 + 1);
    (&file)
        .take((CELL_PERIODIC_SNAPSHOT_POLICY_BYTES_V1 + 1) as u64)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let current = fs::symlink_metadata(&path)?;
    require(
        after.len() == before.len(),
        "periodic snapshot policy changed",
    )?;
    require(
        current.is_file() && !current.file_type().is_symlink() && current.len() == before.len(),
        "periodic snapshot policy changed",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            before.dev() == metadata.dev()
                && before.ino() == metadata.ino()
                && after.dev() == current.dev()
                && after.ino() == current.ino()
                && before.nlink() == 1
                && after.nlink() == 1
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec(),
            "periodic snapshot policy changed",
        )?;
    }
    check_directory(directory)?;
    checkpoint(deadline)?;
    CellPeriodicSnapshotPolicyV1::decode(&bytes)
}

impl CellPeriodicSnapshotOwnerV1 {
    pub fn create(
        directory: &Path,
        policy: CellPeriodicSnapshotPolicyV1,
        deadline: Instant,
    ) -> CellResultV1<Self> {
        checkpoint(deadline)?;
        let bytes = policy.encode()?;
        let commitment = policy.commitment()?;
        let mut directory_options = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory_options.mode(0o700);
        }
        directory_options.create(directory)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options.open(directory.join(POLICY_FILE))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            File::open(directory)?.sync_all()?;
            let parent = directory
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            File::open(parent)?.sync_all()?;
        }
        // A failure after fsync retains the original file for pinned reopening.
        checkpoint(deadline)?;
        Self::open(directory, commitment, deadline)
    }

    pub fn open(directory: &Path, expected: CellDigestV1, deadline: Instant) -> CellResultV1<Self> {
        let policy = read_policy(directory, deadline)?;
        require(
            expected != [0; 32] && policy.commitment()? == expected,
            "periodic snapshot independent policy pin",
        )?;
        Ok(Self {
            directory: directory.to_path_buf(),
            policy,
            commitment: expected,
        })
    }

    pub fn policy(&self) -> &CellPeriodicSnapshotPolicyV1 {
        &self.policy
    }
    pub fn commitment(&self) -> CellDigestV1 {
        self.commitment
    }

    fn check_policy(&self, deadline: Instant) -> CellResultV1<()> {
        let actual = read_policy(&self.directory, deadline)?;
        require(
            actual == self.policy && actual.commitment()? == self.commitment,
            "periodic snapshot stored policy changed",
        )
    }

    fn require_scope(
        &self,
        contract: &CellVersionRetentionContractV3,
        initial: &CellVersionRetentionContractV3,
    ) -> CellResultV1<()> {
        let expected = &initial.model.context;
        let actual = &contract.model.context;
        require(
            contract.responsible_owner == self.policy.responsible_owner
                && actual.family == expected.family
                && actual.base == expected.base
                && actual.tokenizer == expected.tokenizer
                && actual.layout == expected.layout,
            "periodic snapshot original owner/model scope",
        )
    }

    fn due(
        &self,
        ordinal: u32,
        height: u64,
        previous: &CellVersionRetentionDutyV3,
        store: &CellVersionRetentionStoreV3,
    ) -> CellResultV1<CellPeriodicSnapshotDueV1> {
        let due_height = self.policy.due_height(ordinal)?;
        Ok(CellPeriodicSnapshotDueV1 {
            ordinal,
            due_height,
            late_by_heights: height.saturating_sub(due_height),
            predecessor_operation: previous.contract.operation,
            predecessor_contract: store.contract_commitment(&previous.contract)?,
        })
    }

    fn require_coverage(
        &self,
        contract: &CellVersionRetentionContractV3,
        due: CellPeriodicSnapshotDueV1,
    ) -> CellResultV1<()> {
        require(
            contract.retain_from_height <= due.due_height
                && due.due_height < contract.retain_until_height,
            "periodic snapshot original lease",
        )?;
        if due.ordinal < self.policy.maximum_snapshots {
            require(
                self.policy.due_height(due.ordinal + 1)? < contract.retain_until_height,
                "periodic snapshot next coverage",
            )?;
        }
        Ok(())
    }

    pub fn progress(
        &self,
        store: &CellVersionRetentionStoreV3,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<CellPeriodicSnapshotProgressV1> {
        self.check_policy(deadline)?;
        require(
            store.store_id() == self.policy.store_id,
            "periodic snapshot original store",
        )?;
        let duties = store.audited_duties(deadline)?;
        let initial = duties
            .iter()
            .find(|duty| duty.contract.operation == self.policy.initial_operation)
            .ok_or(CellErrorV1::Invalid(
                "periodic snapshot initial duty missing",
            ))?;
        require(
            initial.state != CellVersionRetentionStateV3::Pending
                && store.contract_commitment(&initial.contract)? == self.policy.initial_contract
                && initial.contract.responsible_owner == self.policy.responsible_owner,
            "periodic snapshot initial complete duty",
        )?;
        require(
            initial.contract.retain_from_height <= self.policy.first_due_height
                && self.policy.first_due_height < initial.contract.retain_until_height,
            "periodic snapshot initial coverage",
        )?;
        let mut snapshots: Vec<_> = duties
            .iter()
            .filter(|duty| {
                duty.contract
                    .snapshot
                    .as_ref()
                    .is_some_and(|link| link.schedule == self.commitment)
            })
            .collect();
        snapshots.sort_by_key(|duty| {
            duty.contract
                .snapshot
                .as_ref()
                .expect("selected link")
                .ordinal
        });
        require(
            snapshots.len() <= self.policy.maximum_snapshots as usize,
            "periodic snapshot finite history",
        )?;
        let mut previous = initial;
        for (index, duty) in snapshots.iter().enumerate() {
            checkpoint(deadline)?;
            let link = duty.contract.snapshot.as_ref().expect("selected link");
            let due = self.due(index as u32 + 1, current_height, previous, store)?;
            require(
                link.ordinal == u64::from(due.ordinal)
                    && link.due_height == due.due_height
                    && link.predecessor_operation == due.predecessor_operation
                    && link.predecessor_contract == due.predecessor_contract,
                "periodic snapshot original sequence",
            )?;
            self.require_scope(&duty.contract, &initial.contract)?;
            // TCA3 also admits independently funded contracts directly. Its
            // history must satisfy this pinned policy before becoming our
            // cursor or a target-only recovery candidate.
            self.require_coverage(&duty.contract, due)?;
            require(
                previous.contract.retain_until_height > due.due_height,
                "periodic snapshot predecessor coverage",
            )?;
            if duty.state == CellVersionRetentionStateV3::Pending {
                require(
                    index + 1 == snapshots.len(),
                    "periodic snapshot pending cursor",
                )?;
                self.check_policy(deadline)?;
                return Ok(CellPeriodicSnapshotProgressV1::Pending {
                    original_operation: duty.contract.operation,
                    due,
                });
            }
            previous = duty;
        }
        self.check_policy(deadline)?;
        if snapshots.len() == self.policy.maximum_snapshots as usize {
            return Ok(CellPeriodicSnapshotProgressV1::Complete {
                snapshots: self.policy.maximum_snapshots,
                last_operation: previous.contract.operation,
            });
        }
        let due = self.due(snapshots.len() as u32 + 1, current_height, previous, store)?;
        Ok(if current_height < due.due_height {
            CellPeriodicSnapshotProgressV1::NotDue(due)
        } else {
            CellPeriodicSnapshotProgressV1::Due(due)
        })
    }

    /// Persist a complete snapshot intent at the original due height. This
    /// reserves no payment and copies no source bytes. Only the existing native
    /// funding owner may dispatch new member effects; its Pending/Done retries
    /// retain the original target-only reconciliation path.
    pub fn reserve_due(
        &self,
        store: &mut CellVersionRetentionStoreV3,
        contract: CellVersionRetentionContractV3,
        expected: CellVersionCatalogAnchorV3,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<CellVersionRetentionReadbackV3> {
        let due = match self.progress(store, current_height, deadline)? {
            CellPeriodicSnapshotProgressV1::Due(due) => due,
            CellPeriodicSnapshotProgressV1::Pending {
                original_operation,
                due,
            } => {
                require(
                    original_operation == contract.operation
                        && store.contract(original_operation, deadline)? == contract,
                    "periodic snapshot original pending operation",
                )?;
                due
            }
            _ => return Err(CellErrorV1::Invalid("periodic snapshot not due")),
        };
        let initial = store.contract(self.policy.initial_operation, deadline)?;
        self.require_scope(&contract, &initial)?;
        require(
            contract.snapshot.as_ref()
                == Some(&CellVersionSnapshotLinkV3 {
                    schedule: self.commitment,
                    ordinal: u64::from(due.ordinal),
                    due_height: due.due_height,
                    predecessor_operation: due.predecessor_operation,
                    predecessor_contract: due.predecessor_contract,
                }),
            "periodic snapshot exact obligation",
        )?;
        self.require_coverage(&contract, due)?;
        require(
            current_height < contract.retain_until_height,
            "periodic snapshot original lease",
        )?;
        let previous = store.contract(due.predecessor_operation, deadline)?;
        require(
            previous.retain_until_height > due.due_height,
            "periodic snapshot predecessor coverage",
        )?;
        let result = store.reserve_version(contract, expected, deadline)?;
        self.check_policy(deadline)?;
        Ok(result)
    }

    /// Resume the one original Pending snapshot from actual retained targets.
    /// There is deliberately no cache, peer, replacement operation or new lease
    /// argument. Missing model/environment bytes leave the same duty Pending.
    pub fn reconcile_pending(
        &self,
        store: &mut CellVersionRetentionStoreV3,
        current_height: u64,
        deadline: Instant,
        checkpoint_owner: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellVersionRetentionReadbackV3> {
        checkpoint_owner()?;
        let operation = match self.progress(store, current_height, deadline)? {
            CellPeriodicSnapshotProgressV1::Pending {
                original_operation, ..
            } => original_operation,
            _ => return Err(CellErrorV1::Invalid("periodic snapshot no pending duty")),
        };
        let result = store.reconcile_version(operation, deadline, checkpoint_owner)?;
        require(
            result.acknowledged && !result.retired && result.operation == operation,
            "periodic snapshot complete target readback",
        )?;
        checkpoint_owner()?;
        self.check_policy(deadline)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
