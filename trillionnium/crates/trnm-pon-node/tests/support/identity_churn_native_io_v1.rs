//! PN1 real-inode storage profile for the original identity-capacity workload.
//! Old V1/V2 schemas/selectors remain unchanged. This bridge never enables full
//! collection: caller, whole-writer and independent-reader qualification remain
//! explicit prerequisites, including the unchanged 4096+fresh paid denominator.
use super::{exec_identity::Held, limits, plan::Mode};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use trnm_sqlite_io_boundary::{
    NativeIoLease, NativeIoOwner, RootReceipt, DOMAIN, GROWTH_QUANTUM_BYTES_V2,
    RESERVATION_DOMAIN_V2, ROOT_COUNT,
};

pub const SCHEMA: &str = "native-public-v3-identity-churn-native-io-v1";
pub const STORAGE_PROFILE: &str = "pn1-full4097-seven-held-roots-real-inode-v1";

/// A fixed storage/evidence contract, selected by a distinct public test entry.
/// This does not change actors, work, deadlines or any resource/evidence cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    ExactV1,
    ReservationV2,
}
impl Profile {
    pub fn schema(self) -> &'static str {
        match self {
            Self::ExactV1 => SCHEMA,
            Self::ReservationV2 => "native-public-v3-identity-churn-native-io-reservation-v2",
        }
    }
    pub fn storage_profile(self) -> &'static str {
        match self {
            Self::ExactV1 => STORAGE_PROFILE,
            Self::ReservationV2 => "pn1-finite-seven-held-roots-reservation-v2",
        }
    }
    pub fn sqlite_domain(self) -> &'static str {
        match self {
            Self::ExactV1 => DOMAIN,
            Self::ReservationV2 => RESERVATION_DOMAIN_V2,
        }
    }
    fn quantum(self) -> Option<u64> {
        match self {
            Self::ExactV1 => None,
            Self::ReservationV2 => Some(GROWTH_QUANTUM_BYTES_V2),
        }
    }
}

fn ensure(value: bool, message: &str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
pub fn full_route_ready() -> bool {
    // Neither a compiled bridge nor finite native controls qualify all writers,
    // the actual Python 3FD caller, the new reader or the original paid work.
    false
}
pub struct Layout {
    profile: Profile,
    raw: Held,
    phases: [Held; 3],
    _owner: NativeIoOwner,
    leases: [NativeIoLease; ROOT_COUNT],
    phase_claimed: [bool; 3],
}
pub struct Phase<'a> {
    profile: Profile,
    mode: Mode,
    directory: &'a Held,
    receiver: &'a NativeIoLease,
    verifier: &'a NativeIoLease,
    receiver_index: usize,
}
impl Phase<'_> {
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub fn directory(&self) -> &Held {
        self.directory
    }
    pub fn receiver(&self) -> &NativeIoLease {
        self.receiver
    }
    pub fn verifier(&self) -> &NativeIoLease {
        self.verifier
    }
    pub fn receiver_index(&self) -> usize {
        self.receiver_index
    }
}
impl Layout {
    pub fn create(raw: Held) -> io::Result<Self> {
        Self::create_for(raw, Profile::ExactV1)
    }
    pub fn create_for(raw: Held, profile: Profile) -> io::Result<Self> {
        let phases = [
            raw.create_child_directory(OsStr::new(Mode::HonestOnly.name()))?,
            raw.create_child_directory(OsStr::new(Mode::ReplayOnly.name()))?,
            raw.create_child_directory(OsStr::new(Mode::FreshIdentities.name()))?,
        ];
        // Phase containers are fresh, held and never recreated by the phase
        // controller. The one production owner creates all seven fresh leaves
        // before the first Node open; any collision is retained and fails.
        let mut parents = Vec::with_capacity(ROOT_COUNT);
        parents.push((
            raw.try_clone_directory_file()?,
            OsStr::new("honest-miner").to_owned(),
        ));
        for (index, phase) in phases.iter().enumerate() {
            for leaf in ["receiver", "independent-client"] {
                let expected = format!(
                    "{}/{leaf}",
                    [Mode::HonestOnly, Mode::ReplayOnly, Mode::FreshIdentities][index].name()
                );
                ensure(
                    limits::NODE_ROOTS[parents.len()] == expected,
                    "original role order changed",
                )?;
                parents.push((
                    phase.try_clone_directory_file()?,
                    OsStr::new(leaf).to_owned(),
                ));
            }
        }
        ensure(
            limits::NODE_ROOTS[0] == "honest-miner",
            "original miner role changed",
        )?;
        let parents = parents
            .try_into()
            .map_err(|_| io::Error::other("exact seven held role parents required"))?;
        let owner = match profile {
            Profile::ExactV1 => NativeIoOwner::create_at(parents),
            Profile::ReservationV2 => NativeIoOwner::create_at_with_reservation_v2(parents),
        }
        .map_err(io::Error::other)?;
        let leases: [NativeIoLease; ROOT_COUNT] = (0..ROOT_COUNT)
            .map(|index| owner.lease(index).map_err(io::Error::other))
            .collect::<io::Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| io::Error::other("exact seven original leases required"))?;
        ensure(
            leases
                .iter()
                .map(NativeIoLease::identity)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == ROOT_COUNT,
            "seven distinct real root inodes required",
        )?;
        Ok(Self {
            profile,
            raw,
            phases,
            _owner: owner,
            leases,
            phase_claimed: [false; 3],
        })
    }
    pub fn miner(&self) -> NativeIoLease {
        self.leases[0].clone()
    }
    pub fn phase(&mut self, mode: Mode) -> io::Result<Phase<'_>> {
        let index = match mode {
            Mode::HonestOnly => 0,
            Mode::ReplayOnly => 1,
            Mode::FreshIdentities => 2,
        };
        ensure(
            !self.phase_claimed[index],
            "native I/O phase claim already consumed",
        )?;
        self.phase_claimed[index] = true; // Failure also consumes this phase.
        let receiver_index = 1 + 2 * index;
        Ok(Phase {
            profile: self.profile,
            mode,
            directory: &self.phases[index],
            receiver: &self.leases[receiver_index],
            verifier: &self.leases[receiver_index + 1],
            receiver_index,
        })
    }
    pub fn summary(&self) -> Value {
        json!({"schema":self.profile.storage_profile(),"sqlite_domain":self.profile.sqlite_domain(),"owner_pid":std::process::id(),
            "raw_capability":self.raw.identity,"phase_claims_consumed":self.phase_claimed,"phase_capabilities":self.phases.iter().map(|p|&p.identity).collect::<Vec<_>>(),
            "roles":self.leases.iter().enumerate().map(|(index,lease)|json!({"index":index,"role":limits::NODE_ROOTS[index],
                "root_dev_ino":lease.identity(),"registered_vfs":lease.vfs_name()})).collect::<Vec<_>>(),
            "original_v2_limits_unchanged":true,"real_retained_inode_domain_bytes":336*1024*1024,
            "legacy_filename_inventory_is_not_lifecycle_proof":true,"physical_block_hard_quota":false,
            "whole_writer_qualified":false,"original_three_FD_caller_qualified":false,
            "independent_reader_qualified":false,"full_W1_4097_qualified":false,"merge_ready":false})
    }
    pub fn all_roots_closed(&self) -> io::Result<()> {
        // At most one full RootReceipt is cloned at a time; this neither drains
        // nor resets the 1024/256 lifecycle or the three retained inode slots.
        for (index, lease) in self.leases.iter().enumerate() {
            let row = root_snapshot_for(self.profile, index, lease)?;
            if let Some(error) = terminal_error(&row) {
                return Err(io::Error::other(error));
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct RoleReceipt {
    pub index: usize,
    pub role: &'static str,
    pub registered_vfs: String,
    pub receipt: RootReceipt,
}
pub fn closed_root(index: usize, lease: &NativeIoLease) -> io::Result<RoleReceipt> {
    let row = root_snapshot(index, lease)?;
    if let Some(error) = terminal_error(&row) {
        return Err(io::Error::other(error));
    }
    Ok(row)
}
pub fn root_snapshot(index: usize, lease: &NativeIoLease) -> io::Result<RoleReceipt> {
    root_snapshot_for(Profile::ExactV1, index, lease)
}
pub fn root_snapshot_for(
    profile: Profile,
    index: usize,
    lease: &NativeIoLease,
) -> io::Result<RoleReceipt> {
    let receipt = lease.receipt().map_err(io::Error::other)?;
    ensure(
        index < ROOT_COUNT
            && receipt.schema == profile.sqlite_domain()
            && receipt.growth_reservation_quantum_bytes == profile.quantum()
            && receipt.owner_pid == std::process::id()
            && (receipt.root_device, receipt.root_inode) == lease.identity(),
        "actual root role/PID/inode required",
    )?;
    Ok(RoleReceipt {
        index,
        role: limits::NODE_ROOTS[index],
        registered_vfs: lease.vfs_name().into(),
        receipt,
    })
}
pub fn terminal_error(row: &RoleReceipt) -> Option<String> {
    let receipt = &row.receipt;
    let healthy = receipt.lifecycle_complete
        && receipt.secondary_failures_complete
        && receipt.quarantine_entries_complete
        && !receipt.failed
        && receipt.first_failure.is_none()
        && receipt.first_failure_sqlite_code.is_none()
        && receipt.secondary_failures.is_empty()
        && receipt.denied_operations == 0
        && receipt.quarantined_actual_states == 0
        && receipt.quarantined_sqlite_codes.is_empty()
        && !receipt.allocated_blocks_hard_cap_implemented;
    let closed = receipt
        .objects
        .iter()
        .all(|o| o.handles == 0 && o.pending_opens == 0 && o.shm_references == 0);
    if healthy && closed {
        None
    } else {
        Some(format!("native role {} not complete/healthy/closed: first_failure={:?} first_SQLite_code={:?} denied={} quarantined={} actual_refs_closed={closed}",
            row.index, receipt.first_failure, receipt.first_failure_sqlite_code, receipt.denied_operations, receipt.quarantined_actual_states))
    }
}

#[derive(Serialize)]
pub struct NativeReport<'a> {
    #[serde(flatten)]
    pub original_workload_report: &'a Value,
    pub native_io_storage_profile: &'static str,
    pub native_io_terminal_roots: Vec<RoleReceipt>,
    pub native_io_terminals_healthy_closed: bool,
    pub whole_writer_qualified: bool,
    #[serde(rename = "original_three_FD_caller_qualified")]
    pub original_three_fd_caller_qualified: bool,
    pub independent_reader_qualified: bool,
    #[serde(rename = "full_W1_4097_qualified")]
    pub full_w1_4097_qualified: bool,
}
pub fn report<'a>(original: &'a Value, roots: Vec<RoleReceipt>) -> io::Result<NativeReport<'a>> {
    report_for(Profile::ExactV1, original, roots)
}
pub fn report_for<'a>(
    profile: Profile,
    original: &'a Value,
    roots: Vec<RoleReceipt>,
) -> io::Result<NativeReport<'a>> {
    ensure(
        roots.iter().all(|root| {
            root.receipt.schema == profile.sqlite_domain()
                && root.receipt.growth_reservation_quantum_bytes == profile.quantum()
        }),
        "mixed native storage evidence domains forbidden",
    )?;
    ensure(
        !roots.is_empty() && roots.len() <= 2,
        "stream at most preparation1 or phase2 full root receipts",
    )?;
    let healthy_closed = roots.iter().all(|root| terminal_error(root).is_none());
    Ok(NativeReport {
        original_workload_report: original,
        native_io_storage_profile: profile.storage_profile(),
        native_io_terminal_roots: roots,
        native_io_terminals_healthy_closed: healthy_closed,
        whole_writer_qualified: false,
        original_three_fd_caller_qualified: false,
        independent_reader_qualified: false,
        full_w1_4097_qualified: false,
    })
}
pub fn file_reference(path: &Path, limit: u64) -> io::Result<Value> {
    let mut file: File = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    ensure(
        before.is_file() && before.nlink() == 1 && before.len() <= limit,
        "original receipt file type/link/cap",
    )?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let mut bytes = 0_u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        ensure(bytes <= limit, "receipt reference stream cap")?;
        hash.update(&buffer[..n]);
    }
    let after = file.metadata()?;
    ensure(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) == (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) && bytes == before.len(),
        "published receipt changed during hash",
    )?;
    Ok(
        json!({"bytes":bytes,"sha256":hex::encode(hash.finalize()),"original_dev_ino":[before.dev(),before.ino()],
        "archived_inode_identity_claimed":false}),
    )
}
