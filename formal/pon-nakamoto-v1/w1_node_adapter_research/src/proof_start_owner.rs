//! Finite, nonrefundable proof starts in one explicitly provisioned Unix owner.
//!
//! Each fixed slot is claimed with create_new and synchronized before work may
//! start. Partial slots remain spent. This is not authenticated anti-rollback
//! storage, a quantum-query bound, or a bound on unmetered library callers.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{MAX_OPERATIONS, OperatorPlan, PROFILE, Result, canonical_hex, digest, err, require};

const POLICY_SCHEMA: &str = "trnm-w1-proof-start-owner-policy-v1";
const START_SCHEMA: &str = "trnm-w1-proof-start-slot-v1";
const POLICY_FILE: &str = "policy-v1.json";
const READY_FILE: &str = "complete-v1";
const SLOTS_DIR: &str = "starts-v1";
const MAX_POLICY_BYTES: usize = 4096;
const MAX_START_BYTES: u64 = 2048;

/// Independently supplied operator policy. The stored file cannot choose it.
/// owner_id is a scope identifier, not an authenticated operator identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofStartPolicy {
    pub schema: String,
    pub owner_id: String,
    pub profile: String,
    pub network: String,
    pub parameters: String,
    pub genesis: String,
    pub maximum_starts: usize,
}

impl ProofStartPolicy {
    pub fn for_plan(owner_id: String, maximum_starts: usize, plan: &OperatorPlan) -> Result<Self> {
        plan.expected()?;
        let policy = Self {
            schema: POLICY_SCHEMA.into(),
            owner_id,
            profile: plan.profile.clone(),
            network: plan.network.clone(),
            parameters: plan.parameters.clone(),
            genesis: plan.genesis.clone(),
            maximum_starts,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        require(self.schema == POLICY_SCHEMA, "proof-start policy schema")?;
        require(self.profile == PROFILE, "proof-start profile")?;
        require(
            (1..=MAX_OPERATIONS).contains(&self.maximum_starts),
            "proof-start maximum range",
        )?;
        for value in [
            &self.owner_id,
            &self.network,
            &self.parameters,
            &self.genesis,
        ] {
            require(canonical_hex(value, 32), "proof-start policy identity")?;
        }
        Ok(())
    }

    fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(err)
    }

    fn matches_plan(&self, plan: &OperatorPlan) -> Result<()> {
        require(
            self.profile == plan.profile
                && self.network == plan.network
                && self.parameters == plan.parameters
                && self.genesis == plan.genesis,
            "proof-start operation context",
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStartPurpose {
    Admission,
    ReopenObservation,
}

/// A diagnostic record can be copied; it is not a permit to execute a proof.
#[derive(Clone, Debug, Serialize)]
pub struct ProofStartRecord {
    pub schema: String,
    pub owner_id: String,
    pub policy_sha256: String,
    pub slot: usize,
    pub purpose: ProofStartPurpose,
    pub reserved_before_work: bool,
}

/// Non-cloneable and non-deserializable. Only a durable slot can mint it.
#[derive(Debug)]
pub struct ProofStartReservation {
    policy: ProofStartPolicy,
    record: ProofStartRecord,
}

impl ProofStartReservation {
    pub fn record(&self) -> &ProofStartRecord {
        &self.record
    }

    pub(crate) fn bind(self, plan: &OperatorPlan) -> Result<ProofStartRecord> {
        self.policy.matches_plan(plan)?;
        Ok(self.record)
    }
}

#[derive(Debug, Serialize)]
pub struct ProofStartSnapshot {
    pub schema: &'static str,
    pub owner_id: String,
    pub policy_sha256: String,
    pub maximum_starts: usize,
    /// Includes empty and interrupted writes; no success receipt is required.
    pub occupied_slots: usize,
    pub exhausted: bool,
    pub lifetime_quantum_query_bound_established: bool,
    pub backup_rollback_protection_established: bool,
}

/// A fixed owner directory with no reset, delete, refund, or quota-update API.
/// Concurrent processes arbitrate each slot through the filesystem, not a
/// process-local counter. The enclosing filesystem must be locally durable and
/// the configured owner path must be protected from deletion/backup rollback.
pub struct ProofStartOwner {
    path: PathBuf,
    policy: ProofStartPolicy,
    policy_bytes: Vec<u8>,
    root: File,
    slots: File,
}

impl ProofStartOwner {
    /// Create-only provisioning, separate from all verification entry points.
    /// A failed initialization remains an incomplete owner and is not reset.
    pub fn create(path: &Path, policy: ProofStartPolicy) -> Result<Self> {
        let policy_bytes = policy.bytes()?;
        let parent = path.parent().ok_or("proof-start owner parent")?;
        require(path.is_absolute(), "proof-start absolute owner path")?;
        require(
            fs::canonicalize(parent).map_err(err)? == parent,
            "proof-start canonical owner parent",
        )?;
        private_directory(path)?;
        private_directory(&path.join(SLOTS_DIR))?;
        new_private_file(&path.join(POLICY_FILE), &policy_bytes)?;
        new_private_file(&path.join(READY_FILE), digest(&policy_bytes).as_bytes())?;
        File::open(path.join(SLOTS_DIR))
            .and_then(|file| file.sync_all())
            .map_err(err)?;
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(err)?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(err)?;
        Self::open(path, policy)
    }

    /// Never initializes a missing owner or infers policy from stored data.
    pub fn open(path: &Path, policy: ProofStartPolicy) -> Result<Self> {
        let policy_bytes = policy.bytes()?;
        check_directory_path(path)?;
        check_directory_path(&path.join(SLOTS_DIR))?;
        let owner = Self {
            path: path.into(),
            policy,
            policy_bytes,
            root: File::open(path).map_err(err)?,
            slots: File::open(path.join(SLOTS_DIR)).map_err(err)?,
        };
        owner.validate_owner()?;
        owner.occupied()?;
        Ok(owner)
    }

    fn validate_owner(&self) -> Result<()> {
        check_directory_identity(&self.path, &self.root)?;
        check_directory_identity(&self.path.join(SLOTS_DIR), &self.slots)?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.path).map_err(err)?.take(4) {
            entries.push(entry.map_err(err)?.file_name());
        }
        entries.sort();
        let mut expected = [POLICY_FILE, READY_FILE, SLOTS_DIR].map(std::ffi::OsString::from);
        expected.sort();
        require(entries == expected, "proof-start owner entries")?;
        require(
            private_read(&self.path.join(POLICY_FILE), MAX_POLICY_BYTES)? == self.policy_bytes,
            "proof-start independent policy mismatch",
        )?;
        require(
            private_read(&self.path.join(READY_FILE), 64)? == digest(&self.policy_bytes).as_bytes(),
            "proof-start owner completion marker",
        )
    }

    fn occupied(&self) -> Result<Vec<bool>> {
        let mut slots = vec![false; self.policy.maximum_starts];
        for entry in fs::read_dir(self.path.join(SLOTS_DIR))
            .map_err(err)?
            .take(self.policy.maximum_starts + 1)
        {
            let entry = entry.map_err(err)?;
            let name = entry.file_name();
            let index = (1..=self.policy.maximum_starts)
                .find(|index| name == slot_name(*index).as_str())
                .ok_or("proof-start unexpected slot")?;
            require(!slots[index - 1], "proof-start duplicate slot")?;
            let metadata = check_file_path(&entry.path())?;
            require(
                metadata.len() <= MAX_START_BYTES,
                "proof-start slot byte limit",
            )?;
            // Existence consumes a slot even when its first write was interrupted.
            // Its payload is never interpreted as a refund or success decision.
            slots[index - 1] = true;
        }
        Ok(slots)
    }

    pub fn snapshot(&self) -> Result<ProofStartSnapshot> {
        self.validate_owner()?;
        let occupied_slots = self
            .occupied()?
            .iter()
            .filter(|occupied| **occupied)
            .count();
        Ok(ProofStartSnapshot {
            schema: "trnm-w1-proof-start-owner-snapshot-v1",
            owner_id: self.policy.owner_id.clone(),
            policy_sha256: digest(&self.policy_bytes),
            maximum_starts: self.policy.maximum_starts,
            occupied_slots,
            exhausted: occupied_slots == self.policy.maximum_starts,
            lifetime_quantum_query_bound_established: false,
            backup_rollback_protection_established: false,
        })
    }

    /// Charge before loading/decoding an untrusted bundle or entering any proof
    /// stage. A returned permit is single-use. Every error leaves created slots
    /// spent, including write/sync failures; it never authorizes work afterward.
    pub fn reserve(&self, purpose: ProofStartPurpose) -> Result<ProofStartReservation> {
        self.validate_owner()?;
        let occupied = self.occupied()?;
        for slot in 1..=self.policy.maximum_starts {
            if occupied[slot - 1] {
                continue;
            }
            let path = self.path.join(SLOTS_DIR).join(slot_name(slot));
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            set_private_mode(&mut options);
            let mut file = match options.open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    // Another process may have claimed this exact slot since
                    // the snapshot. Do not overwrite, truncate, or reuse it.
                    check_file_path(&path)?;
                    continue;
                }
                Err(error) => return Err(err(error)),
            };
            let record = ProofStartRecord {
                schema: START_SCHEMA.into(),
                owner_id: self.policy.owner_id.clone(),
                policy_sha256: digest(&self.policy_bytes),
                slot,
                purpose,
                reserved_before_work: true,
            };
            let bytes = serde_json::to_vec(&record).map_err(err)?;
            require(
                bytes.len() as u64 <= MAX_START_BYTES,
                "proof-start record limit",
            )?;
            file.write_all(&bytes).map_err(err)?;
            file.sync_all().map_err(err)?;
            self.slots.sync_all().map_err(err)?;
            check_file_identity(&path, &file)?;
            self.validate_owner()?;
            return Ok(ProofStartReservation {
                policy: self.policy.clone(),
                record,
            });
        }
        Err("proof-start budget exhausted".into())
    }
}

fn slot_name(slot: usize) -> String {
    format!("{slot:02}.start")
}

fn private_directory(path: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(err)?;
    check_directory_path(path).map(|_| ())
}

fn set_private_mode(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = options;
}

fn new_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    set_private_mode(&mut options);
    let mut file = options.open(path).map_err(err)?;
    file.write_all(bytes).map_err(err)?;
    file.sync_all().map_err(err)?;
    check_file_identity(path, &file)
}

fn check_directory_path(path: &Path) -> Result<fs::Metadata> {
    require(
        path.is_absolute() && fs::canonicalize(path).map_err(err)? == path,
        "proof-start canonical owner path",
    )?;
    let metadata = fs::symlink_metadata(path).map_err(err)?;
    require(metadata.file_type().is_dir(), "proof-start owner directory")?;
    check_mode(&metadata, 0o700, false)?;
    Ok(metadata)
}

fn check_file_path(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(err)?;
    require(metadata.file_type().is_file(), "proof-start regular file")?;
    check_mode(&metadata, 0o600, true)?;
    Ok(metadata)
}

#[cfg(unix)]
fn check_mode(metadata: &fs::Metadata, expected: u32, file: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    require(
        metadata.mode() & 0o7777 == expected,
        "proof-start private permissions",
    )?;
    require(
        !file || metadata.nlink() == 1,
        "proof-start single-link file",
    )
}

#[cfg(not(unix))]
fn check_mode(_: &fs::Metadata, _: u32, _: bool) -> Result<()> {
    Err("proof-start owner requires Unix metadata".into())
}

#[cfg(unix)]
fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino() && left.uid() == right.uid()
}

#[cfg(not(unix))]
fn same_identity(_: &fs::Metadata, _: &fs::Metadata) -> bool {
    false
}

fn check_file_identity(path: &Path, file: &File) -> Result<()> {
    require(
        same_identity(&check_file_path(path)?, &file.metadata().map_err(err)?),
        "proof-start file identity changed",
    )
}

fn check_directory_identity(path: &Path, file: &File) -> Result<()> {
    require(
        same_identity(&check_directory_path(path)?, &file.metadata().map_err(err)?),
        "proof-start owner identity changed",
    )
}

fn private_read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = check_file_path(path)?;
    require(
        metadata.len() <= maximum as u64,
        "proof-start metadata byte limit",
    )?;
    let mut file = File::open(path).map_err(err)?;
    check_file_identity(path, &file)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    require(
        bytes.len() <= maximum,
        "proof-start changed metadata byte limit",
    )?;
    check_file_identity(path, &file)?;
    Ok(bytes)
}
