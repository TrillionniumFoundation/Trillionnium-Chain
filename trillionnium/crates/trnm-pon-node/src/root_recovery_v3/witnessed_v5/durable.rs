//! Native V5 durable register component, using the original V5 dual-family domains.
//!
//! SQLite COMMIT and file/directory synchronization precede every Advanced ACK.
//! Cold open requires an independently retained exact head and complete policy;
//! the database cannot manufacture either recovery authority. This typed owner
//! is not a daemon, codec, distributed quorum service, or proof of independent
//! custody. Its keys and storage must survive outside the declared restore domain.
//!
//! Concurrent filesystem administration by the private directory's owner UID is
//! trusted. SQLite opens the checked pathname without exposing its main-file fd;
//! held-file/directory checks cannot exclude a same-UID swap-and-restore race.
//! The original budget is checked around I/O and callbacks and by SQLite's
//! progress handler; it cannot preempt an OS sync or arbitrary signer callback.
use super::{
    map_error, rejected, require, JournalEnrollmentV3, JournalHeadV3, OwnerBudgetV3,
    RootOwnerResultV3, RootWitnessTransportV5, RootWriterSignerV3, SignedWitnessReceiptV5,
    WitnessEnvelopeV5, WitnessOutcomeV5, WitnessPolicyV5, WitnessReceiptV5, WitnessRequestV5,
};
use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use rustix::fs::{openat, Mode, OFlags};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

mod receipts;
use receipts::ArchiveV6;
pub use receipts::{ReceiptedRootWitnessV6, RetainedWitnessReceiptV6, WitnessReceiptCheckpointV6};

const MAX_DATABASE_BYTES: u64 = 1024 * 1024;
const MAX_RECEIPT_DATABASE_BYTES_V6: u64 = 32 * 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Namespace {
    RegisterV5,
    ReceiptsV6,
}
impl Namespace {
    fn application_id(self) -> u32 {
        match self {
            Self::RegisterV5 => 0x5257_5635,
            Self::ReceiptsV6 => 0x5257_5636,
        }
    }
    fn version(self) -> u32 {
        match self {
            Self::RegisterV5 => 5,
            Self::ReceiptsV6 => 6,
        }
    }
    fn maximum_bytes(self) -> u64 {
        match self {
            Self::RegisterV5 => MAX_DATABASE_BYTES,
            Self::ReceiptsV6 => MAX_RECEIPT_DATABASE_BYTES_V6,
        }
    }
}
const DDL: &str = "CREATE TABLE root_witness_v5(singleton INTEGER PRIMARY KEY CHECK(singleton=1),policy BLOB NOT NULL,version INTEGER NOT NULL CHECK(version>=0 AND version<=128),root BLOB NOT NULL CHECK(length(root)=64),previous_version INTEGER NOT NULL CHECK(previous_version>=0),previous_root BLOB NOT NULL CHECK(length(previous_root)=64))";

#[derive(Clone, Copy, Eq, PartialEq)]
struct Row {
    head: JournalHeadV3,
    previous: Option<JournalHeadV3>,
}

/// One non-clonable, exclusively held V5 register. The signing callback must
/// return the independently provisioned witness roster's dual-family quorum.
/// It receives the same operation budget; replacement is rejected even on Err.
pub struct DurableRootWitnessV5 {
    // Declaration order closes SQLite before releasing its file/directory lease.
    db: Connection,
    files: HeldFiles,
    namespace: Namespace,
    archive: Option<ArchiveV6>,
    policy: WitnessPolicyV5,
    policy_bytes: Vec<u8>,
    signer: Box<dyn RootWriterSignerV3>,
    known: Row,
    // Persisted predecessor bytes do not authenticate their own cold recovery.
    // Only a CAS verified and durably committed by this live owner can retry.
    retry_from: Option<JournalHeadV3>,
    fenced: bool,
}

impl DurableRootWitnessV5 {
    /// Register only an independently new namespace at the authenticated initial
    /// version-zero head derived from the complete policy-bound enrollment.
    /// Existing/partial databases are never overwritten.
    pub fn register_new(
        path: &Path,
        policy: WitnessPolicyV5,
        enrollment: &JournalEnrollmentV3,
        signer: impl RootWriterSignerV3 + 'static,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        Self::register(
            path,
            policy,
            enrollment,
            signer,
            budget,
            Namespace::RegisterV5,
        )
    }
    fn register(
        path: &Path,
        policy: WitnessPolicyV5,
        enrollment: &JournalEnrollmentV3,
        signer: impl RootWriterSignerV3 + 'static,
        budget: &mut OwnerBudgetV3,
        namespace: Namespace,
    ) -> RootOwnerResultV3<Self> {
        budget.check()?;
        policy.check_enrollment(enrollment)?;
        let initial = enrollment.initial_head()?;
        initial.validate()?;
        require(initial.version == 0, "ROOT_WITNESS_V5_INITIAL_HEAD")?;
        let files = HeldFiles::bind(path, true, namespace)?;
        let mut db = connection(path, namespace)?;
        files.check()?;
        let policy_bytes = canonical_policy(&policy);
        {
            let guard = progress(&mut db, budget)?;
            let tx = guard
                .0
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(map_error)?;
            tx.execute_batch(DDL).map_err(map_error)?;
            tx.pragma_update(None, "application_id", namespace.application_id())
                .map_err(map_error)?;
            tx.pragma_update(None, "user_version", namespace.version())
                .map_err(map_error)?;
            if namespace == Namespace::ReceiptsV6 {
                tx.execute_batch(receipts::DDL).map_err(map_error)?;
            }
            tx.execute(
                "INSERT INTO root_witness_v5 VALUES(1,?,0,?,0,zeroblob(64))",
                params![&policy_bytes, initial.root.as_slice()],
            )
            .map_err(map_error)?;
            files.check()?;
            budget.check()?;
            tx.commit().map_err(map_error)?;
            files.sync()?;
        }
        let mut owner = Self {
            db,
            files,
            namespace,
            archive: if namespace == Namespace::ReceiptsV6 {
                Some(ArchiveV6::initial(&policy))
            } else {
                None
            },
            policy,
            policy_bytes,
            signer: Box::new(signer),
            known: Row {
                head: initial,
                previous: None,
            },
            retry_from: None,
            fenced: false,
        };
        owner.check_known(budget)?;
        Ok(owner)
    }

    /// `expected` and `policy` must come from authenticated authority outside the
    /// restored witness database and its sibling files. Both an older and newer
    /// stored head require explicit external reconciliation, never auto-adoption.
    /// A cold owner does not acknowledge historical CAS retries from database
    /// predecessor metadata. Fresh Current can authenticate the retained head.
    pub fn open_existing(
        path: &Path,
        policy: WitnessPolicyV5,
        expected: JournalHeadV3,
        signer: impl RootWriterSignerV3 + 'static,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        Self::reopen(path, policy, expected, None, signer, budget)
    }
    fn reopen(
        path: &Path,
        policy: WitnessPolicyV5,
        expected: JournalHeadV3,
        expected_archive: Option<ArchiveV6>,
        signer: impl RootWriterSignerV3 + 'static,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        budget.check()?;
        expected.validate()?;
        let namespace = if expected_archive.is_some() {
            Namespace::ReceiptsV6
        } else {
            Namespace::RegisterV5
        };
        let files = HeldFiles::bind(path, false, namespace)?;
        let mut db = connection(path, namespace)?;
        files.check()?;
        let policy_bytes = canonical_policy(&policy);
        let known = read_transaction(&mut db, &files, &policy_bytes, namespace, budget)?;
        if let Some(expected) = expected_archive {
            let recovered = receipts::replay(&db, &policy, known.head, budget, true)?;
            require(
                recovered == expected,
                "ROOT_WITNESS_V6_INDEPENDENT_RECEIPT_CHECKPOINT",
            )?;
        }
        require(
            known.head == expected,
            "ROOT_WITNESS_V5_INDEPENDENT_REOPEN_HEAD",
        )?;
        Ok(Self {
            db,
            files,
            namespace,
            archive: expected_archive,
            policy,
            policy_bytes,
            signer: Box::new(signer),
            known,
            retry_from: None,
            fenced: false,
        })
    }

    fn check_known(&mut self, budget: &mut OwnerBudgetV3) -> RootOwnerResultV3<()> {
        require(
            read_transaction(
                &mut self.db,
                &self.files,
                &self.policy_bytes,
                self.namespace,
                budget,
            )? == self.known,
            "ROOT_WITNESS_V5_DURABLE_STATE_CHANGED",
        )?;
        if let Some(expected) = self.archive {
            require(
                receipts::replay(&self.db, &self.policy, self.known.head, budget, false)?
                    == expected,
                "ROOT_WITNESS_V6_RECEIPT_HISTORY_CHANGED",
            )?;
        }
        Ok(())
    }

    fn decide(
        &mut self,
        request: &WitnessRequestV5,
        budget: &OwnerBudgetV3,
    ) -> RootOwnerResultV3<WitnessOutcomeV5> {
        budget.check()?;
        self.files.check()?;
        let guard = progress(&mut self.db, budget)?;
        let tx = guard
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_error)?;
        let before = read_row(&tx, &self.policy_bytes, self.namespace)?;
        require(
            before == self.known,
            "ROOT_WITNESS_V5_DURABLE_STATE_CHANGED",
        )?;
        let mut after = before;
        let outcome = match (request.expected, request.target) {
            (None, None) => WitnessOutcomeV5::Current,
            (Some(expected), Some(target)) if before.head == expected => {
                // Request authentication has checked the immediate successor.
                let changed = tx.execute(
                    "UPDATE root_witness_v5 SET version=?1,root=?2,previous_version=?3,previous_root=?4 WHERE singleton=1 AND version=?3 AND root=?4 AND policy=?5",
                    params![target.version, target.root.as_slice(), expected.version, expected.root.as_slice(), &self.policy_bytes],
                ).map_err(map_error)?;
                require(changed == 1, "ROOT_WITNESS_V5_DURABLE_CAS")?;
                after = Row {
                    head: target,
                    previous: Some(expected),
                };
                WitnessOutcomeV5::Advanced
            }
            (Some(expected), Some(target))
                if before.head == target
                    && before.previous == Some(expected)
                    && self.retry_from == Some(expected) =>
            {
                // Only this live owner authenticated and durably committed the
                // original transition; cold predecessor bytes are insufficient.
                WitnessOutcomeV5::Advanced
            }
            (Some(_), Some(_)) => WitnessOutcomeV5::Mismatch,
            _ => return Err(rejected("ROOT_WITNESS_V5_REQUEST_SHAPE")),
        };
        require(
            read_row(&tx, &self.policy_bytes, self.namespace)? == after,
            "ROOT_WITNESS_V5_DURABLE_CAS",
        )?;
        self.files.check()?;
        budget.check()?;
        // From here any error, including an unknown COMMIT, signing, or final
        // observation, fences the owner. A later disk read cannot clear it.
        self.fenced = true;
        tx.commit().map_err(map_error)?;
        if outcome == WitnessOutcomeV5::Advanced {
            self.files.sync()?;
        }
        self.known = after;
        if after.head != before.head {
            self.retry_from = Some(before.head);
        }
        self.files.check()?;
        budget.check()?;
        Ok(outcome)
    }
}

impl RootWitnessTransportV5 for DurableRootWitnessV5 {
    fn exchange(
        &mut self,
        envelope: WitnessEnvelopeV5,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedWitnessReceiptV5> {
        budget.check()?;
        require(!self.fenced, "ROOT_WITNESS_V5_DURABLE_FENCED")?;
        // Unauthenticated input cannot mutate or fence durable authority.
        envelope.verify_writer(&self.policy, budget)?;
        let original_budget = budget.identity.clone();
        if let Some(archive) = self.archive {
            let replay = (|| {
                self.check_known(budget)?;
                receipts::contains_request(&self.db, archive, envelope.request.digest()?, budget)
            })();
            match replay {
                // A captured request cannot consume new archive capacity. Refusal
                // does not mutate or fence an otherwise healthy live owner.
                Ok(true) => return Err(rejected("ROOT_WITNESS_V6_REQUEST_ALREADY_RETAINED")),
                Ok(false) => {}
                Err(error) => {
                    self.fenced = true;
                    return Err(error);
                }
            }
        }
        let result = (|| {
            self.check_known(budget)?;
            if let Some(archive) = self.archive {
                require(
                    archive.count < receipts::MAX_RECORDS,
                    "ROOT_WITNESS_V6_RECEIPT_CAPACITY",
                )?;
            }
            let outcome = self.decide(&envelope.request, budget)?;
            let receipt =
                WitnessReceiptV5::for_request(&envelope.request, self.known.head, outcome)?;
            let message = receipt.message()?;
            let approvals = self.signer.sign(&message, budget);
            budget.check_identity(&original_budget)?;
            let approvals = approvals?;
            self.policy
                .witness
                .verify_quorum(&message, &approvals, budget.verification())
                .map_err(map_error)?;
            // Signing is an external callback. Recheck the exact persisted row
            // and held identities before releasing its authenticated receipt.
            self.check_known(budget)?;
            budget.check_identity(&original_budget)?;
            let response = SignedWitnessReceiptV5 { receipt, approvals };
            if self.archive.is_some() {
                receipts::retain(self, &envelope, &response, budget)?;
            }
            self.check_known(budget)?;
            budget.check_identity(&original_budget)?;
            Ok(response)
        })();
        self.fenced = result.is_err();
        result
    }
}

// Exact stored policy bytes are checked against caller-provisioned policy, never
// parsed to create a trust pin. No existing request/signature domain is changed.
fn canonical_policy(policy: &WitnessPolicyV5) -> Vec<u8> {
    let mut bytes = b"TRNM/RootWitness/DurablePolicy/v5\0".to_vec();
    bytes.extend(policy.binding);
    bytes.extend(policy.enrollment_commitment);
    bytes.extend(policy.restore_domain);
    bytes.extend(policy.recovery_epoch.to_be_bytes());
    for roster in [&policy.writer, &policy.witness] {
        let encoded = roster.encode();
        bytes.extend((encoded.len() as u64).to_be_bytes());
        bytes.extend(encoded);
    }
    bytes
}

fn read_row(db: &Connection, policy: &[u8], namespace: Namespace) -> RootOwnerResultV3<Row> {
    let (application, version, schema_rows): (u32, u32, u64) = db.query_row(
        "SELECT (SELECT application_id FROM pragma_application_id),(SELECT user_version FROM pragma_user_version),(SELECT COUNT(*) FROM sqlite_master)",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(map_error)?;
    require(
        application == namespace.application_id()
            && version == namespace.version()
            && schema_rows
                == if namespace == Namespace::ReceiptsV6 {
                    2
                } else {
                    1
                },
        "ROOT_WITNESS_V5_DURABLE_SCHEMA",
    )?;
    let schema: bool = db.query_row(
        "SELECT COALESCE(type='table' AND name='root_witness_v5' AND tbl_name='root_witness_v5' AND typeof(sql)='text' AND length(CAST(sql AS BLOB))=?1 AND sql=?2,0) FROM sqlite_master WHERE name='root_witness_v5'",
        params![DDL.len(), DDL], |row| row.get(0),
    ).map_err(map_error)?;
    require(schema, "ROOT_WITNESS_V5_DURABLE_SCHEMA")?;
    if namespace == Namespace::ReceiptsV6 {
        receipts::check_schema(db)?;
    }
    let count: u64 = db
        .query_row("SELECT COUNT(*) FROM root_witness_v5", [], |row| row.get(0))
        .map_err(map_error)?;
    require(count == 1, "ROOT_WITNESS_V5_DURABLE_ROW")?;
    let valid: bool = db.query_row(
        "SELECT typeof(singleton)='integer' AND singleton=1 AND typeof(policy)='blob' AND length(policy)=?1 AND policy=?2 AND typeof(version)='integer' AND version>=0 AND version<=128 AND typeof(root)='blob' AND length(root)=64 AND root<>zeroblob(64) AND typeof(previous_version)='integer' AND previous_version>=0 AND typeof(previous_root)='blob' AND length(previous_root)=64 AND ((version=0 AND previous_version=0 AND previous_root=zeroblob(64)) OR (version>0 AND previous_version=version-1 AND previous_root<>zeroblob(64))) FROM root_witness_v5",
        params![policy.len(), policy], |row| row.get(0),
    ).map_err(map_error)?;
    require(valid, "ROOT_WITNESS_V5_DURABLE_POLICY_OR_ROW")?;
    // Widths/cardinality were checked before allocating any restored values.
    let (version, root, previous_version, previous_root): (u64, Vec<u8>, u64, Vec<u8>) = db
        .query_row(
            "SELECT version,root,previous_version,previous_root FROM root_witness_v5",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(map_error)?;
    let head = JournalHeadV3 {
        version,
        root: root
            .try_into()
            .map_err(|_| rejected("ROOT_WITNESS_V5_DURABLE_ROW"))?,
    };
    let previous = if version == 0 {
        None
    } else {
        Some(JournalHeadV3 {
            version: previous_version,
            root: previous_root
                .try_into()
                .map_err(|_| rejected("ROOT_WITNESS_V5_DURABLE_ROW"))?,
        })
    };
    Ok(Row { head, previous })
}

struct ProgressReset<'a>(&'a mut Connection);
impl Drop for ProgressReset<'_> {
    fn drop(&mut self) {
        let _ = self.0.progress_handler(0, None::<fn() -> bool>);
    }
}
fn progress<'a>(
    db: &'a mut Connection,
    budget: &OwnerBudgetV3,
) -> RootOwnerResultV3<ProgressReset<'a>> {
    budget.check()?;
    let deadline = budget.deadline;
    let cancelled = budget.cancelled.clone();
    let guard = ProgressReset(db);
    guard
        .0
        .progress_handler(
            100,
            Some(move || cancelled.load(Ordering::Acquire) || Instant::now() >= deadline),
        )
        .map_err(map_error)?;
    Ok(guard)
}
fn read_transaction(
    db: &mut Connection,
    files: &HeldFiles,
    policy: &[u8],
    namespace: Namespace,
    budget: &OwnerBudgetV3,
) -> RootOwnerResultV3<Row> {
    files.check()?;
    let guard = progress(db, budget)?;
    let tx = guard
        .0
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(map_error)?;
    let row = read_row(&tx, policy, namespace)?;
    files.check()?;
    budget.check()?;
    tx.commit().map_err(map_error)?;
    files.check()?;
    budget.check()?;
    Ok(row)
}
fn connection(path: &Path, namespace: Namespace) -> RootOwnerResultV3<Connection> {
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(map_error)?;
    db.busy_timeout(Duration::ZERO).map_err(map_error)?;
    db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0;").map_err(map_error)?;
    let journal: String = db
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(map_error)?;
    let page_size: u64 = db
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(map_error)?;
    require(
        journal == "delete" && page_size == 4096,
        "ROOT_WITNESS_V5_DURABLE_DATABASE_MODE",
    )?;
    db.pragma_update(
        None,
        "max_page_count",
        namespace.maximum_bytes() / page_size,
    )
    .map_err(map_error)?;
    Ok(db)
}

struct HeldFiles {
    file: File,
    directory: File,
    path: PathBuf,
    parent: PathBuf,
    process: u32,
    namespace: Namespace,
}
impl HeldFiles {
    fn bind(path: &Path, create: bool, namespace: Namespace) -> RootOwnerResultV3<Self> {
        require(path.is_absolute(), "ROOT_WITNESS_V5_DURABLE_ABSOLUTE_PATH")?;
        let parent = path
            .parent()
            .ok_or_else(|| rejected("ROOT_WITNESS_V5_DURABLE_PATH"))?;
        require(
            parent.canonicalize()? == parent,
            "ROOT_WITNESS_V5_DURABLE_CANONICAL_PARENT",
        )?;
        let name = path
            .file_name()
            .ok_or_else(|| rejected("ROOT_WITNESS_V5_DURABLE_PATH"))?;
        let mut components = Path::new(name).components();
        require(
            matches!(components.next(), Some(Component::Normal(value)) if value == name)
                && components.next().is_none(),
            "ROOT_WITNESS_V5_DURABLE_BASENAME",
        )?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(parent)?;
        private_directory(&directory)?;
        let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        if create {
            flags |= OFlags::CREATE | OFlags::EXCL;
        }
        let file = File::from(openat(&directory, name, flags, Mode::RUSR | Mode::WUSR)?);
        private_file(&file, namespace)?;
        file.try_lock_exclusive()
            .map_err(|_| rejected("ROOT_WITNESS_V5_DURABLE_BUSY"))?;
        if !create {
            let mut header = [0; 100];
            file.try_clone()?.read_exact(&mut header)?;
            require(
                &header[..16] == b"SQLite format 3\0"
                    && header[18] == 1
                    && header[19] == 1
                    && u32::from_be_bytes(header[60..64].try_into().unwrap())
                        == namespace.version()
                    && u32::from_be_bytes(header[68..72].try_into().unwrap())
                        == namespace.application_id(),
                "ROOT_WITNESS_V5_DURABLE_DATABASE_NAMESPACE",
            )?;
        }
        let value = Self {
            file,
            directory,
            path: path.to_path_buf(),
            parent: parent.to_path_buf(),
            process: std::process::id(),
            namespace,
        };
        value.check()?;
        Ok(value)
    }
    fn check(&self) -> RootOwnerResultV3<()> {
        require(
            self.process == std::process::id(),
            "ROOT_WITNESS_V5_DURABLE_PROCESS_CHANGED",
        )?;
        private_file(&self.file, self.namespace)?;
        private_directory(&self.directory)?;
        require(
            self.parent.canonicalize()? == self.parent,
            "ROOT_WITNESS_V5_DURABLE_PARENT_REPLACED",
        )?;
        let named_parent = fs::symlink_metadata(&self.parent)?;
        require(
            named_parent.is_dir()
                && identity(&named_parent) == identity(&self.directory.metadata()?),
            "ROOT_WITNESS_V5_DURABLE_PARENT_REPLACED",
        )?;
        let name = self
            .path
            .file_name()
            .ok_or_else(|| rejected("ROOT_WITNESS_V5_DURABLE_PATH"))?;
        let named = File::from(openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        private_file(&named, self.namespace)?;
        require(
            identity(&named.metadata()?) == identity(&self.file.metadata()?),
            "ROOT_WITNESS_V5_DURABLE_DATABASE_REPLACED",
        )
    }
    fn sync(&self) -> RootOwnerResultV3<()> {
        self.file.sync_all()?;
        self.directory.sync_all()?;
        self.check()
    }
}
fn identity(meta: &fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}
fn private_file(file: &File, namespace: Namespace) -> RootOwnerResultV3<()> {
    let meta = file.metadata()?;
    require(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.mode() & 0o7777 == 0o600
            && meta.len() <= namespace.maximum_bytes(),
        "ROOT_WITNESS_V5_DURABLE_FILE_IDENTITY",
    )
}
fn private_directory(file: &File) -> RootOwnerResultV3<()> {
    let meta = file.metadata()?;
    require(
        meta.is_dir()
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.mode() & 0o7777 == 0o700,
        "ROOT_WITNESS_V5_DURABLE_DIRECTORY_IDENTITY",
    )
}
