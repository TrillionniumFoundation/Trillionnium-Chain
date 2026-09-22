//! Owner-consuming schema0 retirement. Child of sqlite to share the exact
//! existing namespace pin/audit machinery without widening that public API.
use super::*;
use crate::{
    ExternalSignerRetirementV1, SignerRetirementHostCutV1, SignerRetirementRecordV1,
    StrictOldSetHandoffAdmissionV1,
};
use trnm_consensus_crypto::StrictPreHandoffContextV1;
use trnm_consensus_types::CanonicalHandoffSignIntentV1;
const RETIRE_SQL: &str = include_str!("retirement_schema_v1.sql");

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerRetirementCutV1 {
    AfterLocalWriteBeforeCommit,
    AfterLocalCommitBeforeSync,
    AfterLocalSyncBeforeExternal,
    AfterExternalBeforeReadback,
}

/// Affine terminal readback, never ordinary signing or new-epoch authority.
/// Constructed only by the real retired owner after local and external reads.
pub struct ConfirmedOrdinarySignerRetirementV1 {
    record: SignerRetirementRecordV1,
    owner: Arc<()>,
}
impl ConfirmedOrdinarySignerRetirementV1 {
    pub const fn record_v1(&self) -> &SignerRetirementRecordV1 {
        &self.record
    }
    /// Fresh local image comparison only, after independent external checks.
    /// It preserves original affinity and never creates a signing/recovery owner.
    pub fn confirm_local_owner_v1<W: ExternalSignerRetirementV1>(
        &self,
        owner: &RetiredSqliteSignerJournalV1<W>,
    ) -> Result<(), SignerJournalErrorV0> {
        if !Arc::ptr_eq(&self.owner, &owner.owner)
            || self.record != owner.record
            || owner.read_record_fresh()? != self.record
        {
            return malformed("retirement local owner comparison differs");
        }
        Ok(())
    }
    pub fn belongs_to_owner_v1<W: ExternalSignerRetirementV1>(
        &self,
        owner: &mut RetiredSqliteSignerJournalV1<W>,
    ) -> bool {
        Arc::ptr_eq(&self.owner, &owner.owner)
            && owner.require_exact_retirement_v1(&self.record).is_ok()
    }
}
impl ConfirmedSignerNodeCheckpointFactsV0 {
    /// Checks a live commissioning capability against the same owner after
    /// consuming its ordinary API. This is identity evidence only: callers
    /// still need fresh local/external retirement confirmation. It deliberately
    /// rejects a reopened owner, even when scalar journal fields are identical.
    pub fn belongs_to_retired_journal_at_path_v1<W: ExternalSignerRetirementV1>(
        &self,
        retired: &RetiredSqliteSignerJournalV1<W>,
        expected_path: &Path,
    ) -> bool {
        let source = retired.record.source_v1();
        Arc::ptr_eq(&self.owner_affinity, &retired.owner)
            && retired.path_v1() == expected_path
            && retired.journal_id == self.journal_id()
            && retired.profile.profile_checksum() == self.profile_checksum()
            && SignerNodeCheckpointIdentityV0::from_profile(&retired.profile) == self.identity()
            && source.scope() == self.exact_watermark().scope()
            && source.journal_id() == self.journal_id()
            && source.sequence() >= self.exact_watermark().sequence()
            && retired.ensure_namespace().is_ok()
    }
}

struct RetirementPinV1 {
    file: File,
    path: PathBuf,
    identity: FileIdentityV0,
    directory: bool,
}
impl RetirementPinV1 {
    fn require_unchanged(&self) -> Result<(), SignerJournalErrorV0> {
        let (named, opened) = if self.directory {
            (
                directory_identity(&self.path)?,
                directory_handle_identity(&self.file)?,
            )
        } else {
            (
                file_identity(&self.path)?,
                file_handle_identity(&self.file)?,
            )
        };
        if named != self.identity || opened != self.identity {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::FileIdentityChanged,
            ));
        }
        Ok(())
    }
}
/// Holds every original inode/lock but has no ordinary signing API and no live
/// SQLite connection. Reopening is existing-only and never restores schema0.
pub struct RetiredSqliteSignerJournalV1<W> {
    pins: [RetirementPinV1; 5],
    profile: SignerJournalProfileV0,
    external: W,
    journal_id: [u8; 32],
    owner: Arc<()>,
    pid: u32,
    record: SignerRetirementRecordV1,
}

impl<W: ExternalSignerRetirementV1> SqliteSignerJournalV0<W> {
    pub fn retire_for_handoff_v1(
        self,
        context: &StrictPreHandoffContextV1,
        intent: &CanonicalHandoffSignIntentV1,
        host: SignerRetirementHostCutV1,
    ) -> Result<RetiredSqliteSignerJournalV1<W>, SignerJournalErrorV0> {
        self.retire_with_observer_v1(context, intent, host, |_| Ok(()))
    }
    /// Consumes the owner even when an error leaves commit/CAS uncertainty.
    /// An exact retired reopen is the sole recovery path after local commit.
    #[doc(hidden)]
    pub fn retire_with_observer_v1(
        mut self,
        context: &StrictPreHandoffContextV1,
        intent: &CanonicalHandoffSignIntentV1,
        host: SignerRetirementHostCutV1,
        mut observer: impl FnMut(SignerRetirementCutV1) -> Result<(), SignerJournalErrorV0>,
    ) -> Result<RetiredSqliteSignerJournalV1<W>, SignerJournalErrorV0> {
        self.ensure_operational()?;
        self.validate_database()?;
        self.synchronize_external_head()?;
        self.require_no_pending_intent()?;
        validate_retirement_context(&self.profile, context, intent)?;
        let capacity = read_capacity(&self.connection)?;
        if capacity
            .maximum_safety_revision
            .is_some_and(|r| host.safety_revision <= r)
        {
            return malformed("retirement Safety revision does not follow ordinary custody");
        }
        let source = self.watermark_for(self.observed_head)?;
        let record = make_record(&self.profile, source, context, intent, host)?;
        // No retirement under a previously retired external scope, even if a
        // restored local schema0 image still looks internally self-consistent.
        if self
            .external_watermark
            .load_signer_retirement_v1(source.scope())
            .map_err(|e| SignerJournalErrorV0::external("preflight external retirement", e))?
            .is_some()
        {
            return malformed("old scope is already retired");
        }
        {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| SignerJournalErrorV0::sqlite("begin ordinary retirement", e))?;
            tx.execute_batch(RETIRE_SQL)
                .map_err(|e| SignerJournalErrorV0::sqlite("install retired schema2", e))?;
            tx.execute(
                "INSERT INTO signer_retirement_v1 VALUES(1,?1)",
                [record.encode_v1().as_slice()],
            )
            .map_err(|e| SignerJournalErrorV0::sqlite("append retirement record", e))?;
            tx.pragma_update(None, "user_version", 2)
                .map_err(|e| SignerJournalErrorV0::sqlite("mark retired schema2", e))?;
            observer(SignerRetirementCutV1::AfterLocalWriteBeforeCommit)?;
            tx.commit()
                .map_err(|e| SignerJournalErrorV0::sqlite("commit ordinary retirement", e))?;
        }
        observer(SignerRetirementCutV1::AfterLocalCommitBeforeSync)?;
        self.ensure_file_identity()?;
        for f in [
            &self.database_file,
            &self.wal_file,
            &self.shm_file,
            &self.lock_file,
            &self.directory_file,
        ] {
            f.sync_all()
                .map_err(|e| SignerJournalErrorV0::io("sync ordinary retirement", e))?;
        }
        self.ensure_file_identity()?;
        let mut retired = RetiredSqliteSignerJournalV1::from_consumed(self, record)?;
        retired.read_record_fresh()?;
        observer(SignerRetirementCutV1::AfterLocalSyncBeforeExternal)?;
        retired.advance_external_exact()?;
        observer(SignerRetirementCutV1::AfterExternalBeforeReadback)?;
        retired.require_exact_retirement_v1(&record)?;
        Ok(retired)
    }
}
impl<W: ExternalSignerRetirementV1> RetiredSqliteSignerJournalV1<W> {
    fn from_consumed(
        source: SqliteSignerJournalV0<W>,
        record: SignerRetirementRecordV1,
    ) -> Result<Self, SignerJournalErrorV0> {
        let SqliteSignerJournalV0 {
            connection,
            database_file,
            lock_file,
            wal_file,
            shm_file,
            directory_file,
            database_path,
            lock_path,
            directory_path,
            database_identity,
            lock_identity,
            wal_identity,
            shm_identity,
            directory_identity,
            profile,
            external_watermark,
            journal_id,
            observed_head: _,
            owner_pid,
            owner_affinity,
        } = source;
        connection
            .close()
            .map_err(|(_, e)| SignerJournalErrorV0::sqlite("close retired writer", e))?;
        let wal_path = sqlite_auxiliary_path(&database_path, "-wal");
        let shm_path = sqlite_auxiliary_path(&database_path, "-shm");
        let pins = [
            RetirementPinV1 {
                file: database_file,
                path: database_path,
                identity: database_identity,
                directory: false,
            },
            RetirementPinV1 {
                file: lock_file,
                path: lock_path,
                identity: lock_identity,
                directory: false,
            },
            RetirementPinV1 {
                file: wal_file,
                path: wal_path,
                identity: wal_identity,
                directory: false,
            },
            RetirementPinV1 {
                file: shm_file,
                path: shm_path,
                identity: shm_identity,
                directory: false,
            },
            RetirementPinV1 {
                file: directory_file,
                path: directory_path,
                identity: directory_identity,
                directory: true,
            },
        ];
        let result = Self {
            pins,
            profile,
            external: external_watermark,
            journal_id,
            owner: owner_affinity,
            pid: owner_pid,
            record,
        };
        result.ensure_namespace()?;
        for pin in &result.pins {
            pin.file
                .sync_all()
                .map_err(|e| SignerJournalErrorV0::io("sync closed retired namespace", e))?;
        }
        result.ensure_namespace()?;
        Ok(result)
    }
    /// Requires the independently selected exact retirement record plus fresh
    /// strict context. It accepts external source/target uncertainty, never an
    /// ordinary owner, and creates/repairs no namespace files.
    pub fn open_existing_v1(
        path: impl AsRef<Path>,
        profile: SignerJournalProfileV0,
        external: W,
        expected: SignerRetirementRecordV1,
        context: &StrictPreHandoffContextV1,
        intent: &CanonicalHandoffSignIntentV1,
    ) -> Result<Self, SignerJournalErrorV0> {
        ensure_supported_platform()?;
        validate_retirement_context(&profile, context, intent)?;
        if expected
            != make_record(
                &profile,
                expected.source_v1(),
                context,
                intent,
                expected.host_cut_v1(),
            )?
        {
            return malformed("foreign retirement record");
        }
        let path = canonical_existing_database_path(path.as_ref())?;
        require_auxiliary_files(&path)?;
        let directory = path
            .parent()
            .ok_or(SignerJournalErrorV0::InvalidProfile("retired directory"))?
            .to_path_buf();
        let lock_path = lock_path_for(&path)?;
        let database_file = open_existing_private_file(&path, "pin retired database")?;
        let lock_file = open_existing_private_file(&lock_path, "pin retired lock")?;
        acquire_lifetime_lock(&lock_file)?;
        acquire_lifetime_lock(&database_file)?;
        let (wal, wal_identity, shm, shm_identity) =
            pin_auxiliary_files(&path, profile.maximum_database_bytes())?;
        let directory_file = File::open(&directory)
            .map_err(|e| SignerJournalErrorV0::io("pin retired directory", e))?;
        let pins = [
            RetirementPinV1 {
                identity: file_handle_identity(&database_file)?,
                file: database_file,
                path: path.clone(),
                directory: false,
            },
            RetirementPinV1 {
                identity: file_handle_identity(&lock_file)?,
                file: lock_file,
                path: lock_path,
                directory: false,
            },
            RetirementPinV1 {
                file: wal,
                path: sqlite_auxiliary_path(&path, "-wal"),
                identity: wal_identity,
                directory: false,
            },
            RetirementPinV1 {
                file: shm,
                path: sqlite_auxiliary_path(&path, "-shm"),
                identity: shm_identity,
                directory: false,
            },
            RetirementPinV1 {
                identity: directory_handle_identity(&directory_file)?,
                file: directory_file,
                path: directory,
                directory: true,
            },
        ];
        let mut result = Self {
            pins,
            profile,
            external,
            journal_id: expected.source_v1().journal_id(),
            owner: Arc::new(()),
            pid: std::process::id(),
            record: expected,
        };
        result.read_record_fresh()?;
        // Observe only. Explicit confirm below may repair the local-first CAS
        // window; callers may join other owner cuts before requesting it.
        match result
            .external
            .load_signer_retirement_v1(expected.source_v1().scope())
        {
            // An unavailable or mode-first pending authority does not authorize
            // anything. Keep only this inert local owner; explicit confirm must
            // complete the exact external CAS and readback before any receipt.
            Err(ExternalWatermarkErrorV0::Unavailable) => {}
            Err(e) => {
                return Err(SignerJournalErrorV0::external(
                    "observe external retirement",
                    e,
                ))
            }
            Ok(Some(actual)) if actual == expected => {}
            Ok(Some(_)) => return malformed("foreign external retirement"),
            Ok(None) => {
                let c = Connection::open_with_flags(
                    &result.pins[0].path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY
                        | OpenFlags::SQLITE_OPEN_NO_MUTEX
                        | OpenFlags::SQLITE_OPEN_NOFOLLOW,
                )
                .map_err(|e| SignerJournalErrorV0::sqlite("open source comparison", e))?;
                configure_pinned_read_only_connection(&c)?;
                let head = load_external_head_v0(
                    &mut result.external,
                    result.profile.external_watermark_scope(),
                    result.journal_id,
                    &c,
                )
                .map_err(|e| SignerJournalErrorV0::external("read retirement predecessor", e));
                c.close()
                    .map_err(|(_, e)| SignerJournalErrorV0::sqlite("close source comparison", e))?;
                if head? != Some(expected.source_v1()) {
                    return malformed("external retirement predecessor differs");
                }
            }
        }
        result.ensure_namespace()?;
        Ok(result)
    }
    pub fn path_v1(&self) -> &Path {
        &self.pins[0].path
    }
    pub const fn profile_v1(&self) -> &SignerJournalProfileV0 {
        &self.profile
    }
    pub const fn record_v1(&self) -> &SignerRetirementRecordV1 {
        &self.record
    }
    pub fn confirm_retirement_v1(
        &mut self,
    ) -> Result<ConfirmedOrdinarySignerRetirementV1, SignerJournalErrorV0> {
        self.read_record_fresh()?;
        self.advance_external_exact()?;
        let expected = self.record;
        self.require_exact_retirement_v1(&expected)?;
        Ok(ConfirmedOrdinarySignerRetirementV1 {
            record: expected,
            owner: Arc::clone(&self.owner),
        })
    }
    /// Freshly proves that an independently pinned earlier ordinary watermark
    /// is an exact prefix of this retired journal. A lower sequence alone is
    /// insufficient. The image audit and event read share one SQLite snapshot.
    pub fn confirms_ordinary_prefix_v1(
        &mut self,
        prefix: SignerWatermarkV0,
    ) -> Result<bool, SignerJournalErrorV0> {
        let record = self.record;
        if prefix.scope() != record.source_v1().scope()
            || prefix.journal_id() != self.journal_id
            || prefix.sequence() > record.source_v1().sequence()
        {
            return Ok(false);
        }
        self.require_exact_retirement_v1(&record)?;
        let c = Connection::open_with_flags(
            &self.pins[0].path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|e| SignerJournalErrorV0::sqlite("open retired prefix", e))?;
        configure_pinned_read_only_connection(&c)?;
        c.execute_batch("BEGIN DEFERRED")
            .map_err(|e| SignerJournalErrorV0::sqlite("begin retired prefix snapshot", e))?;
        validate_retired_image(&c, &self.profile, self.journal_id, record)?;
        let actual = if prefix.sequence() == 0 {
            Some(initial_head(&self.profile, self.journal_id))
        } else {
            read_event(&c, prefix.sequence())?.map(|event| JournalHeadV0 {
                sequence: event.sequence,
                chain_checksum: event.chain_checksum,
            })
        };
        let exact = actual
            .map(|head| watermark_for_parts(&self.profile, self.journal_id, head))
            .transpose()?
            == Some(prefix);
        c.execute_batch("COMMIT")
            .map_err(|e| SignerJournalErrorV0::sqlite("end retired prefix snapshot", e))?;
        c.close()
            .map_err(|(_, e)| SignerJournalErrorV0::sqlite("close retired prefix", e))?;
        self.require_exact_retirement_v1(&record)?;
        Ok(exact)
    }

    fn advance_external_exact(&mut self) -> Result<(), SignerJournalErrorV0> {
        self.ensure_namespace()?;
        let target = self
            .external
            .retire_signer_exact_v1(&self.record)
            .map_err(|e| SignerJournalErrorV0::external("advance external terminal cut", e))?;
        if target != self.record.terminal_watermark_v1() {
            return malformed("external terminal CAS target");
        }
        Ok(())
    }
    fn require_exact_retirement_v1(
        &mut self,
        expected: &SignerRetirementRecordV1,
    ) -> Result<(), SignerJournalErrorV0> {
        if expected != &self.record {
            return malformed("retirement capability record differs");
        }
        self.read_record_fresh()?;
        if self
            .external
            .load_signer_retirement_v1(expected.source_v1().scope())
            .map_err(|e| SignerJournalErrorV0::external("fresh terminal readback", e))?
            != Some(*expected)
        {
            return malformed("fresh external retirement differs");
        }
        self.ensure_namespace()
    }
    fn ensure_namespace(&self) -> Result<(), SignerJournalErrorV0> {
        if self.pid != std::process::id() {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::ProcessChanged,
            ));
        }
        for pin in &self.pins {
            pin.require_unchanged()?;
        }
        Ok(())
    }
    fn read_record_fresh(&self) -> Result<SignerRetirementRecordV1, SignerJournalErrorV0> {
        self.ensure_namespace()?;
        validate_storage_resource_bounds(&self.pins[0].path, &self.profile)?;
        let c = Connection::open_with_flags(
            &self.pins[0].path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|e| SignerJournalErrorV0::sqlite("fresh retired read", e))?;
        configure_pinned_read_only_connection(&c)?;
        let value = validate_retired_image(&c, &self.profile, self.journal_id, self.record);
        c.close()
            .map_err(|(_, e)| SignerJournalErrorV0::sqlite("close retired read", e))?;
        self.ensure_namespace()?;
        value
    }
}
fn validate_retirement_context(
    profile: &SignerJournalProfileV0,
    context: &StrictPreHandoffContextV1,
    intent: &CanonicalHandoffSignIntentV1,
) -> Result<(), SignerJournalErrorV0> {
    if profile.validator_set() != context.old_validator_set()
        || profile.author() != intent.validator_id()
    {
        return malformed("retirement old role/profile mismatch");
    }
    StrictOldSetHandoffAdmissionV1::from_verified_context(intent, context)
        .map_err(|_| SignerJournalErrorV0::InvalidProfile("strict old handoff intent required"))?;
    Ok(())
}
fn make_record(
    profile: &SignerJournalProfileV0,
    source: SignerWatermarkV0,
    context: &StrictPreHandoffContextV1,
    intent: &CanonicalHandoffSignIntentV1,
    host: SignerRetirementHostCutV1,
) -> Result<SignerRetirementRecordV1, SignerJournalErrorV0> {
    if source.scope() != profile.external_watermark_scope() {
        return malformed("retirement source scope");
    }
    SignerRetirementRecordV1::new(
        source,
        host,
        context.binding_ref(),
        *intent.preimage().descriptor_digest().as_bytes(),
        *intent.fingerprint().as_bytes(),
        profile.profile_checksum(),
    )
    .map_err(|e| SignerJournalErrorV0::external("retirement field bounds", e))
}
fn validate_retired_image(
    c: &Connection,
    profile: &SignerJournalProfileV0,
    journal: [u8; 32],
    expected: SignerRetirementRecordV1,
) -> Result<SignerRetirementRecordV1, SignerJournalErrorV0> {
    validate_pinned_read_only_environment(c)?;
    validate_retired_schema_v1(c)?;
    if read_and_validate_metadata(c, profile)? != journal {
        return Err(SignerJournalErrorV0::MetadataMismatch);
    }
    validate_integrity(c)?;
    validate_all_records(c, profile, journal)?;
    if read_pending_intent_facts(c)?.is_some() {
        return malformed("retired signer contains an unresolved intent");
    }
    if watermark_for_parts(profile, journal, read_head(c, journal)?)? != expected.source_v1() {
        return malformed("retired source event head differs");
    }
    let (count, size): (i64, i64) = c
        .query_row(
            "SELECT count(*),coalesce(max(length(record)),0) FROM signer_retirement_v1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|e| SignerJournalErrorV0::sqlite("retirement row bounds", e))?;
    if count != 1 || size != crate::SIGNER_RETIREMENT_RECORD_BYTES_V1 as i64 {
        return malformed("retirement row count/size");
    }
    let bytes: Vec<u8> = c
        .query_row(
            "SELECT record FROM signer_retirement_v1 WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(|e| SignerJournalErrorV0::sqlite("retirement readback", e))?;
    let actual = SignerRetirementRecordV1::decode_v1_exact(&bytes)
        .map_err(|e| SignerJournalErrorV0::external("retirement exact decoder", e))?;
    if actual != expected {
        return malformed("retirement record differs from independent expected cut");
    }
    Ok(actual)
}
fn malformed<T>(why: &'static str) -> Result<T, SignerJournalErrorV0> {
    Err(SignerJournalErrorV0::PersistedRepresentationMalformed(why))
}

pub(crate) fn validate_retired_schema_v1(c: &Connection) -> Result<(), SignerJournalErrorV0> {
    let version: i64 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| SignerJournalErrorV0::sqlite("retired schema version", e))?;
    if version != 2 {
        return malformed("ordinary namespace has no retired schema2");
    }
    let reference = Connection::open_in_memory()
        .map_err(|e| SignerJournalErrorV0::sqlite("retired schema reference", e))?;
    reference
        .execute_batch(crate::schema::JOURNAL_SCHEMA_SQL_V0)
        .and_then(|_| reference.execute_batch(RETIRE_SQL))
        .map_err(|e| SignerJournalErrorV0::sqlite("retired exact schema reference", e))?;
    if crate::schema::schema_objects(c)? != crate::schema::schema_objects(&reference)? {
        return Err(SignerJournalErrorV0::SchemaMismatch);
    }
    Ok(())
}
