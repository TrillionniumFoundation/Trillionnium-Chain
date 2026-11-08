//! Epoch-scoped replay high water and separately charged active leases.
//! Expiry/withdrawal releases active quota, never the current epoch's high water.
//! Advancing the durable epoch atomically retires every old signed record.
//! This local owner does not resist complete host/database/clock rollback.
use super::super::directory_wait::{lock_before, with_sqlite_deadline};
use super::*;
#[cfg(unix)]
use fs2::FileExt;
#[cfg(unix)]
use rusqlite::OpenFlags;
use rusqlite::{params, Connection, TransactionBehavior};
#[cfg(unix)]
use std::fs::OpenOptions;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

const APPLICATION: i64 = 0x4344_5033;
const MAX_IDENTITIES: u64 = 512;
const MAX_ACTIVE_OWNER: u64 = 16;
const MAX_ACTIVE_MANIFEST: u64 = 16;
const MAX_ACTIVE_SOURCE: u64 = 64;
const MAX_ACTIVE_PREFIX: u64 = 128;
// Replay slots are separately bounded and last at most the current epoch.
// They are not active quota and do not claim permissionless Sybil fairness.
const MAX_REPLAY_OWNER: u64 = 64;
const MAX_REPLAY_MANIFEST: u64 = 64;
const MAX_REPLAY_SOURCE: u64 = 256;
const MAX_REPLAY_PREFIX: u64 = 512;
const MAX_PAGES: u64 = 4096;
const META: &str="CREATE TABLE discovery_meta_v3 (singleton INTEGER PRIMARY KEY CHECK(singleton=1),context BLOB NOT NULL CHECK(length(context)=128),authority BLOB NOT NULL CHECK(length(authority)=32),clock BLOB NOT NULL CHECK(length(clock)=8),epoch BLOB NOT NULL CHECK(length(epoch)=8),revision BLOB NOT NULL CHECK(length(revision)=8)) STRICT";
const RECORDS: &str="CREATE TABLE discovery_providers_v3 (manifest BLOB NOT NULL CHECK(length(manifest)=32),owner BLOB NOT NULL CHECK(length(owner)=32),sequence BLOB NOT NULL CHECK(length(sequence)=8),wire BLOB NOT NULL CHECK(length(wire)=3600),digest BLOB NOT NULL CHECK(length(digest)=32),source BLOB NOT NULL CHECK(length(source)=17),prefix BLOB NOT NULL CHECK(length(prefix)=17),PRIMARY KEY(manifest,owner)) STRICT";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellProviderDirectoryUsageV3 {
    /// These counts are evaluated at the last committed operation's clock.
    pub observed_unix_seconds: u64,
    pub lease_epoch: u64,
    pub active_identities: u64,
    pub tombstone_identities: u64,
    pub retained_identities: u64,
    pub maximum_identities: u64,
    pub retained_wire_bytes: u64,
    pub database_bytes: u64,
    pub maximum_database_bytes: u64,
    /// Main DB pages only: no total journal/disk/RSS reservation is implied.
    pub database_bound_includes_journal_or_rss: bool,
}

struct State {
    db: Connection,
    observed_revision: u64,
}
pub struct CellProviderDirectoryV3 {
    context: CellDiscoveryContextV1,
    keys: CellPqKeyPinsV2,
    path: PathBuf,
    identity: File,
    state: Mutex<State>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Metadata {
    clock: u64,
    epoch: u64,
    revision: u64,
}

impl CellProviderDirectoryV3 {
    #[cfg(not(unix))]
    pub fn open(
        _path: &Path,
        _context: CellDiscoveryContextV1,
        _keys: CellPqKeyPinsV2,
    ) -> CellResultV1<Self> {
        Err(CellErrorV1::Invalid("discovery file identity unsupported"))
    }

    #[cfg(unix)]
    pub fn open(
        path: &Path,
        context: CellDiscoveryContextV1,
        keys: CellPqKeyPinsV2,
    ) -> CellResultV1<Self> {
        context.validate()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()?;
        let path = parent.join(
            path.file_name()
                .ok_or(CellErrorV1::Invalid("discovery directory path"))?,
        );
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let identity = options.open(&path)?;
        FileExt::try_lock_exclusive(&identity)?;
        check_identity(&path, &identity)?;
        // SQLite separately opens the path. A retained File does not attest
        // SQLite's descriptor or defeat a same-privilege A -> B -> A race.
        let mut db = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(Duration::from_millis(100))?;
        db.pragma_update(None, "trusted_schema", false)?;
        let app: i64 = db.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if app == 0 && version == 0 {
            let count: i64 =
                db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
            require(count == 0, "foreign discovery database")?;
            let now = wall_now()?.as_secs();
            lease_epoch_end(now / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3)?;
            db.pragma_update(None, "page_size", 4096)?;
            db.pragma_update(None, "journal_mode", "DELETE")?;
            db.pragma_update(None, "synchronous", "FULL")?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(META)?;
            tx.execute_batch(RECORDS)?;
            tx.pragma_update(None, "application_id", APPLICATION)?;
            tx.pragma_update(None, "user_version", 3)?;
            require(
                tx.execute(
                    "INSERT INTO discovery_meta_v3 VALUES(1,?1,?2,?3,?4,?5)",
                    params![
                        context.encode(),
                        keys.digest().as_slice(),
                        now.to_be_bytes().as_slice(),
                        (now / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3)
                            .to_be_bytes()
                            .as_slice(),
                        0u64.to_be_bytes().as_slice()
                    ],
                )? == 1,
                "discovery initial metadata",
            )?;
            tx.commit()?;
            File::open(&parent)?.sync_all()?;
        }
        db.pragma_update(None, "synchronous", "FULL")?;
        db.pragma_update(None, "max_page_count", MAX_PAGES)?;
        db.pragma_update(None, "cache_size", -2048)?;
        db.pragma_update(None, "mmap_size", 0)?;
        validate_schema(&db)?;
        let meta = metadata(&db, context, keys.digest())?;
        check_identity(&path, &identity)?;
        Ok(Self {
            context,
            keys,
            path,
            identity,
            state: Mutex::new(State {
                db,
                observed_revision: meta.revision,
            }),
        })
    }

    pub(super) fn keys(&self) -> &CellPqKeyPinsV2 {
        &self.keys
    }

    /// Read-only diagnostic at the last committed clock, explicitly reported.
    /// Call `usage_at` with the owner's clock/deadline for current reclamation.
    pub fn usage(&self) -> CellResultV1<CellProviderDirectoryUsageV3> {
        let deadline = Instant::now() + Duration::from_secs(1);
        self.identity()?;
        let mut state = lock_before(&self.state, deadline)?;
        let State {
            db,
            observed_revision,
        } = &mut *state;
        let minimum = *observed_revision;
        with_sqlite_deadline(db, deadline, |db, wait| {
            let tx = db.transaction()?;
            wait.before_sql(&tx)?;
            validate_schema(&tx)?;
            let meta = metadata(&tx, self.context, self.keys.digest())?;
            require(
                meta.revision >= minimum,
                "discovery clock/revision rollback",
            )?;
            let rows = stored_rows(&tx, self.context, &self.keys, meta.epoch, deadline)?;
            check_quotas(&rows, meta.clock, &self.keys)?;
            let result = usage(&tx, &rows, meta, &self.keys)?;
            wait.before_sql(&tx)?;
            tx.commit()?;
            self.identity()?;
            check_deadline(deadline)?;
            // A diagnostic can reconcile a previously unknown committed write.
            // Once observed, that revision cannot be forgotten in this process.
            *observed_revision = meta.revision;
            Ok(result)
        })
    }

    /// Reconcile expiry/epoch under the caller's original deadline and persist
    /// the monotonic clock before reporting the returned active/tombstone counts.
    pub fn usage_at(
        &self,
        now: u64,
        deadline: Instant,
    ) -> CellResultV1<CellProviderDirectoryUsageV3> {
        self.current_epoch(now, deadline, |db, rows| {
            usage(
                db,
                rows,
                Metadata {
                    clock: now,
                    epoch: now / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3,
                    revision: 0,
                },
                &self.keys,
            )
        })
    }

    fn identity(&self) -> CellResultV1<()> {
        check_identity(&self.path, &self.identity)
    }

    // Only the network boundary, after actual ML-DSA verification, calls this.
    // Source is the actual accepted socket or authenticated queried bootstrap.
    pub(super) fn accept_verified(
        &self,
        record: &CellProviderRecordV3,
        source: IpAddr,
        now: u64,
        deadline: Instant,
    ) -> CellResultV1<()> {
        check_deadline(deadline)?;
        record.shape()?;
        record.live_at(now)?;
        require(
            record.statement.request.context == self.context,
            "discovery directory context",
        )?;
        // Verification and durable acceptance can straddle key expiry. This
        // cheap current roster check does not charge an unreserved signature.
        let pin = self
            .keys
            .pins()
            .find(|pin| pin.key_id == record.statement.owner)
            .ok_or(CellErrorV1::Invalid("PQ Cell unknown key"))?;
        require(
            pin.generation == record.statement.owner_generation,
            "PQ Cell key generation",
        )?;
        pin.live_at(now)?;
        self.current_epoch(now, deadline, |db, rows| {
            let s = &record.statement;
            let prior = rows.iter().position(|row| row.manifest == s.request.manifest && row.owner == s.owner);
            let source = match source {
                IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(source),
                _ => source,
            };
            let mut expected = Stored {
                manifest: s.request.manifest,
                owner: s.owner,
                sequence: s.sequence,
                wire: record.encode(),
                digest: record.digest(),
                source: ip_bytes(source),
                prefix: source_prefix(source),
                record: record.clone(),
            };
            if let Some(index) = prior {
                let old = &rows[index];
                require(old.record.statement.request == s.request, "discovery immutable pin")?;
                require(s.sequence >= old.sequence, "discovery sequence replay")?;
                expected.source = old.source;
                expected.prefix = old.prefix;
                if s.sequence == old.sequence {
                    require(old.digest == expected.digest, "discovery sequence equivocation")?;
                    // Equivalent randomized valid signatures retain the original bytes.
                    return Ok(());
                }
                let previous = old.clone();
                rows[index] = expected.clone();
                check_quotas(rows, now, &self.keys)?;
                require(db.execute("UPDATE discovery_providers_v3 SET sequence=?1,wire=?2,digest=?3 WHERE manifest=?4 AND owner=?5 AND sequence=?6 AND digest=?7",params![expected.sequence.to_be_bytes().as_slice(),&expected.wire,expected.digest.as_slice(),expected.manifest.as_slice(),expected.owner.as_slice(),previous.sequence.to_be_bytes().as_slice(),previous.digest.as_slice()])?==1,"discovery sequence CAS")?;
            } else {
                rows.push(expected.clone());
                rows.sort_by_key(|row| (row.manifest, row.owner));
                check_quotas(rows, now, &self.keys)?;
                require(db.execute("INSERT INTO discovery_providers_v3 VALUES(?1,?2,?3,?4,?5,?6,?7)",params![expected.manifest.as_slice(),expected.owner.as_slice(),expected.sequence.to_be_bytes().as_slice(),&expected.wire,expected.digest.as_slice(),expected.source.as_slice(),expected.prefix.as_slice()])?==1,"discovery record insert")?;
            }
            check_deadline(deadline)
        })
    }

    /// Complete bounded high water for the requested manifest in this epoch.
    /// Expired/withdrawn rows remain replay evidence, not eligible providers.
    pub(super) fn records(
        &self,
        request: CellDiscoveryRequestV1,
        now: u64,
        deadline: Instant,
    ) -> CellResultV1<Vec<CellProviderRecordV3>> {
        request.validate()?;
        require(
            request.context == self.context,
            "discovery directory context",
        )?;
        self.current_epoch(now, deadline, |_, rows| {
            Ok(rows
                .iter()
                .filter(|row| row.manifest == request.manifest)
                .map(|row| row.record.clone())
                .collect())
        })
    }

    fn current_epoch<T>(
        &self,
        now: u64,
        deadline: Instant,
        operation: impl FnOnce(&Connection, &mut Vec<Stored>) -> CellResultV1<T>,
    ) -> CellResultV1<T> {
        check_deadline(deadline)?;
        let epoch = now / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3;
        lease_epoch_end(epoch)?;
        self.identity()?;
        let mut state = lock_before(&self.state, deadline)?;
        let State {
            db,
            observed_revision,
        } = &mut *state;
        let minimum = *observed_revision;
        with_sqlite_deadline(db, deadline, |db, wait| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            wait.before_sql(&tx)?;
            validate_schema(&tx)?;
            let old = metadata(&tx, self.context, self.keys.digest())?;
            require(
                now >= old.clock && old.revision >= minimum,
                "discovery clock/revision rollback",
            )?;
            let mut rows = stored_rows(&tx, self.context, &self.keys, old.epoch, deadline)?;
            check_quotas(&rows, old.clock, &self.keys)?;
            if epoch > old.epoch {
                // Signed epoch validity, not an eviction guess, makes all old
                // sequence evidence irrelevant. Validate it before deleting it.
                check_deadline(deadline)?;
                require(
                    tx.execute("DELETE FROM discovery_providers_v3", [])? == rows.len(),
                    "discovery epoch retirement",
                )?;
                rows.clear();
            }
            let result = operation(&tx, &mut rows)?;
            check_deadline(deadline)?;
            check_quotas(&rows, now, &self.keys)?;
            let next = advance_clock(&tx, old, now)?;
            validate_schema(&tx)?;
            require(
                metadata(&tx, self.context, self.keys.digest())? == next
                    && stored_rows(&tx, self.context, &self.keys, epoch, deadline)? == rows,
                "discovery transaction readback",
            )?;
            self.identity()?;
            wait.before_sql(&tx)?;
            tx.commit()?;
            // A failed post-COMMIT check cannot rewind the durable epoch or
            // fabricate ACK. Re-entry reconciles the same committed record.
            self.identity()?;
            wait.before_sql(db)?;
            let readback = db.transaction()?;
            wait.before_sql(&readback)?;
            validate_schema(&readback)?;
            require(
                metadata(&readback, self.context, self.keys.digest())? == next
                    && stored_rows(&readback, self.context, &self.keys, epoch, deadline)? == rows,
                "discovery committed readback",
            )?;
            wait.before_sql(&readback)?;
            readback.commit()?;
            self.identity()?;
            *observed_revision = next.revision;
            check_deadline(deadline)?;
            Ok(result)
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
struct Stored {
    manifest: CellDigestV1,
    owner: CellDigestV1,
    sequence: u64,
    wire: Vec<u8>,
    digest: CellDigestV1,
    source: [u8; 17],
    prefix: [u8; 17],
    record: CellProviderRecordV3,
}
type RawStored = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);
fn stored_rows(
    db: &Connection,
    context: CellDiscoveryContextV1,
    keys: &CellPqKeyPinsV2,
    epoch: u64,
    deadline: Instant,
) -> CellResultV1<Vec<Stored>> {
    check_deadline(deadline)?;
    let mut query = db.prepare("SELECT substr(manifest,1,33),substr(owner,1,33),substr(sequence,1,9),substr(wire,1,3601),substr(digest,1,33),substr(source,1,18),substr(prefix,1,18) FROM discovery_providers_v3 ORDER BY manifest,owner LIMIT 513")?;
    let raw = query.query_map([], |r| {
        Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
        ))
    })?;
    let mut rows = Vec::new();
    for raw in raw {
        check_deadline(deadline)?;
        require(
            rows.len() < MAX_IDENTITIES as usize,
            "discovery capacity integrity",
        )?;
        let (manifest, owner, sequence, wire, digest, source, prefix): RawStored = raw?;
        let record = CellProviderRecordV3::decode(&wire)?;
        let row = Stored {
            manifest: fixed(manifest)?,
            owner: fixed(owner)?,
            sequence: u64::from_be_bytes(fixed(sequence)?),
            wire,
            digest: fixed(digest)?,
            source: fixed(source)?,
            prefix: fixed(prefix)?,
            record,
        };
        let s = &row.record.statement;
        require(
            s.request.context == context
                && s.lease_epoch == epoch
                && s.request.manifest == row.manifest
                && s.owner == row.owner
                && s.sequence == row.sequence
                && row.record.digest() == row.digest,
            "discovery stored key/epoch/identity",
        )?;
        require(
            keys.pins()
                .any(|pin| pin.key_id == s.owner && pin.generation == s.owner_generation),
            "discovery stored authority",
        )?;
        let mut endpoint = [0; 19];
        endpoint[..17].copy_from_slice(&row.source);
        endpoint[18] = 1;
        let source = decode_endpoint(endpoint)?.ip();
        require(
            ip_bytes(source) == row.source && source_prefix(source) == row.prefix,
            "discovery stored source prefix",
        )?;
        rows.push(row);
    }
    Ok(rows)
}

fn active(row: &Stored, now: u64, keys: &CellPqKeyPinsV2) -> bool {
    !row.record.statement.withdrawn
        && row.record.live_at(now).is_ok()
        && keys.pins().any(|pin| {
            pin.key_id == row.owner
                && pin.generation == row.record.statement.owner_generation
                && pin.live_at(now).is_ok()
        })
}

#[derive(Default)]
struct Counts {
    owner: BTreeMap<CellDigestV1, u64>,
    manifest: BTreeMap<CellDigestV1, u64>,
    source: BTreeMap<[u8; 17], u64>,
    prefix: BTreeMap<[u8; 17], u64>,
}
impl Counts {
    fn add(&mut self, row: &Stored) {
        *self.owner.entry(row.owner).or_default() += 1;
        *self.manifest.entry(row.manifest).or_default() += 1;
        *self.source.entry(row.source).or_default() += 1;
        *self.prefix.entry(row.prefix).or_default() += 1;
    }
    fn within(&self, owner: u64, manifest: u64, source: u64, prefix: u64) -> bool {
        self.owner.values().all(|count| *count <= owner)
            && self.manifest.values().all(|count| *count <= manifest)
            && self.source.values().all(|count| *count <= source)
            && self.prefix.values().all(|count| *count <= prefix)
    }
}
fn check_quotas(rows: &[Stored], now: u64, keys: &CellPqKeyPinsV2) -> CellResultV1<()> {
    let mut replay = Counts::default();
    let mut live = Counts::default();
    for row in rows {
        replay.add(row);
        if active(row, now, keys) {
            live.add(row);
        }
    }
    require(
        rows.len() <= MAX_IDENTITIES as usize
            && replay.within(
                MAX_REPLAY_OWNER,
                MAX_REPLAY_MANIFEST,
                MAX_REPLAY_SOURCE,
                MAX_REPLAY_PREFIX,
            )
            && live.within(
                MAX_ACTIVE_OWNER,
                MAX_ACTIVE_MANIFEST,
                MAX_ACTIVE_SOURCE,
                MAX_ACTIVE_PREFIX,
            ),
        "discovery identity capacity",
    )
}
fn usage(
    db: &Connection,
    rows: &[Stored],
    meta: Metadata,
    keys: &CellPqKeyPinsV2,
) -> CellResultV1<CellProviderDirectoryUsageV3> {
    let retained = rows.len() as u64;
    let active = rows
        .iter()
        .filter(|row| active(row, meta.clock, keys))
        .count() as u64;
    let pages: u64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
    Ok(CellProviderDirectoryUsageV3 {
        observed_unix_seconds: meta.clock,
        lease_epoch: meta.epoch,
        active_identities: active,
        tombstone_identities: retained - active,
        retained_identities: retained,
        maximum_identities: MAX_IDENTITIES,
        retained_wire_bytes: retained * CELL_PROVIDER_RECORD_BYTES_V3 as u64,
        database_bytes: pages * 4096,
        maximum_database_bytes: MAX_PAGES * 4096,
        database_bound_includes_journal_or_rss: false,
    })
}
fn fixed<const N: usize>(bytes: Vec<u8>) -> CellResultV1<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| CellErrorV1::Invalid("discovery stored field length"))
}
// Bounded raw columns in their schema order: context, authority, clock, epoch, revision.
type RawMetadata = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn metadata(
    db: &Connection,
    context: CellDiscoveryContextV1,
    authority: CellDigestV1,
) -> CellResultV1<Metadata> {
    let (actual,keys,clock,epoch,revision):RawMetadata=db.query_row("SELECT substr(context,1,129),substr(authority,1,33),substr(clock,1,9),substr(epoch,1,9),substr(revision,1,9) FROM discovery_meta_v3 WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    require(
        actual == context.encode() && keys == authority,
        "discovery persisted namespace/authority",
    )?;
    let meta = Metadata {
        clock: u64::from_be_bytes(fixed(clock)?),
        epoch: u64::from_be_bytes(fixed(epoch)?),
        revision: u64::from_be_bytes(fixed(revision)?),
    };
    lease_epoch_end(meta.epoch)?;
    require(
        meta.epoch == meta.clock / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3,
        "discovery stored clock/epoch",
    )?;
    Ok(meta)
}
fn advance_clock(db: &Connection, old: Metadata, now: u64) -> CellResultV1<Metadata> {
    let next = Metadata {
        clock: now,
        epoch: now / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3,
        revision: old
            .revision
            .checked_add(1)
            .ok_or(CellErrorV1::Invalid("discovery revision overflow"))?,
    };
    require(db.execute("UPDATE discovery_meta_v3 SET clock=?1,epoch=?2,revision=?3 WHERE singleton=1 AND clock=?4 AND epoch=?5 AND revision=?6",params![next.clock.to_be_bytes().as_slice(),next.epoch.to_be_bytes().as_slice(),next.revision.to_be_bytes().as_slice(),old.clock.to_be_bytes().as_slice(),old.epoch.to_be_bytes().as_slice(),old.revision.to_be_bytes().as_slice()])?==1,"discovery clock CAS")?;
    Ok(next)
}
fn validate_schema(db: &Connection) -> CellResultV1<()> {
    let app: i64 = db.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let journal: String = db.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    let page: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
    let maximum: u64 = db.pragma_query_value(None, "max_page_count", |r| r.get(0))?;
    let pages: u64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
    require(
        app == APPLICATION
            && version == 3
            && journal == "delete"
            && page == 4096
            && maximum == MAX_PAGES
            && pages <= MAX_PAGES,
        "discovery live namespace/resource mode",
    )?;
    let mut query=db.prepare("SELECT type,substr(name,1,64),substr(tbl_name,1,64),substr(sql,1,2048) FROM sqlite_schema ORDER BY name LIMIT 4")?;
    let actual = query
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = vec![
        (
            "table".into(),
            "discovery_meta_v3".into(),
            "discovery_meta_v3".into(),
            Some(META.into()),
        ),
        (
            "table".into(),
            "discovery_providers_v3".into(),
            "discovery_providers_v3".into(),
            Some(RECORDS.into()),
        ),
        (
            "index".into(),
            "sqlite_autoindex_discovery_providers_v3_1".into(),
            "discovery_providers_v3".into(),
            None,
        ),
    ];
    require(actual == expected, "discovery live schema")
}
fn source_prefix(ip: IpAddr) -> [u8; 17] {
    let mut key = ip_bytes(ip);
    if ip.is_ipv4() {
        key[16] = 0;
    } else {
        key[9..].fill(0);
    }
    key
}
fn check_identity(path: &Path, file: &File) -> CellResultV1<()> {
    let named = fs::symlink_metadata(path)?;
    let opened = file.metadata()?;
    require(
        named.is_file() && opened.is_file(),
        "discovery database type",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            named.dev() == opened.dev() && named.ino() == opened.ino() && opened.nlink() == 1,
            "discovery database identity",
        )
    }
    #[cfg(not(unix))]
    {
        Err(CellErrorV1::Invalid("discovery file identity unsupported"))
    }
}

#[cfg(all(test, unix))]
mod deadline_fixture {
    use super::*;
    use crate::cell::pq::CellPqKeyPinV2;
    use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
    use zeroize::Zeroizing;

    pub(super) type Directory = CellProviderDirectoryV3;
    pub(super) type Record = CellProviderRecordV3;
    pub(super) const META_TABLE: &str = "discovery_meta_v3";
    pub(super) const RECORD_TABLE: &str = "discovery_providers_v3";

    pub(super) fn fixture(path: &Path) -> (Directory, Record, Record, u64) {
        let context = CellDiscoveryContextV1 {
            namespace: [81; 32],
            network: [82; 32],
            parameters: [83; 32],
            genesis: [84; 32],
        };
        let request = CellDiscoveryRequestV1 {
            context,
            cell_context: [85; 32],
            manifest: [86; 32],
        };
        let seed = Zeroizing::new([87; 32]);
        let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
        let key_id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
        let key = PqNativeSigningKey::from_owned_seed(seed, key_id).unwrap();
        let keys = CellPqKeyPinsV2::new(vec![CellPqKeyPinV2 {
            key_id,
            generation: 1,
            spki,
            not_before: 1,
            expires_at: u64::MAX,
            revoked_at: None,
        }])
        .unwrap();
        let directory = Directory::open(path, context, keys).unwrap();
        let usage = directory.usage().unwrap();
        // Keep reopen under the same original synthetic operation clock.
        let now = if usage.retained_identities > 0 {
            usage.observed_unix_seconds
        } else {
            (usage.lease_epoch + 1) * CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3 + 10
        };
        let record = |sequence| {
            let record = CellProviderRecordV3::sign(
                CellProviderStatementV3 {
                    request,
                    owner: key_id,
                    owner_generation: 1,
                    endpoint: "127.0.0.1:19081".parse().unwrap(),
                    sequence,
                    lease_epoch: now / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3,
                    issued_unix_seconds: now,
                    expires_unix_seconds: now + 240,
                    withdrawn: false,
                },
                &key,
            )
            .unwrap();
            record
                .verify_at(
                    request,
                    now,
                    &CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![19081] },
                    directory.keys(),
                )
                .unwrap();
            record
        };
        let first = record(1);
        let second = record(2);
        (directory, first, second, now)
    }
}

#[cfg(all(test, unix))]
mod deadline_tests {
    crate::cell::discovery::directory_deadline_tests::declare_tests!();
}
