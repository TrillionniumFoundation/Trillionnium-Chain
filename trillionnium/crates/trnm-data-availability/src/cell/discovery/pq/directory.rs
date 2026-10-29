//! Fixed-capacity replay high water. Expiry does not delete identities or release
//! their quotas. This local owner does not resist complete host/database rollback.
use super::*;
#[cfg(unix)]
use fs2::FileExt;
#[cfg(unix)]
use rusqlite::OpenFlags;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
#[cfg(unix)]
use std::{fs::OpenOptions, time::Duration};
use std::{
    fs::{self, File},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Instant,
};

const APPLICATION: i64 = 0x4344_5032;
const MAX_IDENTITIES: u64 = 512;
const MAX_OWNER: u64 = 16;
const MAX_MANIFEST: u64 = 16;
const MAX_SOURCE: u64 = 64;
const MAX_PREFIX: u64 = 128;
const MAX_PAGES: u64 = 4096;
const META: &str="CREATE TABLE discovery_meta_v2 (singleton INTEGER PRIMARY KEY CHECK(singleton=1),context BLOB NOT NULL CHECK(length(context)=128),authority BLOB NOT NULL CHECK(length(authority)=32),clock BLOB NOT NULL CHECK(length(clock)=8),revision BLOB NOT NULL CHECK(length(revision)=8)) STRICT";
const RECORDS: &str="CREATE TABLE discovery_providers_v2 (manifest BLOB NOT NULL CHECK(length(manifest)=32),owner BLOB NOT NULL CHECK(length(owner)=32),sequence BLOB NOT NULL CHECK(length(sequence)=8),wire BLOB NOT NULL CHECK(length(wire)=3592),digest BLOB NOT NULL CHECK(length(digest)=32),source BLOB NOT NULL CHECK(length(source)=17),prefix BLOB NOT NULL CHECK(length(prefix)=17),PRIMARY KEY(manifest,owner)) STRICT";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellProviderDirectoryUsageV2 {
    pub retained_identities: u64,
    pub maximum_identities: u64,
    pub retained_wire_bytes: u64,
    pub database_bytes: u64,
    pub maximum_database_bytes: u64,
    /// Main DB pages are bounded; this is not a total disk/RSS reservation.
    /// DELETE rollback journal, filesystem metadata, SQLite buffers and
    /// transient query/signature allocations are reported as outside this cap.
    pub database_bound_includes_journal_or_rss: bool,
}

struct State {
    db: Connection,
    observed_revision: u64,
}
pub struct CellProviderDirectoryV2 {
    context: CellDiscoveryContextV1,
    keys: CellPqKeyPinsV2,
    path: PathBuf,
    identity: File,
    state: Mutex<State>,
}

impl CellProviderDirectoryV2 {
    /// This development owner currently requires Unix file identity and locking.
    /// Unsupported platforms fail before opening or creating any path.
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let identity = options.open(&path)?;
        FileExt::try_lock_exclusive(&identity)?;
        check_identity(&path, &identity)?;
        // SQLite opens this path separately: the retained File is not proof of
        // SQLite's own descriptor identity. These checks detect an observed
        // stable replacement, not an adversarial A -> B -> A swap during open.
        // The hosting filesystem namespace must not be controlled by an attacker.
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
            db.pragma_update(None, "page_size", 4096)?;
            db.pragma_update(None, "journal_mode", "DELETE")?;
            db.pragma_update(None, "synchronous", "FULL")?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(META)?;
            tx.execute_batch(RECORDS)?;
            tx.pragma_update(None, "application_id", APPLICATION)?;
            tx.pragma_update(None, "user_version", 2)?;
            require(
                tx.execute(
                    "INSERT INTO discovery_meta_v2 VALUES(1,?1,?2,?3,?4)",
                    params![
                        context.encode(),
                        keys.digest().as_slice(),
                        wall_now()?.as_secs().to_be_bytes().as_slice(),
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
        let (_, revision) = metadata(&db, context, keys.digest())?;
        check_identity(&path, &identity)?;
        Ok(Self {
            context,
            keys,
            path,
            identity,
            state: Mutex::new(State {
                db,
                observed_revision: revision,
            }),
        })
    }

    pub(super) fn keys(&self) -> &CellPqKeyPinsV2 {
        &self.keys
    }

    pub fn usage(&self) -> CellResultV1<CellProviderDirectoryUsageV2> {
        self.identity()?;
        let state = self
            .state
            .lock()
            .map_err(|_| CellErrorV1::Invalid("discovery owner poisoned"))?;
        validate_schema(&state.db)?;
        metadata(&state.db, self.context, self.keys.digest())?;
        let retained: u64 =
            state
                .db
                .query_row("SELECT count(*) FROM discovery_providers_v2", [], |r| {
                    r.get(0)
                })?;
        require(retained <= MAX_IDENTITIES, "discovery capacity integrity")?;
        let pages: u64 = state
            .db
            .pragma_query_value(None, "page_count", |r| r.get(0))?;
        self.identity()?;
        Ok(CellProviderDirectoryUsageV2 {
            retained_identities: retained,
            maximum_identities: MAX_IDENTITIES,
            retained_wire_bytes: retained * CELL_PROVIDER_RECORD_BYTES_V2 as u64,
            database_bytes: pages * 4096,
            maximum_database_bytes: MAX_PAGES * 4096,
            database_bound_includes_journal_or_rss: false,
        })
    }
    fn identity(&self) -> CellResultV1<()> {
        check_identity(&self.path, &self.identity)
    }

    // Called only after the network boundary verifies the actual signed record.
    // The source is the accepted socket or the queried bootstrap, never a field
    // supplied by an advertiser. No network operation occurs while this locks.
    pub(super) fn accept_verified(
        &self,
        record: &CellProviderRecordV2,
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
        self.identity()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CellErrorV1::Invalid("discovery owner poisoned"))?;
        let minimum = state.observed_revision;
        let tx = state
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_schema(&tx)?;
        let (clock, revision) = metadata(&tx, self.context, self.keys.digest())?;
        require(
            now >= clock && revision >= minimum,
            "discovery clock/revision rollback",
        )?;
        let prior = stored(
            &tx,
            record.statement.request.manifest,
            record.statement.owner,
        )?;
        let source = match source {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(source),
            _ => source,
        };
        let mut origin = ip_bytes(source);
        let mut prefix = source_prefix(source);
        let mut wire = record.encode();
        let digest = record.digest();
        let sequence = record.statement.sequence.to_be_bytes();
        if let Some(prior) = &prior {
            origin = prior.source;
            prefix = prior.prefix;
            let old = prior.record()?;
            require(
                old.statement.request == record.statement.request,
                "discovery immutable pin",
            )?;
            require(
                record.statement.sequence >= old.statement.sequence,
                "discovery sequence replay",
            )?;
            if record.statement.sequence == old.statement.sequence {
                require(prior.digest == digest, "discovery sequence equivocation")?;
                // Keep the original durable signature when an equivalent
                // randomized valid signature is presented at the same seq.
                wire = prior.wire.clone();
            } else {
                require(tx.execute("UPDATE discovery_providers_v2 SET sequence=?1,wire=?2,digest=?3 WHERE manifest=?4 AND owner=?5 AND sequence=?6 AND digest=?7",params![sequence.as_slice(),&wire,digest.as_slice(),record.statement.request.manifest.as_slice(),record.statement.owner.as_slice(),prior.sequence.to_be_bytes().as_slice(),prior.digest.as_slice()])?==1,"discovery sequence CAS")?;
            }
        } else {
            let counts:(u64,u64,u64,u64,u64)=tx.query_row("SELECT count(*),coalesce(sum(owner=?1),0),coalesce(sum(manifest=?2),0),coalesce(sum(source=?3),0),coalesce(sum(prefix=?4),0) FROM discovery_providers_v2",params![record.statement.owner.as_slice(),record.statement.request.manifest.as_slice(),origin.as_slice(),prefix.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
            require(
                counts.0 < MAX_IDENTITIES
                    && counts.1 < MAX_OWNER
                    && counts.2 < MAX_MANIFEST
                    && counts.3 < MAX_SOURCE
                    && counts.4 < MAX_PREFIX,
                "discovery identity capacity",
            )?;
            require(
                tx.execute(
                    "INSERT INTO discovery_providers_v2 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        record.statement.request.manifest.as_slice(),
                        record.statement.owner.as_slice(),
                        sequence.as_slice(),
                        &wire,
                        digest.as_slice(),
                        origin.as_slice(),
                        prefix.as_slice()
                    ],
                )? == 1,
                "discovery record insert",
            )?;
        }
        let next = advance_clock(&tx, clock, revision, now)?;
        validate_schema(&tx)?;
        let expected = Stored {
            sequence: record.statement.sequence,
            wire,
            digest,
            source: origin,
            prefix,
        };
        require(
            stored(
                &tx,
                record.statement.request.manifest,
                record.statement.owner,
            )?
            .as_ref()
                == Some(&expected),
            "discovery transaction readback",
        )?;
        require(
            metadata(&tx, self.context, self.keys.digest())? == (now, next),
            "discovery transaction clock readback",
        )?;
        self.identity()?;
        check_deadline(deadline)?;
        tx.commit()?;
        // The durable high water remains committed on a failed post-COMMIT
        // check. Retry reconciles it; no caller receives a fabricated ACK.
        self.identity()?;
        let readback = state.db.transaction()?;
        validate_schema(&readback)?;
        require(
            metadata(&readback, self.context, self.keys.digest())? == (now, next)
                && stored(
                    &readback,
                    record.statement.request.manifest,
                    record.statement.owner,
                )?
                .as_ref()
                    == Some(&expected),
            "discovery committed readback",
        )?;
        readback.commit()?;
        self.identity()?;
        state.observed_revision = next;
        check_deadline(deadline)
    }

    pub(super) fn records(
        &self,
        request: CellDiscoveryRequestV1,
        now: u64,
        deadline: Instant,
    ) -> CellResultV1<Vec<CellProviderRecordV2>> {
        check_deadline(deadline)?;
        self.identity()?;
        request.validate()?;
        require(
            request.context == self.context,
            "discovery directory context",
        )?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CellErrorV1::Invalid("discovery owner poisoned"))?;
        let minimum = state.observed_revision;
        let tx = state
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_schema(&tx)?;
        let (clock, revision) = metadata(&tx, self.context, self.keys.digest())?;
        require(
            now >= clock && revision >= minimum,
            "discovery clock/revision rollback",
        )?;
        // A still-valid signed old wire is not the current high water. Read
        // every returned row through the same key/sequence/digest checks as a
        // publication; accepting wire alone would hide a partial SQL rewind.
        let rows = manifest_rows(&tx, request.manifest)?;
        let mut records = Vec::with_capacity(rows.len());
        for (_, row) in &rows {
            let record = row.record()?;
            require(
                record.statement.request.context == self.context,
                "discovery stored namespace",
            )?;
            records.push(record);
        }
        let next = advance_clock(&tx, clock, revision, now)?;
        validate_schema(&tx)?;
        require(
            metadata(&tx, self.context, self.keys.digest())? == (now, next),
            "discovery lookup clock readback",
        )?;
        self.identity()?;
        check_deadline(deadline)?;
        tx.commit()?;
        self.identity()?;
        let readback = state.db.transaction()?;
        validate_schema(&readback)?;
        require(
            metadata(&readback, self.context, self.keys.digest())? == (now, next)
                && manifest_rows(&readback, request.manifest)? == rows,
            "discovery committed lookup readback",
        )?;
        readback.commit()?;
        self.identity()?;
        state.observed_revision = next;
        check_deadline(deadline)?;
        Ok(records)
    }
}

#[derive(PartialEq, Eq)]
struct Stored {
    sequence: u64,
    wire: Vec<u8>,
    digest: CellDigestV1,
    source: [u8; 17],
    prefix: [u8; 17],
}
impl Stored {
    fn record(&self) -> CellResultV1<CellProviderRecordV2> {
        let record = CellProviderRecordV2::decode(&self.wire)?;
        require(
            record.digest() == self.digest && record.statement.sequence == self.sequence,
            "discovery stored identity",
        )?;
        Ok(record)
    }
}
fn manifest_rows(
    db: &Connection,
    manifest: CellDigestV1,
) -> CellResultV1<Vec<(CellDigestV1, Stored)>> {
    let owners = {
        let mut query=db.prepare("SELECT substr(owner,1,33) FROM discovery_providers_v2 WHERE manifest=?1 ORDER BY owner LIMIT 17")?;
        let rows = query.query_map([manifest.as_slice()], |r| r.get::<_, Vec<u8>>(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    require(
        owners.len() <= MAX_MANIFEST as usize,
        "discovery manifest capacity integrity",
    )?;
    owners
        .into_iter()
        .map(|owner| {
            let owner = fixed(owner)?;
            Ok((
                owner,
                stored(db, manifest, owner)?
                    .ok_or(CellErrorV1::Invalid("discovery missing stored row"))?,
            ))
        })
        .collect()
}
type RawStored = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
fn stored(
    db: &Connection,
    manifest: CellDigestV1,
    owner: CellDigestV1,
) -> CellResultV1<Option<Stored>> {
    let raw:Option<RawStored>=db.query_row("SELECT substr(sequence,1,9),substr(wire,1,3593),substr(digest,1,33),substr(source,1,18),substr(prefix,1,18) FROM discovery_providers_v2 WHERE manifest=?1 AND owner=?2",params![manifest.as_slice(),owner.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
    raw.map(|(sequence, wire, digest, source, prefix)| {
        let out = Stored {
            sequence: u64::from_be_bytes(fixed(sequence)?),
            wire,
            digest: fixed(digest)?,
            source: fixed(source)?,
            prefix: fixed(prefix)?,
        };
        let record = out.record()?;
        require(
            record.statement.request.manifest == manifest && record.statement.owner == owner,
            "discovery stored key",
        )?;
        let mut endpoint = [0; 19];
        endpoint[..17].copy_from_slice(&out.source);
        endpoint[18] = 1;
        let source = decode_endpoint(endpoint)?.ip();
        require(
            ip_bytes(source) == out.source && source_prefix(source) == out.prefix,
            "discovery stored source prefix",
        )?;
        Ok(out)
    })
    .transpose()
}
fn fixed<const N: usize>(bytes: Vec<u8>) -> CellResultV1<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| CellErrorV1::Invalid("discovery stored field length"))
}
fn metadata(
    db: &Connection,
    context: CellDiscoveryContextV1,
    authority: CellDigestV1,
) -> CellResultV1<(u64, u64)> {
    let (actual,keys,clock,revision):(Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>)=db.query_row("SELECT substr(context,1,129),substr(authority,1,33),substr(clock,1,9),substr(revision,1,9) FROM discovery_meta_v2 WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    require(
        actual == context.encode() && keys == authority,
        "discovery persisted namespace/authority",
    )?;
    Ok((
        u64::from_be_bytes(fixed(clock)?),
        u64::from_be_bytes(fixed(revision)?),
    ))
}
fn advance_clock(db: &Connection, clock: u64, revision: u64, now: u64) -> CellResultV1<u64> {
    let next = revision
        .checked_add(1)
        .ok_or(CellErrorV1::Invalid("discovery revision overflow"))?;
    require(db.execute("UPDATE discovery_meta_v2 SET clock=?1,revision=?2 WHERE singleton=1 AND clock=?3 AND revision=?4",params![now.to_be_bytes().as_slice(),next.to_be_bytes().as_slice(),clock.to_be_bytes().as_slice(),revision.to_be_bytes().as_slice()])?==1,"discovery clock CAS")?;
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
            && version == 2
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
            "discovery_meta_v2".into(),
            "discovery_meta_v2".into(),
            Some(META.into()),
        ),
        (
            "table".into(),
            "discovery_providers_v2".into(),
            "discovery_providers_v2".into(),
            Some(RECORDS.into()),
        ),
        (
            "index".into(),
            "sqlite_autoindex_discovery_providers_v2_1".into(),
            "discovery_providers_v2".into(),
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
