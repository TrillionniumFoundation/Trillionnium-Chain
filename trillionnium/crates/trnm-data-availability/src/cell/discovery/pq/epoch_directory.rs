//! Finite epoch replay state with separately bounded active and retained rows.
//! Expiry releases active quotas; a current-epoch high water is never evicted.
//! Complete host/database rollback and independent-Sybil authority are outside
//! this local owner. The host pins both provider keys and admission sources.
use super::super::directory_wait::{lock_before, with_sqlite_deadline};
use super::epoch::*;
use super::*;
#[cfg(unix)]
use fs2::FileExt;
#[cfg(unix)]
use rusqlite::OpenFlags;
use rusqlite::{params, Connection, TransactionBehavior};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Instant,
};
#[cfg(unix)]
use std::{fs::OpenOptions, time::Duration};

const APPLICATION: i64 = 0x4344_5033;
const MAX_PAGES: u64 = 4096;
const META: &str = "CREATE TABLE discovery_meta_v3 (singleton INTEGER PRIMARY KEY CHECK(singleton=1),context BLOB NOT NULL CHECK(length(context)=128),authority BLOB NOT NULL CHECK(length(authority)=32),sources BLOB NOT NULL CHECK(length(sources)=32),clock BLOB NOT NULL CHECK(length(clock)=8),revision BLOB NOT NULL CHECK(length(revision)=8),reclaimed BLOB NOT NULL CHECK(length(reclaimed)=8)) STRICT";
const RECORDS: &str = "CREATE TABLE discovery_providers_v3 (epoch BLOB NOT NULL CHECK(length(epoch)=8),manifest BLOB NOT NULL CHECK(length(manifest)=32),owner BLOB NOT NULL CHECK(length(owner)=32),sequence BLOB NOT NULL CHECK(length(sequence)=8),expires BLOB NOT NULL CHECK(length(expires)=8),withdrawn INTEGER NOT NULL CHECK(withdrawn IN (0,1)),wire BLOB NOT NULL CHECK(length(wire)=3600),digest BLOB NOT NULL CHECK(length(digest)=32),source_id BLOB NOT NULL CHECK(length(source_id)=32),source_generation BLOB NOT NULL CHECK(length(source_generation)=8),source BLOB NOT NULL CHECK(length(source)=17),prefix BLOB NOT NULL CHECK(length(prefix)=17),PRIMARY KEY(epoch,manifest,owner)) STRICT";

/// Hard limits for one directory. A source is one fixed host-pinned key ID;
/// another endpoint or generation of that key cannot multiply its allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellProviderQuotaLimitsV3 {
    pub global: u64,
    pub per_owner: u64,
    pub per_manifest: u64,
    pub per_source: u64,
    pub per_ip: u64,
    pub per_prefix: u64,
    pub per_source_manifest: u64,
}
pub const CELL_DISCOVERY_ACTIVE_LIMITS_V3: CellProviderQuotaLimitsV3 = CellProviderQuotaLimitsV3 {
    global: 512,
    per_owner: 16,
    per_manifest: 16,
    per_source: 64,
    per_ip: 64,
    per_prefix: 128,
    per_source_manifest: 4,
};
pub const CELL_DISCOVERY_REPLAY_LIMITS_V3: CellProviderQuotaLimitsV3 = CellProviderQuotaLimitsV3 {
    global: 512,
    per_owner: 32,
    per_manifest: 32,
    per_source: 128,
    per_ip: 128,
    per_prefix: 256,
    per_source_manifest: 8,
};

/// Host configuration, never inferred from an incoming key ID or advertisement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellDiscoverySourcePinV3 {
    pub authenticated_key_id: CellDigestV1,
    pub generation: u64,
    pub ip: IpAddr,
}
/// An authenticated transport boundary constructs this after proof verification.
/// Its fields are not writable by an external directory caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellDiscoverySourceV3 {
    pub(super) authenticated_key_id: CellDigestV1,
    pub(super) generation: u64,
    pub(super) ip: IpAddr,
}
type SourceIdentity = (CellDigestV1, u64, [u8; 17]);
#[derive(Clone, Debug)]
pub struct CellDiscoverySourcePinsV3 {
    sources: BTreeSet<SourceIdentity>,
    digest: CellDigestV1,
}
impl CellDiscoverySourcePinsV3 {
    pub fn new(pins: Vec<CellDiscoverySourcePinV3>) -> CellResultV1<Self> {
        require(
            !pins.is_empty() && pins.len() <= 64,
            "discovery source pin count",
        )?;
        let mut sources = BTreeSet::new();
        for pin in pins {
            require(
                pin.authenticated_key_id != [0; 32] && pin.generation > 0,
                "discovery source pin identity",
            )?;
            require(
                sources.insert((
                    pin.authenticated_key_id,
                    pin.generation,
                    ip_bytes(canonical_ip(pin.ip)),
                )),
                "discovery duplicate source pin",
            )?;
        }
        let mut hash = Sha256::new();
        hash.update(b"TRNM/Cell/Discovery/PinnedSources/v3\0");
        hash.update((sources.len() as u32).to_be_bytes());
        for (key, generation, ip) in &sources {
            hash.update(key);
            hash.update(generation.to_be_bytes());
            hash.update(ip);
        }
        Ok(Self {
            sources,
            digest: hash.finalize().into(),
        })
    }
    pub fn digest(&self) -> CellDigestV1 {
        self.digest
    }
    pub(super) fn contains(&self, source: CellDiscoverySourceV3) -> bool {
        self.sources.contains(&(
            source.authenticated_key_id,
            source.generation,
            ip_bytes(canonical_ip(source.ip)),
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellProviderDirectoryUsageV3 {
    pub epoch: u64,
    pub clock_floor: u64,
    pub active_identities: u64,
    /// Includes active records and inactive high-water history in this epoch.
    pub retained_identities: u64,
    pub replay_only_identities: u64,
    /// Cumulative rows retired only after their signed epoch was closed.
    pub reclaimed_closed_epoch_identities: u64,
    pub active_limits: CellProviderQuotaLimitsV3,
    pub replay_limits: CellProviderQuotaLimitsV3,
    pub retained_wire_bytes: u64,
    pub database_bytes: u64,
    pub maximum_database_bytes: u64,
    /// The main DB page limit does not include the DELETE rollback journal,
    /// filesystem metadata, SQLite buffers, or transient bounded allocations.
    pub database_bound_includes_journal_or_rss: bool,
}
struct State {
    db: Connection,
    observed_revision: u64,
}
pub struct CellProviderDirectoryV3 {
    context: CellDiscoveryContextV1,
    keys: CellPqKeyPinsV2,
    source_pins: CellDiscoverySourcePinsV3,
    path: PathBuf,
    identity: File,
    state: Mutex<State>,
}

impl CellProviderDirectoryV3 {
    #[cfg(not(unix))]
    pub fn open(
        _path: &Path,
        _context: CellDiscoveryContextV1,
        _keys: CellPqKeyPinsV2,
        _source_pins: CellDiscoverySourcePinsV3,
    ) -> CellResultV1<Self> {
        Err(CellErrorV1::Invalid("discovery file identity unsupported"))
    }
    /// A new V3 database is required. Neither a V1/V2 file nor a changed provider
    /// or source roster is migrated or silently accepted into this namespace.
    #[cfg(unix)]
    pub fn open(
        path: &Path,
        context: CellDiscoveryContextV1,
        keys: CellPqKeyPinsV2,
        source_pins: CellDiscoverySourcePinsV3,
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
        // SQLite opens its own descriptor. A hostile same-privilege A->B->A
        // path swap during open is outside the observed-identity checks here.
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
            tx.pragma_update(None, "user_version", 3)?;
            require(
                tx.execute(
                    "INSERT INTO discovery_meta_v3 VALUES(1,?1,?2,?3,?4,?5,?6)",
                    params![
                        context.encode(),
                        keys.digest().as_slice(),
                        source_pins.digest().as_slice(),
                        wall_now()?.as_secs().to_be_bytes().as_slice(),
                        0u64.to_be_bytes().as_slice(),
                        0u64.to_be_bytes().as_slice(),
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
        let meta = metadata(&db, context, keys.digest(), source_pins.digest())?;
        check_identity(&path, &identity)?;
        Ok(Self {
            context,
            keys,
            source_pins,
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
    pub(super) fn source_pins(&self) -> &CellDiscoverySourcePinsV3 {
        &self.source_pins
    }
    fn identity(&self) -> CellResultV1<()> {
        check_identity(&self.path, &self.identity)
    }

    /// A sealed provider receipt and an authenticated, host-pinned source are
    /// required. No network operation or second signature verification occurs
    /// while holding this owner. Equal-statement randomized re-signing keeps
    /// the original durable wire and does not transfer source attribution.
    pub(super) fn accept_verified(
        &self,
        verified: &CellVerifiedProviderRecordV3,
        mut source: CellDiscoverySourceV3,
        now: u64,
        deadline: Instant,
    ) -> CellResultV1<()> {
        let deadline = deadline.min(verified.monotonic_expiry());
        check_deadline(deadline)?;
        let record = verified.check_at(now, self.keys.digest())?;
        record.shape()?;
        require(
            record.statement().request.base.context == self.context,
            "discovery directory context",
        )?;
        require(
            self.source_pins.contains(source),
            "discovery unpinned source",
        )?;
        source.ip = canonical_ip(source.ip);
        self.operate(now, deadline, |tx, rows| {
            // Recheck at the admission boundary, including receipts verified
            // before a wait or with a different immutable authority roster.
            verified.check_at(now, self.keys.digest())?;
            let key = record_key(record);
            let prior = rows.binary_search_by_key(&key, |row| record_key(&row.record));
            let mut replacement = Stored::new(record.clone(), source, verified.valid_until());
            if let Ok(index) = prior {
                let old = &rows[index];
                let old_statement = old.record.statement();
                let statement = record.statement();
                require(
                    statement.request == old_statement.request,
                    "discovery immutable pin",
                )?;
                require(
                    statement.sequence >= old_statement.sequence,
                    "discovery sequence replay",
                )?;
                if statement.sequence == old_statement.sequence {
                    require(
                        replacement.digest == old.digest,
                        "discovery sequence equivocation",
                    )?;
                    replacement = old.clone();
                } else {
                    // Refreshing through a second source cannot launder the
                    // identity out of the source that first consumed its quota.
                    replacement.source = old.source;
                    replacement.prefix = old.prefix;
                }
                rows[index] = replacement.clone();
            } else {
                rows.push(replacement.clone());
                rows.sort_by_key(|row| record_key(&row.record));
            }
            // This also checks an expired or withdrawn existing key becoming
            // live again. Updating a row is not an exemption from active caps.
            check_quotas(rows, now)?;
            write_record(tx, &replacement)?;
            Ok(())
        })
        .map(|_| ())
    }

    /// Returns bounded current-epoch high water, including withdrawals and
    /// expired leases. A caller must verify liveness/signatures before sending
    /// or using a record; local history alone never creates a discovered peer.
    pub(super) fn records(
        &self,
        request: CellDiscoveryRequestV3,
        now: u64,
        deadline: Instant,
    ) -> CellResultV1<Vec<CellProviderRecordV3>> {
        request.validate_at(now)?;
        require(
            request.base.context == self.context,
            "discovery directory context",
        )?;
        self.operate(now, deadline, |_, rows| {
            Ok(rows
                .iter()
                .filter(|row| row.record.statement().request.base.manifest == request.base.manifest)
                .map(|row| row.record.clone())
                .collect())
        })
        .map(|(records, _)| records)
    }
    /// Maintenance and reporting share the same clock/revision transaction as
    /// admission. Reporting zero active records never implies free history.
    pub fn usage_at(
        &self,
        now: u64,
        deadline: Instant,
    ) -> CellResultV1<CellProviderDirectoryUsageV3> {
        let ((retained, active, pages), meta) = self.operate(now, deadline, |db, rows| {
            let pages: u64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
            Ok((
                rows.len() as u64,
                rows.iter().filter(|row| row.active_at(now)).count() as u64,
                pages,
            ))
        })?;
        Ok(CellProviderDirectoryUsageV3 {
            epoch: CellDiscoveryRequestV3::epoch_at(now),
            clock_floor: meta.clock,
            active_identities: active,
            retained_identities: retained,
            replay_only_identities: retained - active,
            reclaimed_closed_epoch_identities: meta.reclaimed,
            active_limits: CELL_DISCOVERY_ACTIVE_LIMITS_V3,
            replay_limits: CELL_DISCOVERY_REPLAY_LIMITS_V3,
            retained_wire_bytes: retained * CELL_PROVIDER_RECORD_BYTES_V3 as u64,
            database_bytes: pages * 4096,
            maximum_database_bytes: MAX_PAGES * 4096,
            database_bound_includes_journal_or_rss: false,
        })
    }

    fn operate<T>(
        &self,
        now: u64,
        deadline: Instant,
        operation: impl FnOnce(&Connection, &mut Vec<Stored>) -> CellResultV1<T>,
    ) -> CellResultV1<(T, Metadata)> {
        check_deadline(deadline)?;
        let epoch = CellDiscoveryRequestV3::epoch_at(now);
        require(
            epoch
                .checked_add(1)
                .and_then(|next| next.checked_mul(CELL_DISCOVERY_EPOCH_SECONDS_V3))
                .is_some(),
            "discovery epoch overflow",
        )?;
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
            let before = metadata(
                &tx,
                self.context,
                self.keys.digest(),
                self.source_pins.digest(),
            )?;
            require(
                now >= before.clock && before.revision >= minimum,
                "discovery clock/revision rollback",
            )?;
            let mut rows = stored_rows(&tx, self.context, &self.keys, &self.source_pins, deadline)?;
            require(
                rows.iter().all(|row| {
                    row.record.statement().request.epoch
                        <= CellDiscoveryRequestV3::epoch_at(before.clock)
                }),
                "discovery stored future epoch",
            )?;
            check_quotas(&rows, before.clock)
                .map_err(|_| CellErrorV1::Invalid("discovery capacity integrity"))?;
            let retained = rows.len();
            rows.retain(|row| row.record.statement().request.epoch == epoch);
            let reclaimed = (retained - rows.len()) as u64;
            require(
                tx.execute(
                    "DELETE FROM discovery_providers_v3 WHERE epoch<?1",
                    [epoch.to_be_bytes().as_slice()],
                )? as u64
                    == reclaimed,
                "discovery epoch retirement readback",
            )?;
            check_deadline(deadline)?;
            let value = operation(&tx, &mut rows)?;
            check_quotas(&rows, now)?;
            let after = advance_clock(&tx, before, now, reclaimed)?;
            validate_schema(&tx)?;
            require(
                metadata(
                    &tx,
                    self.context,
                    self.keys.digest(),
                    self.source_pins.digest(),
                )? == after
                    && stored_rows(&tx, self.context, &self.keys, &self.source_pins, deadline)?
                        == rows,
                "discovery transaction readback",
            )?;
            self.identity()?;
            wait.before_sql(&tx)?;
            tx.commit()?;
            // A failed post-COMMIT check does not roll back an admitted high
            // water or a closed epoch. Retrying reconciles the durable state.
            self.identity()?;
            wait.before_sql(db)?;
            let readback = db.transaction()?;
            wait.before_sql(&readback)?;
            validate_schema(&readback)?;
            require(
                metadata(
                    &readback,
                    self.context,
                    self.keys.digest(),
                    self.source_pins.digest(),
                )? == after
                    && stored_rows(
                        &readback,
                        self.context,
                        &self.keys,
                        &self.source_pins,
                        deadline,
                    )? == rows,
                "discovery committed readback",
            )?;
            wait.before_sql(&readback)?;
            readback.commit()?;
            self.identity()?;
            *observed_revision = after.revision;
            check_deadline(deadline)?;
            Ok((value, after))
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Stored {
    record: CellProviderRecordV3,
    wire: Vec<u8>,
    digest: CellDigestV1,
    source: CellDiscoverySourceV3,
    prefix: [u8; 17],
    // Derived from the immutable provider roster, not a mutable SQL claim.
    valid_until: u64,
}
impl Stored {
    fn new(record: CellProviderRecordV3, source: CellDiscoverySourceV3, valid_until: u64) -> Self {
        Self {
            wire: record.encode(),
            digest: record.digest(),
            record,
            source,
            prefix: source_prefix(source.ip),
            valid_until,
        }
    }
    fn active_at(&self, now: u64) -> bool {
        let statement = self.record.statement();
        !statement.withdrawn && now < self.valid_until
    }
}
fn record_key(record: &CellProviderRecordV3) -> (u64, CellDigestV1, CellDigestV1) {
    let statement = record.statement();
    (
        statement.request.epoch,
        statement.request.base.manifest,
        statement.owner,
    )
}
fn write_record(db: &Connection, row: &Stored) -> CellResultV1<()> {
    let statement = row.record.statement();
    require(
        db.execute(
            "INSERT INTO discovery_providers_v3 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(epoch,manifest,owner) DO UPDATE SET sequence=excluded.sequence,expires=excluded.expires,withdrawn=excluded.withdrawn,wire=excluded.wire,digest=excluded.digest,source_id=excluded.source_id,source_generation=excluded.source_generation,source=excluded.source,prefix=excluded.prefix",
            params![
                statement.request.epoch.to_be_bytes().as_slice(),
                statement.request.base.manifest.as_slice(),
                statement.owner.as_slice(),
                statement.sequence.to_be_bytes().as_slice(),
                statement.expires_unix_seconds.to_be_bytes().as_slice(),
                i64::from(statement.withdrawn),
                &row.wire,
                row.digest.as_slice(),
                row.source.authenticated_key_id.as_slice(),
                row.source.generation.to_be_bytes().as_slice(),
                ip_bytes(row.source.ip).as_slice(),
                row.prefix.as_slice(),
            ],
        )? == 1,
        "discovery record write",
    )
}
struct RawStored {
    epoch: Vec<u8>,
    manifest: Vec<u8>,
    owner: Vec<u8>,
    sequence: Vec<u8>,
    expires: Vec<u8>,
    withdrawn: i64,
    wire: Vec<u8>,
    digest: Vec<u8>,
    source_id: Vec<u8>,
    source_generation: Vec<u8>,
    source: Vec<u8>,
    prefix: Vec<u8>,
}
fn stored_rows(
    db: &Connection,
    context: CellDiscoveryContextV1,
    keys: &CellPqKeyPinsV2,
    sources: &CellDiscoverySourcePinsV3,
    deadline: Instant,
) -> CellResultV1<Vec<Stored>> {
    check_deadline(deadline)?;
    let mut query = db.prepare("SELECT substr(epoch,1,9),substr(manifest,1,33),substr(owner,1,33),substr(sequence,1,9),substr(expires,1,9),withdrawn,substr(wire,1,3601),substr(digest,1,33),substr(source_id,1,33),substr(source_generation,1,9),substr(source,1,18),substr(prefix,1,18) FROM discovery_providers_v3 ORDER BY epoch,manifest,owner LIMIT 513")?;
    let raw = query
        .query_map([], |row| {
            Ok(RawStored {
                epoch: row.get(0)?,
                manifest: row.get(1)?,
                owner: row.get(2)?,
                sequence: row.get(3)?,
                expires: row.get(4)?,
                withdrawn: row.get(5)?,
                wire: row.get(6)?,
                digest: row.get(7)?,
                source_id: row.get(8)?,
                source_generation: row.get(9)?,
                source: row.get(10)?,
                prefix: row.get(11)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    require(
        raw.len() <= CELL_DISCOVERY_REPLAY_LIMITS_V3.global as usize,
        "discovery capacity integrity",
    )?;
    raw.into_iter()
        .map(|raw| {
            check_deadline(deadline)?;
            let record = CellProviderRecordV3::decode(&raw.wire)?;
            let statement = record.statement();
            let pin = keys
                .pins()
                .find(|pin| pin.key_id == statement.owner)
                .ok_or(CellErrorV1::Invalid("discovery stored provider key"))?;
            require(
                pin.generation == statement.owner_generation,
                "discovery stored provider generation",
            )?;
            let valid_until = statement
                .expires_unix_seconds
                .min(pin.expires_at)
                .min(pin.revoked_at.unwrap_or(u64::MAX));
            let digest = fixed(raw.digest)?;
            require(
                statement.request.base.context == context
                    && statement.request.epoch == u64::from_be_bytes(fixed(raw.epoch)?)
                    && statement.request.base.manifest == fixed::<32>(raw.manifest)?
                    && statement.owner == fixed::<32>(raw.owner)?
                    && statement.sequence == u64::from_be_bytes(fixed(raw.sequence)?)
                    && statement.expires_unix_seconds == u64::from_be_bytes(fixed(raw.expires)?)
                    && i64::from(statement.withdrawn) == raw.withdrawn
                    && record.digest() == digest,
                "discovery stored identity",
            )?;
            let source_bytes: [u8; 17] = fixed(raw.source)?;
            let mut endpoint = [0; 19];
            endpoint[..17].copy_from_slice(&source_bytes);
            endpoint[18] = 1;
            let ip = decode_endpoint(endpoint)?.ip();
            let source = CellDiscoverySourceV3 {
                authenticated_key_id: fixed(raw.source_id)?,
                generation: u64::from_be_bytes(fixed(raw.source_generation)?),
                ip,
            };
            let prefix = fixed(raw.prefix)?;
            require(
                ip_bytes(canonical_ip(ip)) == source_bytes
                    && source_prefix(ip) == prefix
                    && sources.contains(source),
                "discovery stored source pin/prefix",
            )?;
            Ok(Stored {
                record,
                wire: raw.wire,
                digest,
                source,
                prefix,
                valid_until,
            })
        })
        .collect()
}
fn fixed<const N: usize>(bytes: Vec<u8>) -> CellResultV1<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| CellErrorV1::Invalid("discovery stored field length"))
}

#[derive(Default)]
struct Counts {
    total: u64,
    owners: BTreeMap<CellDigestV1, u64>,
    manifests: BTreeMap<CellDigestV1, u64>,
    sources: BTreeMap<CellDigestV1, u64>,
    ips: BTreeMap<[u8; 17], u64>,
    prefixes: BTreeMap<[u8; 17], u64>,
    source_manifests: BTreeMap<(CellDigestV1, CellDigestV1), u64>,
}
impl Counts {
    fn add(&mut self, row: &Stored) {
        let statement = row.record.statement();
        self.total += 1;
        *self.owners.entry(statement.owner).or_default() += 1;
        *self
            .manifests
            .entry(statement.request.base.manifest)
            .or_default() += 1;
        *self
            .sources
            .entry(row.source.authenticated_key_id)
            .or_default() += 1;
        *self.ips.entry(ip_bytes(row.source.ip)).or_default() += 1;
        *self.prefixes.entry(row.prefix).or_default() += 1;
        *self
            .source_manifests
            .entry((
                row.source.authenticated_key_id,
                statement.request.base.manifest,
            ))
            .or_default() += 1;
    }
    fn within(&self, limits: CellProviderQuotaLimitsV3) -> bool {
        self.total <= limits.global
            && self.owners.values().all(|count| *count <= limits.per_owner)
            && self
                .manifests
                .values()
                .all(|count| *count <= limits.per_manifest)
            && self
                .sources
                .values()
                .all(|count| *count <= limits.per_source)
            && self.ips.values().all(|count| *count <= limits.per_ip)
            && self
                .prefixes
                .values()
                .all(|count| *count <= limits.per_prefix)
            && self
                .source_manifests
                .values()
                .all(|count| *count <= limits.per_source_manifest)
    }
}
fn check_quotas(rows: &[Stored], now: u64) -> CellResultV1<()> {
    let mut active = Counts::default();
    let mut retained = Counts::default();
    for row in rows {
        retained.add(row);
        if row.active_at(now) {
            active.add(row);
        }
    }
    require(
        retained.within(CELL_DISCOVERY_REPLAY_LIMITS_V3),
        "discovery replay capacity",
    )?;
    require(
        active.within(CELL_DISCOVERY_ACTIVE_LIMITS_V3),
        "discovery active capacity",
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Metadata {
    clock: u64,
    revision: u64,
    reclaimed: u64,
}
fn metadata(
    db: &Connection,
    context: CellDiscoveryContextV1,
    authority: CellDigestV1,
    sources: CellDigestV1,
) -> CellResultV1<Metadata> {
    type Raw = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let (actual, keys, origin, clock, revision, reclaimed): Raw = db.query_row(
        "SELECT substr(context,1,129),substr(authority,1,33),substr(sources,1,33),substr(clock,1,9),substr(revision,1,9),substr(reclaimed,1,9) FROM discovery_meta_v3 WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
    )?;
    require(
        actual == context.encode() && keys == authority && origin == sources,
        "discovery persisted namespace/authority/sources",
    )?;
    Ok(Metadata {
        clock: u64::from_be_bytes(fixed(clock)?),
        revision: u64::from_be_bytes(fixed(revision)?),
        reclaimed: u64::from_be_bytes(fixed(reclaimed)?),
    })
}
fn advance_clock(
    db: &Connection,
    before: Metadata,
    now: u64,
    reclaimed: u64,
) -> CellResultV1<Metadata> {
    let after = Metadata {
        clock: now,
        revision: before
            .revision
            .checked_add(1)
            .ok_or(CellErrorV1::Invalid("discovery revision overflow"))?,
        reclaimed: before
            .reclaimed
            .checked_add(reclaimed)
            .ok_or(CellErrorV1::Invalid("discovery reclaimed count overflow"))?,
    };
    require(
        db.execute(
            "UPDATE discovery_meta_v3 SET clock=?1,revision=?2,reclaimed=?3 WHERE singleton=1 AND clock=?4 AND revision=?5 AND reclaimed=?6",
            params![
                after.clock.to_be_bytes().as_slice(),
                after.revision.to_be_bytes().as_slice(),
                after.reclaimed.to_be_bytes().as_slice(),
                before.clock.to_be_bytes().as_slice(),
                before.revision.to_be_bytes().as_slice(),
                before.reclaimed.to_be_bytes().as_slice(),
            ],
        )? == 1,
        "discovery clock CAS",
    )?;
    Ok(after)
}
fn validate_schema(db: &Connection) -> CellResultV1<()> {
    let app: i64 = db.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let journal: String = db.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let page: u64 = db.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let maximum: u64 = db.pragma_query_value(None, "max_page_count", |row| row.get(0))?;
    let pages: u64 = db.pragma_query_value(None, "page_count", |row| row.get(0))?;
    require(
        app == APPLICATION
            && version == 3
            && journal == "delete"
            && page == 4096
            && maximum == MAX_PAGES
            && pages <= MAX_PAGES,
        "discovery live namespace/resource mode",
    )?;
    let mut query = db.prepare("SELECT type,substr(name,1,64),substr(tbl_name,1,64),substr(sql,1,2048) FROM sqlite_schema ORDER BY name LIMIT 4")?;
    let actual = query
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
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
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(address) => address.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
fn source_prefix(ip: IpAddr) -> [u8; 17] {
    let ip = canonical_ip(ip);
    let mut prefix = ip_bytes(ip);
    if ip.is_ipv4() {
        prefix[16] = 0;
    } else {
        prefix[9..].fill(0);
    }
    prefix
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
#[path = "epoch_directory_tests.rs"]
mod tests;
