use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};

use super::{
    manifest::MAX_MANIFEST_BYTES, require, CellChunkV1, CellContextV1, CellDigestV1, CellErrorV1,
    CellManifestV1, CellReleaseManifestV1, CellResultV1, MAX_CELL_BYTES, MAX_CHUNK_BYTES,
};

static OUTPUT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
// One short FULL transaction retains at most 32 MiB of already received bytes.
// The caller must collect the batch before taking the SQLite writer lock.
pub(super) const MAX_CHUNK_COMMIT_BATCH: usize = 8;

/// One release owner's finite verification reservation. Shared chunks count
/// once per member reference because full payload verification reads them again.
/// Filesystem calls are cooperative and cannot be interrupted by the deadline.
#[derive(Clone, Copy, Debug)]
pub struct CellReleaseLimitsV1 {
    pub max_payload_bytes: u64,
    pub max_chunks: u64,
    pub deadline: Instant,
}

/// A separate, disposable byte cache; never a ledger or release authority.
pub struct CellStoreV1 {
    connection: Connection,
    read_only: bool,
}

impl CellStoreV1 {
    pub fn open(path: &Path, config: super::CellCacheConfigV3) -> CellResultV1<Self> {
        config.validate()?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "trusted_schema", false)?;
        super::cache_budget::open(&connection, Some(config), true)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        Ok(Self {
            connection,
            read_only: false,
        })
    }

    /// Existing disposable cache only; serving never creates or repairs a DB.
    pub fn open_read_only(path: &Path) -> CellResultV1<Self> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(std::time::Duration::ZERO)?;
        connection.pragma_update(None, "trusted_schema", false)?;
        super::cache_budget::open(&connection, None, false)?;
        Ok(Self {
            connection,
            read_only: true,
        })
    }

    pub fn cache_usage(&self) -> CellResultV1<super::CellCacheUsageV2> {
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Deferred,
        )?;
        let usage = super::cache_budget::audit(&transaction, None)?;
        transaction.commit()?;
        Ok(usage)
    }

    pub fn put_manifest(&self, pinned: CellDigestV1, wire: &[u8]) -> CellResultV1<CellManifestV1> {
        let manifest = CellManifestV1::decode(wire)?;
        require(manifest.id() == pinned, "manifest digest")?;
        self.connection.execute(
            "INSERT INTO cell_manifests_v1(id, wire) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET wire = excluded.wire",
            params![pinned.as_slice(), wire],
        )?;
        Ok(manifest)
    }

    pub fn manifest(&self, pinned: CellDigestV1) -> CellResultV1<Option<CellManifestV1>> {
        let wire: Option<Option<Vec<u8>>> = self
            .connection
            .query_row(
                "SELECT CASE WHEN length(wire) <= ?2 THEN wire ELSE NULL END
             FROM cell_manifests_v1 WHERE id = ?1",
                params![pinned.as_slice(), MAX_MANIFEST_BYTES as i64],
                |r| r.get(0),
            )
            .optional()?;
        match wire {
            None => Ok(None),
            Some(None) => Err(CellErrorV1::Invalid("cached manifest length")),
            Some(Some(bytes)) => {
                let manifest = CellManifestV1::decode(&bytes)?;
                require(manifest.id() == pinned, "cached manifest digest")?;
                Ok(Some(manifest))
            }
        }
    }

    pub fn put_chunk(&self, expected: &CellChunkV1, bytes: &[u8]) -> CellResultV1<()> {
        verify_chunk(expected, bytes)?;
        self.connection.execute(
            "INSERT INTO cell_chunks_v1(hash, bytes) VALUES (?1, ?2)
             ON CONFLICT(hash) DO UPDATE SET bytes = excluded.bytes",
            params![expected.sha256.as_slice(), bytes],
        )?;
        Ok(())
    }

    pub(super) fn put_chunk_batch(&self, chunks: &[(&CellChunkV1, &[u8])]) -> CellResultV1<()> {
        require(
            !chunks.is_empty() && chunks.len() <= MAX_CHUNK_COMMIT_BATCH,
            "chunk commit batch bound",
        )?;
        // Reject a malformed member before changing even the first cache row.
        // Per-chunk lengths also bound this batch by 8 * MAX_CHUNK_BYTES.
        for (expected, bytes) in chunks {
            verify_chunk(expected, bytes)?;
        }
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        {
            let mut statement = transaction.prepare_cached(
                "INSERT INTO cell_chunks_v1(hash, bytes) VALUES (?1, ?2)
                 ON CONFLICT(hash) DO UPDATE SET bytes = excluded.bytes",
            )?;
            for (expected, bytes) in chunks {
                require(
                    statement.execute(params![expected.sha256.as_slice(), bytes])? == 1,
                    "cache chunk write",
                )?;
            }
        }
        // synchronous=FULL is unchanged. No network operation or wait occurs
        // inside this transaction; a failure rolls back this batch only.
        transaction.commit()?;
        Ok(())
    }

    /// Every read hashes the actual bytes. A corrupt disposable chunk is removed
    /// and becomes missing, so the ordinary fetch path can repair it.
    pub fn chunk(&self, hash: CellDigestV1) -> CellResultV1<Option<Vec<u8>>> {
        let row: Option<Option<Vec<u8>>> = self
            .connection
            .query_row(
                "SELECT CASE WHEN length(bytes) BETWEEN 1 AND ?2 THEN bytes ELSE NULL END
             FROM cell_chunks_v1 WHERE hash = ?1",
                params![hash.as_slice(), i64::from(MAX_CHUNK_BYTES)],
                |r| r.get(0),
            )
            .optional()?;
        let Some(row) = row else {
            return Ok(None);
        };
        if let Some(bytes) = row {
            if <[u8; 32]>::from(Sha256::digest(&bytes)) == hash {
                return Ok(Some(bytes));
            }
        }
        if !self.read_only {
            self.connection.execute(
                "DELETE FROM cell_chunks_v1 WHERE hash = ?1",
                [hash.as_slice()],
            )?;
        }
        Ok(None)
    }

    pub fn pack_file(
        &self,
        path: &Path,
        context: CellContextV1,
        chunk_bytes: u32,
    ) -> CellResultV1<CellManifestV1> {
        context.validate()?;
        require(
            (16_384..=MAX_CHUNK_BYTES).contains(&chunk_bytes) && chunk_bytes.is_power_of_two(),
            "chunk size",
        )?;
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        require(
            metadata.is_file() && (1..=MAX_CELL_BYTES).contains(&metadata.len()),
            "input file size/type",
        )?;
        require(
            metadata.len().div_ceil(u64::from(chunk_bytes)) <= 16_384,
            "chunk count",
        )?;
        let mut total = 0_u64;
        let mut full = Sha256::new();
        let mut chunks = Vec::new();
        let mut bytes = vec![0; chunk_bytes as usize];
        while total < metadata.len() {
            let count = (metadata.len() - total).min(u64::from(chunk_bytes)) as usize;
            file.read_exact(&mut bytes[..count])?;
            let chunk = CellChunkV1 {
                size: count as u32,
                sha256: Sha256::digest(&bytes[..count]).into(),
            };
            self.put_chunk(&chunk, &bytes[..count])?;
            full.update(&bytes[..count]);
            total += count as u64;
            chunks.push(chunk);
        }
        require(file.read(&mut [0; 1])? == 0, "input grew during pack")?;
        let manifest =
            CellManifestV1::new(context, total, full.finalize().into(), chunk_bytes, chunks)?;
        self.put_manifest(manifest.id(), &manifest.encode())
    }

    pub fn verify_complete(&self, manifest: &CellManifestV1) -> CellResultV1<()> {
        self.write_verified(manifest, &mut std::io::sink(), None)
    }

    /// Verify every member of the release owner's declared required-cell set
    /// from the local cache. The caller must pin the release manifest and its
    /// completeness through its release owner; this cache cannot infer missing
    /// dependencies, select a release, or authorize loading it.
    pub fn verify_release_complete(
        &self,
        release: &CellReleaseManifestV1,
        limits: CellReleaseLimitsV1,
    ) -> CellResultV1<()> {
        release.validate()?;
        require(limits.max_payload_bytes > 0, "release payload budget")?;
        require(limits.max_chunks > 0, "release chunk budget")?;
        let check_deadline = || {
            require(
                Instant::now() <= limits.deadline,
                "release verification deadline",
            )
        };
        check_deadline()?;
        let mut payload_bytes = 0_u64;
        let mut chunks = 0_u64;
        // Inspect all pinned manifests before reading any payload. Do not retain
        // an unbounded collection of decoded manifests or read a large first
        // member before discovering an over-budget later member.
        for digest in release.cells() {
            check_deadline()?;
            let manifest = self.manifest(*digest)?.ok_or(CellErrorV1::Unavailable)?;
            require(
                manifest.context() == release.context(),
                "release cell context",
            )?;
            payload_bytes = payload_bytes
                .checked_add(manifest.size())
                .ok_or(CellErrorV1::Invalid("release payload budget"))?;
            require(
                payload_bytes <= limits.max_payload_bytes,
                "release payload budget",
            )?;
            chunks = chunks
                .checked_add(manifest.chunks().len() as u64)
                .ok_or(CellErrorV1::Invalid("release chunk budget"))?;
            require(chunks <= limits.max_chunks, "release chunk budget")?;
        }
        for digest in release.cells() {
            check_deadline()?;
            // Content addressing binds this re-read to the preflight manifest.
            let manifest = self.manifest(*digest)?.ok_or(CellErrorV1::Unavailable)?;
            self.verify_complete_until(&manifest, limits.deadline)?;
        }
        check_deadline()?;
        Ok(())
    }

    pub(super) fn verify_complete_until(
        &self,
        manifest: &CellManifestV1,
        deadline: Instant,
    ) -> CellResultV1<()> {
        self.write_verified(manifest, &mut std::io::sink(), Some(deadline))
    }

    /// Publish only after checking the complete ordered payload. The output must
    /// be absent; neither a partial download nor an existing path is published.
    pub fn materialize(&self, manifest: &CellManifestV1, output: &Path) -> CellResultV1<()> {
        self.materialize_with_deadline(manifest, output, None)
    }

    /// Recheck bytes and publish against the caller's original absolute deadline.
    /// Filesystem I/O is not preemptible. Expiry before the publication checkpoint
    /// leaves no output; once the no-replace link begins, durability and cleanup
    /// finish without treating a complete published file as a removable partial.
    pub fn materialize_until(
        &self,
        manifest: &CellManifestV1,
        output: &Path,
        deadline: Instant,
    ) -> CellResultV1<()> {
        self.materialize_with_deadline(manifest, output, Some(deadline))
    }

    fn materialize_with_deadline(
        &self,
        manifest: &CellManifestV1,
        output: &Path,
        deadline: Option<Instant>,
    ) -> CellResultV1<()> {
        let check_deadline = || {
            require(
                deadline.is_none_or(|end| Instant::now() <= end),
                "materialization deadline",
            )
        };
        check_deadline()?;
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let sequence = OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".trnm-cell-{}-{sequence}.partial",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let result: CellResultV1<()> = (|| {
            self.write_verified(manifest, &mut file, deadline)?;
            check_deadline()?;
            file.sync_all()?;
            #[cfg(test)]
            super::tests::before_materialize_publication(deadline);
            check_deadline()?;
            fs::hard_link(&temporary, output)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        drop(file);
        let cleanup = fs::remove_file(&temporary);
        result?;
        cleanup?;
        Ok(())
    }

    fn write_verified(
        &self,
        manifest: &CellManifestV1,
        writer: &mut impl Write,
        deadline: Option<Instant>,
    ) -> CellResultV1<()> {
        manifest.validate()?;
        let mut full = Sha256::new();
        let mut total = 0_u64;
        for expected in manifest.chunks() {
            require(
                deadline.is_none_or(|end| Instant::now() <= end),
                "verification deadline",
            )?;
            let bytes = self
                .chunk(expected.sha256)?
                .ok_or(CellErrorV1::Unavailable)?;
            // chunk() just hashed these actual bytes against expected.sha256.
            // Retain the manifest's length relation and the ordered payload
            // hash without hashing the same immutable buffer a second time.
            verify_chunk_length(expected, &bytes)?;
            full.update(&bytes);
            total += bytes.len() as u64;
            writer.write_all(&bytes)?;
        }
        require(
            total == manifest.size()
                && <[u8; 32]>::from(full.finalize()) == manifest.payload_sha256(),
            "complete payload digest",
        )
    }
}

pub(super) fn verify_chunk(expected: &CellChunkV1, bytes: &[u8]) -> CellResultV1<()> {
    verify_chunk_length(expected, bytes)?;
    require(
        <[u8; 32]>::from(Sha256::digest(bytes)) == expected.sha256,
        "chunk digest",
    )
}

pub(super) fn verify_chunk_length(expected: &CellChunkV1, bytes: &[u8]) -> CellResultV1<()> {
    require(
        expected.size > 0
            && expected.size <= MAX_CHUNK_BYTES
            && bytes.len() == expected.size as usize,
        "chunk length",
    )
}
