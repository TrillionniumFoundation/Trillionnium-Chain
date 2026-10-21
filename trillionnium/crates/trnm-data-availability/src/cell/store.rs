use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use super::{
    manifest::MAX_MANIFEST_BYTES, require, CellChunkV1, CellContextV1, CellDigestV1, CellErrorV1,
    CellManifestV1, CellReleaseManifestV1, CellResultV1, MAX_CELL_BYTES, MAX_CHUNK_BYTES,
};

const APPLICATION_ID: i64 = 0x5443_4c31;
static OUTPUT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A separate, disposable byte cache; never a ledger or release authority.
pub struct CellStoreV1 {
    connection: Connection,
}

impl CellStoreV1 {
    pub fn open(path: &Path) -> CellResultV1<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "trusted_schema", false)?;
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application == 0 && version == 0 {
            let tables: i64 = connection.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )?;
            require(tables == 0, "foreign cache database")?;
            connection.execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE cell_manifests_v1 (
                     id BLOB PRIMARY KEY CHECK(length(id) = 32),
                     wire BLOB NOT NULL CHECK(length(wire) <= 1048576));
                 CREATE TABLE cell_chunks_v1 (
                     hash BLOB PRIMARY KEY CHECK(length(hash) = 32),
                     bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 4194304));
                 PRAGMA application_id = 1413696561;
                 PRAGMA user_version = 1;
                 COMMIT;",
            )?;
        } else {
            require(
                application == APPLICATION_ID && version == 1,
                "cache namespace",
            )?;
        }
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        Ok(Self { connection })
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
        self.connection.execute(
            "DELETE FROM cell_chunks_v1 WHERE hash = ?1",
            [hash.as_slice()],
        )?;
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

    /// Verify every member of a release's complete dependency closure from
    /// the local cache.  Arbitrary cached cells never imply a usable release:
    /// the caller must provide the canonical release manifest and all listed
    /// members must match its bound model context.
    pub fn verify_release_complete(
        &self,
        release: &CellReleaseManifestV1,
    ) -> CellResultV1<()> {
        release.validate()?;
        for digest in release.cells() {
            let manifest = self
                .manifest(*digest)?
                .ok_or(CellErrorV1::Unavailable)?;
            require(
                manifest.context() == release.context(),
                "release cell context",
            )?;
            self.verify_complete(&manifest)?;
        }
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
            verify_chunk(expected, &bytes)?;
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
    require(
        expected.size > 0
            && expected.size <= MAX_CHUNK_BYTES
            && bytes.len() == expected.size as usize,
        "chunk length",
    )?;
    require(
        <[u8; 32]>::from(Sha256::digest(bytes)) == expected.sha256,
        "chunk digest",
    )
}
