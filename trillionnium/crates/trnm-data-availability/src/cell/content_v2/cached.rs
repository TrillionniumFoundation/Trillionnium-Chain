//! Bridge complete CCH1 payload verification to the bytes actually materialized
//! from the existing disposable TCM1 cache. Transport aliases are not authority.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use sha2::{Digest, Sha256};
use trnm_protocol::content_commitment::{observe_reader, ContentClaimV1, ContentReadBudget};

use super::{require, CellContentErrorV2, CellContentManifestV2, CellContentReadbackV2};
use crate::cell::{
    network::remaining, store::verify_chunk_length, CellErrorV1, CellManifestV1, CellResultV1,
    CellStoreV1,
};

static OUTPUT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

impl CellContentManifestV2 {
    /// Verify an independently pinned complete TCM2 manifest, then materialize
    /// its actual complete payload from the bounded TCM1 cache. The old manifest
    /// supplies chunk locations and consistency checks only. Its family, aliases
    /// and size must match TCM2; its SHA-256 hashes cannot substitute for CCH1.
    /// Every buffer returned to the SHA-512 observer is the same buffer written
    /// to the staged file. No second cache read or digest-only wrapper is used.
    /// The existing TCM1/TCM2 nonempty-payload validation remains unchanged.
    ///
    /// The caller supplies one cumulative budget and its original absolute
    /// deadline. Manifest and payload reservations include EOF and are never
    /// refunded. Both reservations precede opening the staged output or reading
    /// the cache. Reads retain at most one bounded cache chunk, and the deadline
    /// is checked around cache reads, each output write, sync and publication.
    /// A failed payload read may evict corrupt disposable cache rows through the
    /// existing repair path; refusal is not a promise of zero cache mutations.
    /// Filesystem/SQLite I/O is cooperative, not preemptible. Once the final
    /// no-replace link begins, durability and temporary-file cleanup finish;
    /// a later failure can leave a complete output, never overwrite an existing
    /// path, and must not cause that output to be treated as an authorized use.
    ///
    /// The caller must control the output directory against concurrent path or
    /// file mutation. This observation does not freeze later file contents or
    /// authenticate the supplied pin. The returned TCM2 readback covers only this
    /// payload; it does not produce a TCC2 dependency-closure observation or cover
    /// installation, CURRENT, a live loader, or FinalUse. A loader still needs
    /// its own current authority and actual-consumed-byte binding.
    pub fn materialize_cached_payload(
        &self,
        store: &CellStoreV1,
        expected_manifest: &ContentClaimV1,
        transport_manifest: &CellManifestV1,
        budget: &mut ContentReadBudget,
        deadline: Instant,
        output: &Path,
    ) -> Result<CellContentReadbackV2, CellContentErrorV2> {
        check_deadline(deadline)?;
        let manifest = self.observe_manifest(expected_manifest.context(), budget)?;
        expected_manifest.verify(&manifest)?;
        transport_manifest
            .validate()
            .map_err(CellContentErrorV2::Metadata)?;
        require(
            transport_manifest.context() == self.legacy_metadata()
                && transport_manifest.size() == self.payload_claim().content_len(),
            "cached payload metadata",
        )?;
        check_deadline(deadline)?;

        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let sequence = OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".trnm-cell-content-v2-{}-{sequence}.partial",
            std::process::id()
        ));
        // No output operation is allowed before observe_reader reserves the
        // payload budget. The reader opens this file lazily on its first read.
        let mut file = None;
        let result: Result<CellContentReadbackV2, CellContentErrorV2> = (|| {
            let mut reader = CachedPayloadReader {
                store,
                manifest: transport_manifest,
                writer: &mut file,
                temporary: &temporary,
                chunk: Cursor::new(Vec::new()),
                next_chunk: 0,
                full: Sha256::new(),
                total: 0,
                deadline,
            };
            // observe_reader reserves the original cumulative budget before the
            // first cache lookup or output open/write. A failed read consumes
            // its reservation; an exhausted budget cannot touch the output path.
            let payload = observe_reader(
                self.payload_claim().context(),
                budget,
                self.payload_claim().content_len(),
                &mut reader,
            )?;
            self.payload_claim().verify(&payload)?;
            check_deadline(deadline)?;
            file.as_ref()
                .expect("a successful payload observation included an EOF read")
                .sync_all()
                .map_err(file_error)?;
            #[cfg(test)]
            tests::checkpoint(tests::Stage::Publication, deadline);
            check_deadline(deadline)?;
            fs::hard_link(&temporary, output).map_err(file_error)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(file_error)?;
            Ok(CellContentReadbackV2 { manifest, payload })
        })();
        let cleanup = if let Some(file) = file.take() {
            drop(file);
            fs::remove_file(&temporary)
        } else {
            Ok(())
        };
        let readback = result?;
        cleanup.map_err(file_error)?;
        Ok(readback)
    }
}

/// Bounded transport reader that writes exactly the bytes yielded to the CCH1
/// observer. SHA-256 remains an additional consistency check for old transport;
/// only the independent full TCM2/CCH1 expectation gates publication.
struct CachedPayloadReader<'a> {
    store: &'a CellStoreV1,
    manifest: &'a CellManifestV1,
    writer: &'a mut Option<File>,
    temporary: &'a Path,
    chunk: Cursor<Vec<u8>>,
    next_chunk: usize,
    full: Sha256,
    total: u64,
    deadline: Instant,
}

impl CachedPayloadReader<'_> {
    fn read_and_write(&mut self, output: &mut [u8]) -> CellResultV1<usize> {
        remaining(self.deadline)?;
        if output.is_empty() {
            return Ok(0);
        }
        if self.writer.is_none() {
            *self.writer = Some(open_temporary(self.temporary)?);
        }
        if self.chunk.position() == self.chunk.get_ref().len() as u64 {
            let Some(expected) = self.manifest.chunks().get(self.next_chunk) else {
                crate::cell::require(
                    self.total == self.manifest.size()
                        && <[u8; 32]>::from(self.full.clone().finalize())
                            == self.manifest.payload_sha256(),
                    "complete cached payload digest",
                )?;
                remaining(self.deadline)?;
                return Ok(0);
            };
            // Release the previous allocation before fetching the next chunk.
            // chunk_with_deadline hashes these actual bytes against the locator.
            self.chunk = Cursor::new(Vec::new());
            let bytes = self
                .store
                .chunk_with_deadline(expected.sha256, Some(self.deadline))?
                .ok_or(CellErrorV1::Unavailable)?;
            verify_chunk_length(expected, &bytes)?;
            self.chunk = Cursor::new(bytes);
            self.next_chunk += 1;
        }
        let count = self.chunk.read(output)?;
        remaining(self.deadline)?;
        self.writer
            .as_mut()
            .expect("the staged output was opened for this read")
            .write_all(&output[..count])?;
        self.full.update(&output[..count]);
        self.total += count as u64;
        #[cfg(test)]
        tests::checkpoint(tests::Stage::PayloadRead, self.deadline);
        remaining(self.deadline)?;
        Ok(count)
    }
}

impl Read for CachedPayloadReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        // Keep the exact cache/I/O refusal as the source of the commitment read
        // failure; interrupted or timed-out reads are not retried or refunded.
        self.read_and_write(output).map_err(|error| match error {
            CellErrorV1::Io(error) => error,
            other => io::Error::other(other),
        })
    }
}

fn check_deadline(deadline: Instant) -> Result<(), CellContentErrorV2> {
    remaining(deadline).map(|_| ()).map_err(file_error)
}

fn open_temporary(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn file_error(error: io::Error) -> CellContentErrorV2 {
    CellContentErrorV2::Metadata(CellErrorV1::Io(error))
}

#[cfg(test)]
mod tests;
