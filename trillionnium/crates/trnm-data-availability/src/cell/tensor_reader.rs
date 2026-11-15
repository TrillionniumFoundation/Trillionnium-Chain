//! Bounded descriptor over immutable, individually verified cache chunks.
//! A seek changes the cursor, never the pinned payload or original deadline.

use std::io::{self, Read, Seek, SeekFrom};
use std::time::Instant;

use super::{CellManifestV1, CellResultV1, CellStoreV1};

pub(super) struct CachePayloadReader<'a> {
    store: &'a CellStoreV1,
    manifest: CellManifestV1,
    deadline: Instant,
    position: u64,
    cached_index: Option<usize>,
    cached_bytes: Vec<u8>,
}

impl<'a> CachePayloadReader<'a> {
    pub(super) fn new(
        store: &'a CellStoreV1,
        manifest: CellManifestV1,
        deadline: Instant,
    ) -> CellResultV1<Self> {
        manifest.validate()?;
        Ok(Self {
            store,
            manifest,
            deadline,
            position: 0,
            cached_index: None,
            cached_bytes: Vec::new(),
        })
    }

    fn check_deadline(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "tensor read deadline",
            ));
        }
        Ok(())
    }
}

impl Read for CachePayloadReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.check_deadline()?;
        if output.is_empty() || self.position >= self.manifest.size() {
            return Ok(0);
        }
        let width = u64::from(self.manifest.chunks()[0].size);
        let index = usize::try_from(self.position / width)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "tensor chunk index"))?;
        let expected = &self.manifest.chunks()[index];
        if self.cached_index != Some(index) {
            // Keep one <=4MiB verified chunk; never reconstruct a whole model
            // in memory or trust the availability probe's unverified length.
            self.cached_index = None;
            self.cached_bytes = Vec::new();
            let bytes = self
                .store
                .chunk_with_deadline(expected.sha256, Some(self.deadline))
                .map_err(io::Error::other)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "tensor chunk absent"))?;
            if bytes.len() != expected.size as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tensor chunk length",
                ));
            }
            self.cached_bytes = bytes;
            self.cached_index = Some(index);
        }
        self.check_deadline()?;
        let offset = (self.position % width) as usize;
        let count = output.len().min(self.cached_bytes.len() - offset);
        output[..count].copy_from_slice(&self.cached_bytes[offset..offset + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for CachePayloadReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.check_deadline()?;
        let next = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(offset) => i128::from(self.manifest.size()) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        self.position = u64::try_from(next)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "tensor seek range"))?;
        Ok(self.position)
    }
}
