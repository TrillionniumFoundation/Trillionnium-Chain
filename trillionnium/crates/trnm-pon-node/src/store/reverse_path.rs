//! Operation-local reverse ancestry spool. Only locators are buffered, never
//! validation verdicts or State. Storage stays bounded at 128 locators in RAM;
//! older locators spill to the same temporary file and are read in reverse batches.
use std::io::{self, Read, Seek, SeekFrom, Write};

const RECORDS: usize = 128;
const WIDTH: usize = 32;

pub(super) struct ReversePath<T> {
    file: Option<T>,
    buffer: [u8; RECORDS * WIDTH],
    buffered: usize,
    spilled: u64,
}

impl<T: Read + Write + Seek> ReversePath<T> {
    #[cfg(test)]
    pub(super) fn new(file: T) -> Self {
        Self {
            file: Some(file),
            buffer: [0; RECORDS * WIDTH],
            buffered: 0,
            spilled: 0,
        }
    }

    /// Defer scratch-file creation until the fixed locator buffer must spill.
    /// This changes no retained State, SQL readback or validation result.
    pub(super) fn new_lazy() -> Self {
        Self {
            file: None,
            buffer: [0; RECORDS * WIDTH],
            buffered: 0,
            spilled: 0,
        }
    }

    // Collection must finish before the first pop. No external writer has this
    // private spool; all durable SQL rows are still read and checked by the caller.
    #[cfg(test)]
    pub(super) fn push(&mut self, id: [u8; WIDTH]) -> io::Result<()> {
        self.push_with(id, || Err(io::Error::other("SPOOL_NOT_PROVIDED")))
    }

    pub(super) fn push_with(
        &mut self,
        id: [u8; WIDTH],
        create: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<()> {
        if self.buffered == RECORDS {
            let next = self
                .spilled
                .checked_add(self.buffer.len() as u64)
                .ok_or_else(|| io::Error::other("ANCESTRY_LIMIT"))?;
            if let Some(file) = &mut self.file {
                file.write_all(&self.buffer)?;
            } else {
                let mut file = create()?;
                file.write_all(&self.buffer)?;
                self.file = Some(file);
            }
            self.spilled = next;
            self.buffered = 0;
        }
        let start = self.buffered * WIDTH;
        self.buffer[start..start + WIDTH].copy_from_slice(&id);
        self.buffered += 1;
        Ok(())
    }

    pub(super) fn pop_with_progress(
        &mut self,
        progress: &mut dyn FnMut() -> crate::Result<()>,
    ) -> crate::Result<Option<[u8; WIDTH]>> {
        if self.buffered == 0 && self.spilled == 0 {
            return Ok(None);
        }
        progress()?;
        Ok(self.pop()?)
    }

    pub(super) fn pop(&mut self) -> io::Result<Option<[u8; WIDTH]>> {
        if self.buffered == 0 {
            if self.spilled == 0 {
                return Ok(None);
            }
            let start = self.spilled - self.buffer.len() as u64;
            let file = self
                .file
                .as_mut()
                .ok_or_else(|| io::Error::other("MISSING_ANCESTRY_SPOOL"))?;
            file.seek(SeekFrom::Start(start))?;
            file.read_exact(&mut self.buffer)?;
            self.spilled = start;
            self.buffered = RECORDS;
        }
        self.buffered -= 1;
        let start = self.buffered * WIDTH;
        let mut id = [0; WIDTH];
        id.copy_from_slice(&self.buffer[start..start + WIDTH]);
        Ok(Some(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn id(index: usize) -> [u8; WIDTH] {
        let mut id = [0; WIDTH];
        id[..8].copy_from_slice(&(index as u64).to_le_bytes());
        id
    }

    #[test]
    fn reverse_spool_preserves_every_locator_across_original_long_chain() {
        for count in [0, 1, 127, 128, 129, 255, 256, 257, 4105] {
            let mut path = ReversePath::new(Cursor::new(Vec::new()));
            for index in 0..count {
                path.push(id(index)).unwrap();
            }
            assert_eq!(
                path.file.as_ref().unwrap().get_ref().len(),
                count.saturating_sub(1) / RECORDS * RECORDS * WIDTH
            );
            for index in (0..count).rev() {
                assert_eq!(path.pop().unwrap(), Some(id(index)));
            }
            assert_eq!(path.pop().unwrap(), None);
        }
    }

    #[test]
    fn reverse_spool_does_not_hide_truncated_spill() {
        let mut path = ReversePath::new(Cursor::new(Vec::new()));
        for index in 0..=RECORDS {
            path.push(id(index)).unwrap();
        }
        path.file
            .as_mut()
            .unwrap()
            .get_mut()
            .truncate(RECORDS * WIDTH - 1);
        assert_eq!(path.pop().unwrap(), Some(id(RECORDS)));
        assert_eq!(path.pop().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[derive(Default)]
    struct CountedFile {
        inner: Cursor<Vec<u8>>,
        writes: usize,
        reads: usize,
        seeks: usize,
        refuse_writes: bool,
    }
    impl Read for CountedFile {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            self.inner.read(bytes)
        }
    }
    impl Write for CountedFile {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.refuse_writes {
                return Err(io::Error::other("SPILL_WRITE_REFUSED"));
            }
            self.inner.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }
    impl Seek for CountedFile {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.seeks += 1;
            self.inner.seek(position)
        }
    }

    #[test]
    fn reverse_spool_batches_io_without_skipping_a_locator() {
        let mut path = ReversePath::new(CountedFile::default());
        for index in 0..4105 {
            path.push(id(index)).unwrap();
        }
        for index in (0..4105).rev() {
            assert_eq!(path.pop().unwrap(), Some(id(index)));
        }
        assert_eq!(path.pop().unwrap(), None);
        assert_eq!(
            (
                path.file.as_ref().unwrap().writes,
                path.file.as_ref().unwrap().reads,
                path.file.as_ref().unwrap().seeks
            ),
            (32, 32, 32)
        );
    }

    #[test]
    fn reverse_spool_propagates_failed_write_before_reusing_buffer() {
        let mut path = ReversePath::new(CountedFile {
            refuse_writes: true,
            ..CountedFile::default()
        });
        for index in 0..RECORDS {
            path.push(id(index)).unwrap();
        }
        assert_eq!(
            path.push(id(RECORDS)).unwrap_err().to_string(),
            "SPILL_WRITE_REFUSED"
        );
        assert_eq!(path.spilled, 0);
        assert_eq!(path.buffered, RECORDS);
    }

    #[test]
    fn locator_reverse_matches_original_file_at_empty_boundary_and_spill_lengths() {
        use std::cell::Cell;
        assert_eq!(std::mem::size_of::<[u8; RECORDS * WIDTH]>(), 4096);
        for count in [0, 1, 127, 128, 129, 256, 257] {
            let creates = Cell::new(0);
            let mut path = ReversePath::new_lazy();
            let mut original = tempfile::tempfile().unwrap();
            for ordinal in 0..count {
                let value = id(ordinal);
                original.write_all(&value).unwrap();
                path.push_with(value, || {
                    creates.set(creates.get() + 1);
                    tempfile::tempfile()
                })
                .unwrap();
            }
            assert_eq!(creates.get(), usize::from(count > RECORDS));
            let mut checkpoints = 0;
            for ordinal in (0..count).rev() {
                original
                    .seek(SeekFrom::Start(ordinal as u64 * WIDTH as u64))
                    .unwrap();
                let mut expected = [0; WIDTH];
                original.read_exact(&mut expected).unwrap();
                assert_eq!(
                    path.pop_with_progress(&mut || {
                        checkpoints += 1;
                        Ok(())
                    })
                    .unwrap(),
                    Some(expected),
                    "{count} / {ordinal}"
                );
            }
            assert!(path
                .pop_with_progress(&mut || panic!("empty path has no locator checkpoint"))
                .unwrap()
                .is_none());
            assert_eq!(checkpoints, count);
        }
    }

    #[test]
    fn locator_tempfile_is_required_only_after_the_fixed_memory_bound() {
        let mut path = ReversePath::<std::fs::File>::new_lazy();
        for ordinal in 0..RECORDS {
            path.push_with(id(ordinal), || panic!("spool below bound"))
                .unwrap();
        }
        let error = path
            .push_with(id(RECORDS), || Err(io::ErrorKind::PermissionDenied.into()))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!((path.buffered, path.spilled), (RECORDS, 0));
        assert!(path.file.is_none());
    }

    #[test]
    fn locator_spill_copy_and_later_write_failures_propagate() {
        let named = tempfile::NamedTempFile::new().unwrap();
        let mut path = ReversePath::new_lazy();
        for ordinal in 0..RECORDS {
            path.push_with(id(ordinal), tempfile::tempfile).unwrap();
        }
        assert!(path
            .push_with(id(RECORDS), || std::fs::File::open(named.path()))
            .is_err());
        assert_eq!((path.buffered, path.spilled), (RECORDS, 0));
        assert!(path.file.is_none());
        // Preserve the current batch spool: the next mandatory write follows
        // another complete in-memory batch, rather than every pushed locator.
        for ordinal in RECORDS..2 * RECORDS {
            path.push_with(id(ordinal), tempfile::tempfile).unwrap();
        }
        path.file = Some(std::fs::File::open(named.path()).unwrap());
        assert!(path.push_with(id(2 * RECORDS), tempfile::tempfile).is_err());
        assert_eq!(
            (path.buffered, path.spilled),
            (RECORDS, (RECORDS * WIDTH) as u64)
        );
    }

    #[test]
    fn locator_cancel_precedes_access_and_retains_exact_retry_order() {
        for count in [1, 128, 129, 257] {
            let mut path = ReversePath::new_lazy();
            for ordinal in 0..count {
                path.push_with(id(ordinal), tempfile::tempfile).unwrap();
            }
            let mut successful = 0;
            for ordinal in (0..count).rev() {
                let error = path
                    .pop_with_progress(&mut || Err("PUBLIC_REQUEST_CANCELLED".into()))
                    .unwrap_err();
                assert_eq!(error.to_string(), "PUBLIC_REQUEST_CANCELLED");
                assert_eq!(
                    path.spilled / WIDTH as u64 + path.buffered as u64,
                    ordinal as u64 + 1
                );
                assert_eq!(
                    path.pop_with_progress(&mut || {
                        successful += 1;
                        Ok(())
                    })
                    .unwrap(),
                    Some(id(ordinal))
                );
            }
            assert_eq!(successful, count);
        }
    }

    #[test]
    fn locator_cancel_wins_before_a_real_truncated_spool_read_error() {
        let mut path = ReversePath::new_lazy();
        for ordinal in 0..=RECORDS {
            path.push_with(id(ordinal), tempfile::tempfile).unwrap();
        }
        path.file.as_ref().unwrap().set_len(0).unwrap();
        // The existing batched reader retains the final locator in memory.
        assert_eq!(
            path.pop_with_progress(&mut || Ok(())).unwrap(),
            Some(id(RECORDS))
        );
        let cancelled = path
            .pop_with_progress(&mut || Err("PUBLIC_REQUEST_CANCELLED".into()))
            .unwrap_err();
        assert_eq!(cancelled.to_string(), "PUBLIC_REQUEST_CANCELLED");
        let read = path.pop_with_progress(&mut || Ok(())).unwrap_err();
        let source = std::error::Error::source(&read)
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!((path.buffered, path.spilled), (0, (RECORDS * WIDTH) as u64));
    }
}
