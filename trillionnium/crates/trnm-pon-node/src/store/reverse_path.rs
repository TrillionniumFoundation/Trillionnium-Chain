//! Operation-local reverse ancestry spool. Only locators are buffered, never
//! validation verdicts or State. Storage stays bounded at 128 locators in RAM;
//! older locators spill to the same temporary file and are read in reverse batches.
use std::io::{self, Read, Seek, SeekFrom, Write};

const RECORDS: usize = 128;
const WIDTH: usize = 32;

pub(super) struct ReversePath<T> {
    file: T,
    buffer: [u8; RECORDS * WIDTH],
    buffered: usize,
    spilled: u64,
}

impl<T: Read + Write + Seek> ReversePath<T> {
    pub(super) fn new(file: T) -> Self {
        Self {
            file,
            buffer: [0; RECORDS * WIDTH],
            buffered: 0,
            spilled: 0,
        }
    }

    // Collection must finish before the first pop. No external writer has this
    // private spool; all durable SQL rows are still read and checked by the caller.
    pub(super) fn push(&mut self, id: [u8; WIDTH]) -> io::Result<()> {
        if self.buffered == RECORDS {
            let next = self
                .spilled
                .checked_add(self.buffer.len() as u64)
                .ok_or_else(|| io::Error::other("ANCESTRY_LIMIT"))?;
            self.file.write_all(&self.buffer)?;
            self.spilled = next;
            self.buffered = 0;
        }
        let start = self.buffered * WIDTH;
        self.buffer[start..start + WIDTH].copy_from_slice(&id);
        self.buffered += 1;
        Ok(())
    }

    pub(super) fn pop(&mut self) -> io::Result<Option<[u8; WIDTH]>> {
        if self.buffered == 0 {
            if self.spilled == 0 {
                return Ok(None);
            }
            let start = self.spilled - self.buffer.len() as u64;
            self.file.seek(SeekFrom::Start(start))?;
            self.file.read_exact(&mut self.buffer)?;
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
                path.file.get_ref().len(),
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
        path.file.get_mut().truncate(RECORDS * WIDTH - 1);
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
            (path.file.writes, path.file.reads, path.file.seeks),
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
}
