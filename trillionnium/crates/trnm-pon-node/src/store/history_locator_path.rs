//! Bounded scratch locators for one current State reconstruction, never State
//! or a validation verdict. The first 128 hashes occupy exactly 4 KiB of array
//! payload, plus fixed count/File metadata. This is not a process RSS bound.
//! Longer paths use the original anonymous tempfile and propagate its failures.
use crate::Result;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

const MEMORY_LOCATORS: usize = 128;
type Locator = [u8; 32];

pub(super) struct LocatorPath {
    memory: [Locator; MEMORY_LOCATORS],
    count: u64,
    spill: Option<File>,
}

impl LocatorPath {
    pub(super) fn new() -> Self {
        Self {
            memory: [[0; 32]; MEMORY_LOCATORS],
            count: 0,
            spill: None,
        }
    }

    pub(super) fn push(&mut self, locator: Locator) -> Result<()> {
        self.push_with(locator, tempfile::tempfile)
    }

    fn push_with(
        &mut self,
        locator: Locator,
        create: impl FnOnce() -> io::Result<File>,
    ) -> Result<()> {
        if let Some(file) = &mut self.spill {
            file.write_all(&locator)?;
        } else if self.count < MEMORY_LOCATORS as u64 {
            self.memory[self.count as usize] = locator;
        } else {
            // No successful in-memory fallback if the required spool fails.
            // Once spilled, every locator uses the original file ordering.
            let mut file = create()?;
            file.write_all(self.memory.as_flattened())?;
            file.write_all(&locator)?;
            self.spill = Some(file);
        }
        // Keep the original write-before-count-overflow error order.
        self.count = self.count.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
        Ok(())
    }

    pub(super) fn reverse(self) -> ReverseLocators {
        ReverseLocators(self)
    }
}

// Consuming the builder prevents appending after reads moved the spool cursor.
pub(super) struct ReverseLocators(LocatorPath);

impl ReverseLocators {
    pub(super) fn pop(
        &mut self,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Option<Locator>> {
        if self.0.count == 0 {
            return Ok(None);
        }
        // This is the existing State reconstruction's per-locator checkpoint,
        // immediately before the original seek/read or the array access.
        progress()?;
        let ordinal = self.0.count - 1;
        let locator = if let Some(file) = &mut self.0.spill {
            file.seek(SeekFrom::Start(
                ordinal.checked_mul(32).ok_or("ANCESTRY_LIMIT")?,
            ))?;
            let mut locator = [0; 32];
            file.read_exact(&mut locator)?;
            locator
        } else {
            self.0.memory[ordinal as usize]
        };
        self.0.count = ordinal;
        Ok(Some(locator))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn locator(ordinal: usize) -> Locator {
        let mut value = [0xa5; 32];
        value[..8].copy_from_slice(&(ordinal as u64).to_le_bytes());
        value[24..].copy_from_slice(&(!(ordinal as u64)).to_le_bytes());
        value
    }

    fn io_source(error: &crate::Error) -> &io::Error {
        std::error::Error::source(error)
            .unwrap()
            .downcast_ref()
            .unwrap()
    }

    #[test]
    fn locator_reverse_matches_original_file_at_empty_boundary_and_spill_lengths() {
        assert_eq!(std::mem::size_of::<[Locator; MEMORY_LOCATORS]>(), 4096);
        for count in [0, 1, 127, 128, 129, 256, 257] {
            let creates = Cell::new(0);
            let mut path = LocatorPath::new();
            let mut original = tempfile::tempfile().unwrap();
            for ordinal in 0..count {
                let value = locator(ordinal);
                original.write_all(&value).unwrap();
                path.push_with(value, || {
                    creates.set(creates.get() + 1);
                    tempfile::tempfile()
                })
                .unwrap();
            }
            assert_eq!(creates.get(), usize::from(count > MEMORY_LOCATORS));
            let mut reverse = path.reverse();
            let mut checkpoints = 0;
            for ordinal in (0..count).rev() {
                original.seek(SeekFrom::Start(ordinal as u64 * 32)).unwrap();
                let mut expected = [0; 32];
                original.read_exact(&mut expected).unwrap();
                let actual = reverse
                    .pop(&mut || {
                        checkpoints += 1;
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(actual, Some(expected), "{count} / {ordinal}");
            }
            assert!(reverse
                .pop(&mut || panic!("empty path has no locator checkpoint"))
                .unwrap()
                .is_none());
            assert_eq!(checkpoints, count);
        }
    }

    #[test]
    fn locator_tempfile_is_required_only_after_the_fixed_memory_bound() {
        let mut path = LocatorPath::new();
        for ordinal in 0..MEMORY_LOCATORS {
            path.push_with(locator(ordinal), || panic!("spool below bound"))
                .unwrap();
        }
        let error = path
            .push_with(locator(MEMORY_LOCATORS), || {
                Err(io::ErrorKind::PermissionDenied.into())
            })
            .unwrap_err();
        assert_eq!(io_source(&error).kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(path.count, MEMORY_LOCATORS as u64);
        assert!(path.spill.is_none());
    }

    #[test]
    fn locator_spill_copy_and_later_write_failures_propagate() {
        let named = tempfile::NamedTempFile::new().unwrap();
        let mut path = LocatorPath::new();
        for ordinal in 0..MEMORY_LOCATORS {
            path.push(locator(ordinal)).unwrap();
        }
        let error = path
            .push_with(locator(MEMORY_LOCATORS), || File::open(named.path()))
            .unwrap_err();
        assert!(std::error::Error::source(&error).unwrap().is::<io::Error>());
        assert_eq!(path.count, MEMORY_LOCATORS as u64);
        assert!(path.spill.is_none());

        path.push(locator(MEMORY_LOCATORS)).unwrap();
        // Replace only this test's scratch file with a real read-only file.
        // Production has no file/verdict injection surface.
        path.spill = Some(File::open(named.path()).unwrap());
        let error = path.push(locator(MEMORY_LOCATORS + 1)).unwrap_err();
        assert!(std::error::Error::source(&error).unwrap().is::<io::Error>());
        assert_eq!(path.count, MEMORY_LOCATORS as u64 + 1);
    }

    #[test]
    fn locator_cancel_precedes_access_and_retains_exact_retry_order() {
        for count in [1, 128, 129, 257] {
            let mut path = LocatorPath::new();
            for ordinal in 0..count {
                path.push(locator(ordinal)).unwrap();
            }
            let mut reverse = path.reverse();
            let mut successful = 0;
            for ordinal in (0..count).rev() {
                let error = reverse
                    .pop(&mut || Err("PUBLIC_REQUEST_CANCELLED".into()))
                    .unwrap_err();
                assert_eq!(error.to_string(), "PUBLIC_REQUEST_CANCELLED");
                assert_eq!(reverse.0.count, ordinal as u64 + 1);
                assert_eq!(
                    reverse
                        .pop(&mut || {
                            successful += 1;
                            Ok(())
                        })
                        .unwrap(),
                    Some(locator(ordinal))
                );
            }
            assert_eq!(successful, count);
        }
    }

    #[test]
    fn locator_cancel_wins_before_a_real_truncated_spool_read_error() {
        let mut path = LocatorPath::new();
        for ordinal in 0..=MEMORY_LOCATORS {
            path.push(locator(ordinal)).unwrap();
        }
        path.spill.as_ref().unwrap().set_len(0).unwrap();
        let mut reverse = path.reverse();
        let cancelled = reverse
            .pop(&mut || Err("PUBLIC_REQUEST_CANCELLED".into()))
            .unwrap_err();
        assert_eq!(cancelled.to_string(), "PUBLIC_REQUEST_CANCELLED");
        let read = reverse.pop(&mut || Ok(())).unwrap_err();
        assert_eq!(io_source(&read).kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(reverse.0.count, MEMORY_LOCATORS as u64 + 1);
    }
}
