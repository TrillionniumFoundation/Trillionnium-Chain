//! A frame has one elapsed-time budget across its header and all partial reads.

use std::{
    io::{self, Read},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

use super::{ExternalCheckpointAuthorityErrorV2, MAX_FRAME_BYTES_V2};

pub(super) fn read_frame_v2(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<Vec<u8>, ExternalCheckpointAuthorityErrorV2> {
    let started = Instant::now();
    read_frame_with_budget_v2(
        stream,
        timeout,
        || started.elapsed(),
        |stream, remaining| stream.set_read_timeout(Some(remaining)),
    )
}

struct FrameDeadlineReaderV2<'a, R, E, T> {
    inner: &'a mut R,
    timeout: Duration,
    elapsed: E,
    set_timeout: T,
}

impl<R, E, T> Read for FrameDeadlineReaderV2<'_, R, E, T>
where
    R: Read,
    E: FnMut() -> Duration,
    T: FnMut(&mut R, Duration) -> io::Result<()>,
{
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // Subtract elapsed time instead of adding an externally configured
        // duration to Instant: even Duration::MAX cannot overflow this budget.
        let remaining = self
            .timeout
            .checked_sub((self.elapsed)())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(frame_timeout_v2)?;
        (self.set_timeout)(self.inner, remaining)?;
        let result = self.inner.read(buffer);
        // A final successful read at or after the deadline must not admit the
        // frame. Preserve an underlying I/O error; Interrupted is retried by
        // read_exact, which rechecks this same budget before the next read.
        if result.is_ok() && (self.elapsed)() >= self.timeout {
            return Err(frame_timeout_v2());
        }
        result
    }
}

fn frame_timeout_v2() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "checkpoint frame deadline expired")
}

fn read_frame_with_budget_v2<R, E, T>(
    stream: &mut R,
    timeout: Duration,
    elapsed: E,
    set_timeout: T,
) -> Result<Vec<u8>, ExternalCheckpointAuthorityErrorV2>
where
    R: Read,
    E: FnMut() -> Duration,
    T: FnMut(&mut R, Duration) -> io::Result<()>,
{
    let mut stream = FrameDeadlineReaderV2 {
        inner: stream,
        timeout,
        elapsed,
        set_timeout,
    };
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "read frame length",
            source,
        })?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES_V2 {
        return Err(ExternalCheckpointAuthorityErrorV2::Protocol("frame length"));
    }
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "read frame body",
            source,
        })?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, collections::VecDeque, rc::Rc};

    enum Step {
        Bytes(Duration, Vec<u8>),
        Error(Duration, io::ErrorKind),
    }

    fn bytes(milliseconds: u64, value: &[u8]) -> Step {
        Step::Bytes(Duration::from_millis(milliseconds), value.to_vec())
    }

    struct MemoryReader {
        steps: VecDeque<Step>,
        elapsed: Rc<Cell<Duration>>,
        reads: usize,
        timeouts: Vec<Duration>,
    }

    impl MemoryReader {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                elapsed: Rc::new(Cell::new(Duration::ZERO)),
                reads: 0,
                timeouts: Vec::new(),
            }
        }

        fn frame(
            &mut self,
            timeout: Duration,
        ) -> Result<Vec<u8>, ExternalCheckpointAuthorityErrorV2> {
            let elapsed = Rc::clone(&self.elapsed);
            read_frame_with_budget_v2(
                self,
                timeout,
                || elapsed.get(),
                |reader, remaining| {
                    reader.timeouts.push(remaining);
                    Ok(())
                },
            )
        }
    }

    impl Read for MemoryReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            match self.steps.pop_front().expect("unexpected extra read") {
                Step::Bytes(after, value) => {
                    self.elapsed.set(self.elapsed.get() + after);
                    assert!(value.len() <= buffer.len());
                    buffer[..value.len()].copy_from_slice(&value);
                    Ok(value.len())
                }
                Step::Error(after, kind) => {
                    self.elapsed.set(self.elapsed.get() + after);
                    Err(io::Error::from(kind))
                }
            }
        }
    }

    fn assert_io(
        result: Result<Vec<u8>, ExternalCheckpointAuthorityErrorV2>,
        expected_stage: &str,
        expected_kind: io::ErrorKind,
    ) {
        match result {
            Err(ExternalCheckpointAuthorityErrorV2::Io { stage, source }) => {
                assert_eq!(stage, expected_stage);
                assert_eq!(source.kind(), expected_kind);
            }
            other => panic!("unexpected frame result: {other:?}"),
        }
    }

    #[test]
    fn complete_frame_uses_remaining_budget_for_each_partial_read() {
        let mut reader = MemoryReader::new([
            bytes(1000, &[0, 0]),
            bytes(1000, &[0, 2]),
            bytes(1000, b"o"),
            bytes(1000, b"k"),
        ]);
        assert_eq!(reader.frame(Duration::from_secs(5)).unwrap(), b"ok");
        assert_eq!(reader.timeouts, [5, 4, 3, 2].map(Duration::from_secs));
    }

    #[test]
    fn partial_body_reads_cannot_restart_the_frame_budget() {
        let mut reader = MemoryReader::new([
            bytes(0, &[0, 0, 0, 3]),
            bytes(2000, b"a"),
            bytes(2000, b"b"),
            bytes(2000, b"c"),
        ]);
        assert_io(
            reader.frame(Duration::from_secs(5)),
            "read frame body",
            io::ErrorKind::TimedOut,
        );
        assert_eq!(reader.timeouts, [5, 5, 3, 1].map(Duration::from_secs));
    }

    #[test]
    fn header_and_body_share_deadline_and_final_read_at_deadline_is_rejected() {
        for body_milliseconds in [2000, 2001] {
            let mut reader =
                MemoryReader::new([bytes(3000, &[0, 0, 0, 1]), bytes(body_milliseconds, b"x")]);
            assert_io(
                reader.frame(Duration::from_secs(5)),
                "read frame body",
                io::ErrorKind::TimedOut,
            );
            assert_eq!(reader.timeouts, [5, 2].map(Duration::from_secs));
        }
    }

    #[test]
    fn interrupted_read_retries_only_with_remaining_time() {
        let mut reader = MemoryReader::new([
            Step::Error(Duration::from_secs(2), io::ErrorKind::Interrupted),
            bytes(1000, &[0, 0, 0, 1]),
            bytes(1000, b"x"),
        ]);
        assert_eq!(reader.frame(Duration::from_secs(5)).unwrap(), b"x");
        assert_eq!(reader.timeouts, [5, 3, 2].map(Duration::from_secs));

        let mut reader = MemoryReader::new([Step::Error(
            Duration::from_secs(5),
            io::ErrorKind::Interrupted,
        )]);
        assert_io(
            reader.frame(Duration::from_secs(5)),
            "read frame length",
            io::ErrorKind::TimedOut,
        );
        assert_eq!(reader.reads, 1);
    }

    #[test]
    fn eof_before_deadline_keeps_original_length_or_body_error() {
        let mut reader = MemoryReader::new([bytes(0, &[])]);
        assert_io(
            reader.frame(Duration::from_secs(5)),
            "read frame length",
            io::ErrorKind::UnexpectedEof,
        );
        let mut reader =
            MemoryReader::new([bytes(0, &[0, 0, 0, 2]), bytes(0, b"x"), bytes(0, &[])]);
        assert_io(
            reader.frame(Duration::from_secs(5)),
            "read frame body",
            io::ErrorKind::UnexpectedEof,
        );
        // An EOF returned at the deadline is still rejected before the header
        // decoder runs; elapsed-time expiry takes priority over a zero read.
        let mut reader = MemoryReader::new([bytes(5000, &[])]);
        assert_io(
            reader.frame(Duration::from_secs(5)),
            "read frame length",
            io::ErrorKind::TimedOut,
        );
    }

    #[test]
    fn invalid_length_is_checked_only_after_a_timely_header() {
        for length in [0, MAX_FRAME_BYTES_V2 as u32 + 1] {
            let mut reader = MemoryReader::new([bytes(0, &length.to_be_bytes())]);
            assert!(matches!(
                reader.frame(Duration::from_secs(5)),
                Err(ExternalCheckpointAuthorityErrorV2::Protocol("frame length"))
            ));
            assert_eq!(reader.reads, 1);

            let mut reader = MemoryReader::new([bytes(5000, &length.to_be_bytes())]);
            assert_io(
                reader.frame(Duration::from_secs(5)),
                "read frame length",
                io::ErrorKind::TimedOut,
            );
        }
    }

    #[test]
    fn zero_budget_is_refused_without_reading_and_max_budget_does_not_overflow() {
        let mut reader = MemoryReader::new([]);
        assert_io(
            reader.frame(Duration::ZERO),
            "read frame length",
            io::ErrorKind::TimedOut,
        );
        assert!(reader.timeouts.is_empty());
        assert_eq!(reader.reads, 0);

        let mut reader = MemoryReader::new([bytes(1000, &[0, 0, 0, 1]), bytes(1000, b"x")]);
        assert_eq!(reader.frame(Duration::MAX).unwrap(), b"x");
        assert_eq!(reader.timeouts[0], Duration::MAX);
        assert_eq!(reader.timeouts[1], Duration::MAX - Duration::from_secs(1));
    }

    #[test]
    fn timeout_setter_failure_keeps_io_mapping_and_never_reads() {
        let mut reader = MemoryReader::new([]);
        assert_io(
            read_frame_with_budget_v2(
                &mut reader,
                Duration::from_secs(5),
                || Duration::ZERO,
                |_, _| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            ),
            "read frame length",
            io::ErrorKind::PermissionDenied,
        );
        assert_eq!(reader.reads, 0);
    }

    #[test]
    fn underlying_io_failure_keeps_its_error_even_when_time_has_elapsed() {
        let mut reader = MemoryReader::new([Step::Error(
            Duration::from_secs(5),
            io::ErrorKind::ConnectionReset,
        )]);
        assert_io(
            reader.frame(Duration::from_secs(5)),
            "read frame length",
            io::ErrorKind::ConnectionReset,
        );
    }
}
