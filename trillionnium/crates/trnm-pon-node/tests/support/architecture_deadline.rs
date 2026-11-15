//! Absolute, cancellable socket budgets for the research dissemination fixture.
//!
//! A socket timeout bounds one blocking syscall. It does not bound a complete
//! fragmented frame. Every retry below uses the same end, and completion checks
//! that end again. This cannot preempt a kernel or filesystem stall.

use std::{
    io::{self, Read, Write},
    net::TcpStream,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const CANCEL_POLL: Duration = Duration::from_millis(20);

pub fn remaining(end: Instant, cancelled: &AtomicBool) -> io::Result<Duration> {
    if cancelled.load(Ordering::Acquire) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "CELL_CANCELLED"));
    }
    let left = end.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "CELL_ABSOLUTE_DEADLINE",
        ));
    }
    Ok(left)
}

pub fn read_exact(
    stream: &mut TcpStream,
    mut buffer: &mut [u8],
    end: Instant,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    while !buffer.is_empty() {
        stream.set_read_timeout(Some(remaining(end, cancelled)?.min(CANCEL_POLL)))?;
        match stream.read(buffer) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => buffer = &mut buffer[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    remaining(end, cancelled).map(|_| ())
}

pub fn write_all(
    stream: &mut TcpStream,
    mut buffer: &[u8],
    end: Instant,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    while !buffer.is_empty() {
        stream.set_write_timeout(Some(remaining(end, cancelled)?.min(CANCEL_POLL)))?;
        match stream.write(buffer) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => buffer = &buffer[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    remaining(end, cancelled).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{Shutdown, TcpListener},
        sync::{mpsc, Arc},
        thread,
    };

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn expired_frame_does_not_consume_available_bytes() {
        let (mut reader, mut writer) = pair();
        writer.write_all(b"live").unwrap();
        let stop = AtomicBool::new(false);
        let mut bytes = [0; 4];
        assert_eq!(
            read_exact(&mut reader, &mut bytes, Instant::now(), &stop)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        read_exact(
            &mut reader,
            &mut bytes,
            Instant::now() + Duration::from_secs(2),
            &stop,
        )
        .unwrap();
        assert_eq!(&bytes, b"live");
    }

    #[test]
    fn fragmented_frame_completes_within_one_original_budget() {
        let (mut reader, mut writer) = pair();
        let sender = thread::spawn(move || {
            writer.write_all(b"ab").unwrap();
            thread::sleep(Duration::from_millis(30));
            writer.write_all(b"cd").unwrap();
        });
        let mut bytes = [0; 4];
        read_exact(
            &mut reader,
            &mut bytes,
            Instant::now() + Duration::from_secs(2),
            &AtomicBool::new(false),
        )
        .unwrap();
        sender.join().unwrap();
        assert_eq!(&bytes, b"abcd");
    }

    #[test]
    fn continued_fragment_progress_cannot_renew_frame_deadline() {
        let (mut reader, mut writer) = pair();
        let stop = Arc::new(AtomicBool::new(false));
        let sender_stop = stop.clone();
        let sender = thread::spawn(move || {
            while !sender_stop.load(Ordering::Acquire) {
                if writer.write_all(b"x").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
        });
        let result = read_exact(
            &mut reader,
            &mut [0; 4096],
            Instant::now() + Duration::from_millis(90),
            &stop,
        );
        stop.store(true, Ordering::Release);
        sender.join().unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn header_and_body_reads_share_the_original_frame_end() {
        let (mut reader, mut writer) = pair();
        let sender = thread::spawn(move || {
            thread::sleep(Duration::from_millis(80));
            writer.write_all(b"h").unwrap();
            thread::sleep(Duration::from_millis(180));
            let _ = writer.write_all(b"b");
        });
        let end = Instant::now() + Duration::from_millis(220);
        let stop = AtomicBool::new(false);
        read_exact(&mut reader, &mut [0; 1], end, &stop).unwrap();
        let result = read_exact(&mut reader, &mut [0; 1], end, &stop);
        sender.join().unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn cancellation_wakes_a_waiting_receiver() {
        let (mut reader, _writer) = pair();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            tx.send(read_exact(
                &mut reader,
                &mut [0; 4],
                Instant::now() + Duration::from_secs(5),
                &worker_stop,
            ))
            .unwrap();
        });
        thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::Release);
        let result = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn stalled_writer_ends_under_original_deadline() {
        let (mut writer, _reader) = pair();
        let data = vec![7; 16 * 1024 * 1024];
        assert_eq!(
            write_all(
                &mut writer,
                &data,
                Instant::now() + Duration::from_millis(90),
                &AtomicBool::new(false),
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn cancelled_writer_does_not_send_a_new_frame() {
        let (mut writer, mut reader) = pair();
        assert_eq!(
            write_all(
                &mut writer,
                b"x",
                Instant::now() + Duration::from_secs(2),
                &AtomicBool::new(true),
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        reader.set_nonblocking(true).unwrap();
        assert_eq!(
            reader.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn partial_eof_remains_an_error() {
        let (mut reader, mut writer) = pair();
        writer.write_all(b"ab").unwrap();
        writer.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            read_exact(
                &mut reader,
                &mut [0; 4],
                Instant::now() + Duration::from_secs(2),
                &AtomicBool::new(false),
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn empty_completion_still_observes_expiry_and_cancellation() {
        let (mut reader, mut writer) = pair();
        assert_eq!(
            read_exact(
                &mut reader,
                &mut [],
                Instant::now(),
                &AtomicBool::new(false)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            write_all(
                &mut writer,
                &[],
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(true),
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
    }
}
