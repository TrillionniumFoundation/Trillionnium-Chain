//! Explicit candidate absolute-deadline TCP adapter for bounded state transfer.
//!
//! Peer bytes remain untrusted. This adapter contains no application, proof
//! verifier, trust context or cryptographic state. It
//! supplies only absolute read/write deadlines and one-shot framing transport;
//! it cannot select validator keys, sign, vote, clear Core fences or activate a
//! node. TCP provides neither peer authentication nor confidentiality here.

use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    time::Instant,
};
/// Owned connected byte stream. Every read/write reuses one absolute deadline.
/// No raw socket, clone, timer reset or authority constructor is exported.
/// Successful I/O authenticates neither the peer nor the transferred state.
pub struct AbsoluteDeadlineTcpStreamV1 {
    stream: TcpStream,
    deadline: Instant,
}
impl AbsoluteDeadlineTcpStreamV1 {
    /// Caller owns connect/DNS, peer identity, confidentiality and global quotas.
    /// This timer covers socket I/O only, not ongoing database/crypto work.
    pub fn new(stream: TcpStream, deadline: Instant) -> io::Result<Self> {
        let value = Self { stream, deadline };
        value.remaining()?;
        Ok(value)
    }

    /// One-shot source completion. This is not receiver commit acknowledgement.
    pub fn finish_write(&self) -> io::Result<()> {
        self.stream.shutdown(Shutdown::Write)
    }

    fn remaining(&self) -> io::Result<std::time::Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "native catch-up absolute deadline")
            })
    }
}
impl Read for AbsoluteDeadlineTcpStreamV1 {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for AbsoluteDeadlineTcpStreamV1 {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread, time::Duration};
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }
    #[test]
    fn expired_deadline_does_not_read_or_write_ready_socket() {
        let (client, mut server) = pair();
        server.write_all(b"x").unwrap();
        let mut bounded = AbsoluteDeadlineTcpStreamV1 {
            stream: client,
            deadline: Instant::now(),
        };
        assert_eq!(
            bounded.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            bounded.write(b"y").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(bounded.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
        server.set_nonblocking(true).unwrap();
        assert_eq!(
            server.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn fragmented_input_cannot_extend_absolute_deadline() {
        let (client, mut server) = pair();
        let sender = thread::spawn(move || {
            for _ in 0..20 {
                if server.write_all(b"x").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(30));
            }
        });
        let mut bounded = AbsoluteDeadlineTcpStreamV1 {
            stream: client,
            deadline: Instant::now() + Duration::from_millis(120),
        };
        let error = bounded.read_exact(&mut [0; 20]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        // Even if the OS reports WouldBlock, a later retry still uses the same
        // deadline; successful partial reads never reset it.
        thread::sleep(Duration::from_millis(150));
        assert_eq!(
            bounded.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(bounded);
        sender.join().unwrap();
    }
    #[test]
    fn complete_fragmented_exchange_and_half_close_preserve_bytes() {
        let (client, mut server) = pair();
        let sender = thread::spawn(move || {
            server.write_all(b"abc").unwrap();
            server.write_all(b"def").unwrap();
            server.shutdown(Shutdown::Write).unwrap();
        });
        let mut bounded = AbsoluteDeadlineTcpStreamV1 {
            stream: client,
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let mut bytes = Vec::new();
        bounded.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcdef");
        sender.join().unwrap();
    }
}
