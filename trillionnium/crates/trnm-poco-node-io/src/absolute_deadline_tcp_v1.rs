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
