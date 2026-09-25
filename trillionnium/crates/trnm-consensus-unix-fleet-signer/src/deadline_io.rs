//! Private fleet-client I/O with one deadline; no signer/request retry.
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    thread,
    time::{Duration, Instant},
};

pub(super) struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}

fn timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "fleet signer operation deadline exceeded",
    )
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(timeout)
}

fn new_stream() -> io::Result<UnixStream> {
    use rustix::net::{AddressFamily, SocketType};
    #[cfg(not(target_vendor = "apple"))]
    let fd = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )?;
    #[cfg(target_vendor = "apple")]
    let fd = {
        let fd = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
        rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
        fd
    };
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(true)?;
    Ok(stream)
}

impl DeadlineStream {
    pub(super) fn connect(path: &Path, deadline: Instant) -> io::Result<Self> {
        remaining(deadline)?;
        let address = rustix::net::SocketAddrUnix::new(path)?;
        let result = Self {
            stream: new_stream()?,
            deadline,
        };
        loop {
            remaining(deadline)?;
            match rustix::net::connect(&result.stream, &address) {
                Ok(()) | Err(rustix::io::Errno::ISCONN) => break,
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) if error == rustix::io::Errno::AGAIN => {
                    // AF_UNIX backlog exhaustion did NOT initiate a connection.
                    // A writable fd/SO_ERROR=0 cannot prove one; retry connect,
                    // never a request, within the same finite budget.
                    thread::sleep(remaining(deadline)?.min(Duration::from_millis(1)));
                }
                Err(error)
                    if error == rustix::io::Errno::INPROGRESS
                        || error == rustix::io::Errno::ALREADY =>
                {
                    result.wait_ready(PollFlags::OUT)?;
                    if let Some(error) = result.stream.take_error()? {
                        return Err(error);
                    }
                    result.stream.peer_addr()?;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        remaining(deadline)?;
        Ok(result)
    }

    fn wait_ready(&self, interest: PollFlags) -> io::Result<()> {
        loop {
            let timeout_value =
                Timespec::try_from(remaining(self.deadline)?).map_err(io::Error::other)?;
            let mut fds = [PollFd::new(
                &self.stream,
                interest | PollFlags::ERR | PollFlags::HUP,
            )];
            match poll(&mut fds, Some(&timeout_value)) {
                Ok(0) => return Err(timeout()),
                Ok(_) => {
                    if fds[0].revents().contains(PollFlags::NVAL) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "invalid fleet signer socket",
                        ));
                    }
                    remaining(self.deadline)?;
                    return Ok(());
                }
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            remaining(self.deadline)?;
            match self.stream.read(bytes) {
                Ok(count) => {
                    remaining(self.deadline)?;
                    return Ok(count);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait_ready(PollFlags::IN)?
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            remaining(self.deadline)?;
            match self.stream.write(bytes) {
                Ok(count) => {
                    remaining(self.deadline)?;
                    return Ok(count);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait_ready(PollFlags::OUT)?
                }
                Err(error) => return Err(error),
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        remaining(self.deadline)?;
        // UnixStream has no userspace write buffer.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_budget_fails_before_socket_creation() {
        let result =
            DeadlineStream::connect(Path::new("/unavailable-fleet-signer"), Instant::now());
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
    }

    #[test]
    fn buffered_bytes_survive_peer_close() {
        let (mut peer, stream) = UnixStream::pair().unwrap();
        peer.write_all(b"actual reply").unwrap();
        drop(peer);
        stream.set_nonblocking(true).unwrap();
        let mut bounded = DeadlineStream {
            stream,
            deadline: Instant::now() + Duration::from_secs(1),
        };
        let mut reply = Vec::new();
        bounded.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"actual reply");
    }

    #[test]
    fn backpressured_write_keeps_original_deadline() {
        let (_peer, stream) = UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        let start = Instant::now();
        let mut bounded = DeadlineStream {
            stream,
            deadline: start + Duration::from_millis(100),
        };
        let error = bounded.write_all(&vec![0; 4 * 1024 * 1024]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
