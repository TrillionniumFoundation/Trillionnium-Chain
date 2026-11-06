//! One bounded connection per signed request; the absolute deadline never resets.
use super::frontier::{invalid, Result};
use super::trust_wire::MAX_FRAME;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use rustix::net::{
    connect as connect_socket, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType,
};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

fn remaining(until: Instant) -> Result<Duration> {
    until
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "M15 signed service deadline"))
}

fn ready(stream: &UnixStream, events: PollFlags, until: Instant) -> Result<()> {
    loop {
        let left = remaining(until)?;
        let millis = left.as_millis().saturating_add(1).min(u128::from(u16::MAX)) as u16;
        let mut fds = [PollFd::new(stream.as_fd(), events)];
        match poll(&mut fds, PollTimeout::from(millis)) {
            Ok(0) => continue,
            Ok(_) => {
                remaining(until)?;
                let actual = fds[0]
                    .revents()
                    .ok_or_else(|| invalid("M15 socket poll flags"))?;
                if actual.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
                    return Err(stream
                        .take_error()?
                        .unwrap_or_else(|| invalid("M15 socket rejected")));
                }
                if actual.intersects(events | PollFlags::POLLHUP) {
                    return Ok(());
                }
            }
            Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
}

fn connect(path: &Path, until: Instant) -> Result<UnixStream> {
    if !path.is_absolute()
        || path
            .parent()
            .ok_or_else(|| invalid("missing socket parent"))?
            .canonicalize()?
            != path
                .parent()
                .ok_or_else(|| invalid("missing socket parent"))?
    {
        return Err(invalid("M15 socket path is not absolute and canonical"));
    }
    let fd = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    let stream = UnixStream::from(fd);
    let address = SocketAddrUnix::new(path)?;
    loop {
        remaining(until)?;
        match connect_socket(&stream, &address) {
            Ok(()) => break,
            Err(rustix::io::Errno::INTR) => continue,
            Err(rustix::io::Errno::AGAIN) => {
                std::thread::sleep(remaining(until)?.min(Duration::from_millis(1)));
            }
            Err(rustix::io::Errno::INPROGRESS) => {
                ready(&stream, PollFlags::POLLOUT, until)?;
                if let Some(error) = stream.take_error()? {
                    return Err(error);
                }
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    remaining(until)?;
    Ok(stream)
}

fn write_all(stream: &mut UnixStream, mut bytes: &[u8], until: Instant) -> Result<()> {
    while !bytes.is_empty() {
        remaining(until)?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                ready(stream, PollFlags::POLLOUT, until)?
            }
            Err(error) => return Err(error),
        }
    }
    remaining(until)?;
    Ok(())
}

fn read_all(stream: &mut UnixStream, mut bytes: &mut [u8], until: Instant) -> Result<()> {
    while !bytes.is_empty() {
        remaining(until)?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => bytes = &mut bytes[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                ready(stream, PollFlags::POLLIN, until)?
            }
            Err(error) => return Err(error),
        }
    }
    remaining(until)?;
    Ok(())
}

pub(super) fn exchange(path: &Path, request: &[u8], until: Instant) -> Result<Vec<u8>> {
    if request.is_empty() || request.len() > MAX_FRAME {
        return Err(invalid("M15 request frame bound"));
    }
    let mut stream = connect(path, until)?;
    write_all(&mut stream, &(request.len() as u32).to_be_bytes(), until)?;
    write_all(&mut stream, request, until)?;
    let mut header = [0; 4];
    read_all(&mut stream, &mut header, until)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(invalid("M15 reply frame bound"));
    }
    let mut reply = vec![0; length];
    read_all(&mut stream, &mut reply, until)?;
    Ok(reply)
}

/// Server transport uses the same original absolute deadline and frame bound.
pub(super) fn receive(stream: &mut UnixStream, until: Instant) -> Result<Vec<u8>> {
    let mut header = [0; 4];
    read_all(stream, &mut header, until)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(invalid("M15 request frame bound"));
    }
    let mut bytes = vec![0; length];
    read_all(stream, &mut bytes, until)?;
    Ok(bytes)
}
pub(super) fn send(stream: &mut UnixStream, bytes: &[u8], until: Instant) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(invalid("M15 reply frame bound"));
    }
    write_all(stream, &(bytes.len() as u32).to_be_bytes(), until)?;
    write_all(stream, bytes, until)
}
