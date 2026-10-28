//! Controller lifetime for the isolated native History fixture.
//!
//! Authority is the private, anonymous socketpair plus the queued kernel pidfd.
//! Numeric peer credentials are observations and consistency checks, not a PID
//! lookup API or authentication by a same-UID pathname listener. Only the
//! controller's own pidfd can be created by the public constructor here.
//! This fixture-local watcher never sends a signal to another process.
use std::io;
use std::mem::{size_of, size_of_val, MaybeUninit};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::sync::mpsc;
use std::thread;

const PREFACE: u8 = 0xa1;
const EXIT_OWNER_LOST: i32 = 137;
const CONTROL_WORDS: usize = 8;

/// The sole controller endpoint remains owned until the service has exited.
pub(crate) struct ControllerLifeline {
    _endpoint: UnixStream,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OwnerObservation {
    pub(crate) peer_pid: libc::pid_t,
    pub(crate) peer_uid: libc::uid_t,
    pub(crate) peer_gid: libc::gid_t,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn own_pidfd() -> io::Result<OwnedFd> {
    // SAFETY: No caller-selected PID is accepted. This asks Linux for this
    // exact process, with the original process-wide (not thread) semantics.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: A successful pidfd_open returns one fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor as RawFd) })
}

fn send_owner(socket: &UnixStream, owner: &OwnedFd) -> io::Result<()> {
    let mut byte = [PREFACE];
    let mut vector = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    // usize storage gives cmsghdr its required alignment, with fixed capacity.
    let mut control = [0_usize; CONTROL_WORDS];
    // SAFETY: The all-zero msghdr has only pointers/counts filled below; the
    // buffers outlive the single synchronous syscall.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    // SAFETY: CMSG_SPACE is arithmetic for one descriptor, within this buffer.
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize };
    if message.msg_controllen > size_of_val(&control) {
        return Err(invalid("owner ancillary buffer capacity"));
    }
    // SAFETY: The aligned buffer contains a complete cmsghdr and one RawFd.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err(invalid("owner ancillary header"));
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
        libc::CMSG_DATA(header)
            .cast::<RawFd>()
            .write(owner.as_raw_fd());
    }
    // Queue the capability BEFORE any sudo/systemd/service process can start.
    // MSG_NOSIGNAL turns a closed endpoint into an ordinary failed preparation.
    let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent != 1 {
        return Err(invalid("complete owner capability record required"));
    }
    Ok(())
}

fn channel_pair() -> io::Result<(ControllerLifeline, OwnedFd)> {
    let (controller, actor) = UnixStream::pair()?;
    let owner = own_pidfd()?;
    send_owner(&controller, &owner)?;
    // The descriptor is already queued in the actor endpoint. No later PID
    // acquisition, reconnect or request field selects the observed owner.
    drop(owner);
    let actor: OwnedFd = actor.into();
    Ok((
        ControllerLifeline {
            _endpoint: controller,
        },
        actor,
    ))
}

pub(crate) fn channel_for_current_process() -> io::Result<(ControllerLifeline, Stdio)> {
    let (controller, actor) = channel_pair()?;
    Ok((controller, Stdio::from(actor)))
}

fn socket_option(socket: BorrowedFd<'_>, option: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: value and length are valid output buffers of the declared size.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::c_int>() {
        return Err(invalid("complete socket option required"));
    }
    Ok(value)
}

fn anonymous_socket(descriptor: OwnedFd) -> io::Result<(UnixStream, OwnerObservation)> {
    if socket_option(descriptor.as_fd(), libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_option(descriptor.as_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM
    {
        return Err(invalid("anonymous UNIX stream capability required"));
    }
    let socket = UnixStream::from(descriptor);
    if !socket.local_addr()?.is_unnamed() || !socket.peer_addr()?.is_unnamed() {
        return Err(invalid("named or abstract owner listener refused"));
    }
    let mut credentials = MaybeUninit::<libc::ucred>::uninit();
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: A connected UNIX socket supplies one complete ucred output.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::ucred>() {
        return Err(invalid("complete kernel peer credentials required"));
    }
    // SAFETY: The successful syscall wrote exactly the checked output size.
    let credentials = unsafe { credentials.assume_init() };
    // These checks do not grant owner authority. The original unprivileged
    // controller and actor must still agree across the privileged launcher.
    if credentials.pid <= 0 || credentials.uid != unsafe { libc::geteuid() } {
        return Err(invalid("owner capability peer context changed"));
    }
    Ok((
        socket,
        OwnerObservation {
            peer_pid: credentials.pid,
            peer_uid: credentials.uid,
            peer_gid: credentials.gid,
        },
    ))
}

fn validate_pidfd(owner: &OwnedFd) -> io::Result<()> {
    // Linux resolves P_PIDFD through pidfd_get_pid before child selection.
    // ECHILD is expected for the non-child controller; non-pidfds yield EBADF.
    // WNOWAIT preserves a real child's wait status. No /proc mount is required.
    let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            owner.as_raw_fd() as libc::id_t,
            &mut information,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ECHILD) {
        Ok(())
    } else {
        Err(error)
    }
}

fn receive_record(socket: &UnixStream) -> io::Result<OwnedFd> {
    // A second data byte, extra rights, truncation or unknown ancillary data
    // is refused. The constructor has queued exactly one record pre-launch.
    let mut bytes = [0_u8; 2];
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0_usize; CONTROL_WORDS];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&control);
    // SAFETY: Bounded, aligned writable buffers live for the complete syscall.
    let count = unsafe {
        libc::recvmsg(
            socket.as_raw_fd(),
            &mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if message.msg_controllen > size_of_val(&control) {
        return Err(invalid("owner ancillary length exceeds its buffer"));
    }
    let mut rights = Vec::new();
    let mut valid_headers = true;
    // SAFETY: CMSG traversal is bounded by the actual returned control length.
    // Every received FD is immediately owned, including on a later refusal.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let start = control.as_ptr() as usize;
            let end = start + message.msg_controllen;
            let position = header as usize;
            if position < start || position + size_of::<libc::cmsghdr>() > end {
                valid_headers = false;
                break;
            }
            let base = libc::CMSG_LEN(0) as usize;
            let length = (*header).cmsg_len;
            if length < base || length > end - position {
                valid_headers = false;
                break;
            }
            let payload = length - base;
            if (*header).cmsg_level != libc::SOL_SOCKET
                || (*header).cmsg_type != libc::SCM_RIGHTS
                || payload % size_of::<RawFd>() != 0
            {
                valid_headers = false;
            } else {
                for index in 0..payload / size_of::<RawFd>() {
                    let descriptor = libc::CMSG_DATA(header)
                        .cast::<RawFd>()
                        .add(index)
                        .read_unaligned();
                    if descriptor < 0 {
                        valid_headers = false;
                    } else {
                        rights.push(OwnedFd::from_raw_fd(descriptor));
                    }
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if count != 1
        || bytes[0] != PREFACE
        || !valid_headers
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || rights.len() != 1
    {
        return Err(invalid("one exact prequeued pidfd capability required"));
    }
    Ok(rights.pop().expect("one checked descriptor"))
}

fn receive_owner(socket: &UnixStream) -> io::Result<OwnedFd> {
    let owner = receive_record(socket)?;
    validate_pidfd(&owner)?;
    Ok(owner)
}

fn owner_lost(owner: &OwnedFd, socket: &UnixStream, timeout: i32) -> io::Result<bool> {
    for _ in 0..16 {
        let mut descriptors = [
            libc::pollfd {
                fd: owner.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: Both descriptors are owned by this scope and the array is live.
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        // The private stream has no protocol after its one capability record:
        // EOF, unexpected further bytes, or any fd error fails closed.
        return Ok(result > 0 && descriptors.iter().any(|item| item.revents != 0));
    }
    Err(invalid(
        "owner poll interrupted without a bounded observation",
    ))
}

fn terminate_this_helper() -> ! {
    // SAFETY: This only exits the current helper process and all its threads.
    // It never targets the controller, an arbitrary PID or an unrelated group.
    // No success report, clean Node close or successful settlement is fabricated.
    unsafe { libc::_exit(EXIT_OWNER_LOST) }
}

pub(crate) fn arm_until_process_exit() -> io::Result<OwnerObservation> {
    // Borrow stdin only long enough to duplicate it. systemd-run --pipe passes
    // the original descriptor through; no pathname is opened inside the actor.
    let input = unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
    let (socket, observation) = anonymous_socket(input.try_clone_to_owned()?)?;
    let owner = receive_owner(&socket)?;
    if owner_lost(&owner, &socket, 0)? {
        terminate_this_helper();
    }
    let (ready, started) = mpsc::sync_channel(0);
    let watcher = thread::Builder::new()
        .name("trnm-owner-watch".to_owned())
        .spawn(move || {
            if owner_lost(&owner, &socket, 0).unwrap_or(true) {
                terminate_this_helper();
            }
            if ready.send(()).is_err() {
                terminate_this_helper();
            }
            loop {
                if owner_lost(&owner, &socket, -1).unwrap_or(true) {
                    terminate_this_helper();
                }
            }
        })?;
    started
        .recv()
        .map_err(|_| invalid("owner watcher did not arm"))?;
    // Dropping JoinHandle detaches, not cancels. The thread owns both kernel
    // capabilities until OS process exit, including outer report/fsync/exit
    // code after the Node runner has returned. There is no disarm operation.
    drop(watcher);
    Ok(observation)
}

#[cfg(test)]
#[path = "multiprocess_history_lifeline_tests.rs"]
mod tests;
