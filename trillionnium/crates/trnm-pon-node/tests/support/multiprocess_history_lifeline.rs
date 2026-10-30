//! Private controller capability for the real History fixture process.
//! Linux is required by the original native campaign. Other platforms return
//! Unsupported before any Node work; they do not manufacture an armed owner.
use std::io;
use std::process::Stdio;

#[cfg(target_os = "linux")]
#[path = "multiprocess_history_lifeline_linux.rs"]
mod linux;

#[cfg(target_os = "linux")]
pub(super) type ControllerLifeline = linux::ControllerLifeline;
#[cfg(target_os = "linux")]
pub(super) type OwnerObservation = linux::OwnerObservation;

#[cfg(not(target_os = "linux"))]
pub(super) struct ControllerLifeline;
#[cfg(not(target_os = "linux"))]
#[derive(Clone, Copy, Debug)]
pub(super) struct OwnerObservation {
    pub(super) peer_pid: libc::pid_t,
    pub(super) peer_uid: libc::uid_t,
    pub(super) peer_gid: libc::gid_t,
}

pub(super) fn channel_for_current_process() -> io::Result<(ControllerLifeline, Stdio)> {
    #[cfg(target_os = "linux")]
    {
        linux::channel_for_current_process()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native History lifetime requires Linux pidfd",
        ))
    }
}

pub(super) fn arm_until_process_exit() -> io::Result<OwnerObservation> {
    #[cfg(target_os = "linux")]
    {
        linux::arm_until_process_exit()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native History lifetime requires Linux pidfd",
        ))
    }
}
