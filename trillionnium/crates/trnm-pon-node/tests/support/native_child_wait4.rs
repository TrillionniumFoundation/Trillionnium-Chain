//! One actual owned child, one wait4 reaper. Shared by fixture process owners.
//! The caller must label the child it really spawned; launcher usage is not
//! usage of an unrelated systemd service process.
use serde_json::{json, Value};
use std::{
    io,
    mem::MaybeUninit,
    os::unix::process::ExitStatusExt,
    process::{Child, Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};

pub(crate) fn monotonic() -> u64 {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    (value.tv_sec as u64) * 1_000_000_000 + value.tv_nsec as u64
}

fn timeval_ns(value: libc::timeval) -> Option<u64> {
    let micros = u64::try_from(value.tv_usec).ok()?;
    (micros < 1_000_000)
        .then_some(u64::try_from(value.tv_sec).ok()?)?
        .checked_mul(1_000_000_000)?
        .checked_add(micros.checked_mul(1_000)?)
}

pub(crate) fn usage(value: libc::rusage) -> Value {
    let user = timeval_ns(value.ru_utime);
    let system = timeval_ns(value.ru_stime);
    let total = user.zip(system).and_then(|(a, b)| a.checked_add(b));
    json!({"user_seconds":value.ru_utime.tv_sec,"user_microseconds":value.ru_utime.tv_usec,
        "system_seconds":value.ru_stime.tv_sec,"system_microseconds":value.ru_stime.tv_usec,
        "user_cpu_ns":user,"system_cpu_ns":system,"total_cpu_ns":total,
        "max_rss_kib":u64::try_from(value.ru_maxrss).ok(),
        "minor_faults":u64::try_from(value.ru_minflt).ok(),
        "major_faults":u64::try_from(value.ru_majflt).ok(),
        "input_blocks":u64::try_from(value.ru_inblock).ok(),
        "output_blocks":u64::try_from(value.ru_oublock).ok(),
        "voluntary_context_switches":u64::try_from(value.ru_nvcsw).ok(),
        "involuntary_context_switches":u64::try_from(value.ru_nivcsw).ok()})
}

pub struct ObservedChild {
    child: Child,
    spawn_started: u64,
    spawn_finished: u64,
    reaped: bool,
    polls: u64,
}

impl ObservedChild {
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        let spawn_started = monotonic();
        let child = command.spawn()?;
        Ok(Self {
            child,
            spawn_started,
            spawn_finished: monotonic(),
            reaped: false,
            polls: 0,
        })
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Observe this still-owned child's terminal state without consuming the
    /// wait status. `finish` remains the sole wait4 reaper and retains rusage.
    pub fn terminal_observed(&mut self) -> io::Result<bool> {
        if self.reaped {
            return Err(io::Error::other("PROCESS_ALREADY_REAPED"));
        }
        // SAFETY: siginfo_t is a C output object for waitid; all-zero bytes are
        // a valid initial value and leave si_pid zero for the WNOHANG case.
        let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: The exact Child PID is still owned and unreaped. WNOWAIT
        // preserves terminal ownership and the later original wait4 result.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut information,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                self.reaped = true;
            }
            return Err(error);
        }
        // SAFETY: waitid initialized siginfo on success; si_pid is the POSIX
        // child identity field, including zero for a still-running child.
        let pid = unsafe { information.si_pid() };
        if pid == 0 {
            Ok(false)
        } else if u32::try_from(pid).ok() == Some(self.child.id()) {
            Ok(true)
        } else {
            Err(io::Error::other("PROCESS_OBSERVE_PID_MISMATCH"))
        }
    }

    fn wait_once(&mut self, nonblocking: bool) -> io::Result<Option<(ExitStatus, Value)>> {
        if self.reaped {
            return Err(io::Error::other("PROCESS_ALREADY_REAPED"));
        }
        let pid =
            i32::try_from(self.child.id()).map_err(|_| io::Error::other("PROCESS_PID_RANGE"))?;
        let mut status = 0;
        let mut resources = MaybeUninit::<libc::rusage>::uninit();
        self.polls = self.polls.saturating_add(1);
        // SAFETY: wait4 receives the exact still-owned child PID and writable
        // status/rusage storage. Resources are read only after it returns that
        // PID. This is the sole reaper: never call Child::try_wait/wait as well.
        let result = unsafe {
            libc::wait4(
                pid,
                &mut status,
                if nonblocking { libc::WNOHANG } else { 0 },
                resources.as_mut_ptr(),
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                // Ownership was lost; never signal a possibly reused PID.
                self.reaped = true;
            }
            return Err(error);
        }
        if result == 0 {
            return Ok(None);
        }
        self.reaped = true;
        if result != pid {
            return Err(io::Error::other("PROCESS_REAP_PID_MISMATCH"));
        }
        // SAFETY: a successful wait4 for this child initialized rusage above.
        let resources = unsafe { resources.assume_init() };
        Ok(Some((ExitStatus::from_raw(status), usage(resources))))
    }

    /// Same polling and absolute cleanup deadline as the original Actor owner.
    /// Normal exit is observed first; only a still-live child at the unchanged
    /// deadline is killed. A successful wait4 is never followed by another reap.
    pub fn finish(&mut self, deadline: Instant) -> Value {
        let started = monotonic();
        let mut forced = false;
        let mut error = None;
        let outcome = loop {
            match self.wait_once(!forced) {
                Ok(Some(value)) => break Some(value),
                Ok(None) => {}
                Err(value) if value.kind() == io::ErrorKind::Interrupted => {}
                Err(value) => {
                    error = Some(value.to_string());
                    break None;
                }
            }
            if !forced && Instant::now() >= deadline {
                if let Err(value) = self.child.kill() {
                    error = Some(value.to_string());
                    break None;
                }
                forced = true;
            } else if !forced {
                thread::sleep(Duration::from_millis(2));
            }
        };
        let ended = monotonic();
        let (raw_status, success, resources) = match outcome {
            Some((status, resources)) => {
                (Some(status.into_raw()), status.success(), Some(resources))
            }
            None => (None, false, None),
        };
        json!({"schema":"pon-child-wait4-cost-v1","parent_pid":std::process::id(),
            "pid":self.id(),"spawn_started_monotonic_ns":self.spawn_started,
            "spawn_finished_monotonic_ns":self.spawn_finished,
            "reap_started_monotonic_ns":started,"reap_finished_monotonic_ns":ended,
            "wait4_calls":self.polls,"successful_reaps":u8::from(raw_status.is_some()),
            "raw_wait_status":raw_status,"exit_success":success,"parent_forced_kill":forced,
            "rusage":resources,"error":error,"physical_authentication":false,
            "scope":"Linux wait4 resource usage for the exact reaped child, including startup, all child threads, final output and process teardown, and any waited-descendant usage included by the kernel. Excludes parent and unrelated sibling processes; nested thread observations are not added to this enclosing total."})
    }
}

impl Drop for ObservedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Error/unwind cleanup only. Normal finish already retained its exact
        // wait4 result. In particular an ECHILD never triggers a PID kill.
        // A response waiter may not have seen the final ownership loss. Make
        // the same non-reaping ownership observation before unwind cleanup;
        // only ECHILD closes the owner here, and wait4 remains the sole reaper.
        if self.terminal_observed().is_err() && self.reaped {
            return;
        }
        let _ = self.finish(Instant::now());
    }
}
