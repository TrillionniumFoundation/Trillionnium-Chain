//! Parent-owned single-child wait4 observations. No runtime or budget changes.
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    mem::MaybeUninit,
};

pub use crate::native_child_wait4::ObservedChild;
use crate::native_child_wait4::{monotonic, usage};

fn rusage_sample(who: libc::c_int) -> io::Result<Value> {
    let mut value = MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage receives valid writable storage and a supported selector.
    if unsafe { libc::getrusage(who, value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful getrusage initialized this storage.
    Ok(usage(unsafe { value.assume_init() }))
}

/// Only the separately named receiver test child calls this. No live service or
/// existing actor/cgroup is changed. Orphaned descendants remain observable by
/// that receiver instead of escaping a final direct-child census.
pub fn enable_receiver_subreaper() -> io::Result<()> {
    // SAFETY: PR_SET_CHILD_SUBREAPER takes an integer flag and no pointer.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Actual final per-thread child lists and rusage. This point sample is never
/// silently upgraded into a hostile-host process-family authenticity proof.
pub fn family_observation() -> Value {
    let started = monotonic();
    let pid = std::process::id();
    let root = format!("/proc/{pid}/task");
    let list = || -> io::Result<BTreeSet<u32>> {
        let mut tids = BTreeSet::new();
        for entry in fs::read_dir(&root)? {
            let name = entry?.file_name();
            let tid = name
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|v| *v > 0)
                .ok_or_else(|| io::Error::other("PROCESS_FAMILY_TID"))?;
            tids.insert(tid);
            if tids.len() > 256 {
                return Err(io::Error::other("PROCESS_FAMILY_TASK_BOUND"));
            }
        }
        Ok(tids)
    };
    let mut rows = Vec::new();
    let mut errors = Vec::new();
    let mut child_pids = BTreeSet::new();
    let before = list();
    if let Ok(tids) = &before {
        for tid in tids {
            let read = (|| -> io::Result<Vec<u32>> {
                let mut raw = String::new();
                fs::File::open(format!("{root}/{tid}/children"))?
                    .take(4097)
                    .read_to_string(&mut raw)?;
                if raw.len() > 4096 {
                    return Err(io::Error::other("PROCESS_FAMILY_CHILD_BOUND"));
                }
                raw.split_whitespace()
                    .map(|s| {
                        s.parse::<u32>()
                            .ok()
                            .filter(|v| *v > 0)
                            .ok_or_else(|| io::Error::other("PROCESS_FAMILY_CHILD_PID"))
                    })
                    .collect()
            })();
            match read {
                Ok(children) => {
                    child_pids.extend(children.iter().copied());
                    rows.push(json!({"tid":tid,"children":children,"error":null}));
                }
                Err(error) => {
                    errors.push(error.to_string());
                    rows.push(json!({"tid":tid,"children":null,"error":error.to_string()}));
                }
            }
        }
    } else if let Err(error) = &before {
        errors.push(error.to_string());
    }
    let after = list();
    let stable = before
        .as_ref()
        .ok()
        .zip(after.as_ref().ok())
        .is_some_and(|(a, b)| a == b && !a.is_empty());
    if !stable {
        errors.push("PROCESS_FAMILY_THREAD_SET_CHANGED_OR_UNAVAILABLE".to_owned());
    }
    let self_usage = rusage_sample(libc::RUSAGE_SELF);
    let children_usage = rusage_sample(libc::RUSAGE_CHILDREN);
    let mut subreaper: libc::c_int = 0;
    // SAFETY: PR_GET_CHILD_SUBREAPER writes one integer through this valid pointer.
    let subreaper_result =
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut subreaper, 0, 0, 0) };
    if subreaper_result != 0 {
        errors.push(io::Error::last_os_error().to_string());
    }
    for value in [&self_usage, &children_usage] {
        if let Err(error) = value {
            errors.push(error.to_string());
        }
    }
    let complete = errors.is_empty();
    json!({"schema":"pon-process-family-observation-v1","pid":pid,
        "started_monotonic_ns":started,"ended_monotonic_ns":monotonic(),
        "thread_ids_before":before.ok(),"thread_ids_after":after.ok(),"thread_children":rows,
        "observed_child_pids":child_pids,"thread_set_stable":stable,
        "self_rusage":self_usage.ok(),"waited_children_rusage":children_usage.ok(),
        "child_subreaper":if subreaper_result==0 {Some(subreaper==1)} else {None},
        "capture_complete":complete,"no_live_or_unreaped_children_observed":complete && child_pids.is_empty(),
        "errors":errors,"physical_authentication":false,
        "scope":"Bounded Linux per-thread child census and actual RUSAGE_SELF/RUSAGE_CHILDREN after owned work. A stable empty census is an observation, not an authenticated proof of absence; waited-child CPU is nested inside Linux wait4 totals and must not be added twice."})
}

pub const CHILD_PROBE_SCOPE: &str = "One non-reaping Linux waitid(P_ALL, WEXITED|WNOHANG|WNOWAIT|__WALL) with unchanged SIG_DFL and no SA_NOCLDWAIT. ECHILD observes no eligible children at this probe, not CLONE_THREAD joins, CLONE_PARENT causal siblings, historical cost completeness or physical authentication.";

fn sigchld_observation() -> Value {
    let mut action = MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: a null new action only reads the current disposition into valid
    // writable storage. No signal behavior is changed by this observation.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) } != 0 {
        return json!({"disposition":null,"flags":null,"no_cld_wait":null,"error":io::Error::last_os_error().to_string()});
    }
    // SAFETY: the successful read initialized the action.
    let action = unsafe { action.assume_init() };
    let disposition = if action.sa_sigaction == libc::SIG_DFL {
        "default"
    } else if action.sa_sigaction == libc::SIG_IGN {
        "ignored"
    } else {
        "handler"
    };
    json!({"disposition":disposition,"flags":action.sa_flags,
        "no_cld_wait":action.sa_flags & libc::SA_NOCLDWAIT != 0,"error":null})
}

/// This is independent of procfs availability. Preserve both observations:
/// neither ENOENT in procfs nor a zero-event waitid return means no children.
/// WNOWAIT keeps a zombie available to its one actual wait4 owner.
pub fn child_ownership_probe() -> Value {
    let started = monotonic();
    let before = sigchld_observation();
    let mut subreaper: libc::c_int = 0;
    // SAFETY: GET writes through one valid integer pointer and changes nothing.
    let subreaper_return =
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut subreaper, 0, 0, 0) };
    let subreaper_error = (subreaper_return != 0).then(|| io::Error::last_os_error().to_string());
    // SAFETY: siginfo_t is C integer/union storage; all-zero is valid initialized
    // storage and preserves the documented no-event si_pid=0 observation.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let options = libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL;
    // SAFETY: P_ALL ignores id=0; options are observation-only and info is valid.
    let returned = unsafe { libc::waitid(libc::P_ALL, 0, &mut info, options) };
    // Read errno immediately and only for -1. Successful calls do not define it.
    let errno = (returned == -1)
        .then(|| io::Error::last_os_error().raw_os_error())
        .flatten();
    let event = if returned == 0 {
        // SAFETY: the zeroed buffer and successful waitid initialize SIGCHLD's
        // pid/uid/status fields, including zero pid when WNOHANG has no event.
        Some(unsafe {
            json!({"signo":info.si_signo,"code":info.si_code,"errno":info.si_errno,
            "pid":info.si_pid(),"uid":info.si_uid(),"status":info.si_status()})
        })
    } else {
        None
    };
    let after = sigchld_observation();
    let signal_safe = before == after
        && before["disposition"] == "default"
        && before["no_cld_wait"] == false
        && before["error"].is_null();
    let echild = returned == -1 && errno == Some(libc::ECHILD);
    json!({"schema":"pon-child-ownership-probe-v1","scope":CHILD_PROBE_SCOPE,
        "pid":std::process::id(),"started_monotonic_ns":started,"ended_monotonic_ns":monotonic(),
        "idtype":libc::P_ALL,"id":0,"options":options,
        "option_names":["P_ALL","WEXITED","WNOHANG","WNOWAIT","__WALL"],
        "sigchld_before":before,"sigchld_after":after,"safe_signal_disposition_observed":signal_safe,
        "waitid_return":returned,"errno":errno,"event":event,
        "child_subreaper":if subreaper_return==0 {Some(subreaper==1)} else {None},
        "subreaper_error":subreaper_error,"waitid_echild_observed":echild,
        "no_eligible_children_at_probe":echild && signal_safe,"successful_reaps":0,
        "physical_authentication":false})
}
