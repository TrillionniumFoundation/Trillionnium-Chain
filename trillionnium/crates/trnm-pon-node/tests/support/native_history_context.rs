//! Shared actual native History fixture context and observations.
//! This module owns no Host permission, CPU credit, admission or validity token.
use serde_json::{json, Value};
use std::{fs, path::Path, thread, time::Instant};
use trnm_pon_node::{Node, Settings};

pub(crate) fn clock(id: rustix::time::ClockId) -> Option<u64> {
    let time = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(id)).ok()?;
    let seconds = u64::try_from(time.tv_sec).ok()?;
    let nanos = u64::try_from(time.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}
pub(crate) fn cpu() -> Option<u64> {
    clock(rustix::time::ClockId::ProcessCPUTime)
}
pub(crate) fn monotonic() -> u64 {
    clock(rustix::time::ClockId::Monotonic).expect("actual Linux monotonic clock")
}
pub(crate) fn elapsed_cpu(start: Option<u64>) -> Option<u64> {
    start.zip(cpu()).and_then(|(a, b)| b.checked_sub(a))
}
pub(crate) fn rss() -> Value {
    let text = fs::read_to_string("/proc/self/status").ok();
    let value = |name: &str| {
        text.as_ref()
            .and_then(|text| text.lines().find(|line| line.starts_with(name)))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|bytes| bytes.parse::<u64>().ok())
            .and_then(|kib| kib.checked_mul(1024))
    };
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: correctly sized writable object, read only after successful syscall.
    let peak = if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } == 0 {
        // SAFETY: successful syscall initialized the object.
        u64::try_from(unsafe { usage.assume_init() }.ru_maxrss)
            .ok()
            .and_then(|v| v.checked_mul(1024))
    } else {
        None
    };
    json!({"rss_bytes":value("VmRSS:"),"lifetime_peak_rss_bytes":value("VmHWM:"),"kernel_rusage_self_peak_rss_bytes":peak,
        "scope":"Linux /proc/self magic self and kernel RUSAGE_SELF; peak is whole process lifetime, not an isolated allocation or incremental memory bound"})
}

pub(crate) fn settings() -> Settings {
    Settings::development_with_profiles(
        Some(1_750_000_000),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap()
}

pub(crate) fn now() -> u64 {
    trnm_pon_node::ingress::now().unwrap()
}

pub(crate) struct ClientOperationStamp {
    started_ns: u64,
    started: Instant,
    thread: thread::ThreadId,
    cpu_ns: Option<u64>,
}
impl ClientOperationStamp {
    pub(crate) fn start(epoch: u64) -> Self {
        Self {
            started_ns: monotonic().saturating_sub(epoch),
            started: Instant::now(),
            thread: thread::current().id(),
            cpu_ns: clock(rustix::time::ClockId::ThreadCPUTime),
        }
    }
    pub(crate) fn finish(self, epoch: u64) -> Value {
        let cpu_ns = (self.thread == thread::current().id())
            .then(|| clock(rustix::time::ClockId::ThreadCPUTime))
            .flatten()
            .zip(self.cpu_ns)
            .and_then(|(end, start)| end.checked_sub(start));
        let ended_ns = monotonic().saturating_sub(epoch);
        let wall_ns = u64::try_from(self.started.elapsed().as_nanos()).ok();
        json!({"started_ns":self.started_ns,"ended_ns":ended_ns,"wall_ns":wall_ns,
            "thread_cpu_ns":cpu_ns,"thread_cpu_observation_available":cpu_ns.is_some(),
            "scope":"calling client thread only; excludes scoped execution worker CPU; unknown clock is null; no deadline or acceptance authority"})
    }
}

#[derive(Clone, Copy)]
pub(crate) enum StateBackendChoice {
    LegacyV2,
    AuthenticatedV1,
}
impl StateBackendChoice {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::LegacyV2 => "legacy-v2",
            Self::AuthenticatedV1 => "authenticated-v1",
        }
    }
    pub(crate) fn open(self, path: &Path, settings: Settings) -> Node {
        // The outer campaign and phase directories are create-only. Select the
        // original opener once for every fresh Node; do not migrate or retry a
        // failed authenticated namespace through the legacy implementation.
        match self {
            Self::LegacyV2 => Node::open(path, settings, 1),
            Self::AuthenticatedV1 => Node::open_with_authenticated_state(path, settings, 1),
        }
        .unwrap()
    }
}
