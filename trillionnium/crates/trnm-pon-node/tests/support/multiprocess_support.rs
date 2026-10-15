//! Actual process/thread clocks and original public client helpers. All values
//! are local observations and never authorization or a physical cost bound.
use serde_json::{json, Value};
use std::{
    fs,
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{self, PublicPolicy, Request},
        DevelopmentIdentity,
    },
    Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope};

pub fn clock(id: rustix::time::ClockId) -> Option<u64> {
    let time = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(id)).ok()?;
    let seconds = u64::try_from(time.tv_sec).ok()?;
    let nanos = u64::try_from(time.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}
pub fn cpu() -> Option<u64> {
    clock(rustix::time::ClockId::ProcessCPUTime)
}
pub fn monotonic() -> u64 {
    clock(rustix::time::ClockId::Monotonic).expect("actual Linux monotonic clock")
}
pub fn elapsed_cpu(start: Option<u64>) -> Option<u64> {
    start.zip(cpu()).and_then(|(a, b)| b.checked_sub(a))
}
pub fn rss() -> Value {
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
pub fn policy() -> PublicPolicy {
    PublicPolicy::new(8, Duration::from_secs(2)).unwrap()
}
pub fn identity(seed: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([seed; 32])).unwrap()
}
pub fn settings() -> Settings {
    Settings::development_with_profiles(
        Some(1_750_000_000),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap()
}
pub fn signed_transfer(settings: &Settings, nonce: u64, recipient: [u8; 32]) -> Vec<u8> {
    let mut payload = recipient.to_vec();
    payload.extend_from_slice(&1_u64.to_le_bytes());
    let mut envelope = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
        expiry: 10000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    envelope.encode().unwrap()
}
pub fn write_new(path: &Path, value: &Value) {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(&serde_json::to_vec(value).unwrap()).unwrap();
    file.sync_all().unwrap();
}
pub fn children_usage() -> Value {
    // The OS sums reaped children, including executable/test-harness startup and
    // final JSON serialization. This is aggregate for simultaneous children.
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage writes one correctly sized rusage; we read only on success.
    let status = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, usage.as_mut_ptr()) };
    if status != 0 {
        return json!({"error":std::io::Error::last_os_error().to_string()});
    }
    // SAFETY: the successful syscall initialized this object.
    let usage = unsafe { usage.assume_init() };
    let ns = |value: libc::timeval| {
        u64::try_from(value.tv_sec)
            .ok()
            .and_then(|s| s.checked_mul(1_000_000_000))
            .zip(
                u64::try_from(value.tv_usec)
                    .ok()
                    .and_then(|us| us.checked_mul(1000)),
            )
            .and_then(|(a, b)| a.checked_add(b))
    };
    json!({"user_cpu_ns":ns(usage.ru_utime),"system_cpu_ns":ns(usage.ru_stime),
        "max_reaped_child_rss_bytes":u64::try_from(usage.ru_maxrss).ok().and_then(|v|v.checked_mul(1024)),
        "scope":"Linux RUSAGE_CHILDREN cumulative reaped CPU; maxrss is maximum of children, never simultaneous memory sum"})
}
pub fn live_children_rss(pids: &[u32]) -> Value {
    let self_status = fs::read_to_string("/proc/self/status").ok();
    let actual_pid = self_status
        .as_ref()
        .and_then(|text| text.lines().find(|line| line.starts_with("Pid:")))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u32>().ok());
    if actual_pid != Some(std::process::id()) {
        return json!({"processes":pids,"complete":false,"sum_rss_bytes":null,
            "unavailable_reason":"numeric child PID namespace does not match mounted /proc; no numeric child memory attributed",
            "observed_proc_self_pid":actual_pid,"getpid":std::process::id()});
    }
    let rows: Vec<_> = pids
        .iter()
        .map(|pid| {
            let text = fs::read_to_string(format!("/proc/{pid}/status")).ok();
            let parent=text.as_ref().and_then(|t|t.lines().find(|line|line.starts_with("PPid:")))
                .and_then(|line|line.split_whitespace().nth(1)).and_then(|v|v.parse::<u32>().ok());
            use std::os::unix::fs::MetadataExt;
            let actual=fs::metadata(format!("/proc/{pid}/exe")).ok();
            let expected=std::env::current_exe().ok().and_then(|path|fs::metadata(path).ok());
            let identity_verified=parent==Some(std::process::id())&&actual.zip(expected).is_some_and(|(a,b)|a.dev()==b.dev()&&a.ino()==b.ino());
            let bytes = identity_verified.then_some(()) .and(text.as_ref())
                .as_ref()
                .and_then(|t| t.lines().find(|line| line.starts_with("VmRSS:")))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
                .and_then(|v| v.checked_mul(1024));
            json!({"pid":pid,"rss_bytes":bytes,"parent_and_executable_identity_verified":identity_verified})
        })
        .collect();
    let complete = rows.iter().all(|row| row["rss_bytes"].as_u64().is_some());
    let sum = if complete {
        rows.iter().try_fold(0_u64, |sum, row| {
            sum.checked_add(row["rss_bytes"].as_u64().unwrap())
        })
    } else {
        None
    };
    json!({"processes":rows,"complete":complete,"sum_rss_bytes":sum,
        "scope":"50ms sampled /proc RSS summed across owned attacker processes; shared pages may be double counted, not exact physical peak"})
}
pub fn call(
    address: SocketAddr,
    settings: &Settings,
    request: Request,
    who: u8,
    epoch: u64,
    window_end: u64,
) -> Value {
    let public_wire_body = serde_json::to_vec(&request).unwrap();
    let started = monotonic();
    let start_cpu = cpu();
    let wall = Instant::now();
    let remaining = window_end.saturating_sub(monotonic());
    let deadline = Instant::now() + Duration::from_nanos(remaining).min(Duration::from_secs(2));
    let (reply, metrics) = public_v3::call_public_protected_v3_with_deadline(
        address,
        &request,
        settings,
        identity(71).public_key(),
        &identity(who),
        policy(),
        Some(deadline),
    );
    let used_cpu = elapsed_cpu(start_cpu);
    let ended = monotonic();
    let (status, response, error) = match reply {
        Ok(reply) => (
            if reply.ok { "ok" } else { "refused" },
            Some(serde_json::to_value(reply).unwrap()),
            None,
        ),
        Err(error) => ("error", None, Some(error.to_string())),
    };
    let request_value = serde_json::to_value(request).unwrap();
    let raw = serde_json::to_vec(&request_value).unwrap();
    let mut value = json!({"started_ns":started.saturating_sub(epoch),"ended_ns":ended.saturating_sub(epoch),
        "elapsed_wall_ns":wall.elapsed().as_nanos(),"calling_process_cpu_ns":used_cpu,
        "returned_after_window":ended >= window_end,"status":status,"error":error,"response":response,
        "recorded_request_digest":hex::encode(hash(b"multiprocess-recorded-request-v1", &[&raw])),
        "public_request_body_digest":hex::encode(hash(b"public-request-body-v3", &[&public_wire_body])),
        "recorded_request_bytes":raw.len(),"metrics":metrics});
    if request_value["op"] != "submit" {
        value["request"] = request_value;
    }
    value
}
pub fn on_time(row: &Value) -> bool {
    row["status"] == "ok" && row["returned_after_window"] == false
}
pub fn ready_sleep() {
    std::thread::sleep(Duration::from_millis(2));
}
pub fn now() -> u64 {
    ingress::now().unwrap()
}
