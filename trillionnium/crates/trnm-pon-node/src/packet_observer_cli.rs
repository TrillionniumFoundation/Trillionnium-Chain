//! Local packet-status runs in a disposable process. The kernel accounts all
//! of that process's threads against one absolute, nonrenewable CPU ceiling.
//! This envelope is separate from public mutation credit and is not a durable
//! or cross-process owner quota. The parent owns temporary files and reaps the
//! reader even when full-history validation cannot reach a checkpoint.
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::Read,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_pon_node::{Error, Result};

const DEFAULT_CPU_SECONDS: u64 = 5;
const MAX_CPU_SECONDS: u64 = 30;
const DEFAULT_WALL_SECONDS: u64 = 30;
const MAX_WALL_SECONDS: u64 = 120;
const MAX_CAPTURE_BYTES: u64 = 128 * 1024;
const WORKER_OPTION: &str = "--packet-observer-worker";

fn seconds(args: &BTreeMap<String, String>, key: &str, default: u64, max: u64) -> Result<u64> {
    let value = args.get(key).map_or(Ok(default), |value| {
        value
            .parse::<u64>()
            .map_err(|_| Error::from("PACKET_OBSERVATION_BUDGET"))
    })?;
    if !(1..=max).contains(&value) {
        return Err("PACKET_OBSERVATION_BUDGET".into());
    }
    Ok(value)
}

/// None is returned only by the separately limited child. Direct invocation
/// of the internal worker flag cannot skip installation of the same hard cap.
pub(crate) fn supervise(args: &BTreeMap<String, String>) -> Result<Option<Value>> {
    let cpu = seconds(
        args,
        "--observation-cpu-seconds",
        DEFAULT_CPU_SECONDS,
        MAX_CPU_SECONDS,
    )?;
    let wall = seconds(
        args,
        "--observation-wall-seconds",
        DEFAULT_WALL_SECONDS,
        MAX_WALL_SECONDS,
    )?;
    if let Some(worker) = args.get(WORKER_OPTION) {
        if worker != "v1" {
            return Err("PACKET_OBSERVATION_WORKER".into());
        }
        install_cpu_ceiling(cpu)?;
        return Ok(None);
    }
    let source = std::path::Path::new(args.get("--store").ok_or("--store")?);
    if !source.join("native.sqlite").is_file() {
        return Err("PACKET_STATUS_EXISTING_STORE_REQUIRED".into());
    }
    // Ignore caller TMPDIR. The supervisor must never create its cleanup root
    // inside the source store, even when the caller selected /tmp as the store.
    let temporary_root = std::fs::canonicalize("/tmp")?;
    if temporary_root.starts_with(source.canonicalize()?) {
        return Err("GROWTH_OBSERVATION_SNAPSHOT_LOCATION".into());
    }
    let temporary = tempfile::Builder::new()
        .prefix("trnm-packet-supervisor-")
        .tempdir_in(temporary_root)?;
    let mut child = Command::new(std::env::current_exe()?);
    child
        .args(std::env::args_os().skip(1))
        .args([WORKER_OPTION, "v1"])
        .env_clear()
        .env("TMPDIR", temporary.path())
        .stdin(Stdio::inherit());
    // temporary outlives execution and every worker pipe. Killing a child never
    // leaves its private snapshot tree behind and never removes source files.
    let result = execute(child, Duration::from_secs(wall));
    temporary.close()?;
    result.map(Some)
}

#[cfg(target_os = "linux")]
fn install_cpu_ceiling(seconds: u64) -> Result<()> {
    use rustix::{
        process::{getrlimit, setrlimit, Resource, Rlimit},
        time::{clock_gettime_dynamic, ClockId, DynamicClockId},
    };
    // RLIMIT_CPU is cumulative process user+system CPU, not wall time or one
    // worker's CPU. Install an absolute value, never now+allowance. Re-entry or
    // an inherited stricter limit can only tighten it. No custom signal handler
    // or post-replay success path substitutes for the kernel hard limit.
    let prior = getrlimit(Resource::Cpu);
    let ceiling = seconds
        .min(prior.current.unwrap_or(seconds))
        .min(prior.maximum.unwrap_or(seconds));
    if ceiling == 0 {
        return Err("PACKET_OBSERVATION_CPU_BUDGET".into());
    }
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| Error::from("PACKET_OBSERVATION_CPU_UNAVAILABLE"))?;
    let limit = Rlimit {
        current: Some(ceiling),
        maximum: Some(ceiling),
    };
    setrlimit(Resource::Cpu, limit)
        .map_err(|_| Error::from("PACKET_OBSERVATION_CPU_UNAVAILABLE"))?;
    if getrlimit(Resource::Cpu) != limit {
        return Err("PACKET_OBSERVATION_CPU_UNAVAILABLE".into());
    }
    let used = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ProcessCPUTime))
        .map_err(|_| Error::from("PACKET_OBSERVATION_CPU_UNAVAILABLE"))?;
    if u64::try_from(used.tv_sec).map_or(true, |used| used >= ceiling) {
        return Err("PACKET_OBSERVATION_CPU_BUDGET".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_cpu_ceiling(_: u64) -> Result<()> {
    Err("PACKET_OBSERVATION_CPU_UNSUPPORTED".into())
}

struct OwnedChild {
    child: Child,
    reaped: bool,
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn capture(mut pipe: impl Read, exceeded: &AtomicBool) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.by_ref()
        .take(MAX_CAPTURE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CAPTURE_BYTES {
        exceeded.store(true, Ordering::Release);
        return Err("PACKET_OBSERVATION_OUTPUT_LIMIT".into());
    }
    Ok(bytes)
}
fn execute(mut command: Command, wall: Duration) -> Result<Value> {
    let deadline = Instant::now()
        .checked_add(wall)
        .ok_or("PACKET_OBSERVATION_BUDGET")?;
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut owned = OwnedChild {
        child,
        reaped: false,
    };
    let stdout = owned
        .child
        .stdout
        .take()
        .ok_or("PACKET_OBSERVATION_OUTPUT")?;
    let stderr = owned
        .child
        .stderr
        .take()
        .ok_or("PACKET_OBSERVATION_OUTPUT")?;
    let exceeded = Arc::new(AtomicBool::new(false));
    let out_limit = exceeded.clone();
    let err_limit = exceeded.clone();
    let out = thread::spawn(move || capture(stdout, &out_limit));
    let err = thread::spawn(move || capture(stderr, &err_limit));
    let mut refusal = None;
    let status = loop {
        if exceeded.load(Ordering::Acquire) {
            refusal = Some("PACKET_OBSERVATION_OUTPUT_LIMIT");
        }
        if Instant::now() >= deadline {
            refusal = Some("PACKET_OBSERVATION_WALL_BUDGET");
        }
        if refusal.is_some() {
            // An exit racing kill is harmless: wait remains authoritative. A
            // returned error never means the original packet was not executed.
            let _ = owned.child.kill();
            break owned.child.wait()?;
        }
        if let Some(status) = owned.child.try_wait()? {
            break status;
        }
        thread::sleep(Duration::from_millis(5));
    };
    owned.reaped = true;
    let stdout = out.join().map_err(|_| "PACKET_OBSERVATION_OUTPUT")?;
    let stderr = err.join().map_err(|_| "PACKET_OBSERVATION_OUTPUT")?;
    if let Some(code) = refusal {
        return Err(code.into());
    }
    let (stdout, stderr) = (stdout?, stderr?);
    if !status.success() {
        if status.code() == Some(2) && stdout.is_empty() && !stderr.is_empty() {
            return Err(String::from_utf8(stderr)
                .map_err(|_| "PACKET_OBSERVATION_OUTPUT")?
                .trim_end()
                .to_owned()
                .into());
        }
        // SIGKILL can mean the CPU ceiling, OOM or another signal. Preserve the
        // ambiguity; never manufacture an absence, safe-retry or completion.
        return Err("PACKET_OBSERVATION_PROCESS_TERMINATED".into());
    }
    if !stderr.is_empty() {
        return Err("PACKET_OBSERVATION_OUTPUT".into());
    }
    serde_json::from_slice(&stdout).map_err(|_| "PACKET_OBSERVATION_OUTPUT".into())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    fn probe(mode: &str, temporary: &std::path::Path) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "packet_observer_cli::tests::kernel_child_probe",
                "--nocapture",
            ])
            .env("TRNM_PACKET_OBSERVER_CPU_TEST", mode)
            .env("TMPDIR", temporary);
        command
    }
    #[test]
    fn kernel_child_probe() {
        let Ok(mode) = std::env::var("TRNM_PACKET_OBSERVER_CPU_TEST") else {
            return;
        };
        install_cpu_ceiling(1).unwrap();
        install_cpu_ceiling(30).unwrap();
        assert_eq!(
            rustix::process::getrlimit(rustix::process::Resource::Cpu),
            rustix::process::Rlimit {
                current: Some(1),
                maximum: Some(1)
            }
        );
        let _private = tempfile::tempdir().unwrap();
        match mode.as_str() {
            "burn" => thread::scope(|scope| {
                // No cooperative checkpoints. All four actual native workers
                // debit the same kernel process ceiling, including replay tails.
                for seed in 0..4_u64 {
                    scope.spawn(move || {
                        let mut n = seed;
                        loop {
                            n = std::hint::black_box(
                                n.wrapping_mul(6364136223846793005).wrapping_add(1),
                            );
                        }
                    });
                }
            }),
            "wall" => thread::sleep(Duration::from_secs(20)),
            "flood" => {
                println!("{}", "x".repeat(MAX_CAPTURE_BYTES as usize + 1));
            }
            _ => panic!("unknown probe"),
        }
    }
    #[test]
    fn actual_scoped_workers_hit_one_absolute_kernel_cpu_ceiling() {
        let temporary = tempfile::tempdir().unwrap();
        let result = execute(probe("burn", temporary.path()), Duration::from_secs(20));
        assert_eq!(
            result.unwrap_err().to_string(),
            "PACKET_OBSERVATION_PROCESS_TERMINATED"
        );
        // The child was killed with no unwinding; the parent still owns removal.
        let path = temporary.path().to_owned();
        temporary.close().unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn wall_timeout_reaps_the_reader_and_private_snapshot() {
        let temporary = tempfile::tempdir().unwrap();
        let result = execute(probe("wall", temporary.path()), Duration::from_millis(100));
        assert_eq!(
            result.unwrap_err().to_string(),
            "PACKET_OBSERVATION_WALL_BUDGET"
        );
        let path = temporary.path().to_owned();
        temporary.close().unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn child_output_cannot_grow_parent_memory_without_a_bound() {
        let temporary = tempfile::tempdir().unwrap();
        let result = execute(probe("flood", temporary.path()), Duration::from_secs(10));
        assert_eq!(
            result.unwrap_err().to_string(),
            "PACKET_OBSERVATION_OUTPUT_LIMIT"
        );
    }
}
