//! Diagnostic process envelope for the original confirmation phases.
//! These clocks include all native threads, including rejected/retried traffic.
//! They do not move the traffic epoch or grant business acceptance.
use serde_json::{json, Value};
use std::{fs, path::Path, time::Instant};

const BOUNDARIES: [&str; 4] = [
    "before_setup",
    "before_service_spawn",
    "after_workers_and_service_join",
    "after_state_and_observation_readback",
];

pub(super) struct PhaseCost {
    started: Instant,
    samples: Vec<Value>,
    disk_before: Value,
}

impl PhaseCost {
    pub(super) fn start(path: &Path) -> Self {
        let started = Instant::now();
        let cpu = super::process_cpu_ns();
        Self {
            started,
            samples: vec![json!({"boundary": BOUNDARIES[0], "elapsed_ns": 0,
                "process_cpu_counter_ns": cpu})],
            // The first clock precedes this disk observation.
            disk_before: disk_snapshot(path),
        }
    }

    pub(super) fn mark(&mut self) {
        assert!(self.samples.len() < BOUNDARIES.len() - 1);
        self.sample();
    }

    fn sample(&mut self) {
        self.samples.push(json!({
            "boundary": BOUNDARIES[self.samples.len()],
            "elapsed_ns": super::ns(self.started),
            "process_cpu_counter_ns": super::process_cpu_ns(),
        }));
    }

    pub(super) fn finish(mut self, path: &Path) -> Value {
        assert_eq!(self.samples.len(), BOUNDARIES.len() - 1);
        let disk_after = disk_snapshot(path);
        self.sample();
        let intervals: Vec<_> = self
            .samples
            .windows(2)
            .map(|pair| interval(&pair[0], &pair[1]))
            .collect();
        json!({
            "schema": "public-v3-confirmation-phase-process-cost-v1",
            "process_id": std::process::id(),
            "cpu_clock": "CLOCK_PROCESS_CPUTIME_ID",
            "samples": self.samples,
            "intervals": intervals,
            "whole_phase": interval(&self.samples[0], &self.samples[3]),
            "retained_files_before": self.disk_before,
            "retained_files_after": disk_after,
            "scope": "all threads of this test process, including setup, failed/cancelled/retried calls, independent replay, joined workers, service shutdown and state/observation readback; includes nested actor/dispatch/Host clocks, never add them again; excludes child processes, this cost record's serialization and the final report write",
            "physical_network_bytes": null,
            "energy_joules": null,
            "business_acceptance_authority": false,
        })
    }
}

fn interval(start: &Value, end: &Value) -> Value {
    let before = start["process_cpu_counter_ns"].as_u64();
    let after = end["process_cpu_counter_ns"].as_u64();
    let cpu = before.zip(after).and_then(|(a, b)| b.checked_sub(a));
    let state = match (before, after, cpu) {
        (_, _, Some(_)) => "observed",
        (Some(_), Some(_), None) => "counter_rewind",
        _ => "clock_unavailable",
    };
    json!({
        "from": start["boundary"], "to": end["boundary"],
        "wall_ns": end["elapsed_ns"].as_u64().unwrap() - start["elapsed_ns"].as_u64().unwrap(),
        "process_cpu_ns": cpu, "cpu_state": state,
    })
}

fn disk_snapshot(path: &Path) -> Value {
    // Logical lengths of retained regular files, not disk I/O or physical media.
    // Bound traversal, reject links/special files, and retain errors as unknown.
    fn visit(
        path: &Path,
        entries: &mut u64,
        files: &mut u64,
        bytes: &mut u64,
    ) -> Result<(), String> {
        *entries = entries.checked_add(1).ok_or("entry_overflow")?;
        if *entries > 4096 {
            return Err("entry_bound".into());
        }
        let info = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if info.is_file() {
            *files = files.checked_add(1).ok_or("file_overflow")?;
            *bytes = bytes.checked_add(info.len()).ok_or("byte_overflow")?;
        } else if info.is_dir() {
            for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
                visit(
                    &entry.map_err(|e| e.to_string())?.path(),
                    entries,
                    files,
                    bytes,
                )?;
            }
        } else {
            return Err("non_regular_entry".into());
        }
        Ok(())
    }
    if matches!(fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
        return json!({"state": "absent", "regular_files": 0, "logical_file_bytes": 0, "error": null});
    }
    let (mut entries, mut files, mut bytes) = (0, 0, 0);
    match visit(path, &mut entries, &mut files, &mut bytes) {
        Ok(()) => {
            json!({"state": "observed", "regular_files": files, "logical_file_bytes": bytes, "error": null})
        }
        Err(error) => {
            json!({"state": "unavailable", "regular_files": null, "logical_file_bytes": null, "error": error})
        }
    }
}

#[test]
fn process_envelope_keeps_joined_worker_cost_and_disk_growth() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("phase");
    let mut cost = PhaseCost::start(&path);
    fs::create_dir(&path).unwrap();
    cost.mark();
    let worker = std::thread::spawn(|| {
        let mut value = 0_u64;
        for i in 0..500_000_u64 {
            value = std::hint::black_box(value.wrapping_add(i));
        }
        value
    });
    assert!(worker.join().unwrap() > 0);
    cost.mark();
    fs::write(path.join("record"), b"failed attempt retained\n").unwrap();
    let observed = cost.finish(&path);
    assert_eq!(observed["retained_files_before"]["state"], "absent");
    assert_eq!(observed["retained_files_after"]["logical_file_bytes"], 24);
    assert_eq!(observed["whole_phase"]["from"], BOUNDARIES[0]);
    assert_eq!(observed["whole_phase"]["to"], BOUNDARIES[3]);
    #[cfg(target_os = "linux")]
    {
        assert!(observed["intervals"][1]["process_cpu_ns"].as_u64().unwrap() > 0);
        let sum: u64 = observed["intervals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["process_cpu_ns"].as_u64().unwrap())
            .sum();
        assert_eq!(observed["whole_phase"]["process_cpu_ns"], sum);
    }
    assert_eq!(observed["business_acceptance_authority"], false);
}

#[test]
fn unavailable_or_reversed_clock_never_becomes_zero() {
    let before = json!({"boundary": "a", "elapsed_ns": 0, "process_cpu_counter_ns": 9});
    let missing = json!({"boundary": "b", "elapsed_ns": 10, "process_cpu_counter_ns": null});
    let reversed = json!({"boundary": "b", "elapsed_ns": 10, "process_cpu_counter_ns": 8});
    assert_eq!(
        interval(&before, &missing)["cpu_state"],
        "clock_unavailable"
    );
    assert!(interval(&before, &missing)["process_cpu_ns"].is_null());
    assert_eq!(interval(&before, &reversed)["cpu_state"], "counter_rewind");
    assert!(interval(&before, &reversed)["process_cpu_ns"].is_null());
}

#[cfg(unix)]
#[test]
fn retained_file_snapshot_refuses_links_without_partial_total() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(temporary.path().join("real"), b"data").unwrap();
    std::os::unix::fs::symlink("real", temporary.path().join("link")).unwrap();
    let observed = disk_snapshot(temporary.path());
    assert_eq!(observed["state"], "unavailable");
    assert!(observed["logical_file_bytes"].is_null());
}
