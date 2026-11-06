//! Actual CLI processes with writerless FIFOs. A finite watchdog makes a future
//! accidental blocking open fail the test, rather than hanging the test runner.
#![cfg(unix)]
use serde_json::json;
use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};
use trnm_useful_cell_v2_reference::{task_json, Model, PreparedModel, DIM};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "trnm-cell-v2-file-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn run(task: &Path, claim: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_trnm-useful-cell-v2-reference"))
        .arg("verify")
        .arg(task)
        .arg(claim)
        .arg("20")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed() > Duration::from_secs(3) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("CLI blocked on special input file: {task:?}, {claim:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
}
fn expect_error(task: &Path, claim: &Path, marker: Option<&str>) {
    let output = run(task, claim);
    assert!(!output.status.success());
    if let Some(marker) = marker {
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(marker),
            "{:?}",
            output
        );
    }
}
fn valid_task() -> Vec<u8> {
    let model = PreparedModel::new(Model {
        version: [1; 32],
        base: [[0; DIM]; 3],
        router: [[0; DIM]; 3],
        deltas: [[[0; DIM]; 3]; 3],
    })
    .unwrap();
    let hash = hex::encode([1; 32]);
    let mut x = vec![0; DIM];
    x[DIM - 1] = 8;
    serde_json::to_vec(&json!({
        "schema":"pon-useful-cell-task-v2",
        "model":{"model_version":hash,"base":vec![vec![0;DIM];3],"router":vec![vec![0;DIM];3],"deltas":vec![vec![vec![0;DIM];3];3]},
        "context":{"chain":hash,"parent":hash,"challenge":hash,"batch_id":hash},
        "requests":[{"id":hash,"scope":hash,"arrival_ns":1,"deadline_ns":3_600_000_000_000_u64,"x":x}],
        "state":{"cell_id":hash,"generation":0,"snapshot_root":hash,"model_commitment":hex::encode(model.commitment())},
        "bindings":{"program_digest":hash,"extractor_digest":hash,"source_inputs_digest":hash,"consumer":hash,"allowed_use":hash,"candidate_artifact":hash},
        "policy":{"shift":0,"clamp_abs":1,"activation":"identity","stop_rule":{"kind":"disabled"}},
        "issued_at_ns":10,"valid_until_ns":3_600_000_000_000_u64,
    }))
    .unwrap()
}

#[test]
fn task_and_claim_reject_writerless_fifo_symlink_directory_and_oversize() {
    let scratch = Scratch::new();
    let task = scratch.path("task.json");
    let data = valid_task();
    task_json::parse(&data).unwrap();
    fs::write(&task, data).unwrap();
    let fifo = scratch.path("no-writer");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    expect_error(&fifo, &fifo, Some("FILE_TYPE"));
    expect_error(&task, &fifo, Some("FILE_TYPE"));
    expect_error(&scratch.0, &fifo, Some("FILE_TYPE"));
    expect_error(&task, &scratch.0, Some("FILE_TYPE"));
    let link = scratch.path("link");
    symlink(&task, &link).unwrap();
    expect_error(&link, &fifo, None);
    expect_error(&task, &link, None);
    let huge = scratch.path("oversized");
    fs::write(&huge, vec![0; task_json::MAX_TASK_BYTES + 1]).unwrap();
    expect_error(&huge, &fifo, Some("FILE_SIZE"));
    expect_error(&task, &huge, Some("FILE_SIZE"));
}
