#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "trnm-{label}-{}-{timestamp}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create private process-test directory");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_trnm-candidate-persistent-host")
}

fn hex_digest(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn base_command(root: &Path, command: &str) -> Command {
    let mut process = Command::new(binary());
    process
        .arg("--acknowledge-candidate-only")
        .arg(command)
        .arg(root)
        .arg(hex_digest(1))
        .arg(hex_digest(2))
        .arg(hex_digest(3))
        .arg("1");
    process
}

fn status(root: &Path) -> Output {
    base_command(root, "status")
        .output()
        .expect("run candidate status process")
}

fn prepare(root: &Path, payload: &str) -> Output {
    base_command(root, "prepare")
        .arg("10")
        .arg("2")
        .arg(hex_digest(10))
        .arg(hex_digest(9))
        .arg(hex_digest(40))
        .arg(hex_digest(41))
        .arg("1")
        .arg(payload)
        .output()
        .expect("run candidate prepare process")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("candidate stdout must be UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("candidate stderr must be UTF-8")
}

#[test]
fn explicit_candidate_acknowledgement_is_mandatory() {
    let output = Command::new(binary())
        .arg("status")
        .output()
        .expect("run candidate process without acknowledgement");
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("explicit --acknowledge-candidate-only is required"));
}

#[test]
fn process_status_is_persistent_but_never_production_ready() {
    let directory = TestDirectory::new("candidate-host-status");
    let output = status(&directory.0);
    assert!(output.status.success(), "{}", stderr(&output));
    let report = stdout(&output);
    assert!(report.contains("\"readiness\":\"ready\""));
    assert!(report.contains("\"persistent_authority\":true"));
    assert!(report.contains("\"authenticated_network\":false"));
    assert!(report.contains("\"pacemaker\":false"));
    assert!(report.contains("\"signing\":false"));
    assert!(report.contains("\"finality\":false"));
    assert!(report.contains("\"production_candidate\":false"));
    assert!(report.contains("\"production_activation\":false"));
    assert!(report.contains("\"start_permitted\":false"));
}

#[test]
fn separate_processes_recover_identical_prepared_receipt_and_reject_substitution() {
    let directory = TestDirectory::new("candidate-host-replay");

    let first = prepare(&directory.0, "proposal-v0");
    assert!(first.status.success(), "{}", stderr(&first));
    let first_report = stdout(&first);
    assert!(first_report.contains("\"stage\":\"Prepared\""));
    assert!(first_report.contains("\"durable_sequence\":0"));
    assert!(first_report.contains("\"exact_replay_safe\":true"));
    assert!(first_report.contains("\"signing\":false"));
    assert!(first_report.contains("\"finality\":false"));

    let replay = prepare(&directory.0, "proposal-v0");
    assert!(replay.status.success(), "{}", stderr(&replay));
    assert_eq!(stdout(&replay), first_report);

    let substituted = prepare(&directory.0, "substituted-proposal");
    assert_eq!(substituted.status.code(), Some(2));
    assert!(stderr(&substituted).contains("authority stage transition is not the exact successor"));

    let replay_after_rejection = prepare(&directory.0, "proposal-v0");
    assert!(
        replay_after_rejection.status.success(),
        "{}",
        stderr(&replay_after_rejection)
    );
    assert_eq!(stdout(&replay_after_rejection), first_report);
}
