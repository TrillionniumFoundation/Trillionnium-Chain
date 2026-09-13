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

fn prepare_at(
    root: &Path,
    height: u64,
    view: u64,
    block: u8,
    parent: u8,
    nonce: u64,
    payload: &str,
) -> Output {
    base_command(root, "prepare")
        .arg(height.to_string())
        .arg(view.to_string())
        .arg(hex_digest(block))
        .arg(hex_digest(parent))
        .arg(hex_digest(40))
        .arg(hex_digest(41))
        .arg(nonce.to_string())
        .arg(payload)
        .output()
        .expect("run candidate prepare process")
}

fn prepare(root: &Path, payload: &str) -> Output {
    prepare_at(root, 10, 2, 10, 9, 1, payload)
}

fn advance(root: &Path, stage: &str, facts: u8) -> Output {
    base_command(root, "advance")
        .arg(stage)
        .arg(hex_digest(facts))
        .output()
        .expect("run candidate advance process")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("candidate stdout must be UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("candidate stderr must be UTF-8")
}

fn assert_stage(report: &str, stage: &str, sequence: u64) {
    assert!(
        report.contains(&format!("\"stage\":\"{stage}\"")),
        "missing stage {stage}: {report}"
    );
    assert!(
        report.contains(&format!("\"durable_sequence\":{sequence}")),
        "missing sequence {sequence}: {report}"
    );
    assert!(report.contains("\"fresh_readback\":true"));
    assert!(report.contains("\"authenticated_network\":false"));
    assert!(report.contains("\"pacemaker\":false"));
    assert!(report.contains("\"signing\":false"));
    assert!(report.contains("\"finality_authority\":false"));
    assert!(report.contains("\"checkpoint_authority\":false"));
    assert!(report.contains("\"production_candidate\":false"));
    assert!(report.contains("\"production_activation\":false"));
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
    assert!(report.contains("\"stage\":null"));
    assert!(report.contains("\"durable_sequence\":null"));
    assert!(report.contains("\"persistent_authority\":true"));
    assert!(report.contains("\"authenticated_network\":false"));
    assert!(report.contains("\"pacemaker\":false"));
    assert!(report.contains("\"signing\":false"));
    assert!(report.contains("\"finality_authority\":false"));
    assert!(report.contains("\"checkpoint_authority\":false"));
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
    assert_stage(&first_report, "Prepared", 0);
    assert!(first_report.contains("\"exact_replay_safe\":true"));

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

#[test]
fn each_process_reopens_and_advances_one_exact_authority_stage() {
    let directory = TestDirectory::new("candidate-host-stage-chain");
    let prepared = prepare(&directory.0, "proposal-v0");
    assert!(prepared.status.success(), "{}", stderr(&prepared));
    assert_stage(&stdout(&prepared), "Prepared", 0);

    let stages = [
        ("ApplicationSealed", 50),
        ("SafetyPersisted", 51),
        ("SignIntentPersisted", 52),
        ("SignatureConfirmed", 53),
        ("FinalityApplied", 54),
        ("CheckpointConfirmed", 55),
        ("OutboundPublished", 56),
    ];
    let mut terminal_report = String::new();
    for (index, (stage, facts)) in stages.into_iter().enumerate() {
        let output = advance(&directory.0, stage, facts);
        assert!(output.status.success(), "{}", stderr(&output));
        let report = stdout(&output);
        assert_stage(&report, stage, u64::try_from(index + 1).unwrap());
        assert!(report.contains("\"exact_replay\":false"));

        let status_output = status(&directory.0);
        assert!(status_output.status.success(), "{}", stderr(&status_output));
        assert_stage(
            &stdout(&status_output),
            stage,
            u64::try_from(index + 1).unwrap(),
        );
        terminal_report = report;
    }
    assert_stage(&terminal_report, "OutboundPublished", 7);

    let second = prepare_at(&directory.0, 11, 3, 11, 10, 2, "proposal-v1");
    assert!(second.status.success(), "{}", stderr(&second));
    assert_stage(&stdout(&second), "Prepared", 8);
}

#[test]
fn advance_replay_is_exact_and_substitution_or_skip_does_not_move_the_tip() {
    let directory = TestDirectory::new("candidate-host-advance-replay");
    let prepared = prepare(&directory.0, "proposal-v0");
    assert!(prepared.status.success(), "{}", stderr(&prepared));

    let first = advance(&directory.0, "ApplicationSealed", 60);
    assert!(first.status.success(), "{}", stderr(&first));
    let first_report = stdout(&first);
    assert_stage(&first_report, "ApplicationSealed", 1);
    assert!(first_report.contains("\"exact_replay\":false"));

    let replay = advance(&directory.0, "ApplicationSealed", 60);
    assert!(replay.status.success(), "{}", stderr(&replay));
    let replay_report = stdout(&replay);
    assert_stage(&replay_report, "ApplicationSealed", 1);
    assert!(replay_report.contains("\"exact_replay\":true"));
    assert!(replay_report.contains(&extract_field(&first_report, "record_digest")));

    let substituted = advance(&directory.0, "ApplicationSealed", 61);
    assert_eq!(substituted.status.code(), Some(2));
    assert!(stderr(&substituted).contains("same authority stage was replayed with different facts"));

    let skipped = advance(&directory.0, "SignatureConfirmed", 62);
    assert_eq!(skipped.status.code(), Some(2));
    assert!(stderr(&skipped).contains("requested stage is not the exact durable successor"));

    let after = status(&directory.0);
    assert!(after.status.success(), "{}", stderr(&after));
    assert_stage(&stdout(&after), "ApplicationSealed", 1);
}

#[test]
fn advance_requires_existing_authority_and_rejects_zero_or_unknown_facts() {
    let directory = TestDirectory::new("candidate-host-invalid-advance");
    let absent = advance(&directory.0, "ApplicationSealed", 70);
    assert_eq!(absent.status.code(), Some(2));
    assert!(stderr(&absent).contains("advance requires an existing Prepared authority receipt"));

    let prepared = prepare(&directory.0, "proposal-v0");
    assert!(prepared.status.success(), "{}", stderr(&prepared));

    let zero = base_command(&directory.0, "advance")
        .arg("ApplicationSealed")
        .arg("00".repeat(32))
        .output()
        .expect("run zero-facts advance");
    assert_eq!(zero.status.code(), Some(2));
    assert!(stderr(&zero).contains("facts-digest may not be the zero digest"));

    let unknown = base_command(&directory.0, "advance")
        .arg("UnknownStage")
        .arg(hex_digest(71))
        .output()
        .expect("run unknown-stage advance");
    assert_eq!(unknown.status.code(), Some(2));
    assert!(stderr(&unknown).contains("next-stage is not a supported exact authority successor"));

    let after = status(&directory.0);
    assert!(after.status.success(), "{}", stderr(&after));
    assert_stage(&stdout(&after), "Prepared", 0);
}

fn extract_field(report: &str, field: &str) -> String {
    let prefix = format!("\"{field}\":\"");
    let start = report.find(&prefix).expect("field must exist") + prefix.len();
    let end = report[start..].find('"').expect("field must terminate") + start;
    format!("\"{field}\":\"{}\"", &report[start..end])
}
