//! Actual native confirmation calls, restart accounting and refusal controls.
#[path = "../examples/support/native_risk_scenario.rs"]
mod scenario;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use trnm_pon_node::native_owner_journal::{
    JournalBackend, JournalCheckpoint, JournaledNativeOwner, NativeJournalOptions,
};
use trnm_pon_node::native_risk_ledger::{
    NativeRiskOwner, RiskConfirmationRequest, RiskLedgerOptions,
};
use trnm_pon_node::Settings;

fn options() -> RiskLedgerOptions {
    RiskLedgerOptions {
        unit_denominator: 100,
        budget_units: 10,
        law_scope_sha256: [42; 32],
        ..RiskLedgerOptions::default()
    }
}
fn request(units: u64) -> RiskConfirmationRequest {
    RiskConfirmationRequest {
        transaction: [1; 32],
        included: [2; 32],
        observed_now: 100,
        allowance_units: units,
        law_scope_sha256: [42; 32],
        statement_sha256: [3; 32],
    }
}
fn open(
    root: &Path,
    native: NativeJournalOptions,
    risk: RiskLedgerOptions,
) -> trnm_pon_node::Result<NativeRiskOwner> {
    NativeRiskOwner::open(
        &root.join("store"),
        &root.join("native"),
        &root.join("bank"),
        Settings::development(Some(1))?,
        native,
        risk,
    )
}
fn refused(root: &Path, native: NativeJournalOptions, risk: RiskLedgerOptions, code: &str) {
    match open(root, native, risk) {
        Ok(_) => panic!("expected {code}"),
        Err(error) => assert_eq!(error.to_string(), code),
    }
}

#[test]
fn native_prefix_replaced_by_fifo_refuses_without_spending_or_blocking() {
    use std::os::unix::fs::FileTypeExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let root = tempfile::tempdir().unwrap();
    let owner = open(root.path(), NativeJournalOptions::default(), options()).unwrap();
    let (bank_pin, native_pin) = owner.finish(100).unwrap();
    let journal = root.path().join("native/journal.pnoj1");
    let saved = root.path().join("native/original-journal.pnoj1");
    let journal_bytes = fs::read(&journal).unwrap();
    let bank = root.path().join("bank/risk.pnrl1");
    let bank_bytes = fs::read(&bank).unwrap();
    fs::rename(&journal, &saved).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &journal,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_risk_fifo_prefix_child",
            "--ignored",
            "--nocapture",
        ])
        .env("TRNM_NATIVE_RISK_FIFO_TEST_ROOT", root.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let ready = root.path().join("prefix-open-ready");
    let mut deadline = Instant::now() + Duration::from_secs(15);
    let mut read_started = false;
    let timed_out = loop {
        if child.try_wait().unwrap().is_some() {
            break false;
        }
        if !read_started && ready.exists() {
            read_started = true;
            deadline = Instant::now() + Duration::from_secs(1);
        }
        if Instant::now() >= deadline {
            break true;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if timed_out {
        child.kill().unwrap();
    }
    // Always reap the actual API caller, including the original blocking
    // implementation. The FIFO has no writer and must not outlive this test.
    let output = child.wait_with_output().unwrap();
    assert_eq!(fs::read(&bank).unwrap(), bank_bytes);
    assert_eq!(fs::read(&saved).unwrap(), journal_bytes);
    assert!(fs::symlink_metadata(&journal)
        .unwrap()
        .file_type()
        .is_fifo());
    assert!(
        !timed_out && output.status.success(),
        "native prefix refusal timed_out={timed_out}, read_started={read_started}, \
         status={}, stdout={}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Restoring the exact original regular file still admits the retained
    // checkpoint. A refusal must not rewrite the native journal or risk bank.
    fs::remove_file(&journal).unwrap();
    fs::rename(&saved, &journal).unwrap();
    let owner = open(
        root.path(),
        NativeJournalOptions {
            expected_checkpoint: Some(native_pin),
            ..NativeJournalOptions::default()
        },
        RiskLedgerOptions {
            expected_checkpoint: Some(bank_pin),
            ..options()
        },
    )
    .unwrap();
    assert_eq!(owner.status().unwrap()["spent_units"], 0);
    owner.finish(100).unwrap();
}

#[test]
#[ignore = "owned subprocess helper, actually executed by the native prefix FIFO test"]
fn native_risk_fifo_prefix_child() {
    let root = std::path::PathBuf::from(
        std::env::var_os("TRNM_NATIVE_RISK_FIFO_TEST_ROOT")
            .expect("explicit parent test directory required"),
    );
    fs::write(root.join("prefix-open-ready"), b"ready").unwrap();
    refused(
        &root,
        NativeJournalOptions::default(),
        options(),
        "RISK_LEDGER_NATIVE_PATH",
    );
}

fn append_nonready_start(root: &Path, before: JournalCheckpoint, spent: u64) {
    let path = root.join("bank/risk.pnrl1");
    let raw = fs::read(&path).unwrap();
    assert_eq!(&raw[..8], b"PNRL1\0\0\0");
    let mut position = 8;
    let mut payloads = Vec::new();
    while position < raw.len() {
        let length = u32::from_be_bytes(raw[position..position + 4].try_into().unwrap()) as usize;
        let frame: Value =
            serde_json::from_slice(&raw[position + 4..position + 4 + length]).unwrap();
        payloads.push(frame["payload"].clone());
        position += 4 + length + 32;
    }
    if payloads.last().unwrap()["kind"] == "lease_end" {
        payloads.pop();
    }
    let opening = payloads
        .iter()
        .rev()
        .find(|payload| payload["kind"] == "lease_open")
        .unwrap();
    let request = request(1);
    payloads.push(json!({"kind":"start","epoch":opening["epoch"],
        "native_owner_epoch":opening["native_owner_epoch"],
        "expected_native_intent_sequence":before.sequence + 1,"native_before":before,
        "transaction":hex::encode(request.transaction),"included":hex::encode(request.included),
        "observed_now":request.observed_now,"allowance_units":request.allowance_units,
        "law_scope_sha256":hex::encode(request.law_scope_sha256),
        "statement_sha256":hex::encode(request.statement_sha256),"spent_units":spent}));
    let mut previous = "00".repeat(32);
    let mut output = b"PNRL1\0\0\0".to_vec();
    for (sequence, payload) in payloads.into_iter().enumerate() {
        let raw = serde_json::to_vec(
            &json!({"sequence":sequence,"previous_hash":previous,"payload":payload}),
        )
        .unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"pon-native-risk-ledger-frame-v1\0");
        hasher.update(&raw);
        let digest = hasher.finalize();
        output.extend_from_slice(&u32::try_from(raw.len()).unwrap().to_be_bytes());
        output.extend_from_slice(&raw);
        output.extend_from_slice(&digest);
        previous = hex::encode(digest);
    }
    fs::write(path, output).unwrap();
}

#[test]
fn recovery_rejects_registration_after_closed_or_incomplete_native_prefix() {
    for record_limit in [None, Some(4), Some(5)] {
        let root = tempfile::tempdir().unwrap();
        let native_options = NativeJournalOptions {
            maximum_records: record_limit.unwrap_or(4096),
            ..NativeJournalOptions::default()
        };
        let mut owner = open(root.path(), native_options, options()).unwrap();
        let (before, spent) = if record_limit.is_none() {
            assert!(owner.confirmation(request(1)).is_err());
            (owner.finish(100).unwrap().1, 2)
        } else {
            assert_eq!(
                owner.observe(100).unwrap_err().to_string(),
                "OWNER_JOURNAL_RECORD_BUDGET"
            );
            let before = owner.native_checkpoint().unwrap();
            drop(owner);
            (before, 1)
        };
        append_nonready_start(root.path(), before, spent);
        let bank_path = root.path().join("bank/risk.pnrl1");
        let native_path = root.path().join("native/journal.pnoj1");
        let bank_bytes = fs::read(&bank_path).unwrap();
        let native_bytes = fs::read(&native_path).unwrap();
        refused(
            root.path(),
            NativeJournalOptions::default(),
            options(),
            "RISK_LEDGER_NATIVE_START_STATE",
        );
        assert_eq!(fs::read(bank_path).unwrap(), bank_bytes);
        assert_eq!(fs::read(native_path).unwrap(), native_bytes);
    }
}

#[test]
fn real_confirmed_unconfirmed_error_and_two_process_cuts_keep_all_eight_charges() {
    let root = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let report = scenario::run(&root.path().join("run"), |plan| {
        Ok(Command::new(&executable)
            .args([
                "--exact",
                "native_risk_process_child",
                "--ignored",
                "--nocapture",
            ])
            .env("NATIVE_RISK_CHILD_PLAN", plan)
            .output()?)
    })
    .unwrap();
    assert_eq!(report["early"]["confirmed"], false);
    assert_eq!(report["confirmed"]["confirmed"], true);
    assert_eq!(report["native_membership_error"], "MEMBERSHIP");
    assert_eq!(
        report["children"][0]["exit_code"],
        scenario::BEFORE_DISPATCH_EXIT
    );
    assert_eq!(
        report["children"][1]["exit_code"],
        scenario::AFTER_NATIVE_EXIT
    );
    assert_eq!(report["final_status"]["starts_registered"], 8);
    assert_eq!(report["final_status"]["spent_units"], 36);
    assert_eq!(
        report["final_status"]["unresolved_starts"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(report["stale_bank_refusal"], "RISK_LEDGER_CHECKPOINT");
    assert_eq!(
        report["global_failure_probability"],
        serde_json::Value::Null
    );
}

#[test]
#[ignore = "owned subprocess helper, actually executed twice by the process-cut test"]
fn native_risk_process_child() {
    let path = std::env::var_os("NATIVE_RISK_CHILD_PLAN").expect("explicit parent plan required");
    scenario::crash_child(Path::new(&path)).unwrap();
    panic!("child must exit at its actual registered cut");
}

#[test]
fn real_native_errors_spend_and_caps_survive_legacy_and_authenticated_reopen() {
    for backend in [JournalBackend::Legacy, JournalBackend::AuthenticatedV1] {
        let root = tempfile::tempdir().unwrap();
        let native = NativeJournalOptions {
            backend,
            ..NativeJournalOptions::default()
        };
        let mut owner = open(root.path(), native.clone(), options()).unwrap();
        assert!(owner.confirmation(request(5)).is_err());
        assert_eq!(owner.status().unwrap()["spent_units"], 5);
        let (bank_pin, native_pin) = owner.finish(100).unwrap();
        let mut owner = open(
            root.path(),
            NativeJournalOptions {
                expected_checkpoint: Some(native_pin),
                ..native
            },
            RiskLedgerOptions {
                expected_checkpoint: Some(bank_pin),
                ..options()
            },
        )
        .unwrap();
        assert!(owner.confirmation(request(5)).is_err());
        let before = owner.native_checkpoint().unwrap();
        let error = match owner.start_confirmation(request(1)) {
            Ok(_) => panic!("overspend"),
            Err(e) => e,
        };
        assert_eq!(error.to_string(), "RISK_LEDGER_BUDGET");
        assert_eq!(owner.native_checkpoint().unwrap(), before);
        assert_eq!(owner.status().unwrap()["spent_units"], 10);
        owner.finish(100).unwrap();
    }
}

#[test]
fn dropped_pre_dispatch_start_is_spent_pending_and_never_automatically_replayed() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = open(root.path(), NativeJournalOptions::default(), options()).unwrap();
    let before = owner.native_checkpoint().unwrap();
    let pending = owner.start_confirmation(request(3)).unwrap();
    drop(pending);
    assert_eq!(owner.native_checkpoint().unwrap(), before);
    assert_eq!(
        owner.observe(100).unwrap_err().to_string(),
        "RISK_LEDGER_UNRESOLVED"
    );
    let pin = owner.checkpoint().unwrap();
    drop(owner);
    let owner = open(
        root.path(),
        NativeJournalOptions::default(),
        RiskLedgerOptions {
            expected_checkpoint: Some(pin),
            ..options()
        },
    )
    .unwrap();
    let status = owner.status().unwrap();
    assert_eq!(status["starts_registered"], 1);
    assert_eq!(status["spent_units"], 3);
    assert_eq!(status["outcomes_recorded"], 0);
    assert_eq!(status["unresolved_starts"].as_array().unwrap().len(), 1);
    owner.finish(100).unwrap();
}

#[test]
fn rejected_scope_has_no_native_call_and_bank_scope_and_budget_are_immutable() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = open(root.path(), NativeJournalOptions::default(), options()).unwrap();
    let before = owner.native_checkpoint().unwrap();
    let mut changed = request(1);
    changed.law_scope_sha256 = [9; 32];
    let error = match owner.start_confirmation(changed) {
        Ok(_) => panic!("wrong scope"),
        Err(e) => e,
    };
    assert_eq!(error.to_string(), "RISK_LEDGER_SCOPE");
    assert_eq!(owner.native_checkpoint().unwrap(), before);
    assert_eq!(owner.status().unwrap()["spent_units"], 0);
    owner.finish(100).unwrap();
    refused(
        root.path(),
        NativeJournalOptions::default(),
        RiskLedgerOptions {
            budget_units: 11,
            ..options()
        },
        "RISK_LEDGER_IMMUTABLE_BUDGET_SCOPE",
    );
    refused(
        root.path(),
        NativeJournalOptions::default(),
        RiskLedgerOptions {
            unit_denominator: 101,
            ..options()
        },
        "RISK_LEDGER_IMMUTABLE_BUDGET_SCOPE",
    );
    refused(
        root.path(),
        NativeJournalOptions::default(),
        RiskLedgerOptions {
            law_scope_sha256: [8; 32],
            ..options()
        },
        "RISK_LEDGER_IMMUTABLE_BUDGET_SCOPE",
    );
}

#[test]
fn full_native_suffix_rejects_a_confirmation_outside_the_risk_wrapper() {
    let root = tempfile::tempdir().unwrap();
    let owner = open(root.path(), NativeJournalOptions::default(), options()).unwrap();
    owner.finish(100).unwrap();
    let mut bypass = JournaledNativeOwner::open(
        &root.path().join("store"),
        &root.path().join("native"),
        Settings::development(Some(1)).unwrap(),
        NativeJournalOptions::default(),
    )
    .unwrap();
    assert!(bypass.confirmation([1; 32], [2; 32], 100).is_err());
    bypass.finish(100).unwrap();
    refused(
        root.path(),
        NativeJournalOptions::default(),
        options(),
        "RISK_LEDGER_UNREGISTERED_CONFIRMATION",
    );
}

#[test]
fn a_new_bank_cannot_reset_a_native_journal_with_previous_confirmation_intents() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = open(root.path(), NativeJournalOptions::default(), options()).unwrap();
    assert!(owner.confirmation(request(1)).is_err());
    owner.finish(100).unwrap();
    match NativeRiskOwner::open(
        &root.path().join("store"),
        &root.path().join("native"),
        &root.path().join("new-bank"),
        Settings::development(Some(1)).unwrap(),
        NativeJournalOptions::default(),
        options(),
    ) {
        Ok(_) => panic!("bank reset"),
        Err(e) => assert_eq!(e.to_string(), "RISK_LEDGER_PRIOR_CONFIRMATIONS"),
    }
}

#[test]
fn incomplete_native_observation_keeps_charge_and_native_stop_before_recovery() {
    let root = tempfile::tempdir().unwrap();
    // Three opening frames, then the confirmation intent. The actual prepared
    // append cannot fit, so the wrapper records its error and never refunds.
    let mut owner = open(
        root.path(),
        NativeJournalOptions {
            maximum_records: 4,
            ..NativeJournalOptions::default()
        },
        options(),
    )
    .unwrap();
    assert_eq!(
        owner.confirmation(request(2)).unwrap_err().to_string(),
        "OWNER_JOURNAL_RECORD_BUDGET"
    );
    let status = owner.status().unwrap();
    assert_eq!(status["spent_units"], 2);
    assert_eq!(status["starts_registered"], 1);
    assert_eq!(status["outcomes_recorded"], 1);
    assert_eq!(status["blocked"], true);
    drop(owner);
    let owner = open(root.path(), NativeJournalOptions::default(), options()).unwrap();
    assert_eq!(owner.status().unwrap()["spent_units"], 2);
    owner.finish(100).unwrap();
}

#[test]
fn bank_capacity_refusal_precedes_native_dispatch_and_torn_tail_is_not_repaired() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = open(
        root.path(),
        NativeJournalOptions::default(),
        RiskLedgerOptions {
            maximum_records: 2,
            ..options()
        },
    )
    .unwrap();
    let before = owner.native_checkpoint().unwrap();
    let error = match owner.start_confirmation(request(1)) {
        Ok(_) => panic!("storage capacity"),
        Err(e) => e,
    };
    assert_eq!(error.to_string(), "RISK_LEDGER_STORAGE_BUDGET");
    assert_eq!(owner.native_checkpoint().unwrap(), before);
    assert_eq!(owner.status().unwrap()["spent_units"], 0);
    drop(owner);
    let path = root.path().join("bank/risk.pnrl1");
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&[0])
        .unwrap();
    let before = fs::read(&path).unwrap();
    refused(
        root.path(),
        NativeJournalOptions::default(),
        options(),
        "RISK_LEDGER_TORN_TAIL",
    );
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn forwarded_native_failure_reports_its_effective_stop_condition() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = open(
        root.path(),
        NativeJournalOptions {
            maximum_records: 4,
            ..NativeJournalOptions::default()
        },
        options(),
    )
    .unwrap();
    assert_eq!(
        owner.observe(100).unwrap_err().to_string(),
        "OWNER_JOURNAL_RECORD_BUDGET"
    );
    let status = owner.status().unwrap();
    assert_eq!(status["bank_operation_blocked"], false);
    assert_eq!(status["native_owner_blocked"], true);
    assert_eq!(status["blocked"], true);
    assert_eq!(status["spent_units"], 0);
    assert_eq!(
        owner.observe(100).unwrap_err().to_string(),
        "RISK_LEDGER_NATIVE_BLOCKED"
    );
}

#[test]
fn exclusive_bank_lock_and_supplied_checkpoint_refuse_competing_or_stale_bank() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = open(root.path(), NativeJournalOptions::default(), options()).unwrap();
    refused(
        root.path(),
        NativeJournalOptions::default(),
        options(),
        "RISK_LEDGER_BUSY",
    );
    let path = root.path().join("bank/risk.pnrl1");
    let old = fs::read(&path).unwrap();
    assert!(owner.confirmation(request(2)).is_err());
    let (pin, _) = owner.finish(100).unwrap();
    fs::write(&path, old).unwrap();
    refused(
        root.path(),
        NativeJournalOptions::default(),
        RiskLedgerOptions {
            expected_checkpoint: Some(pin),
            ..options()
        },
        "RISK_LEDGER_CHECKPOINT",
    );
}
