use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

fn unique_fixture_path(name: &str, ext: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("trnm_rpc_{}_{}.{}", name, ts, ext))
}

fn run_submit(ingress: &PathBuf, key: &str) -> std::process::Output {
    Command::new("cargo")
        .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args([
            "submit-message",
            "--channel",
            "telegram",
            "--user-id",
            "u-submit",
            "--session-id",
            "s-submit",
            "--text",
            "hello",
            "--idempotency-key",
            key,
        ])
        .env("TRNM_RPC_INGRESS_FILE", ingress)
        .output()
        .expect("run submit-message")
}

fn run_dispatch(ingress: &PathBuf) -> std::process::Output {
    Command::new("cargo")
        .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args([
            "dispatch-open",
            "--worker-id",
            "worker-serial",
            "--limit",
            "1",
        ])
        .env("TRNM_RPC_INGRESS_FILE", ingress)
        .output()
        .expect("run dispatch-open")
}

#[test]
fn dispatch_open_and_submit_message_stay_serializable_under_contention() {
    let ingress = unique_fixture_path("dispatch_submit_serial", "jsonl");
    let _ = fs::remove_file(&ingress);

    // Seed one open task so dispatch-open always has work and writes back.
    let seed = r#"{"request_id":"r-seed","task_id":10001,"channel":"telegram","user_id":"u-seed","session_id":"s-seed","text":"seed","idempotency_key":"k-seed","status":"Open","created_at_unix_ms":1}"#;
    fs::write(&ingress, format!("{}\n", seed)).expect("seed ingress");

    for i in 0..4 {
        let ingress_a = ingress.clone();
        let ingress_b = ingress.clone();
        let key = format!("k-{}", i);

        let j1 = thread::spawn(move || run_submit(&ingress_a, &key));
        let j2 = thread::spawn(move || run_dispatch(&ingress_b));

        let out_submit = j1.join().expect("join submit");
        let out_dispatch = j2.join().expect("join dispatch");

        assert!(
            out_submit.status.success(),
            "submit stderr: {}",
            String::from_utf8_lossy(&out_submit.stderr)
        );
        assert!(
            out_dispatch.status.success(),
            "dispatch stderr: {}",
            String::from_utf8_lossy(&out_dispatch.stderr)
        );
    }

    let raw = fs::read_to_string(&ingress).expect("read ingress");
    let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        5,
        "all submit-message appends must survive concurrent dispatch writes"
    );

    let mut task_ids = std::collections::BTreeSet::new();
    for line in &lines {
        let v: Value = serde_json::from_str(line).expect("valid ingress json");
        let id = v["task_id"].as_u64().expect("task_id");
        assert!(task_ids.insert(id), "duplicate task_id {} detected", id);
    }

    // Ensure lock file is not leaked by either command.
    let lock = ingress.with_file_name(format!(
        "{}.lock",
        ingress
            .file_name()
            .and_then(|v| v.to_str())
            .expect("ingress file name")
    ));
    assert!(!lock.exists(), "ingress lock file should be cleaned");
}

#[test]
fn dispatch_open_with_no_open_tasks_leaves_ingress_unchanged() {
    let ingress = unique_fixture_path("dispatch_submit_noop", "jsonl");
    let _ = fs::remove_file(&ingress);

    let seed = r#"{"request_id":"r-seed","task_id":10001,"channel":"telegram","user_id":"u-seed","session_id":"s-seed","text":"seed","idempotency_key":"k-seed","status":"Assigned","created_at_unix_ms":1,"assigned_worker":"worker-existing","assigned_at_unix_ms":2,"model_output":null,"result_hash":null,"verifier_status":null,"resolution_code":null,"commit_tx_hash":null,"reveal_tx_hash":null}"#;
    fs::write(&ingress, format!("{}\n", seed)).expect("seed ingress");
    let before = fs::read_to_string(&ingress).expect("read ingress before noop dispatch");

    let out_dispatch = run_dispatch(&ingress);
    assert!(
        out_dispatch.status.success(),
        "dispatch stderr: {}",
        String::from_utf8_lossy(&out_dispatch.stderr)
    );

    let stdout = String::from_utf8_lossy(&out_dispatch.stdout);
    let assigned: Value = serde_json::from_str(&stdout).expect("dispatch json response");
    assert_eq!(
        assigned,
        serde_json::json!([]),
        "noop dispatch should assign nothing"
    );

    let after = fs::read_to_string(&ingress).expect("read ingress after noop dispatch");
    assert_eq!(
        after, before,
        "noop dispatch should not rewrite ingress state"
    );
}
