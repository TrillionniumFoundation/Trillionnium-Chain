//! Explicit local-process conformance; never substitute it for physical LAN evidence.
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{public_key_hex, signing_key_from_hex, verify_hex_strict};
use trnm_protocol::pon_wire::hash;
fn child(binary: &Path, config: &Path, log: &Path, resume: bool) -> Child {
    Command::new(binary)
        .arg(if resume { "resume" } else { "run" })
        .arg(config)
        .stdout(Stdio::from(File::create(log).unwrap()))
        .stderr(Stdio::from(
            File::create(log.with_extension("stderr")).unwrap(),
        ))
        .spawn()
        .unwrap()
}
fn finish(mut child: Child, limit: u64) -> bool {
    let start = Instant::now();
    loop {
        if let Some(code) = child.try_wait().unwrap() {
            return code.success();
        }
        if start.elapsed() > Duration::from_secs(limit) {
            child.kill().unwrap();
            child.wait().unwrap();
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn check_receipts(root: &Path, expected: &str) -> Value {
    let raw = fs::read_to_string(root.join("receipts.jsonl")).unwrap();
    let mut previous = "00".repeat(32);
    let mut final_payload = None;
    for (index, line) in raw.lines().enumerate() {
        let row: Value = serde_json::from_str(line).unwrap();
        let body = &row["body"];
        assert_eq!(body["sequence"], index);
        assert_eq!(body["previous"], previous);
        assert_eq!(body["run"]["scope"], "local-process-test");
        assert_eq!(body["run"]["physical_host_verified"], false);
        assert_eq!(body["run"]["public_network_ready"], false);
        let digest = hash(
            b"distributed-receipt-v1",
            &[&serde_json::to_vec(body).unwrap()],
        );
        assert_eq!(row["receipt_digest"], hex::encode(digest));
        verify_hex_strict(
            body["run"]["role_public"].as_str().unwrap(),
            &digest,
            row["signature"].as_str().unwrap(),
        )
        .unwrap();
        let mut tampered = body.clone();
        tampered["event"] = json!("forged");
        let invalid = hash(
            b"distributed-receipt-v1",
            &[&serde_json::to_vec(&tampered).unwrap()],
        );
        assert!(verify_hex_strict(
            body["run"]["role_public"].as_str().unwrap(),
            &invalid,
            row["signature"].as_str().unwrap()
        )
        .is_err());
        previous = hex::encode(digest);
        if body["event"] == expected {
            final_payload = Some(body["payload"].clone());
        }
    }
    final_payload.expect("actual role completion receipt required")
}
fn campaign(restart: bool) {
    let binary =
        PathBuf::from(std::env::var("TRNM_DISTRIBUTED_TEST_BINARY").expect("binary required"));
    let root = PathBuf::from(
        std::env::var("TRNM_DISTRIBUTED_TEST_OUTPUT").expect("retained output path required"),
    );
    fs::create_dir_all(&root).unwrap();
    let root = root.join(if restart { "restart" } else { "fresh" });
    fs::create_dir(&root).unwrap();
    let output = Command::new(&binary).arg("fingerprint").output().unwrap();
    assert!(output.status.success());
    let fp: Value = serde_json::from_slice(&output.stdout).unwrap();
    fs::write(root.join("fingerprint.json"), &output.stdout).unwrap();
    let pin = json!({"commit":fp["commit"],"tree":fp["tree"],"inventory_digest":fp["inventory_digest"],"binary_digest":fp["binary_digest"]});
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut configs = Vec::new();
    let mut pubs = Vec::new();
    for (index, role) in ["validator", "producer", "confirmer"].iter().enumerate() {
        let secret = hex::encode([index as u8 + 1; 32]);
        let key = signing_key_from_hex(&secret).unwrap();
        pubs.push(public_key_hex(&key));
        let path = root.join(format!("{role}.key"));
        fs::write(&path, secret).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        configs.push(json!({"schema":"pon-distributed-role-config-v1","role":role,"scope":"local-process-test","run_id":"three-process-conformance","run_root":root.join(role),"source_pin":pin,"genesis_time":now-100,"workers":1,"evaluation_policy":"closed-round-all-eligible-min-v1","task_profile":"signed-task-dev-v1","pattern":"disjoint4","data_blocks":2,"transactions_per_block":4,"drain_blocks":6,"pace_ms":if restart {350}else{0},"server_seconds":20,"poll_ms":40,"timeout_seconds":16,"listen":if *role=="validator"{Some(addr.to_string())}else{None},"peer":if *role=="validator"{None}else{Some(addr.to_string())},"auth_secret":path,"peer_roster":if *role=="validator"{Some(root.join("roster.json"))}else{None},"server_public":Value::Null,"session_generation":1}));
    }
    fs::write(
        root.join("roster.json"),
        serde_json::to_vec(&vec![&pubs[1], &pubs[2]]).unwrap(),
    )
    .unwrap();
    fs::set_permissions(root.join("roster.json"), fs::Permissions::from_mode(0o644)).unwrap();
    configs[1]["server_public"] = json!(pubs[0]);
    configs[2]["server_public"] = json!(pubs[0]);
    let mut paths = Vec::new();
    for c in &configs {
        let path = root.join(format!("{}.json", c["role"].as_str().unwrap()));
        fs::write(&path, serde_json::to_vec_pretty(c).unwrap()).unwrap();
        paths.push(path);
    }
    let validator = child(&binary, &paths[0], &root.join("validator.log"), false);
    let ready = Instant::now();
    while !fs::read_to_string(root.join("validator.log"))
        .unwrap()
        .contains("validator-listening")
    {
        assert!(ready.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(20));
    }
    let mut confirmer = child(&binary, &paths[2], &root.join("confirmer.log"), false);
    let mut producer = child(&binary, &paths[1], &root.join("producer.log"), false);
    assert_ne!(validator.id(), confirmer.id());
    assert_ne!(validator.id(), producer.id());
    assert_ne!(producer.id(), confirmer.id());
    if restart {
        let wait = Instant::now();
        while !fs::read_to_string(root.join("producer.log"))
            .unwrap_or_default()
            .contains("producer-block")
        {
            assert!(wait.elapsed() < Duration::from_secs(8));
            thread::sleep(Duration::from_millis(5));
        }
        producer.kill().unwrap();
        producer.wait().unwrap();
        confirmer.kill().unwrap();
        confirmer.wait().unwrap();
        let journal = root.join("producer/receipts.jsonl");
        let prefix = fs::read(&journal).unwrap();
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open(&journal)
            .unwrap()
            .write_all(b"{\"uncommitted\":")
            .unwrap();
        // The database remains untouched. Corrupt only a copied packet artifact;
        // resume must preserve these exact failed bytes and recover from Node.
        let packet = fs::read_dir(root.join("producer/packets"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|s| s == "pnk1"))
            .unwrap();
        fs::write(&packet, b"interrupted artifact write").unwrap();
        producer = child(&binary, &paths[1], &root.join("producer-resume.log"), true);
        confirmer = child(&binary, &paths[2], &root.join("confirmer-resume.log"), true);
        assert!(fs::read(&journal).unwrap().starts_with(&prefix));
    }
    let producer_ok = finish(producer, 16);
    let confirmer_ok = finish(confirmer, 20);
    let validator_ok = finish(validator, 25);
    assert!(producer_ok, "producer failure logs retained");
    assert!(confirmer_ok, "confirmer failure logs retained");
    assert!(validator_ok, "validator failure logs retained");
    let p = check_receipts(&root.join("producer"), "producer-complete");
    let v = check_receipts(&root.join("validator"), "validator-complete");
    let c = check_receipts(&root.join("confirmer"), "confirmer-complete");
    assert_eq!(c["confirmed_transfers"], 8);
    assert_eq!(c["independent_store_full_verification"], true);
    for key in [
        "tip",
        "height",
        "state_root",
        "chainwork_hex",
        "network",
        "parameters",
        "genesis",
    ] {
        assert_eq!(p["state"][key], v["state"][key]);
        assert_eq!(p["state"][key], c["state"][key]);
    }
    if restart {
        for role in ["producer", "confirmer"] {
            let raw = fs::read_to_string(root.join(role).join("receipts.jsonl")).unwrap();
            let rows: Vec<Value> = raw
                .lines()
                .map(|s| serde_json::from_str(s).unwrap())
                .collect();
            assert_eq!(
                rows.iter()
                    .filter(|r| r["body"]["event"] == "role-resumed")
                    .count(),
                1
            );
            assert_eq!(
                rows.iter()
                    .filter(|r| r["body"]["event"] == format!("{role}-start"))
                    .count(),
                1
            );
        }
        assert!(fs::read_dir(root.join("producer")).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("receipt-uncommitted-tail-")));
        assert!(fs::read_dir(root.join("producer")).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("damaged-packet-")));
    }
    for role in ["producer", "validator", "confirmer"] {
        assert_eq!(
            fs::read_dir(root.join(role).join("packets"))
                .unwrap()
                .count(),
            8
        );
    }
}

#[test]
#[ignore = "requires explicit built example and retained output directory; local-process scope"]
fn three_separate_processes_fully_verify_and_confirm_with_signed_receipts() {
    campaign(false);
}
#[test]
#[ignore = "requires explicit built example; retained restart and partial-write conformance"]
fn killed_producer_and_confirmer_resume_exact_owners_without_rewinding_receipts() {
    campaign(true);
}
