//! Actual first-Startup failure, birth-to-death empty-container observation,
//! separately signed finite closure, interrupted publication and ordinary restart.
//! Fixture authority is disclosed. No arbitrary process or partial Native is reset.
use super::super::startup_no_native_v1::{Authorization, ClosedProcess, Pins};
use super::*;
use std::cell::Cell;
use std::process::{Command, Stdio};

const SOURCE_ENV: &str = "TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT";
fn compiled_source() -> &'static str {
    let Some(source) = option_env!("TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT") else {
        panic!("exact-source History runner must pin the actual compile source");
    };
    policy::id(source, 20).unwrap();
    assert_eq!(std::env::var(SOURCE_ENV).unwrap(), source);
    source
}
fn fixture_sha() -> String {
    policy::digest(include_bytes!("startup_no_native.rs"))
}
fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub(super) fn child(store: &Path, control: &Path, launch: &Path, sha: &str) -> ! {
    let raw = read(launch);
    let identity: Identity = serde_json::from_value(raw["identity"].clone()).unwrap();
    assert_eq!(identity.source_commit, compiled_source());
    let signed: Vec<u8> = serde_json::from_value(raw["signed_startup"].clone()).unwrap();
    let before_node = Cell::new(0);
    let state_reads = Cell::new(0);
    let result = HistoryEffectV6::open_with_startup_progress(
        store,
        ProtectedHistoryV6Input::load(launch, uid(), sha).unwrap(),
        2,
        deadline(),
        None,
        &|point| {
            if point == StartupProgress::BeforeNode {
                before_node.set(before_node.get() + 1);
            }
            if matches!(
                point,
                StartupProgress::FirstState | StartupProgress::SecondState
            ) {
                state_reads.set(state_reads.get() + 1);
            }
            Ok(())
        },
    );
    let error = match result {
        Ok(_) => panic!("wrong initial frontier became Native"),
        Err(e) => e,
    };
    assert_eq!(error.to_string(), "HISTORY_V6_INITIAL_FRONTIER");
    assert_eq!(before_node.get(), 1);
    assert_eq!(state_reads.get(), 0);
    let path = PathBuf::from(raw["journal_path"].as_str().unwrap());
    let mut records: Vec<_> = fs::read_dir(&path)
        .unwrap()
        .map(|r| r.unwrap().path())
        .filter(|p| p.file_name().unwrap() != "owner.lock")
        .collect();
    records.sort();
    assert_eq!(records.len(), 3);
    let intent: journal::Frame = serde_json::from_slice(&fs::read(&records[1]).unwrap()).unwrap();
    let journal::Event::Intent { signed: recorded } = intent.event else {
        panic!("missing real Intent")
    };
    assert_eq!(recorded, signed);
    let operation = policy::operation(&signed, &identity, intent.at_ns).unwrap();
    let settled_raw = fs::read(&records[2]).unwrap();
    let settled: journal::Frame = serde_json::from_slice(&settled_raw).unwrap();
    let head = Anchor {
        sequence: settled.sequence,
        digest: policy::digest(&settled_raw),
    };
    let journal::Event::Settlement {
        operation: id,
        marker,
        native_id,
        native_error,
        effect_readback_known,
        cpu,
    } = settled.event
    else {
        panic!("missing actual CPU settlement")
    };
    assert_eq!(id, operation.body.operation_id);
    assert!(marker.is_none() && native_id.is_none() && effect_readback_known);
    assert_eq!(native_error.as_deref(), Some("HISTORY_V6_INITIAL_FRONTIER"));
    assert!(cpu.known() && !cpu.live_refused && cpu.total_cpu_ns.unwrap() > 0);
    assert_eq!(cpu.scoped_worker_cpu_ns, Some(0));
    assert_eq!(
        cpu.spawned_workers + cpu.started_workers + cpu.finished_workers + cpu.known_workers,
        0
    );
    let journal = journal::Journal::open_existing(&path, uid(), &identity, &head).unwrap();
    let observed = journal.observation();
    assert_eq!(observed["used_operations"], 1);
    assert_eq!(observed["known_settlements"], 1);
    assert_eq!(observed["spent"]["cpu_ns"], 4_000_000_000u64);
    assert!(observed["pending"].is_null() && !observed["epoch"].is_null());
    assert_eq!(fs::read_dir(store).unwrap().count(), 0);
    write_value(
        &control.join("crash-ready.json"),
        &json!({
            "schema":"actual-history-first-startup-known-failure-barrier-v1",
            "pid":std::process::id(),"actual_compiled_source":compiled_source(),"fixture_sha256":fixture_sha(),
            "anchor":head,"intent_sha256":operation.intent_sha256,"original_cpu":cpu,
            "journal":observed,"before_node_calls":before_node.get(),"state_reads":state_reads.get(),
            "not_started_fabricated":false,"clean_close_created":false,
        }),
    );
    // Retain the journal lock until the independent guardian actually reaps us.
    loop {
        std::hint::black_box(&journal);
        std::thread::park_timeout(Duration::from_secs(5));
    }
}

struct Observed {
    // Fields drop in declaration order. Retain the real fixture before the
    // authority's TempDir removes its source, including on assertion failure.
    _retain: process::Retain,
    authority: TestAuthority,
    closed_raw: Vec<u8>,
    closed: ClosedProcess,
    pins: Pins,
    original_records: BTreeMap<String, String>,
}
fn records(path: &Path) -> BTreeMap<String, String> {
    fs::read_dir(path)
        .unwrap()
        .map(|r| r.unwrap())
        .filter(|r| r.file_name() != "owner.lock")
        .map(|r| {
            (
                r.file_name().into_string().unwrap(),
                process::sha_file(&r.path()),
            )
        })
        .collect()
}
fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/ci")
        .join(name)
}
fn observe(label: &str, lifetime: u64) -> Observed {
    let mut a = TestAuthority::with_source_and_budget_lifetime(compiled_source(), lifetime);
    let retain = process::retain_fixture(a.f.dir.path(), label);
    let parent = a.f.dir.path().join("first-startup-container");
    a.store = parent.join("native");
    let control = a.f.dir.path().join("first-startup-guardian");
    fs::create_dir(&control).unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
    let binary = std::env::current_exe().unwrap();
    let guardian = script("history_startup_no_native_process_guard.py");
    let mut pins = Pins {
        source_commit: compiled_source().into(),
        executable_sha256: process::sha_file(&binary),
        fixture_sha256: fixture_sha(),
        guardian_sha256: policy::digest(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../scripts/ci/history_startup_no_native_process_guard.py"
        ))),
        observer_sha256: policy::digest(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../scripts/ci/history_effect_v6_process_guard.py"
        ))),
        process_guard_sha256: policy::digest(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../scripts/ci/history_native_process_guard.py"
        ))),
        preparation_sha256: String::new(),
    };
    assert_eq!(process::sha_file(&guardian), pins.guardian_sha256);
    assert_eq!(
        process::sha_file(&script("history_effect_v6_process_guard.py")),
        pins.observer_sha256
    );
    assert_eq!(
        process::sha_file(&script("history_native_process_guard.py")),
        pins.process_guard_sha256
    );
    let mut source_pins = serde_json::to_value(&pins).unwrap();
    source_pins
        .as_object_mut()
        .unwrap()
        .remove("preparation_sha256");
    let prep = a.f.dir.path().join("namespace-preparation.json");
    let prep_sha = write_value(
        &prep,
        &json!({
            "schema":"actual-history-startup-no-native-preparation-v1","source_pins":source_pins,
            "namespace_parent":parent,"journal_path":a.journal,"expected_uid":uid(),
            "identity":a.identity,"identity_sha256":a.identity.digest().unwrap(),
        }),
    );
    pins.preparation_sha256 = prep_sha.clone();
    let log = File::create(control.join("guardian.stdout.log")).unwrap();
    let mut guard = process::Process {
        child: Command::new("python3")
            .arg(&guardian)
            .arg("--binary")
            .arg(&binary)
            .args([
                "--binary-sha256",
                &pins.executable_sha256,
                "--configuration",
            ])
            .arg(&prep)
            .args(["--configuration-sha256", &prep_sha, "--directory"])
            .arg(&control)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
        guardian: true,
    };
    let ready = process::wait(&control.join("namespace-ready.json"), &mut guard);
    let mut wrong = a.genesis();
    wrong.generation = 1;
    // This signature is created only after the guardian durably creates, locks
    // and observes the complete empty namespace. No old path is adopted.
    let (launch, launch_sha) = a.launch("known-failed-first", 1, 1, wrong, a.installed.clone());
    let config = a.f.dir.path().join("first-startup-child.json");
    let config_sha = write_value(
        &config,
        &json!({
            "schema":"actual-history-effect-child-fixture-v6","mode":"startup-no-native",
            "store":a.store,"control":control,"page":[],"launch":launch,"launch_sha256":launch_sha,
            "recovery":null,"recovery_sha256":null,"publication":null,"publication_sha256":null,
        }),
    );
    write_value(
        &control.join("outside-child.json"),
        &json!({"path":config,"sha256":config_sha}),
    );
    let result = process::wait(&control.join("guardian-result.json"), &mut guard);
    assert!(guard.child.wait().unwrap().success(), "{result}");
    assert_eq!(result["passed"], true);
    assert_eq!(result["actual_wait4"], true);
    assert_eq!(result["exact_empty_namespace_unchanged"], true);
    let closed_raw = fs::read(control.join("closed-process.json")).unwrap();
    let closed: ClosedProcess = serde_json::from_slice(&closed_raw).unwrap();
    assert_eq!(closed.pins, pins);
    assert_eq!(closed.before, closed.after);
    assert_eq!(json!(closed.before), ready["before"]);
    assert_eq!(
        closed.namespace_prepared_ns,
        ready["namespace_prepared_ns"].as_u64().unwrap()
    );
    assert_eq!(process::sha_file(&binary), pins.executable_sha256);
    let original_records = records(&a.journal);
    Observed {
        _retain: retain,
        authority: a,
        closed_raw,
        closed,
        pins,
        original_records,
    }
}

fn envelope(body: &Authorization) -> Vec<u8> {
    let registry = signing_key_from_hex(&"11".repeat(32)).unwrap();
    let task = signing_key_from_hex(&"22".repeat(32)).unwrap();
    policy::encoded(&policy::Envelope {
        body,
        registry_signature: sign_hex(
            &registry,
            &super::super::startup_no_native_v1::message(1, body).unwrap(),
        ),
        task_signature: sign_hex(
            &task,
            &super::super::startup_no_native_v1::message(2, body).unwrap(),
        ),
    })
    .unwrap()
}
fn body(observed: &Observed) -> Authorization {
    let a = &observed.authority;
    let now = policy::now().unwrap();
    Authorization {
        schema: "restricted-history-startup-no-native-closure-authorization-v1".into(),
        identity: a.identity.clone(),
        budget_id: policy::digest(b"v6-test-budget"),
        reconciliation_id: a.id(10),
        request_nonce: 10,
        outside_anchor: observed.closed.original_journal.clone(),
        startup_operation_id: a.id(1),
        startup_intent_sha256: observed.closed.intent_sha256.clone(),
        signed_startup_sha256: policy::digest(&observed.closed.signed_startup),
        closed_process_sha256: policy::digest(&observed.closed_raw),
        namespace_parent: observed.closed.namespace_parent.clone(),
        allowance: Usage {
            cpu_ns: 4_000_000_000,
            material_bytes: 0,
            received_bytes: 0,
            operations: 1,
        },
        issued_ns: now,
        expires_ns: now + 3_000_000_000_000,
    }
}
fn configuration(observed: &Observed, body: &Authorization, signed: &[u8], closed: &[u8]) -> Value {
    let a = &observed.authority;
    json!({"schema":"restricted-history-startup-no-native-closure-input-v1", "identity":a.identity,
        "journal_path":a.journal,"outside_latest_anchor":body.outside_anchor,"expected_pins":observed.pins,
        "namespace_parent":observed.closed.namespace_parent,"signed":signed,"closed_process":closed})
}
fn input(a: &TestAuthority, label: &str, config: &Value) -> (PathBuf, String) {
    let path = a.f.dir.path().join(format!("no-native-{label}.json"));
    let sha = write_value(&path, config);
    (path, sha)
}
fn load(path: &Path, sha: &str) -> Result<ProtectedHistoryStartupNoNativeV1Input> {
    ProtectedHistoryStartupNoNativeV1Input::load(path, uid(), sha)
}
fn close(path: &Path, sha: &str) -> Result<Value> {
    close_history_startup_no_native_v1(load(path, sha)?)
}
fn refused(observed: &Observed, label: &str, config: &Value) -> String {
    let (path, sha) = input(&observed.authority, label, config);
    let error = close(&path, &sha).unwrap_err().to_string();
    assert_eq!(
        records(&observed.authority.journal),
        observed.original_records,
        "{label}"
    );
    assert_eq!(fs::read_dir(&observed.authority.store).unwrap().count(), 0);
    error
}

fn negatives(observed: &Observed) -> BTreeMap<String, String> {
    let original = body(observed);
    let mut refusals = BTreeMap::new();
    for label in [
        "old-domain",
        "nonce-reuse",
        "used-id",
        "wrong-anchor",
        "wrong-intent",
        "wrong-envelope",
        "expired-new-authorization",
        "lifetime-overdraft",
        "insufficient-process-allowance",
    ] {
        let mut body = original.clone();
        match label {
            "old-domain" => {}
            "nonce-reuse" => body.request_nonce = 1,
            "used-id" => body.reconciliation_id = observed.authority.id(1),
            "wrong-anchor" => body.outside_anchor.digest = "ab".repeat(32),
            "wrong-intent" => body.startup_intent_sha256 = "ab".repeat(32),
            "wrong-envelope" => body.signed_startup_sha256 = "ab".repeat(32),
            "expired-new-authorization" => {
                body.issued_ns = 0;
                body.expires_ns = 1;
            }
            "lifetime-overdraft" => body.allowance.cpu_ns = 128_000_000_000,
            "insufficient-process-allowance" => {
                body.allowance.cpu_ns = observed.closed.reported_cpu_upper_bound_ns - 1
            }
            _ => unreachable!(),
        }
        let signed = if label == "old-domain" {
            signed(b'O', &body)
        } else {
            envelope(&body)
        };
        refusals.insert(
            label.into(),
            refused(
                observed,
                label,
                &configuration(observed, &body, &signed, &observed.closed_raw),
            ),
        );
    }
    for label in [
        "no-wait4",
        "wrong-signal",
        "wrong-source",
        "wrong-binary",
        "wrong-preparation",
        "wrong-journal",
        "prepared-after-signature",
        "changed-empty-container",
        "cpu-below-original",
        "descendant-claim",
    ] {
        let mut closed = observed.closed.clone();
        match label {
            "no-wait4" => closed.actual_wait4 = false,
            "wrong-signal" => closed.signal = 15,
            "wrong-source" => closed.pins.source_commit = "ab".repeat(20),
            "wrong-binary" => closed.pins.executable_sha256 = "ab".repeat(32),
            "wrong-preparation" => closed.pins.preparation_sha256 = "ab".repeat(32),
            "wrong-journal" => {
                closed.journal_path = closed.journal_path.with_extension("unrelated")
            }
            "prepared-after-signature" => {
                closed.namespace_prepared_ns = closed.process_spawn_before_ns + 1
            }
            "changed-empty-container" => closed.after.native.changed_nanoseconds ^= 1,
            "cpu-below-original" => {
                closed.user_cpu_microseconds = 0;
                closed.system_cpu_microseconds = 0;
                closed.reported_user_seconds = "0".into();
                closed.reported_system_seconds = "0".into();
                closed.reported_cpu_upper_bound_ns = 2000;
            }
            "descendant-claim" => closed.descendants.push(123),
            _ => unreachable!(),
        }
        let raw = policy::encoded(&closed).unwrap();
        let mut body = original.clone();
        body.closed_process_sha256 = policy::digest(&raw);
        refusals.insert(
            label.into(),
            refused(
                observed,
                label,
                &configuration(observed, &body, &envelope(&body), &raw),
            ),
        );
    }
    for field in [
        "source_commit",
        "executable_sha256",
        "fixture_sha256",
        "guardian_sha256",
        "observer_sha256",
        "process_guard_sha256",
        "preparation_sha256",
    ] {
        let mut config = configuration(
            observed,
            &original,
            &envelope(&original),
            &observed.closed_raw,
        );
        config["expected_pins"][field] =
            json!("ac".repeat(if field == "source_commit" { 20 } else { 32 }));
        let label = format!("independent-{field}");
        refusals.insert(label.clone(), refused(observed, &label, &config));
    }
    for label in ["lease-preparation-binding", "lease-journal-path-binding"] {
        let mut closed = observed.closed.clone();
        let mut expected = observed.pins.clone();
        let journal_path = if label == "lease-journal-path-binding" {
            let copy = observed
                .authority
                .f
                .dir
                .path()
                .join("separate-journal-copy");
            fs::create_dir(&copy).unwrap();
            fs::set_permissions(&copy, fs::Permissions::from_mode(0o700)).unwrap();
            for row in fs::read_dir(&observed.authority.journal).unwrap() {
                let row = row.unwrap();
                fs::copy(row.path(), copy.join(row.file_name())).unwrap();
            }
            closed.journal_path = copy.clone();
            copy
        } else {
            closed.pins.preparation_sha256 = "ad".repeat(32);
            expected.preparation_sha256 = closed.pins.preparation_sha256.clone();
            observed.authority.journal.clone()
        };
        let raw = policy::encoded(&closed).unwrap();
        let mut bound = original.clone();
        bound.closed_process_sha256 = policy::digest(&raw);
        let mut config = configuration(observed, &bound, &envelope(&bound), &raw);
        config["expected_pins"] = json!(expected);
        config["journal_path"] = json!(journal_path);
        let error = refused(observed, label, &config);
        assert!(error.contains("LEASE_BINDING"), "{label}: {error}");
        refusals.insert(label.into(), error);
    }
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .open(
            observed
                .closed
                .namespace_parent
                .join("startup-namespace.lock"),
        )
        .unwrap();
    lease.try_lock_exclusive().unwrap();
    let config = configuration(
        observed,
        &original,
        &envelope(&original),
        &observed.closed_raw,
    );
    refusals.insert(
        "lease-still-owned".into(),
        refused(observed, "lease-still-owned", &config),
    );
    drop(lease);
    refusals
}

fn publication_crash(a: &TestAuthority, input: &Path, input_sha: &str) -> Value {
    let mode = "startup-no-native-publish-file-synced";
    let control = a.f.dir.path().join(mode);
    fs::create_dir(&control).unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
    let cfg = a.f.dir.path().join(format!("{mode}.json"));
    let cfg_sha = write_value(
        &cfg,
        &json!({
            "schema":"actual-history-effect-child-fixture-v6","mode":mode,"store":a.store,
            "control":control,"page":[],"launch":null,"launch_sha256":null,
            "recovery":input,"recovery_sha256":input_sha,"publication":null,"publication_sha256":null,
        }),
    );
    let binary = std::env::current_exe().unwrap();
    let binary_sha = process::sha_file(&binary);
    let guardian = script("history_effect_v6_process_guard.py");
    let log = File::create(control.join("guardian.stdout.log")).unwrap();
    let mut process = process::Process {
        child: Command::new("python3")
            .arg(&guardian)
            .arg("--binary")
            .arg(&binary)
            .args(["--binary-sha256", &binary_sha, "--configuration"])
            .arg(&cfg)
            .args(["--configuration-sha256", &cfg_sha, "--directory"])
            .arg(&control)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
        guardian: true,
    };
    let observed = process::wait(&control.join("guardian-result.json"), &mut process);
    assert!(process.child.wait().unwrap().success(), "{observed}");
    assert_eq!(observed["passed"], true);
    assert_eq!(observed["actual_wait4"], true);
    assert_eq!(observed["native_operation_started"], false);
    assert_eq!(observed["v6_closed_process_receipt_created"], false);
    assert!(!control.join("closed-process.json").exists());
    assert_eq!(process::sha_file(&binary), binary_sha);
    read(&control.join("crash-ready.json"))
}
fn wait_until_expired(expires: u64, bound: u64) {
    let end = Instant::now() + Duration::from_secs(bound);
    while policy::now().unwrap() < expires {
        assert!(
            Instant::now() < end,
            "original signed clock window did not expire"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}
fn interrupted_close(observed: &Observed) -> (Value, PathBuf, String) {
    let a = &observed.authority;
    let old_budget: policy::Envelope<policy::Budget> = serde_json::from_slice(&a.budget).unwrap();
    // Real wall-clock expiration, not a changed signed budget or invented clock.
    wait_until_expired(old_budget.body.expires_ns, 40);
    let mut body = body(observed);
    body.expires_ns = body.issued_ns + 10_000_000_000;
    assert!(body.issued_ns >= old_budget.body.expires_ns);
    let cfg = configuration(observed, &body, &envelope(&body), &observed.closed_raw);
    let (path, sha) = input(a, "actual-expiring-closure", &cfg);
    let barrier = publication_crash(a, &path, &sha);
    let candidate: Anchor = serde_json::from_value(barrier["anchor"].clone()).unwrap();
    assert_eq!(
        barrier["acknowledged_prefix_anchor"],
        json!(observed.closed.original_journal)
    );
    let pending = a
        .journal
        .join(format!("pending-{:020}", candidate.sequence));
    let final_path = a.journal.join(format!(
        "{:020}-{}.json",
        candidate.sequence, candidate.digest
    ));
    let frame_raw = fs::read(&pending).unwrap();
    assert!(!final_path.exists());
    assert_eq!(policy::digest(&frame_raw), candidate.digest);
    let frame: journal::Frame = serde_json::from_slice(&frame_raw).unwrap();
    assert_eq!(
        frame.schema,
        super::super::startup_no_native_v1::RECORD_SCHEMA
    );
    let journal::Event::StartupNoNativeClosedV1 {
        signed,
        closed_process,
    } = &frame.event
    else {
        panic!("new closure did not retain its fresh record namespace");
    };
    assert_eq!(signed, &envelope(&body));
    assert_eq!(closed_process, &observed.closed_raw);
    assert!(body.issued_ns <= frame.at_ns && frame.at_ns < body.expires_ns);
    wait_until_expired(body.expires_ns, 15);
    let now = policy::now().unwrap();
    let authorization = journal::publication::Authorization {
        schema: "restricted-history-journal-publication-authorization-v1".into(),
        identity: a.identity.clone(),
        prefix_anchor: observed.closed.original_journal.clone(),
        published_anchor: candidate.clone(),
        frame_sha256: candidate.digest.clone(),
        frame_bytes: frame_raw.len() as u64,
        issued_ns: now,
        expires_ns: now + 3_000_000_000_000,
    };
    let (pub_path, pub_sha) = publication::input(
        a,
        "no-native-current",
        &authorization,
        &publication::envelope(&authorization),
        candidate.clone(),
    );
    let generic = publication::repair(&pub_path, &pub_sha)
        .unwrap_err()
        .to_string();
    assert!(generic.contains("NO_NATIVE_PINS_REQUIRED"), "{generic}");
    let mut refusals = BTreeMap::new();
    for label in [
        "expired-publication",
        "wrong-independent-binary",
        "different-signed-bytes",
        "different-closed-bytes",
    ] {
        let mut changed = cfg.clone();
        let mut pub_body = authorization.clone();
        match label {
            "expired-publication" => {
                pub_body.issued_ns = 0;
                pub_body.expires_ns = 1;
            }
            "wrong-independent-binary" => {
                changed["expected_pins"]["executable_sha256"] = json!("ab".repeat(32))
            }
            "different-signed-bytes" => {
                let mut altered = body.clone();
                altered.expires_ns += 1;
                changed["signed"] = json!(envelope(&altered));
            }
            "different-closed-bytes" => {
                let mut altered = observed.closed_raw.clone();
                altered.push(b' ');
                changed["closed_process"] = json!(altered);
            }
            _ => unreachable!(),
        }
        let (p, s) = input(a, &format!("repair-{label}"), &changed);
        let (pp, ps) = publication::input(
            a,
            &format!("no-native-{label}"),
            &pub_body,
            &publication::envelope(&pub_body),
            candidate.clone(),
        );
        let error = repair_history_startup_no_native_v1_publication(
            load(&p, &s).unwrap(),
            ProtectedHistoryJournalPublicationV1Input::load(&pp, uid(), &ps).unwrap(),
        )
        .unwrap_err()
        .to_string();
        refusals.insert(label, error);
        assert_eq!(fs::read(&pending).unwrap(), frame_raw);
        assert!(!final_path.exists());
    }
    let repair = || {
        repair_history_startup_no_native_v1_publication(
            load(&path, &sha).unwrap(),
            ProtectedHistoryJournalPublicationV1Input::load(&pub_path, uid(), &pub_sha).unwrap(),
        )
    };
    let repaired = repair().unwrap();
    let duplicate = repair().unwrap();
    assert_eq!(repaired["journal"], duplicate["journal"]);
    assert_eq!(duplicate["already_published"], true);
    assert_eq!(repaired["journal"]["spent"]["cpu_ns"], 8_000_000_000u64);
    assert_eq!(repaired["journal"]["used_operations"], 2);
    assert_eq!(repaired["journal"]["known_settlements"], 1);
    assert_eq!(repaired["journal"]["startup_no_native_closures_v1"], 1);
    assert!(repaired["journal"]["epoch"].is_null() && repaired["journal"]["pending"].is_null());
    assert_eq!(fs::read(&final_path).unwrap(), frame_raw);
    assert!(!pending.exists());
    assert_eq!(fs::read_dir(&a.store).unwrap().count(), 0);
    write_value(
        &a.f.dir
            .path()
            .join("no-native-interrupted-publication-result.json"),
        &json!({
            "barrier":barrier,"original_budget_expires_ns":old_budget.body.expires_ns,
            "new_closure_issued_ns":body.issued_ns,"new_closure_expires_ns":body.expires_ns,
            "original_frame_at_ns":frame.at_ns,"current_repair_issued_ns":authorization.issued_ns,
            "refusals":refusals,"generic_bypass_refused":generic,"repaired":repaired,"duplicate":duplicate,
            "original_signed_bytes_preserved":true,"original_dead_process_receipt_preserved":true,
            "administrative_wait4_used_as_original_receipt":false,"new_epoch_or_cpu_receipt_created":false,
        }),
    );
    (repaired, path, sha)
}

fn renew(a: &mut TestAuthority, anchor: Anchor) -> Anchor {
    let old: policy::Envelope<policy::Budget> = serde_json::from_slice(&a.budget).unwrap();
    assert!(policy::now().unwrap() >= old.body.expires_ns);
    let (launch, sha) = a.launch(
        "old-expired-remains-refused",
        11,
        2,
        a.genesis(),
        anchor.clone(),
    );
    let before = records(&a.journal);
    let error = HistoryEffectV6::open(
        &a.store,
        ProtectedHistoryV6Input::load(&launch, uid(), &sha).unwrap(),
        2,
        deadline(),
    )
    .err()
    .expect("closure revived expired old work authority")
    .to_string();
    assert!(
        error.contains("BUDGET_EXPIRED") || error.contains("WINDOW"),
        "{error}"
    );
    assert_eq!(records(&a.journal), before);
    assert_eq!(fs::read_dir(&a.store).unwrap().count(), 0);
    let mut budget = old.body;
    budget.sequence += 1;
    budget.outside_anchor = anchor.clone();
    budget.issued_ns = policy::now().unwrap();
    budget.expires_ns = budget.issued_ns + 3_600_000_000_000;
    let envelope = signed(b'B', &budget);
    let path =
        a.f.dir
            .path()
            .join("renew-after-first-startup-closure.json");
    let digest = write_value(
        &path,
        &json!({"schema":"restricted-history-effect-budget-input-v6",
        "identity":a.identity,"journal_path":a.journal,"outside_latest_anchor":anchor,"signed_budget":envelope}),
    );
    let result = prepare_history_effect_v6_budget(
        ProtectedHistoryV6BudgetInput::load(&path, uid(), &digest).unwrap(),
    )
    .unwrap();
    assert_eq!(result["spent"]["cpu_ns"], 8_000_000_000u64);
    a.budget = envelope;
    write_value(
        &a.f.dir.path().join("separate-budget-renewal-result.json"),
        &json!({
            "expired_old_work_refusal":error,"prior_journal_unchanged":true,"renewal":result,
            "lifetime_ceiling_increased":false,"existing_predebits_refunded":false,
        }),
    );
    serde_json::from_value(result["anchor"].clone()).unwrap()
}
fn ordinary_restart(observed: &mut Observed, closed: &Value) -> Value {
    let a = &mut observed.authority;
    let after = renew(
        a,
        serde_json::from_value(closed["journal"]["anchor"].clone()).unwrap(),
    );
    let control = a.f.dir.path().join("ordinary-next-epoch");
    fs::create_dir(&control).unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
    let cfg = a.f.dir.path().join("ordinary-next-process.json");
    let cfg_sha = write_value(
        &cfg,
        &json!({"schema":"actual-history-effect-child-fixture-v6",
        "mode":"resume-published-startup-no-native","store":a.store,"control":control,"page":process::page(a, &a.f.packet),
        "launch":null,"launch_sha256":null,"recovery":null,"recovery_sha256":null,
        "publication":null,"publication_sha256":null}),
    );
    let binary = std::env::current_exe().unwrap();
    let log = File::create(control.join("ordinary-native-process.log")).unwrap();
    let mut process = process::Process {
        child: Command::new(&binary)
            .args([
                super::super::startup_no_native_v1::SELECTOR,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TRNM_HISTORY_V6_CHILD_CONFIG", &cfg)
            .env("TRNM_HISTORY_V6_CHILD_CONFIG_SHA256", cfg_sha)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
        guardian: false,
    };
    let (launch, sha) = a.launch("ordinary-next", 11, 2, a.genesis(), after);
    write_value(
        &control.join("outside-launch.json"),
        &json!({"path":launch,"sha256":sha}),
    );
    let started = process::wait(&control.join("startup-ready.json"), &mut process);
    assert_eq!(started["initial_cpu"]["stored_credit_ns"], 0);
    let validation = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: 12,
        epoch: 2,
        frontier: a.genesis(),
        anchor: serde_json::from_value(started["journal"]["anchor"].clone()).unwrap(),
        packet: Some(&a.f.packet),
        pair: Some((12, 13)),
    });
    write(&control.join("outside-validation.json"), &validation);
    let validated = process::wait(&control.join("validation-ready.json"), &mut process);
    let activation = a.grant(Grant {
        purpose: Purpose::Activation,
        nonce: 13,
        epoch: 2,
        frontier: a.genesis(),
        anchor: serde_json::from_value(validated["observation"]["journal"]["anchor"].clone())
            .unwrap(),
        packet: Some(&a.f.packet),
        pair: Some((12, 13)),
    });
    write(&control.join("outside-activation.json"), &activation);
    let activated = process::wait(&control.join("activation-ready.json"), &mut process);
    let close = a.grant(Grant {
        purpose: Purpose::Close,
        nonce: 14,
        epoch: 2,
        frontier: serde_json::from_value(activated["frontier"].clone()).unwrap(),
        anchor: serde_json::from_value(activated["observation"]["journal"]["anchor"].clone())
            .unwrap(),
        packet: None,
        pair: None,
    });
    write(&control.join("outside-close.json"), &close);
    let finished = process::wait(&control.join("finished.json"), &mut process);
    assert!(process.child.wait().unwrap().success());
    assert_ne!(finished["pid"], json!(observed.closed.owned_namespace_pid));
    assert_eq!(finished["cold_journal"]["used_operations"], 6);
    assert_eq!(finished["cold_journal"]["known_settlements"], 5);
    assert_eq!(
        finished["cold_journal"]["spent"]["cpu_ns"],
        24_000_000_000u64
    );
    assert_eq!(finished["cold_journal"]["startup_no_native_closures_v1"], 1);
    assert!(
        finished["cold_journal"]["epoch"].is_null()
            && finished["cold_journal"]["pending"].is_null()
    );
    assert_eq!(finished["marker_count"], 2);
    assert_eq!(finished["frontier"]["generation"], 1);
    assert_eq!(
        finished["frontier"]["block"],
        hex::encode(a.f.packet.id().unwrap())
    );
    assert_eq!(process::sha_file(&binary), observed.pins.executable_sha256);
    let final_records = records(&a.journal);
    for (path, sha) in &observed.original_records {
        assert_eq!(final_records.get(path), Some(sha));
    }
    finished
}

#[test]
fn first_failed_startup_empty_namespace_closes_after_real_death_and_publication_crash_then_runs() {
    let mut observed = observe("first-startup-no-native-positive", 30_000_000_000);
    let refusals = negatives(&observed);
    let (closed, original_path, original_sha) = interrupted_close(&observed);
    let finished = ordinary_restart(&mut observed, &closed);
    // Refresh only the new closure signature and preserve the old original
    // Startup/death evidence: replay still cannot select a later epoch.
    let fresh_body = body(&observed);
    let (replay, replay_sha) = input(
        &observed.authority,
        "fresh-signature-replay",
        &configuration(
            &observed,
            &fresh_body,
            &envelope(&fresh_body),
            &observed.closed_raw,
        ),
    );
    let before_replay = records(&observed.authority.journal);
    let error = close(&replay, &replay_sha).unwrap_err().to_string();
    assert!(
        error.contains("ROLLBACK") || error.contains("KNOWN_STARTUP"),
        "{error}"
    );
    assert_eq!(records(&observed.authority.journal), before_replay);
    let old_error = close(&original_path, &original_sha)
        .unwrap_err()
        .to_string();
    assert!(old_error.contains("AUTHORIZATION"));
    write_value(
        &observed
            .authority
            .f
            .dir
            .path()
            .join("first-startup-no-native-result.json"),
        &json!({
            "schema":"actual-history-first-startup-empty-container-closure-result-v1",
            "source_commit":compiled_source(),"pins":observed.pins,"refusals":refusals,
            "publication":closed,"ordinary_next_process":finished,"fresh_signature_replay_error":error,
            "expired_original_closure_error":old_error,"original_records":observed.original_records,
            "whole_history_p0_closed":false,"partial_initialization_qualified":false,
            "general_process_tree_qualified":false,"original_predebit_and_cpu_preserved":true,
        }),
    );
    // A separately observed real failed Startup becomes ineligible if any new
    // Native entry appears. Keep that entry and its changed namespace metadata;
    // never remove it to reuse the positive witness.
    let changed = observe(
        "first-startup-no-native-physical-negative",
        3_600_000_000_000,
    );
    let unexpected = changed.authority.store.join("unexpected-state");
    write(&unexpected, b"preserved incompatible Native bytes");
    let auth = body(&changed);
    let (path, sha) = input(
        &changed.authority,
        "physical-state-refusal",
        &configuration(&changed, &auth, &envelope(&auth), &changed.closed_raw),
    );
    let error = close(&path, &sha).unwrap_err().to_string();
    assert!(
        error.contains("NAMESPACE_CHANGED") || error.contains("NAMESPACE_NOT_EMPTY"),
        "{error}"
    );
    assert_eq!(
        records(&changed.authority.journal),
        changed.original_records
    );
    assert_eq!(
        fs::read(&unexpected).unwrap(),
        b"preserved incompatible Native bytes"
    );
    write_value(
        &changed
            .authority
            .f
            .dir
            .path()
            .join("incompatible-native-preserved.json"),
        &json!({
            "error":error,"journal_unchanged":true,"incompatible_bytes_preserved":true,
            "native_reset":false,"closure_fabricated":false,
        }),
    );
}
