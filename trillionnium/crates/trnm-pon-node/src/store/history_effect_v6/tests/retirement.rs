//! Real known-settlement death, external retirement, cold Startup and next
//! validation/activation. No synthetic settlement or closed-process success.
use super::*;
use known_epoch::{Authorization, ClosedProcess, KnownEpoch};
use process::{child_wait, sha_file, snapshot, wait, Process, Retain};
use std::cell::RefCell;
use std::process::{Command, Stdio};

thread_local! {
    static HOOK: RefCell<Option<(String, PathBuf)>> = const { RefCell::new(None) };
}
fn compiled_source_commit() -> &'static str {
    let compiled = match option_env!("TRNM_HISTORY_KNOWN_EPOCH_SOURCE_COMMIT") {
        Some(value) => value,
        None => panic!("known-epoch fixture requires an explicit frozen compile commit"),
    };
    policy::id(compiled, 20).unwrap();
    let supplied = std::env::var("TRNM_HISTORY_KNOWN_EPOCH_SOURCE_COMMIT")
        .expect("known-epoch fixture requires its explicit runtime source pin");
    assert_eq!(
        supplied, compiled,
        "known-epoch runtime source differs from compiled source"
    );
    compiled
}
fn actual_source_refusals(a: &TestAuthority, binary: &Path) -> Value {
    let before = snapshot(&a.journal);
    let mut rows = BTreeMap::new();
    for (label, supplied, expected) in [
        ("missing", None, "requires its explicit runtime source pin"),
        (
            "different",
            Some("0000000000000000000000000000000000000000"),
            "runtime source differs from compiled source",
        ),
    ] {
        let mut command = Command::new(binary);
        command
            .args([
                known_epoch::FIXTURE_SELECTOR,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_remove("TRNM_HISTORY_KNOWN_EPOCH_CHILD_CONFIG")
            .env_remove("TRNM_HISTORY_KNOWN_EPOCH_CHILD_CONFIG_SHA256")
            .stdin(Stdio::null());
        if let Some(supplied) = supplied {
            command.env("TRNM_HISTORY_KNOWN_EPOCH_SOURCE_COMMIT", supplied);
        } else {
            command.env_remove("TRNM_HISTORY_KNOWN_EPOCH_SOURCE_COMMIT");
        }
        let result = command.output().unwrap();
        assert!(!result.status.success());
        let mut raw = result.stdout;
        raw.extend(result.stderr);
        assert!(String::from_utf8_lossy(&raw).contains(expected));
        let path = a.f.dir.path().join(format!("source-refusal-{label}.log"));
        let sha = write(&path, &raw);
        assert_eq!(snapshot(&a.journal), before);
        rows.insert(
            label,
            json!({"actual_child_exit":result.status.code(),"log_sha256":sha,
            "journal_unchanged":true,"native_operation_started":false}),
        );
    }
    json!(rows)
}
fn sources() -> (String, String) {
    (
        policy::digest(include_bytes!("retirement.rs")),
        policy::digest(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../scripts/ci/history_known_epoch_process_guard.py"
        ))),
    )
}
fn park() -> ! {
    loop {
        std::thread::park_timeout(Duration::from_secs(5));
    }
}
pub(in crate::store::history_effect_v6) fn settlement_cut(
    journal: &journal::Journal,
    purpose: Option<Purpose>,
) {
    let Some((mode, control)) = HOOK.with(|slot| slot.borrow().clone()) else {
        return;
    };
    let selected = matches!(
        (mode.as_str(), purpose),
        ("known-validation", Some(Purpose::Validation))
            | ("known-activation", Some(Purpose::Activation))
            | ("known-close", Some(Purpose::Close))
    );
    if !selected {
        return;
    }
    assert!(journal.pending().is_none());
    let epoch = journal.known_epoch().unwrap();
    assert!(epoch.known_operations >= 2 && epoch.known_cpu_ns > 0);
    let (fixture, guardian) = sources();
    write_value(
        &control.join("crash-ready.json"),
        &json!({"schema":"actual-history-known-epoch-crash-barrier-v1",
        "pid":std::process::id(),"cutpoint":mode,"anchor":journal.anchor(),
        "known_epoch":epoch,"known_epoch_raw":policy::encoded(epoch).unwrap(),
        "known_epoch_sha256":epoch.digest().unwrap(),"journal":journal.observation(),
        "fixture_source_sha256":fixture,"guardian_source_sha256":guardian,
        "source_commit":compiled_source_commit(),
        "clean_close_created":false,"original_cpu_already_settled":true}),
    );
    park()
}
pub(in crate::store::history_effect_v6) fn publication_cut(
    journal: &journal::Journal,
    frame: &journal::Frame,
    raw: &[u8],
    stage: &str,
) {
    let Some((mode, control)) = HOOK.with(|slot| slot.borrow().clone()) else {
        return;
    };
    if mode != format!("retirement-publication-{stage}")
        || !matches!(frame.event, journal::Event::KnownEpochRetiredV1 { .. })
    {
        return;
    }
    assert_eq!(frame.schema, known_epoch::RECORD_SCHEMA);
    let (fixture, guardian) = sources();
    write_value(
        &control.join("crash-ready.json"),
        &json!({"schema":"actual-history-known-epoch-publication-barrier-v1",
        "pid":std::process::id(),"cutpoint":mode,"prefix_anchor":journal.anchor(),
        "published_anchor":Anchor{sequence:frame.sequence,digest:policy::digest(raw)},
        "frame_bytes":raw.len(),"fixture_source_sha256":fixture,"guardian_source_sha256":guardian,
        "source_commit":compiled_source_commit(),
        "native_operation_started":false,"new_cpu_epoch_created":false,
        "clean_close_created":false,"per_scope_receipt_created":false}),
    );
    park()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildConfig {
    schema: String,
    mode: String,
    store: PathBuf,
    control: PathBuf,
    page: Vec<u8>,
    launch: Option<PathBuf>,
    launch_sha256: Option<String>,
    retirement: Option<PathBuf>,
    retirement_sha256: Option<String>,
}
pub(super) fn child() {
    // No subprocess is spawned by this native helper. The guardian and parent
    // separately verify the current Git commit before creating this process.
    let compiled = compiled_source_commit();
    let path = PathBuf::from(std::env::var("TRNM_HISTORY_KNOWN_EPOCH_CHILD_CONFIG").unwrap());
    let raw = fs::read(&path).unwrap();
    assert_eq!(
        policy::digest(&raw),
        std::env::var("TRNM_HISTORY_KNOWN_EPOCH_CHILD_CONFIG_SHA256").unwrap()
    );
    let config: ChildConfig = serde_json::from_slice(&raw).unwrap();
    assert_eq!(config.schema, "actual-history-known-epoch-child-fixture-v1");
    let uid = rustix::process::geteuid().as_raw();
    HOOK.with(|slot| *slot.borrow_mut() = Some((config.mode.clone(), config.control.clone())));
    if config.mode == "retire" || config.mode.starts_with("retirement-publication-") {
        assert_eq!(
            read(config.retirement.as_ref().unwrap())["identity"]["source_commit"],
            compiled
        );
        let result = retire_history_known_epoch_v1(
            &config.store,
            ProtectedHistoryKnownEpochRetirementV1Input::load(
                config.retirement.as_ref().unwrap(),
                uid,
                config.retirement_sha256.as_deref().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            config.mode, "retire",
            "requested publication cut did not execute"
        );
        write_value(&config.control.join("retired-ready.json"), &result);
        return;
    }
    // This fixed helper has exactly one Startup call after process creation.
    // Resume is a separate owned process with its own separately signed claim.
    let launch = config.launch.as_ref().unwrap();
    assert_eq!(read(launch)["identity"]["source_commit"], compiled);
    let mut owner = HistoryEffectV6::open(
        &config.store,
        ProtectedHistoryV6Input::load(launch, uid, config.launch_sha256.as_deref().unwrap())
            .unwrap(),
        2,
        deadline(),
    )
    .unwrap();
    assert_eq!(owner.initial_cpu.stored_credit_ns, 0);
    write_value(
        &config.control.join("startup-ready.json"),
        &owner.observation().unwrap(),
    );
    let validation = child_wait(&config.control.join("outside-validation.json"));
    let validated = owner
        .receive_with_progress(&validation, &config.page, CLOCK, deadline(), &|_| Ok(()))
        .unwrap();
    let startup_config = read(launch);
    let startup_envelope: policy::Envelope<Operation> = serde_json::from_slice(
        &serde_json::from_value::<Vec<u8>>(startup_config["signed_startup"].clone()).unwrap(),
    )
    .unwrap();
    let expected_workers =
        if config.mode == "resume" && startup_envelope.body.owner_frontier.generation == 0 {
            0
        } else {
            2
        };
    checked(&validated, expected_workers);
    assert!(validated.known_success());
    write_value(
        &config.control.join("validation-ready.json"),
        &json!({"result":validated,"observation":owner.observation().unwrap(),"frontier":actual(&owner)}),
    );
    let activation = child_wait(&config.control.join("outside-activation.json"));
    let activated = owner
        .activate_with_progress(&activation, CLOCK, deadline(), &|_| Ok(()))
        .unwrap();
    checked(&activated, 0);
    assert!(activated.known_success());
    write_value(
        &config.control.join("activation-ready.json"),
        &json!({"result":activated,"observation":owner.observation().unwrap(),"frontier":actual(&owner)}),
    );
    let close = child_wait(&config.control.join("outside-close.json"));
    let closed = owner.close(&close, deadline()).unwrap();
    assert_eq!(config.mode, "resume");
    let identity = owner.owner.identity.clone();
    let head = serde_json::from_value(closed["journal"]["anchor"].clone()).unwrap();
    let journal_path = PathBuf::from(read(launch)["journal_path"].as_str().unwrap());
    drop(owner);
    let journal = journal::Journal::open(&journal_path, uid, &identity, &head).unwrap();
    assert!(journal.pending().is_none() && journal.known_epoch().is_none());
    let db = Connection::open_with_flags(
        config.store.join("native.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    storage::verify_known_markers(&db, &journal, None).unwrap();
    let count: u64 = db
        .query_row("SELECT COUNT(*) FROM history_effect_v6", [], |r| r.get(0))
        .unwrap();
    write_value(
        &config.control.join("finished.json"),
        &json!({"schema":"actual-history-known-epoch-next-process-finished-v1",
        "pid":std::process::id(),"closed":closed,"cold_journal":journal.observation(),
        "frontier":storage::frontier(&db).unwrap(),"marker_count":count,
        "old_cpu_receipts_fabricated":false,"production_qualified":false}),
    );
}

fn protected_input(
    a: &TestAuthority,
    label: &str,
    body: &Authorization,
    signed: Vec<u8>,
    closed: &[u8],
) -> (PathBuf, String) {
    let (fixture, guardian) = sources();
    let value = json!({"schema":"restricted-history-known-epoch-retirement-input-v1",
        "identity":a.identity,"journal_path":a.journal,"outside_latest_anchor":body.outside_anchor,
        "expected_executable_sha256":sha_file(&std::env::current_exe().unwrap()),
        "expected_fixture_source_sha256":fixture,"expected_guardian_source_sha256":guardian,
        "signed_retirement":signed,"closed_process":closed});
    let path = a.f.dir.path().join(format!("retirement-{label}.json"));
    let sha = write_value(&path, &value);
    (path, sha)
}
fn signed_retirement(body: &Authorization) -> Vec<u8> {
    let registry = signing_key_from_hex(&"11".repeat(32)).unwrap();
    let task = signing_key_from_hex(&"22".repeat(32)).unwrap();
    policy::encoded(&policy::Envelope {
        body,
        registry_signature: sign_hex(&registry, &known_epoch::message(1, body).unwrap()),
        task_signature: sign_hex(&task, &known_epoch::message(2, body).unwrap()),
    })
    .unwrap()
}
fn retire(store: &Path, path: &Path, sha: &str) -> Result<Value> {
    retire_history_known_epoch_v1(
        store,
        ProtectedHistoryKnownEpochRetirementV1Input::load(
            path,
            rustix::process::geteuid().as_raw(),
            sha,
        )?,
    )
}
fn refused(a: &TestAuthority, path: &Path, sha: &str) -> String {
    let before = snapshot(&a.journal);
    let result = retire(&a.store, path, sha);
    let error = result
        .expect_err("invalid retirement unexpectedly accepted")
        .to_string();
    assert_eq!(snapshot(&a.journal), before);
    error
}
fn negative_controls(a: &TestAuthority, body: &Authorization, closed_raw: &[u8]) -> Value {
    let closed: ClosedProcess = serde_json::from_slice(closed_raw).unwrap();
    let mut errors = BTreeMap::new();
    for mode in [
        "old-domain",
        "one-signature",
        "nonce-replay",
        "snapshot",
        "outside-anchor",
        "missing-closure",
        "two-startups",
        "born-after-startup",
        "source-pin",
        "over-cpu",
        "under-cpu",
    ] {
        let mut b = body.clone();
        let mut c = closed.clone();
        match mode {
            "nonce-replay" => b.request_nonce = b.original_used_operations,
            "snapshot" => {
                b.known_epoch.known_cpu_ns += 1;
                c.known_epoch_sha256 = b.known_epoch.digest().unwrap();
            }
            "outside-anchor" => {
                b.outside_anchor.digest = "ee".repeat(32);
                c.original_journal = b.outside_anchor.clone();
            }
            "missing-closure" => c.pidfd_identity_verified = false,
            "two-startups" => c.observed_epoch_start_count = 2,
            "born-after-startup" => c.process_spawn_before_ns = b.known_epoch.startup_at_ns + 1,
            "source-pin" => {
                b.fixture_source_sha256 = "dd".repeat(32);
                c.fixture_source_sha256 = b.fixture_source_sha256.clone();
            }
            "over-cpu" | "under-cpu" => {
                c.user_cpu_microseconds = if mode == "over-cpu" {
                    b.known_epoch.known_allowance_cpu_ns / 1000 + 1
                } else {
                    0
                };
                c.system_cpu_microseconds = 0;
                c.reported_user_seconds = format!(
                    "{}.{:06}",
                    c.user_cpu_microseconds / 1_000_000,
                    c.user_cpu_microseconds % 1_000_000
                );
                c.reported_system_seconds = "0".into();
                c.reported_cpu_upper_bound_ns = (c.user_cpu_microseconds + 2) * 1000;
            }
            "old-domain" | "one-signature" => (),
            _ => unreachable!(),
        }
        let raw = if c == closed {
            closed_raw.to_vec()
        } else {
            policy::encoded(&c).unwrap()
        };
        b.closed_process_sha256 = policy::digest(&raw);
        let envelope = if mode == "old-domain" {
            signed(b'R', &b)
        } else if mode == "one-signature" {
            let mut value: Value = serde_json::from_slice(&signed_retirement(&b)).unwrap();
            value["task_signature"] = value["registry_signature"].clone();
            policy::encoded(&value).unwrap()
        } else {
            signed_retirement(&b)
        };
        let (path, sha) = protected_input(a, mode, &b, envelope, &raw);
        errors.insert(mode, refused(a, &path, &sha));
    }
    for name in ["over-cpu", "under-cpu"] {
        assert!(
            errors[name].contains("PROCESS_CPU_BOUND"),
            "{}",
            errors[name]
        );
    }
    assert!(errors["snapshot"].contains("JOURNAL_BINDING"));
    assert!(errors["nonce-replay"].contains("REPLAY"));
    assert!(errors["source-pin"].contains("OUTSIDE_BINDING"));
    json!(errors)
}
fn pending_and_namespace_controls(
    a: &TestAuthority,
    body: &Authorization,
    closed_raw: &[u8],
) -> Value {
    let uid = rustix::process::geteuid().as_raw();
    let pending_path = a.f.dir.path().join("negative-pending-journal");
    process::copy_tree(&a.journal, &pending_path);
    let mut journal =
        journal::Journal::open(&pending_path, uid, &a.identity, &body.outside_anchor).unwrap();
    let raw = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: 8,
        epoch: 1,
        frontier: body.actual_frontier.clone(),
        anchor: body.outside_anchor.clone(),
        packet: Some(&a.f.packet),
        pair: Some((8, 9)),
    });
    journal.reserve(&raw).unwrap();
    let pending_before = journal.observation();
    let mut b = body.clone();
    b.outside_anchor = journal.anchor();
    let mut c: ClosedProcess = serde_json::from_slice(closed_raw).unwrap();
    c.original_journal = b.outside_anchor.clone();
    let c_raw = policy::encoded(&c).unwrap();
    b.closed_process_sha256 = policy::digest(&c_raw);
    let pending_error = journal
        .retire(&signed_retirement(&b), &c_raw)
        .unwrap_err()
        .to_string();
    assert!(pending_error.contains("PENDING_SCOPE"));
    assert_eq!(journal.observation(), pending_before);
    drop(journal);
    let wrong_namespace = a.f.dir.path().join("negative-old-record-schema");
    process::copy_tree(&a.journal, &wrong_namespace);
    let frame = journal::Frame {
        schema: "restricted-history-effect-record-v6".into(),
        identity_sha256: a.identity.digest().unwrap(),
        sequence: body.outside_anchor.sequence + 1,
        previous: body.outside_anchor.digest.clone(),
        at_ns: policy::now().unwrap(),
        event: journal::Event::KnownEpochRetiredV1 {
            signed: signed_retirement(body),
            closed_process: closed_raw.to_vec(),
        },
    };
    let raw = policy::encoded(&frame).unwrap();
    let head = Anchor {
        sequence: frame.sequence,
        digest: policy::digest(&raw),
    };
    write(
        &wrong_namespace.join(format!("{:020}-{}.json", head.sequence, head.digest)),
        &raw,
    );
    let schema_error = journal::Journal::open(&wrong_namespace, uid, &a.identity, &head)
        .err()
        .unwrap()
        .to_string();
    assert!(schema_error.contains("JOURNAL_CHAIN"));
    json!({"pending_scope":pending_error,"pending_reservation_unchanged":pending_before,
        "new_event_in_old_record_schema":schema_error,"fictional_success_receipt_created":false})
}
fn directory(a: &TestAuthority, name: &str) -> PathBuf {
    let path = a.f.dir.path().join(name);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}
fn native_negative_controls(a: &TestAuthority, path: &Path, sha: &str, mode: &str) -> Value {
    let original = snapshot(&a.journal);
    let native_sha = sha_file(&a.store.join("native.sqlite"));
    let mut errors = BTreeMap::new();
    for case in ["frontier", "missing-marker", "schema", "pending-reorg"] {
        if case == "pending-reorg" && mode == "known-validation" {
            continue;
        }
        let copy = a.f.dir.path().join(format!("negative-native-{case}"));
        process::copy_tree(&a.store, &copy);
        let db = Connection::open(copy.join("native.sqlite")).unwrap();
        match case {
            "frontier" => assert_eq!(
                db.execute(
                    "UPDATE active SET generation=generation+1 WHERE singleton=1",
                    []
                )
                .unwrap(),
                1
            ),
            "missing-marker" => assert_eq!(
                db.execute("DELETE FROM history_effect_v6 WHERE operation=?", [a.id(2)])
                    .unwrap(),
                1
            ),
            "schema" => db
                .execute_batch("CREATE TABLE unauthorized_retirement_extra(value BLOB)")
                .unwrap(),
            "pending-reorg" => assert_eq!(
                db.execute("UPDATE reorg SET done=0 WHERE done=1", [])
                    .unwrap(),
                1
            ),
            _ => unreachable!(),
        }
        drop(db);
        let error = retire(&copy, path, sha)
            .expect_err("corrupt native copy accepted retirement")
            .to_string();
        assert_eq!(snapshot(&a.journal), original);
        errors.insert(case, error);
    }
    let owner = recovery::private_file(
        &a.store.join("owner.lock"),
        rustix::process::geteuid().as_raw(),
    )
    .unwrap();
    owner.try_lock_exclusive().unwrap();
    let locked = retire(&a.store, path, sha)
        .expect_err("live native owner lock ignored")
        .to_string();
    drop(owner);
    errors.insert("native-lock-held", locked);
    assert_eq!(snapshot(&a.journal), original);
    assert_eq!(sha_file(&a.store.join("native.sqlite")), native_sha);
    assert!(errors["frontier"].contains("NATIVE_FRONTIER"));
    assert!(errors["missing-marker"].contains("SQL_MARKER_SET"));
    assert!(errors["schema"].contains("NATIVE_SCHEMA"));
    json!(errors)
}
fn spawn(a: &TestAuthority, config: Value, control: &Path, guarded: bool) -> Process {
    let mode = config["mode"].as_str().unwrap();
    let path = a.f.dir.path().join(format!("child-{mode}.json"));
    let sha = write_value(&path, &config);
    let binary = std::env::current_exe().unwrap();
    let mut command = if guarded {
        let guard = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../scripts/ci/history_known_epoch_process_guard.py");
        assert_eq!(sha_file(&guard), sources().1);
        let shared = guard.with_file_name("history_effect_v6_process_guard.py");
        assert_eq!(
            sha_file(&shared),
            policy::digest(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../scripts/ci/history_effect_v6_process_guard.py"
            )))
        );
        let lower = guard.with_file_name("history_native_process_guard.py");
        assert_eq!(
            sha_file(&lower),
            policy::digest(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../scripts/ci/history_native_process_guard.py"
            )))
        );
        let mut command = Command::new("python3");
        command
            .arg(guard)
            .arg("--binary")
            .arg(&binary)
            .args(["--binary-sha256", &sha_file(&binary), "--configuration"])
            .arg(&path)
            .args(["--configuration-sha256", &sha, "--directory"])
            .arg(control);
        command
    } else {
        let mut command = Command::new(&binary);
        command
            .args([
                known_epoch::FIXTURE_SELECTOR,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TRNM_HISTORY_KNOWN_EPOCH_CHILD_CONFIG", &path)
            .env("TRNM_HISTORY_KNOWN_EPOCH_CHILD_CONFIG_SHA256", &sha);
        command
    };
    let log = File::create(control.join("process.stdout.log")).unwrap();
    Process {
        child: command
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
        guardian: guarded,
    }
}
fn child_config(
    a: &TestAuthority,
    mode: &str,
    control: &Path,
    page: Vec<u8>,
    launch: Option<(PathBuf, String)>,
    retirement: Option<(PathBuf, String)>,
) -> Value {
    json!({"schema":"actual-history-known-epoch-child-fixture-v1","mode":mode,"store":a.store,"control":control,"page":page,
        "launch":launch.as_ref().map(|v|&v.0),"launch_sha256":launch.as_ref().map(|v|&v.1),
        "retirement":retirement.as_ref().map(|v|&v.0),"retirement_sha256":retirement.as_ref().map(|v|&v.1)})
}
fn publication_input(
    a: &TestAuthority,
    body: &journal::publication::Authorization,
    v2: bool,
) -> (PathBuf, String) {
    let registry = signing_key_from_hex(&"11".repeat(32)).unwrap();
    let task = signing_key_from_hex(&"22".repeat(32)).unwrap();
    let message = |role| {
        if v2 {
            journal::publication::message_v2(role, body)
        } else {
            journal::publication::message(role, body)
        }
        .unwrap()
    };
    let signed = policy::encoded(&policy::Envelope {
        body,
        registry_signature: sign_hex(&registry, &message(1)),
        task_signature: sign_hex(&task, &message(2)),
    })
    .unwrap();
    let version = if v2 { "v2" } else { "v1" };
    let path =
        a.f.dir
            .path()
            .join(format!("retirement-publication-{version}.json"));
    let sha = write_value(
        &path,
        &json!({"schema":format!("restricted-history-journal-publication-input-{version}"),
        "identity":a.identity,"journal_path":a.journal,"outside_latest_anchor":body.published_anchor,"signed_publication":signed}),
    );
    (path, sha)
}
fn repair_retirement(a: &TestAuthority, barrier: &Value) -> Value {
    let now = policy::now().unwrap();
    let mut body = journal::publication::Authorization {
        schema: "restricted-history-journal-publication-authorization-v1".into(),
        identity: a.identity.clone(),
        prefix_anchor: serde_json::from_value(barrier["prefix_anchor"].clone()).unwrap(),
        published_anchor: serde_json::from_value(barrier["published_anchor"].clone()).unwrap(),
        frame_sha256: barrier["published_anchor"]["digest"]
            .as_str()
            .unwrap()
            .into(),
        frame_bytes: barrier["frame_bytes"].as_u64().unwrap(),
        issued_ns: now,
        expires_ns: now + 3_000_000_000_000,
    };
    let uid = rustix::process::geteuid().as_raw();
    let (old, old_sha) = publication_input(a, &body, false);
    let before = snapshot(&a.journal);
    let refused = repair_history_journal_publication_v1(
        ProtectedHistoryJournalPublicationV1Input::load(&old, uid, &old_sha).unwrap(),
    )
    .unwrap_err()
    .to_string();
    assert!(refused.contains("RECORD_NAMESPACE"));
    assert_eq!(snapshot(&a.journal), before);
    body.schema = "restricted-history-journal-publication-authorization-v2".into();
    let (path, sha) = publication_input(a, &body, true);
    let result = repair_history_journal_publication_v2(
        ProtectedHistoryJournalPublicationV2Input::load(&path, uid, &sha).unwrap(),
    )
    .unwrap();
    let after = snapshot(&a.journal);
    let repeated = repair_history_journal_publication_v2(
        ProtectedHistoryJournalPublicationV2Input::load(&path, uid, &sha).unwrap(),
    )
    .unwrap();
    assert_eq!(snapshot(&a.journal), after);
    assert_eq!(repeated["already_published"], true);
    assert_eq!(result["journal"], repeated["journal"]);
    json!({"v1_refused":refused,"repair":result,"idempotent_retry":repeated})
}

pub(super) fn run(mode: &str) {
    let compiled = compiled_source_commit();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let current = Command::new("git")
        .args(["--no-replace-objects", "rev-parse", "HEAD"])
        .current_dir(&repository)
        .output()
        .unwrap();
    assert!(current.status.success());
    assert_eq!(
        String::from_utf8(current.stdout).unwrap().trim(),
        compiled,
        "known-epoch source checkout differs from the compiled commit"
    );
    let a = TestAuthority::with_source_commit(compiled);
    let _retain = Retain {
        source: a.f.dir.path().to_path_buf(),
        target: std::env::var_os("TRNM_HISTORY_V6_ARTIFACT_DIR").map(|base| {
            let base = PathBuf::from(base);
            fs::create_dir_all(&base).unwrap();
            base.join(mode)
        }),
    };
    let binary = std::env::current_exe().unwrap();
    let binary_sha = sha_file(&binary);
    let source_refusals = if mode == "known-validation" {
        actual_source_refusals(&a, &binary)
    } else {
        json!({"executed_in":"known-validation"})
    };
    let first = directory(&a, "known-crash-control");
    let launch = a.launch("known-crash", 1, 1, a.genesis(), a.installed.clone());
    let mut killed = spawn(
        &a,
        child_config(&a, mode, &first, a.f.page.clone(), Some(launch), None),
        &first,
        true,
    );
    let startup = wait(&first.join("startup-ready.json"), &mut killed);
    let validation = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: 2,
        epoch: 1,
        frontier: a.genesis(),
        anchor: serde_json::from_value(startup["journal"]["anchor"].clone()).unwrap(),
        packet: Some(&a.f.packet),
        pair: Some((2, 3)),
    });
    write(&first.join("outside-validation.json"), &validation);
    if mode != "known-validation" {
        let validated = wait(&first.join("validation-ready.json"), &mut killed);
        let activation = a.grant(Grant {
            purpose: Purpose::Activation,
            nonce: 3,
            epoch: 1,
            frontier: a.genesis(),
            anchor: serde_json::from_value(validated["observation"]["journal"]["anchor"].clone())
                .unwrap(),
            packet: Some(&a.f.packet),
            pair: Some((2, 3)),
        });
        write(&first.join("outside-activation.json"), &activation);
        if mode == "known-close" {
            let activated = wait(&first.join("activation-ready.json"), &mut killed);
            let close = a.grant(Grant {
                purpose: Purpose::Close,
                nonce: 4,
                epoch: 1,
                frontier: serde_json::from_value(activated["frontier"].clone()).unwrap(),
                anchor: serde_json::from_value(
                    activated["observation"]["journal"]["anchor"].clone(),
                )
                .unwrap(),
                packet: None,
                pair: None,
            });
            write(&first.join("outside-close.json"), &close);
        }
    }
    let guardian = wait(&first.join("guardian-result.json"), &mut killed);
    assert!(killed.child.wait().unwrap().success(), "{guardian}");
    assert_eq!(guardian["passed"], true);
    let barrier = read(&first.join("crash-ready.json"));
    let closed_raw = fs::read(first.join("closed-process.json")).unwrap();
    let closed: ClosedProcess = serde_json::from_slice(&closed_raw).unwrap();
    let known: KnownEpoch = serde_json::from_slice(
        &serde_json::from_value::<Vec<u8>>(barrier["known_epoch_raw"].clone()).unwrap(),
    )
    .unwrap();
    let old_count = if mode == "known-validation" {
        2
    } else if mode == "known-activation" {
        3
    } else {
        4
    };
    assert_eq!(known.known_operations, old_count);
    assert_eq!(known.known_allowance_cpu_ns, old_count * 4_000_000_000u64);
    let original = snapshot(&a.journal);
    let (refused_path, refused_sha) = a.launch(
        "unclosed-refused",
        9,
        2,
        closed.actual_frontier.clone(),
        closed.original_journal.clone(),
    );
    let ordinary_error = HistoryEffectV6::open(
        &a.store,
        ProtectedHistoryV6Input::load(
            &refused_path,
            rustix::process::geteuid().as_raw(),
            &refused_sha,
        )
        .unwrap(),
        2,
        deadline(),
    )
    .err()
    .unwrap()
    .to_string();
    assert!(ordinary_error.contains("UNCLOSED_EPOCH"));
    assert_eq!(snapshot(&a.journal), original);
    let now = policy::now().unwrap();
    let (fixture_sha, guard_sha) = sources();
    let body = Authorization {
        schema: "restricted-history-known-epoch-retirement-authorization-v1".into(),
        identity: a.identity.clone(),
        request_nonce: 10,
        outside_anchor: closed.original_journal.clone(),
        known_epoch: known,
        original_spent: serde_json::from_value(barrier["journal"]["spent"].clone()).unwrap(),
        original_used_operations: old_count,
        executable_sha256: binary_sha.clone(),
        fixture_source_sha256: fixture_sha,
        guardian_source_sha256: guard_sha,
        closed_process_sha256: policy::digest(&closed_raw),
        actual_frontier: closed.actual_frontier.clone(),
        issued_ns: now,
        expires_ns: now + 3_000_000_000_000,
    };
    let negatives = negative_controls(&a, &body, &closed_raw);
    let namespace_negatives = pending_and_namespace_controls(&a, &body, &closed_raw);
    let (retire_path, retire_sha) =
        protected_input(&a, "actual", &body, signed_retirement(&body), &closed_raw);
    let native_negatives = native_negative_controls(&a, &retire_path, &retire_sha, mode);
    let admin = directory(&a, "retirement-control");
    let retirement_mode = match mode {
        "known-validation" => "retire",
        "known-activation" => "retirement-publication-linked",
        _ => "retirement-publication-unlinked",
    };
    let mut retired_process = spawn(
        &a,
        child_config(
            &a,
            retirement_mode,
            &admin,
            Vec::new(),
            None,
            Some((retire_path.clone(), retire_sha.clone())),
        ),
        &admin,
        retirement_mode != "retire",
    );
    let (retired, publication) = if retirement_mode == "retire" {
        let retired = wait(&admin.join("retired-ready.json"), &mut retired_process);
        assert!(retired_process.child.wait().unwrap().success());
        assert_eq!(retired["clean_close_created"], false);
        assert_eq!(retired["new_cpu_receipt_created"], false);
        (retired["journal"].clone(), json!({"executed":false}))
    } else {
        let observed = wait(&admin.join("guardian-result.json"), &mut retired_process);
        assert!(
            retired_process.child.wait().unwrap().success(),
            "{observed}"
        );
        assert_eq!(observed["closed_process_receipt_created"], false);
        assert!(!admin.join("closed-process.json").exists());
        let cut = read(&admin.join("crash-ready.json"));
        let repaired = repair_retirement(&a, &cut);
        (
            repaired["repair"]["journal"].clone(),
            json!({"guardian":observed,"publication":repaired}),
        )
    };
    assert_eq!(retired["spent"], barrier["journal"]["spent"]);
    assert_eq!(retired["used_operations"], old_count);
    assert_eq!(retired["known_settlements"], old_count);
    assert_eq!(retired["unknown_prepaid_reconciliations"], 0);
    assert_eq!(retired["request_nonce"], 10);
    assert!(retired["pending"].is_null() && retired["epoch"].is_null());
    let after_retirement = snapshot(&a.journal);
    for (name, sha) in &original {
        assert_eq!(after_retirement.get(name), Some(sha));
    }
    let duplicate_error = refused(&a, &retire_path, &retire_sha);
    assert!(duplicate_error.contains("ROLLBACK"));
    let retired_head: Anchor = serde_json::from_value(retired["anchor"].clone()).unwrap();
    let (reuse_path, reuse_sha) = a.launch(
        "old-epoch-refused",
        11,
        1,
        closed.actual_frontier.clone(),
        retired_head.clone(),
    );
    let old_epoch_error = HistoryEffectV6::open(
        &a.store,
        ProtectedHistoryV6Input::load(&reuse_path, rustix::process::geteuid().as_raw(), &reuse_sha)
            .unwrap(),
        2,
        deadline(),
    )
    .err()
    .unwrap()
    .to_string();
    assert!(old_epoch_error.contains("UNCLOSED_EPOCH"));
    assert_eq!(snapshot(&a.journal), after_retirement);
    let next = if mode == "known-validation" {
        Packet::decode(&a.f.packet.encode().unwrap()).unwrap()
    } else {
        process::next_packet(&a)
    };
    let resumed = directory(&a, "known-resume-control");
    let launch = a.launch(
        "known-resume",
        11,
        2,
        closed.actual_frontier.clone(),
        retired_head,
    );
    let mut next_process = spawn(
        &a,
        child_config(
            &a,
            "resume",
            &resumed,
            process::page(&a, &next),
            Some(launch),
            None,
        ),
        &resumed,
        false,
    );
    let started = wait(&resumed.join("startup-ready.json"), &mut next_process);
    assert_eq!(started["initial_cpu"]["stored_credit_ns"], 0);
    let validation = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: 12,
        epoch: 2,
        frontier: closed.actual_frontier.clone(),
        anchor: serde_json::from_value(started["journal"]["anchor"].clone()).unwrap(),
        packet: Some(&next),
        pair: Some((12, 13)),
    });
    write(&resumed.join("outside-validation.json"), &validation);
    let validated = wait(&resumed.join("validation-ready.json"), &mut next_process);
    let activation = a.grant(Grant {
        purpose: Purpose::Activation,
        nonce: 13,
        epoch: 2,
        frontier: closed.actual_frontier.clone(),
        anchor: serde_json::from_value(validated["observation"]["journal"]["anchor"].clone())
            .unwrap(),
        packet: Some(&next),
        pair: Some((12, 13)),
    });
    write(&resumed.join("outside-activation.json"), &activation);
    let activated = wait(&resumed.join("activation-ready.json"), &mut next_process);
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
    write(&resumed.join("outside-close.json"), &close);
    let finished = wait(&resumed.join("finished.json"), &mut next_process);
    assert!(next_process.child.wait().unwrap().success(), "{finished}");
    assert_ne!(finished["pid"], closed.owned_namespace_pid);
    assert_eq!(
        finished["cold_journal"]["spent"]["cpu_ns"],
        (old_count + 4) * 4_000_000_000u64
    );
    assert_eq!(finished["cold_journal"]["used_operations"], old_count + 4);
    assert_eq!(finished["cold_journal"]["known_settlements"], old_count + 4);
    assert_eq!(
        finished["cold_journal"]["unknown_prepaid_reconciliations"],
        0
    );
    assert_eq!(finished["cold_journal"]["request_nonce"], 14);
    assert!(finished["cold_journal"]["epoch"].is_null());
    assert_eq!(
        finished["frontier"]["block"],
        hex::encode(next.id().unwrap())
    );
    assert_eq!(
        finished["frontier"]["generation"],
        if mode == "known-validation" { 1 } else { 2 }
    );
    assert_eq!(
        finished["marker_count"],
        if mode == "known-validation" { 3 } else { 4 }
    );
    let final_records = snapshot(&a.journal);
    for (name, sha) in &after_retirement {
        assert_eq!(final_records.get(name), Some(sha));
    }
    assert_eq!(sha_file(&binary), binary_sha);
    write_value(
        &a.f.dir.path().join("known-epoch-result.json"),
        &json!({
        "schema":"actual-history-known-epoch-retirement-three-process-result-v1","cutpoint":mode,
        "guardian":guardian,"before":barrier["journal"],"retired":retired,"finished":finished,
        "publication_crash":publication,"negative_authorization_controls":negatives,
        "negative_native_controls":native_negatives,
        "negative_pending_and_namespace_controls":namespace_negatives,"ordinary_unclosed_error":ordinary_error,
        "duplicate_retirement_error":duplicate_error,"old_epoch_reuse_error":old_epoch_error,
        "original_record_sha256":original,"original_records_unchanged":true,"binary_sha256":binary_sha,
        "compiled_source_commit":compiled,
        "source_pin_negative_processes":source_refusals,
        "per_scope_receipts_fabricated":false,"physical_power_loss_qualified":false,"production_qualified":false}),
    );
    eprintln!(
        "HISTORY_KNOWN_EPOCH_ACTUAL {}",
        serde_json::to_string(&finished).unwrap()
    );
}
