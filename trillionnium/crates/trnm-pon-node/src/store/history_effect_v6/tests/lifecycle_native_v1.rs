//! Actual initialization/Close boundaries, actual child death and ordinary
//! fresh Startup. Disclosed fixture signers are not production authorities.
use super::journal::lifecycle_recovery_v1::{self as lifecycle, Authorization, Closure, Database};
use super::startup_no_native_v1::Pins;
use super::tests::*;
use super::*;
use crate::store::operator_continuous_owner::history_import::tests::fixture::CLOCK;
use policy::{Anchor, Identity, Operation, Usage};
use serde_json::json;
use std::process::{Command, Stdio};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};

fn compiled_source() -> &'static str {
    let Some(source) = option_env!("TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT") else {
        panic!("actual compile-source pin required for lifecycle fixtures")
    };
    assert_eq!(
        std::env::var("TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT").unwrap(),
        source
    );
    source
}

fn fixture_sha() -> String {
    policy::digest(include_bytes!("lifecycle_native_v1.rs"))
}

fn latest_frame(path: &Path) -> (Anchor, journal::Frame) {
    let mut frames = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect::<Vec<_>>();
    frames.sort();
    let raw = fs::read(frames.last().unwrap()).unwrap();
    let frame: journal::Frame = serde_json::from_slice(&raw).unwrap();
    (
        Anchor {
            sequence: frame.sequence,
            digest: policy::digest(&raw),
        },
        frame,
    )
}

fn journal_files(path: &Path) -> BTreeMap<String, String> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_name() != "owner.lock")
        .map(|entry| {
            (
                entry.file_name().into_string().unwrap(),
                process::sha_file(&entry.path()),
            )
        })
        .collect()
}

fn retains_prefix(before: &BTreeMap<String, String>, path: &Path) {
    let after = journal_files(path);
    for (name, digest) in before {
        assert_eq!(after.get(name), Some(digest));
    }
}

fn read_wait(path: &Path) -> Value {
    let end = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(
            Instant::now() < end,
            "missing outside lifecycle step {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    read(path)
}

fn park(control: &Path, value: &Value) -> ! {
    write_value(&control.join("crash-ready.json"), value);
    loop {
        std::thread::park_timeout(Duration::from_secs(5));
    }
}

fn startup_barrier(launch: &Path, mode: &str, control: &Path, closure: Closure) -> ! {
    let config = read(launch);
    let identity: Identity = serde_json::from_value(config["identity"].clone()).unwrap();
    let signed: Vec<u8> = serde_json::from_value(config["signed_startup"].clone()).unwrap();
    assert_eq!(identity.source_commit, compiled_source());
    let verified = policy::operation(&signed, &identity, policy::now().unwrap()).unwrap();
    let (anchor, frame) = latest_frame(Path::new(config["journal_path"].as_str().unwrap()));
    match (&closure, &frame.event) {
        (Closure::PendingStartup, journal::Event::Intent { signed: actual }) => {
            assert_eq!(actual, &signed);
        }
        (
            Closure::SettledStartup,
            journal::Event::Settlement {
                operation,
                native_id,
                native_error,
                cpu,
                marker,
                ..
            },
        ) => {
            assert_eq!(operation, &verified.body.operation_id);
            assert!(native_id.is_none() && marker.is_none());
            assert_eq!(native_error.as_deref(), Some("HISTORY_V6_CANCELLED"));
            assert!(cpu.known());
        }
        _ => panic!("actual requested Startup journal boundary required"),
    }
    park(
        control,
        &json!({
            "schema":"actual-history-lifecycle-barrier-v1", "pid":std::process::id(),
            "cutpoint":mode,"closure":closure,"anchor":anchor,
            "actual_compiled_source":compiled_source(),"fixture_sha256":fixture_sha(),
            "operation_id":verified.body.operation_id,"intent_sha256":verified.intent_sha256,
            "epoch":verified.body.epoch,"declared_frontier":verified.body.owner_frontier,
            "clean_close_created":false,
        }),
    )
}

pub(super) fn child(config: &Value) {
    let mode = config["mode"].as_str().unwrap();
    let store = PathBuf::from(config["store"].as_str().unwrap());
    let control = PathBuf::from(config["control"].as_str().unwrap());
    let uid = rustix::process::geteuid().as_raw();
    if mode.starts_with("lifecycle-publish-") {
        publication::install_hook(mode, &control);
        let result = prepare_history_lifecycle_v1_recovery(
            &store,
            ProtectedHistoryLifecycleV1Input::load(
                Path::new(config["recovery"].as_str().unwrap()),
                uid,
                config["recovery_sha256"].as_str().unwrap(),
            )
            .unwrap(),
        );
        panic!("lifecycle publication returned before actual barrier: {result:?}");
    }
    let launch = PathBuf::from(config["launch"].as_str().unwrap());
    let input =
        ProtectedHistoryV6Input::load(&launch, uid, config["launch_sha256"].as_str().unwrap())
            .unwrap();
    let raw: Vec<u8> = serde_json::from_value(read(&launch)["signed_startup"].clone()).unwrap();
    let operation: policy::Envelope<Operation> = serde_json::from_slice(&raw).unwrap();
    let cancellation =
        HistoryEffectV6StartupCancellation::for_operation(&operation.body.operation_id).unwrap();
    let opened = HistoryEffectV6::open_with_startup_progress(
        &store,
        input,
        2,
        deadline(),
        Some(&cancellation),
        &|point| {
            if mode == "lifecycle-startup-settled-cancel"
                && point == StartupProgress::NativeInitialization("init-before-commit")
            {
                cancellation.cancel();
            }
            if mode == "lifecycle-no-native-settled-cancel"
                && matches!(point, StartupProgress::Material(_))
            {
                cancellation.cancel();
            }
            if (mode == "lifecycle-no-native-before-node" && point == StartupProgress::BeforeNode)
                || (mode == "lifecycle-no-native-waiting-credit"
                    && point == StartupProgress::WaitingForCredit)
            {
                startup_barrier(&launch, mode, &control, Closure::PendingStartup);
            }
            let selected = mode.strip_prefix("lifecycle-");
            if matches!(point, StartupProgress::NativeInitialization(stage) if Some(stage) == selected)
                || (mode == "lifecycle-startup-pending-ready"
                    && point == StartupProgress::BeforeSettlement)
            {
                startup_barrier(&launch, mode, &control, Closure::PendingStartup);
            }
            Ok(())
        },
    );
    if mode == "lifecycle-startup-settled-cancel" || mode == "lifecycle-no-native-settled-cancel" {
        assert_eq!(opened.err().unwrap().to_string(), "HISTORY_V6_CANCELLED");
        startup_barrier(&launch, mode, &control, Closure::SettledStartup);
    }
    let mut owner = opened.unwrap();
    assert_eq!(owner.initial_cpu.stored_credit_ns, 0);
    assert!(mode.starts_with("lifecycle-close-"));
    write_value(
        &control.join("startup-ready.json"),
        &json!({
            "observation":owner.observation().unwrap(),"frontier":actual(&owner),
        }),
    );
    for step in 0..8 {
        let request = read_wait(&control.join(format!("outside-step-{step}.json")));
        let action = request["action"].as_str().unwrap();
        let signed: Vec<u8> = serde_json::from_value(request["signed"].clone()).unwrap();
        let result = match action {
            "validation" => {
                let page: Vec<u8> = serde_json::from_value(config["page"].clone()).unwrap();
                let result = owner
                    .receive_with_progress(&signed, &page, CLOCK, deadline(), &|_| Ok(()))
                    .unwrap();
                checked(&result, 2);
                assert!(result.known_success());
                serde_json::to_value(result).unwrap()
            }
            "activation" => {
                let result = owner
                    .activate_with_progress(&signed, CLOCK, deadline(), &|_| Ok(()))
                    .unwrap();
                checked(&result, 0);
                assert!(result.known_success());
                serde_json::to_value(result).unwrap()
            }
            "close-refuse" => {
                assert_eq!(
                    owner.close(&signed, deadline()).unwrap_err().to_string(),
                    "HISTORY_V6_CLOSE_ACCOUNTING"
                );
                let (_, frame) = latest_frame(owner.owner.journal().unwrap().path());
                let journal::Event::Settlement {
                    native_error, cpu, ..
                } = frame.event
                else {
                    panic!("known wrong-frontier Close settlement required")
                };
                assert_eq!(native_error.as_deref(), Some("HISTORY_V6_OWNER_FRONTIER"));
                assert!(cpu.known());
                json!({"journal":owner.owner.journal().unwrap().observation(),
                    "native_error":native_error,"cpu":cpu})
            }
            "close" => {
                let shared = owner.owner.clone();
                let result = owner.close_with_progress(&signed, deadline(), &|point| {
                    if point == Progress::BeforeSettlement {
                        let journal = shared.journal()?;
                        let pending = journal.pending().unwrap();
                        assert_eq!(pending.operation.purpose, Purpose::Close);
                        let barrier = json!({
                            "schema":"actual-history-lifecycle-barrier-v1","pid":std::process::id(),
                            "cutpoint":mode,"closure":"pending-close","anchor":journal.anchor(),
                            "operation_id":pending.operation.operation_id,"intent_sha256":pending.intent_sha256,
                            "epoch":pending.operation.epoch,"declared_frontier":pending.operation.owner_frontier,
                            "clean_close_created":false,
                        });
                        drop(journal);
                        park(&control, &barrier);
                    }
                    Ok(())
                });
                panic!("Close returned before actual pending barrier: {result:?}");
            }
            _ => panic!("unexpected outside lifecycle action"),
        };
        write_value(
            &control.join(format!("step-ready-{step}.json")),
            &json!({
                "result":result,"frontier":actual(&owner),
            }),
        );
    }
    panic!("finite lifecycle child exhausted outside actions");
}

struct Observed {
    // Evidence must be copied before TestAuthority drops its TempDir.
    _retain: process::Retain,
    authority: TestAuthority,
    control: PathBuf,
    closed_raw: Vec<u8>,
    closed: lifecycle::ClosedProcess,
    original: Operation,
    prefix: BTreeMap<String, String>,
    database_identity: Option<(u64, u64)>,
}

fn guardian(a: &TestAuthority, control: &Path, config: &Value) -> process::Process {
    let path = control.join("child.json");
    let digest = write_value(&path, config);
    let binary = std::env::current_exe().unwrap();
    let sha = process::sha_file(&binary);
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/ci/history_lifecycle_process_guard_v1.py");
    let log = File::create(control.join("guardian.log")).unwrap();
    let child = Command::new("python3")
        .arg(script)
        .arg("--binary")
        .arg(&binary)
        .arg("--binary-sha256")
        .arg(sha)
        .arg("--configuration")
        .arg(path)
        .arg("--configuration-sha256")
        .arg(digest)
        .arg("--directory")
        .arg(control)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    if config["schema"] == "actual-history-lifecycle-no-native-preparation-v1" {
        assert_eq!(config["namespace_parent"], json!(a.store.parent().unwrap()));
    } else {
        assert_eq!(config["store"], json!(a.store));
    }
    process::Process {
        child,
        guardian: true,
    }
}

fn cut_existing(
    a: &TestAuthority,
    label: &str,
    mode: &str,
    nonce: u64,
    epoch: u64,
    frontier: Frontier,
    outside: Anchor,
) -> (PathBuf, Vec<u8>, lifecycle::ClosedProcess, Operation) {
    let control = a.f.dir.path().join(label);
    fs::create_dir(&control).unwrap();
    let (launch, launch_sha) = a.launch(label, nonce, epoch, frontier, outside);
    let startup: Vec<u8> = serde_json::from_value(read(&launch)["signed_startup"].clone()).unwrap();
    let mut original = serde_json::from_slice::<policy::Envelope<Operation>>(&startup)
        .unwrap()
        .body;
    let config = json!({"schema":"actual-history-effect-child-fixture-v6","mode":mode,
        "store":a.store,"control":control,"page":a.f.page,"launch":launch,"launch_sha256":launch_sha,
        "recovery":null,"recovery_sha256":null});
    let mut process = guardian(a, &control, &config);
    if mode.starts_with("lifecycle-close-") {
        let ready = process::wait(&control.join("startup-ready.json"), &mut process);
        let mut current: Frontier = serde_json::from_value(ready["frontier"].clone()).unwrap();
        let mut head: Anchor =
            serde_json::from_value(ready["observation"]["journal"]["anchor"].clone()).unwrap();
        for (step, purpose, action) in [
            (0, Purpose::Validation, "validation"),
            (1, Purpose::Activation, "activation"),
        ] {
            let signed = a.grant(Grant {
                purpose,
                nonce: nonce + step + 1,
                epoch,
                frontier: current.clone(),
                anchor: head,
                packet: Some(&a.f.packet),
                pair: Some((nonce + 1, nonce + 2)),
            });
            write_value(
                &control.join(format!("outside-step-{step}.json")),
                &json!({"action":action,"signed":signed}),
            );
            let response = process::wait(
                &control.join(format!("step-ready-{step}.json")),
                &mut process,
            );
            current = serde_json::from_value(response["frontier"].clone()).unwrap();
            head = serde_json::from_value(response["result"]["journal"]["anchor"].clone()).unwrap();
        }
        let wrong = mode == "lifecycle-close-wrong-frontier";
        let mut declared = current;
        if wrong {
            declared.root = "ab".repeat(32);
        }
        let mut next = nonce + 3;
        let mut step = 2;
        if wrong {
            let signed = a.grant(Grant {
                purpose: Purpose::Close,
                nonce: next,
                epoch,
                frontier: declared.clone(),
                anchor: head,
                packet: None,
                pair: None,
            });
            write_value(
                &control.join(format!("outside-step-{step}.json")),
                &json!({"action":"close-refuse","signed":signed}),
            );
            let response = process::wait(
                &control.join(format!("step-ready-{step}.json")),
                &mut process,
            );
            assert_eq!(
                response["result"]["native_error"],
                "HISTORY_V6_OWNER_FRONTIER"
            );
            head = serde_json::from_value(response["result"]["journal"]["anchor"].clone()).unwrap();
            next += 1;
            step += 1;
        }
        let signed = a.grant(Grant {
            purpose: Purpose::Close,
            nonce: next,
            epoch,
            frontier: declared,
            anchor: head,
            packet: None,
            pair: None,
        });
        original = serde_json::from_slice::<policy::Envelope<Operation>>(&signed)
            .unwrap()
            .body;
        write_value(
            &control.join(format!("outside-step-{step}.json")),
            &json!({"action":"close","signed":signed}),
        );
    }
    let result = process::wait(&control.join("guardian-result.json"), &mut process);
    assert!(process.child.wait().unwrap().success());
    assert_eq!(result["passed"], true);
    assert_eq!(result["actual_wait4"], true);
    assert_eq!(result["absent_frontier_fabricated"], false);
    let raw = fs::read(control.join("closed-process.json")).unwrap();
    let closed: lifecycle::ClosedProcess = serde_json::from_slice(&raw).unwrap();
    closed.validate().unwrap();
    assert_eq!(closed.epoch, original.epoch);
    assert_eq!(closed.declared_frontier, original.owner_frontier);
    assert_eq!(
        closed.intent_sha256,
        policy::digest(&policy::message(b'I', 0, &original).unwrap())
    );
    (control, raw, closed, original)
}

fn observe(label: &str, mode: &str) -> Observed {
    let Some(source) = option_env!("TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT") else {
        panic!("actual compile-source pin required for lifecycle fixtures")
    };
    let a = TestAuthority::with_source_and_budget_lifetime(source, 3_600_000_000_000);
    observe_with_authority(label, mode, a)
}

fn observe_with_authority(label: &str, mode: &str, a: TestAuthority) -> Observed {
    let retain = process::retain_fixture(a.f.dir.path(), label);
    let (control, raw, closed, original) = cut_existing(
        &a,
        "initial-death",
        mode,
        1,
        1,
        a.genesis(),
        a.installed.clone(),
    );
    let prefix = journal_files(&a.journal);
    let database_identity = fs::metadata(a.store.join("native.sqlite"))
        .ok()
        .map(|m| (m.dev(), m.ino()));
    Observed {
        _retain: retain,
        authority: a,
        control,
        closed_raw: raw,
        closed,
        original,
        prefix,
        database_identity,
    }
}

#[test]
fn exhausted_pending_startup_requires_explicit_budget_renewal_and_keeps_old_debt() {
    let Some(source) = option_env!("TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT") else {
        panic!("actual compile-source pin required for lifecycle fixtures")
    };
    let a = TestAuthority::with_source_and_budget_limits(
        source,
        3_600_000_000_000,
        Usage {
            cpu_ns: 4_000_000_000,
            material_bytes: 2 << 20,
            received_bytes: 2 << 20,
            operations: 1,
        },
    );
    let mut o = observe_with_authority(
        "lifecycle-exhausted-budget",
        "lifecycle-init-before-commit",
        a,
    );
    let uid = rustix::process::geteuid().as_raw();
    let before = journal_files(&o.authority.journal);
    let old = journal::Journal::open_existing(
        &o.authority.journal,
        uid,
        &o.authority.identity,
        &o.closed.original_journal,
    )
    .unwrap();
    assert!(old.pending().is_some());
    assert_eq!(old.observation()["spent"]["cpu_ns"], 4_000_000_000_u64);
    assert_eq!(old.observation()["spent"]["operations"], 1);
    drop(old);

    let original_body = authorization(&o);
    let (path, sha) = recovery_input(
        &o,
        "exhausted-no-renewal",
        &original_body,
        envelope(&original_body),
        &o.closed_raw,
    );
    assert!(prepare_history_lifecycle_v1_recovery(&o.authority.store, load(&path, &sha)).is_err());
    assert_eq!(journal_files(&o.authority.journal), before);

    let mut renewal =
        serde_json::from_slice::<policy::Envelope<policy::Budget>>(&o.authority.budget)
            .unwrap()
            .body;
    renewal.budget_id = policy::digest(b"explicit-lifecycle-exhausted-budget-renewal-v1");
    renewal.sequence += 1;
    renewal.outside_anchor = o.closed.original_journal.clone();
    renewal.lifetime_ceiling = Usage {
        cpu_ns: 32_000_000_000,
        material_bytes: 16 << 20,
        received_bytes: 16 << 20,
        operations: 8,
    };
    let now = policy::now().unwrap();
    renewal.issued_ns = now;
    renewal.expires_ns = now + 3_600_000_000_000;
    let renewed = signed(b'B', &renewal);
    let mut old = journal::Journal::open_existing(
        &o.authority.journal,
        uid,
        &o.authority.identity,
        &o.closed.original_journal,
    )
    .unwrap();
    // The ordinary Budget path still refuses pending debt. Only the new
    // management domain can atomically bind this exact Budget and closure.
    assert!(old.install_budget(&renewed).is_err());
    drop(old);
    assert_eq!(journal_files(&o.authority.journal), before);

    let mut body = original_body;
    body.budget_id = renewal.budget_id.clone();
    body.renewal_budget = Some(renewed.clone());
    let mut old_anchor = renewal.clone();
    old_anchor.outside_anchor = o.authority.installed.clone();
    let mut wrong_sequence = renewal.clone();
    wrong_sequence.sequence += 1;
    let mut rollback = renewal.clone();
    rollback.lifetime_ceiling.material_bytes = 0;
    let mut replay_id = renewal.clone();
    replay_id.budget_id = o.original.budget_id.clone();
    for (label, invalid) in [
        ("renewal-old-anchor", old_anchor),
        ("renewal-wrong-sequence", wrong_sequence),
        ("renewal-ceiling-rollback", rollback),
        ("renewal-budget-id-replay", replay_id),
    ] {
        let mut invalid_body = body.clone();
        invalid_body.budget_id = invalid.budget_id.clone();
        invalid_body.renewal_budget = Some(signed(b'B', &invalid));
        let (path, sha) = recovery_input(
            &o,
            label,
            &invalid_body,
            envelope(&invalid_body),
            &o.closed_raw,
        );
        assert!(
            prepare_history_lifecycle_v1_recovery(&o.authority.store, load(&path, &sha)).is_err()
        );
        assert_eq!(journal_files(&o.authority.journal), before);
    }
    let mut forged = serde_json::from_slice::<policy::Envelope<policy::Budget>>(&renewed).unwrap();
    forged.registry_signature = "00".repeat(64);
    let mut invalid_body = body.clone();
    invalid_body.renewal_budget = Some(policy::encoded(&forged).unwrap());
    let (path, sha) = recovery_input(
        &o,
        "renewal-inner-signature",
        &invalid_body,
        envelope(&invalid_body),
        &o.closed_raw,
    );
    assert!(prepare_history_lifecycle_v1_recovery(&o.authority.store, load(&path, &sha)).is_err());
    assert_eq!(journal_files(&o.authority.journal), before);

    let mut excess_closed = o.closed.clone();
    excess_closed.user_cpu_microseconds = 4_000_001;
    excess_closed.system_cpu_microseconds = 0;
    excess_closed.reported_user_seconds = "4.000001".into();
    excess_closed.reported_system_seconds = "0".into();
    excess_closed.reported_cpu_upper_bound_ns = 4_000_003_000;
    let excess_raw = policy::encoded(&excess_closed).unwrap();
    let mut excess_body = body.clone();
    excess_body.closed_process_sha256 = policy::digest(&excess_raw);
    excess_body.allowance.cpu_ns = 8_000_000_000;
    let (path, sha) = recovery_input(
        &o,
        "renewal-cannot-cover-old-overrun",
        &excess_body,
        envelope(&excess_body),
        &excess_raw,
    );
    assert!(prepare_history_lifecycle_v1_recovery(&o.authority.store, load(&path, &sha)).is_err());
    assert_eq!(journal_files(&o.authority.journal), before);

    let (body, head) = recover_with_body(&o, body);
    o.authority.budget = renewed;
    let journal =
        journal::Journal::open_existing(&o.authority.journal, uid, &o.authority.identity, &head)
            .unwrap();
    assert_eq!(journal.observation()["spent"]["cpu_ns"], 8_000_000_000_u64);
    assert_eq!(journal.observation()["spent"]["operations"], 2);
    assert!(journal.pending().is_none());
    drop(journal);
    finish_ordinary(&o, &body, head);
}

fn envelope(body: &Authorization) -> Vec<u8> {
    let registry = signing_key_from_hex(&"11".repeat(32)).unwrap();
    let task = signing_key_from_hex(&"22".repeat(32)).unwrap();
    policy::encoded(&policy::Envelope {
        body,
        registry_signature: sign_hex(&registry, &lifecycle::message(1, body).unwrap()),
        task_signature: sign_hex(&task, &lifecycle::message(2, body).unwrap()),
    })
    .unwrap()
}

fn authorization(o: &Observed) -> Authorization {
    let now = policy::now().unwrap();
    let nonce = o.original.request_nonce + 1;
    Authorization {
        schema: "restricted-history-lifecycle-authorization-v1".into(),
        identity: o.authority.identity.clone(),
        executable_sha256: o.closed.executable_sha256.clone(),
        budget_id: o.original.budget_id.clone(),
        renewal_budget: None,
        reconciliation_id: o.authority.id(nonce),
        request_nonce: nonce,
        epoch: o.original.epoch.clone(),
        outside_anchor: o.closed.original_journal.clone(),
        operation_id: o.original.operation_id.clone(),
        intent_sha256: o.closed.intent_sha256.clone(),
        closed_process_sha256: policy::digest(&o.closed_raw),
        closure: if o.original.purpose == Purpose::Close {
            Closure::PendingClose
        } else if read(&o.control.join("crash-ready.json"))["closure"] == "settled-startup" {
            Closure::SettledStartup
        } else {
            Closure::PendingStartup
        },
        snapshot: o.closed.snapshot(),
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

fn recovery_input(
    o: &Observed,
    label: &str,
    body: &Authorization,
    signed: Vec<u8>,
    closed: &[u8],
) -> (PathBuf, String) {
    let config = json!({"schema":"restricted-history-lifecycle-input-v1","identity":o.authority.identity,
        "expected_source_commit":o.authority.identity.source_commit,"expected_executable_sha256":o.closed.executable_sha256,
        "journal_path":o.authority.journal,"outside_latest_anchor":body.outside_anchor,
        "expected_no_native_pins":o.closed.no_native.as_ref().map(|proof| &proof.pins),
        "expected_namespace_parent":o.closed.no_native.as_ref().map(|proof| &proof.namespace_parent),
        "signed":signed,"closed_process":closed});
    let path = o
        .authority
        .f
        .dir
        .path()
        .join(format!("lifecycle-{label}.json"));
    let sha = write_value(&path, &config);
    (path, sha)
}

fn load(path: &Path, sha: &str) -> ProtectedHistoryLifecycleV1Input {
    ProtectedHistoryLifecycleV1Input::load(path, rustix::process::geteuid().as_raw(), sha).unwrap()
}

fn recover(o: &Observed) -> (Authorization, Anchor) {
    let body = authorization(o);
    recover_with_body(o, body)
}

fn recover_with_body(o: &Observed, body: Authorization) -> (Authorization, Anchor) {
    let (path, sha) = recovery_input(
        o,
        &format!("authorized-{}", body.request_nonce),
        &body,
        envelope(&body),
        &o.closed_raw,
    );
    let result =
        prepare_history_lifecycle_v1_recovery(&o.authority.store, load(&path, &sha)).unwrap();
    assert_eq!(result["journal"]["pending"], Value::Null);
    assert_eq!(result["journal"]["epoch"], Value::Null);
    assert_eq!(result["new_cpu_epoch_created"], false);
    assert_eq!(result["native_initialization_executed"], false);
    assert_eq!(result["clean_close_fabricated"], false);
    assert_eq!(result["original_allowances_refunded"], false);
    assert_eq!(
        result["journal"]["spent"]["cpu_ns"].as_u64().unwrap(),
        result["prior_journal"]["spent"]["cpu_ns"].as_u64().unwrap() + body.allowance.cpu_ns
    );
    retains_prefix(&o.prefix, &o.authority.journal);
    let frozen = journal_files(&o.authority.journal);
    assert!(prepare_history_lifecycle_v1_recovery(&o.authority.store, load(&path, &sha)).is_err());
    assert_eq!(journal_files(&o.authority.journal), frozen);
    write_value(&o.control.join("authorized-recovery.json"), &result);
    (
        body,
        serde_json::from_value(result["journal"]["anchor"].clone()).unwrap(),
    )
}

fn finish_ordinary(o: &Observed, body: &Authorization, head: Anchor) {
    let a = &o.authority;
    let frontier = o
        .closed
        .actual_frontier
        .clone()
        .unwrap_or_else(|| a.genesis());
    let nonce = body.request_nonce + 1;
    let epoch = nonce;
    let mut owner = a.open("ordinary-recovery", nonce, epoch, frontier.clone(), head);
    assert_eq!(owner.initial_cpu.stored_credit_ns, 0);
    assert_eq!(actual(&owner), frontier);
    assert!(!a.store.join("initializing.json").exists());
    if let Some((dev, ino)) = o.database_identity {
        let metadata = fs::metadata(a.store.join("native.sqlite")).unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), (dev, ino));
    }
    let next = (frontier.block != a.identity.genesis).then(|| process::next_packet(a));
    let packet = next.as_ref().unwrap_or(&a.f.packet);
    let page = next
        .as_ref()
        .map_or_else(|| a.f.page.clone(), |p| process::page(a, p));
    let validation = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: nonce + 1,
        epoch,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: Some(packet),
        pair: Some((nonce + 1, nonce + 2)),
    });
    let result = owner
        .receive_with_progress(&validation, &page, CLOCK, deadline(), &|_| Ok(()))
        .unwrap();
    checked(&result, 2);
    assert!(result.known_success());
    let activation = a.grant(Grant {
        purpose: Purpose::Activation,
        nonce: nonce + 2,
        epoch,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: Some(packet),
        pair: Some((nonce + 1, nonce + 2)),
    });
    let activated = owner
        .activate_with_progress(&activation, CLOCK, deadline(), &|_| Ok(()))
        .unwrap();
    checked(&activated, 0);
    assert!(activated.known_success());
    let final_frontier = actual(&owner);
    assert_eq!(final_frontier.generation, frontier.generation + 1);
    let close = a.grant(Grant {
        purpose: Purpose::Close,
        nonce: nonce + 3,
        epoch,
        frontier: final_frontier.clone(),
        anchor: anchor(&owner),
        packet: None,
        pair: None,
    });
    let closed = owner.close(&close, deadline()).unwrap();
    let cold_anchor = serde_json::from_value(closed["journal"]["anchor"].clone()).unwrap();
    drop(owner);
    let journal = journal::Journal::open_existing(
        &a.journal,
        rustix::process::geteuid().as_raw(),
        &a.identity,
        &cold_anchor,
    )
    .unwrap();
    assert!(journal.pending().is_none());
    assert_eq!(journal.observation()["epoch"], Value::Null);
    let db = Connection::open_with_flags(
        a.store.join("native.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    assert_eq!(storage::frontier(&db).unwrap(), final_frontier);
    storage::verify_known_markers(&db, &journal, None).unwrap();
    retains_prefix(&o.prefix, &a.journal);
    let result = json!({"schema":"actual-history-lifecycle-ordinary-finished-v1",
        "source_commit":a.identity.source_commit,"closed_process":o.closed,
        "fresh_startup_credit_ns":0,"actual_validation":result,"actual_activation":activated,
        "ordinary_close":closed,"cold_journal":journal.observation(),"cold_frontier":final_frontier,
        "existing_database_inode_preserved":o.database_identity.is_some(),"native_database_deleted":false,
        "old_journal_prefix_preserved":true,"original_unknown_receipt_fabricated":false,
        "production_qualified":false});
    write_value(&o.control.join("ordinary-finished.json"), &result);
    println!(
        "HISTORY_LIFECYCLE_ACTUAL {}",
        serde_json::to_string(&result).unwrap()
    );
}

fn run(label: &str, mode: &str, expected: Database) {
    let o = observe(label, mode);
    assert_eq!(o.closed.database, expected);
    let (body, head) = recover(&o);
    finish_ordinary(&o, &body, head);
}

#[test]
fn actual_init_intent_death_preserves_absent_frontier_and_runs_ordinary_startup() {
    run(
        "lifecycle-init-intent",
        "lifecycle-init-intent",
        Database::Absent,
    );
}
#[test]
fn actual_uncommitted_initialization_death_keeps_database_inode_and_replays_startup() {
    run(
        "lifecycle-init-before-commit",
        "lifecycle-init-before-commit",
        Database::Empty,
    );
}
#[test]
fn actual_committed_initialization_death_finishes_marker_then_runs_work_and_close() {
    run(
        "lifecycle-init-committed",
        "lifecycle-init-committed",
        Database::Genesis,
    );
}
#[test]
fn actual_ready_native_pending_startup_is_reconciled_without_fabricating_success() {
    run(
        "lifecycle-startup-ready",
        "lifecycle-startup-pending-ready",
        Database::Ready,
    );
}
#[test]
fn actual_pending_close_death_keeps_existing_effects_then_runs_fresh_work() {
    run(
        "lifecycle-close-pending",
        "lifecycle-close-pending",
        Database::Ready,
    );
}
#[test]
fn actual_wrong_frontier_close_refusal_and_pending_death_keep_the_actual_frontier() {
    let o = observe(
        "lifecycle-close-wrong-frontier",
        "lifecycle-close-wrong-frontier",
    );
    assert_ne!(
        o.closed.actual_frontier.as_ref(),
        Some(&o.closed.declared_frontier)
    );
    let (body, head) = recover(&o);
    finish_ordinary(&o, &body, head);
}
#[test]
fn repeated_known_initialization_cancellation_uses_fresh_closures_without_refunds() {
    let mut o = observe(
        "lifecycle-known-cancel-twice",
        "lifecycle-startup-settled-cancel",
    );
    let (first, head) = recover(&o);
    let (control, raw, closed, original) = cut_existing(
        &o.authority,
        "second-cancellation",
        "lifecycle-startup-settled-cancel",
        first.request_nonce + 1,
        first.request_nonce + 1,
        o.authority.genesis(),
        head,
    );
    o.control = control;
    o.closed_raw = raw;
    o.closed = closed;
    o.original = original;
    let (second, head) = recover(&o);
    assert!(second.request_nonce > first.request_nonce);
    finish_ordinary(&o, &second, head);
}

#[test]
fn wrong_domain_nonce_snapshot_cpu_and_namespace_cannot_close_original_startup_debt() {
    let o = observe("lifecycle-refusals", "lifecycle-init-committed");
    let body = authorization(&o);
    let before = journal_files(&o.authority.journal);
    let mut cases = Vec::new();
    cases.push((
        "wrong-domain",
        body.clone(),
        signed(b'R', &body),
        o.closed_raw.clone(),
    ));
    let mut stale = body.clone();
    stale.request_nonce = o.original.request_nonce;
    cases.push((
        "stale-nonce",
        stale.clone(),
        envelope(&stale),
        o.closed_raw.clone(),
    ));
    let mut wrong = body.clone();
    wrong.snapshot.initializing_sha256 = Some("ab".repeat(32));
    cases.push((
        "wrong-snapshot",
        wrong.clone(),
        envelope(&wrong),
        o.closed_raw.clone(),
    ));
    let mut fake = o.closed.clone();
    fake.user_cpu_microseconds = 4_000_001;
    fake.system_cpu_microseconds = 0;
    fake.reported_user_seconds = "4.000001".into();
    fake.reported_system_seconds = "0".into();
    fake.reported_cpu_upper_bound_ns = 4_000_003_000;
    let raw = policy::encoded(&fake).unwrap();
    let mut excess = body.clone();
    excess.closed_process_sha256 = policy::digest(&raw);
    excess.allowance.cpu_ns = 8_000_000_000;
    cases.push((
        "old-scope-cpu-not-covered",
        excess.clone(),
        envelope(&excess),
        raw,
    ));
    for (label, body, signed, closed) in cases {
        let (path, sha) = recovery_input(&o, label, &body, signed, &closed);
        assert!(
            prepare_history_lifecycle_v1_recovery(&o.authority.store, load(&path, &sha)).is_err()
        );
        assert_eq!(journal_files(&o.authority.journal), before);
    }
    let unexpected = o.authority.store.join("unowned-extra-file");
    write(&unexpected, b"controlled namespace negative");
    let (path, sha) = recovery_input(&o, "unknown-entry", &body, envelope(&body), &o.closed_raw);
    assert!(prepare_history_lifecycle_v1_recovery(&o.authority.store, load(&path, &sha)).is_err());
    assert_eq!(journal_files(&o.authority.journal), before);
    fs::remove_file(unexpected).unwrap();
    let (body, head) = recover(&o);
    finish_ordinary(&o, &body, head);
}

#[test]
fn actual_lifecycle_record_publication_all_five_cuts_repair_without_native_reset() {
    for stage in [
        "file-synced",
        "linked",
        "final-synced",
        "unlinked",
        "published",
    ] {
        let o = observe(
            &format!("lifecycle-publication-{stage}"),
            "lifecycle-init-committed",
        );
        let body = authorization(&o);
        let (recovery, sha) =
            recovery_input(&o, "publication", &body, envelope(&body), &o.closed_raw);
        let control = o.authority.f.dir.path().join("publication-crash");
        fs::create_dir(&control).unwrap();
        let config = json!({"schema":"actual-history-effect-child-fixture-v6",
            "mode":format!("lifecycle-publish-{stage}"),"store":o.authority.store,"control":control,
            "page":[],"launch":null,"launch_sha256":null,"recovery":recovery,"recovery_sha256":sha});
        let mut process = guardian(&o.authority, &control, &config);
        let guardian = process::wait(&control.join("guardian-result.json"), &mut process);
        assert!(process.child.wait().unwrap().success());
        assert_eq!(guardian["passed"], true);
        let barrier = read(&control.join("crash-ready.json"));
        let candidate: Anchor = serde_json::from_value(barrier["anchor"].clone()).unwrap();
        let acknowledged: Anchor =
            serde_json::from_value(barrier["acknowledged_prefix_anchor"].clone()).unwrap();
        assert_eq!(acknowledged, body.outside_anchor);
        let pending = o
            .authority
            .journal
            .join(format!("pending-{:020}", candidate.sequence));
        let final_path = o.authority.journal.join(format!(
            "{:020}-{}.json",
            candidate.sequence, candidate.digest
        ));
        let frame = fs::read(if pending.exists() {
            &pending
        } else {
            &final_path
        })
        .unwrap();
        assert_eq!(policy::digest(&frame), candidate.digest);
        let now = policy::now().unwrap();
        let publication_body = journal::publication::Authorization {
            schema: "restricted-history-journal-publication-authorization-v1".into(),
            identity: o.authority.identity.clone(),
            prefix_anchor: acknowledged,
            published_anchor: candidate.clone(),
            frame_sha256: candidate.digest.clone(),
            frame_bytes: frame.len() as u64,
            issued_ns: now,
            expires_ns: now + 3_000_000_000_000,
        };
        let (publication_path, publication_sha) = publication::input(
            &o.authority,
            "lifecycle-publication",
            &publication_body,
            &publication::envelope(&publication_body),
            candidate.clone(),
        );
        let before = journal_files(&o.authority.journal);
        assert!(publication::repair(&publication_path, &publication_sha).is_err());
        assert_eq!(journal_files(&o.authority.journal), before);
        let publication_input = || {
            ProtectedHistoryJournalPublicationV1Input::load(
                &publication_path,
                rustix::process::geteuid().as_raw(),
                &publication_sha,
            )
            .unwrap()
        };
        let result = repair_history_lifecycle_v1_publication(
            &o.authority.store,
            load(&recovery, &sha),
            publication_input(),
        )
        .unwrap();
        assert_eq!(result["journal"]["anchor"], json!(candidate));
        assert_eq!(result["journal"]["pending"], Value::Null);
        assert_eq!(result["journal"]["epoch"], Value::Null);
        assert_eq!(fs::read(&final_path).unwrap(), frame);
        assert!(!pending.exists());
        let frozen = journal_files(&o.authority.journal);
        let retry = repair_history_lifecycle_v1_publication(
            &o.authority.store,
            load(&recovery, &sha),
            publication_input(),
        )
        .unwrap();
        assert_eq!(retry["already_published"], true);
        assert_eq!(retry["journal"], result["journal"]);
        assert_eq!(journal_files(&o.authority.journal), frozen);
        write_value(
            &control.join("dedicated-repair-result.json"),
            &json!({"result":result,"retry":retry}),
        );
        finish_ordinary(&o, &body, candidate);
    }
}

fn source_pins() -> Pins {
    Pins {
        source_commit: compiled_source().into(),
        executable_sha256: process::sha_file(&std::env::current_exe().unwrap()),
        fixture_sha256: fixture_sha(),
        guardian_sha256: policy::digest(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../scripts/ci/history_lifecycle_process_guard_v1.py"
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
    }
}

fn birth_cut(
    a: &mut TestAuthority,
    label: &str,
    mode: &str,
    nonce: u64,
    head: Anchor,
    previous: Option<&lifecycle::NoNativeProof>,
) -> (PathBuf, Vec<u8>, lifecycle::ClosedProcess, Operation) {
    let namespace = previous.map_or_else(
        || a.f.dir.path().join("lifecycle-empty-container"),
        |proof| proof.namespace_parent.clone(),
    );
    a.store = namespace.join("native");
    let control = a.f.dir.path().join(label);
    fs::create_dir(&control).unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
    let mut pins = source_pins();
    let mut unprepared = serde_json::to_value(&pins).unwrap();
    unprepared
        .as_object_mut()
        .unwrap()
        .remove("preparation_sha256");
    let prep = json!({
        "schema":"actual-history-lifecycle-no-native-preparation-v1",
        "cutpoint":mode,"source_pins":unprepared,"namespace_parent":namespace,
        "journal_path":a.journal,"expected_uid":rustix::process::geteuid().as_raw(),
        "identity":a.identity,"identity_sha256":a.identity.digest().unwrap(),
        "previous_proof":previous,
    });
    let mut process = guardian(a, &control, &prep);
    let ready = process::wait(&control.join("namespace-ready.json"), &mut process);
    pins.preparation_sha256 = previous.map_or_else(
        || process::sha_file(&control.join("child.json")),
        |proof| proof.pins.preparation_sha256.clone(),
    );
    assert_eq!(ready["pins"], json!(pins));
    assert_eq!(ready["new_namespace_created"], previous.is_none());
    if let Some(previous) = previous {
        assert_eq!(ready["birth"], json!(previous.birth));
        assert_eq!(
            ready["namespace_prepared_ns"],
            previous.namespace_prepared_ns
        );
    }
    // This original Startup is signed after the guardian really owns the
    // original birth lease. The child cannot choose its own outside anchor.
    let (launch, launch_sha) = a.launch(label, nonce, nonce, a.genesis(), head);
    let signed: Vec<u8> = serde_json::from_value(read(&launch)["signed_startup"].clone()).unwrap();
    let original = serde_json::from_slice::<policy::Envelope<Operation>>(&signed)
        .unwrap()
        .body;
    let child_path = control.join("bound-child.json");
    let child_sha = write_value(
        &child_path,
        &json!({
            "schema":"actual-history-effect-child-fixture-v6","mode":mode,"store":a.store,
            "control":control,"page":[],"launch":launch,"launch_sha256":launch_sha,
            "recovery":null,"recovery_sha256":null,"publication":null,"publication_sha256":null,
        }),
    );
    write_value(
        &control.join("outside-child.json"),
        &json!({"path":child_path,"sha256":child_sha}),
    );
    let result = process::wait(&control.join("guardian-result.json"), &mut process);
    assert!(process.child.wait().unwrap().success(), "{result}");
    assert_eq!(result["passed"], true);
    assert_eq!(result["actual_wait4"], true);
    assert_eq!(result["exact_empty_namespace_unchanged"], true);
    assert_eq!(result["new_namespace_created"], previous.is_none());
    assert_eq!(result["same_namespace_reacquired"], previous.is_some());
    let raw = fs::read(control.join("closed-process.json")).unwrap();
    let closed: lifecycle::ClosedProcess = serde_json::from_slice(&raw).unwrap();
    closed.validate().unwrap();
    assert_eq!(closed.database, Database::Absent);
    assert!(closed.actual_frontier.is_none() && closed.initializing_sha256.is_none());
    let proof = closed.no_native.as_ref().unwrap();
    assert_eq!(proof.pins, pins);
    assert_eq!(proof.birth, proof.before);
    assert_eq!(proof.before, proof.after);
    assert_eq!(json!(proof.birth), ready["birth"]);
    assert_eq!(proof.signed_startup, signed);
    assert_eq!(proof.child_configuration_sha256, child_sha);
    assert_eq!(closed.epoch, original.epoch);
    assert_eq!(
        closed.intent_sha256,
        policy::digest(&policy::message(b'I', 0, &original).unwrap())
    );
    assert_eq!(fs::read_dir(&a.store).unwrap().count(), 0);
    (control, raw, closed, original)
}

fn observe_birth(label: &str, mode: &str) -> Observed {
    let mut a =
        TestAuthority::with_source_and_budget_lifetime(compiled_source(), 3_600_000_000_000);
    let retain = process::retain_fixture(a.f.dir.path(), label);
    let initial = a.installed.clone();
    let (control, raw, closed, original) =
        birth_cut(&mut a, "first-birth-death", mode, 1, initial, None);
    let prefix = journal_files(&a.journal);
    Observed {
        _retain: retain,
        authority: a,
        control,
        closed_raw: raw,
        closed,
        original,
        prefix,
        database_identity: None,
    }
}

fn refuse_birth_config(o: &Observed, label: &str, config: &Value) -> String {
    let path = o
        .authority
        .f
        .dir
        .path()
        .join(format!("birth-refuse-{label}.json"));
    let digest = write_value(&path, config);
    let before = journal_files(&o.authority.journal);
    let result =
        ProtectedHistoryLifecycleV1Input::load(&path, rustix::process::geteuid().as_raw(), &digest)
            .and_then(|input| prepare_history_lifecycle_v1_recovery(&o.authority.store, input));
    let error = result.unwrap_err().to_string();
    assert_eq!(journal_files(&o.authority.journal), before);
    error
}

fn birth_configuration(o: &Observed, label: &str, body: &Authorization, closed: &[u8]) -> Value {
    let (path, _) = recovery_input(o, label, body, envelope(body), closed);
    read(&path)
}

fn birth_refusals(o: &Observed) {
    let body = authorization(o);
    let baseline = birth_configuration(o, "birth-baseline", &body, &o.closed_raw);
    let mut refusals = BTreeMap::new();
    for field in [
        "source_commit",
        "executable_sha256",
        "fixture_sha256",
        "guardian_sha256",
        "observer_sha256",
        "process_guard_sha256",
        "preparation_sha256",
    ] {
        let mut bad = baseline.clone();
        bad["expected_no_native_pins"][field] =
            json!("ab".repeat(if field == "source_commit" { 20 } else { 32 }));
        let label = format!("outside-{field}");
        refusals.insert(label.clone(), refuse_birth_config(o, &label, &bad));
    }
    let mut wrong_path = baseline.clone();
    wrong_path["expected_namespace_parent"] =
        json!(o.authority.f.dir.path().join("other-native-parent"));
    refusals.insert(
        "outside-path".into(),
        refuse_birth_config(o, "outside-path", &wrong_path),
    );
    let mut missing_pair = baseline.clone();
    missing_pair["expected_no_native_pins"] = Value::Null;
    refusals.insert(
        "outside-pin-pair".into(),
        refuse_birth_config(o, "outside-pin-pair", &missing_pair),
    );
    for label in [
        "missing-birth-proof",
        "no-exclusive-birth",
        "no-live-lease",
        "changed-birth-ctime",
        "changed-after-ctime",
        "original-envelope-bytes",
        "original-intent-time",
        "lease-preparation-binding",
    ] {
        let mut closed = o.closed.clone();
        if label == "missing-birth-proof" {
            closed.no_native = None;
        } else {
            let proof = closed.no_native.as_mut().unwrap();
            match label {
                "no-exclusive-birth" => proof.namespace_created_exclusively = false,
                "no-live-lease" => proof.lease_held_from_process_spawn_through_reap = false,
                "changed-birth-ctime" => proof.birth.native.changed_nanoseconds ^= 1,
                "changed-after-ctime" => proof.after.native.changed_nanoseconds ^= 1,
                "original-envelope-bytes" => {
                    let value: Value = serde_json::from_slice(&proof.signed_startup).unwrap();
                    let changed = serde_json::to_vec_pretty(&value).unwrap();
                    assert_ne!(changed, proof.signed_startup);
                    assert!(policy::operation(
                        &changed,
                        &o.authority.identity,
                        proof.startup_intent_at_ns
                    )
                    .is_ok());
                    proof.signed_startup = changed;
                }
                "original-intent-time" => proof.startup_intent_at_ns += 1,
                "lease-preparation-binding" => proof.pins.preparation_sha256 = "cd".repeat(32),
                _ => unreachable!(),
            }
        }
        let raw = policy::encoded(&closed).unwrap();
        let mut changed = body.clone();
        changed.closed_process_sha256 = policy::digest(&raw);
        let mut config = birth_configuration(o, label, &changed, &raw);
        if label == "missing-birth-proof" {
            config["expected_no_native_pins"] = Value::Null;
            config["expected_namespace_parent"] = Value::Null;
        } else if label == "lease-preparation-binding" {
            config["expected_no_native_pins"] = json!(closed.no_native.as_ref().unwrap().pins);
        }
        let error = refuse_birth_config(o, label, &config);
        if label == "lease-preparation-binding" {
            assert!(error.contains("LEASE_BINDING"), "{error}");
        }
        if label == "original-envelope-bytes" || label == "original-intent-time" {
            assert!(error.contains("NO_NATIVE_ORIGINAL_INTENT"), "{error}");
        }
        refusals.insert(label.into(), error);
    }
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .open(
            o.closed
                .no_native
                .as_ref()
                .unwrap()
                .namespace_parent
                .join("startup-namespace.lock"),
        )
        .unwrap();
    lease.try_lock_exclusive().unwrap();
    refusals.insert(
        "actual-competing-lease".into(),
        refuse_birth_config(o, "actual-competing-lease", &baseline),
    );
    drop(lease);
    write_value(&o.control.join("birth-refusals.json"), &json!(refusals));
}

#[test]
fn actual_pending_startup_before_native_uses_birth_proof_and_refuses_changed_namespace() {
    for (label, mode) in [
        (
            "lifecycle-no-native-waiting",
            "lifecycle-no-native-waiting-credit",
        ),
        (
            "lifecycle-no-native-before-node",
            "lifecycle-no-native-before-node",
        ),
    ] {
        let o = observe_birth(label, mode);
        birth_refusals(&o);
        let (body, head) = recover(&o);
        finish_ordinary(&o, &body, head);
    }
    // Changing even an empty live directory's metadata must not be presented
    // as the old witnessed birth. This isolated negative retains the debt.
    let o = observe_birth(
        "lifecycle-no-native-actual-ctime",
        "lifecycle-no-native-before-node",
    );
    let body = authorization(&o);
    let config = birth_configuration(&o, "real-ctime", &body, &o.closed_raw);
    let prior = fs::metadata(&o.authority.store).unwrap();
    std::thread::sleep(Duration::from_millis(2));
    fs::set_permissions(&o.authority.store, fs::Permissions::from_mode(0o700)).unwrap();
    let changed = fs::metadata(&o.authority.store).unwrap();
    assert_ne!(
        (prior.ctime(), prior.ctime_nsec()),
        (changed.ctime(), changed.ctime_nsec())
    );
    let error = refuse_birth_config(&o, "real-ctime", &config);
    assert!(error.contains("NAMESPACE_CHANGED"), "{error}");
    write_value(
        &o.control.join("actual-ctime-refusal.json"),
        &json!({
            "error":error,"debt_retained":true,"native_reset":false,"changed_directory_adopted":false,
        }),
    );
}

#[test]
fn repeated_pre_native_known_cancellation_reacquires_original_birth_then_runs_ordinary_work() {
    let mut o = observe_birth(
        "lifecycle-no-native-repeated-known",
        "lifecycle-no-native-settled-cancel",
    );
    let birth = o.closed.no_native.as_ref().unwrap().clone();
    let (first, head) = recover(&o);
    let (control, raw, closed, original) = birth_cut(
        &mut o.authority,
        "second-birth-cancellation",
        "lifecycle-no-native-settled-cancel",
        first.request_nonce + 1,
        head,
        Some(&birth),
    );
    retains_prefix(&o.prefix, &o.authority.journal);
    let second = closed.no_native.as_ref().unwrap();
    assert_eq!(second.birth, birth.birth);
    assert_eq!(second.namespace_prepared_ns, birth.namespace_prepared_ns);
    assert_eq!(
        second.pins.preparation_sha256,
        birth.pins.preparation_sha256
    );
    assert!(second.lease_acquired_ns > birth.process_reaped_after_ns);
    assert_ne!(second.signed_startup, birth.signed_startup);
    o.control = control;
    o.closed_raw = raw;
    o.closed = closed;
    o.original = original;
    o.prefix = journal_files(&o.authority.journal);
    let (second, head) = recover(&o);
    assert!(second.request_nonce > first.request_nonce);
    finish_ordinary(&o, &second, head);
}
