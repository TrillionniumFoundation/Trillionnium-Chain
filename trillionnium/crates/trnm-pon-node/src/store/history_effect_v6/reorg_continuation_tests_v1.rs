//! Real fork/cursor operations, real child death and separately signed retries.
//! Disclosed fixture authority is not external production authority.
use super::reorg_continuation_v1::{self as continuation, Authorization, Closure, Original};
use super::tests::*;
use super::*;
use crate::store::operator_continuous_owner::history_import::tests::fixture::CLOCK;
use policy::{Anchor, Identity, Operation, Usage};
use serde_json::json;
use std::process::{Command, Stdio};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};

fn read_wait(path: &Path) -> Value {
    let end = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(
            Instant::now() < end,
            "outside reorg fixture did not supply {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    read(path)
}
fn park(value: &Value, control: &Path) -> ! {
    write_value(&control.join("crash-ready.json"), value);
    loop {
        std::thread::park_timeout(Duration::from_secs(5));
    }
}
fn barrier(
    owner: &HistoryEffectV6,
    signed: &[u8],
    mode: &str,
    control: &Path,
    closure: Closure,
) -> ! {
    let journal = owner.owner.journal().unwrap();
    let verified = policy::operation(signed, journal.identity(), policy::now().unwrap()).unwrap();
    if closure == Closure::PendingUnknown {
        assert_eq!(
            journal.pending().unwrap().operation.operation_id,
            verified.body.operation_id
        );
    } else {
        assert!(journal.pending().is_none());
    }
    let value = json!({"schema":"actual-history-reorg-continuation-barrier-v1",
        "pid":std::process::id(),"cutpoint":mode,"closure":closure,
        "anchor":journal.anchor(),"operation_id":verified.body.operation_id,
        "intent_sha256":verified.intent_sha256,"epoch":verified.body.epoch,
        "original_cpu":owner.owner.cpu.observe().unwrap(),"journal":journal.observation(),
        "clean_close_created":false});
    drop(journal);
    park(&value, control)
}
fn startup_barrier(launch: &Path, mode: &str, control: &Path, closure: Closure) -> ! {
    let config = read(launch);
    let identity: Identity = serde_json::from_value(config["identity"].clone()).unwrap();
    let signed: Vec<u8> = serde_json::from_value(config["signed_startup"].clone()).unwrap();
    let journal = PathBuf::from(config["journal_path"].as_str().unwrap());
    let mut frames = fs::read_dir(journal)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "json"))
        .collect::<Vec<_>>();
    frames.sort();
    let raw = fs::read(frames.last().unwrap()).unwrap();
    let frame: journal::Frame = serde_json::from_slice(&raw).unwrap();
    if closure == Closure::NotStarted {
        assert!(matches!(frame.event, journal::Event::NotStarted { .. }));
    } else {
        let journal::Event::Intent { signed: actual } = &frame.event else {
            panic!("actual pending Startup required")
        };
        assert_eq!(actual, &signed);
    }
    let verified = policy::operation(&signed, &identity, policy::now().unwrap()).unwrap();
    park(
        &json!({"schema":"actual-history-reorg-continuation-barrier-v1",
        "pid":std::process::id(),"cutpoint":mode,"closure":closure,
        "anchor":Anchor{sequence:frame.sequence,digest:policy::digest(&raw)},
        "operation_id":verified.body.operation_id,"intent_sha256":verified.intent_sha256,
        "epoch":verified.body.epoch,"clean_close_created":false}),
        control,
    )
}

pub(super) fn child(config: &Value) {
    let mode = config["mode"].as_str().unwrap();
    let store = PathBuf::from(config["store"].as_str().unwrap());
    let control = PathBuf::from(config["control"].as_str().unwrap());
    let uid = rustix::process::geteuid().as_raw();
    if mode.starts_with("reorg-repair-") {
        publication::install_hook(mode, &control);
        let result = repair_history_reorg_continuation_v1_publication(
            &store,
            ProtectedHistoryReorgContinuationV1Input::load(
                Path::new(config["recovery"].as_str().unwrap()),
                uid,
                config["recovery_sha256"].as_str().unwrap(),
            )
            .unwrap(),
            ProtectedHistoryJournalPublicationV1Input::load(
                Path::new(config["publication"].as_str().unwrap()),
                uid,
                config["publication_sha256"].as_str().unwrap(),
            )
            .unwrap(),
        );
        panic!("reorg repair returned before publication barrier: {result:?}");
    }
    if mode.starts_with("reorg-publish-") {
        publication::install_hook(mode, &control);
        let result = prepare_history_reorg_continuation_v1(
            &store,
            ProtectedHistoryReorgContinuationV1Input::load(
                Path::new(config["recovery"].as_str().unwrap()),
                uid,
                config["recovery_sha256"].as_str().unwrap(),
            )
            .unwrap(),
        );
        panic!("reorg authorization returned before publication barrier: {result:?}");
    }
    let launch = PathBuf::from(config["launch"].as_str().unwrap());
    let load = || {
        ProtectedHistoryV6Input::load(&launch, uid, config["launch_sha256"].as_str().unwrap())
            .unwrap()
    };
    if mode == "reorg-startup-not-started" {
        let startup: policy::Envelope<Operation> = serde_json::from_slice(
            &serde_json::from_value::<Vec<u8>>(read(&launch)["signed_startup"].clone()).unwrap(),
        )
        .unwrap();
        let cancellation =
            HistoryEffectV6StartupCancellation::for_operation(&startup.body.operation_id).unwrap();
        cancellation.cancel();
        let error =
            HistoryEffectV6::open_with_cancellation(&store, load(), 2, deadline(), &cancellation)
                .err()
                .unwrap();
        assert_eq!(error.to_string(), "HISTORY_V6_CANCELLED");
        startup_barrier(&launch, mode, &control, Closure::NotStarted);
    }
    let mut owner = HistoryEffectV6::open_with_startup_progress(
        &store,
        load(),
        2,
        deadline(),
        None,
        &|point| {
            if mode == "reorg-startup-pending" && point == StartupProgress::BeforeSettlement {
                startup_barrier(&launch, mode, &control, Closure::PendingUnknown);
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(owner.initial_cpu.stored_credit_ns, 0);
    write_value(
        &control.join("startup-ready.json"),
        &owner.observation().unwrap(),
    );
    for step in 0..16 {
        let request = read_wait(&control.join(format!("outside-step-{step}.json")));
        let action = request["action"].as_str().unwrap();
        if action == "stop" {
            return;
        }
        let signed: Vec<u8> = serde_json::from_value(request["signed"].clone()).unwrap();
        if action == "close" {
            let closed = owner.close(&signed, deadline()).unwrap();
            write_value(&control.join(format!("step-ready-{step}.json")), &closed);
            continue;
        }
        let verified =
            policy::operation(&signed, &owner.owner.identity, policy::now().unwrap()).unwrap();
        let shared = owner.owner.clone();
        let cancellation = owner.cancellation_for(&verified.body.operation_id).unwrap();
        let observer = Mutex::new(
            Connection::open_with_flags(
                store.join("native.sqlite"),
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .unwrap(),
        );
        let cancelled = AtomicBool::new(false);
        let callback = |point| -> Result<()> {
            if action == "validation"
                && mode == "reorg-validation-pending"
                && point == Progress::BeforeSettlement
            {
                let journal = shared.journal()?;
                let pending = journal.pending().unwrap();
                let value = json!({"schema":"actual-history-reorg-continuation-barrier-v1",
                    "pid":std::process::id(),"cutpoint":mode,"closure":"pending-unknown",
                    "anchor":journal.anchor(),"operation_id":pending.operation.operation_id,
                    "intent_sha256":pending.intent_sha256,"epoch":pending.operation.epoch});
                drop(journal);
                park(&value, &control);
            }
            if action == "activation" && point == Progress::Activation {
                let row: Option<(u64, u64)> = observer
                    .lock()
                    .unwrap()
                    .query_row("SELECT cursor,done FROM reorg WHERE singleton=1", [], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .optional()?;
                let target = mode
                    .strip_prefix("reorg-cursor-")
                    .map(|s| s.parse::<u64>().unwrap());
                if row.is_some_and(|(cursor, done)| done == 0 && target == Some(cursor)) {
                    let journal = shared.journal()?;
                    let pending = journal.pending().unwrap();
                    let value = json!({"schema":"actual-history-reorg-continuation-barrier-v1",
                        "pid":std::process::id(),"cutpoint":mode,"closure":"pending-unknown",
                        "anchor":journal.anchor(),"operation_id":pending.operation.operation_id,
                        "intent_sha256":pending.intent_sha256,"epoch":pending.operation.epoch});
                    drop(journal);
                    park(&value, &control);
                }
                if mode == "reorg-cancel-cursor-1" && row == Some((1, 0)) {
                    assert!(cancellation.cancel()?);
                    cancelled.store(true, Ordering::Release);
                }
            }
            if action == "activation"
                && mode == "reorg-final-commit"
                && point == Progress::BeforeSettlement
            {
                let journal = shared.journal()?;
                let pending = journal.pending().unwrap();
                let value = json!({"schema":"actual-history-reorg-continuation-barrier-v1",
                    "pid":std::process::id(),"cutpoint":mode,"closure":"pending-unknown",
                    "anchor":journal.anchor(),"operation_id":pending.operation.operation_id,
                    "intent_sha256":pending.intent_sha256,"epoch":pending.operation.epoch});
                drop(journal);
                park(&value, &control);
            }
            Ok(())
        };
        let result = if action == "validation" {
            let page: Vec<u8> = serde_json::from_value(request["page"].clone()).unwrap();
            owner
                .receive_with_progress(&signed, &page, CLOCK, deadline(), &callback)
                .unwrap()
        } else {
            assert_eq!(action, "activation");
            owner
                .activate_with_progress(&signed, CLOCK, deadline(), &callback)
                .unwrap()
        };
        if cancelled.load(Ordering::Acquire) {
            checked(&result, 0);
            assert_eq!(result.native_error.as_deref(), Some("HISTORY_V6_CANCELLED"));
            assert!(result.operation_closed);
            assert!(owner.owner.unavailable.load(Ordering::Acquire));
            barrier(&owner, &signed, mode, &control, Closure::SettledKnown);
        }
        assert!(
            result.known_success(),
            "{}",
            serde_json::to_string(&result).unwrap()
        );
        write_value(
            &control.join(format!("step-ready-{step}.json")),
            &json!({"result":result,"observation":owner.observation().unwrap(),"frontier":actual(&owner)}),
        );
    }
    panic!("reorg fixture exhausted its finite control program");
}

fn original(a: &TestAuthority, operation: &str) -> Original {
    for entry in fs::read_dir(&a.journal).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let frame: journal::Frame = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        if let journal::Event::Intent { signed } = frame.event {
            let verified = policy::operation(&signed, &a.identity, frame.at_ns).unwrap();
            if verified.body.operation_id == operation {
                return Original {
                    operation: verified.body,
                    intent_sha256: verified.intent_sha256,
                    envelope_sha256: policy::digest(&signed),
                    intent_at_ns: frame.at_ns,
                };
            }
        }
    }
    panic!("original retained Intent missing for {operation}");
}
fn fork_packet(a: &TestAuthority) -> Packet {
    let mut producer =
        Node::open(&a.f.dir.path().join("producer"), a.f.settings.clone(), 2).unwrap();
    let rows = a.f.material_inputs();
    let material =
        |role: &str| fs::read(&rows.iter().find(|r| r.role == role).unwrap().path).unwrap();
    let model = material("model");
    let input = material("input");
    let (am, bm) = derive_matrices(&model, &input).unwrap();
    let boot = a.f.settings.bootstrap_lifecycle_task().unwrap();
    let material = TaskMaterial {
        model: &model,
        input: &input,
        a: &am,
        b: &bm,
    };
    let admission =
        trnm_crypto_primitives::qualified_work_task::lifecycle_v2::verify_lifecycle_admission(
            &boot.signed.encode().unwrap(),
            material,
            &boot.lease,
            1,
        )
        .unwrap();
    let prepared = producer
        .prepare_with_task(
            a.f.settings.genesis(),
            a.f.packet.transactions.clone(),
            a.f.packet.header.miner,
            a.f.packet.header.timestamp + 1,
            4096,
            &admission,
            TaskMaterial {
                model: &model,
                input: &input,
                a: &am,
                b: &bm,
            },
        )
        .unwrap();
    let packet = prepared
        .search_owned_window(1, 4096, &|| Ok(()))
        .unwrap()
        .packet
        .unwrap();
    assert_ne!(packet.id().unwrap(), a.f.packet.id().unwrap());
    producer.admit(&packet, CLOCK).unwrap();
    packet
}
fn prepare_fork(a: &TestAuthority) -> (Packet, Frontier, Anchor) {
    let fork = fork_packet(a);
    let target = process::next_packet(a);
    let mut owner = a.open("fork-parent", 1, 1, a.genesis(), a.installed.clone());
    for (nonce, packet, pair) in [(2, &a.f.packet, (2, 3)), (4, &fork, (4, 5))] {
        let signed = a.grant(Grant {
            purpose: Purpose::Validation,
            nonce,
            epoch: 1,
            frontier: actual(&owner),
            anchor: anchor(&owner),
            packet: Some(packet),
            pair: Some(pair),
        });
        let result = owner
            .receive_with_progress(
                &signed,
                &process::page(a, packet),
                CLOCK,
                deadline(),
                &|_| Ok(()),
            )
            .unwrap();
        checked(&result, 2);
        assert!(result.known_success());
    }
    let signed = a.grant(Grant {
        purpose: Purpose::Activation,
        nonce: 5,
        epoch: 1,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: Some(&fork),
        pair: Some((4, 5)),
    });
    let activated = owner
        .activate_with_progress(&signed, CLOCK, deadline(), &|_| Ok(()))
        .unwrap();
    checked(&activated, 0);
    assert!(activated.known_success());
    let frontier = actual(&owner);
    let signed = a.grant(Grant {
        purpose: Purpose::Close,
        nonce: 6,
        epoch: 1,
        frontier: frontier.clone(),
        anchor: anchor(&owner),
        packet: None,
        pair: None,
    });
    let closed = owner.close(&signed, deadline()).unwrap();
    let outside = serde_json::from_value(closed["journal"]["anchor"].clone()).unwrap();
    (target, frontier, outside)
}

struct Run {
    process: process::Process,
    control: PathBuf,
    next_step: usize,
}
impl Run {
    fn send(&mut self, request: Value) -> usize {
        let step = self.next_step;
        self.next_step += 1;
        write_value(
            &self.control.join(format!("outside-step-{step}.json")),
            &request,
        );
        step
    }
    fn result(&mut self, step: usize) -> Value {
        process::wait(
            &self.control.join(format!("step-ready-{step}.json")),
            &mut self.process,
        )
    }
    fn startup(&mut self) -> Value {
        process::wait(&self.control.join("startup-ready.json"), &mut self.process)
    }
    fn killed(&mut self) -> Vec<u8> {
        let observed = process::wait(
            &self.control.join("guardian-result.json"),
            &mut self.process,
        );
        assert!(self.process.child.wait().unwrap().success(), "{observed}");
        assert_eq!(observed["passed"], true);
        let raw = fs::read(self.control.join("closed-process.json")).unwrap();
        serde_json::from_slice::<policy::ClosedProcess>(&raw)
            .unwrap()
            .validate()
            .unwrap();
        raw
    }
    fn stop(&mut self) {
        self.send(json!({"action":"stop"}));
        assert!(self.process.child.wait().unwrap().success());
    }
}
fn spawn_config(
    a: &TestAuthority,
    label: &str,
    mode: &str,
    mut config: Value,
    guardian: bool,
) -> Run {
    let control = a.f.dir.path().join(format!("reorg-control-{label}"));
    fs::create_dir(&control).unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
    config["schema"] = json!("actual-history-effect-child-fixture-v6");
    config["mode"] = json!(mode);
    config["store"] = json!(a.store);
    config["control"] = json!(control);
    config["page"] = json!([]);
    let path = a.f.dir.path().join(format!("reorg-child-{label}.json"));
    let sha = write_value(&path, &config);
    let binary = std::env::current_exe().unwrap();
    let log = File::create(control.join("controller.log")).unwrap();
    let child = if guardian {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../scripts/ci/history_reorg_continuation_process_guard_v1.py");
        assert_eq!(
            process::sha_file(&script),
            policy::digest(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../scripts/ci/history_reorg_continuation_process_guard_v1.py"
            )))
        );
        Command::new("python3")
            .arg(script)
            .arg("--binary")
            .arg(&binary)
            .args([
                "--binary-sha256",
                &process::sha_file(&binary),
                "--configuration",
            ])
            .arg(path)
            .args(["--configuration-sha256", &sha, "--directory"])
            .arg(&control)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap()
    } else {
        Command::new(&binary)
            .args([
                "store::history_effect_v6::tests::history_effect_v6_process_child_helper",
                "--exact",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("TRNM_HISTORY_V6_CHILD_CONFIG", path)
            .env("TRNM_HISTORY_V6_CHILD_CONFIG_SHA256", sha)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap()
    };
    Run {
        process: process::Process { child, guardian },
        control,
        next_step: 0,
    }
}
fn spawn(
    a: &TestAuthority,
    label: &str,
    mode: &str,
    nonce: u64,
    epoch: u64,
    frontier: Frontier,
    outside: Anchor,
) -> Run {
    // Every interruption mode belongs to the external death observer. Only
    // the ordinary successful continuation runs without that guardian.
    let guardian = mode != "reorg-resume";
    let (launch, sha) = a.launch(&format!("reorg-{label}"), nonce, epoch, frontier, outside);
    spawn_config(
        a,
        label,
        mode,
        json!({"launch":launch,"launch_sha256":sha,"recovery":null,
        "recovery_sha256":null}),
        guardian,
    )
}
fn validation(
    a: &TestAuthority,
    run: &mut Run,
    nonce: u64,
    epoch: u64,
    frontier: Frontier,
    outside: Anchor,
    target: &Packet,
) -> usize {
    let signed = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce,
        epoch,
        frontier,
        anchor: outside,
        packet: Some(target),
        pair: Some((nonce, nonce + 1)),
    });
    run.send(json!({"action":"validation","signed":signed,"page":process::page(a,target)}))
}
fn activation(
    a: &TestAuthority,
    run: &mut Run,
    nonce: u64,
    epoch: u64,
    frontier: Frontier,
    outside: Anchor,
    target: &Packet,
) -> usize {
    let signed = a.grant(Grant {
        purpose: Purpose::Activation,
        nonce,
        epoch,
        frontier,
        anchor: outside,
        packet: Some(target),
        pair: Some((nonce - 1, nonce)),
    });
    run.send(json!({"action":"activation","signed":signed}))
}
fn known_result(value: &Value, workers: u64) {
    assert_eq!(
        value["result"]["accounting_record_persisted"], true,
        "{value}"
    );
    assert_eq!(value["result"]["operation_closed"], true, "{value}");
    assert_eq!(
        value["result"]["within_original_allowance"], true,
        "{value}"
    );
    assert_eq!(value["result"]["native_error"], Value::Null, "{value}");
    let cpu = &value["result"]["cpu"];
    for key in [
        "spawned_workers",
        "started_workers",
        "finished_workers",
        "known_workers",
    ] {
        assert_eq!(cpu[key], workers, "{value}");
    }
    assert!(cpu["total_cpu_ns"].as_u64().unwrap() > 0);
}
fn first_crash(
    a: &TestAuthority,
    mode: &str,
    target: &Packet,
    frontier: Frontier,
    outside: Anchor,
) -> Vec<u8> {
    let mut run = spawn(a, "first", mode, 7, 2, frontier.clone(), outside);
    let started = run.startup();
    let step = validation(
        a,
        &mut run,
        8,
        2,
        frontier.clone(),
        serde_json::from_value(started["journal"]["anchor"].clone()).unwrap(),
        target,
    );
    let validated = run.result(step);
    known_result(&validated, 2);
    activation(
        a,
        &mut run,
        9,
        2,
        frontier,
        serde_json::from_value(validated["observation"]["journal"]["anchor"].clone()).unwrap(),
        target,
    );
    run.killed()
}
fn envelope(body: &Authorization) -> Vec<u8> {
    policy::encoded(&policy::Envelope {
        body,
        registry_signature: sign_hex(
            &signing_key_from_hex(&"11".repeat(32)).unwrap(),
            &continuation::message(1, body).unwrap(),
        ),
        task_signature: sign_hex(
            &signing_key_from_hex(&"22".repeat(32)).unwrap(),
            &continuation::message(2, body).unwrap(),
        ),
    })
    .unwrap()
}
fn authorization(
    a: &TestAuthority,
    closed_raw: &[u8],
    root: &Original,
    previous: Option<String>,
    closure: Closure,
    nonce: u64,
    next_epoch: u64,
) -> Authorization {
    let closed: policy::ClosedProcess = serde_json::from_slice(closed_raw).unwrap();
    let db = Connection::open_with_flags(
        a.store.join("native.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.execute_batch("PRAGMA query_only=ON; BEGIN;").unwrap();
    let snapshot = continuation::snapshot(&db, &mut || Ok(())).unwrap();
    let current = fs::read_dir(&a.journal)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .find_map(|p| {
            let frame: journal::Frame = serde_json::from_slice(&fs::read(p).unwrap()).unwrap();
            let journal::Event::Intent { signed } = frame.event else {
                return None;
            };
            let op = policy::operation(&signed, &a.identity, frame.at_ns).unwrap();
            (op.intent_sha256 == closed.intent_sha256).then_some(op.body.operation_id)
        })
        .unwrap();
    let now = policy::now().unwrap();
    Authorization {
        schema: "restricted-history-reorg-continuation-authorization-v1".into(),
        identity: a.identity.clone(),
        executable_sha256: closed.executable_sha256.clone(),
        budget_id: serde_json::from_slice::<policy::Envelope<policy::Budget>>(&a.budget)
            .unwrap()
            .body
            .budget_id,
        renewal_budget: None,
        continuation_id: a.id(nonce),
        previous_continuation_id: previous,
        request_nonce: nonce,
        outside_anchor: closed.original_journal.clone(),
        closure,
        closed_operation_id: current,
        closed_intent_sha256: closed.intent_sha256.clone(),
        closed_epoch: closed.epoch.clone(),
        closed_process_sha256: policy::digest(closed_raw),
        original: root.clone(),
        snapshot,
        next_epoch: a.epoch(next_epoch),
        startup_operation_id: a.id(nonce + 1),
        validation_operation_id: a.id(nonce + 2),
        activation_operation_id: a.id(nonce + 3),
        allowance: Usage {
            cpu_ns: 4_000_000_000,
            material_bytes: 0,
            received_bytes: 0,
            operations: 1,
        },
        issued_ns: now,
        expires_ns: now + 3_600_000_000_000,
    }
}
fn input(a: &TestAuthority, label: &str, body: &Authorization, closed: &[u8]) -> (PathBuf, String) {
    let path =
        a.f.dir
            .path()
            .join(format!("reorg-authorization-{label}.json"));
    let sha = write_value(
        &path,
        &json!({"schema":"restricted-history-reorg-continuation-input-v1","identity":a.identity,
        "expected_source_commit":a.identity.source_commit,"expected_executable_sha256":body.executable_sha256,
        "journal_path":a.journal,"outside_latest_anchor":body.outside_anchor,"signed":envelope(body),"closed_process":closed}),
    );
    (path, sha)
}
fn prepare(a: &TestAuthority, path: &Path, sha: &str) -> Result<Value> {
    prepare_history_reorg_continuation_v1(
        &a.store,
        ProtectedHistoryReorgContinuationV1Input::load(
            path,
            rustix::process::geteuid().as_raw(),
            sha,
        )?,
    )
}
fn records(a: &TestAuthority) -> BTreeMap<String, String> {
    fs::read_dir(&a.journal)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap() != "owner.lock")
        .map(|p| {
            (
                p.file_name().unwrap().to_str().unwrap().to_owned(),
                process::sha_file(&p),
            )
        })
        .collect()
}
fn negatives(a: &TestAuthority, body: &Authorization, closed: &[u8]) {
    let before = records(a);
    let mut cases = Vec::new();
    for (label, change) in [
        ("cursor", 0),
        ("steps", 1),
        ("staging", 2),
        ("target", 3),
        ("old-root", 4),
        ("origin", 5),
        ("old-nonce", 6),
        ("allowance", 7),
        ("used-op", 8),
        ("used-epoch", 9),
        ("closure", 10),
        ("prior", 11),
        ("expired-authority", 12),
    ] {
        let mut bad = body.clone();
        match change {
            0 => bad.snapshot.cursor = (bad.snapshot.cursor + 1) % (bad.snapshot.steps + 1),
            1 => bad.snapshot.steps_sha256 = "ab".repeat(32),
            2 => bad.snapshot.staging_sha256 = "cd".repeat(32),
            3 => bad.snapshot.target = "ef".repeat(32),
            4 => bad.snapshot.old_frontier.root = "ab".repeat(32),
            5 => bad.original.intent_sha256 = "ab".repeat(32),
            6 => bad.request_nonce = 1,
            7 => bad.allowance.cpu_ns = 1,
            8 => bad.startup_operation_id = a.id(1),
            9 => bad.next_epoch = a.epoch(1),
            10 => {
                bad.closure = if bad.closure == Closure::PendingUnknown {
                    Closure::SettledKnown
                } else {
                    Closure::PendingUnknown
                }
            }
            11 => bad.previous_continuation_id = Some("ab".repeat(32)),
            12 => {
                bad.issued_ns = 0;
                bad.expires_ns = 1;
            }
            _ => unreachable!(),
        }
        let (path, sha) = input(a, label, &bad, closed);
        let error = prepare(a, &path, &sha).unwrap_err().to_string();
        assert_eq!(records(a), before, "{label}");
        cases.push(json!({"case":label,"error":error,"journal_unchanged":true}));
    }
    write_value(
        &a.f.dir.path().join("reorg-negative-controls.json"),
        &json!(cases),
    );
}
fn finish_attempt(
    a: &TestAuthority,
    target: &Packet,
    body: &Authorization,
    prepared: &Value,
    epoch: u64,
) -> Value {
    let first = body.request_nonce + 1;
    let mut run = spawn(
        a,
        &format!("finish-{first}"),
        "reorg-resume",
        first,
        epoch,
        body.snapshot.old_frontier.clone(),
        serde_json::from_value(prepared["journal"]["anchor"].clone()).unwrap(),
    );
    let started = run.startup();
    let step = validation(
        a,
        &mut run,
        first + 1,
        epoch,
        body.snapshot.old_frontier.clone(),
        serde_json::from_value(started["journal"]["anchor"].clone()).unwrap(),
        target,
    );
    let validated = run.result(step);
    known_result(&validated, 0);
    let step = activation(
        a,
        &mut run,
        first + 2,
        epoch,
        body.snapshot.old_frontier.clone(),
        serde_json::from_value(validated["observation"]["journal"]["anchor"].clone()).unwrap(),
        target,
    );
    let activated = run.result(step);
    known_result(&activated, 0);
    assert_eq!(activated["frontier"]["block"], body.snapshot.target);
    assert_eq!(
        activated["frontier"]["generation"],
        body.snapshot.generation
    );
    assert!(activated["observation"]["journal"]["reorg_continuation_v1"].is_null());
    let frontier: Frontier = serde_json::from_value(activated["frontier"].clone()).unwrap();
    let signed = a.grant(Grant {
        purpose: Purpose::Close,
        nonce: first + 3,
        epoch,
        frontier: frontier.clone(),
        anchor: serde_json::from_value(activated["observation"]["journal"]["anchor"].clone())
            .unwrap(),
        packet: None,
        pair: None,
    });
    let step = run.send(json!({"action":"close","signed":signed}));
    let closed = run.result(step);
    run.stop();
    let mut cold = a.open(
        &format!("cold-{first}"),
        first + 4,
        epoch + 1,
        frontier.clone(),
        serde_json::from_value(closed["journal"]["anchor"].clone()).unwrap(),
    );
    assert_eq!(cold.initial_cpu.stored_credit_ns, 0);
    assert_eq!(actual(&cold), frontier);
    let signed = a.grant(Grant {
        purpose: Purpose::Close,
        nonce: first + 5,
        epoch: epoch + 1,
        frontier,
        anchor: anchor(&cold),
        packet: None,
        pair: None,
    });
    let final_close = cold.close(&signed, deadline()).unwrap();
    json!({"activated":activated,"closed":closed,"cold_closed":final_close})
}
fn compiled_source() -> &'static str {
    let Some(source) = option_env!("TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT") else {
        panic!("exact-source History runner must pin the actual compile source");
    };
    policy::id(source, 20).unwrap();
    assert_eq!(
        std::env::var("TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT").unwrap(),
        source
    );
    source
}
fn authority() -> TestAuthority {
    TestAuthority::with_source_and_budget_lifetime(compiled_source(), 3_600_000_000_000)
}
#[test]
fn partial_reorg_intent_and_each_committed_cursor_recover_with_fresh_paid_attempt() {
    for cursor in 0..=3 {
        let a = authority();
        let _retain = process::retain_fixture(a.f.dir.path(), &format!("reorg-cursor-{cursor}"));
        let (target, frontier, outside) = prepare_fork(&a);
        let closed = first_crash(
            &a,
            &format!("reorg-cursor-{cursor}"),
            &target,
            frontier,
            outside,
        );
        write(
            &a.f.dir.path().join("original-closed-process.json"),
            &closed,
        );
        let root = original(&a, &a.id(9));
        let body = authorization(&a, &closed, &root, None, Closure::PendingUnknown, 10, 3);
        assert_eq!(body.snapshot.cursor, cursor);
        assert_eq!(body.snapshot.steps, 3);
        if cursor == 0 {
            negatives(&a, &body, &closed);
        }
        let before = records(&a);
        let (path, sha) = input(&a, "first", &body, &closed);
        let prepared = prepare(&a, &path, &sha).unwrap();
        for (name, sha) in before {
            assert_eq!(records(&a).get(&name), Some(&sha));
        }
        assert_eq!(prepared["journal"]["spent"]["cpu_ns"], 36_000_000_000u64);
        let finished = finish_attempt(&a, &target, &body, &prepared, 3);
        let final_records = records(&a);
        assert!(prepare(&a, &path, &sha).is_err());
        assert_eq!(records(&a), final_records);
        write_value(
            &a.f.dir.path().join("reorg-result.json"),
            &json!({"cursor":cursor,"prepared":prepared,"finished":finished,
            "whole_history_p0_closed":false,"partial_initialization_qualified":false}),
        );
    }
}

fn interrupted_attempt(
    a: &TestAuthority,
    target: &Packet,
    body: &Authorization,
    prepared: &Value,
    mode: &str,
    epoch: u64,
) -> Vec<u8> {
    let first = body.request_nonce + 1;
    let mut run = spawn(
        a,
        &format!("retry-cut-{first}"),
        mode,
        first,
        epoch,
        body.snapshot.old_frontier.clone(),
        serde_json::from_value(prepared["journal"]["anchor"].clone()).unwrap(),
    );
    if mode.starts_with("reorg-startup-") {
        return run.killed();
    }
    let started = run.startup();
    let step = validation(
        a,
        &mut run,
        first + 1,
        epoch,
        body.snapshot.old_frontier.clone(),
        serde_json::from_value(started["journal"]["anchor"].clone()).unwrap(),
        target,
    );
    if mode == "reorg-validation-pending" {
        return run.killed();
    }
    let validated = run.result(step);
    known_result(&validated, 0);
    activation(
        a,
        &mut run,
        first + 2,
        epoch,
        body.snapshot.old_frontier.clone(),
        serde_json::from_value(validated["observation"]["journal"]["anchor"].clone()).unwrap(),
        target,
    );
    run.killed()
}
#[test]
fn reorg_continuation_known_cancel_and_pending_startup_validation_each_require_new_authority() {
    for (mode, closure) in [
        ("reorg-cancel-cursor-1", Closure::SettledKnown),
        ("reorg-startup-pending", Closure::PendingUnknown),
        ("reorg-validation-pending", Closure::PendingUnknown),
        ("reorg-startup-not-started", Closure::NotStarted),
    ] {
        let a = authority();
        let _retain = process::retain_fixture(a.f.dir.path(), mode);
        let (target, frontier, outside) = prepare_fork(&a);
        let closed = first_crash(&a, "reorg-cursor-0", &target, frontier, outside);
        let root = original(&a, &a.id(9));
        let first = authorization(&a, &closed, &root, None, Closure::PendingUnknown, 10, 3);
        let (path, sha) = input(&a, "first", &first, &closed);
        let prepared = prepare(&a, &path, &sha).unwrap();
        let interrupted = interrupted_attempt(&a, &target, &first, &prepared, mode, 3);
        let after_interruption = records(&a);
        let actual_closed: policy::ClosedProcess = serde_json::from_slice(&interrupted).unwrap();
        let (reuse, sha) = a.launch(
            "reorg-same-permit-refused",
            11,
            3,
            first.snapshot.old_frontier.clone(),
            actual_closed.original_journal.clone(),
        );
        let refused = HistoryEffectV6::open(
            &a.store,
            ProtectedHistoryV6Input::load(&reuse, rustix::process::geteuid().as_raw(), &sha)
                .unwrap(),
            2,
            deadline(),
        );
        assert!(refused.is_err());
        assert_eq!(records(&a), after_interruption);
        let second = authorization(
            &a,
            &interrupted,
            &root,
            Some(first.continuation_id.clone()),
            closure,
            14,
            4,
        );
        assert!(second.snapshot.same_plan(&first.snapshot));
        assert_eq!(
            second.snapshot.cursor,
            if closure == Closure::SettledKnown {
                1
            } else {
                0
            }
        );
        // The prior Validation name may still be unused after a Startup cut.
        // It nonetheless belongs to that attempt and cannot move to the next.
        let mut recycled = second.clone();
        recycled.validation_operation_id = first.validation_operation_id.clone();
        let (path, sha) = input(&a, "recycled-phase", &recycled, &interrupted);
        let refusal = prepare(&a, &path, &sha).unwrap_err().to_string();
        assert_eq!(refusal, "HISTORY_REORG_V1_FRESH_ATTEMPT_IDS");
        assert_eq!(records(&a), after_interruption);
        let (path, sha) = input(&a, "second", &second, &interrupted);
        let again = prepare(&a, &path, &sha).unwrap();
        for (name, sha) in after_interruption {
            assert_eq!(records(&a).get(&name), Some(&sha));
        }
        assert_eq!(again["journal"]["reorg_continuations_v1"], 2);
        let final_result = finish_attempt(&a, &target, &second, &again, 4);
        write_value(
            &a.f.dir.path().join("reorg-retry-result.json"),
            &json!({"mode":mode,"closure":closure,
            "first":prepared,"second":again,"finished":final_result,"same_permit_reused":false,
            "old_allowances_refunded":false,"whole_history_p0_closed":false}),
        );
    }
}

#[test]
fn reorg_final_native_marker_survives_crash_before_settlement_and_clears_permit() {
    let a = authority();
    let _retain = process::retain_fixture(a.f.dir.path(), "reorg-final-marker");
    let (target, frontier, outside) = prepare_fork(&a);
    let closed = first_crash(&a, "reorg-cursor-0", &target, frontier, outside);
    let root = original(&a, &a.id(9));
    let body = authorization(&a, &closed, &root, None, Closure::PendingUnknown, 10, 3);
    let (path, sha) = input(&a, "first", &body, &closed);
    let prepared = prepare(&a, &path, &sha).unwrap();
    let closed = interrupted_attempt(&a, &target, &body, &prepared, "reorg-final-commit", 3);
    let closed_process: policy::ClosedProcess = serde_json::from_slice(&closed).unwrap();
    assert_eq!(
        closed_process.marker.as_ref().unwrap().operation_id,
        a.id(13)
    );
    let original = original(&a, &a.id(13));
    let now = policy::now().unwrap();
    let recovery = policy::Recovery {
        schema: "restricted-history-effect-reconciliation-v6".into(),
        identity: a.identity.clone(),
        pending_operation_id: a.id(13),
        intent_sha256: original.intent_sha256,
        request_nonce: 14,
        outside_anchor: closed_process.original_journal.clone(),
        closed_process_sha256: policy::digest(&closed),
        actual_frontier: closed_process.actual_frontier.clone(),
        marker_sha256: closed_process
            .marker
            .as_ref()
            .map(|m| policy::digest(&policy::encoded(m).unwrap())),
        issued_ns: now,
        expires_ns: now + 3_600_000_000_000,
    };
    let recovery_path = a.f.dir.path().join("reorg-final-recovery.json");
    let sha = write_value(
        &recovery_path,
        &json!({"schema":"restricted-history-effect-recovery-input-v6",
        "identity":a.identity,"journal_path":a.journal,"outside_latest_anchor":closed_process.original_journal,
        "recovery":{"signed":signed(b'R',&recovery),"closed_process":closed}}),
    );
    let reconciled = prepare_history_effect_v6_recovery(
        &a.store,
        ProtectedHistoryV6RecoveryInput::load(
            &recovery_path,
            rustix::process::geteuid().as_raw(),
            &sha,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(reconciled["journal"]["reorg_continuation_v1"].is_null());
    let mut owner = a.open(
        "reorg-published-cold",
        15,
        4,
        closed_process.actual_frontier,
        serde_json::from_value(reconciled["journal"]["anchor"].clone()).unwrap(),
    );
    assert_eq!(owner.initial_cpu.stored_credit_ns, 0);
    assert_eq!(actual(&owner).block, hex::encode(target.id().unwrap()));
    let grant = a.grant(Grant {
        purpose: Purpose::Close,
        nonce: 16,
        epoch: 4,
        frontier: actual(&owner),
        anchor: anchor(&owner),
        packet: None,
        pair: None,
    });
    let final_close = owner.close(&grant, deadline()).unwrap();
    write_value(
        &a.f.dir.path().join("reorg-final-marker-result.json"),
        &json!({"reconciled":reconciled,"closed":final_close,
        "old_effect_repeated":false,"whole_history_p0_closed":false}),
    );
}

#[test]
fn reorg_snapshot_streams_the_original_complete_state_capacity_above_32_mib() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(&StateBackend::HistoryEffectV6.ddl())
        .unwrap();
    let old = [1u8; 32];
    let target = [2u8; 32];
    let root = [3u8; 32];
    db.execute(
        "INSERT INTO blocks VALUES(?,NULL,0,?,NULL,?)",
        params![old.as_slice(), [0u8; 64].as_slice(), root.as_slice()],
    )
    .unwrap();
    db.execute(
        "INSERT INTO blocks VALUES(?,?,1,?,NULL,?)",
        params![
            target.as_slice(),
            old.as_slice(),
            [1u8; 64].as_slice(),
            root.as_slice()
        ],
    )
    .unwrap();
    db.execute("INSERT INTO active VALUES(1,?,0,0)", [old.as_slice()])
        .unwrap();
    db.execute(
        "INSERT INTO reorg VALUES(1,?,?,1,0,0)",
        params![old.as_slice(), target.as_slice()],
    )
    .unwrap();
    db.execute("INSERT INTO steps VALUES(0,1,?)", [target.as_slice()])
        .unwrap();
    let raw = serde_json::to_vec(&"x".repeat(4094)).unwrap();
    assert_eq!(raw.len(), 4096);
    let tx = db.unchecked_transaction().unwrap();
    for index in 0..8193 {
        tx.execute(
            "INSERT INTO kv VALUES(1,?,?)",
            params![format!("key-{index:08}"), raw],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let first = continuation::snapshot(&db, &mut || Ok(())).unwrap();
    let mut checkpoints = 0usize;
    let second = continuation::snapshot(&db, &mut || {
        checkpoints += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(first, second);
    assert!(checkpoints >= 8193);
    db.execute(
        "UPDATE kv SET value=? WHERE key='key-00000000'",
        [vec![b' '; 4097]],
    )
    .unwrap();
    assert!(continuation::snapshot(&db, &mut || Ok(()))
        .unwrap_err()
        .to_string()
        .contains("STAGING_LIMIT"));
}

#[test]
fn reorg_permit_every_publication_cut_repairs_exact_bytes_and_runs_once() {
    for stage in [
        "file-synced",
        "linked",
        "final-synced",
        "unlinked",
        "published",
    ] {
        let a = authority();
        let _retain = process::retain_fixture(a.f.dir.path(), &format!("reorg-publish-{stage}"));
        let (target, frontier, outside) = prepare_fork(&a);
        let closed = first_crash(&a, "reorg-cursor-1", &target, frontier, outside);
        let root = original(&a, &a.id(9));
        let body = authorization(&a, &closed, &root, None, Closure::PendingUnknown, 10, 3);
        let (path, sha) = input(&a, "first", &body, &closed);
        let mut run = spawn_config(
            &a,
            "publish",
            &format!("reorg-publish-{stage}"),
            json!({"launch":null,"launch_sha256":null,"recovery":path,"recovery_sha256":sha}),
            true,
        );
        let observed = process::wait(&run.control.join("guardian-result.json"), &mut run.process);
        assert!(run.process.child.wait().unwrap().success(), "{observed}");
        assert_eq!(observed["passed"], true);
        assert_eq!(observed["v6_closed_process_receipt_created"], false);
        assert!(!run.control.join("closed-process.json").exists());
        let barrier = read(&run.control.join("crash-ready.json"));
        let published: Anchor = serde_json::from_value(barrier["anchor"].clone()).unwrap();
        let pending = a
            .journal
            .join(format!("pending-{:020}", published.sequence));
        let final_path = a.journal.join(format!(
            "{:020}-{}.json",
            published.sequence, published.digest
        ));
        let raw = fs::read(if pending.exists() {
            &pending
        } else {
            &final_path
        })
        .unwrap();
        assert_eq!(policy::digest(&raw), published.digest);
        let frame: journal::Frame = serde_json::from_slice(&raw).unwrap();
        assert_eq!(frame.schema, continuation::RECORD_SCHEMA);
        let now = policy::now().unwrap();
        let pub_body = journal::publication::Authorization {
            schema: "restricted-history-journal-publication-authorization-v1".into(),
            identity: a.identity.clone(),
            prefix_anchor: body.outside_anchor.clone(),
            published_anchor: published.clone(),
            frame_sha256: policy::digest(&raw),
            frame_bytes: raw.len() as u64,
            issued_ns: now,
            expires_ns: now + 3_600_000_000_000,
        };
        let (pub_path, pub_sha) = publication::input(
            &a,
            "reorg",
            &pub_body,
            &publication::envelope(&pub_body),
            published.clone(),
        );
        let before = records(&a);
        assert!(publication::repair(&pub_path, &pub_sha)
            .unwrap_err()
            .to_string()
            .contains("REORG_V1_PUBLICATION_VALIDATION_REQUIRED"));
        assert_eq!(records(&a), before);
        let repair = || {
            repair_history_reorg_continuation_v1_publication(
                &a.store,
                ProtectedHistoryReorgContinuationV1Input::load(
                    &path,
                    rustix::process::geteuid().as_raw(),
                    &sha,
                )
                .unwrap(),
                ProtectedHistoryJournalPublicationV1Input::load(
                    &pub_path,
                    rustix::process::geteuid().as_raw(),
                    &pub_sha,
                )
                .unwrap(),
            )
            .unwrap()
        };
        if stage == "file-synced" {
            // Re-crash the specialized repair while its original frame and
            // conservative predebit are still becoming durably visible.
            for repair_stage in ["linked", "unlinked"] {
                let mode = format!("reorg-repair-{repair_stage}");
                let mut repair_child = spawn_config(
                    &a,
                    &mode,
                    &mode,
                    json!({"launch":null,"launch_sha256":null,"recovery":path,
                        "recovery_sha256":sha,"publication":pub_path,"publication_sha256":pub_sha}),
                    true,
                );
                let observation = process::wait(
                    &repair_child.control.join("guardian-result.json"),
                    &mut repair_child.process,
                );
                assert!(
                    repair_child.process.child.wait().unwrap().success(),
                    "{observation}"
                );
                assert_eq!(observation["passed"], true);
                assert_eq!(observation["v6_closed_process_receipt_created"], false);
                assert!(!repair_child.control.join("closed-process.json").exists());
                assert_eq!(fs::read(&final_path).unwrap(), raw);
                assert_eq!(pending.exists(), repair_stage == "linked");
                assert_eq!(
                    fs::symlink_metadata(&final_path).unwrap().nlink(),
                    if repair_stage == "linked" { 2 } else { 1 }
                );
            }
        }
        let repaired = repair();
        assert_eq!(repaired["journal"]["anchor"], json!(published));
        assert_eq!(repaired["journal"]["spent"]["cpu_ns"], 36_000_000_000u64);
        assert_eq!(fs::read(&final_path).unwrap(), raw);
        let idempotent = repair();
        assert_eq!(idempotent["already_published"], true);
        assert_eq!(idempotent["journal"], repaired["journal"]);
        let finished = finish_attempt(&a, &target, &body, &repaired, 3);
        write_value(
            &a.f.dir.path().join("reorg-publication-result.json"),
            &json!({"stage":stage,"repair":repaired,"idempotent":idempotent,"finished":finished,
                "whole_history_p0_closed":false}),
        );
    }
}

fn install_budget(
    a: &TestAuthority,
    label: &str,
    body: &policy::Budget,
    outside: Anchor,
) -> Result<Value> {
    let path = a.f.dir.path().join(format!("reorg-budget-{label}.json"));
    let sha = write_value(
        &path,
        &json!({"schema":"restricted-history-effect-budget-input-v6","identity":a.identity,
        "journal_path":a.journal,"outside_latest_anchor":outside,"signed_budget":signed(b'B',body)}),
    );
    prepare_history_effect_v6_budget(ProtectedHistoryV6BudgetInput::load(
        &path,
        rustix::process::geteuid().as_raw(),
        &sha,
    )?)
}
#[test]
fn expired_reorg_closure_grants_no_work_until_ordinary_fresh_budget_renewal() {
    let source = compiled_source();
    let mut a = TestAuthority::with_source_and_budget_lifetime(source, 45_000_000_000);
    let _retain = process::retain_fixture(a.f.dir.path(), "reorg-expired-budget");
    let (target, frontier, outside) = prepare_fork(&a);
    let closed = first_crash(&a, "reorg-cursor-1", &target, frontier, outside);
    let old_budget: policy::Envelope<policy::Budget> = serde_json::from_slice(&a.budget).unwrap();
    let wait_until = Instant::now() + Duration::from_secs(50);
    while policy::now().unwrap() < old_budget.body.expires_ns {
        assert!(Instant::now() < wait_until);
        std::thread::sleep(Duration::from_millis(25));
    }
    let root = original(&a, &a.id(9));
    let body = authorization(&a, &closed, &root, None, Closure::PendingUnknown, 10, 3);
    assert!(body.issued_ns >= old_budget.body.expires_ns);
    let mut renewed = old_budget.body.clone();
    renewed.sequence += 1;
    renewed.budget_id = a.id(500);
    renewed.outside_anchor = body.outside_anchor.clone();
    renewed.issued_ns = policy::now().unwrap();
    renewed.expires_ns = renewed.issued_ns + 3_600_000_000_000;
    renewed.nonce_first = 11;
    let original_records = records(&a);
    assert!(
        install_budget(&a, "before-close", &renewed, body.outside_anchor.clone())
            .unwrap_err()
            .to_string()
            .contains("PENDING_DEBT")
    );
    assert_eq!(records(&a), original_records);
    let (path, sha) = input(&a, "expired-close", &body, &closed);
    let prepared = prepare(&a, &path, &sha).unwrap();
    let outside: Anchor = serde_json::from_value(prepared["journal"]["anchor"].clone()).unwrap();
    let (launch, sha) = a.launch(
        "reorg-expired-work",
        11,
        3,
        body.snapshot.old_frontier.clone(),
        outside.clone(),
    );
    let before = records(&a);
    let error = HistoryEffectV6::open(
        &a.store,
        ProtectedHistoryV6Input::load(&launch, rustix::process::geteuid().as_raw(), &sha).unwrap(),
        2,
        deadline(),
    )
    .err()
    .unwrap();
    // install_budget reauthenticates the retained signed envelope before
    // reserve checks its budget expiry; both original refusals forbid work.
    assert!(matches!(
        error.to_string().as_str(),
        "HISTORY_V6_BUDGET_EXPIRED" | "HISTORY_V6_WINDOW"
    ));
    assert_eq!(records(&a), before);
    renewed.outside_anchor = outside.clone();
    for (label, mut bad) in [
        ("decrease", renewed.clone()),
        ("anchor", renewed.clone()),
        ("sequence", renewed.clone()),
    ] {
        match label {
            "decrease" => bad.lifetime_ceiling.cpu_ns -= 1,
            "anchor" => bad.outside_anchor = Anchor::empty(),
            "sequence" => bad.sequence -= 1,
            _ => unreachable!(),
        }
        assert!(install_budget(&a, label, &bad, outside.clone()).is_err());
        assert_eq!(records(&a), before);
    }
    let installed = install_budget(&a, "fresh", &renewed, outside).unwrap();
    a.budget = signed(b'B', &renewed);
    let current: Anchor = serde_json::from_value(installed["anchor"].clone()).unwrap();
    let (launch, _) = a.launch(
        "reorg-old-nonce",
        11,
        3,
        body.snapshot.old_frontier.clone(),
        current.clone(),
    );
    let mut config = read(&launch);
    let mut signed_startup: policy::Envelope<Operation> = serde_json::from_slice(
        &serde_json::from_value::<Vec<u8>>(config["signed_startup"].clone()).unwrap(),
    )
    .unwrap();
    signed_startup.body.request_nonce = 7;
    config["signed_startup"] = json!(signed(b'O', &signed_startup.body));
    let stale = a.f.dir.path().join("reorg-old-nonce-signed.json");
    let sha = write_value(&stale, &config);
    let before = records(&a);
    let rejected = HistoryEffectV6::open(
        &a.store,
        ProtectedHistoryV6Input::load(&stale, rustix::process::geteuid().as_raw(), &sha).unwrap(),
        2,
        deadline(),
    );
    assert!(rejected.is_err());
    assert_eq!(records(&a), before);
    let ready = json!({"journal":{"anchor":current}});
    let finished = finish_attempt(&a, &target, &body, &ready, 3);
    write_value(
        &a.f.dir.path().join("reorg-expired-result.json"),
        &json!({"old_budget_expires_ns":old_budget.body.expires_ns,
        "administrative_issued_ns":body.issued_ns,"prepared":prepared,"renewed":installed,"finished":finished,
        "old_work_revived":false,"whole_history_p0_closed":false}),
    );
}

#[test]
fn exhausted_reorg_budget_requires_atomic_fresh_budget_and_preserves_original_debt() {
    let source = compiled_source();
    let mut a = TestAuthority::with_source_and_budget_limits(
        source,
        3_600_000_000_000,
        Usage {
            cpu_ns: 32_000_000_000,
            material_bytes: 128 << 20,
            received_bytes: 128 << 20,
            operations: 8,
        },
    );
    let _retain = process::retain_fixture(a.f.dir.path(), "reorg-exhausted-budget");
    // Retain an earlier, different Budget ID as well as the current one, so
    // the replay control exercises the full journal history.
    let initial: policy::Envelope<policy::Budget> = serde_json::from_slice(&a.budget).unwrap();
    let mut old = initial.body.clone();
    old.sequence += 1;
    old.budget_id = a.id(499);
    old.outside_anchor = a.installed.clone();
    let installed = install_budget(&a, "exhausted-prefix", &old, a.installed.clone()).unwrap();
    a.budget = signed(b'B', &old);
    a.installed = serde_json::from_value(installed["anchor"].clone()).unwrap();
    let (target, frontier, outside) = prepare_fork(&a);
    let closed = first_crash(&a, "reorg-cursor-1", &target, frontier, outside);
    let root = original(&a, &a.id(9));
    let mut body = authorization(&a, &closed, &root, None, Closure::PendingUnknown, 10, 3);
    let before = records(&a);
    let (path, sha) = input(&a, "no-renewal", &body, &closed);
    assert_eq!(
        prepare(&a, &path, &sha).unwrap_err().to_string(),
        "HISTORY_REORG_V1_FRESH_ALLOWANCE"
    );
    assert_eq!(records(&a), before);
    let mut renewal = old.clone();
    renewal.sequence += 1;
    renewal.budget_id = a.id(500);
    renewal.outside_anchor = body.outside_anchor.clone();
    renewal.issued_ns = policy::now().unwrap();
    renewal.expires_ns = renewal.issued_ns + 3_600_000_000_000;
    renewal.lifetime_ceiling.cpu_ns = 128_000_000_000;
    renewal.lifetime_ceiling.operations = 32;
    renewal.nonce_first = 10;
    body.budget_id = renewal.budget_id.clone();
    body.renewal_budget = Some(signed(b'B', &renewal));
    // The original standalone Budget gate remains closed while debt is pending.
    assert_eq!(
        install_budget(&a, "pending-renewal", &renewal, body.outside_anchor.clone())
            .unwrap_err()
            .to_string(),
        "HISTORY_V6_PENDING_DEBT"
    );
    assert_eq!(records(&a), before);
    let mut refusals = Vec::new();
    for label in [
        "sequence",
        "anchor",
        "identity",
        "decrease",
        "expired",
        "current-id",
        "historical-id",
        "used-operation-id",
        "nonce-window",
        "no-new-headroom",
        "signature",
    ] {
        let mut bad_budget = renewal.clone();
        match label {
            "sequence" => bad_budget.sequence -= 1,
            "anchor" => bad_budget.outside_anchor = Anchor::empty(),
            "identity" => bad_budget.identity.owner = "ab".repeat(32),
            "decrease" => bad_budget.lifetime_ceiling.cpu_ns = old.lifetime_ceiling.cpu_ns - 1,
            "expired" => {
                bad_budget.issued_ns = 0;
                bad_budget.expires_ns = 1;
            }
            "current-id" => bad_budget.budget_id = old.budget_id.clone(),
            "historical-id" => bad_budget.budget_id = initial.body.budget_id.clone(),
            "used-operation-id" => bad_budget.budget_id = a.id(9),
            "nonce-window" => bad_budget.nonce_first = 11,
            "no-new-headroom" => bad_budget.lifetime_ceiling = old.lifetime_ceiling,
            "signature" => {}
            _ => unreachable!(),
        }
        let mut grant = body.clone();
        grant.budget_id = bad_budget.budget_id.clone();
        let mut inner: policy::Envelope<policy::Budget> =
            serde_json::from_slice(&signed(b'B', &bad_budget)).unwrap();
        if label == "signature" {
            let prefix = if inner.task_signature.starts_with('0') {
                "1"
            } else {
                "0"
            };
            inner.task_signature.replace_range(..1, prefix);
        }
        grant.renewal_budget = Some(policy::encoded(&inner).unwrap());
        let (path, sha) = input(&a, &format!("renewal-{label}"), &grant, &closed);
        let error = prepare(&a, &path, &sha).unwrap_err().to_string();
        assert_eq!(records(&a), before, "{label}");
        refusals.push(json!({"case":label,"error":error,"journal_unchanged":true}));
    }
    // Deliberately substituted counter values are a negative control, never
    // an actual CPU measurement. A bigger new budget must not cover this old
    // operation's overrun, even when the new administrative allowance would.
    let mut overrun: policy::ClosedProcess = serde_json::from_slice(&closed).unwrap();
    overrun.user_cpu_microseconds = 4_000_001;
    overrun.system_cpu_microseconds = 0;
    overrun.reported_user_seconds = "4.000001".into();
    overrun.reported_system_seconds = "0".into();
    overrun.reported_cpu_upper_bound_ns = 4_000_003_000;
    let overrun = policy::encoded(&overrun).unwrap();
    let mut overrun_grant = body.clone();
    overrun_grant.closed_process_sha256 = policy::digest(&overrun);
    overrun_grant.allowance.cpu_ns = 5_000_000_000;
    let (path, sha) = input(&a, "old-overrun-control", &overrun_grant, &overrun);
    assert_eq!(
        prepare(&a, &path, &sha).unwrap_err().to_string(),
        "HISTORY_V6_UNCOVERED_PROCESS_CPU"
    );
    assert_eq!(records(&a), before);
    let (path, sha) = input(&a, "atomic-renewal", &body, &closed);
    let mut publishing = spawn_config(
        &a,
        "atomic-renewal-cut",
        "reorg-publish-file-synced",
        json!({"launch":null,"launch_sha256":null,"recovery":path,"recovery_sha256":sha}),
        true,
    );
    let observation = process::wait(
        &publishing.control.join("guardian-result.json"),
        &mut publishing.process,
    );
    assert!(
        publishing.process.child.wait().unwrap().success(),
        "{observation}"
    );
    assert_eq!(observation["passed"], true);
    assert_eq!(observation["v6_closed_process_receipt_created"], false);
    let barrier = read(&publishing.control.join("crash-ready.json"));
    let published: Anchor = serde_json::from_value(barrier["anchor"].clone()).unwrap();
    let pending = a
        .journal
        .join(format!("pending-{:020}", published.sequence));
    let raw = fs::read(&pending).unwrap();
    assert_eq!(policy::digest(&raw), published.digest);
    let now = policy::now().unwrap();
    let pub_body = journal::publication::Authorization {
        schema: "restricted-history-journal-publication-authorization-v1".into(),
        identity: a.identity.clone(),
        prefix_anchor: body.outside_anchor.clone(),
        published_anchor: published.clone(),
        frame_sha256: policy::digest(&raw),
        frame_bytes: raw.len() as u64,
        issued_ns: now,
        expires_ns: now + 3_600_000_000_000,
    };
    let (pub_path, pub_sha) = publication::input(
        &a,
        "atomic-renewal",
        &pub_body,
        &publication::envelope(&pub_body),
        published.clone(),
    );
    let repair = || {
        repair_history_reorg_continuation_v1_publication(
            &a.store,
            ProtectedHistoryReorgContinuationV1Input::load(
                &path,
                rustix::process::geteuid().as_raw(),
                &sha,
            )
            .unwrap(),
            ProtectedHistoryJournalPublicationV1Input::load(
                &pub_path,
                rustix::process::geteuid().as_raw(),
                &pub_sha,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let prepared = repair();
    let repeated = repair();
    assert_eq!(repeated["already_published"], true);
    assert_eq!(prepared["journal"], repeated["journal"]);
    assert_eq!(
        fs::read(a.journal.join(format!(
            "{:020}-{}.json",
            published.sequence, published.digest
        )))
        .unwrap(),
        raw
    );
    assert_eq!(prepared["before"]["spent"]["cpu_ns"], 32_000_000_000u64);
    assert_eq!(prepared["before"]["spent"]["operations"], 8);
    assert_eq!(prepared["journal"]["spent"]["cpu_ns"], 36_000_000_000u64);
    assert_eq!(prepared["journal"]["spent"]["operations"], 9);
    assert_eq!(records(&a).len(), before.len() + 1);
    for (name, sha) in &before {
        assert_eq!(records(&a).get(name), Some(sha));
    }
    let after = records(&a);
    assert!(prepare(&a, &path, &sha).is_err());
    assert_eq!(records(&a), after);
    a.budget = body.renewal_budget.clone().unwrap();
    let finished = finish_attempt(&a, &target, &body, &prepared, 3);
    write_value(
        &a.f.dir.path().join("reorg-exhausted-result.json"),
        &json!({
        "prepared":prepared,"finished":finished,"renewal_refusals":refusals,
        "old_receipt_counter_substitution_was_negative_control":true,
        "old_overrun_refused":true,"old_spent_refunded":false,
        "standalone_pending_budget_gate_changed":false,"whole_history_p0_closed":false}),
    );
}
