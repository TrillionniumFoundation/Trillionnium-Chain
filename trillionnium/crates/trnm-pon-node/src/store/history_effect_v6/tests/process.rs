use super::*;
use std::process::{Child, Command, Stdio};

const SELECTOR: &str = "store::history_effect_v6::tests::history_effect_v6_process_child_helper";

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
    recovery: Option<PathBuf>,
    recovery_sha256: Option<String>,
    #[serde(default)]
    publication: Option<PathBuf>,
    #[serde(default)]
    publication_sha256: Option<String>,
}
pub(in crate::store::history_effect_v6) struct Process {
    pub(in crate::store::history_effect_v6) child: Child,
    pub(in crate::store::history_effect_v6) guardian: bool,
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            // The guardian owns a native child and has a bounded finally/wait4
            // cleanup. Do not orphan that grandchild by killing the guardian.
            if !self.guardian {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
        }
    }
}
pub(in crate::store::history_effect_v6) fn wait(path: &Path, process: &mut Process) -> Value {
    let end = Instant::now() + Duration::from_secs(85);
    loop {
        if path.exists() {
            return read(path);
        }
        if let Some(status) = process.child.try_wait().unwrap() {
            panic!("process exited {status} before {}", path.display());
        }
        assert!(
            Instant::now() < end,
            "timed out awaiting {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn child_wait(path: &Path) -> Vec<u8> {
    let end = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(
            Instant::now() < end,
            "outside fixture did not supply {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let raw = fs::read(path).unwrap();
    assert!(raw.len() <= policy::MAX_ENVELOPE);
    raw
}
fn barrier(owner: &Owner, path: &Path, cutpoint: &str, worker: bool) -> ! {
    let value = {
        let journal = owner.journal().unwrap();
        let pending = journal.pending().unwrap();
        json!({"schema":"actual-history-effect-crash-barrier-v6","pid":std::process::id(),"cutpoint":cutpoint,
            "anchor":journal.anchor(),"pending_operation":pending.operation.operation_id,"intent_sha256":pending.intent_sha256,
            "epoch":pending.operation.epoch,"actual_worker_thread":worker,"thread":format!("{:?}",std::thread::current().id()),
            "original_cpu":owner.cpu.observe().unwrap(),"journal":journal.observation(),"clean_close_created":false})
    };
    write_value(path, &value);
    loop {
        std::thread::park_timeout(Duration::from_secs(5));
    }
}
pub(in crate::store::history_effect_v6) fn child() {
    let path = PathBuf::from(std::env::var("TRNM_HISTORY_V6_CHILD_CONFIG").unwrap());
    let raw = fs::read(&path).unwrap();
    assert_eq!(
        policy::digest(&raw),
        std::env::var("TRNM_HISTORY_V6_CHILD_CONFIG_SHA256").unwrap()
    );
    let config: ChildConfig = serde_json::from_slice(&raw).unwrap();
    assert_eq!(config.schema, "actual-history-effect-child-fixture-v6");
    let uid = rustix::process::geteuid().as_raw();
    if config.mode.starts_with("reorg-") {
        super::super::reorg_continuation_tests_v1::child(&serde_json::from_slice(&raw).unwrap());
        return;
    }
    if config.mode.starts_with("lifecycle-") {
        super::super::lifecycle_native_tests_v1::child(&serde_json::from_slice(&raw).unwrap());
        return;
    }
    if config.mode == "startup-no-native" {
        startup_no_native::child(
            &config.store,
            &config.control,
            config.launch.as_ref().unwrap(),
            config.launch_sha256.as_deref().unwrap(),
        );
    }
    if config.mode.starts_with("startup-no-native-publish-") {
        publication::install_hook(&config.mode, &config.control);
        let result = close_history_startup_no_native_v1(
            ProtectedHistoryStartupNoNativeV1Input::load(
                config.recovery.as_ref().unwrap(),
                uid,
                config.recovery_sha256.as_deref().unwrap(),
            )
            .unwrap(),
        );
        panic!("first Startup closure returned without its publication barrier: {result:?}");
    }
    if config.mode.starts_with("epoch-recovery-publish-") {
        publication::install_hook(&config.mode, &config.control);
        let result = prepare_history_settled_epoch_v1_recovery(
            &config.store,
            ProtectedHistorySettledEpochV1Input::load(
                config.recovery.as_ref().unwrap(),
                uid,
                config.recovery_sha256.as_deref().unwrap(),
            )
            .unwrap(),
        );
        panic!("epoch recovery returned without its selected publication barrier: {result:?}");
    }
    if config.mode.starts_with("publication-repair-") {
        if let Some(recovery) = &config.recovery {
            publication::install_hook(&config.mode, &config.control);
            let result = repair_history_settled_epoch_v1_publication(
                &config.store,
                ProtectedHistorySettledEpochV1Input::load(
                    recovery,
                    uid,
                    config.recovery_sha256.as_deref().unwrap(),
                )
                .unwrap(),
                ProtectedHistoryJournalPublicationV1Input::load(
                    config.publication.as_ref().unwrap(),
                    uid,
                    config.publication_sha256.as_deref().unwrap(),
                )
                .unwrap(),
            );
            panic!("pinned epoch publication repair returned without crash barrier: {result:?}");
        }
        publication::repair_child(
            &config.mode,
            &config.control,
            config.publication.as_ref().unwrap(),
            config.publication_sha256.as_deref().unwrap(),
        );
        return;
    }
    let (launch, sha) = if config.mode == "resume-published-settled-epoch"
        || config.mode == "resume-published-startup-no-native"
    {
        let launch: Value =
            serde_json::from_slice(&child_wait(&config.control.join("outside-launch.json")))
                .unwrap();
        (
            PathBuf::from(launch["path"].as_str().unwrap()),
            launch["sha256"].as_str().unwrap().to_owned(),
        )
    } else if config.mode == "resume" || config.mode == "resume-settled-epoch" {
        let result = if config.mode == "resume-settled-epoch" {
            prepare_history_settled_epoch_v1_recovery(
                &config.store,
                ProtectedHistorySettledEpochV1Input::load(
                    config.recovery.as_ref().unwrap(),
                    uid,
                    config.recovery_sha256.as_deref().unwrap(),
                )
                .unwrap(),
            )
            .unwrap()
        } else {
            let recovery = ProtectedHistoryV6RecoveryInput::load(
                config.recovery.as_ref().unwrap(),
                uid,
                config.recovery_sha256.as_deref().unwrap(),
            )
            .unwrap();
            prepare_history_effect_v6_recovery(&config.store, recovery).unwrap()
        };
        write_value(&config.control.join("reconciled-ready.json"), &result);
        let launch: Value =
            serde_json::from_slice(&child_wait(&config.control.join("outside-launch.json")))
                .unwrap();
        (
            PathBuf::from(launch["path"].as_str().unwrap()),
            launch["sha256"].as_str().unwrap().to_owned(),
        )
    } else {
        (
            config.launch.clone().unwrap(),
            config.launch_sha256.clone().unwrap(),
        )
    };
    let mut owner = HistoryEffectV6::open(
        &config.store,
        ProtectedHistoryV6Input::load(&launch, uid, &sha).unwrap(),
        2,
        deadline(),
    )
    .unwrap();
    assert_eq!(owner.initial_cpu.stored_credit_ns, 0);
    write_value(
        &config.control.join("startup-ready.json"),
        &owner.observation().unwrap(),
    );
    publication::install_hook(&config.mode, &config.control);
    let validation = child_wait(&config.control.join("outside-validation.json"));
    let owner_thread = std::thread::current().id();
    let validated = {
        // The barrier observer owns a clone only for this live call. Keeping it
        // to the end of the helper would also keep the original journal flock
        // alive after drop(owner), invalidating the intended cold readback.
        let shared = owner.owner.clone();
        owner
            .receive_with_progress(&validation, &config.page, CLOCK, deadline(), &|point| {
                if config.mode == "validation-worker"
                    && point == Progress::Execution(ExecutionProgress::AfterPrepare { index: 0 })
                {
                    assert_ne!(std::thread::current().id(), owner_thread);
                    barrier(
                        &shared,
                        &config.control.join("crash-ready.json"),
                        &config.mode,
                        true,
                    );
                }
                Ok(())
            })
            .unwrap()
    };
    checked(&validated, 2);
    assert!(
        validated.known_success(),
        "{}",
        serde_json::to_string(&validated).unwrap()
    );
    write_value(
        &config.control.join("validation-ready.json"),
        &json!({"result":validated,"observation":owner.observation().unwrap(),"frontier":actual(&owner)}),
    );
    let activation = child_wait(&config.control.join("outside-activation.json"));
    let activated = {
        let shared = owner.owner.clone();
        owner
            .activate_with_progress(&activation, CLOCK, deadline(), &|point| {
                if config.mode == "activation-committed" && point == Progress::BeforeSettlement {
                    barrier(
                        &shared,
                        &config.control.join("crash-ready.json"),
                        &config.mode,
                        false,
                    );
                }
                Ok(())
            })
            .unwrap()
    };
    checked(&activated, 0);
    assert!(activated.known_success());
    if config.mode == "settled-epoch" {
        settled_epoch::barrier(&owner, &activation, &activated, &config.control);
    }
    if config.mode == "settled-epoch-wrong-frontier" {
        write_value(
            &config.control.join("activation-ready.json"),
            &json!({"result":activated,"observation":owner.observation().unwrap(),"frontier":actual(&owner)}),
        );
        let wrong = child_wait(&config.control.join("outside-wrong-frontier.json"));
        let refused = owner
            .receive_with_progress(&wrong, &config.page, CLOCK, deadline(), &|_| Ok(()))
            .unwrap();
        settled_epoch::refused_frontier_barrier(&owner, &wrong, &refused, &config.control);
    }
    assert!(
        config.mode == "resume"
            || config.mode == "resume-settled-epoch"
            || config.mode == "resume-published-settled-epoch"
            || config.mode == "resume-published-startup-no-native"
    );
    write_value(
        &config.control.join("activation-ready.json"),
        &json!({"result":activated,"observation":owner.observation().unwrap(),"frontier":actual(&owner)}),
    );
    let close = child_wait(&config.control.join("outside-close.json"));
    let closed = owner.close(&close, deadline()).unwrap();
    let identity = owner.owner.identity.clone();
    let head = serde_json::from_value(closed["journal"]["anchor"].clone()).unwrap();
    let launch_raw: Value = read(&launch);
    let journal_path = PathBuf::from(launch_raw["journal_path"].as_str().unwrap());
    drop(owner);
    let journal = journal::Journal::open(&journal_path, uid, &identity, &head).unwrap();
    assert!(journal.pending().is_none());
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
        &json!({"schema":"actual-history-effect-new-process-finished-v6",
        "pid":std::process::id(),"closed":closed,"cold_journal":journal.observation(),"frontier":storage::frontier(&db).unwrap(),
        "marker_count":count,"unknown_receipts_fabricated":false,"production_qualified":false}),
    );
}

pub(in crate::store::history_effect_v6) fn sha_file(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    let mut file = File::open(path).unwrap();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    hex::encode(hash.finalize())
}
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap();
    fs::set_permissions(to, fs::Permissions::from_mode(0o700)).unwrap();
    for row in fs::read_dir(from).unwrap() {
        let row = row.unwrap();
        let path = row.path();
        let target = to.join(row.file_name());
        if row.file_type().unwrap().is_dir() {
            copy_tree(&path, &target);
        } else if row.file_type().unwrap().is_file() {
            fs::copy(path, target).unwrap();
        }
    }
}
pub(in crate::store::history_effect_v6) struct Retain {
    source: PathBuf,
    target: Option<PathBuf>,
}
impl Drop for Retain {
    fn drop(&mut self) {
        if let Some(target) = &self.target {
            if !target.exists() {
                copy_tree(&self.source, target);
            }
        }
    }
}
pub(in crate::store::history_effect_v6) fn retain_fixture(source: &Path, label: &str) -> Retain {
    Retain {
        source: source.to_path_buf(),
        target: std::env::var_os("TRNM_HISTORY_V6_ARTIFACT_DIR").map(|base| {
            let base = PathBuf::from(base);
            fs::create_dir_all(&base).unwrap();
            base.join(label)
        }),
    }
}
fn snapshot(path: &Path) -> BTreeMap<String, String> {
    fs::read_dir(path)
        .unwrap()
        .map(|r| r.unwrap())
        .filter(|r| r.file_name() != "owner.lock")
        .map(|r| (r.file_name().into_string().unwrap(), sha_file(&r.path())))
        .collect()
}
pub(in crate::store::history_effect_v6) fn next_packet(a: &TestAuthority) -> Packet {
    let mut producer =
        Node::open(&a.f.dir.path().join("producer"), a.f.settings.clone(), 2).unwrap();
    let mut rows = a.f.material_inputs();
    let model = fs::read(
        rows.remove(rows.iter().position(|r| r.role == "model").unwrap())
            .path,
    )
    .unwrap();
    let input = fs::read(
        rows.remove(rows.iter().position(|r| r.role == "input").unwrap())
            .path,
    )
    .unwrap();
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
            2,
        )
        .unwrap();
    let transactions =
        a.f.packet
            .transactions
            .iter()
            .enumerate()
            .map(|(i, raw)| {
                let mut tx = trnm_protocol::pon_wire::Envelope::decode(raw).unwrap();
                tx.nonce = 2;
                tx.signature = hex::decode(sign_hex(
                    &signing_key_from_hex(&hex::encode([71 + i as u8; 32])).unwrap(),
                    &tx.signing_digest().unwrap(),
                ))
                .unwrap()
                .try_into()
                .unwrap();
                tx.encode().unwrap()
            })
            .collect();
    let prepared = producer
        .prepare_with_task(
            a.f.packet.id().unwrap(),
            transactions,
            a.f.packet.header.miner,
            a.f.packet.header.timestamp + 10,
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
    let searched = prepared.search_owned_window(1, 4096, &|| Ok(())).unwrap();
    assert!(searched.error.is_none());
    let packet = searched.packet.unwrap();
    let id = producer.admit(&packet, CLOCK).unwrap();
    assert_eq!(producer.activate(id).unwrap(), id);
    pon_work::verify_reference(
        packet.header.challenge(),
        packet.header.work_task,
        packet.header.target,
        &packet.proof,
    )
    .unwrap();
    packet
}
pub(in crate::store::history_effect_v6) fn page(a: &TestAuthority, packet: &Packet) -> Vec<u8> {
    policy::encoded(&crate::ingress::Page {
        schema: "pon-native-history-v1".into(),
        network: a.identity.network.clone(),
        parameters: a.identity.parameters.clone(),
        genesis: a.identity.genesis.clone(),
        tip: hex::encode(packet.id().unwrap()),
        after: hex::encode(packet.header.parent),
        packets: vec![hex::encode(packet.encode().unwrap())],
        next: hex::encode(packet.id().unwrap()),
        complete: true,
    })
    .unwrap()
}
fn recovery_input(
    a: &TestAuthority,
    label: &str,
    closed_raw: &[u8],
    operation: &str,
) -> (PathBuf, String) {
    let closed: policy::ClosedProcess = serde_json::from_slice(closed_raw).unwrap();
    let now = policy::now().unwrap();
    let body = policy::Recovery {
        schema: "restricted-history-effect-reconciliation-v6".into(),
        identity: a.identity.clone(),
        request_nonce: 10,
        outside_anchor: closed.original_journal.clone(),
        pending_operation_id: operation.into(),
        intent_sha256: closed.intent_sha256.clone(),
        closed_process_sha256: policy::digest(closed_raw),
        actual_frontier: closed.actual_frontier.clone(),
        marker_sha256: closed
            .marker
            .as_ref()
            .map(|m| policy::digest(&policy::encoded(m).unwrap())),
        issued_ns: now,
        expires_ns: now + 3_000_000_000_000,
    };
    let config = json!({"schema":"restricted-history-effect-recovery-input-v6","identity":a.identity,"journal_path":a.journal,
        "outside_latest_anchor":closed.original_journal,"recovery":{"signed":signed(b'R',&body),"closed_process":closed_raw}});
    let path = a.f.dir.path().join(format!("recovery-{label}.json"));
    let sha = write_value(&path, &config);
    (path, sha)
}
fn rejects(a: &TestAuthority, path: &Path, sha: &str) -> String {
    let before = snapshot(&a.journal);
    let result = if read(path)["schema"] == "restricted-history-settled-epoch-input-v1" {
        prepare_history_settled_epoch_v1_recovery(
            &a.store,
            ProtectedHistorySettledEpochV1Input::load(
                path,
                rustix::process::geteuid().as_raw(),
                sha,
            )
            .unwrap(),
        )
    } else {
        prepare_history_effect_v6_recovery(
            &a.store,
            ProtectedHistoryV6RecoveryInput::load(path, rustix::process::geteuid().as_raw(), sha)
                .unwrap(),
        )
    };
    let error = result
        .expect_err("adversarial recovery unexpectedly accepted")
        .to_string();
    assert_eq!(snapshot(&a.journal), before);
    error
}

pub(in crate::store::history_effect_v6) fn run(cutpoint: &str) {
    let epoch_cut = cutpoint.starts_with("settled-epoch");
    let wrong_frontier = cutpoint == "settled-epoch-wrong-frontier";
    let recovery_stage = cutpoint.strip_prefix("settled-epoch-record-");
    let expired_budget = cutpoint == "settled-epoch-expired-budget";
    let validation_cut =
        cutpoint == "validation-worker" || cutpoint.starts_with("publication-intent-");
    let mut a = if expired_budget {
        TestAuthority::with_budget_lifetime(30_000_000_000)
    } else {
        TestAuthority::new()
    };
    let _retain = Retain {
        source: a.f.dir.path().to_path_buf(),
        target: std::env::var_os("TRNM_HISTORY_V6_ARTIFACT_DIR").map(|base| {
            let base = PathBuf::from(base);
            fs::create_dir_all(&base).unwrap();
            base.join(cutpoint)
        }),
    };
    let binary = std::env::current_exe().unwrap();
    let binary_sha = sha_file(&binary);
    let first = a.f.dir.path().join("crash-control");
    fs::create_dir(&first).unwrap();
    fs::set_permissions(&first, fs::Permissions::from_mode(0o700)).unwrap();
    let (launch, launch_sha) = a.launch("crash", 1, 1, a.genesis(), a.installed.clone());
    let config = json!({"schema":"actual-history-effect-child-fixture-v6","mode":if epoch_cut && !wrong_frontier {"settled-epoch"} else {cutpoint},"store":a.store,"control":first,"page":a.f.page,
        "launch":launch,"launch_sha256":launch_sha,"recovery":null,"recovery_sha256":null});
    let conf = a.f.dir.path().join("crash-child.json");
    let conf_sha = write_value(&conf, &config);
    let guardian = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/ci/history_effect_v6_process_guard.py");
    assert_eq!(
        sha_file(&guardian),
        policy::digest(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../scripts/ci/history_effect_v6_process_guard.py"
        )))
    );
    let shared_guardian = guardian.with_file_name("history_native_process_guard.py");
    assert_eq!(
        sha_file(&shared_guardian),
        policy::digest(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../scripts/ci/history_native_process_guard.py"
        )))
    );
    let log = File::create(first.join("guardian.stdout.log")).unwrap();
    let mut guard = Process {
        child: Command::new("python3")
            .arg(&guardian)
            .args(["--binary"])
            .arg(&binary)
            .args(["--binary-sha256", &binary_sha, "--configuration"])
            .arg(&conf)
            .args(["--configuration-sha256", &conf_sha, "--directory"])
            .arg(&first)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
        guardian: true,
    };
    let started = wait(&first.join("startup-ready.json"), &mut guard);
    let start_anchor: Anchor =
        serde_json::from_value(started["journal"]["anchor"].clone()).unwrap();
    let validation = a.grant(Grant {
        purpose: Purpose::Validation,
        nonce: 2,
        epoch: 1,
        frontier: a.genesis(),
        anchor: start_anchor.clone(),
        packet: Some(&a.f.packet),
        pair: Some((2, 3)),
    });
    write(&first.join("outside-validation.json"), &validation);
    if cutpoint == "activation-committed" || epoch_cut {
        let validated = wait(&first.join("validation-ready.json"), &mut guard);
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
    }
    if wrong_frontier {
        let activated = wait(&first.join("activation-ready.json"), &mut guard);
        assert_eq!(activated["frontier"]["generation"], 1);
        let wrong = a.grant(Grant {
            purpose: Purpose::Validation,
            nonce: 4,
            epoch: 1,
            frontier: a.genesis(),
            anchor: serde_json::from_value(activated["observation"]["journal"]["anchor"].clone())
                .unwrap(),
            packet: Some(&a.f.packet),
            pair: Some((4, 5)),
        });
        write(&first.join("outside-wrong-frontier.json"), &wrong);
    }
    let observed = wait(&first.join("guardian-result.json"), &mut guard);
    assert!(guard.child.wait().unwrap().success(), "{observed}");
    assert_eq!(observed["passed"], true);
    let barrier = read(&first.join("crash-ready.json"));
    let pending = if epoch_cut {
        barrier["last_settled_operation"].as_str().unwrap()
    } else {
        barrier["pending_operation"].as_str().unwrap()
    };
    let publication_repair = if cutpoint.starts_with("publication-intent-") {
        Some(publication::after_crash(
            &a,
            &first,
            &barrier,
            &start_anchor,
        ))
    } else {
        None
    };
    let original_records = snapshot(&a.journal);
    let closed_raw = fs::read(first.join("closed-process.json")).unwrap();
    let closed: policy::ClosedProcess = serde_json::from_slice(&closed_raw).unwrap();
    assert!(closed.reported_cpu_upper_bound_ns <= 4_000_000_000);
    assert_eq!(closed.epoch, a.epoch(1));
    if wrong_frontier {
        assert_eq!(pending, a.id(4));
        assert!(closed.marker.is_none());
        assert_eq!(closed.actual_frontier.generation, 1);
        assert_ne!(json!(closed.actual_frontier), barrier["requested_frontier"]);
        let mut forged = closed.clone();
        forged.actual_frontier =
            serde_json::from_value(barrier["requested_frontier"].clone()).unwrap();
        let (path, sha) = settled_epoch::input(
            &a,
            "refused-request-cannot-rewind-frontier",
            &policy::encoded(&forged).unwrap(),
            pending,
        );
        let error = rejects(&a, &path, &sha);
        assert!(error.contains("SETTLED_BINDING"));
        write_value(
            &first.join("requested-frontier-refusal.json"),
            &json!({
                "error":error,"actual_frontier":closed.actual_frontier,
                "refused_requested_frontier":forged.actual_frontier,"marker":null,
                "journal_unchanged":snapshot(&a.journal)==original_records,
            }),
        );
        assert_eq!(snapshot(&a.journal), original_records);
    }
    let (noauth, noauthsha) = a.launch(
        "pending-refused",
        9,
        2,
        closed.actual_frontier.clone(),
        closed.original_journal.clone(),
    );
    let refused = HistoryEffectV6::open(
        &a.store,
        ProtectedHistoryV6Input::load(&noauth, rustix::process::geteuid().as_raw(), &noauthsha)
            .unwrap(),
        2,
        deadline(),
    );
    let pending_error = refused.err().unwrap().to_string();
    assert!(pending_error.contains(if epoch_cut {
        "UNCLOSED_EPOCH"
    } else {
        "PENDING_DEBT"
    }));
    assert_eq!(snapshot(&a.journal), original_records);
    if expired_budget {
        settled_epoch::wait_expired(&a);
    }
    if !epoch_cut {
        let (p, s) = settled_epoch::input(&a, "pending-cannot-be-forgiven", &closed_raw, pending);
        assert!(rejects(&a, &p, &s).contains("PENDING_DEBT"));
    }
    let recovery_input = |a: &TestAuthority, label: &str, raw: &[u8], operation: &str| {
        if epoch_cut {
            settled_epoch::input(a, label, raw, operation)
        } else {
            self::recovery_input(a, label, raw, operation)
        }
    };
    let mut missing = closed.clone();
    missing.all_descendants_closed = false;
    let (p, s) = recovery_input(
        &a,
        "missing-closure",
        &policy::encoded(&missing).unwrap(),
        pending,
    );
    let missing_error = rejects(&a, &p, &s);
    let mut unsupported = closed.clone();
    unsupported.descendant_accounting_profile = "arbitrary-process-tree".into();
    let (p, s) = recovery_input(
        &a,
        "unsupported-process-tree",
        &policy::encoded(&unsupported).unwrap(),
        pending,
    );
    let unsupported_error = rejects(&a, &p, &s);
    let mut over = closed.clone();
    over.user_cpu_microseconds = 4_000_001;
    over.system_cpu_microseconds = 0;
    over.reported_user_seconds = "4.000001".into();
    over.reported_system_seconds = "0".into();
    over.reported_cpu_upper_bound_ns = 4_000_003_000;
    let (p, s) = recovery_input(&a, "over-budget", &policy::encoded(&over).unwrap(), pending);
    let over_error = rejects(&a, &p, &s);
    assert!(over_error.contains(if epoch_cut {
        "CLOSED_BINDING"
    } else {
        "UNCOVERED_PROCESS_CPU"
    }));
    let mut wrong = closed.clone();
    wrong.actual_frontier.root = "ee".repeat(32);
    let (p, s) = recovery_input(
        &a,
        "wrong-frontier",
        &policy::encoded(&wrong).unwrap(),
        pending,
    );
    let wrong_error = rejects(&a, &p, &s);
    let mut roll = closed.clone();
    roll.original_journal.digest = "dd".repeat(32);
    let (p, s) = recovery_input(
        &a,
        "wrong-anchor",
        &policy::encoded(&roll).unwrap(),
        pending,
    );
    let rollback_error = rejects(&a, &p, &s);
    write_value(
        &first.join("adversarial-refusals.json"),
        &json!({"pending_without_recovery":pending_error,"missing_closure":missing_error,
        "unsupported_process_tree":unsupported_error,
        "original_ceiling_not_covered":over_error,"wrong_frontier":wrong_error,"wrong_outside_anchor":rollback_error,"journal_unchanged":true}),
    );
    let (recovery_path, recovery_sha) = recovery_input(&a, "actual", &closed_raw, pending);
    if epoch_cut {
        settled_epoch::refusals(&a, &recovery_path, &recovery_sha, &rejects);
    }
    let published_recovery = recovery_stage.map(|stage| {
        settled_epoch::publish_interrupted(&a, stage, &recovery_path, &recovery_sha, &closed_raw)
    });
    let next = if validation_cut {
        Packet::decode(&a.f.packet.encode().unwrap()).unwrap()
    } else {
        next_packet(&a)
    };
    let second = a.f.dir.path().join("resume-control");
    fs::create_dir(&second).unwrap();
    fs::set_permissions(&second, fs::Permissions::from_mode(0o700)).unwrap();
    let cfg = json!({"schema":"actual-history-effect-child-fixture-v6","mode":if published_recovery.is_some() {"resume-published-settled-epoch"} else if epoch_cut {"resume-settled-epoch"} else {"resume"},"store":a.store,"control":second,"page":page(&a,&next),
        "launch":null,"launch_sha256":null,"recovery":recovery_path,"recovery_sha256":recovery_sha});
    let cfgpath = a.f.dir.path().join("resume-child.json");
    let cfgsha = write_value(&cfgpath, &cfg);
    let log = File::create(second.join("new-native-process.log")).unwrap();
    let mut resumed = Process {
        child: Command::new(&binary)
            .args([
                SELECTOR,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TRNM_HISTORY_V6_CHILD_CONFIG", &cfgpath)
            .env("TRNM_HISTORY_V6_CHILD_CONFIG_SHA256", cfgsha)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
        guardian: false,
    };
    let reconciled = published_recovery
        .unwrap_or_else(|| wait(&second.join("reconciled-ready.json"), &mut resumed));
    if epoch_cut {
        assert_eq!(reconciled["clean_close_fabricated"], false);
        assert_eq!(reconciled["original_settlements_preserved"], true);
        assert_eq!(
            reconciled["additional_conservative_debit"]["cpu_ns"],
            4_000_000_000u64
        );
        assert_eq!(reconciled["journal"]["settled_epoch_reconciliations_v1"], 1);
    } else {
        assert_eq!(reconciled["original_cpu_split"], "unknown-preserved");
    }
    assert_eq!(reconciled["native_effect_repeated"], false);
    assert_eq!(
        reconciled["journal"]["unknown_prepaid_reconciliations"],
        if epoch_cut { 0 } else { 1 }
    );
    let mut recovered_head =
        serde_json::from_value(reconciled["journal"]["anchor"].clone()).unwrap();
    if expired_budget {
        recovered_head = settled_epoch::renew_budget(&mut a, recovered_head);
    }
    let (launch, sha) = a.launch(
        "resume",
        11,
        2,
        closed.actual_frontier.clone(),
        recovered_head,
    );
    write_value(
        &second.join("outside-launch.json"),
        &json!({"path":launch,"sha256":sha}),
    );
    let started = wait(&second.join("startup-ready.json"), &mut resumed);
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
    write(&second.join("outside-validation.json"), &validation);
    let validated = wait(&second.join("validation-ready.json"), &mut resumed);
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
    write(&second.join("outside-activation.json"), &activation);
    let activated = wait(&second.join("activation-ready.json"), &mut resumed);
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
    write(&second.join("outside-close.json"), &close);
    let finished = wait(&second.join("finished.json"), &mut resumed);
    assert!(resumed.child.wait().unwrap().success());
    assert_ne!(finished["pid"], json!(closed.owned_namespace_pid));
    let count = if wrong_frontier {
        9
    } else if epoch_cut {
        8
    } else if validation_cut {
        6
    } else {
        7
    };
    assert_eq!(finished["cold_journal"]["used_operations"], count);
    assert_eq!(finished["cold_journal"]["known_settlements"], count - 1);
    assert_eq!(
        finished["cold_journal"]["spent"]["cpu_ns"],
        count * 4_000_000_000u64
    );
    assert_eq!(
        finished["cold_journal"]["unknown_prepaid_reconciliations"],
        if epoch_cut { 0 } else { 1 }
    );
    assert_eq!(finished["marker_count"], if validation_cut { 2 } else { 4 });
    assert_eq!(
        finished["frontier"]["block"],
        hex::encode(next.id().unwrap())
    );
    assert_eq!(
        finished["frontier"]["generation"],
        if validation_cut { 1 } else { 2 }
    );
    let final_records = snapshot(&a.journal);
    if cutpoint == "settled-epoch" {
        settled_epoch::rejects_legacy_record_relabel(&a);
    }
    for (name, digest) in &original_records {
        assert_eq!(final_records.get(name), Some(digest));
    }
    let replay_error = rejects(&a, &recovery_path, &recovery_sha);
    assert!(replay_error.contains("ROLLBACK"));
    if let Some((path, digest)) = publication_repair {
        publication::rejects_after_advance(&a, &path, &digest);
    }
    assert_eq!(sha_file(&binary), binary_sha);
    write_value(
        &a.f.dir.path().join("process-result.json"),
        &json!({"schema":"actual-history-effect-two-process-result-v6","cutpoint":cutpoint,
        "guardian":observed,"reconciliation":reconciled,"finished":finished,"duplicate_recovery_error":replay_error,
        "original_record_sha256":original_records,"original_records_unchanged":true,"binary_sha256":binary_sha,
        "physical_power_loss_qualified":false,"external_registry2_admission":false,"production_qualified":false}),
    );
    eprintln!(
        "HISTORY_V6_ACTUAL_PROCESS {}",
        serde_json::to_string(&finished).unwrap()
    );
}

/// A fresh administrative repair process is actually killed at its selected
/// syscall. Its wait4 observation is NOT an original-operation CPU closure.
pub(in crate::store::history_effect_v6) fn repair_crash(
    a: &TestAuthority,
    stage: &str,
    input: &Path,
    input_sha: &str,
    epoch_recovery: Option<(&Path, &str)>,
) {
    let binary = std::env::current_exe().unwrap();
    let binary_sha = sha_file(&binary);
    let mode = format!("publication-repair-{stage}");
    let control = a.f.dir.path().join(&mode);
    fs::create_dir(&control).unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
    let config = json!({"schema":"actual-history-effect-child-fixture-v6","mode":mode,
        "store":a.store,"control":control,"page":[],"launch":null,"launch_sha256":null,
        "recovery":epoch_recovery.map(|v|v.0),"recovery_sha256":epoch_recovery.map(|v|v.1),
        "publication":input,"publication_sha256":input_sha});
    let path = a.f.dir.path().join(format!("{mode}.json"));
    let digest = write_value(&path, &config);
    let guardian = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/ci/history_effect_v6_process_guard.py");
    assert_eq!(
        sha_file(&guardian),
        policy::digest(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../scripts/ci/history_effect_v6_process_guard.py"
        )))
    );
    let log = File::create(control.join("guardian.stdout.log")).unwrap();
    let mut guard = Process {
        child: Command::new("python3")
            .arg(&guardian)
            .arg("--binary")
            .arg(&binary)
            .args(["--binary-sha256", &binary_sha, "--configuration"])
            .arg(&path)
            .args(["--configuration-sha256", &digest, "--directory"])
            .arg(&control)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
        guardian: true,
    };
    let observed = wait(&control.join("guardian-result.json"), &mut guard);
    assert!(guard.child.wait().unwrap().success(), "{observed}");
    assert_eq!(observed["passed"], true);
    assert_eq!(observed["actual_wait4"], true);
    assert_eq!(observed["native_operation_started"], false);
    assert_eq!(observed["v6_closed_process_receipt_created"], false);
    assert!(!control.join("closed-process.json").exists());
    assert_eq!(sha_file(&binary), binary_sha);
}

pub(in crate::store::history_effect_v6) fn epoch_recovery_crash(
    a: &TestAuthority,
    stage: &str,
    input: &Path,
    input_sha: &str,
) -> Value {
    let binary = std::env::current_exe().unwrap();
    let binary_sha = sha_file(&binary);
    let mode = format!("epoch-recovery-publish-{stage}");
    let control = a.f.dir.path().join(&mode);
    fs::create_dir(&control).unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
    let config = json!({"schema":"actual-history-effect-child-fixture-v6","mode":mode,
        "store":a.store,"control":control,"page":[],"launch":null,"launch_sha256":null,
        "recovery":input,"recovery_sha256":input_sha,"publication":null,"publication_sha256":null});
    let path = a.f.dir.path().join(format!("{mode}.json"));
    let digest = write_value(&path, &config);
    let guardian = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/ci/history_effect_v6_process_guard.py");
    assert_eq!(
        sha_file(&guardian),
        policy::digest(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../scripts/ci/history_effect_v6_process_guard.py"
        )))
    );
    let log = File::create(control.join("guardian.stdout.log")).unwrap();
    let mut guard = Process {
        child: Command::new("python3")
            .arg(&guardian)
            .arg("--binary")
            .arg(&binary)
            .args(["--binary-sha256", &binary_sha, "--configuration"])
            .arg(&path)
            .args(["--configuration-sha256", &digest, "--directory"])
            .arg(&control)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
        guardian: true,
    };
    let observed = wait(&control.join("guardian-result.json"), &mut guard);
    assert!(guard.child.wait().unwrap().success(), "{observed}");
    assert_eq!(observed["passed"], true);
    assert_eq!(observed["actual_wait4"], true);
    assert_eq!(observed["v6_closed_process_receipt_created"], false);
    assert!(!control.join("closed-process.json").exists());
    assert_eq!(sha_file(&binary), binary_sha);
    read(&control.join("crash-ready.json"))
}
