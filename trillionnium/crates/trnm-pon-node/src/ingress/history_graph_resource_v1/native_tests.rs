//! Parent-driven physical controls. This ignored helper has no fallback: the
//! source-pinned CI guardian must own the actual fixed cgroup and mutate its
//! real files/membership. Observing a fixture JSON never creates a budget.
use super::*;
use crate::account_archive_prototype::native_store::{self, LiftCache};
use crate::host_kernel_parent::{self, HostKernelBudget as KernelBudget};
use crate::native_progress::TypedNativeProgress;
use crate::{development_public, ErrorKind, Node, Packet, Settings};
use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use trnm_mvcc_fee::pon_executor::{ExecutionControl, State};
use trnm_protocol::pon_wire::hash;

const PARENT: &str = host_kernel_parent::FIXED_PUBLIC_KERNEL_PARENT;

fn read(path: &Path) -> Value {
    let mut raw = Vec::new();
    File::open(path)
        .unwrap()
        .take(65_537)
        .read_to_end(&mut raw)
        .unwrap();
    assert!(raw.len() <= 65_536);
    serde_json::from_slice(&raw).unwrap()
}
fn publish(path: &Path, value: &Value) {
    let raw = serde_json::to_vec(value).unwrap();
    assert!(raw.len() <= 65_536 && !path.exists());
    let pending = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&pending)
        .unwrap();
    file.write_all(&raw).unwrap();
    file.sync_all().unwrap();
    fs::rename(pending, path).unwrap();
}
fn sha(path: &Path) -> String {
    let mut file = File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65_536];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            return hex::encode(hash.finalize());
        }
        hash.update(&buffer[..count]);
    }
}
fn await_file(path: &Path) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.is_file() {
        assert!(
            Instant::now() < deadline,
            "finite physical guardian handshake"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    read(path)
}
fn identity() -> Value {
    let task = fs::canonicalize("/proc/thread-self").unwrap();
    let tid: u32 = task.file_name().unwrap().to_str().unwrap().parse().unwrap();
    assert_ne!(
        tid,
        std::process::id(),
        "the real verifier must be a non-leader thread"
    );
    json!({"pid":std::process::id(),"tid":tid,
        "thread_cgroup":fs::read_to_string("/proc/thread-self/cgroup").unwrap().trim(),
        "uid":rustix::process::getuid().as_raw(),"gid":rustix::process::getgid().as_raw()})
}
fn mutate(path: &Path, job: &Value, point: Value) {
    publish(
        &path.join("mutation-request.json"),
        &json!({
            "schema":"history-graph-resource-physical-request-v1", "case":job["case"],
            "action":job["action"],"identity":identity(),"point":point,
            "binary_sha256":sha(&std::env::current_exe().unwrap()),
        }),
    );
    let acknowledgement = await_file(&path.join("mutation-applied.json"));
    assert_eq!(acknowledgement["case"], job["case"]);
    assert_eq!(acknowledgement["action"], job["action"]);
    assert_eq!(acknowledgement["actual_mutation_applied"], true);
}
fn restored(path: &Path, job: &Value, kernel: &KernelBudget, result: &Value) {
    publish(&path.join("native-result-before-restore.json"), result);
    let acknowledgement = await_file(&path.join("mutation-restored.json"));
    assert_eq!(acknowledgement["case"], job["case"]);
    assert_eq!(acknowledgement["actual_restored"], true);
    kernel.verify().unwrap();
}
fn expected_error(job: &Value, error: &crate::Error) {
    let expected = match job["action"].as_str().unwrap() {
        "cpu" | "burst" | "memory" | "swap" | "pids" => "PUBLIC_HOST_KERNEL_LIMITS_CHANGED",
        "unreadable-cpu" => "PUBLIC_HOST_KERNEL_UNAVAILABLE",
        "migrate-process" => "PUBLIC_HOST_KERNEL_CONTEXT",
        _ => panic!("explicit physical mutation"),
    };
    assert_eq!(error.to_string(), expected);
    assert_ne!(error.kind(), ErrorKind::ProtocolInvalid);
}
fn graph_control(path: &Path, job: &Value, kernel: &KernelBudget) -> Value {
    let state: State = (0..32u64)
        .map(|i| {
            let owner = hash(b"graph-resource-physical-account-v1", &[&i.to_le_bytes()]);
            (
                format!("account:{}", hex::encode(owner)),
                json!({"balance":i + 1,"nonce":i}),
            )
        })
        .collect();
    let db = Connection::open(path.join("actual-graph.sqlite")).unwrap();
    db.execute_batch(crate::store::native_authenticated::DDL)
        .unwrap();
    let root = native_store::seed(&db, &state, &mut || kernel.verify()).unwrap();
    let cache = LiftCache::default();
    native_store::verify_with_lifts(&db, &root, &state, &mut || kernel.verify(), Some(&cache))
        .unwrap();
    let decode_before = cache.decode_observation();
    let domain = super::super::public_v3::ServiceMutationCpuDomain::cold_remote_history_epoch();
    let operation = super::super::begin_history_import_cpu(&domain).unwrap();
    let cpu = || operation.checkpoint();
    let counters = SharedCounters::default();
    let full = || measured_kernel(&counters, || kernel.verify());
    let mut native_events = Vec::new();
    let result;
    let mut completed = None;
    let trigger = job["trigger"].as_str().unwrap();
    let mut triggered = false;
    if trigger == "strict-after-node0" {
        let mut ordinal = 0u32;
        result = native_store::verify_with_lifts(
            &db,
            &root,
            &state,
            &mut || {
                cpu()?;
                full()?;
                if ordinal == 0 {
                    mutate(
                        path,
                        job,
                        json!({"strict_original_callback":true,"after_full_check_before_body":0}),
                    );
                    triggered = true;
                }
                ordinal += 1;
                Ok(())
            },
            Some(&cache),
        );
        completed = Some(ordinal);
        assert_eq!(
            ordinal, 1,
            "the original strict callback rereads at the next actual node"
        );
    } else {
        let mut graph = GraphProgress::new(&cpu, &full, Arc::clone(&counters));
        let mut observer = TypedNativeProgress(|point| {
            let kind = match &point {
                NativeProgressPoint::AccountGraph(point) => point.kind(),
                _ => panic!("only the actual graph verifier emits this control's events"),
            };
            native_events.push(format!("{kind:?}"));
            let before = matches!(
                (trigger, kind),
                ("enter", AccountGraphKind::Enter)
                    | (
                        "final-relation",
                        AccountGraphKind::BeforeFinalRelation { .. }
                    )
                    | (
                        "exit",
                        AccountGraphKind::Exit {
                            succeeded: true,
                            ..
                        },
                    )
            );
            if before {
                assert!(!triggered);
                triggered = true;
                mutate(
                    path,
                    job,
                    json!({"before_typed_full_boundary":format!("{kind:?}")}),
                );
            }
            if let AccountGraphKind::Exit {
                completed: bodies, ..
            } = kind
            {
                completed = Some(bodies);
            }
            let result = graph.point(point);
            if let AccountGraphKind::BeforeNode { ordinal } = kind {
                if trigger == "after-node" && u64::from(ordinal) == job["offset"].as_u64().unwrap()
                {
                    result.as_ref().unwrap();
                    assert!(!triggered);
                    triggered = true;
                    // The original checkpoint has really returned before the
                    // administrator mutates the current kernel state.
                    mutate(
                        path,
                        job,
                        json!({"after_typed_checkpoint_before_body":ordinal}),
                    );
                }
            }
            result
        });
        result = native_store::verify_with_lifts_native_progress(
            &db,
            &root,
            &state,
            &mut observer,
            Some(&cache),
        );
        assert!(
            graph.complete().is_err(),
            "failed resource observation is latched"
        );
    }
    assert!(triggered);
    let error = result.unwrap_err();
    expected_error(job, &error);
    if trigger == "after-node" {
        assert_eq!(completed, Some(8));
        assert!(8 - job["offset"].as_u64().unwrap() <= 8);
    } else if trigger == "enter" {
        assert_eq!(completed, Some(0));
        assert_eq!(
            cache.decode_observation(),
            decode_before,
            "Enter refusal precedes every root SQL/decode"
        );
    } else if trigger == "final-relation" || trigger == "exit" {
        assert_eq!(
            completed,
            Some(63),
            "the actual 32-account Patricia graph has 63 completed bodies"
        );
    }
    // Resource failure remains a refusal at the original CPU settlement edge.
    assert!(kernel.verify().is_err());
    let cpu_receipt = operation.finish();
    assert!(!cpu_receipt.accounting_unavailable);
    let value = json!({"schema":"history-graph-resource-physical-native-result-v1",
        "case":job["case"],"error":error.to_string(),"protocol_invalid":false,
        "triggered":triggered,"completed_node_bodies":completed,"actual_graph_events":native_events,
        "decode_before":decode_before,"decode_after":cache.decode_observation(),
        "graph_resource":observe(&counters).unwrap(),"cpu_receipt":cpu_receipt,
        "original_cpu":domain.observe().unwrap(),"original_cpu_flow":domain.observe_actual_flow().unwrap(),
        "identity_after_refusal":identity(),"fixture_account_count":32,
        "scope":"actual warm arithmetic and fresh SQL graph; actual cold CPU operation and actual fixed parent; no full public-import performance claim"});
    restored(path, job, kernel, &value);
    value
}

fn settings() -> Settings {
    Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap()
}
fn packet(path: &Path, settings: &Settings) -> Packet {
    let producer =
        Node::open_with_authenticated_state(&path.join("producer"), settings.clone(), 1).unwrap();
    producer
        .make_consensus_maintenance(
            settings.genesis(),
            vec![],
            development_public(7).unwrap(),
            11,
            4096,
        )
        .unwrap()
}
fn markers(path: &Path) -> Value {
    let db = Connection::open_with_flags(
        path.join("native.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let rows: Vec<(String, String)> = db.prepare("SELECT key,hex(value) FROM metadata WHERE key IN ('ordinary-public-v3-epoch-v1','ordinary-history-graph-resource-policy-v1') ORDER BY key")
        .unwrap().query_map([], |row| Ok((row.get(0)?,row.get(1)?))).unwrap().map(|row| row.unwrap()).collect();
    json!(rows)
}
fn commit_control(path: &Path, job: &Value, kernel: &KernelBudget) -> Value {
    let settings = settings();
    let packet = packet(path, &settings);
    let id = packet.id().unwrap();
    let store = path.join("native");
    let mut node = Node::open_with_authenticated_state(&store, settings, 1).unwrap();
    let activation = job["trigger"] == "activation-commit";
    if activation {
        node.admit(&packet, 100).unwrap();
    }
    let before = node.read_active().unwrap();
    let stats_before = node.stats().unwrap();
    let domain = node.remote_history_cpu_domain().unwrap();
    let epoch = node
        .begin_history_graph_resource_v1(&kernel.identity_observation().unwrap(), &|| {
            kernel.verify()
        })
        .unwrap();
    let before_markers = markers(&store);
    let operation = super::super::begin_history_import_cpu(&domain).unwrap();
    let cpu = || operation.checkpoint();
    let counters = node.history_graph_resource_counters();
    let full = || {
        epoch.verify()?;
        measured_kernel(&counters, || kernel.verify())
    };
    let triggered = Cell::new(false);
    let mut graph = GraphProgress::new(&cpu, &full, Arc::clone(&counters));
    let mut observer = TypedNativeProgress(|point| {
        if matches!(&point, NativeProgressPoint::BeforeCommit) {
            assert!(!triggered.replace(true));
            mutate(
                path,
                job,
                json!({"before_actual_native_commit":true,"activation":activation}),
            );
        }
        graph.point(point)
    });
    let result = if activation {
        node.activate_observed_with_native_progress(id, 100, &mut observer)
            .map(|_| ())
    } else {
        node.check_admission_context_with_native_progress(&packet, 100, &mut observer)
            .unwrap();
        let permit = node.begin_owner_work(&packet).unwrap();
        let checked =
            crate::store::WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |point| {
                cpu()?;
                if super::super::history_kernel_work_checkpoint(point) {
                    full()?;
                }
                Ok(())
            })
            .unwrap();
        let checked = node.attach_owner_work(checked, permit).unwrap();
        let execution = |_| {
            cpu()?;
            full()
        };
        let control = ExecutionControl::new(&execution, operation.worker_accounting());
        node.admit_work_checked_with_native_control(checked, 100, &control, &mut |_, point| {
            crate::native_progress::dispatch(&mut observer, point)
        })
        .map(|_| ())
    };
    assert!(triggered.get());
    let error = result.unwrap_err();
    expected_error(job, &error);
    assert!(graph.complete().is_err());
    drop(graph);
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(node.stats().unwrap(), stats_before);
    assert_eq!(
        markers(&store),
        before_markers,
        "rejected real commit retains its original epoch"
    );
    assert!(full().is_err());
    let cpu_receipt = operation.finish();
    assert!(!cpu_receipt.accounting_unavailable);
    let mut value = json!({"schema":"history-graph-resource-physical-native-result-v1",
        "case":job["case"],"error":error.to_string(),"protocol_invalid":false,
        "triggered":true,"original_native_state_unchanged":true,"original_markers_preserved":true,
        "markers":before_markers,"graph_resource":observe(&counters).unwrap(),
        "cpu_receipt":cpu_receipt,"original_cpu":domain.observe().unwrap(),
        "original_cpu_flow":domain.observe_actual_flow().unwrap(),"identity_after_refusal":identity(),
        "scope":"actual admission/activation transaction and original CPU; current resource refusal before commit"});
    restored(path, job, kernel, &value);
    let clean = domain.observe().unwrap();
    assert!(clean.in_flight == 0 && !clean.accounting_unavailable && clean.stored_credit_ns >= 0);
    node.finish_history_graph_resource_v1(&epoch, true, &|| kernel.verify())
        .unwrap();
    assert_eq!(markers(&store), json!([]));
    // A known aborted native operation is not a permanent disabling path.
    node.begin_ordinary_public_service_epoch().unwrap();
    node.finish_ordinary_public_service_epoch(true).unwrap();
    value["known_abort_closed_after_actual_restore"] = json!(true);
    value["next_original_strict_epoch_completed"] = json!(true);
    value
}

fn settlement_control(path: &Path, job: &Value, kernel: &KernelBudget) -> Value {
    let store = path.join("native");
    let settings = settings();
    let mut node = Node::open_with_authenticated_state(&store, settings.clone(), 1).unwrap();
    let domain = node.remote_history_cpu_domain().unwrap();
    let epoch = node
        .begin_history_graph_resource_v1(&kernel.identity_observation().unwrap(), &|| {
            kernel.verify()
        })
        .unwrap();
    let before = markers(&store);
    let operation = super::super::begin_history_import_cpu(&domain).unwrap();
    operation.checkpoint().unwrap();
    kernel.verify().unwrap();
    let cpu_receipt = operation.finish();
    assert!(!cpu_receipt.accounting_unavailable);
    let error = node
        .finish_history_graph_resource_v1(&epoch, true, &|| {
            mutate(
                path,
                job,
                json!({"inside_epoch_close_transaction_before_commit":true}),
            );
            kernel.verify()
        })
        .unwrap_err();
    expected_error(job, &error);
    assert_eq!(markers(&store), before);
    let mut value = json!({"schema":"history-graph-resource-physical-native-result-v1",
        "case":job["case"],"error":error.to_string(),"protocol_invalid":false,"triggered":true,
        "original_markers_preserved":true,"markers":before,"cpu_receipt":cpu_receipt,
        "original_cpu":domain.observe().unwrap(),"original_cpu_flow":domain.observe_actual_flow().unwrap(),
        "identity_after_refusal":identity(),"scope":"actual SQLite cleanup rollback at the original CPU epoch close boundary"});
    restored(path, job, kernel, &value);
    drop(node);
    let mut reopened = Node::open_with_authenticated_state(&store, settings, 1).unwrap();
    assert!(reopened.remote_history_cpu_domain().is_err());
    assert!(reopened.begin_ordinary_public_service_epoch().is_err());
    assert_eq!(markers(&store), before);
    value["cold_restart_did_not_clear_unsettled_markers"] = json!(true);
    value
}

fn import_equivalence(path: &Path, kernel: &KernelBudget) -> Value {
    let settings = settings();
    let packet = packet(path, &settings);
    let tip = packet.id().unwrap();
    let page = super::super::Page {
        schema: "pon-native-history-v1".into(),
        network: hex::encode(settings.network()),
        parameters: hex::encode(settings.parameters()),
        genesis: hex::encode(settings.genesis()),
        tip: hex::encode(tip),
        after: hex::encode(settings.genesis()),
        next: hex::encode(tip),
        complete: true,
        packets: vec![hex::encode(packet.encode().unwrap())],
    };
    let source: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let strict_path = path.join("strict");
    let bounded_path = path.join("bounded");
    let mut strict =
        Node::open_with_authenticated_state(&strict_path, settings.clone(), 1).unwrap();
    let mut bounded =
        Node::open_with_authenticated_state(&bounded_path, settings.clone(), 1).unwrap();
    let strict_page = serde_json::from_value(serde_json::to_value(&page).unwrap()).unwrap();
    assert_eq!(
        super::super::receive_public_page_from(
            &mut strict,
            source,
            strict_page,
            tip,
            settings.genesis(),
            100
        )
        .unwrap(),
        tip
    );
    assert_eq!(
        super::super::receive_public_page_with_graph_resource_fence_v1(
            &mut bounded,
            source,
            page,
            tip,
            settings.genesis(),
            100
        )
        .unwrap(),
        tip
    );
    assert_eq!(
        strict.read_active().unwrap(),
        bounded.read_active().unwrap()
    );
    assert_eq!(strict.stats().unwrap(), bounded.stats().unwrap());
    assert_eq!(markers(&strict_path), json!([]));
    assert_eq!(markers(&bounded_path), json!([]));
    let counters = bounded.history_graph_resource_observation_v1().unwrap();
    assert_eq!(counters["counters"]["imports"], 1);
    assert_eq!(counters["counters"]["imports_closed"], 1);
    let active = strict.read_active().unwrap();
    drop(strict);
    drop(bounded);
    let strict = Node::open_with_authenticated_state(&strict_path, settings.clone(), 1).unwrap();
    let bounded = Node::open_with_authenticated_state(&bounded_path, settings, 1).unwrap();
    assert_eq!(strict.read_active().unwrap(), active);
    assert_eq!(bounded.read_active().unwrap(), active);
    kernel.verify().unwrap();
    json!({"schema":"history-graph-resource-physical-native-result-v1","case":"full-import-equivalence",
        "triggered":false,"same_legal_packet_and_active_state":true,"clean_both_epochs":true,
        "cold_reopen_both_equal":true,"graph_resource":counters,"identity_after_refusal":identity(),
        "scope":"same physical parent, same actual ELF, complete strict and explicit v1 public import; one legal packet, not a campaign timing result"})
}

fn production_import_known_close(path: &Path, job: &Value, kernel: &KernelBudget) -> Value {
    let settings = settings();
    let packet = packet(path, &settings);
    let tip = packet.id().unwrap();
    let source: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let page = |packet: &Packet, after: trnm_protocol::pon_wire::Hash| super::super::Page {
        schema: "pon-native-history-v1".into(),
        network: hex::encode(settings.network()),
        parameters: hex::encode(settings.parameters()),
        genesis: hex::encode(settings.genesis()),
        tip: hex::encode(packet.id().unwrap()),
        after: hex::encode(after),
        next: hex::encode(packet.id().unwrap()),
        complete: true,
        packets: vec![hex::encode(packet.encode().unwrap())],
    };
    let store = path.join("actual-public-import");
    let mut node = Node::open_with_authenticated_state(&store, settings.clone(), 1).unwrap();
    let before = node.read_active().unwrap();
    let stats_before = node.stats().unwrap();
    let domain = node.remote_history_cpu_domain().unwrap();
    let triggered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let trigger = Arc::clone(&triggered);
    let control_path = path.to_owned();
    let control_job = job.clone();
    node.history_graph_resource_before_commit_hook = Some(Arc::new(move || {
        if !trigger.swap(true, std::sync::atomic::Ordering::SeqCst) {
            mutate(
                &control_path,
                &control_job,
                json!({"before_actual_public_import_commit":true}),
            );
        }
    }));
    // This is the actual public entry and its actual error/settlement path.
    // The private test observer only chooses when the root guardian changes
    // real sysfs; it supplies no resource verdict or native progress success.
    let error = super::super::receive_public_page_with_graph_resource_fence_v1(
        &mut node,
        source,
        page(&packet, settings.genesis()),
        tip,
        settings.genesis(),
        100,
    )
    .unwrap_err();
    expected_error(job, &error);
    assert!(triggered.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(node.stats().unwrap(), stats_before);
    let observed = node.history_graph_resource_observation_v1().unwrap();
    assert_eq!(observed["live_known_close_pending"], true);
    let held = markers(&store);
    assert_eq!(held.as_array().unwrap().len(), 2);
    assert!(kernel.verify().is_err());
    let cpu = domain.observe().unwrap();
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(cpu.in_flight, 0);
    assert!(!cpu.accounting_unavailable && cpu.stored_credit_ns >= 0);
    assert!(flow.balance_identity_verified && flow.live_owners == 0);
    assert!(node.history_graph_resource_cpu_receipts.len() >= 2);
    assert!(node
        .history_graph_resource_cpu_receipts
        .iter()
        .all(|receipt| !receipt.accounting_unavailable));
    let premature =
        super::super::resume_public_history_graph_resource_settlement_v1(&mut node, source)
            .unwrap_err();
    expected_error(job, &premature);
    assert_eq!(
        node.history_graph_resource_observation_v1().unwrap()["live_known_close_pending"],
        true
    );
    assert_eq!(markers(&store), held);
    assert_eq!(domain.observe().unwrap(), cpu);
    assert_eq!(domain.observe_actual_flow().unwrap().unwrap(), flow);
    let mut value = json!({"schema":"history-graph-resource-physical-native-result-v1",
        "case":job["case"],"error":error.to_string(),"protocol_invalid":false,"triggered":true,
        "actual_public_entry_returned_error_before_restore":true,"original_native_state_unchanged":true,
        "actual_premature_public_resume_refused_without_poison":true,
        "premature_resume_error":premature.to_string(),
        "original_markers_preserved":true,"markers":held,"graph_resource":observed,
        "cpu_receipts":node.history_graph_resource_cpu_receipts,"original_cpu":cpu,"original_cpu_flow":flow,
        "identity_after_refusal":identity(),"cold_epoch_recovery_claimed":false,
        "scope":"actual public N8 entry returned with its original live known-settlement token; no manual replacement admission path"});
    restored(path, job, kernel, &value);
    let credit_before = domain.observe().unwrap();
    let flow_before = domain.observe_actual_flow().unwrap();
    super::super::resume_public_history_graph_resource_settlement_v1(&mut node, source).unwrap();
    assert_eq!(domain.observe().unwrap(), credit_before);
    assert_eq!(domain.observe_actual_flow().unwrap(), flow_before);
    assert!(node
        .public_service_cpu_domain()
        .unwrap()
        .shares_domain_with(&domain));
    assert_eq!(markers(&store), json!([]));
    let recovered = node.history_graph_resource_observation_v1().unwrap();
    assert_eq!(recovered["live_known_close_pending"], false);
    assert_eq!(recovered["counters"]["imports_failed"], 1);
    assert_eq!(recovered["counters"]["imports_closed"], 1);
    assert!(
        super::super::resume_public_history_graph_resource_settlement_v1(&mut node, source)
            .is_err()
    );
    value["same_live_domain_preserved"] = json!(true);
    value["credit_before_resume"] = serde_json::to_value(&credit_before).unwrap();
    value["credit_after_resume"] = serde_json::to_value(domain.observe().unwrap()).unwrap();
    value["flow_before_resume"] = serde_json::to_value(&flow_before).unwrap();
    value["flow_after_resume"] =
        serde_json::to_value(domain.observe_actual_flow().unwrap()).unwrap();
    value["known_abort_closed_after_actual_restore"] = json!(true);
    value["repeated_resume_refused"] = json!(true);
    value["graph_resource_after_resume"] = recovered;
    node.history_graph_resource_before_commit_hook = None;
    assert_eq!(
        super::super::receive_public_page_from(
            &mut node,
            source,
            page(&packet, settings.genesis()),
            tip,
            settings.genesis(),
            100
        )
        .unwrap(),
        tip
    );
    assert_eq!(node.read_active().unwrap().0, tip);
    let next = node
        .make_consensus_maintenance(tip, vec![], development_public(7).unwrap(), 12, 4096)
        .unwrap();
    let next_tip = next.id().unwrap();
    assert_ne!(next_tip, tip);
    assert_eq!(
        super::super::receive_public_page_with_graph_resource_fence_v1(
            &mut node,
            source,
            page(&next, tip),
            next_tip,
            tip,
            100
        )
        .unwrap(),
        next_tip
    );
    let final_active = node.read_active().unwrap();
    assert_eq!(final_active.0, next_tip);
    assert_eq!(final_active.1, 2);
    assert_eq!(markers(&store), json!([]));
    value["next_original_strict_import_completed"] = json!(true);
    value["next_explicit_v1_import_completed"] = json!(true);
    value["actual_strict_tip"] = json!(hex::encode(tip));
    value["actual_next_tip"] = json!(hex::encode(next_tip));
    value["final_height"] = json!(final_active.1);
    value["final_graph_resource"] = node.history_graph_resource_observation_v1().unwrap();
    drop(node);
    let cold = Node::open_with_authenticated_state(&store, settings, 1).unwrap();
    assert_eq!(cold.read_active().unwrap(), final_active);
    value["clean_cold_readback_after_real_next_imports"] = json!(true);
    value
}

#[test]
#[ignore = "requires exact source-pinned root guardian, actual fixed parent and actual resource mutations; never a mock or unsupported-host PASS"]
fn graph_resource_v1_native_owned_parent_case() {
    let path = PathBuf::from(std::env::var_os("TRNM_HISTORY_GRAPH_RESOURCE_NATIVE_CASE").unwrap());
    assert!(path.is_absolute());
    let job = read(&path.join("job.json"));
    assert_eq!(job["schema"], "history-graph-resource-physical-job-v1");
    assert_eq!(job["parent"], PARENT);
    assert_eq!(job["binary_sha256"], sha(&std::env::current_exe().unwrap()));
    let source: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let kernel = host_kernel_parent::require_host_kernel_budget(source, Some(PARENT))
        .unwrap()
        .unwrap();
    kernel.verify().unwrap();
    assert_ne!(
        rustix::process::getuid().as_raw(),
        0,
        "only the administrative guardian is root"
    );
    publish(
        &path.join("ready.json"),
        &json!({"case":job["case"],"identity":identity(),
        "binary_sha256":sha(&std::env::current_exe().unwrap()),"parent":kernel.identity_observation().unwrap()}),
    );
    let result = match job["trigger"].as_str().unwrap() {
        "after-node" | "strict-after-node0" | "enter" | "final-relation" | "exit" => {
            graph_control(&path, &job, &kernel)
        }
        "admission-commit" | "activation-commit" => commit_control(&path, &job, &kernel),
        "settlement" => settlement_control(&path, &job, &kernel),
        "full-import-equivalence" => import_equivalence(&path, &kernel),
        "public-import-known-close" => production_import_known_close(&path, &job, &kernel),
        _ => panic!("explicit owned physical case required"),
    };
    publish(
        &path.join("complete.json"),
        &json!({"schema":"history-graph-resource-physical-completion-v1",
        "case":job["case"],"passed":true,"binary_sha256":sha(&std::env::current_exe().unwrap()),
        "parent_restored_and_rechecked":true,"final_identity":identity(),"result":result}),
    );
}
