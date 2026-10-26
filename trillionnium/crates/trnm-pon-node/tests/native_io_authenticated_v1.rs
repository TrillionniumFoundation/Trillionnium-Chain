//! Candidate v3 only: original AuthenticatedV1 and ordinary retained PN1 input.
//! NOT BUILT / NOT RUN. This finite integration is not the 4097 identity campaign.
//! Proposed path: trnm-pon-node/tests/native_io_authenticated_v1.rs.
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use rusqlite::OpenFlags;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write},
    net::{SocketAddr, TcpListener},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use trnm_pon_node::{
    ingress::{
        public_v3::{
            self, PublicClientMetrics, PublicMetrics, PublicPolicy, PublicReply, PublicServer,
            Request,
        },
        DevelopmentIdentity,
    },
    Node, Packet, PoolLimits, Settings,
};
use trnm_sqlite_io_boundary::{NativeIoLease, NativeIoOwner, RootReceipt, ROOT_COUNT};

type R<T> = Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pn1-native-node-authenticated-integration-control-v3";
const INPUT_SHA256: &str = "534ee01b8254d4675754b9fc6142aca62e57898b1acdc840a147217a1fd4e1a2";
const JSON_BYTES: usize = 2 * 1024 * 1024;

fn require(value: bool, why: &str) -> R<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(why).into())
    }
}
fn save(path: &Path, value: &impl Serialize) -> R<()> {
    let raw = serde_json::to_vec_pretty(value)?;
    require(
        raw.len() < JSON_BYTES,
        "finite metadata cap; no omitted receipt pass",
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&raw)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn healthy(r: &RootReceipt) -> R<()> {
    require(
        r.lifecycle_complete && r.secondary_failures_complete && r.quarantine_entries_complete,
        "complete original lifecycle, secondary and actual-cleanup evidence required",
    )?;
    require(
        !r.allocated_blocks_hard_cap_implemented
            && r.lifecycle.len() <= 1024
            && r.cleanup_lifecycle.len() <= 256
            && r.lifecycle_serialized_bytes_cap == 655360
            && r.lifecycle_serialized_bytes <= r.lifecycle_serialized_bytes_cap,
        "original bounded lifecycle evidence; logical cap is not physical quota",
    )?;
    require(
        !r.failed
            && r.first_failure.is_none()
            && r.first_failure_sqlite_code.is_none()
            && r.secondary_failures.is_empty()
            && r.quarantined_actual_states == 0,
        "actual I/O domain must remain healthy",
    )?;
    require(
        r.logical_bytes_limit == 48 * 1024 * 1024
            && r.retained_object_limit == 3
            && r.high_water_sum <= r.retained_logical_bytes_peak
            && r.retained_logical_bytes_peak <= 48 * 1024 * 1024
            && r.retained_objects_peak <= 3
            && r.objects.len() <= 3
            && r.objects.iter().all(|o| {
                o.actual_last_bytes <= o.high_water_bytes && o.high_water_bytes <= 16 * 1024 * 1024
            }),
        "original retained-inode and byte limits",
    )?;
    Ok(())
}
fn snapshot(base: &Path, name: &str, lease: &NativeIoLease) -> R<RootReceipt> {
    let r = lease.receipt()?;
    save(&base.join(format!("{name}.json")), &r)?; // Preserve before checking.
    healthy(&r)?;
    require(
        (r.root_device, r.root_inode) == lease.identity(),
        "held real root continuity",
    )?;
    Ok(r)
}
fn closed(r: &RootReceipt) -> R<()> {
    require(
        r.objects
            .iter()
            .all(|o| o.handles == 0 && o.pending_opens == 0 && o.shm_references == 0),
        "all actual SQLite connections and mappings must be closed",
    )
}
fn identity(seed: u8) -> R<DevelopmentIdentity> {
    Ok(DevelopmentIdentity::from_secret_hex(&hex::encode(
        [seed; 32],
    ))?)
}
fn policy() -> R<PublicPolicy> {
    // Exact ordinary PN1 multiprocess_support fixture, not a cheaper profile.
    Ok(PublicPolicy::new(8, Duration::from_millis(2000))?)
}
fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    let text = if let Some(text) = payload.downcast_ref::<&str>() {
        *text
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.as_str()
    } else {
        "non-string panic payload"
    };
    text.chars().take(1024).collect()
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ServiceJoin {
    JoinedOk { metrics: Box<PublicMetrics> },
    JoinedError { error: String },
    JoinedPanic { panic: String },
    HandleUnavailable { reason: &'static str },
}
struct Service {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<trnm_pon_node::Result<PublicMetrics>>>,
    observed: Option<ServiceJoin>,
    actual_join_attempts: u8,
}
impl Service {
    fn start(node: Arc<Mutex<Node>>, server: DevelopmentIdentity) -> R<(Self, SocketAddr)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let server = PublicServer::new(server, policy()?)?;
        let worker = thread::Builder::new().spawn(move || {
            public_v3::serve_public_protected_v3(
                listener,
                node,
                Duration::from_secs(30),
                signal,
                server,
            )
        })?;
        Ok((
            Self {
                stop,
                worker: Some(worker),
                observed: None,
                actual_join_attempts: 0,
            },
            address,
        ))
    }
    fn stop_and_observe_join(&mut self) {
        self.stop.store(true, Ordering::Release);
        if self.observed.is_some() {
            return;
        } // Reuse the SAME actual result, never a second join success.
        self.observed = Some(match self.worker.take() {
            Some(worker) => {
                self.actual_join_attempts += 1;
                match worker.join() {
                    Ok(Ok(metrics)) => ServiceJoin::JoinedOk {
                        metrics: Box::new(metrics),
                    },
                    Ok(Err(error)) => ServiceJoin::JoinedError {
                        error: error.to_string().chars().take(1024).collect(),
                    },
                    Err(payload) => ServiceJoin::JoinedPanic {
                        panic: panic_text(payload.as_ref()),
                    },
                }
            }
            None => ServiceJoin::HandleUnavailable {
                reason: "no handle and no observed terminal; not a successful join",
            },
        });
    }
    fn successful(&self) -> bool {
        self.actual_join_attempts == 1
            && matches!(&self.observed, Some(ServiceJoin::JoinedOk { .. }))
    }
    fn finish(&mut self) -> R<PublicMetrics> {
        self.stop_and_observe_join();
        match &self.observed {
            Some(ServiceJoin::JoinedOk { metrics }) => Ok(metrics.as_ref().clone()),
            Some(ServiceJoin::JoinedError { error }) => Err(io::Error::other(error.clone()).into()),
            Some(ServiceJoin::JoinedPanic { panic }) => {
                Err(io::Error::other(format!("actual service worker panic: {panic}")).into())
            }
            _ => Err(io::Error::other("actual service join terminal unavailable").into()),
        }
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        // Last-resort ownership only. It is NEVER counted as a persisted
        // terminal; missing files/nonzero/abort remain failure to the root collector.
        self.stop_and_observe_join();
    }
}
fn final_failure(outcome: &mut R<Value>, errors: &mut Vec<String>, why: impl AsRef<str>) {
    let bounded: String = why.as_ref().chars().take(1024).collect();
    if outcome.is_ok() {
        *outcome = Err(io::Error::other(bounded.clone()).into());
    }
    errors.push(bounded); // At most the fixed service + seven-root finalization paths.
}

fn call(
    base: &Path,
    label: &str,
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    server: &str,
) -> R<PublicReply> {
    let (reply, metrics): (_, PublicClientMetrics) =
        public_v3::call_public_protected_v3_with_deadline(
            address,
            request,
            settings,
            server,
            &identity(72)?,
            policy()?,
            Some(Instant::now() + Duration::from_secs(2)),
        );
    let value = match &reply {
        Ok(r) => json!({"reply":r}),
        Err(e) => json!({"error":e.to_string()}),
    };
    save(
        &base.join(format!("{label}.json")),
        &json!({"request":request,"observation":value,
        "client_metrics":metrics,"original_call_seconds":2,"no_retry":true}),
    )?;
    let reply = reply?;
    require(reply.ok, "actual public read refused")?;
    Ok(reply)
}

#[test]
#[ignore = "fresh finite Node integration; explicit retained input and owned output required; not W1 qualification"]
fn authenticated_native_io_seed_writer_public_read_and_cold_reopen() {
    let base = PathBuf::from(
        std::env::var_os("TRNM_PN1_NATIVE_NODE_CONTROL_DIR").expect("explicit output"),
    );
    assert!(base.is_absolute());
    DirBuilder::new()
        .mode(0o700)
        .create(&base)
        .expect("fresh owned output only");
    let started = Instant::now();
    let mut stage = "input";
    let mut owner: Option<NativeIoOwner> = None;
    let mut service: Option<Service> = None; // Reachable even when the work closure unwinds.
    let mut service_start_attempted = false;
    let work = catch_unwind(AssertUnwindSafe(|| -> R<Value> {
        save(
            &base.join("started.json"),
            &json!({"schema":SCHEMA,"pid":std::process::id(),
            "full_W1_4097_qualified":false,"full_guard_changed":false}),
        )?;
        let input_path = PathBuf::from(
            std::env::var_os("TRNM_PN1_NATIVE_NODE_INPUT_JSON").ok_or_else(|| {
                io::Error::other("explicit immutable original preparation required")
            })?,
        );
        require(
            input_path.is_absolute() && fs::metadata(&input_path)?.len() <= 8 * 1024 * 1024,
            "bounded original retained preparation input",
        )?;
        let raw = fs::read(&input_path)?;
        require(
            format!("{:x}", Sha256::digest(&raw)) == INPUT_SHA256,
            "exact original cdb preparation input",
        )?;
        let input: Value = serde_json::from_slice(&raw)?;
        let wire = hex::decode(
            input["seed_packets"][0]
                .as_str()
                .ok_or_else(|| io::Error::other("original first seed missing"))?,
        )?;
        let packet = Packet::decode(&wire)?;
        require(
            packet.encode()? == wire && packet.transactions.len() == 256,
            "unaltered first real seed packet",
        )?;
        // Exact support::settings() arguments, copied to avoid importing its unrelated unsafe rusage helper.
        let settings = Settings::development_with_profiles(
            Some(1_750_000_000),
            "native-public-evaluation-dev-v1",
            trnm_mvcc_fee::continuity_v1::PROFILE,
        )?;
        require(
            packet.header.parent == settings.genesis() && packet.header.height == 1,
            "actual installed parent context, no synthetic header",
        )?;
        save(
            &base.join("input-pin.json"),
            &json!({"preparation_sha256":INPUT_SHA256,"preparation_bytes":raw.len(),
            "selected_seed_index":0,"packet_sha256":format!("{:x}",Sha256::digest(&wire)),"packet_bytes":wire.len(),
            "packet":hex::encode(&wire),"transactions":packet.transactions.len(),"new_W1_proof_generation_count":0,
            "retained_real_proofs_to_verify":1,"settings_fixture":"ordinary PN1 multiprocess_support::settings"}),
        )?;
        stage = "owner";
        owner = Some(NativeIoOwner::create(std::array::from_fn(|i| {
            base.join(format!("root-{i}"))
        }))?);
        let owned = owner
            .as_ref()
            .ok_or_else(|| io::Error::other("actual owner absent"))?;
        save(&base.join("initial-seven-roots.json"), &owned.receipts()?)?;
        require(ROOT_COUNT == 7, "original seven root partition")?;
        let lease = owned.lease(0)?;
        let root_id = lease.identity();
        stage = "authenticated-bootstrap";
        save(
            &base.join("bootstrap-started.json"),
            &json!({"stage":stage,"root_identity":root_id}),
        )?;
        let mut node =
            Node::open_with_authenticated_state_and_native_io(lease.clone(), settings.clone(), 1)?;
        let initial = node.read_active()?;
        require(initial.0 == settings.genesis(), "real genesis bootstrap")?;
        require(
            node.native_io_receipt()?.is_some(),
            "actual bounded Node route selected",
        )?;
        let (checkpoint, _, _) = node.authenticated_account_multiproof(
            initial.0,
            &[trnm_pon_node::development_public(0)?],
        )?;
        require(
            checkpoint.branch() == settings.genesis() && checkpoint.height() == 0,
            "actual AuthenticatedV1 backend, not Legacy substitute",
        )?;
        let bootstrap = snapshot(&base, "authenticated-bootstrap", &lease)?;
        stage = "original-packet-admit-activate";
        let id = node.admit(&packet, settings.genesis_time() + 100_000)?;
        require(id == packet.id()?, "actual original W1 packet admitted")?;
        node.activate(id)?;
        let active = node.read_active()?;
        let stats = node.stats()?;
        require(
            active.0 == id && stats["height"] == 1 && stats["stored_blocks"] == 2,
            "real writer changed durable active branch",
        )?;
        save(
            &base.join("writer-active.json"),
            &json!({"stats":stats,"tip":hex::encode(active.0),"generation":active.1}),
        )?;
        snapshot(&base, "after-original-writer", &lease)?;
        stage = "original-public-v3-owner-pool-setup";
        // Original ordinary PN1 receiver setup, before starting its public service.
        // This trusted owner call preserves the service's POOL_NOT_ENABLED refusal.
        let pool_limits = PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 4,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: trnm_pon_node::development_public(0)?,
        };
        let pool_context = node.enable_local_mempool(pool_limits.clone())?;
        stage = "safe-readonly-factory";
        let reader = lease.open(
            &lease.directory().join("native.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        reader.pragma_update(None, "query_only", true)?;
        let page: i64 = reader.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let mode: String = reader.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        let retained: Vec<u8> = reader.query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [id.as_slice()],
            |r| r.get(0),
        )?;
        require(
            page == 4096 && mode == "wal" && retained == wire,
            "actual original4KiB WAL read-only packet bytes",
        )?;
        let history = node.history(id, settings.genesis(), 1)?;
        require(
            history.len() == 1 && history[0].encode()? == wire,
            "public Node history exact original packet",
        )?;
        let concurrent = snapshot(&base, "writer-and-readonly-live", &lease)?;
        require(
            concurrent
                .objects
                .iter()
                .any(|o| o.basename == "native.sqlite" && o.handles >= 2),
            "two actual bounded SQLite connections",
        )?;
        save(
            &base.join("readonly-result.json"),
            &json!({"page_size":page,"journal_mode":mode,
            "exact_packet_readback":true,"query_only":true,"production_public_history_verified":true,
            "trusted_owner_pool_setup":{"requested_original_limits":pool_limits,"actual_context":hex::encode(pool_context),"guest_enabled":false},
            "private_cfg_test_snapshot_path_executed":false,"writer_FULL_SQL_configuration_source_bound_not_readonly_PRAGMA_claim":true}),
        )?;
        stage = "original-public-v3-read";
        let node = Arc::new(Mutex::new(node));
        let server = identity(71)?;
        let server_key = server.public_key().to_owned();
        service_start_attempted = true;
        let (started_service, address) = Service::start(node.clone(), server)?;
        service = Some(started_service);
        let head = call(
            &base,
            "public-head",
            address,
            &Request::Head,
            &settings,
            &server_key,
        )?;
        require(head.value["tip"] == hex::encode(id), "actual public Head")?;
        let page = call(
            &base,
            "public-history",
            address,
            &Request::History {
                tip: hex::encode(id),
                after: hex::encode(settings.genesis()),
            },
            &settings,
            &server_key,
        )?;
        require(
            page.value["tip"] == hex::encode(id)
                && page.value["after"] == hex::encode(settings.genesis())
                && page.value["network"] == hex::encode(settings.network())
                && page.value["parameters"] == hex::encode(settings.parameters())
                && page.value["genesis"] == hex::encode(settings.genesis())
                && page.value["packets"]
                    .as_array()
                    .is_some_and(|p| p.len() == 1 && p[0] == hex::encode(&wire)),
            "actual public History context and exact bytes",
        )?;
        let metrics = service
            .as_mut()
            .ok_or_else(|| io::Error::other("service owner absent"))?
            .finish()?;
        save(&base.join("public-service-stopped.json"), &metrics)?;
        stage = "all-connections-real-close";
        drop(reader);
        let mutex = Arc::try_unwrap(node)
            .map_err(|_| io::Error::other("actual service still retains Node owner"))?;
        let node = mutex
            .into_inner()
            .map_err(|_| io::Error::other("Node owner mutex poisoned"))?;
        drop(node);
        let no_connections = snapshot(&base, "all-original-connections-closed", &lease)?;
        closed(&no_connections)?;
        stage = "same-domain-authenticated-cold-reopen";
        let cold =
            Node::open_with_authenticated_state_and_native_io(lease.clone(), settings.clone(), 1)?;
        require(
            cold.read_active()? == active && cold.packet(id)?.encode()? == wire,
            "same real durable state and packet after all connections closed",
        )?;
        let (checkpoint, _, _) =
            cold.authenticated_account_multiproof(id, &[trnm_pon_node::development_public(0)?])?;
        require(
            checkpoint.branch() == id && checkpoint.height() == 1,
            "cold remains AuthenticatedV1",
        )?;
        require(
            lease.identity() == root_id,
            "same held root inode, no fresh quota",
        )?;
        let cold_receipt = snapshot(&base, "same-domain-cold-readback", &lease)?;
        require(
            cold_receipt.retained_logical_bytes_peak >= concurrent.retained_logical_bytes_peak
                && cold_receipt.retained_logical_bytes_peak
                    >= bootstrap.retained_logical_bytes_peak,
            "no ledger highwater reset",
        )?;
        save(&base.join("cold-state.json"), &cold.stats()?)?;
        drop(cold);
        closed(&snapshot(&base, "cold-connection-really-closed", &lease)?)?;
        save(&base.join("final-seven-roots.json"), &owned.receipts()?)?;
        Ok(
            json!({"root_identity":root_id,"admitted_packet":hex::encode(id),"height":1,
            "actual_new_W1_proofs_generated":0,"actual_retained_proofs_admitted":1,"ordinary_input_transactions":256,
            "public_read_calls":2,"each_call_deadline_seconds":2,"readonly_page_size":4096,
            "private_cfg_test_public_reader_path_executed":false,"same_domain_AuthenticatedV1_cold_reopen":true}),
        )
    }));
    // A work panic changes ONLY the verdict. Do not resume SQL, reset the root,
    // reopen after failure or replenish any allowance. The original panic hook
    // still writes its raw observation to the externally captured stderr.
    let mut work_panic = None;
    let mut outcome = match work {
        Ok(result) => result,
        Err(payload) => {
            let text = panic_text(payload.as_ref());
            work_panic = Some(text.clone());
            Err(io::Error::other(format!("actual work panic: {text}")).into())
        }
    };
    let mut finalization_errors = Vec::new();
    let previously_observed = service.as_ref().is_some_and(|s| s.observed.is_some());
    let stop_join = catch_unwind(AssertUnwindSafe(|| {
        if let Some(service) = service.as_mut() {
            service.stop_and_observe_join();
        }
    }));
    let finalizer_panic = stop_join.err().map(|p| panic_text(p.as_ref()));
    if let Some(text) = &finalizer_panic {
        final_failure(
            &mut outcome,
            &mut finalization_errors,
            format!("service finalizer panic: {text}"),
        );
    }
    let service_ok = service.as_ref().is_some_and(Service::successful) && finalizer_panic.is_none();
    if outcome.is_ok() && !service_ok {
        final_failure(
            &mut outcome,
            &mut finalization_errors,
            "successful work requires a real joined-OK service terminal",
        );
    }
    let terminal = json!({"schema":"pn1-native-node-service-terminal-v2",
        "service_start_attempted":service_start_attempted,"owner_present":service.is_some(),
        "stop_requested":service.as_ref().map(|s|s.stop.load(Ordering::Acquire)),
        "actual_join_attempts":service.as_ref().map_or(0,|s|s.actual_join_attempts),
        "actual_join":service.as_ref().and_then(|s|s.observed.as_ref()),
        "same_observation_reused_by_finalizer":previously_observed,
        "not_started":!service_start_attempted,"finalizer_panic":finalizer_panic,
        "joined_ok":service_ok,"work_panic":work_panic,
        "missing_or_uncertain_is_failure":true,"full_W1_4097_qualified":false});
    if let Err(error) = save(&base.join("public-service-terminal.json"), &terminal) {
        final_failure(
            &mut outcome,
            &mut finalization_errors,
            format!("service terminal publication failed: {error}"),
        );
    }
    // Failure is retained before the final test assertion; never repair/reset a capped root.
    if let Some(owner) = &owner {
        let rows = catch_unwind(AssertUnwindSafe(|| owner.receipts()));
        match rows {
            Ok(Ok(rows)) => {
                if let Err(error) = save(&base.join("terminal-seven-roots.json"), &rows) {
                    final_failure(
                        &mut outcome,
                        &mut finalization_errors,
                        format!("terminal roots publication failed: {error}"),
                    );
                }
                for row in &rows {
                    if let Err(error) = healthy(row).and_then(|_| closed(row)) {
                        final_failure(
                            &mut outcome,
                            &mut finalization_errors,
                            format!("actual terminal root failed: {error}"),
                        );
                    }
                }
            }
            failure => {
                let (kind, error) = match failure {
                    Ok(Err(error)) => ("error", error.to_string()),
                    Err(payload) => ("panic", panic_text(payload.as_ref())),
                    Ok(Ok(_)) => unreachable!(),
                };
                final_failure(
                    &mut outcome,
                    &mut finalization_errors,
                    format!("terminal root snapshot {kind}: {error}"),
                );
                if let Err(write_error) = save(
                    &base.join("terminal-owner-receipt-error.json"),
                    &json!({"kind":kind,"error":error}),
                ) {
                    final_failure(
                        &mut outcome,
                        &mut finalization_errors,
                        format!("root failure publication failed: {write_error}"),
                    );
                }
            }
        }
    } else if outcome.is_ok() {
        final_failure(
            &mut outcome,
            &mut finalization_errors,
            "successful work has no retained owner terminal",
        );
    }
    let report = match &outcome {
        Ok(v) => json!({"ok":true,"observed":v}),
        Err(e) => json!({"ok":false,"error":e.to_string()}),
    };
    let result_saved = save(
        &base.join("result.json"),
        &json!({"schema":SCHEMA,"pid":std::process::id(),"last_stage":stage,
        "elapsed_ns":started.elapsed().as_nanos(),"result":report,"component_only":true,
        "full_W1_4097_qualified":false,"full_guard_changed":false,"work_hardness_accepted":false,
        "WAN_qualified":false,"merge_ready":false,"work_panic":work_panic,
        "service_joined_ok":service_ok,"finalization_errors":finalization_errors}),
    );
    // Explicit finalization owns the evidence. Drop may only reuse its actual
    // join observation; it cannot turn an unobserved/failed terminal into a pass.
    drop(service);
    assert!(
        outcome.is_ok() && result_saved.is_ok(),
        "finite actual Node integration failed; retain every original raw file"
    );
}
