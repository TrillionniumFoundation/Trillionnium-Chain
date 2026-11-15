//! One explicitly partitioned allowance for both ends of one loopback replay.
//! No member, cached continuation, refusal, or readback creates a fresh owner.

use super::*;
use std::{
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::Ordering,
        mpsc::{self, Receiver, RecvTimeoutError},
        Arc,
    },
};

use serde::Serialize;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Allowance {
    max_connections: u64,
    max_received_bytes: u64,
    max_sent_bytes: u64,
    max_messages: u64,
    max_readback_bytes: u64,
    max_readback_chunks: u64,
    max_readback_attempts: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Network {
    schema: String,
    request_timeout_ms: u64,
    total: Allowance,
    publisher: Allowance,
    consumer: Allowance,
}

impl Network {
    pub(super) fn validate(&self) -> Result<()> {
        check(
            self.schema == "trnm.cell-sealed-research-network.v2"
                && (10..=30_000).contains(&self.request_timeout_ms),
            "explicit V2 network profile and bounded request timeout",
        )?;
        // Both endpoints are charged. A new member receives neither another
        // deadline nor another copy of either endpoint's reservation.
        for (publisher, consumer, total) in [
            (
                self.publisher.max_connections,
                self.consumer.max_connections,
                self.total.max_connections,
            ),
            (
                self.publisher.max_received_bytes,
                self.consumer.max_received_bytes,
                self.total.max_received_bytes,
            ),
            (
                self.publisher.max_sent_bytes,
                self.consumer.max_sent_bytes,
                self.total.max_sent_bytes,
            ),
            (
                self.publisher.max_messages,
                self.consumer.max_messages,
                self.total.max_messages,
            ),
            (
                self.publisher.max_readback_bytes,
                self.consumer.max_readback_bytes,
                self.total.max_readback_bytes,
            ),
            (
                self.publisher.max_readback_chunks,
                self.consumer.max_readback_chunks,
                self.total.max_readback_chunks,
            ),
            (
                self.publisher.max_readback_attempts,
                self.consumer.max_readback_attempts,
                self.total.max_readback_attempts,
            ),
        ] {
            check(
                publisher > 0
                    && consumer > 0
                    && publisher
                        .checked_add(consumer)
                        .is_some_and(|sum| sum <= total),
                "endpoint allowances must fit one finite operation allowance",
            )?;
        }
        Ok(())
    }

    fn limits(&self, allowance: &Allowance, deadline: Instant) -> CellBep52ReleaseLimitsV2 {
        CellBep52ReleaseLimitsV2 {
            deadline,
            request_timeout: Duration::from_millis(self.request_timeout_ms),
            max_connections: allowance.max_connections,
            max_received_bytes: allowance.max_received_bytes,
            max_sent_bytes: allowance.max_sent_bytes,
            max_messages: allowance.max_messages,
            max_readback_bytes: allowance.max_readback_bytes,
            max_readback_chunks: allowance.max_readback_chunks,
            max_readback_attempts: allowance.max_readback_attempts,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct Usage {
    connection_attempts: u64,
    dht_query_attempts: u64,
    received_bytes: u64,
    sent_bytes: u64,
    received_messages: u64,
    sent_messages: u64,
    refused_connections: u64,
    refused_dht_queries: u64,
    completed_fetches: u64,
    readback_reserved_bytes: u64,
    readback_reserved_chunks: u64,
    readback_attempts: u64,
    readback_completed: u64,
}

impl Usage {
    fn capture(session: &CellBep52ReleaseSessionV2<'_>) -> Self {
        let usage = session.usage();
        let readback = session.readback_usage();
        Self {
            connection_attempts: usage.connection_attempts,
            dht_query_attempts: usage.dht_query_attempts,
            received_bytes: usage.received_bytes,
            sent_bytes: usage.sent_bytes,
            received_messages: usage.received_messages,
            sent_messages: usage.sent_messages,
            refused_connections: usage.refused_connections,
            refused_dht_queries: usage.refused_dht_queries,
            completed_fetches: usage.completed_fetches,
            readback_reserved_bytes: readback.reserved_bytes,
            readback_reserved_chunks: readback.reserved_chunks,
            readback_attempts: readback.attempts,
            readback_completed: readback.completed,
        }
    }

    fn total(&self, other: &Self) -> Result<Self> {
        fn add(left: u64, right: u64) -> Result<u64> {
            left.checked_add(right)
                .ok_or_else(|| "operation usage overflow".into())
        }
        Ok(Self {
            connection_attempts: add(self.connection_attempts, other.connection_attempts)?,
            dht_query_attempts: add(self.dht_query_attempts, other.dht_query_attempts)?,
            received_bytes: add(self.received_bytes, other.received_bytes)?,
            sent_bytes: add(self.sent_bytes, other.sent_bytes)?,
            received_messages: add(self.received_messages, other.received_messages)?,
            sent_messages: add(self.sent_messages, other.sent_messages)?,
            refused_connections: add(self.refused_connections, other.refused_connections)?,
            refused_dht_queries: add(self.refused_dht_queries, other.refused_dht_queries)?,
            completed_fetches: add(self.completed_fetches, other.completed_fetches)?,
            readback_reserved_bytes: add(
                self.readback_reserved_bytes,
                other.readback_reserved_bytes,
            )?,
            readback_reserved_chunks: add(
                self.readback_reserved_chunks,
                other.readback_reserved_chunks,
            )?,
            readback_attempts: add(self.readback_attempts, other.readback_attempts)?,
            readback_completed: add(self.readback_completed, other.readback_completed)?,
        })
    }

    fn fits(&self, allowance: &Allowance) -> Result<()> {
        check(
            self.connection_attempts <= allowance.max_connections
                && self.received_bytes <= allowance.max_received_bytes
                && self.sent_bytes <= allowance.max_sent_bytes
                && self
                    .received_messages
                    .checked_add(self.sent_messages)
                    .is_some_and(|total| total <= allowance.max_messages)
                && self.readback_reserved_bytes <= allowance.max_readback_bytes
                && self.readback_reserved_chunks <= allowance.max_readback_chunks
                && self.readback_attempts <= allowance.max_readback_attempts
                && self.dht_query_attempts == 0,
            "actual endpoint totals exceeded the original operation allowance",
        )
    }
}

struct Member {
    index: usize,
    finished: Arc<AtomicBool>,
}

struct Publisher<'a> {
    source_path: &'a Path,
    listener: TcpListener,
    requests: Receiver<Member>,
    expected_plan: [u8; 64],
    owner: &'a CellVersionLoaderContextV1<'a>,
    deadline: Instant,
    stopped: Arc<AtomicBool>,
}

fn publish(context: Publisher<'_>, session: &mut CellBep52ReleaseSessionV2<'_>) -> Result<()> {
    // Open a separate read-only SQLite connection in this thread; the source
    // connection is never shared across concurrent threads.
    let source = CellStoreV1::open_read_only(context.source_path)?;
    loop {
        check(
            !context.stopped.load(Ordering::Acquire),
            "original TCP operation stopped",
        )?;
        let remaining = context
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or("original TCP publication deadline")?;
        let member = match context.requests.recv_timeout(remaining) {
            Ok(member) => member,
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => {
                return Err("original TCP publication deadline".into())
            }
        };
        loop {
            check(
                Instant::now() < context.deadline,
                "original TCP accept deadline",
            )?;
            check(
                !context.stopped.load(Ordering::Acquire),
                "original TCP operation stopped",
            )?;
            match context.listener.accept() {
                Ok((stream, peer)) => {
                    check(
                        peer.ip().is_loopback(),
                        "research publisher accepts loopback only",
                    )?;
                    session.serve_member(
                        &source,
                        member.index,
                        context.expected_plan,
                        context.owner,
                        stream,
                        *b"-TRNM-V2-PUBLISHER--",
                    )?;
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    // Cross-member dedup may complete a member without a TCP
                    // connection. Its original session and charge remain.
                    if member.finished.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

pub(super) struct Transfer<'a> {
    pub source: &'a CellStoreV1,
    pub source_path: &'a Path,
    pub received: &'a CellStoreV1,
    pub version: &'a CellVersionManifestV1,
    pub owner: &'a CellVersionLoaderContextV1<'a>,
    pub operation: [u8; 32],
    pub deadline: Instant,
    pub output: &'a Path,
    pub network: &'a Network,
}

pub(super) fn transfer(input: Transfer<'_>, report: &mut Value) -> Result<[u8; 64]> {
    input.network.validate()?;
    let empty = input.received.cache_usage()?;
    check(
        empty.chunk_rows == 0 && empty.manifest_rows == 0,
        "empty BEP52 receiving cache required",
    )?;
    let mut bindings = Vec::new();
    for manifest in input.version.manifests() {
        bindings.push(CellBep52StorageBindingV2::from_pinned_store(
            manifest,
            manifest.id(),
            manifest.context(),
            input.source,
            CellReleaseLimitsV1 {
                max_payload_bytes: manifest.size(),
                max_chunks: manifest.chunks().len() as u64,
                deadline: input.deadline,
            },
        )?);
    }
    let plan = CellBep52ReleasePlanV2::new(input.version.clone(), input.owner, bindings)?;
    let expected_plan = plan.commitment();
    let artifacts = input.output.join("bep52");
    fs::create_dir(&artifacts)?;
    fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700))?;
    write_new(
        &artifacts.join("owner-version.tcv1"),
        &input.version.encode(),
    )?;
    let mut members = Vec::new();
    for (index, binding) in plan.bindings().iter().enumerate() {
        let mapping = format!("{index:04}-{}.cbm2", hex::encode(binding.manifest_id()));
        write_new(&artifacts.join(&mapping), &binding.mapping_bytes())?;
        members.push(json!({"index": index, "manifest": hex::encode(binding.manifest_id()),
            "mapping": hex::encode(binding.mapping_id()), "info_hash": hex::encode(binding.info_hash()),
            "payload_bytes": binding.manifest().size(), "storage_chunks": binding.manifest().chunks().len(),
            "merkle_leaves": binding.leaf_count(), "mapping_file": mapping}));
    }
    write_new(
        &artifacts.join("owner-plan.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema": "trnm.cell-sealed-research-bep52-plan.v2", "operation": hex::encode(input.operation),
            "plan": hex::encode(expected_plan), "tcv1": hex::encode(input.version.commitment()),
            "payload_bytes": plan.payload_bytes(), "storage_chunks": plan.chunks(), "members": members,
            "pins_origin": "same independently pinned source capture; never peer latest",
        }))?,
    )?;

    let mut consumer = CellBep52ReleaseSessionV2::new(
        input.operation,
        &plan,
        expected_plan,
        input.owner,
        input
            .network
            .limits(&input.network.consumer, input.deadline),
    )?;
    let mut publisher = CellBep52ReleaseSessionV2::new(
        input.operation,
        &plan,
        expected_plan,
        input.owner,
        input
            .network
            .limits(&input.network.publisher, input.deadline),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    check(address.ip().is_loopback(), "explicit loopback listener")?;
    report["bep52"] = json!({
        "profile": CELL_BEP52_RELEASE_PROFILE_V2, "operation": hex::encode(input.operation),
        "plan": hex::encode(expected_plan), "tcv1": hex::encode(input.version.commitment()),
        "peer": address.to_string(), "loopback_only": true, "single_operator": true,
        "independent_failure_domains": false, "empty_initial_cache": true,
        "original_absolute_deadline": true, "endpoint_sessions": 2,
        "sessions_per_endpoint": 1, "member_sessions_created": 0,
        "allowance": input.network, "complete_readback": false,
        "transport_plan_includes_cts1": false, "refunded_after_failure": false,
    });
    let publisher_cancel = publisher.cancellation_handle();
    let consumer_cancel = consumer.cancellation_handle();
    let stopped = Arc::new(AtomicBool::new(false));
    // At most one bounded-plan request is enqueued per canonical member. This
    // queue does not contain payload bytes and has no retry producer.
    let (requests, receiver) = mpsc::channel();
    let mut fetched_members = Vec::new();
    let (fetched, served, publisher_usage) = thread::scope(|scope| {
        let source_path = input.source_path;
        let owner = input.owner;
        let deadline = input.deadline;
        let worker_stopped = Arc::clone(&stopped);
        let worker_consumer_cancel = Arc::clone(&consumer_cancel);
        let worker_publisher_cancel = Arc::clone(&publisher_cancel);
        let worker = scope.spawn(move || {
            let result = publish(
                Publisher {
                    source_path,
                    listener,
                    requests: receiver,
                    expected_plan,
                    owner,
                    deadline,
                    stopped: Arc::clone(&worker_stopped),
                },
                &mut publisher,
            );
            if result.is_err() {
                worker_stopped.store(true, Ordering::Release);
                worker_consumer_cancel.store(true, Ordering::Release);
                worker_publisher_cancel.store(true, Ordering::Release);
            }
            (result, Usage::capture(&publisher))
        });
        let fetched = (|| -> Result<()> {
            for (index, _) in plan.bindings().iter().enumerate() {
                check(
                    !stopped.load(Ordering::Acquire),
                    "original publisher stopped",
                )?;
                let finished = Arc::new(AtomicBool::new(false));
                requests.send(Member {
                    index,
                    finished: Arc::clone(&finished),
                })?;
                let result = consumer.fetch_member(
                    input.received,
                    index,
                    expected_plan,
                    input.owner,
                    &[address],
                    *b"-TRNM-V2-CONSUMER---",
                );
                finished.store(true, Ordering::Release);
                let fetched = result?;
                check(
                    fetched.supplying_peers.iter().all(|peer| *peer == address),
                    "only selected loopback source",
                )?;
                fetched_members.push(json!({"index": index, "manifest": hex::encode(fetched.manifest_id),
                    "payload_bytes": fetched.payload_bytes, "downloaded_bytes": fetched.downloaded_bytes,
                    "downloaded_chunks": fetched.downloaded_chunks, "cached_chunks": fetched.cached_chunks,
                    "supplying_peers": fetched.supplying_peers.iter().map(SocketAddr::to_string).collect::<Vec<_>>()}));
            }
            consumer.verify_complete(input.received, expected_plan, input.owner)?;
            Ok(())
        })();
        if fetched.is_err() {
            stopped.store(true, Ordering::Release);
            publisher_cancel.store(true, Ordering::Release);
            consumer_cancel.store(true, Ordering::Release);
        }
        drop(requests);
        // No publisher thread or source connection survives the transfer stage.
        match worker.join() {
            Ok((served, usage)) => (fetched, served, Some(usage)),
            Err(_) => (
                fetched,
                Err("original publisher thread panicked".into()),
                None,
            ),
        }
    });
    let consumer_usage = Usage::capture(&consumer);
    report["bep52"]["members"] = json!(fetched_members);
    report["bep52"]["consumer_usage"] = json!(consumer_usage);
    report["bep52"]["publisher_usage"] = json!(publisher_usage);
    report["bep52"]["consumer_error"] = json!(fetched.as_ref().err().map(ToString::to_string));
    report["bep52"]["publisher_error"] = json!(served.as_ref().err().map(ToString::to_string));
    if let Some(publisher_usage) = publisher_usage {
        publisher_usage.fits(&input.network.publisher)?;
        consumer_usage.fits(&input.network.consumer)?;
        let total = publisher_usage.total(&consumer_usage)?;
        total.fits(&input.network.total)?;
        report["bep52"]["total_usage"] = json!(total);
    }
    fetched?;
    served?;
    check(
        consumer_usage.connection_attempts > 0 && consumer_usage.readback_completed == 1,
        "actual TCP and one complete received-byte readback required",
    )?;
    check(
        Instant::now() < input.deadline,
        "original complete-transfer deadline",
    )?;
    report["bep52"]["complete_readback"] = json!(true);
    Ok(expected_plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network() -> Network {
        let grant = Allowance {
            max_connections: 64,
            max_received_bytes: 1 << 30,
            max_sent_bytes: 1 << 30,
            max_messages: 1_000_000,
            max_readback_bytes: 512 << 20,
            max_readback_chunks: 2048,
            max_readback_attempts: 1,
        };
        let total = Allowance {
            max_connections: 128,
            max_received_bytes: 2 << 30,
            max_sent_bytes: 2 << 30,
            max_messages: 2_000_000,
            max_readback_bytes: 1024 << 20,
            max_readback_chunks: 4096,
            max_readback_attempts: 2,
        };
        Network {
            schema: "trnm.cell-sealed-research-network.v2".into(),
            request_timeout_ms: 3000,
            total,
            publisher: grant.clone(),
            consumer: grant,
        }
    }

    #[test]
    fn explicit_endpoint_allowances_fit_one_total() {
        network().validate().unwrap();
        let mut input = network();
        input.total.max_received_bytes -= 1;
        assert!(input.validate().is_err());
        input = network();
        input.publisher.max_connections = u64::MAX;
        assert!(input.validate().is_err());
    }

    #[test]
    fn old_network_profile_unknown_fields_and_missing_grants_are_refused() {
        let input = network();
        let mut value = serde_json::to_value(input).unwrap();
        value["schema"] = json!("trnm.cell-sealed-research-network.v1");
        assert!(serde_json::from_value::<Network>(value.clone())
            .unwrap()
            .validate()
            .is_err());
        value["schema"] = json!("trnm.cell-sealed-research-network.v2");
        value["latest"] = json!(true);
        assert!(serde_json::from_value::<Network>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove("latest");
        value.as_object_mut().unwrap().remove("publisher");
        assert!(serde_json::from_value::<Network>(value).is_err());
    }

    #[test]
    fn same_operation_transfer_handles_cross_member_cache_dedup() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("publisher.sqlite");
        let source = cache(&source_path).unwrap();
        let received = cache(&directory.path().join("received.sqlite")).unwrap();
        let payload_path = directory.path().join("synthetic-fixture.bin");
        let payload = b"synthetic transport fixture; this is not a model run";
        fs::write(&payload_path, payload).unwrap();
        let input = Input {
            path: payload_path,
            sha256: hex::encode(Sha256::digest(payload)),
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        let context = CellContextV1 {
            family: "test".into(),
            base: [1; 32],
            parent: [2; 32],
            tokenizer: [3; 32],
            layout: [4; 32],
            runtime: [5; 32],
        };
        let environment_input = BTreeMap::from([("runtime.bin".into(), input.clone())]);
        let (mut manifests, files) =
            pack(&source, &environment_input, &context, true, deadline).unwrap();
        let environment =
            CellReleaseClosureV1::new(context.clone(), 1, [6; 32], vec![0], files).unwrap();
        let mut model_context = context;
        model_context.runtime = environment.id();
        let model_input = BTreeMap::from([("base/model.safetensors".into(), input)]);
        let (model_manifests, files) =
            pack(&source, &model_input, &model_context, false, deadline).unwrap();
        let model = CellModelReleaseRootV1::new(
            CellReleaseClosureV1::new(model_context, 1, [7; 32], vec![0], files).unwrap(),
            vec![],
        )
        .unwrap();
        manifests.extend(model_manifests);
        manifests.sort_by_key(CellManifestV1::id);
        let version = CellVersionManifestV1::new(model, environment, manifests).unwrap();
        let model_owner = owner(version.model().closure(), vec![CellFileRoleV1::Base], 1024);
        let environment_owner = owner(
            version.environment(),
            vec![CellFileRoleV1::Configuration],
            1024,
        );
        let expected = CellVersionLoaderContextV1 {
            commitment: version.commitment(),
            model: &model_owner,
            environment: &environment_owner,
        };
        let allowance = network();
        let mut report = json!({});
        transfer(
            Transfer {
                source: &source,
                source_path: &source_path,
                received: &received,
                version: &version,
                owner: &expected,
                operation: [9; 32],
                deadline,
                output: directory.path(),
                network: &allowance,
            },
            &mut report,
        )
        .unwrap();
        assert_eq!(report["bep52"]["complete_readback"], true);
        assert_eq!(report["bep52"]["tcv1"], hex::encode(version.commitment()));
        assert_eq!(report["bep52"]["members"].as_array().unwrap().len(), 2);
        assert_eq!(report["bep52"]["consumer_usage"]["connection_attempts"], 1);
        assert_eq!(report["bep52"]["publisher_usage"]["connection_attempts"], 1);
        assert_eq!(received.cache_usage().unwrap().manifest_rows, 2);
        assert_eq!(received.cache_usage().unwrap().chunk_rows, 1);
    }
}
