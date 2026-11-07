//! Signed reference-DAG dissemination feeding the unchanged native PoN owners.
//! This is not a Conflux, Narwhal, Bullshark or Mysticeti consensus implementation.
#[path = "support/architecture_deadline.rs"]
mod architecture_deadline;
#[path = "support/current_elf_host.rs"]
mod current_elf_host;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex, verify_hex_strict};
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{self, PublicPolicy, PublicServer, Request},
        DevelopmentIdentity,
    },
    Node, Packet, PoolLimits, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

const CELL_LIMIT: usize = 65536;
const CALL_LIMIT: Duration = Duration::from_secs(2);
const ROUND_LIMIT: Duration = Duration::from_secs(15);
const MODES: [&str; 3] = [
    "serial-signed-batches",
    "concurrent-proposer-batches",
    "signed-reference-dag",
];

fn identity(index: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([index; 32])).unwrap()
}
fn policy() -> PublicPolicy {
    PublicPolicy::new(8, Duration::from_secs(2)).unwrap()
}
fn elapsed(start: Instant) -> u64 {
    start.elapsed().as_nanos().try_into().unwrap()
}
#[cfg(target_os = "linux")]
fn process_cpu() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let clock = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ProcessCPUTime)).ok()?;
    u64::try_from(clock.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(clock.tv_nsec).ok()?)
}
#[cfg(not(target_os = "linux"))]
fn process_cpu() -> Option<u64> {
    None
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cell {
    network: Hash,
    parameters: Hash,
    proposer: u64,
    round: u64,
    parents: Vec<Hash>,
    body: Hash,
    signature: String,
    transactions: Option<Vec<String>>,
}
impl Cell {
    fn body_id(transactions: &[String]) -> Hash {
        hash(
            b"research-dissemination-body-v1",
            &[&serde_json::to_vec(transactions).unwrap()],
        )
    }
    fn statement(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.network);
        bytes.extend(self.parameters);
        bytes.extend(self.proposer.to_le_bytes());
        bytes.extend(self.round.to_le_bytes());
        bytes.extend((self.parents.len() as u16).to_le_bytes());
        for parent in &self.parents {
            bytes.extend(parent);
        }
        bytes.extend(self.body);
        bytes
    }
    fn id(&self) -> Hash {
        hash(b"research-dissemination-cell-v1", &[&self.statement()])
    }
    fn authenticate(&self, settings: &Settings) -> Result<(), String> {
        if self.network != settings.network()
            || self.parameters != settings.parameters()
            || self.proposer >= 4
            || self.round >= 2
            || self.parents.len() > 4
            || self.parents.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err("CELL_CONTEXT_OR_PARENTS".into());
        }
        verify_hex_strict(
            &hex::encode(development_public(self.proposer).unwrap()),
            &self.id(),
            &self.signature,
        )
        .map_err(|_| "CELL_SIGNATURE".to_owned())
    }
    fn complete(&self, settings: &Settings) -> Result<(), String> {
        self.authenticate(settings)?;
        let transactions = self
            .transactions
            .as_ref()
            .ok_or("CELL_PAYLOAD_UNAVAILABLE")?;
        if transactions.len() != 4
            || transactions.iter().any(|raw| raw.len() > 4096)
            || Self::body_id(transactions) != self.body
        {
            return Err("CELL_BODY".into());
        }
        for raw in transactions {
            Envelope::decode(&hex::decode(raw).map_err(|_| "CELL_HEX")?)
                .map_err(|_| "CELL_ENVELOPE")?;
        }
        Ok(())
    }
    fn sign(&mut self) {
        let key = signing_key_from_hex(&hex::encode(hash(
            b"DEV-ONLY-KEY",
            &[&self.proposer.to_le_bytes()],
        )))
        .unwrap();
        self.signature = sign_hex(&key, &self.id());
    }
}

fn transfer(settings: &Settings, who: u64, account_sequence: u64, recipient: u64) -> String {
    let mut payload = development_public(recipient).unwrap().to_vec();
    payload.extend(1u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(who).unwrap(),
        nonce: account_sequence,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    hex::encode(tx.encode().unwrap())
}

fn cells(settings: &Settings, hotspot: bool) -> Vec<Cell> {
    let mut cells = Vec::new();
    for round in 0..2 {
        let mut parents: Vec<_> = if round == 0 {
            vec![]
        } else {
            cells.iter().map(Cell::id).collect()
        };
        parents.sort();
        for proposer in 0..4 {
            let transactions = (1..=4)
                .map(|offset| {
                    transfer(
                        settings,
                        proposer,
                        round * 4 + offset,
                        if hotspot { 4 } else { 10 + proposer },
                    )
                })
                .collect::<Vec<_>>();
            let mut cell = Cell {
                network: settings.network(),
                parameters: settings.parameters(),
                proposer,
                round,
                parents: parents.clone(),
                body: Cell::body_id(&transactions),
                signature: String::new(),
                transactions: Some(transactions),
            };
            cell.sign();
            cells.push(cell);
        }
    }
    cells
}

fn ordered_complete(cells: &[Cell], settings: &Settings) -> Result<Vec<Cell>, String> {
    if cells.len() != 8 {
        return Err("CELL_SET_INCOMPLETE".into());
    }
    let mut slots = BTreeMap::new();
    let mut by_id = BTreeMap::new();
    for cell in cells {
        cell.complete(settings)?;
        if slots
            .insert((cell.round, cell.proposer), cell.id())
            .is_some()
        {
            return Err("CELL_EQUIVOCATION_OR_DUPLICATE".into());
        }
        by_id.insert(cell.id(), cell);
    }
    let roots: BTreeSet<_> = cells
        .iter()
        .filter(|cell| cell.round == 0)
        .map(Cell::id)
        .collect();
    if roots.len() != 4 {
        return Err("CELL_SET_INCOMPLETE".into());
    }
    for cell in cells {
        if (cell.round == 0 && !cell.parents.is_empty())
            || (cell.round == 1 && cell.parents.iter().copied().collect::<BTreeSet<_>>() != roots)
            || cell.parents.iter().any(|id| !by_id.contains_key(id))
        {
            return Err("CELL_CAUSAL_HISTORY_UNAVAILABLE".into());
        }
    }
    let mut ordered = cells.to_vec();
    ordered.sort_by_key(|cell| (cell.round, cell.proposer));
    Ok(ordered)
}

// Test-only framed dissemination. Every mode sends the identical signed cell
// bytes through TCP and syncs them to disk, so DAG metadata is not free bandwidth.
fn disseminate(
    path: &Path,
    source: &[Cell],
    mode: usize,
    settings: &Settings,
) -> Result<(Vec<Cell>, Value), String> {
    let started = Instant::now();
    let end = started + ROUND_LIMIT;
    let cancelled = Arc::new(AtomicBool::new(false));
    fs::create_dir(path).map_err(|error| error.to_string())?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let address = listener.local_addr().unwrap();
    let receiver_path = path.to_path_buf();
    let receiver_settings = settings.clone();
    let receiver_cancelled = cancelled.clone();
    let receive = move || -> Result<(Vec<Cell>, usize), String> {
        let mut incoming = Vec::new();
        let mut bytes = 0;
        while incoming.len() < 8 {
            architecture_deadline::remaining(end, &receiver_cancelled)
                .map_err(|error| error.to_string())?;
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let frame_end = end.min(Instant::now() + CALL_LIMIT);
                    let mut length = [0; 4];
                    architecture_deadline::read_exact(
                        &mut stream,
                        &mut length,
                        frame_end,
                        &receiver_cancelled,
                    )
                    .map_err(|error| error.to_string())?;
                    let length = u32::from_be_bytes(length) as usize;
                    if length > CELL_LIMIT {
                        return Err("CELL_FRAME_LIMIT".into());
                    }
                    let mut raw = vec![0; length];
                    architecture_deadline::read_exact(
                        &mut stream,
                        &mut raw,
                        frame_end,
                        &receiver_cancelled,
                    )
                    .map_err(|error| error.to_string())?;
                    let cell: Cell =
                        serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
                    cell.complete(&receiver_settings)?;
                    architecture_deadline::remaining(frame_end, &receiver_cancelled)
                        .map_err(|error| error.to_string())?;
                    let file = receiver_path.join(format!("{}.json", hex::encode(cell.id())));
                    let mut output = fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(file)
                        .map_err(|error| error.to_string())?;
                    output.write_all(&raw).map_err(|error| error.to_string())?;
                    output.sync_all().map_err(|error| error.to_string())?;
                    fs::File::open(&receiver_path)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|error| error.to_string())?;
                    // A completed durable copy remains a fact if fsync overran.
                    // It cannot become a late successful ACK. Filesystem stalls
                    // are not preempted by these cooperative socket budgets.
                    architecture_deadline::write_all(
                        &mut stream,
                        b"stored-not-confirmed",
                        frame_end,
                        &receiver_cancelled,
                    )
                    .map_err(|error| error.to_string())?;
                    bytes += length + 4 + 20;
                    incoming.push(cell);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        architecture_deadline::remaining(end, &receiver_cancelled)
            .map_err(|error| error.to_string())?;
        Ok((incoming, bytes))
    };
    let failed_receiver = cancelled.clone();
    let receiver = thread::spawn(move || {
        let result = receive();
        if result.is_err() {
            failed_receiver.store(true, Ordering::Release);
        }
        result
    });
    let send = |cell: &Cell| -> Result<(), String> {
        let frame_end = end.min(Instant::now() + CALL_LIMIT);
        let raw = serde_json::to_vec(cell).map_err(|error| error.to_string())?;
        if raw.len() > CELL_LIMIT {
            return Err("CELL_FRAME_LIMIT".into());
        }
        let left = architecture_deadline::remaining(frame_end, &cancelled)
            .map_err(|error| error.to_string())?;
        let mut stream =
            TcpStream::connect_timeout(&address, left).map_err(|error| error.to_string())?;
        architecture_deadline::write_all(
            &mut stream,
            &(raw.len() as u32).to_be_bytes(),
            frame_end,
            &cancelled,
        )
        .and_then(|_| architecture_deadline::write_all(&mut stream, &raw, frame_end, &cancelled))
        .map_err(|error| error.to_string())?;
        let mut ack = [0; 20];
        architecture_deadline::read_exact(&mut stream, &mut ack, frame_end, &cancelled)
            .map_err(|error| error.to_string())?;
        if &ack != b"stored-not-confirmed" {
            return Err("CELL_ACK".into());
        }
        Ok(())
    };
    let send_or_cancel = |cell: &Cell| {
        let result = send(cell);
        if result.is_err() {
            cancelled.store(true, Ordering::Release);
        }
        result
    };
    let mut failures = Vec::new();
    if mode == 0 {
        for cell in source {
            if let Err(error) = send_or_cancel(cell) {
                failures.push(error);
                break;
            }
        }
    } else {
        thread::scope(|scope| {
            // Four real proposer threads each sends its two vertices. The DAG
            // arm reverses rounds to exercise missing-parent staging explicitly.
            let handles = (0..4)
                .map(|proposer| {
                    let send = &send_or_cancel;
                    scope.spawn(move || {
                        let order = if mode == 2 {
                            [proposer + 4, proposer]
                        } else {
                            [proposer, proposer + 4]
                        };
                        order
                            .into_iter()
                            .filter_map(|index| send(&source[index]).err())
                            .collect::<Vec<_>>()
                    })
                })
                .collect::<Vec<_>>();
            for handle in handles {
                match handle.join() {
                    Ok(errors) => failures.extend(errors),
                    Err(_) => {
                        cancelled.store(true, Ordering::Release);
                        failures.push("CELL_SENDER_PANIC".into());
                    }
                }
            }
        });
    }
    let receiver_result = receiver
        .join()
        .unwrap_or_else(|_| Err("CELL_RECEIVER_PANIC".into()));
    if !failures.is_empty() {
        // A derivative receiver cancellation must not erase the sender's
        // original error (for example an oversized frame).
        return Err(format!(
            "CELL_CLIENT_FAILURES:{failures:?};receiver_error:{:?}",
            receiver_result.as_ref().err()
        ));
    }
    let (received, application_bytes) = receiver_result?;
    // Read back the exact persisted material before constructing any pool input.
    let recovered = received
        .iter()
        .map(|cell| {
            let raw = fs::read(path.join(format!("{}.json", hex::encode(cell.id()))))
                .map_err(|error| error.to_string())?;
            serde_json::from_slice::<Cell>(&raw).map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    architecture_deadline::remaining(end, &cancelled).map_err(|error| error.to_string())?;
    Ok((
        recovered,
        json!({"wall_ns": elapsed(started), "application_frame_bytes": application_bytes,
        "physical_network_bytes": null, "signed_cells": 8, "durable_copy_count": 1,
        "quorum_availability_certified": false, "ack_scope": "one local stored copy, never transaction inclusion or consensus finality"}),
    ))
}

struct Service {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<public_v3::PublicMetrics>>,
}
impl Service {
    fn finish(mut self) -> public_v3::PublicMetrics {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn call(address: SocketAddr, settings: &Settings, who: u8, request: Request) -> Value {
    let started = Instant::now();
    let (reply, metrics) = public_v3::call_public_protected_v3_with_deadline(
        address,
        &request,
        settings,
        identity(71).public_key(),
        &identity(who),
        policy(),
        Some(started + CALL_LIMIT),
    );
    match reply {
        Ok(reply) => {
            json!({"ok": reply.ok, "reply": reply, "transport": metrics, "wall_ns": elapsed(started), "error": null})
        }
        Err(error) => {
            json!({"ok": false, "reply": null, "transport": metrics, "wall_ns": elapsed(started), "error": error.to_string()})
        }
    }
}

fn trial(
    path: &Path,
    settings: &Settings,
    source: &[Cell],
    packets: &[Packet],
    mode: usize,
) -> Value {
    fs::create_dir(path).unwrap();
    let start = Instant::now();
    let cpu = process_cpu();
    // Reacquire all seven complete proofs on a fresh producer for EVERY arm.
    // Identical pre-recorded bytes define the workload, not free timed tickets.
    let acquisition_started = Instant::now();
    let acquisition_cpu = process_cpu();
    let mut producer = Node::open(&path.join("trial-producer"), settings.clone(), 1).unwrap();
    let mut acquired_attempts = 0;
    for expected in packets {
        let actual = producer
            .mine(
                expected.transactions.clone(),
                expected.header.timestamp,
                ingress::now().unwrap(),
            )
            .unwrap();
        assert_eq!(
            actual.encode().unwrap(),
            expected.encode().unwrap(),
            "fixed complete proof stream"
        );
        acquired_attempts += actual.header.nonce + 1;
    }
    let acquisition_wall_ns = elapsed(acquisition_started);
    let acquisition_process_cpu_ns = acquisition_cpu
        .zip(process_cpu())
        .and_then(|(before, after)| after.checked_sub(before));
    drop(producer);
    let mut receiver = Node::open(&path.join("receiver"), settings.clone(), 1).unwrap();
    let context = hex::encode(
        receiver
            .enable_local_mempool(PoolLimits {
                max_records: 64,
                max_bytes: 131072,
                max_group_members: 16,
                critical_reserve: 0,
                max_removals: 128,
                preview_miner: development_public(0).unwrap(),
            })
            .unwrap(),
    );
    let owner = Arc::new(Mutex::new(receiver));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (shared, signal) = (owner.clone(), stop.clone());
    let service = Service {
        stop,
        worker: Some(thread::spawn(move || {
            public_v3::serve_public_protected_v3(
                listener,
                shared,
                Duration::from_secs(60),
                signal,
                PublicServer::new(identity(71), policy()).unwrap(),
            )
            .unwrap()
        })),
    };
    let mut errors = Vec::new();
    let mut pool_calls = Vec::new();
    let dissemination = disseminate(&path.join("cells"), source, mode, settings);
    let mut material = None;
    let mut dissemination_report = Value::Null;
    match dissemination.and_then(|(received, report)| {
        ordered_complete(&received, settings).map(|ordered| (ordered, report))
    }) {
        Ok((ordered, report)) => {
            material = Some(ordered);
            dissemination_report = report;
        }
        Err(error) => errors.push(error),
    }
    if let Some(ordered) = &material {
        for round in 0..2 {
            let ready = &ordered[round * 4..round * 4 + 4];
            if mode == 0 {
                for cell in ready {
                    pool_calls.push(call(
                        address,
                        settings,
                        80 + cell.proposer as u8,
                        Request::PoolSubmitBundle {
                            pool_context: context.clone(),
                            transactions: cell.transactions.clone().unwrap(),
                        },
                    ));
                }
            } else {
                thread::scope(|scope| {
                    let handles = ready
                        .iter()
                        .map(|cell| {
                            let context = context.clone();
                            scope.spawn(move || {
                                call(
                                    address,
                                    settings,
                                    80 + cell.proposer as u8,
                                    Request::PoolSubmitBundle {
                                        pool_context: context,
                                        transactions: cell.transactions.clone().unwrap(),
                                    },
                                )
                            })
                        })
                        .collect::<Vec<_>>();
                    for handle in handles {
                        pool_calls.push(handle.join().unwrap());
                    }
                });
            }
        }
    }
    let pool_admitted = pool_calls.len() == 8 && pool_calls.iter().all(|row| row["ok"] == true);
    let mut submit_calls = Vec::new();
    if pool_admitted {
        for packet in packets {
            submit_calls.push(call(
                address,
                settings,
                90,
                Request::Submit {
                    packet: hex::encode(packet.encode().unwrap()),
                },
            ));
        }
    }
    let admitted = submit_calls.len() == 7 && submit_calls.iter().all(|row| row["ok"] == true);
    let mut verifier = Node::open(&path.join("independent-client"), settings.clone(), 1).unwrap();
    let tip = packets.last().unwrap().id().unwrap();
    let included = packets[0].id().unwrap();
    let mut after = settings.genesis();
    let mut history_calls = Vec::new();
    if admitted {
        for _ in 0..16 {
            let row = call(
                address,
                settings,
                91,
                Request::History {
                    tip: hex::encode(tip),
                    after: hex::encode(after),
                },
            );
            if row["ok"] == true {
                let result = serde_json::from_value::<ingress::Page>(row["reply"]["value"].clone())
                    .map_err(|error| error.to_string())
                    .and_then(|page| {
                        ingress::receive_public_page_from(
                            &mut verifier,
                            address,
                            page,
                            tip,
                            after,
                            ingress::now().unwrap(),
                        )
                        .map_err(|error| error.to_string())
                    });
                match result {
                    Ok(next) => after = next,
                    Err(error) => errors.push(error),
                }
            }
            history_calls.push(row);
            if after == tip || !errors.is_empty() {
                break;
            }
        }
    }
    let mut confirmations = Vec::new();
    if after == tip {
        match verifier.confirmations(
            &packets[0]
                .transactions
                .iter()
                .map(|raw| (hash(b"tx-id", &[raw]), included))
                .collect::<Vec<_>>(),
            ingress::now().unwrap(),
        ) {
            Ok(batch) => confirmations = batch.observations,
            Err(error) => errors.push(error.to_string()),
        }
    }
    let latency = elapsed(start);
    let confirmed = confirmations.len() == 32
        && confirmations.iter().all(|row| {
            row.confirmed && row.depth == Some(6) && !row.finalized && !row.execution_authority
        });
    let metrics = service.finish();
    let receiver = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
    let before = receiver.read_active().unwrap();
    let client = verifier.read_active().unwrap();
    let state_equal = before.0 == client.0 && before.2 == client.2;
    drop(receiver);
    let reopened = Node::open(&path.join("receiver"), settings.clone(), 1).unwrap();
    let restart_equal = before == reopened.read_active().unwrap();
    let full_cpu = cpu
        .zip(process_cpu())
        .and_then(|(before, after)| after.checked_sub(before));
    json!({"mode": MODES[mode], "signed_transaction_count": 32, "application_payload_bytes": packets[0].transactions.iter().map(Vec::len).sum::<usize>(),
        "cold_proof_acquisition_wall_ns": acquisition_wall_ns, "cold_proof_acquisition_process_cpu_ns": acquisition_process_cpu_ns,
        "work_attempts_including_target_misses": acquired_attempts,
        "dissemination": dissemination_report, "pool_calls": pool_calls, "block_submissions": submit_calls,
        "history_calls": history_calls, "independent_confirmations": confirmations, "confirmed_transactions": if confirmed { 32 } else { 0 },
        "full_business_latency_ns": latency, "whole_trial_wall_ns_including_cold_reopen": elapsed(start), "whole_trial_process_cpu_ns": full_cpu,
        "cpu_scope": "trial process interval including proposer threads, relay, native pool, full W1, writer, independent client and cold reopen; excludes final report construction/serialization and separately measured source-workload preparation; no per-actor allocation",
        "service": metrics, "errors": errors, "native_state_equal": state_equal, "cold_reopen_equal": restart_equal,
        "finite_business_target_met": confirmed && pool_admitted && admitted && state_equal && restart_equal && errors.is_empty(),
        "consensus_profile": "unchanged-pon-nakamoto-v1", "dag_consensus_implemented": false, "committee_bft_implemented": false,
        "ghast_implemented": false, "quorum_data_availability_qualified": false, "wan_tested": false,
        "independent_operators": false, "work_profile_qualified": false, "production_activation": false})
}

fn retain_architecture_report(
    output: &Path,
    receipt_dir: Option<&Path>,
    temporary_report_dir: Option<&Path>,
    report: &Value,
) -> std::io::Result<std::path::PathBuf> {
    let raw = serde_json::to_vec_pretty(report)?;
    let write_new = |path: &Path| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&raw)?;
        file.sync_all()
    };
    let original = output.join("report.json");
    write_new(&original)?;
    if let Some(receipts) = receipt_dir {
        fs::create_dir_all(receipts)?;
        let retained = receipts.join("architecture-delivery-comparison.json");
        write_new(&retained)?;
        return Ok(retained);
    }
    if let Some(directory) = temporary_report_dir {
        // Retain only the completed JSON for direct local invocations. The
        // temporary chains still clean up normally, including assertion unwind.
        let mut retained = tempfile::Builder::new()
            .prefix("trnm-architecture-delivery-")
            .suffix(".json")
            .tempfile_in(directory)?;
        retained.write_all(&raw)?;
        retained.as_file().sync_all()?;
        let (file, path) = retained.keep().map_err(|error| error.error)?;
        drop(file);
        return Ok(path);
    }
    Ok(original)
}

#[test]
fn signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract() {
    if current_elf_host::execute_in_fixed_host(
        "architecture_delivery_compare",
        "signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract",
        None,
    ) {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let (output, temporary_report_dir) = match std::env::var_os("TRNM_ARCHITECTURE_COMPARE_DIR") {
        Some(path) => (std::path::PathBuf::from(path), None),
        None => (
            temporary.path().join("architecture-comparison"),
            Some(std::env::temp_dir()),
        ),
    };
    fs::create_dir(&output).unwrap();
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let mut samples = Vec::new();
    let mut workloads = Vec::new();
    for hotspot in [false, true] {
        let label = if hotspot {
            "hot-recipient"
        } else {
            "disjoint-recipients"
        };
        let source = cells(&settings, hotspot);
        let ordered = ordered_complete(&source, &settings).unwrap();
        let transactions = ordered
            .iter()
            .flat_map(|cell| cell.transactions.as_ref().unwrap().iter())
            .map(|raw| hex::decode(raw).unwrap())
            .collect::<Vec<_>>();
        let producer_path = output.join(format!("producer-{label}"));
        let mut producer = Node::open(&producer_path, settings.clone(), 1).unwrap();
        let generation = Instant::now();
        let generation_cpu = process_cpu();
        let mut packets = Vec::new();
        for height in 1..=7 {
            packets.push(
                producer
                    .mine(
                        if height == 1 {
                            transactions.clone()
                        } else {
                            vec![]
                        },
                        settings.genesis_time() + height * 10,
                        ingress::now().unwrap(),
                    )
                    .unwrap(),
            );
        }
        let acquisition_cpu = generation_cpu
            .zip(process_cpu())
            .and_then(|(before, after)| after.checked_sub(before));
        workloads.push(json!({"scenario": label, "cells": source, "signed_packets": packets.iter().map(|packet| hex::encode(packet.encode().unwrap())).collect::<Vec<_>>(),
            "native_acquisition_wall_ns": elapsed(generation), "native_acquisition_process_cpu_ns": acquisition_cpu,
            "work_attempts_including_target_misses": packets.iter().map(|packet| packet.header.nonce+1).sum::<u64>()}));
        for sample in 0..3 {
            for position in 0..3 {
                let mode = (sample + position) % 3;
                let path = output.join(format!(
                    "{label}-sample{sample}-position{position}-mode{mode}"
                ));
                let mut report = trial(&path, &settings, &source, &packets, mode);
                report["scenario"] = json!(label);
                report["sample"] = json!(sample);
                report["position"] = json!(position);
                samples.push(report);
            }
        }
    }
    let all_business = samples
        .iter()
        .all(|sample| sample["finite_business_target_met"] == true);
    let report = json!({"schema": "native-signed-dag-delivery-comparison-v1", "network": hex::encode(settings.network()),
        "parameters": hex::encode(settings.parameters()), "genesis": hex::encode(settings.genesis()), "workloads": workloads, "samples": samples,
        "same_signed_packets_across_modes_and_repetitions": true, "samples_per_workload_and_mode": 3, "balanced_cyclic_mode_order": true,
        "confirmation_contract": "client full native replay, depth6 AND required-work6; probabilistic unqualified-risk profile; never BFT finality",
        "all_finite_business_targets_met": all_business, "architecture_winner_declared": false,
        "protocol_switch_qualified": false, "independent_accepted": false, "wan_tested": false, "production_activation": false});
    // Publication happens after every original timing/CPU observation and before
    // the original invariant assertion. Never overwrite a prior receipt. Direct
    // local runs retain the complete JSON even without an exported destination.
    let receipt_dir = std::env::var_os("TRNM_CI_RECEIPT_DIR").map(std::path::PathBuf::from);
    let retained_report = retain_architecture_report(
        &output,
        receipt_dir.as_deref(),
        temporary_report_dir.as_deref(),
        &report,
    )
    .unwrap();
    println!(
        "{}",
        json!({"schema": report["schema"], "samples": 18, "all_finite_business_targets_met": all_business, "report_path": retained_report})
    );
    // Emit bounded failure details after every original timing/CPU observation
    // and the complete report write. Preserve the original predicate below.
    for sample in samples.iter().take(18) {
        if sample["cold_reopen_equal"] == true && sample["errors"] == json!([]) {
            continue;
        }
        let text = |key: &str| {
            sample[key]
                .as_str()
                .map(|value| value.chars().take(32).collect::<String>())
        };
        let raw_errors = sample["errors"].as_array();
        let errors = raw_errors
            .into_iter()
            .flatten()
            .take(4)
            .map(|error| {
                error
                    .as_str()
                    .unwrap_or("<non-string error>")
                    .chars()
                    .take(96)
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        eprintln!(
            "{}",
            json!({"schema": "native-signed-dag-delivery-failure-v1", "scenario": text("scenario"),
                "sample": sample["sample"].as_u64(), "position": sample["position"].as_u64(), "mode": text("mode"),
                "cold_reopen_equal": sample["cold_reopen_equal"].as_bool(), "native_state_equal": sample["native_state_equal"].as_bool(),
                "error_count": raw_errors.map(Vec::len), "error_limit": 4, "error_text_limit_chars": 96, "errors": errors})
        );
    }
    assert!(
        samples
            .iter()
            .all(|sample| sample["cold_reopen_equal"] == true && sample["errors"] == json!([])),
        "retained native delivery/replay invariants failed"
    );
}

#[test]
fn architecture_report_retains_failure_and_unknown_cost_after_fixture_unwind() {
    // File-retention control only: no native workload or service qualification.
    let report = json!({"schema": "synthetic-report-retention-control-v1",
        "all_finite_business_targets_met": false, "samples": [{
            "errors": ["original failure"], "whole_trial_process_cpu_ns": null,
            "native_state_equal": false}]});
    let expected = serde_json::to_vec_pretty(&report).unwrap();
    for use_receipts in [false, true] {
        let retained = tempfile::tempdir().unwrap();
        let fixture = tempfile::tempdir().unwrap();
        let output = fixture.path().join("architecture-comparison");
        fs::create_dir(&output).unwrap();
        let path = retain_architecture_report(
            &output,
            use_receipts.then_some(retained.path()),
            (!use_receipts).then_some(retained.path()),
            &report,
        )
        .unwrap();
        let failure = std::panic::catch_unwind(move || {
            let _fixture = fixture;
            panic!("synthetic failure after complete report publication");
        });
        assert!(failure.is_err());
        assert!(!output.exists());
        assert_eq!(fs::read(&path).unwrap(), expected);
        let observed: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(
            observed["samples"][0]["errors"],
            json!(["original failure"])
        );
        assert!(observed["samples"][0]["whole_trial_process_cpu_ns"].is_null());
        assert_eq!(observed["all_finite_business_targets_met"], false);
    }
}

#[test]
fn architecture_report_refuses_to_overwrite_an_original_receipt() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let receipts = root.path().join("receipts");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&receipts).unwrap();
    let prior = b"original failed report bytes";
    let retained = receipts.join("architecture-delivery-comparison.json");
    fs::write(&retained, prior).unwrap();
    let report = json!({"synthetic": true, "succeeded": false});
    let error = retain_architecture_report(&output, Some(&receipts), None, &report).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(retained).unwrap(), prior);
    let original = fs::read(output.join("report.json")).unwrap();
    assert_eq!(original, serde_json::to_vec_pretty(&report).unwrap());
    let error = retain_architecture_report(&output, None, None, &json!({})).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(output.join("report.json")).unwrap(), original);
}

#[test]
fn architecture_report_fallback_is_unique_and_explicit_output_stays_in_place() {
    let root = tempfile::tempdir().unwrap();
    let mut retained = Vec::new();
    for sample in 0..2 {
        let fixture = tempfile::tempdir().unwrap();
        let output = fixture.path().join("output");
        fs::create_dir(&output).unwrap();
        let report = json!({"synthetic": true, "sample": sample});
        let path = retain_architecture_report(&output, None, Some(root.path()), &report).unwrap();
        drop(fixture);
        assert_eq!(
            fs::read(&path).unwrap(),
            serde_json::to_vec_pretty(&report).unwrap()
        );
        retained.push(path);
    }
    assert_ne!(retained[0], retained[1]);
    let explicit = root.path().join("explicit");
    fs::create_dir(&explicit).unwrap();
    let report = json!({"synthetic": true, "sample": null});
    let path = retain_architecture_report(&explicit, None, None, &report).unwrap();
    assert_eq!(path, explicit.join("report.json"));
    assert_eq!(
        fs::read(path).unwrap(),
        serde_json::to_vec_pretty(&report).unwrap()
    );
}

#[test]
fn dissemination_cancellation_preserves_original_sender_and_receiver_failures() {
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut oversized = cells(&settings, true);
    oversized[0].transactions.as_mut().unwrap()[0] = "ff".repeat(CELL_LIMIT);
    let error = disseminate(
        &directory.path().join("oversized"),
        &oversized,
        0,
        &settings,
    )
    .unwrap_err();
    assert!(error.contains("CELL_FRAME_LIMIT"), "{error}");
    assert!(error.contains("CELL_CANCELLED"), "{error}");

    let mut invalid = cells(&settings, true);
    invalid[0].signature = "00".repeat(64);
    let error = disseminate(&directory.path().join("invalid"), &invalid, 2, &settings).unwrap_err();
    assert!(error.contains("CELL_SIGNATURE"), "{error}");
}

#[test]
fn absolute_deadline_dissemination_keeps_complete_material_in_all_three_modes() {
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let original = cells(&settings, true);
    let directory = tempfile::tempdir().unwrap();
    let mut expected_bytes = None;
    for mode in 0..MODES.len() {
        let (received, report) = disseminate(
            &directory.path().join(mode.to_string()),
            &original,
            mode,
            &settings,
        )
        .unwrap();
        let ordered = ordered_complete(&received, &settings).unwrap();
        assert_eq!(
            serde_json::to_vec(&ordered).unwrap(),
            serde_json::to_vec(&original).unwrap()
        );
        let bytes = report["application_frame_bytes"].as_u64().unwrap();
        assert!(bytes > 0);
        assert!(expected_bytes.is_none_or(|previous| previous == bytes));
        expected_bytes = Some(bytes);
        assert_eq!(report["signed_cells"], 8);
        assert_eq!(report["quorum_availability_certified"], false);
    }
}

#[test]
fn reference_dag_rejects_withheld_body_equivocation_and_changed_signed_history() {
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let original = cells(&settings, true);
    let mut withheld = original.clone();
    withheld[0].transactions = None;
    assert_eq!(
        ordered_complete(&withheld, &settings).unwrap_err(),
        "CELL_PAYLOAD_UNAVAILABLE"
    );
    let mut changed = original.clone();
    changed[4].parents[0][0] ^= 1;
    assert!(ordered_complete(&changed, &settings).is_err());
    let mut equivocation = original.clone();
    equivocation[1] = equivocation[0].clone();
    equivocation[1].transactions.as_mut().unwrap()[0] = transfer(&settings, 0, 1, 11);
    equivocation[1].body = Cell::body_id(equivocation[1].transactions.as_ref().unwrap());
    equivocation[1].sign();
    assert_eq!(
        ordered_complete(&equivocation, &settings).unwrap_err(),
        "CELL_EQUIVOCATION_OR_DUPLICATE"
    );
    let mut missing = original.clone();
    missing.remove(0);
    assert_eq!(
        ordered_complete(&missing, &settings).unwrap_err(),
        "CELL_SET_INCOMPLETE"
    );
}
