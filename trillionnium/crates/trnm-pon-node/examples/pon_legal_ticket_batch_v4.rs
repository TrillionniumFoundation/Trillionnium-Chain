//! Real CPU batch solving with first admission and archived winning packet bytes.
//! This finite paired experiment changes no producer, work predicate or Node.
//! Each cohort owns a fresh store. Sibling tickets are not active-chain rewards.
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    collections::BTreeSet,
    error::Error,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};
use trnm_crypto_primitives::pon_work::{
    self, maintenance_limb::MaintenanceLimbPreparedTask, PreparedTask,
};
use trnm_pon_node::{development_public, Node, Packet, Settings};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const SCHEMA: &str = "pon-legal-ticket-cpu-batch-cost-v4";
const SEARCHES: u64 = 64;
const ATTEMPTS: u64 = 8;
const ROUNDS: u64 = 2;
const SEED: u64 = 1;
const SECONDS: u64 = 240;

#[derive(Clone, Copy, Serialize)]
struct Timing {
    wall_ns: u128,
    process_cpu_ns: Option<u64>,
}
impl Timing {
    fn zero() -> Self {
        Self {
            wall_ns: 0,
            process_cpu_ns: Some(0),
        }
    }
    fn add(&mut self, other: Self) -> Result<()> {
        self.wall_ns = self
            .wall_ns
            .checked_add(other.wall_ns)
            .ok_or("WALL_OVERFLOW")?;
        self.process_cpu_ns = self
            .process_cpu_ns
            .zip(other.process_cpu_ns)
            .and_then(|(a, b)| a.checked_add(b));
        Ok(())
    }
}
fn cpu() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ProcessCPUTime)).ok()?;
    let nanos = u64::try_from(t.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    u64::try_from(t.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(nanos)
}
fn measured<T>(f: impl FnOnce() -> T) -> (T, Timing) {
    let before = cpu();
    let start = Instant::now();
    let result = f();
    let wall_ns = start.elapsed().as_nanos();
    (
        result,
        Timing {
            wall_ns,
            process_cpu_ns: before.zip(cpu()).and_then(|(a, b)| b.checked_sub(a)),
        },
    )
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn emit(mut value: Value) -> Result<()> {
    value["schema"] = json!(SCHEMA);
    let raw = serde_json::to_vec(&value)?;
    if raw.len() > 2 * 1024 * 1024 {
        return Err("ROW_BOUND".into());
    }
    let mut output = std::io::stdout().lock();
    output.write_all(&raw)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
fn within(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err("CAMPAIGN_DEADLINE".into());
    }
    Ok(())
}
enum Producer {
    General(PreparedTask),
    Limb(MaintenanceLimbPreparedTask),
}
impl Producer {
    fn new(limb: bool, a: &[u32], b: &[u32]) -> Result<Self> {
        if limb {
            Ok(Self::Limb(
                MaintenanceLimbPreparedTask::new(a, b)
                    .map_err(|e| format!("LIMB_PREPARE:{e:?}"))?
                    .ok_or("MAINTENANCE_UNSUPPORTED")?,
            ))
        } else {
            Ok(Self::General(
                PreparedTask::new(a, b).map_err(|e| format!("PREPARE:{e:?}"))?,
            ))
        }
    }
    fn prove(&self, challenge: pon_work::Hash) -> Result<Vec<u8>> {
        match self {
            Self::General(p) => p.prove(challenge),
            Self::Limb(p) => p.prove(challenge),
        }
        .map_err(|e| format!("COMPLETE_W1:{e:?}").into())
    }
}

fn cohort(
    settings: &Settings,
    round: u64,
    limb: bool,
    order: usize,
    workers: usize,
    packet_root: &Path,
    deadline: Instant,
) -> Result<(String, Value)> {
    let cohort_started = Instant::now();
    let cohort_cpu = cpu();
    within(deadline)?;
    let label = format!(
        "round-{round}-workers-{workers}-{}",
        if limb { "limb" } else { "general" }
    );
    let archive = packet_root.join(&label);
    let (dir, directory) = measured(|| -> Result<_> {
        let dir = tempfile::tempdir()?;
        std::fs::create_dir(&archive)?;
        Ok(dir)
    });
    let dir = dir?;
    let (node, open) = measured(|| Node::open(dir.path(), settings.clone(), 1));
    let mut node = node?;
    let (bundle, bootstrap_material) = measured(|| settings.public_task_bootstrap());
    let bundle = bundle?;
    // Retain and charge actual original template acquisition, including its
    // original complete proof search. It is not another effective ticket.
    let (seed, template) = measured(|| {
        node.make_public_bootstrap(
            &bundle,
            settings.genesis(),
            vec![],
            development_public(3).expect("fixed public fixture identity"),
            settings.genesis_time() + 11,
            4096,
        )
    });
    let seed = seed?;
    let ((a, b), matrices) = measured(trnm_mvcc_fee::continuity_v1::maintenance_matrices);
    let task = pon_work::task_id(&a, &b).map_err(|e| format!("TASK:{e:?}"))?;
    if seed.header.work_task != task
        || seed.header.target != node.expected_target(seed.header.parent)?
    {
        return Err("ACTUAL_NATIVE_TASK_OR_TARGET".into());
    }
    // One immutable prepared producer is shared. The entire thread batch is
    // timed once with the process clock; overlapping trial times are diagnostic.
    let (producer, setup) = measured(|| Producer::new(limb, &a, &b));
    let producer = producer?;
    let (batch, generation) = measured(|| -> Result<_> {
        let batch_origin = Instant::now();
        std::thread::scope(|scope| -> Result<_> {
            let producer_ref = &producer;
            let seed_ref = &seed;
            let mut handles = Vec::new();
            for worker in 0..workers {
                handles.push(scope.spawn(move || -> Result<_> {
                    let started_offset_ns = batch_origin.elapsed().as_nanos();
                    let mut completed = Vec::new();
                    for search in (worker as u64..SEARCHES).step_by(workers) {
                        within(deadline)?;
                        let mut trials = Vec::new();
                        let mut winner = None;
                        let mut search_stream = Sha256::new();
                        search_stream.update(b"TRNM-LEGAL-CPU-BATCH-SEARCH-V4\0");
                        search_stream.update(search.to_le_bytes());
                        for trial in 0..ATTEMPTS {
                            within(deadline)?;
                            let mut header = seed_ref.header.clone();
                            header.nonce = (SEED << 32) + round * (1_u64 << 24) + search * ATTEMPTS + trial;
                            let started = Instant::now();
                            let challenge = header.challenge();
                            let proof = producer_ref.prove(challenge)?;
                            if proof.len() != pon_work::PROOF_BYTES {
                                return Err("PROOF_LENGTH".into());
                            }
                            let ticket = pon_work::hash(b"ticket", &[&challenge, &proof[pon_work::PROOF_BYTES - 32..]]);
                            let proof_wall_ns = started.elapsed().as_nanos();
                            let hit = ticket <= header.target;
                            search_stream.update(header.encode());
                            search_stream.update(&proof);
                            search_stream.update(ticket);
                            trials.push(json!({"trial":trial,"nonce":header.nonce,
                                "challenge":hex::encode(challenge),"proof_sha256":sha(&proof),
                                "ticket":hex::encode(ticket),"target_hit":hit,
                                "overlapping_kernel_wall_ns":proof_wall_ns}));
                            if hit {
                                winner = Some(Packet { header, transactions: vec![], proof });
                                break;
                            }
                        }
                        completed.push((search, worker, trials, winner, hex::encode(search_stream.finalize())));
                    }
                    let observation = json!({"worker":worker,"thread_id":format!("{:?}",std::thread::current().id()),
                        "searches":completed.len(),"started_offset_ns":started_offset_ns,
                        "finished_offset_ns":batch_origin.elapsed().as_nanos()});
                    Ok((completed, observation))
                }));
            }
            // Every scoped worker is joined, including on an error. No native
            // admission runs concurrently with this batch interval.
            let mut completed = Vec::new();
            let mut observations = Vec::new();
            for handle in handles {
                let (searches, observation) = handle.join().map_err(|_| "BATCH_WORKER_PANIC")??;
                completed.extend(searches);
                observations.push(observation);
            }
            Ok((completed, observations))
        })
    });
    let (mut batch, worker_observations) = batch?;
    batch.sort_by_key(|row| row.0);
    if batch.len() != SEARCHES as usize {
        return Err("INCOMPLETE_BATCH".into());
    }
    let mut encode = Timing::zero();
    let mut archive_cost = Timing::zero();
    let mut admit = Timing::zero();
    let mut readback = Timing::zero();
    let mut attempts = 0;
    let mut winners = Vec::new();
    let mut ids = BTreeSet::new();
    let mut searches = Vec::new();
    let mut stream = Sha256::new();
    stream.update(b"TRNM-LEGAL-CPU-BATCH-STREAM-V4\0");
    for (index, (search, worker, mut trials, winner, search_digest)) in
        batch.into_iter().enumerate()
    {
        within(deadline)?;
        if search != index as u64 || worker != index % workers {
            return Err("BATCH_SEARCH_OWNERSHIP".into());
        }
        stream.update(search.to_le_bytes());
        stream.update(hex::decode(&search_digest)?);
        attempts += trials.len();
        let won = winner.is_some();
        if let Some(packet) = winner {
            let id = packet.id()?;
            if !ids.insert(id) {
                return Err("DUPLICATE_NATIVE_TICKET".into());
            }
            let (bytes, encoded) = measured(|| packet.encode());
            let bytes = bytes?;
            encode.add(encoded)?;
            let relative = format!("{label}/{}.packet", hex::encode(id));
            let (saved, timing) = measured(|| -> Result<()> {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(packet_root.join(&relative))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                Ok(())
            });
            saved?;
            archive_cost.add(timing)?;
            let (accepted, timing) = measured(|| node.admit(&packet, packet.header.timestamp + 1));
            admit.add(timing)?;
            if accepted? != id {
                return Err("NATIVE_ADMISSION_ID".into());
            }
            winners.push((id, sha(&bytes), bytes.len(), relative));
            let last = trials.last_mut().ok_or("TRIAL_ABSENT")?;
            last["native_admission"] = json!(timing);
            last["packet_id"] = json!(hex::encode(id));
            last["packet_bytes"] = json!(bytes.len());
        }
        searches.push(json!({"search":search,"worker":worker,"won":won,
            "search_stream_sha256":search_digest,"trials":trials}));
    }
    let hot_active = node.active()?;
    if hot_active.0 != settings.genesis() {
        return Err("ADMISSION_CHANGED_ACTIVE_TIP".into());
    }
    // Ordinary cold open performs STATE_RECOVERY. All admitted siblings have
    // the same parent/target/height, so the original work/height/id ordering
    // selects the lowest packet id. Its real recovery cost stays in reopen.
    let expected_cold_tip = ids.first().copied().unwrap_or(settings.genesis());
    let (_, close) = measured(|| drop(node));
    within(deadline)?;
    let (cold, reopen) = measured(|| Node::open(dir.path(), settings.clone(), 1));
    let cold = cold?;
    let cold_active = cold.active()?;
    if cold_active.0 != expected_cold_tip {
        return Err("ORDINARY_COLD_RECOVERY_SELECTION".into());
    }
    let mut retained = Vec::new();
    for (id, expected, bytes, relative) in &winners {
        within(deadline)?;
        let (checked, timing) = measured(|| -> Result<()> {
            let raw = cold.packet(*id)?.encode()?;
            if raw.len() != *bytes
                || sha(&raw) != *expected
                || std::fs::read(packet_root.join(relative))? != raw
            {
                return Err("COLD_PACKET_BYTES_CHANGED".into());
            }
            Ok(())
        });
        checked?;
        readback.add(timing)?;
        retained
            .push(json!({"id":hex::encode(id),"sha256":expected,"bytes":bytes,"file":relative}));
    }
    let (_, cold_close) = measured(|| drop(cold));
    within(deadline)?;
    let digest = hex::encode(stream.finalize());
    let phases = [
        directory,
        open,
        bootstrap_material,
        template,
        matrices,
        setup,
        generation,
        encode,
        archive_cost,
        admit,
        close,
        reopen,
        readback,
        cold_close,
    ];
    let mut exclusive = Timing::zero();
    for phase in phases {
        exclusive.add(phase)?;
    }
    let mut recurring = Timing::zero();
    for phase in [setup, generation, encode, admit] {
        recurring.add(phase)?;
    }
    let observed_outer = Timing {
        wall_ns: cohort_started.elapsed().as_nanos(),
        process_cpu_ns: cohort_cpu.zip(cpu()).and_then(|(a, b)| b.checked_sub(a)),
    };
    let value = json!({"kind":"cohort","status":"complete","round":round,"reuse":true,"order":order,"batch_workers":workers,
        "strategy":if limb {"maintenance-split-limb"} else {"prepared-general"},
        "parent":hex::encode(seed.header.parent),"target":hex::encode(seed.header.target),"task":hex::encode(task),
        "native_template_header":hex::encode(seed.header.encode()),"template_seed_admitted":false,
        "fresh_store":true,"search_horizon":SEARCHES,"attempt_budget":ATTEMPTS,"attempts":attempts,
        "winners":winners.len(),"exhausted":SEARCHES-winners.len() as u64,"producer_setup_calls":1,"batch_process_clock_intervals":1,"worker_observations":worker_observations,
        "overlapping_trial_times_added_to_batch":false,"batch_includes_spawn_join_and_trial_records":true,
        "first_native_admissions":ids.len(),"cold_packet_readbacks":retained.len(),"explicit_activation_calls":0,
        "hot_active_before_close":{"id":hex::encode(hot_active.0),"generation":hot_active.1},
        "cold_recovery_active":{"id":hex::encode(cold_active.0),"generation":cold_active.1},
        "cold_recovery_selected_height":u64::from(!ids.is_empty()),
        "standalone_verifier_added_to_native_admission":false,
        "phases":{"directory":directory,"node_open":open,"bootstrap_material":bootstrap_material,
            "template_acquisition":template,"matrix_material":matrices,"producer_setup":setup,
            "all_attempt_generation":generation,"packet_encoding":encode,"packet_archival":archive_cost,"first_native_admission":admit,
            "node_close":close,"cold_node_open":reopen,"cold_packet_readback":readback,"cold_node_close":cold_close},
        "recurring_producer_encode_admission":recurring,"all_exclusive_phases":exclusive,"observed_outer":observed_outer,
        "stream_sha256":digest,"searches":searches,"retained_packets":retained,
        "scope":"real 1/2/4-thread CPU batch, one shared preparation; winning packet payload retained in independent cohort directory; fresh-store distinct fixed-parent tickets; complete native validation and SQLite admission; ordinary cold recovery and byte readback; no physical power loss, live-chain rewards, global optimum or throughput qualification"});
    // Tempdir cleanup and serialization are outside per-cohort phases and still
    // present in the full-process accounting captured by the independent runner.
    drop(dir);
    Ok((digest, value))
}
fn run() -> Result<()> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 2 {
        return Err("EXACT_NEW_PACKET_ARCHIVE_DIRECTORY_REQUIRED".into());
    }
    let packet_root = PathBuf::from(&arguments[1]);
    if !packet_root.is_absolute() {
        return Err("ABSOLUTE_PACKET_ARCHIVE_REQUIRED".into());
    }
    let started = Instant::now();
    let deadline = started + std::time::Duration::from_secs(SECONDS);
    let (created, packet_archive_setup) = measured(|| std::fs::create_dir(&packet_root));
    created?;
    let (settings, setup) = measured(|| {
        Settings::development_with_profiles(
            Some(1_800_010_000),
            "native-public-evaluation-dev-v1",
            trnm_mvcc_fee::continuity_v1::PROFILE,
        )
    });
    let settings = settings?;
    emit(
        json!({"kind":"begin","searches":SEARCHES,"attempts":ATTEMPTS,"rounds":ROUNDS,
        "seed":SEED,"budget_seconds":SECONDS,"native_workers":1,"settings_setup":setup,"packet_archive_setup":packet_archive_setup,
        "cpu_batch_workers":[1,2,4],"cpu_batching_measured":true,"winning_packet_payloads_retained":true,
        "compiled_driver_sha256":sha(include_bytes!("pon_legal_ticket_batch_v4.rs")),
        "compiled_cargo_lock_sha256":sha(include_bytes!("../../../Cargo.lock")),
        "positive_legal_tickets_only":true,"standalone_verifier_added_to_native_admission":false,
        "gpu_measured":false,"energy_measured":false,"hardware_batching_measured":false,
        "hardware_authenticated":false,"exclusive_host":false,"global_minimum_proved":false,
        "source_scope":"same current source, paired complete header/proof streams; each cohort uses a fresh store"}),
    )?;
    let mut streams = BTreeMap::new();
    let mut total = 0;
    for round in 0..ROUNDS {
        for workers in if round.is_multiple_of(2) {
            [1, 2, 4]
        } else {
            [4, 2, 1]
        } {
            let arms = if round.is_multiple_of(2) {
                [false, true]
            } else {
                [true, false]
            };
            for (order, limb) in arms.into_iter().enumerate() {
                let (stream, row) = cohort(
                    &settings,
                    round,
                    limb,
                    order,
                    workers,
                    &packet_root,
                    deadline,
                )?;
                emit(row)?;
                if streams
                    .insert(round, stream.clone())
                    .is_some_and(|previous| previous != stream)
                {
                    return Err("PAIRED_FULL_PROOF_STREAM_CHANGED".into());
                }
                total += 1;
            }
        }
    }
    within(deadline)?;
    emit(
        json!({"kind":"terminal","status":"complete","cohorts":total,"wall_ns":started.elapsed().as_nanos(),
        "production_qualified":false,"global_minimum_proved":false,"active_chain_rewards_measured":false}),
    )
}
fn main() {
    if let Err(error) = run() {
        let _ = emit(
            json!({"kind":"terminal","status":"failed","error":error.to_string(),"production_qualified":false}),
        );
        eprintln!("{error}");
        std::process::exit(1);
    }
}
