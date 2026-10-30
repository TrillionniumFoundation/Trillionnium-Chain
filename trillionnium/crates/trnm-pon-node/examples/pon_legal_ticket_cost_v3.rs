//! First admission and retained-byte cost of distinct legal maintenance tickets.
//! This finite paired experiment changes no producer, work predicate or Node.
//! Each cohort owns a fresh store. Sibling tickets are not active-chain rewards.
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, collections::BTreeSet, error::Error, io::Write, time::Instant};
use trnm_crypto_primitives::pon_work::{
    self, maintenance_limb::MaintenanceLimbPreparedTask, PreparedTask,
};
use trnm_pon_node::{development_public, Node, Packet, Settings};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SCHEMA: &str = "pon-legal-ticket-first-admission-cost-v3";
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
    reuse: bool,
    limb: bool,
    order: usize,
    deadline: Instant,
) -> Result<(String, Value)> {
    let cohort_started = Instant::now();
    let cohort_cpu = cpu();
    within(deadline)?;
    let (dir, directory) = measured(tempfile::tempdir);
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
    let mut setup = Timing::zero();
    let mut generation = Timing::zero();
    let mut encode = Timing::zero();
    let mut admit = Timing::zero();
    let mut readback = Timing::zero();
    let mut producer = None;
    let mut setups = 0;
    let mut attempts = 0;
    let mut winners = Vec::new();
    let mut ids = BTreeSet::new();
    let mut searches = Vec::new();
    let mut stream = Sha256::new();
    stream.update(b"TRNM-LEGAL-TICKET-FIRST-ADMISSION-STREAM-V3\0");
    for search in 0..SEARCHES {
        within(deadline)?;
        if !reuse || producer.is_none() {
            let (value, timing) = measured(|| Producer::new(limb, &a, &b));
            setup.add(timing)?;
            producer = Some(value?);
            setups += 1;
        }
        let mut trials = Vec::new();
        let mut won = false;
        for trial in 0..ATTEMPTS {
            within(deadline)?;
            let mut header = seed.header.clone();
            header.nonce = (SEED << 32) + round * (1_u64 << 24) + search * ATTEMPTS + trial;
            let (result, timing) = measured(|| -> Result<_> {
                let challenge = header.challenge();
                let proof = producer
                    .as_ref()
                    .ok_or("PRODUCER_ABSENT")?
                    .prove(challenge)?;
                if proof.len() != pon_work::PROOF_BYTES {
                    return Err("PROOF_LENGTH".into());
                }
                let ticket = pon_work::hash(
                    b"ticket",
                    &[&challenge, &proof[pon_work::PROOF_BYTES - 32..]],
                );
                Ok((challenge, proof, ticket))
            });
            generation.add(timing)?;
            let (challenge, proof, ticket) = result?;
            attempts += 1;
            stream.update(header.encode());
            stream.update(&proof);
            stream.update(ticket);
            let hit = ticket <= header.target;
            trials.push(json!({"trial":trial,"nonce":header.nonce,"challenge":hex::encode(challenge),
                "proof_sha256":sha(&proof),"ticket":hex::encode(ticket),"target_hit":hit,"generation":timing}));
            if hit {
                let packet = Packet {
                    header,
                    transactions: vec![],
                    proof,
                };
                let id = packet.id()?;
                // No seed was admitted, and no winner is submitted twice in
                // this fresh store. Cross-cohort repeats stay explicitly paired.
                if !ids.insert(id) {
                    return Err("DUPLICATE_NATIVE_TICKET".into());
                }
                let (bytes, encoded) = measured(|| packet.encode());
                let bytes = bytes?;
                encode.add(encoded)?;
                let (accepted, timing) =
                    measured(|| node.admit(&packet, packet.header.timestamp + 1));
                admit.add(timing)?;
                if accepted? != id {
                    return Err("NATIVE_ADMISSION_ID".into());
                }
                within(deadline)?;
                winners.push((id, sha(&bytes), bytes.len()));
                trials.last_mut().ok_or("TRIAL_ABSENT")?["native_admission"] = json!(timing);
                trials.last_mut().ok_or("TRIAL_ABSENT")?["packet_id"] = json!(hex::encode(id));
                trials.last_mut().ok_or("TRIAL_ABSENT")?["packet_bytes"] = json!(bytes.len());
                won = true;
                break;
            }
        }
        searches.push(json!({"search":search,"won":won,"trials":trials}));
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
    for (id, expected, bytes) in &winners {
        within(deadline)?;
        let (raw, timing) = measured(|| -> trnm_pon_node::Result<_> { cold.packet(*id)?.encode() });
        readback.add(timing)?;
        let raw = raw?;
        if raw.len() != *bytes || sha(&raw) != *expected {
            return Err("COLD_PACKET_BYTES_CHANGED".into());
        }
        retained.push(json!({"id":hex::encode(id),"sha256":expected,"bytes":bytes}));
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
    let value = json!({"kind":"cohort","status":"complete","round":round,"reuse":reuse,"order":order,
        "strategy":if limb {"maintenance-split-limb"} else {"prepared-general"},
        "parent":hex::encode(seed.header.parent),"target":hex::encode(seed.header.target),"task":hex::encode(task),
        "native_template_header":hex::encode(seed.header.encode()),"template_seed_admitted":false,
        "fresh_store":true,"search_horizon":SEARCHES,"attempt_budget":ATTEMPTS,"attempts":attempts,
        "winners":winners.len(),"exhausted":SEARCHES-winners.len() as u64,"producer_setup_calls":setups,
        "first_native_admissions":ids.len(),"cold_packet_readbacks":retained.len(),"explicit_activation_calls":0,
        "hot_active_before_close":{"id":hex::encode(hot_active.0),"generation":hot_active.1},
        "cold_recovery_active":{"id":hex::encode(cold_active.0),"generation":cold_active.1},
        "cold_recovery_selected_height":u64::from(!ids.is_empty()),
        "standalone_verifier_added_to_native_admission":false,
        "phases":{"directory":directory,"node_open":open,"bootstrap_material":bootstrap_material,
            "template_acquisition":template,"matrix_material":matrices,"producer_setup":setup,
            "all_attempt_generation":generation,"packet_encoding":encode,"first_native_admission":admit,
            "node_close":close,"cold_node_open":reopen,"cold_packet_readback":readback,"cold_node_close":cold_close},
        "recurring_producer_encode_admission":recurring,"all_exclusive_phases":exclusive,"observed_outer":observed_outer,
        "stream_sha256":digest,"searches":searches,"retained_packets":retained,
        "scope":"fresh-store distinct fixed-parent tickets; complete native validation and SQLite admission; ordinary cold recovery and byte readback; no physical power loss, live-chain rewards, global optimum or throughput qualification"});
    // Tempdir cleanup and serialization are outside per-cohort phases and still
    // present in the full-process accounting captured by the independent runner.
    drop(dir);
    Ok((digest, value))
}
fn run() -> Result<()> {
    if std::env::args().len() != 1 {
        return Err("NO_RUNTIME_PROFILE_OVERRIDES".into());
    }
    let started = Instant::now();
    let deadline = started + std::time::Duration::from_secs(SECONDS);
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
        "seed":SEED,"budget_seconds":SECONDS,"native_workers":1,"settings_setup":setup,
        "compiled_driver_sha256":sha(include_bytes!("pon_legal_ticket_cost_v3.rs")),
        "compiled_cargo_lock_sha256":sha(include_bytes!("../../../Cargo.lock")),
        "positive_legal_tickets_only":true,"standalone_verifier_added_to_native_admission":false,
        "gpu_measured":false,"energy_measured":false,"hardware_batching_measured":false,
        "hardware_authenticated":false,"exclusive_host":false,"global_minimum_proved":false,
        "source_scope":"same current source, paired complete header/proof streams; each cohort uses a fresh store"}),
    )?;
    let mut streams = BTreeMap::new();
    let mut total = 0;
    for round in 0..ROUNDS {
        for reuse in [false, true] {
            let arms = if round.is_multiple_of(2) {
                [false, true]
            } else {
                [true, false]
            };
            for (order, limb) in arms.into_iter().enumerate() {
                let (stream, row) = cohort(&settings, round, reuse, limb, order, deadline)?;
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
