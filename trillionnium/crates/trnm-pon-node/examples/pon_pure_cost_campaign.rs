//! Reproducible finite W1 amortization experiment, not a hardness proof.
//! Real PNH1 header encoding and the unchanged production verifier are used.
//! Only the genesis maintenance cohort is native-admitted; other task classes
//! deliberately measure the primitive and do not claim registered useful demand.
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod material;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    error::Error,
    io::Write,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};
use trnm_crypto_primitives::pon_work::{self, Hash, WorkError};
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::pon_wire::Header;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SCHEMA: &str = "pon-pure-w1-amortization-campaign-v1";

#[derive(Clone, Copy)]
enum Strategy {
    General,
    Structured,
    Tiled,
    Strassen,
    Paired,
    Zero,
    ZeroPaired,
    OneZeroRankOne,
    MaintenanceLimb,
    MaintenancePeriodic,
    MaintenancePrefix,
    MaintenanceIntegerPaired,
}
impl Strategy {
    const ALL: [Self; 12] = [
        Self::General,
        Self::Structured,
        Self::Tiled,
        Self::Strassen,
        Self::Paired,
        Self::Zero,
        Self::ZeroPaired,
        Self::OneZeroRankOne,
        Self::MaintenanceLimb,
        Self::MaintenancePeriodic,
        Self::MaintenancePrefix,
        Self::MaintenanceIntegerPaired,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::General => "prepared-general",
            Self::Structured => "structured",
            Self::Tiled => "tiled-classical",
            Self::Strassen => "tiled-strassen-one-level",
            Self::Paired => "paired-field-products",
            Self::Zero => "blocked-zero",
            Self::ZeroPaired => "blocked-zero-integer-paired",
            Self::OneZeroRankOne => "blocked-one-zero-rank-one",
            Self::MaintenanceLimb => "maintenance-split-limb",
            Self::MaintenancePeriodic => "maintenance-periodic",
            Self::MaintenancePrefix => "maintenance-prefix",
            Self::MaintenanceIntegerPaired => "maintenance-integer-paired",
        }
    }
}
enum Producer {
    General(pon_work::PreparedTask),
    Structured(pon_work::structured::StructuredPreparedTask),
    Tiled(pon_work::structured::TiledPreparedTask),
    Paired(pon_work::paired_product::PairedPreparedTask),
    Zero(pon_work::blocked_zero::BlockedZeroPreparedTask),
    ZeroPaired(pon_work::blocked_zero_paired::BlockedZeroPairedPreparedTask),
    OneZeroRankOne(pon_work::blocked_one_zero::BlockedOneZeroRankOnePreparedTask),
    MaintenanceLimb(pon_work::maintenance_limb::MaintenanceLimbPreparedTask),
    MaintenancePeriodic(pon_work::maintenance_periodic::MaintenancePeriodicPreparedTask),
    MaintenancePrefix(Box<pon_work::maintenance_prefix::MaintenancePrefixPreparedTask>),
    MaintenanceIntegerPaired(pon_work::maintenance_prefix::MaintenanceIntegerPairedPreparedTask),
}
impl Producer {
    fn new(kind: Strategy, a: &[u32], b: &[u32]) -> std::result::Result<Option<Self>, WorkError> {
        Ok(match kind {
            Strategy::General => Some(Self::General(pon_work::PreparedTask::new(a, b)?)),
            Strategy::Structured => {
                pon_work::structured::StructuredPreparedTask::new(a, b)?.map(Self::Structured)
            }
            Strategy::Tiled => Some(Self::Tiled(pon_work::structured::TiledPreparedTask::new(
                a,
                b,
                pon_work::structured::TileKernel::Classical,
            )?)),
            Strategy::Strassen => Some(Self::Tiled(pon_work::structured::TiledPreparedTask::new(
                a,
                b,
                pon_work::structured::TileKernel::StrassenOneLevel,
            )?)),
            Strategy::Paired => Some(Self::Paired(
                pon_work::paired_product::PairedPreparedTask::new(a, b)?,
            )),
            Strategy::Zero => {
                pon_work::blocked_zero::BlockedZeroPreparedTask::new(a, b)?.map(Self::Zero)
            }
            Strategy::ZeroPaired => {
                pon_work::blocked_zero_paired::BlockedZeroPairedPreparedTask::new(a, b)?
                    .map(Self::ZeroPaired)
            }
            Strategy::OneZeroRankOne => {
                pon_work::blocked_one_zero::BlockedOneZeroRankOnePreparedTask::new(a, b)?
                    .map(Self::OneZeroRankOne)
            }
            Strategy::MaintenanceLimb => {
                pon_work::maintenance_limb::MaintenanceLimbPreparedTask::new(a, b)?
                    .map(Self::MaintenanceLimb)
            }
            Strategy::MaintenancePeriodic => {
                pon_work::maintenance_periodic::MaintenancePeriodicPreparedTask::new(a, b)?
                    .map(Self::MaintenancePeriodic)
            }
            Strategy::MaintenancePrefix => {
                pon_work::maintenance_prefix::MaintenancePrefixPreparedTask::new(a, b)?
                    .map(|p| Self::MaintenancePrefix(Box::new(p)))
            }
            Strategy::MaintenanceIntegerPaired => {
                pon_work::maintenance_prefix::MaintenanceIntegerPairedPreparedTask::new(a, b)?
                    .map(Self::MaintenanceIntegerPaired)
            }
        })
    }
    fn prove(&self, challenge: Hash) -> std::result::Result<Vec<u8>, WorkError> {
        match self {
            Self::General(p) => p.prove(challenge),
            Self::Structured(p) => p.prove(challenge),
            Self::Tiled(p) => p.prove(challenge),
            Self::Paired(p) => p.prove(challenge),
            Self::Zero(p) => p.prove(challenge),
            Self::ZeroPaired(p) => p.prove(challenge),
            Self::OneZeroRankOne(p) => p.prove(challenge),
            Self::MaintenanceLimb(p) => p.prove(challenge),
            Self::MaintenancePeriodic(p) => p.prove(challenge),
            Self::MaintenancePrefix(p) => p.prove(challenge),
            Self::MaintenanceIntegerPaired(p) => p.prove(challenge),
        }
    }
}
fn cpu() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ProcessCPUTime)).ok()?;
    u64::try_from(t.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(t.tv_nsec).ok()?)
}
fn measured<T>(f: impl FnOnce() -> T) -> (T, u128, Option<u64>) {
    let before = cpu();
    let start = Instant::now();
    let result = f();
    let wall = start.elapsed().as_nanos();
    (
        result,
        wall,
        before.zip(cpu()).and_then(|(a, b)| b.checked_sub(a)),
    )
}
fn add_cpu(total: &mut Option<u64>, delta: Option<u64>) {
    *total = total.zip(delta).and_then(|(a, b)| a.checked_add(b));
}
fn emit(mut value: Value) -> Result<()> {
    static WRITTEN: AtomicUsize = AtomicUsize::new(0);
    value["schema"] = json!(SCHEMA);
    let terminal = value["kind"] == "terminal";
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    if bytes.len() > 1024 * 1024 {
        return Err("REPORT_ROW_BOUND".into());
    }
    let cap = 32 * 1024 * 1024 - if terminal { 0 } else { 4096 };
    WRITTEN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            n.checked_add(bytes.len()).filter(|n| *n <= cap)
        })
        .map_err(|_| "REPORT_TOTAL_BOUND")?;
    let mut out = std::io::stdout().lock();
    out.write_all(&bytes)?;
    out.flush()?;
    Ok(())
}
fn work<T>(result: std::result::Result<T, WorkError>) -> Result<T> {
    result.map_err(|e| format!("W1:{e:?}").into())
}
#[derive(Clone, Copy)]
struct Plan {
    searches: u64,
    attempts: u64,
    rounds: u64,
    seed: u64,
    seconds: u64,
}
fn options() -> Result<Plan> {
    let mut p = Plan {
        searches: 256,
        attempts: 64,
        rounds: 2,
        seed: 1,
        seconds: 600,
    };
    let mut args = std::env::args().skip(1);
    let mut seen = std::collections::BTreeSet::new();
    while let Some(flag) = args.next() {
        if !seen.insert(flag.clone()) {
            return Err("duplicate option".into());
        }
        let value: u64 = args.next().ok_or("missing option value")?.parse()?;
        match flag.as_str() {
            "--searches" => p.searches = value,
            "--attempts" => p.attempts = value,
            "--rounds" => p.rounds = value,
            "--seed" => p.seed = value,
            "--seconds" => p.seconds = value,
            _ => return Err("unknown option".into()),
        }
    }
    if !(1..=1024).contains(&p.searches)
        || !(1..=4096).contains(&p.attempts)
        || !(1..=64).contains(&p.rounds)
        || p.seed >= u64::from(u32::MAX)
        || !(1..=3600).contains(&p.seconds)
    {
        return Err("campaign limits".into());
    }
    Ok(p)
}

#[allow(clippy::too_many_arguments)]
fn cohort(
    p: Plan,
    base: &Header,
    m: &material::Material,
    strategy: Strategy,
    reuse: bool,
    horizon: u64,
    round: u64,
    deadline: Instant,
    native: &mut Node,
) -> Result<(String, Value)> {
    let task = work(pon_work::task_id(&m.a, &m.b))?;
    let mut header = base.clone();
    header.work_task = task;
    let mut preparation = 0u128;
    let mut generation = 0u128;
    let mut verification = 0u128;
    let mut generation_cpu = Some(0u64);
    let mut preparation_cpu = Some(0u64);
    let mut stream = Sha256::new();
    stream.update(b"TRNM-PURE-W1-COST-STREAM-V1\0");
    let mut kept: Option<Producer> = None;
    let mut rows = Vec::new();
    let mut total_attempts = 0u64;
    let mut winners = 0u64;
    let mut native_verified = 0u64;
    let mut setup_count = 0u64;
    for search in 0..horizon {
        if Instant::now() >= deadline {
            return Err("CAMPAIGN_DEADLINE".into());
        }
        if !reuse || kept.is_none() {
            let (prepared, wall, used) = measured(|| Producer::new(strategy, &m.a, &m.b));
            preparation += wall;
            add_cpu(&mut preparation_cpu, used);
            setup_count += 1;
            kept = work(prepared)?;
            if kept.is_none() {
                return Ok((
                    String::new(),
                    json!({"kind":"cohort", "status":"unsupported",
                    "material":m.name,"strategy":strategy.name(),"reuse":reuse,"horizon":horizon,
                    "round":round,"target":hex::encode(header.target),"setup_count":setup_count,
                    "setup_wall_ns":preparation,"setup_cpu_ns":preparation_cpu,"attempts":0,"winners":0}),
                ));
            }
        }
        let producer = kept.as_ref().ok_or("producer absent")?;
        let mut tried = 0u64;
        let mut won = false;
        let mut search_ns = 0u128;
        let mut search_cpu = Some(0u64);
        let mut final_ticket = [0; 32];
        for attempt in 0..p.attempts {
            if Instant::now() >= deadline {
                return Err("CAMPAIGN_DEADLINE".into());
            }
            header.nonce =
                p.seed * (1u64 << 32) + round * (1u64 << 24) + search * p.attempts + attempt;
            let ((proof, ticket), wall, used) = measured(|| {
                let challenge = header.challenge();
                let proof = producer.prove(challenge);
                let ticket = proof.as_ref().ok().map(|proof| {
                    pon_work::hash(
                        b"ticket",
                        &[&challenge, &proof[pon_work::PROOF_BYTES - 32..]],
                    )
                });
                (proof, ticket)
            });
            let proof = work(proof)?;
            let ticket = ticket.ok_or("no ticket")?;
            search_ns += wall;
            add_cpu(&mut search_cpu, used);
            tried += 1;
            total_attempts += 1;
            final_ticket = ticket;
            // Harness stream hashing is outside producer timings and identified
            // separately by complete campaign wall time. Every miss is included.
            stream.update(header.encode());
            stream.update(&proof);
            stream.update(ticket);
            if ticket <= header.target {
                let (valid, wall, _) =
                    measured(|| pon_work::verify(header.challenge(), task, header.target, &proof));
                work(valid)?;
                verification += wall;
                if m.name == "genesis-maintenance"
                    && header.target == native.expected_target(header.parent)?
                {
                    let packet = Packet {
                        header: header.clone(),
                        transactions: vec![],
                        proof,
                    };
                    native.admit(&packet, header.timestamp + 1)?;
                    native_verified += 1;
                }
                winners += 1;
                won = true;
                break;
            }
        }
        generation += search_ns;
        add_cpu(&mut generation_cpu, search_cpu);
        rows.push(json!({"search":search,"attempts":tried,"winner":won,
            "search_wall_ns":search_ns,"search_cpu_ns":search_cpu,"last_ticket":hex::encode(final_ticket)}));
    }
    let digest = hex::encode(stream.finalize());
    Ok((
        digest.clone(),
        json!({"kind":"cohort","status":"complete","material":m.name,
        "strategy":strategy.name(),"reuse":reuse,"horizon":horizon,"round":round,
        "target":hex::encode(header.target),"setup_count":setup_count,
        "setup_wall_ns":preparation,"search_wall_ns":generation,
        "total_producer_wall_ns":preparation+generation,
        "setup_cpu_ns":preparation_cpu,"search_cpu_ns":generation_cpu,
        "total_producer_cpu_ns":preparation_cpu.zip(generation_cpu).and_then(|(a,b)|a.checked_add(b)),
        "attempts":total_attempts,"winners":winners,"exhausted":horizon-winners,
        "production_verifier_wall_ns":verification,"native_accepted_calls":native_verified,
        "stream_sha256":digest,"searches":rows,
        "cost_scope":"setup plus all actual attempts; excludes verification, native admission, report IO and stream hashing"}),
    ))
}

fn rejection_cost(packet: &Packet, a: &[u32], b: &[u32]) -> Result<()> {
    let (fact, setup, _) = measured(|| pon_work::public_product::PublicProduct::new(a, b));
    let fact = work(fact)?;
    let mut raw = 0u128;
    let mut filtered = 0u128;
    for index in 0..64usize {
        let mut false_proof = packet.proof.clone();
        let at = 4 + pon_work::CELLS * 8 + index * 4;
        let old = u32::from_le_bytes(false_proof[at..at + 4].try_into()?);
        false_proof[at..at + 4]
            .copy_from_slice(&(((u128::from(old) + 1) % pon_work::Q) as u32).to_le_bytes());
        // Alternate order; compare exactly the same false bytes and target.
        for fast in if index % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            if fast {
                let (result, wall, _) = measured(|| {
                    fact.precheck(
                        packet.header.challenge(),
                        packet.header.work_task,
                        packet.header.target,
                        &false_proof,
                    )
                });
                if result != Err(WorkError::Product) {
                    return Err("wrong precheck rejection".into());
                }
                filtered += wall;
            } else {
                let (result, wall, _) = measured(|| {
                    pon_work::verify(
                        packet.header.challenge(),
                        packet.header.work_task,
                        packet.header.target,
                        &false_proof,
                    )
                });
                if !matches!(result, Err(WorkError::Product)) {
                    return Err("wrong baseline rejection".into());
                }
                raw += wall;
            }
        }
    }
    emit(
        json!({"kind":"late_product_rejection","cases":64,"fact_setup_wall_ns":setup,
        "raw_rejection_wall_ns":raw,"filtered_rejection_wall_ns":filtered,
        "fixed_fact_software_bytes":fact.software_bytes(),
        "scope":"same actual native maintenance proof; acquisition is separate; wrong-transcript and unknown-task attacks still need full verification"}),
    )
}
fn run() -> Result<()> {
    let plan = options()?;
    let started = Instant::now();
    let deadline = started + std::time::Duration::from_secs(plan.seconds);
    let dir = tempfile::tempdir()?;
    let settings = Settings::development_with_profiles(
        Some(1_800_010_000),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )?;
    let mut native = Node::open(dir.path(), settings.clone(), 1)?;
    let bundle = settings.public_task_bootstrap()?;
    let (seed, acquire_wall, acquire_cpu) = measured(|| {
        native.make_public_bootstrap(
            &bundle,
            settings.genesis(),
            vec![],
            development_public(3).expect("fixed development identity"),
            settings.genesis_time() + 11,
            4096,
        )
    });
    let seed = seed?;
    native.admit(&seed, seed.header.timestamp + 1)?;
    emit(
        json!({"kind":"begin","seed":plan.seed,"rounds":plan.rounds,"max_horizon":plan.searches,
        "attempt_budget":plan.attempts,"absolute_budget_seconds":plan.seconds,
        "native_seed_header":hex::encode(seed.header.encode()),
        "native_target":hex::encode(seed.header.target),
        "native_seed_packet_sha256":hex::encode(Sha256::digest(seed.encode()?)),
        "native_seed_acquisition_wall_ns":acquire_wall,"native_seed_acquisition_cpu_ns":acquire_cpu,
        "same_host":true,"energy_measured":false,"hardness_proved":false,
        "warmup":"none; first samples retained; all fixed strategies offered, order rotated by round",
        "batch_schedule":"material/round/horizon/reuse/target/rotated-fixed-strategy",
        "scope":"finite paired algorithm observation; shared nested challenge streams; structural nonmaintenance tasks are primitive-only, not native-registered useful work"}),
    )?;
    let (materials, material_wall, material_cpu) = measured(|| material::materials(None, None));
    let mut materials = materials?;
    let (a, b) = trnm_mvcc_fee::continuity_v1::maintenance_matrices();
    rejection_cost(&seed, &a, &b)?;
    materials.retain(|m| m.name != "continuity-maintenance-v1");
    let rank_one = materials
        .iter()
        .find(|m| m.name == "rank-one")
        .ok_or("RANK_ONE_MATERIAL")?;
    let rank_a = rank_one.a.clone();
    let rank_b = rank_one.b.clone();
    materials.push(material::Material {
        name: "zero-left-rank-one-right",
        source: "synthetic-fixture",
        a: vec![0; pon_work::CELLS],
        b: rank_b,
    });
    materials.push(material::Material {
        name: "rank-one-left-zero-right",
        source: "synthetic-fixture",
        a: rank_a,
        b: vec![0; pon_work::CELLS],
    });
    materials.push(material::Material {
        name: "genesis-maintenance",
        source: "installed-public-genesis",
        a,
        b,
    });
    emit(json!({"kind":"material_setup","wall_ns":material_wall,"cpu_ns":material_cpu}))?;
    let mut horizons = vec![1, 8, 64, plan.searches];
    horizons.retain(|n| *n <= plan.searches);
    horizons.sort_unstable();
    horizons.dedup();
    let mut matched = BTreeMap::new();
    let mut count = 0u64;
    for m in &materials {
        emit(json!({"kind":"material","name":m.name,"source":m.source,
            "rank_a":material::rank(&m.a),"rank_b":material::rank(&m.b),
            "task":hex::encode(work(pon_work::task_id(&m.a,&m.b))?)}))?;
        for round in 0..plan.rounds {
            let mut arms = Strategy::ALL;
            arms.rotate_left(round as usize % Strategy::ALL.len());
            for horizon in &horizons {
                for reuse in [false, true] {
                    for harder in [false, true] {
                        let mut header = seed.header.clone();
                        if harder {
                            header.target = [255; 32];
                            header.target[0] = 7;
                        }
                        for strategy in arms {
                            let (stream, row) = cohort(
                                plan,
                                &header,
                                m,
                                strategy,
                                reuse,
                                *horizon,
                                round,
                                deadline,
                                &mut native,
                            )?;
                            if !stream.is_empty() {
                                let key = (m.name, round, *horizon, hex::encode(header.target));
                                if let Some(previous) = matched.insert(key, stream.clone()) {
                                    if previous != stream {
                                        return Err("paired complete proof streams diverged".into());
                                    }
                                }
                            }
                            emit(row)?;
                            count += 1;
                        }
                    }
                }
            }
        }
    }
    emit(
        json!({"kind":"terminal","status":"complete","cohorts":count,
        "campaign_wall_ns":started.elapsed().as_nanos(),"hardness_proved":false,
        "production_qualified":false,"useful_model_work_qualified":false}),
    )
}
fn main() {
    if let Err(error) = run() {
        let _ = emit(
            json!({"kind":"terminal","status":"failed","error":error.to_string(),
            "hardness_proved":false,"production_qualified":false}),
        );
        eprintln!("{error}");
        std::process::exit(1);
    }
}
