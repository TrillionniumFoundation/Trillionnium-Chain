//! Paired native costs of legacy, candidate-all and winning-only proof assembly.
//! Uses the existing W1 relation, native admission and ordinary cold recovery.
//! All failed trials remain observed; this is not a minimum-cost or TPS claim.
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, collections::BTreeSet, error::Error, io::Write, time::Instant};
use trnm_crypto_primitives::pon_work::{
    self, maintenance_limb::MaintenanceLimbPreparedTask, Hash, PreparedTask, ProducerCandidate,
};
use trnm_pon_node::{development_public, Node, Packet, Settings};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SCHEMA: &str = "pon-ticket-first-native-cost-v1";
const HORIZONS: [u64; 4] = [1, 8, 64, 256];
const ATTEMPTS: u64 = 8;
const ROUNDS: u64 = 2;
const SEED: u64 = 2;
const SECONDS: u64 = 600;
const ARMS: [&str; 6] = [
    "generic-legacy",
    "generic-candidate-all",
    "generic-ticket-first",
    "limb-legacy",
    "limb-candidate-all",
    "limb-ticket-first",
];

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
    let value = f();
    (
        value,
        Timing {
            wall_ns: start.elapsed().as_nanos(),
            process_cpu_ns: before.zip(cpu()).and_then(|(a, b)| b.checked_sub(a)),
        },
    )
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn proof_digest(prefix: &[u8], trace: Hash) -> String {
    let mut h = Sha256::new();
    h.update(prefix);
    h.update(trace);
    hex::encode(h.finalize())
}
fn emit(mut value: Value) -> Result<()> {
    value["schema"] = json!(SCHEMA);
    let raw = serde_json::to_vec(&value)?;
    if raw.len() > 2 * 1024 * 1024 {
        return Err("ROW_BOUND".into());
    }
    let mut out = std::io::stdout().lock();
    out.write_all(&raw)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
// Separate write-ahead records preserve observations from an incomplete cohort.
// Their bounded fixed shapes cannot contain proof payloads. The original capture
// keeps stderr, including kill/timeout cases; this I/O is in outer cost scopes.
fn journal(mut value: Value) -> Result<()> {
    value["schema"] = json!("pon-ticket-first-progress-v1");
    let raw = serde_json::to_vec(&value)?;
    if raw.len() > 16 * 1024 {
        return Err("PROGRESS_ROW_BOUND".into());
    }
    let mut out = std::io::stderr().lock();
    out.write_all(&raw)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
fn within(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err("CAMPAIGN_DEADLINE".into())
    } else {
        Ok(())
    }
}
enum Producer {
    Generic(PreparedTask),
    Limb(MaintenanceLimbPreparedTask),
}
impl Producer {
    fn new(arm: usize, a: &[u32], b: &[u32]) -> Result<Self> {
        match arm / 3 {
            0 => Ok(Self::Generic(
                PreparedTask::new(a, b).map_err(|e| format!("PREPARE:{e:?}"))?,
            )),
            1 => Ok(Self::Limb(
                MaintenanceLimbPreparedTask::new(a, b)
                    .map_err(|e| format!("PREPARE:{e:?}"))?
                    .ok_or("UNSUPPORTED_MAINTENANCE")?,
            )),
            _ => Err("ARM".into()),
        }
    }
    fn prove(&self, challenge: Hash) -> Result<Vec<u8>> {
        match self {
            Self::Generic(p) => p.prove(challenge),
            Self::Limb(p) => p.prove(challenge),
        }
        .map_err(|e| format!("PROVE:{e:?}").into())
    }
    fn candidate(&self, challenge: Hash) -> Result<ProducerCandidate<'_>> {
        match self {
            Self::Generic(p) => p.candidate(challenge),
            Self::Limb(p) => p.candidate(challenge),
        }
        .map_err(|e| format!("CANDIDATE:{e:?}").into())
    }
    fn attempt(&self, arm: usize, challenge: Hash, target: Hash) -> Result<Attempt> {
        if arm.is_multiple_of(3) {
            let proof = self.prove(challenge)?;
            let trace: Hash = proof[pon_work::PROOF_BYTES - 32..].try_into()?;
            let ticket = pon_work::hash(b"ticket", &[&challenge, &trace]);
            Ok(Attempt {
                trace,
                ticket,
                proof: Some(proof),
            })
        } else {
            let candidate = self.candidate(challenge)?;
            let trace = candidate.trace();
            let ticket = candidate.ticket();
            let proof = if arm % 3 == 1 || ticket <= target {
                Some(candidate.into_proof())
            } else {
                None
            };
            Ok(Attempt {
                trace,
                ticket,
                proof,
            })
        }
    }
}
struct Attempt {
    trace: Hash,
    ticket: Hash,
    proof: Option<Vec<u8>>,
}

fn cohort(
    settings: &Settings,
    round: u64,
    horizon: u64,
    reuse: bool,
    arm: usize,
    order: usize,
    deadline: Instant,
) -> Result<(String, Value)> {
    let outer_start = Instant::now();
    let outer_cpu = cpu();
    within(deadline)?;
    let identity = json!({"round":round,"horizon":horizon,"reuse":reuse,"arm":ARMS[arm]});
    journal(json!({"kind":"cohort-start","cohort":identity}))?;
    let (dir, directory) = measured(tempfile::tempdir);
    let dir = dir?;
    let (node, node_open) = measured(|| Node::open(dir.path(), settings.clone(), 1));
    let mut node = node?;
    let (bundle, bootstrap_material) = measured(|| settings.public_task_bootstrap());
    let bundle = bundle?;
    let (seed, template_acquisition) = measured(|| {
        node.make_public_bootstrap(
            &bundle,
            settings.genesis(),
            vec![],
            development_public(3).expect("fixed fixture"),
            settings.genesis_time() + 11,
            4096,
        )
    });
    let seed = seed?;
    let ((a, b), matrix_material) = measured(trnm_mvcc_fee::continuity_v1::maintenance_matrices);
    let task = pon_work::task_id(&a, &b).map_err(|e| format!("TASK:{e:?}"))?;
    if seed.header.work_task != task
        || seed.header.target != node.expected_target(seed.header.parent)?
        || seed.proof.len() != pon_work::PROOF_BYTES
    {
        return Err("NATIVE_TEMPLATE".into());
    }
    // A/B/C are fixed by the actual native template. Audit hashes stream these
    // bytes plus the real trace without materializing a failed candidate proof.
    let prefix = &seed.proof[..pon_work::PROOF_BYTES - 32];
    let mut producer_setup = Timing::zero();
    let mut all_attempt_generation = Timing::zero();
    let mut packet_encoding = Timing::zero();
    let mut first_native_admission = Timing::zero();
    let mut cold_packet_readback = Timing::zero();
    let mut producer = None;
    let mut setup_calls = 0;
    let mut attempted = 0;
    let mut serialized = 0;
    let mut ids = BTreeSet::new();
    let mut winners = Vec::new();
    let mut searches = Vec::new();
    let mut stream = Sha256::new();
    stream.update(b"TRNM-TICKET-FIRST-NATIVE-STREAM-V1\0");
    for search in 0..horizon {
        within(deadline)?;
        if !reuse || producer.is_none() {
            let (value, t) = measured(|| Producer::new(arm, &a, &b));
            producer_setup.add(t)?;
            producer = Some(value?);
            setup_calls += 1;
        }
        let mut trials = Vec::new();
        let mut won = false;
        for trial in 0..ATTEMPTS {
            within(deadline)?;
            let mut header = seed.header.clone();
            header.nonce =
                (SEED << 32) + round * (1_u64 << 24) + horizon * 4096 + search * ATTEMPTS + trial;
            journal(
                json!({"kind":"trial-start","cohort":identity,"search":search,"trial":trial,"nonce":header.nonce}),
            )?;
            let (result, generation) = measured(|| {
                let challenge = header.challenge();
                producer
                    .as_ref()
                    .ok_or_else(|| Box::<dyn Error>::from("PRODUCER_ABSENT"))?
                    .attempt(arm, challenge, header.target)
                    .map(|value| (challenge, value))
            });
            all_attempt_generation.add(generation)?;
            let (challenge, value) = result?;
            attempted += 1;
            let hit = value.ticket <= header.target;
            let materialized = value.proof.is_some();
            if materialized != (arm % 3 != 2 || hit) {
                return Err("ASSEMBLY_SCOPE".into());
            }
            if let Some(proof) = value.proof.as_ref() {
                if proof.len() != pon_work::PROOF_BYTES
                    || &proof[..pon_work::PROOF_BYTES - 32] != prefix
                    || proof[pon_work::PROOF_BYTES - 32..] != value.trace
                {
                    return Err("COMPLETE_PROOF_CHANGED".into());
                }
                serialized += 1;
            }
            let proof_sha = proof_digest(prefix, value.trace);
            // This deterministic audit work is outside the generation timer,
            // inside the enclosing cohort/process. It is identical across arms.
            stream.update(header.encode());
            stream.update(value.trace);
            stream.update(value.ticket);
            stream.update(hex::decode(&proof_sha)?);
            trials.push(json!({"trial":trial,"nonce":header.nonce,"challenge":hex::encode(challenge),"trace":hex::encode(value.trace),"ticket":hex::encode(value.ticket),"canonical_proof_sha256":proof_sha,"target_hit":hit,"proof_materialized":materialized,"generation":generation}));
            journal(
                json!({"kind":"trial-generated","cohort":identity,"search":search,"observation":trials.last().ok_or("TRIAL_ABSENT")?}),
            )?;
            if hit {
                let packet = Packet {
                    header,
                    transactions: vec![],
                    proof: value.proof.ok_or("WINNER_PROOF_ABSENT")?,
                };
                let id = packet.id()?;
                if !ids.insert(id) {
                    return Err("DUPLICATE_FIRST_ADMISSION".into());
                }
                let (bytes, t) = measured(|| packet.encode());
                let bytes = bytes?;
                packet_encoding.add(t)?;
                journal(
                    json!({"kind":"admission-start","cohort":identity,"search":search,"trial":trial,"packet_id":hex::encode(id),"packet_encoding":t}),
                )?;
                let (accepted, t) = measured(|| node.admit(&packet, packet.header.timestamp + 1));
                first_native_admission.add(t)?;
                journal(
                    json!({"kind":"admission-result","cohort":identity,"search":search,"trial":trial,"packet_id":hex::encode(id),"timing":t,"accepted_id":accepted.as_ref().ok().map(hex::encode),"error":accepted.as_ref().err().map(|e|e.to_string())}),
                )?;
                if accepted? != id {
                    return Err("ADMISSION_ID".into());
                }
                let row = trials.last_mut().ok_or("TRIAL_ABSENT")?;
                row["native_admission"] = json!(t);
                row["packet_id"] = json!(hex::encode(id));
                row["packet_bytes"] = json!(bytes.len());
                winners.push((id, sha(&bytes), bytes.len()));
                won = true;
                within(deadline)?;
                break;
            }
        }
        searches.push(json!({"search":search,"won":won,"trials":trials}));
    }
    let hot = node.active()?;
    if hot.0 != settings.genesis() {
        return Err("ADMISSION_CHANGED_ACTIVE".into());
    }
    let expected = ids.first().copied().unwrap_or(settings.genesis());
    journal(
        json!({"kind":"generation-complete","cohort":identity,"attempts":attempted,"winners":winners.len(),"all_attempt_generation":all_attempt_generation,"first_native_admission":first_native_admission}),
    )?;
    let (_, node_close) = measured(|| drop(node));
    within(deadline)?;
    let (cold, cold_node_open) = measured(|| Node::open(dir.path(), settings.clone(), 1));
    let cold = cold?;
    let active = cold.active()?;
    if active.0 != expected {
        return Err("COLD_SELECTION".into());
    }
    let mut retained = Vec::new();
    for (id, digest, len) in &winners {
        within(deadline)?;
        journal(json!({"kind":"cold-read-start","cohort":identity,"packet_id":hex::encode(id)}))?;
        let (raw, t) = measured(|| -> trnm_pon_node::Result<_> { cold.packet(*id)?.encode() });
        cold_packet_readback.add(t)?;
        let raw = raw?;
        if raw.len() != *len || sha(&raw) != *digest {
            return Err("COLD_BYTES".into());
        }
        retained.push(json!({"id":hex::encode(id),"sha256":digest,"bytes":len}));
        journal(
            json!({"kind":"cold-read-result","cohort":identity,"packet_id":hex::encode(id),"sha256":digest,"bytes":len,"timing":t}),
        )?;
    }
    let (_, cold_node_close) = measured(|| drop(cold));
    within(deadline)?;
    let phases = [
        directory,
        node_open,
        bootstrap_material,
        template_acquisition,
        matrix_material,
        producer_setup,
        all_attempt_generation,
        packet_encoding,
        first_native_admission,
        node_close,
        cold_node_open,
        cold_packet_readback,
        cold_node_close,
    ];
    let mut all_exclusive = Timing::zero();
    for t in phases {
        all_exclusive.add(t)?;
    }
    let mut recurring = Timing::zero();
    for t in [
        producer_setup,
        all_attempt_generation,
        packet_encoding,
        first_native_admission,
    ] {
        recurring.add(t)?;
    }
    let observed_outer = Timing {
        wall_ns: outer_start.elapsed().as_nanos(),
        process_cpu_ns: outer_cpu.zip(cpu()).and_then(|(a, b)| b.checked_sub(a)),
    };
    let digest = hex::encode(stream.finalize());
    let phase_values = json!({"directory":directory,"node_open":node_open,"bootstrap_material":bootstrap_material,"template_acquisition":template_acquisition,"matrix_material":matrix_material,"producer_setup":producer_setup,"all_attempt_generation":all_attempt_generation,"packet_encoding":packet_encoding,"first_native_admission":first_native_admission,"node_close":node_close,"cold_node_open":cold_node_open,"cold_packet_readback":cold_packet_readback,"cold_node_close":cold_node_close});
    let row = json!({"kind":"cohort","status":"complete","round":round,"search_horizon":horizon,"reuse":reuse,"order":order,"arm":ARMS[arm],"arm_index":arm,
        "parent":hex::encode(seed.header.parent),"target":hex::encode(seed.header.target),"task":hex::encode(task),"native_template_header":hex::encode(seed.header.encode()),"proof_prefix_sha256":sha(prefix),
        "fresh_store":true,"template_seed_admitted":false,"attempt_budget":ATTEMPTS,"attempts":attempted,"winners":winners.len(),"exhausted":horizon-winners.len() as u64,
        "producer_setup_calls":setup_calls,"proof_materializations":serialized,"proof_bytes_materialized":serialized*pon_work::PROOF_BYTES,"first_native_admissions":ids.len(),"cold_packet_readbacks":retained.len(),"explicit_activation_calls":0,
        "hot_active_before_close":{"id":hex::encode(hot.0),"generation":hot.1},"cold_recovery_active":{"id":hex::encode(active.0),"generation":active.1},
        "phases":phase_values,
        "all_exclusive_phases":all_exclusive,"recurring_producer_encode_admission":recurring,"observed_outer":observed_outer,"stream_sha256":digest,"searches":searches,"retained_packets":retained});
    // Cleanup and JSON serialization remain in the outer native process capture.
    drop(dir);
    journal(json!({"kind":"cohort-complete","cohort":identity,"stream_sha256":digest}))?;
    Ok((digest, row))
}
fn run() -> Result<()> {
    if cfg!(debug_assertions) {
        return Err("RELEASE_PROFILE_REQUIRED".into());
    }
    if std::env::args().len() != 1 {
        return Err("NO_RUNTIME_OVERRIDES".into());
    }
    let start = Instant::now();
    let deadline = start + std::time::Duration::from_secs(SECONDS);
    let (settings, settings_setup) = measured(|| {
        Settings::development_with_profiles(
            Some(1_800_010_000),
            "native-public-evaluation-dev-v1",
            trnm_mvcc_fee::continuity_v1::PROFILE,
        )
    });
    let settings = settings?;
    emit(
        json!({"kind":"begin","horizons":HORIZONS,"arms":ARMS,"attempts":ATTEMPTS,"rounds":ROUNDS,"seed":SEED,"budget_seconds":SECONDS,"native_workers":1,"settings_setup":settings_setup,
        "compiled_driver_sha256":sha(include_bytes!("pon_ticket_first_cost_v1.rs")),"compiled_cargo_lock_sha256":sha(include_bytes!("../../../Cargo.lock")),
        "old_v3_v4_v5_experiments_unchanged":true,"failed_proof_materialization_is_not_required_work":true,"winning_only_still_computes_all_transcript_tiles":true,"debug_assertions":cfg!(debug_assertions),
        "gpu_measured":false,"energy_measured":false,"hardware_authenticated":false,"exclusive_host":false,"global_minimum_proved":false,"production_qualified":false,
        "scope":"finite paired native maintenance candidates; original W1 and complete native admission; audit and cleanup included by outer process; no active-chain reward, network fairness, model utility, quantum or throughput qualification"}),
    )?;
    let mut streams = BTreeMap::new();
    let mut count = 0;
    for round in 0..ROUNDS {
        for (horizon_index, horizon) in HORIZONS.into_iter().enumerate() {
            for reuse in [false, true] {
                let mut arms = [0, 1, 2, 3, 4, 5];
                if !round.is_multiple_of(2) {
                    arms.reverse();
                }
                arms.rotate_left((horizon_index + usize::from(reuse)) % ARMS.len());
                for (order, arm) in arms.into_iter().enumerate() {
                    let (stream, row) =
                        cohort(&settings, round, horizon, reuse, arm, order, deadline)?;
                    emit(row)?;
                    if streams
                        .insert((round, horizon), stream.clone())
                        .is_some_and(|old| old != stream)
                    {
                        return Err("PAIRED_TRANSCRIPT_STREAM_CHANGED".into());
                    }
                    count += 1;
                }
            }
        }
    }
    within(deadline)?;
    emit(
        json!({"kind":"terminal","status":"complete","cohorts":count,"wall_ns":start.elapsed().as_nanos(),"global_minimum_proved":false,"public_fairness_qualified":false,"active_chain_rewards_measured":false,"production_qualified":false}),
    )
}
fn main() {
    if let Err(e) = run() {
        let _ = emit(
            json!({"kind":"terminal","status":"failed","error":e.to_string(),"production_qualified":false}),
        );
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_six_arms_keep_tickets_and_only_the_declared_paths_assemble_misses() {
        let (a, b) = trnm_mvcc_fee::continuity_v1::maintenance_matrices();
        let generic = Producer::new(0, &a, &b).unwrap();
        let challenge = [41; 32];
        let expected = generic.prove(challenge).unwrap();
        for arm in 0..ARMS.len() {
            let p = Producer::new(arm, &a, &b).unwrap();
            let hit = p.attempt(arm, challenge, [255; 32]).unwrap();
            assert_eq!(hit.proof.unwrap(), expected);
            let miss = p.attempt(arm, challenge, [0; 32]).unwrap();
            assert_ne!(miss.ticket, [0; 32]);
            assert_eq!(miss.ticket, hit.ticket);
            assert_eq!(miss.trace, hit.trace);
            assert_eq!(miss.proof.is_some(), arm % 3 != 2);
            if let Some(proof) = miss.proof {
                assert_eq!(proof, expected);
            }
        }
    }
}
