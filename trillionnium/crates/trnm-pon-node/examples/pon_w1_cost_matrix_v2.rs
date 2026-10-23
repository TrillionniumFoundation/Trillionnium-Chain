//! Explicit cost-observation V2. Existing W1 and all V1 reports are unchanged.
//! Clocks and every attempted proof are observations, never work-cost lower bounds.
#[path = "support/w1_from_zero.rs"]
mod w1_from_zero;
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod w1_material;

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{hint::black_box, io::Write, thread, time::Instant};
use trnm_crypto_primitives::pon_work::{
    self,
    blocked_one_zero::BlockedOneZeroRankOnePreparedTask,
    blocked_zero::BlockedZeroPreparedTask,
    blocked_zero_paired::BlockedZeroPairedPreparedTask,
    facts::{FactCounters, FactError, WorkFactCache, MAX_FACT_SLOTS},
    maintenance_limb::MaintenanceLimbPreparedTask,
    maintenance_periodic::MaintenancePeriodicPreparedTask,
    maintenance_prefix::{MaintenanceIntegerPairedPreparedTask, MaintenancePrefixPreparedTask},
    paired_product::PairedPreparedTask,
    structured::{StructuredPreparedTask, TileKernel, TiledPreparedTask},
    Hash, PreparedTask, VerifiedWork, WorkError, CELLS, PROOF_BYTES, Q,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-w1-all-producers-cost-v2";
const SAMPLES: u64 = 8;
const LIMIT: u64 = 4096;
const SEED: u64 = 0;
const ARMS: [&str; 13] = [
    "scalar-original",
    "prepared-generic",
    "prepared-structured",
    "tiled-classical",
    "tiled-strassen-one-level",
    "paired-product",
    "blocked-zero",
    "blocked-zero-integer-paired",
    "blocked-one-zero-rank-one",
    "maintenance-periodic",
    "maintenance-integer-paired",
    "maintenance-prefix",
    "maintenance-limb",
];

struct Clock {
    wall: Instant,
    cpu: Option<u64>,
    owner: thread::ThreadId,
}
impl Clock {
    fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: cpu(),
            owner: thread::current().id(),
        }
    }
    fn finish(self) -> Timing {
        Timing {
            wall_ns: u64::try_from(self.wall.elapsed().as_nanos()).ok(),
            cpu_ns: if self.owner == thread::current().id() {
                self.cpu.and_then(|start| cpu()?.checked_sub(start))
            } else {
                None
            },
        }
    }
}
#[derive(Clone, Copy, Serialize)]
struct Timing {
    cpu_ns: Option<u64>,
    wall_ns: Option<u64>,
}
#[cfg(target_os = "linux")]
fn cpu() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let stamp = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let seconds = u64::try_from(stamp.tv_sec).ok()?;
    let nanos = u64::try_from(stamp.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}
#[cfg(not(target_os = "linux"))]
fn cpu() -> Option<u64> {
    None
}
fn emit(mut row: Value) -> Result<()> {
    row.as_object_mut()
        .ok_or("COST_RECORD_OBJECT")?
        .insert("schema".into(), SCHEMA.into());
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &row)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn raw(matrix: &[u32]) -> Vec<u8> {
    matrix.iter().flat_map(|n| n.to_le_bytes()).collect()
}
fn target() -> Hash {
    let mut value = [255; 32];
    value[0] = 127;
    value
}
fn challenge(task: Hash, sample: u64, nonce: u64) -> Hash {
    pon_work::hash(
        b"pon-w1-cost-matrix-challenge-v2",
        &[
            &task,
            &SEED.to_le_bytes(),
            &sample.to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    )
}

enum Producer {
    Scalar(Vec<u32>, Vec<u32>),
    Generic(Box<PreparedTask>),
    Structured(Box<StructuredPreparedTask>),
    Tiled(Box<TiledPreparedTask>),
    Paired(Box<PairedPreparedTask>),
    Zero(Box<BlockedZeroPreparedTask>),
    ZeroPaired(Box<BlockedZeroPairedPreparedTask>),
    OneZero(Box<BlockedOneZeroRankOnePreparedTask>),
    Periodic(Box<MaintenancePeriodicPreparedTask>),
    Integer(Box<MaintenanceIntegerPairedPreparedTask>),
    Prefix(Box<MaintenancePrefixPreparedTask>),
    Limb(Box<MaintenanceLimbPreparedTask>),
}
impl Producer {
    fn new(index: usize, a: &[u32], b: &[u32]) -> std::result::Result<Option<Self>, WorkError> {
        Ok(match index {
            0 => {
                pon_work::task_id(a, b)?;
                Some(Self::Scalar(a.to_vec(), b.to_vec()))
            }
            1 => Some(Self::Generic(Box::new(PreparedTask::new(a, b)?))),
            2 => StructuredPreparedTask::new(a, b)?.map(|t| Self::Structured(Box::new(t))),
            3 | 4 => Some(Self::Tiled(Box::new(TiledPreparedTask::new(
                a,
                b,
                if index == 3 {
                    TileKernel::Classical
                } else {
                    TileKernel::StrassenOneLevel
                },
            )?))),
            5 => Some(Self::Paired(Box::new(PairedPreparedTask::new(a, b)?))),
            6 => BlockedZeroPreparedTask::new(a, b)?.map(|t| Self::Zero(Box::new(t))),
            7 => BlockedZeroPairedPreparedTask::new(a, b)?.map(|t| Self::ZeroPaired(Box::new(t))),
            8 => BlockedOneZeroRankOnePreparedTask::new(a, b)?.map(|t| Self::OneZero(Box::new(t))),
            9 => MaintenancePeriodicPreparedTask::new(a, b)?.map(|t| Self::Periodic(Box::new(t))),
            10 => {
                MaintenanceIntegerPairedPreparedTask::new(a, b)?.map(|t| Self::Integer(Box::new(t)))
            }
            11 => MaintenancePrefixPreparedTask::new(a, b)?.map(|t| Self::Prefix(Box::new(t))),
            12 => MaintenanceLimbPreparedTask::new(a, b)?.map(|t| Self::Limb(Box::new(t))),
            _ => return Err(WorkError::Task),
        })
    }
    fn prove(&self, value: Hash) -> std::result::Result<Vec<u8>, WorkError> {
        match self {
            Self::Scalar(a, b) => pon_work::prove(value, a, b),
            Self::Generic(t) => t.prove(value),
            Self::Structured(t) => t.prove(value),
            Self::Tiled(t) => t.prove(value),
            Self::Paired(t) => t.prove(value),
            Self::Zero(t) => t.prove(value),
            Self::ZeroPaired(t) => t.prove(value),
            Self::OneZero(t) => t.prove(value),
            Self::Periodic(t) => t.prove(value),
            Self::Integer(t) => t.prove(value),
            Self::Prefix(t) => t.prove(value),
            Self::Limb(t) => t.prove(value),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Trial {
    nonce: u64,
    challenge: String,
    trace: String,
    ticket: String,
    proof_sha256: Option<String>,
    target_hit: bool,
}
#[derive(Clone, PartialEq, Eq)]
struct Winner {
    challenge: Hash,
    proof: Vec<u8>,
}
struct Search {
    attempts: Vec<Trial>,
    winner: Option<Winner>,
}
fn legal_search(producer: &Producer, task: Hash, sample: u64, limit: u64) -> Result<Search> {
    let mut result = Search {
        attempts: Vec::new(),
        winner: None,
    };
    for nonce in 0..limit {
        let context = challenge(task, sample, nonce);
        let proof = producer
            .prove(context)
            .map_err(|e| format!("GENERATION:{e:?}"))?;
        if proof.len() != PROOF_BYTES {
            return Err("GENERATED_PROOF_LENGTH".into());
        }
        let trace = &proof[PROOF_BYTES - 32..];
        let ticket = pon_work::hash(b"ticket", &[&context, trace]);
        let hit = ticket <= target();
        result.attempts.push(Trial {
            nonce,
            challenge: hex::encode(context),
            trace: hex::encode(trace),
            ticket: hex::encode(ticket),
            proof_sha256: Some(sha(&proof)),
            target_hit: hit,
        });
        if hit {
            result.winner = Some(Winner {
                challenge: context,
                proof,
            });
            break;
        }
    }
    Ok(result)
}
fn producer_row(
    material: &w1_material::Material,
    task: Hash,
    sample: u64,
    order: usize,
    canonical: &mut Option<Search>,
) -> Result<()> {
    let index = (sample as usize + order) % ARMS.len();
    let total = Clock::start();
    let setup = Clock::start();
    let prepared =
        Producer::new(index, &material.a, &material.b).map_err(|e| format!("PREPARATION:{e:?}"))?;
    let setup = setup.finish();
    let (searched, search) = if let Some(producer) = prepared {
        let started = Clock::start();
        let searched = legal_search(&producer, task, sample, LIMIT)?;
        let measured = started.finish();
        (Some(searched), Some(measured))
    } else {
        (None, None)
    };
    let total = total.finish();
    let status = match &searched {
        None => "unsupported",
        Some(s) if s.winner.is_none() => "exhausted",
        Some(_) => "target-hit-unverified",
    };
    let row = json!({"kind":"producer","class":material.name,"sample":sample,"arm":ARMS[index],
        "invocation_order":order,"task":hex::encode(task),"target":hex::encode(target()),
        "status":status,"setup_calls":1,"setup":setup,"search":search,"total":total,
        "attempts":searched.as_ref().map(|s|s.attempts.as_slice()).unwrap_or(&[]),
        "winner":searched.as_ref().and_then(|s|s.winner.as_ref()).map(|w|
            json!({"challenge":hex::encode(w.challenge),"proof_sha256":sha(&w.proof)}))});
    // Preserve the actual arm before failing a byte-equivalence assertion.
    emit(row)?;
    if let Some(searched) = searched {
        if let Some(original) = canonical {
            if original.attempts != searched.attempts || original.winner != searched.winner {
                return Err("SUPPORTED_PRODUCER_STREAM_DISAGREEMENT".into());
            }
        } else {
            *canonical = Some(searched);
        }
    }
    Ok(())
}

struct Forgery {
    proof: Option<Vec<u8>>,
    attempts: Vec<Trial>,
    setup: Timing,
    search: Timing,
    total: Timing,
}
fn false_trace(material: &w1_material::Material, context: Hash, limit: u64) -> Result<Forgery> {
    let total = Clock::start();
    let setup = Clock::start();
    let mut prefix = w1_from_zero::proof_prefix(&material.a, &material.b)
        .map_err(|e| format!("FALSE_PREFIX:{e:?}"))?;
    let setup = setup.finish();
    let search = Clock::start();
    let mut attempts = Vec::new();
    let mut proof = None;
    for nonce in 0..limit {
        let (trace, ticket) = w1_from_zero::trial(context, nonce);
        let hit = ticket <= target();
        attempts.push(Trial {
            nonce,
            challenge: hex::encode(context),
            trace: hex::encode(trace),
            ticket: hex::encode(ticket),
            proof_sha256: None,
            target_hit: hit,
        });
        if hit {
            prefix[PROOF_BYTES - 32..].copy_from_slice(&trace);
            proof = Some(prefix);
            break;
        }
    }
    Ok(Forgery {
        proof,
        attempts,
        setup,
        search: search.finish(),
        total: total.finish(),
    })
}
fn wrong_product(original: &[u8]) -> Forgery {
    let total = Clock::start();
    let setup = Clock::start().finish();
    let search = Clock::start();
    let mut proof = original.to_vec();
    let offset = PROOF_BYTES - 36;
    let old = u32::from_le_bytes(proof[offset..offset + 4].try_into().unwrap());
    let changed = ((u128::from(old) + 1) % Q) as u32;
    proof[offset..offset + 4].copy_from_slice(&changed.to_le_bytes());
    Forgery {
        proof: Some(proof),
        attempts: Vec::new(),
        setup,
        search: search.finish(),
        total: total.finish(),
    }
}
fn forged_row(
    material: &w1_material::Material,
    task: Hash,
    sample: u64,
    winner: &Winner,
    variant: &str,
    forged: &Forgery,
) -> Result<()> {
    let acquired = variant == "product-last";
    emit(
        json!({"kind":"forgery","class":material.name,"sample":sample,"variant":variant,
        "challenge":hex::encode(winner.challenge),"task":hex::encode(task),"target":hex::encode(target()),
        "status":if forged.proof.is_some(){"target-hit-unverified"}else{"exhausted"},
        "setup":forged.setup,"search":forged.search,"total":forged.total,"attempts":forged.attempts,
        "winner":forged.proof.as_ref().map(|p|json!({"trace":hex::encode(&p[PROOF_BYTES-32..]),"proof_sha256":sha(p)})),
        "valid_proof_acquisition_used":acquired,"construction_scope":if acquired{
            "existing-valid-proof-clone-and-canonical-last-cell-increment"
        }else{"full-public-prefix-and-all-hash-trials"}}),
    )
}
fn accepted(work: VerifiedWork, proof: &[u8]) -> String {
    if raw(work.product()) == proof[4 + 8 * CELLS..PROOF_BYTES - 32] {
        "Accepted".into()
    } else {
        "AcceptedWrongProduct".into()
    }
}
fn regular_outcome(result: std::result::Result<VerifiedWork, WorkError>, proof: &[u8]) -> String {
    match result {
        Ok(work) => accepted(work, proof),
        Err(error) => format!("{error:?}"),
    }
}
fn fact_outcome(
    result: std::result::Result<VerifiedWork, FactError<std::convert::Infallible>>,
    proof: &[u8],
) -> String {
    match result {
        Ok(work) => accepted(work, proof),
        Err(FactError::Relation(error)) => format!("{error:?}"),
        Err(FactError::Cancelled(never)) => match never {},
        Err(FactError::Unavailable) => "Unavailable".into(),
    }
}
fn counters(value: FactCounters) -> Value {
    json!({"full_replays":value.full_replays,"hits":value.hits,
        "wait_polls":value.wait_polls,"evictions":value.evictions})
}
fn verifiers(
    material: &w1_material::Material,
    task: Hash,
    sample: u64,
    winner: &Winner,
    case: &str,
    proof: &[u8],
) -> Result<()> {
    for path in ["production", "facts-cold", "facts-warm"] {
        let mut row = json!({"kind":"verifier","class":material.name,"sample":sample,"case":case,
            "path":path,"challenge":hex::encode(winner.challenge),"task":hex::encode(task),
            "target":hex::encode(target()),"proof_sha256":sha(proof),
            "cache_capacity":null,"cache_before":null,"cache_after":null,
            "cache_setup":null,"warmup":null});
        let (timing, outcome) = if path == "production" {
            let started = Clock::start();
            let native = black_box(pon_work::verify(winner.challenge, task, target(), proof));
            (started.finish(), regular_outcome(native, proof))
        } else {
            let setup = Clock::start();
            let cache = WorkFactCache::new(MAX_FACT_SLOTS).map_err(|e| e.to_string())?;
            row["cache_setup"] = serde_json::to_value(setup.finish())?;
            row["cache_capacity"] = MAX_FACT_SLOTS.into();
            if path == "facts-warm" {
                let started = Clock::start();
                let native =
                    black_box(cache.verify(winner.challenge, task, target(), &winner.proof));
                let timing = started.finish();
                let outcome = fact_outcome(native, &winner.proof);
                row["warmup"] = json!({"timing":timing,"outcome":outcome,
                    "proof_sha256":sha(&winner.proof)});
            }
            row["cache_before"] = counters(cache.counters());
            let started = Clock::start();
            let native = black_box(cache.verify(winner.challenge, task, target(), proof));
            let timing = started.finish();
            row["cache_after"] = counters(cache.counters());
            (timing, fact_outcome(native, proof))
        };
        row["timing"] = serde_json::to_value(timing)?;
        row["outcome"] = outcome.into();
        emit(row)?;
    }
    Ok(())
}
fn run() -> Result<()> {
    if std::env::args_os().len() != 1 {
        return Err("V2_FIXED_CAMPAIGN_NO_ARGUMENTS".into());
    }
    let material_started = Clock::start();
    let mut materials = w1_material::materials(None, None)?;
    let nonzero: Vec<u32> = (0..CELLS)
        .map(|i| ((i / 64 + 1) * (i % 64 + 2)) as u32)
        .collect();
    materials.push(w1_material::Material {
        name: "one-zero-left-rank-one",
        source: "synthetic-fixture",
        a: vec![0; CELLS],
        b: nonzero.clone(),
    });
    materials.push(w1_material::Material {
        name: "one-zero-right-rank-one",
        source: "synthetic-fixture",
        a: nonzero,
        b: vec![0; CELLS],
    });
    let material_setup = material_started.finish();
    emit(
        json!({"kind":"campaign","samples":SAMPLES,"attempt_budget":LIMIT,"seed":SEED,
        "target":hex::encode(target()),"arms":ARMS,"classes":materials.iter().map(|m|m.name).collect::<Vec<_>>(),
        "clock":"thread-cpu-and-monotonic-wall-ns","material_setup":material_setup,
        "setup_amortization":"modeled-setup-divisor-not-observed-multiwinner",
        "public_listener_uses_work_facts":false,"hardness_accepted":false,"production_activation":false}),
    )?;
    let (mut producer_count, mut candidate_count, mut forgery_count, mut verifier_count) =
        (0, 0, 0, 0);
    for material in &materials {
        let task =
            pon_work::task_id(&material.a, &material.b).map_err(|e| format!("MATERIAL:{e:?}"))?;
        emit(
            json!({"kind":"material","class":material.name,"source":material.source,"task":hex::encode(task),
            "a_hex":hex::encode(raw(&material.a)),"b_hex":hex::encode(raw(&material.b))}),
        )?;
        for sample in 0..SAMPLES {
            let mut canonical = None;
            for order in 0..ARMS.len() {
                producer_row(material, task, sample, order, &mut canonical)?;
                producer_count += 1;
            }
            if let Some(winner) = canonical.and_then(|searched| searched.winner) {
                emit(
                    json!({"kind":"candidate","class":material.name,"sample":sample,
                    "task":hex::encode(task),"target":hex::encode(target()),
                    "challenge":hex::encode(winner.challenge),"proof_hex":hex::encode(&winner.proof),
                    "proof_sha256":sha(&winner.proof)}),
                )?;
                candidate_count += 1;
                verifiers(material, task, sample, &winner, "legal", &winner.proof)?;
                verifier_count += 3;
                for (variant, forged) in [
                    (
                        "from-zero-transcript",
                        false_trace(material, winner.challenge, LIMIT)?,
                    ),
                    ("product-last", wrong_product(&winner.proof)),
                ] {
                    forged_row(material, task, sample, &winner, variant, &forged)?;
                    forgery_count += 1;
                    if let Some(proof) = &forged.proof {
                        verifiers(material, task, sample, &winner, variant, proof)?;
                        verifier_count += 3;
                    }
                }
            }
        }
    }
    emit(
        json!({"kind":"end","material_count":materials.len(),"producer_count":producer_count,
        "candidate_count":candidate_count,"forgery_count":forgery_count,
        "verifier_count":verifier_count,"complete":true}),
    )
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_existing_arm_is_exercised_without_unsupported_fallback() {
        let zero = vec![0; CELLS];
        let supported: Vec<_> = (0..ARMS.len())
            .filter(|i| Producer::new(*i, &zero, &zero).unwrap().is_some())
            .collect();
        assert_eq!(supported, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        let (a, b) = trnm_mvcc_fee::continuity_v1::maintenance_matrices();
        let supported: Vec<_> = (0..ARMS.len())
            .filter(|i| Producer::new(*i, &a, &b).unwrap().is_some())
            .collect();
        assert_eq!(supported, vec![0, 1, 3, 4, 5, 9, 10, 11, 12]);
    }
    #[test]
    fn exact_complete_proofs_and_fact_cold_warm_outcomes_match() {
        let zero = vec![0; CELLS];
        let task = pon_work::task_id(&zero, &zero).unwrap();
        let first = legal_search(
            &Producer::new(1, &zero, &zero).unwrap().unwrap(),
            task,
            0,
            LIMIT,
        )
        .unwrap();
        let winner = first.winner.as_ref().unwrap();
        for index in [0, 2, 3, 4, 5, 6, 7] {
            let checked = legal_search(
                &Producer::new(index, &zero, &zero).unwrap().unwrap(),
                task,
                0,
                LIMIT,
            )
            .unwrap();
            assert_eq!(checked.attempts, first.attempts);
            assert!(checked.winner == first.winner);
        }
        let cache = WorkFactCache::new(MAX_FACT_SLOTS).unwrap();
        assert_eq!(
            fact_outcome(
                cache.verify(winner.challenge, task, target(), &winner.proof),
                &winner.proof
            ),
            "Accepted"
        );
        assert_eq!(
            (cache.counters().full_replays, cache.counters().hits),
            (1, 0)
        );
        let changed = wrong_product(&winner.proof).proof.unwrap();
        assert_eq!(
            fact_outcome(
                cache.verify(winner.challenge, task, target(), &changed),
                &changed
            ),
            "Product"
        );
        assert_eq!(
            (cache.counters().full_replays, cache.counters().hits),
            (1, 1)
        );
        let material = w1_material::Material {
            name: "zero",
            source: "synthetic-fixture",
            a: zero.clone(),
            b: zero,
        };
        let changed = false_trace(&material, winner.challenge, LIMIT)
            .unwrap()
            .proof
            .unwrap();
        assert_eq!(
            fact_outcome(
                cache.verify(winner.challenge, task, target(), &changed),
                &changed
            ),
            "Transcript"
        );
        assert_eq!(
            (cache.counters().full_replays, cache.counters().hits),
            (2, 1)
        );
    }
}
