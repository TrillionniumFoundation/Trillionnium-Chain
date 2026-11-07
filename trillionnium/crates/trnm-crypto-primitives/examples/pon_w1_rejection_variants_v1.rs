//! Finite local refusal costs. No public-service, work-hardness or energy claim.
use serde_json::{json, Value};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pon_work::{self as work, rejection_cache::RejectionCache, *};

const SAMPLES: u64 = 8;
const VARIANTS: u32 = 32;
const SEARCH_LIMIT: u64 = 65_536;

#[cfg(target_os = "linux")]
fn cpu() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    u64::try_from(t.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(t.tv_nsec).ok()?)
}
#[cfg(not(target_os = "linux"))]
fn cpu() -> Option<u64> {
    None
}

fn measured<T>(f: impl FnOnce() -> T) -> (T, Value) {
    let started = Instant::now();
    let before = cpu();
    let value = f();
    let used = before.zip(cpu()).and_then(|(a, b)| b.checked_sub(a));
    (
        value,
        json!({"wall_ns": started.elapsed().as_nanos(), "thread_cpu_ns": used}),
    )
}

fn verify_observed(
    cache: Option<&RejectionCache>,
    challenge: Hash,
    task: Hash,
    target: Hash,
    proof: &[u8],
) -> Value {
    let mut points = 0;
    let mut tiles = 0;
    let (result, timing) = measured(|| {
        let mut progress = |point| {
            points += 1;
            tiles += usize::from(matches!(point, VerificationProgress::TranscriptTile { .. }));
            Ok::<(), std::convert::Infallible>(())
        };
        match cache {
            Some(cache) => {
                cache.verify_with_progress(challenge, task, target, proof, &mut progress)
            }
            None => work::verify_with_progress(challenge, task, target, proof, &mut progress),
        }
    });
    let (outcome, product) = match result {
        Ok(verified) => ("Accepted".to_owned(), Some(verified.product().to_vec())),
        Err(VerificationError::Relation(error)) => (format!("{error:?}"), None),
        Err(VerificationError::Cancelled(impossible)) => match impossible {},
    };
    black_box(&product);
    json!({"outcome":outcome, "timing":timing, "progress_points":points,
           "transcript_tiles":tiles, "accepted_product":product})
}

fn main() {
    let mut rows = Vec::new();
    let mut materials = Vec::new();
    for class in ["zero", "dense-periodic", "rank-one", "sparse"] {
        let ((a, b, task, prefix), setup) = measured(|| {
            let matrix = |right: bool| {
                (0..CELLS)
                    .map(|i| match class {
                        "zero" => 0,
                        "rank-one" => ((i / N + 1 + usize::from(right)) * (i % N + 1)) as u32,
                        "sparse" => u32::from(i / N == i % N),
                        _ => ((i * if right { 7 } else { 1 }) % 31) as u32,
                    })
                    .collect::<Vec<_>>()
            };
            let a = matrix(false);
            let b = matrix(true);
            let task = task_id(&a, &b).expect("canonical material");
            let mut prefix = b"PNW1".to_vec();
            prefix.extend(a.iter().chain(&b).flat_map(|v| v.to_le_bytes()));
            prefix.resize(PROOF_BYTES, 0);
            (a, b, task, prefix)
        });
        materials.push(json!({"class":class,"setup":setup,"task":hex::encode(task),
                              "a":a,"b":b,"setup_charged_once_per_class":true}));
        for top in [127_u8, 7] {
            let mut target = [255_u8; 32];
            target[0] = top;
            for sample in 0..SAMPLES {
                // This attacker constructs no valid transcript or product to acquire its false claim.
                let challenge = hash(
                    b"rejection-c-variants-v1",
                    &[class.as_bytes(), &[top], &sample.to_le_bytes()],
                );
                let ((attempts, selected), search) = measured(|| {
                    let mut attempts = Vec::new();
                    let mut selected = None;
                    for nonce in 0..SEARCH_LIMIT {
                        let trace = hash(
                            b"false-trace-c-variants-v1",
                            &[&challenge, &nonce.to_le_bytes()],
                        );
                        let ticket = hash(b"ticket", &[&challenge, &trace]);
                        attempts.push(json!({"nonce":nonce,"trace":hex::encode(trace),
                                             "ticket":hex::encode(ticket),"meets_target":ticket <= target}));
                        if ticket <= target {
                            selected = Some(trace);
                            break;
                        }
                    }
                    (attempts, selected)
                });
                let (cache, cache_setup) =
                    measured(|| RejectionCache::new(256, Duration::from_secs(30)).unwrap());
                let mut variants = Vec::new();
                if let Some(trace) = selected {
                    for variant in 0..VARIANTS {
                        let (proof, construction) = measured(|| {
                            let mut proof = prefix.clone();
                            proof[PROOF_BYTES - 32..].copy_from_slice(&trace);
                            let word = [0, CELLS / 2, CELLS - 1][variant as usize % 3];
                            let offset = 4 + 2 * CELLS * 4 + word * 4;
                            proof[offset..offset + 4].copy_from_slice(&(variant + 1).to_le_bytes());
                            proof
                        });
                        let cached_first = (sample + u64::from(variant)).is_multiple_of(2);
                        let (native, cached) = if cached_first {
                            let cached =
                                verify_observed(Some(&cache), challenge, task, target, &proof);
                            (
                                verify_observed(None, challenge, task, target, &proof),
                                cached,
                            )
                        } else {
                            let native = verify_observed(None, challenge, task, target, &proof);
                            (
                                native,
                                verify_observed(Some(&cache), challenge, task, target, &proof),
                            )
                        };
                        assert_eq!(native["outcome"], "Transcript");
                        assert_eq!(cached["outcome"], "Transcript");
                        assert_eq!(native["transcript_tiles"], 512);
                        assert_eq!(
                            cached["transcript_tiles"],
                            if variant == 0 { 512 } else { 0 }
                        );
                        variants.push(json!({"variant":variant,"cached_first":cached_first,
                            "proof_commitment":hex::encode(hash(b"measured-proof", &[&proof])),
                            "construction":construction,"native_no_cache":native,"configured_cache":cached}));
                    }
                }
                // Positive control is acquired afterwards and uses the same challenge/material.
                // The real proof's own ticket is used so acceptance tests the full relation.
                let (valid, positive_setup) = measured(|| prove(challenge, &a, &b).unwrap());
                let honest_target = hash(b"ticket", &[&challenge, &valid[PROOF_BYTES - 32..]]);
                let positive =
                    verify_observed(Some(&cache), challenge, task, honest_target, &valid);
                assert_eq!(positive["outcome"], "Accepted");
                let positive_same_attack_target = if honest_target <= target {
                    let observation =
                        verify_observed(Some(&cache), challenge, task, target, &valid);
                    assert_eq!(observation["outcome"], "Accepted");
                    Some(observation)
                } else {
                    None
                };
                let (_, cache_destruction) = measured(|| drop(cache));
                rows.push(json!({"class":class,"sample":sample,"challenge":hex::encode(challenge),
                    "target":hex::encode(target),"search":search,"attempt_limit":SEARCH_LIMIT,
                    "attempts":attempts,"exhausted":selected.is_none(),"variants":variants,
                    "cache_setup":cache_setup,"cache_destruction":cache_destruction,
                    "positive_setup":positive_setup,"positive_target":hex::encode(honest_target),
                    "positive_trace":hex::encode(&valid[PROOF_BYTES - 32..]),
                    "positive_control_scope":"same challenge and A/B, own exact ticket target; relation acceptance only, not production at attack target",
                    "positive_same_attack_target":positive_same_attack_target,
                    "positive":positive}));
            }
        }
    }
    println!(
        "{}",
        json!({"schema":"pon-w1-rejection-c-variants-cost-v1", "samples":SAMPLES,
        "variants_per_claim":VARIANTS,"materials":materials,"rows":rows,
        "timing_scope":"same-process local producer and verifier with progress instrumentation; search includes attempt-record construction",
        "control_scope":"native-no-cache versus explicitly configured cache; not a before/after deployed service comparison",
        "material_scope":"synthetic fixtures; dense-periodic is a modulo-31 pattern, with no full-rank claim",
        "cpu_unknown_is_null":true,"signatures_cpu_ns":null,"network_bytes":null,"queue_wall_ns":null,
        "energy_joules":null,"public_service_measured":false,"original_resource_gate_passed":false,
        "minimum_work_cost_proved":false,"production_activation":false})
    );
}
