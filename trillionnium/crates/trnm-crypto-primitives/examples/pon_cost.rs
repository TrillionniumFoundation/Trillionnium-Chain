//! Fixed workload cost evidence; no throughput/security extrapolation.
use std::{hint::black_box, time::Instant};
use trnm_crypto_primitives::pon_work::*;
fn main() {
    let a: Vec<_> = (0..CELLS).map(|i| (i % 31) as u32).collect();
    let b: Vec<_> = (0..CELLS).map(|i| ((i * 7) % 37) as u32).collect();
    let task = task_id(&a, &b).unwrap();
    let target = [255; 32];
    let mut generation = Vec::new();
    let mut verification = Vec::new();
    let mut bad_verify = Vec::new();
    let mut forgery = Vec::new();
    for i in 0_u64..32 {
        let challenge = hash(b"cost-context", &[&i.to_le_bytes()]);
        let start = Instant::now();
        let proof = black_box(prove(challenge, &a, &b).unwrap());
        generation.push(start.elapsed().as_nanos());
        let start = Instant::now();
        black_box(verify(challenge, task, target, &proof).unwrap());
        verification.push(start.elapsed().as_nanos());
        let mut bad = proof;
        let len = bad.len();
        let start = Instant::now();
        let forged = hash(b"cheap-forged-trace", &[&i.to_le_bytes()]);
        bad[len - 32..].copy_from_slice(&forged);
        black_box(hash(b"ticket", &[&challenge, &forged]));
        forgery.push(start.elapsed().as_nanos());
        let start = Instant::now();
        assert!(verify(challenge, task, target, &bad).is_err());
        bad_verify.push(start.elapsed().as_nanos());
    }
    println!("{{\"profile\":\"{PROFILE}\",\"sample_count\":32,\"proof_bytes\":{PROOF_BYTES},\"generation_ns\":{generation:?},\"verification_ns\":{verification:?},\"invalid_verification_ns\":{bad_verify:?},\"cheap_forgery_ns\":{forgery:?},\"hardness_accepted\":false,\"production_activation\":false}}");
}
