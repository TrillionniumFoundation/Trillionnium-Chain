//! Paired producer implementation costs; original verifier and admitted relation unchanged.
use std::{hint::black_box, time::Instant};
use trnm_crypto_primitives::pon_work::*;
fn search(
    class: &str,
    sample: u64,
    target: Hash,
    mut prover: impl FnMut(Hash) -> Vec<u8>,
) -> (u64, Vec<u8>, Hash, u128) {
    let start = Instant::now();
    for nonce in 0u64..4096 {
        let challenge = hash(
            b"prepared-cost",
            &[
                class.as_bytes(),
                &sample.to_le_bytes(),
                &nonce.to_le_bytes(),
            ],
        );
        let proof = prover(challenge);
        if hash(b"ticket", &[&challenge, &proof[PROOF_BYTES - 32..]]) <= target {
            return (nonce + 1, proof, challenge, start.elapsed().as_nanos());
        }
    }
    panic!("bounded measured search budget exhausted");
}
fn main() {
    print!("{{\"schema\":\"pon-prepared-producer-cost-v1\",\"samples\":[");
    let mut first = true;
    for class in ["dense", "zero", "rank-one", "sparse"] {
        let a: Vec<u32> = (0..CELLS)
            .map(|i| match class {
                "zero" => 0,
                "sparse" => u32::from(i / N == i % N),
                "rank-one" => ((i / N + 1) * (i % N + 1)) as u32,
                _ => (i % 31) as u32,
            })
            .collect();
        let b: Vec<u32> = (0..CELLS)
            .map(|i| match class {
                "zero" => 0,
                "sparse" => u32::from(i / N == i % N),
                "rank-one" => ((i / N + 2) * (i % N + 1)) as u32,
                _ => ((i * 7) % 37) as u32,
            })
            .collect();
        let task = task_id(&a, &b).unwrap();
        for top in [127u8, 7u8] {
            let mut target = [255; 32];
            target[0] = top;
            for sample in 0u64..8 {
                let baseline_first = sample.is_multiple_of(2);
                let baseline = || search(class, sample, target, |c| prove(c, &a, &b).unwrap());
                let prepared = || {
                    let start = Instant::now();
                    let task = PreparedTask::new(&a, &b).unwrap();
                    let setup = start.elapsed().as_nanos();
                    let value = search(class, sample, target, |c| task.prove(c).unwrap());
                    (setup, value)
                };
                let (original, (setup, optimized)) = if baseline_first {
                    (baseline(), prepared())
                } else {
                    let p = prepared();
                    (baseline(), p)
                };
                assert_eq!(original.0, optimized.0);
                assert_eq!(original.1, optimized.1);
                assert_eq!(original.2, optimized.2);
                let start = Instant::now();
                black_box(verify(original.2, task, target, &optimized.1).unwrap());
                let verification = start.elapsed().as_nanos();
                if !first {
                    print!(",");
                }
                first = false;
                print!("{{\"class\":\"{class}\",\"target\":\"{}\",\"sample\":{sample},\"baseline_first\":{baseline_first},\"attempts\":{},\"baseline_ns\":{},\"prepared_setup_ns\":{setup},\"prepared_search_ns\":{},\"prepared_total_ns\":{},\"original_verifier_ns\":{verification},\"proof_bytes\":{PROOF_BYTES},\"proof_commitment\":\"{}\"}}",hex::encode(target),original.0,original.3,optimized.3,setup+optimized.3,hex::encode(hash(b"measured-proof",&[&optimized.1])));
            }
        }
    }
    println!("],\"fastest_adversary_qualified\":false,\"public_service_measured\":false,\"production_activation\":false}}");
}
