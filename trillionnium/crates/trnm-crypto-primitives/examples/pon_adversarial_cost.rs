//! Controlled work/forgery costs at the actual experimental target. Not a cost lower bound.
use std::{hint::black_box, time::Instant};
use trnm_crypto_primitives::pon_work::*;
fn main() {
    let mut target = [255_u8; 32];
    target[0] = 127;
    print!("{{\"schema\":\"pon-structured-cost-v3\",\"target\":\"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"samples\":[");
    let mut first = true;
    for class in ["dense", "zero", "rank-one", "sparse"] {
        let a: Vec<u32> = (0..CELLS)
            .map(|i| match class {
                "zero" => 0,
                "rank-one" => ((i / N + 1) * (i % N + 1)) as u32,
                "sparse" => u32::from(i / N == i % N),
                _ => (i % 31) as u32,
            })
            .collect();
        let b: Vec<u32> = (0..CELLS)
            .map(|i| match class {
                "zero" => 0,
                "rank-one" => ((i / N + 2) * (i % N + 1)) as u32,
                "sparse" => u32::from(i / N == i % N),
                _ => ((i * 7) % 37) as u32,
            })
            .collect();
        let task = task_id(&a, &b).expect("fixed inputs");
        for sample in 0_u64..8 {
            let start = Instant::now();
            let mut attempts = 0_u64;
            let (challenge, proof) = loop {
                let challenge = hash(
                    b"adversarial-cost",
                    &[
                        class.as_bytes(),
                        &sample.to_le_bytes(),
                        &attempts.to_le_bytes(),
                    ],
                );
                let proof = prove(challenge, &a, &b).expect("fixed profile");
                attempts += 1;
                if hash(b"ticket", &[&challenge, &proof[PROOF_BYTES - 32..]]) <= target {
                    break (challenge, proof);
                }
                assert!(attempts < 4096, "bounded honest attempt budget");
            };
            let honest_ns = start.elapsed().as_nanos();
            let start = Instant::now();
            black_box(verify(challenge, task, target, &proof).expect("honest accepted output"));
            let verify_ns = start.elapsed().as_nanos();
            let start = Instant::now();
            let mut forged = proof.clone();
            let mut hashes = 0_u64;
            loop {
                let fake = hash(b"fake-trace", &[&challenge, &hashes.to_le_bytes()]);
                hashes += 1;
                if hash(b"ticket", &[&challenge, &fake]) <= target
                    && fake != proof[PROOF_BYTES - 32..]
                {
                    forged[PROOF_BYTES - 32..].copy_from_slice(&fake);
                    break;
                }
                assert!(hashes < 4096, "bounded forgery budget");
            }
            let forge_ns = start.elapsed().as_nanos();
            let start = Instant::now();
            assert!(verify(challenge, task, target, &forged).is_err());
            let reject_ns = start.elapsed().as_nanos();
            if !first {
                print!(",");
            }
            first = false;
            print!("{{\"class\":\"{class}\",\"sample\":{sample},\"honest_attempts\":{attempts},\"honest_winning_ns\":{honest_ns},\"valid_verify_ns\":{verify_ns},\"forgery_hash_trials\":{hashes},\"forgery_ns\":{forge_ns},\"invalid_verify_ns\":{reject_ns}}}");
        }
    }
    println!("],\"fastest_adversary_implemented\":false,\"hardness_accepted\":false,\"production_activation\":false}}");
}
