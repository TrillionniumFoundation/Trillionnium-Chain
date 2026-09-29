//! Actual verifier work under a local owned-capacity flood. No public fairness theorem.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Instant;
use trnm_crypto_primitives::pon_work::*;
use trnm_transport::proof_admission::bounded_ingress;
fn main() {
    let (public, recovery) = bounded_ingress();
    let a: Vec<_> = (0..CELLS).map(|i| (i % 31) as u32).collect();
    let b: Vec<_> = (0..CELLS).map(|i| ((i * 7) % 37) as u32).collect();
    let task = task_id(&a, &b).unwrap();
    let challenge = hash(b"admission-load", &[]);
    let proof = Arc::new(prove(challenge, &a, &b).unwrap());
    // A permissive threshold isolates scheduling, not mining or attacker work cost.
    let target = [255; 32];
    let start = Arc::new(Barrier::new(5));
    let busy = AtomicUsize::new(0);
    let rejected = AtomicUsize::new(0);
    let begin = Instant::now();
    let recovery_samples = std::thread::scope(|scope| {
        for thread in 0_u32..4 {
            let ingress = public.clone();
            let start = start.clone();
            let proof = proof.clone();
            let busy = &busy;
            let rejected = &rejected;
            scope.spawn(move || {
                start.wait();
                for i in 0_u32..512 {
                    let peer = hash(b"flood-peer", &[&thread.to_le_bytes(), &i.to_le_bytes()]);
                    let fake = hash(b"flood-trace", &[&peer]);
                    let mut bad = proof.as_ref().clone();
                    bad[PROOF_BYTES - 32..].copy_from_slice(&fake);
                    if let Ok(_permit) = ingress.try_acquire(peer, hash(b"certificate", &[&bad])) {
                        assert!(verify(challenge, task, target, &bad).is_err());
                        rejected.fetch_add(1, Ordering::Relaxed);
                    } else {
                        busy.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
        start.wait();
        let mut times = Vec::new();
        for i in 0_u64..16 {
            let begin = Instant::now();
            let _permit = recovery
                .try_acquire(hash(b"recovery-request", &[&i.to_le_bytes()]))
                .unwrap();
            std::hint::black_box(verify(challenge, task, target, &proof).unwrap());
            times.push(begin.elapsed().as_nanos());
        }
        times
    });
    println!("{{\"schema\":\"pon-owned-verifier-capacity-load-v3\",\"attempted_public_jobs\":2048,\"invalid_proofs_recomputed_and_rejected\":{},\"busy_before_work\":{},\"local_recovery_verified\":16,\"recovery_ns\":{:?},\"elapsed_ns\":{},\"permissionless_honest_admission_guaranteed\":false,\"full_network_host\":false,\"production_activation\":false}}",rejected.load(Ordering::Relaxed),busy.load(Ordering::Relaxed),recovery_samples,begin.elapsed().as_nanos());
}
