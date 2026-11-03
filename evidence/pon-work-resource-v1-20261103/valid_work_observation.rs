//! Local valid-W1 observation only. This is not a public-service or hardness gate.
use std::{hint::black_box, time::Instant};
use trnm_crypto_primitives::pon_work::{self, Hash, CELLS, PROOF_BYTES, Q};

struct Fixture {
    class: usize,
    sample: usize,
    challenge: Hash,
    task: Hash,
    target: Hash,
    proof: Vec<u8>,
    proof_digest: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn thread_cpu_ticks() -> u64 {
    let raw = std::fs::read_to_string("/proc/thread-self/stat").unwrap();
    let fields: Vec<_> = raw.rsplit_once(") ").unwrap().1.split_whitespace().collect();
    // The suffix starts at proc field 3. utime and stime are fields 14 and 15.
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

fn main() {
    let loops: usize = std::env::args().nth(1).unwrap_or("256".into()).parse().unwrap();
    assert!((1..=4096).contains(&loops));
    let mut target = [255; 32];
    target[0] = 127;
    let mut fixtures = Vec::new();
    for sample in 0usize..8 {
        for offset in 0usize..3 {
            let class = (sample + offset) % 3;
            let a: Vec<u32> = (0..CELLS).map(|i| match class {
                0 => ((i * 65_537 + 258) as u128 % Q) as u32,
                1 => 0,
                _ => if i % 65 == 0 { (Q - 1 - i as u128) as u32 } else { 0 },
            }).collect();
            let b: Vec<u32> = (0..CELLS).map(|i| match class {
                0 => (Q - 1 - (i % 257) as u128) as u32,
                1 => (i * 131 + 7) as u32,
                _ => ((i * 4099 + 17) as u128 % Q) as u32,
            }).collect();
            let task = pon_work::task_id(&a, &b).unwrap();
            let (challenge, proof) = (0u64..64).find_map(|nonce| {
                let challenge = pon_work::hash(b"valid-resource-observation-v1", &[
                    &(class as u64).to_le_bytes(), &(sample as u64).to_le_bytes(), &nonce.to_le_bytes(),
                ]);
                // Every candidate here pays the original full legal prover.
                let proof = pon_work::prove(challenge, &a, &b).unwrap();
                let ticket = pon_work::hash(b"ticket", &[&challenge, &proof[PROOF_BYTES - 32..]]);
                (ticket <= target).then_some((challenge, proof))
            }).expect("bounded complete legal proof preparation");
            let oracle = pon_work::verify_reference(challenge, task, target, &proof).unwrap();
            let actual = pon_work::verify(challenge, task, target, &proof).unwrap();
            assert_eq!(actual.challenge(), oracle.challenge());
            assert_eq!(actual.task(), oracle.task());
            assert_eq!(actual.ticket(), oracle.ticket());
            assert_eq!(actual.product(), oracle.product());
            let proof_digest = hex(&pon_work::hash(b"resource-proof-v1", &[&proof]));
            fixtures.push(Fixture { class, sample, challenge, task, target, proof, proof_digest });
        }
    }
    println!("{{\"schema\":\"w1-valid-resource-local-v1\",\"samples\":8,\"classes\":3,\"loops_per_sample\":{loops},\"full_scalar_parity_checks\":24,\"qualification\":\"HOLD\"}}");
    let mut checksum = 0u32;
    for f in fixtures {
        let cpu_start = thread_cpu_ticks();
        let start = Instant::now();
        for i in 0..loops {
            let work = pon_work::verify(
                black_box(f.challenge), black_box(f.task), black_box(f.target), black_box(&f.proof),
            ).unwrap();
            checksum ^= black_box(work.product())[(i + f.sample) % CELLS];
            black_box(&work);
        }
        let wall_ns = start.elapsed().as_nanos();
        let cpu_ticks = thread_cpu_ticks() - cpu_start;
        println!("{{\"class\":{},\"sample\":{},\"calls\":{},\"wall_ns\":{},\"thread_cpu_ticks\":{},\"proof_digest\":\"{}\"}}", f.class, f.sample, loops, wall_ns, cpu_ticks, f.proof_digest);
    }
    println!("{{\"checksum\":{checksum},\"valid_calls\":{}}}", 24 * loops);
}
