//! Bounded, single-threaded legal-W1 allocation observation. No network or timing.
//! Counts successful allocation requests and full requested realloc sizes, not RSS.
use std::alloc::{GlobalAlloc, Layout, System};
use std::convert::Infallible;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use trnm_crypto_primitives::pon_work::{
    self,
    arithmetic_facts::{ArithmeticFactCache, ArithmeticObservation},
    facts::WorkFactCache,
    Hash, VerifiedWork, CELLS, Q,
};

struct ObservedAllocator;
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;
static ENABLED: AtomicBool = AtomicBool::new(false);
static REQUESTS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static BYTES: AtomicU64 = AtomicU64::new(0);
fn record(pointer: *mut u8, bytes: usize, kind: usize) {
    if !pointer.is_null() && ENABLED.load(Ordering::Relaxed) {
        REQUESTS[kind].fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        record(pointer, layout.size(), 0);
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        record(pointer, layout.size(), 1);
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        record(pointer, size, 2);
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}
struct Counts {
    requests: [u64; 3],
    bytes: u64,
}
fn measured(call: impl FnOnce() -> VerifiedWork) -> (VerifiedWork, Counts) {
    assert!(!ENABLED.load(Ordering::SeqCst));
    for counter in &REQUESTS {
        counter.store(0, Ordering::Relaxed);
    }
    BYTES.store(0, Ordering::Relaxed);
    ENABLED.store(true, Ordering::SeqCst);
    let work = black_box(call());
    ENABLED.store(false, Ordering::SeqCst);
    (
        work,
        Counts {
            requests: std::array::from_fn(|index| REQUESTS[index].load(Ordering::Relaxed)),
            bytes: BYTES.load(Ordering::Relaxed),
        },
    )
}
struct Fixture {
    class: usize,
    variant: usize,
    challenge: Hash,
    task: Hash,
    proof: Vec<u8>,
    digest: String,
    oracle: VerifiedWork,
}
fn parity(work: &VerifiedWork, oracle: &VerifiedWork) {
    assert_eq!(work.challenge(), oracle.challenge());
    assert_eq!(work.task(), oracle.task());
    assert_eq!(work.ticket(), oracle.ticket());
    assert_eq!(work.product(), oracle.product());
}
fn emit(path: &str, fixture: &Fixture, result: (VerifiedWork, Counts), full_replay: bool) {
    let (work, counts) = result;
    parity(&work, &fixture.oracle); // Comparison and output occur after measurement.
    println!("{{\"path\":\"{}\",\"class\":{},\"variant\":{},\"proof_digest\":\"{}\",\"calls\":1,\"alloc_requests\":{},\"zeroed_requests\":{},\"realloc_requests\":{},\"successful_requests\":{},\"requested_bytes\":{},\"full_replay\":{},\"scalar_parity\":true}}",
        path, fixture.class, fixture.variant, fixture.digest, counts.requests[0],
        counts.requests[1], counts.requests[2], counts.requests.iter().sum::<u64>(),
        counts.bytes, full_replay);
}
fn fixtures() -> Vec<Fixture> {
    let mut fixtures = Vec::new();
    for class in 0..3usize {
        let a: Vec<u32> = (0..CELLS)
            .map(|i| match class {
                0 => ((i * 65_537 + 258) as u128 % Q) as u32,
                1 => 0,
                _ => (Q - 1 - (i % 257) as u128) as u32,
            })
            .collect();
        let b: Vec<u32> = (0..CELLS)
            .map(|i| match class {
                0 => (Q - 1 - (i % 127) as u128) as u32,
                1 => (i * 131 + 7) as u32,
                _ => [0, 1, (Q - 1) as u32, 1 << 31][i % 4],
            })
            .collect();
        let task = pon_work::task_id(&a, &b).unwrap();
        for variant in 0..2usize {
            let challenge = pon_work::hash(
                b"valid-cache-allocation-v1",
                &[&(class as u64).to_le_bytes(), &(variant as u64).to_le_bytes()],
            );
            let proof = pon_work::prove(challenge, &a, &b).unwrap();
            let oracle = pon_work::verify_reference(challenge, task, [255; 32], &proof).unwrap();
            let digest = pon_work::hash(b"valid-cache-proof-v1", &[&proof])
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            fixtures.push(Fixture { class, variant, challenge, task, proof, digest, oracle });
        }
    }
    fixtures
}
fn arithmetic(
    cache: &ArithmeticFactCache,
    fixture: &Fixture,
    out: &mut ArithmeticObservation,
) -> VerifiedWork {
    cache
        .verify_with_observation(
            fixture.challenge,
            fixture.task,
            [255; 32],
            &fixture.proof,
            &mut |_| Ok::<(), Infallible>(()),
            out,
        )
        .unwrap()
}
fn main() {
    let fixtures = fixtures(); // All legal proof generation and scalar oracles are excluded.
    println!("{{\"schema\":\"w1-valid-cache-allocation-v1\",\"classes\":3,\"challenges_per_task\":2,\"measured_calls\":24,\"scalar_reference_calls\":6,\"setup_verifier_calls\":12,\"fixture_generation_measured\":false,\"cache_construction_measured\":false,\"warm_setup_measured\":false,\"parity_and_output_measured\":false,\"target\":\"maximum-256-bit\",\"ticket_search\":false,\"counter\":\"successful-alloc-zeroed-realloc-full-request-size\",\"rss_or_cpu_measurement\":false,\"qualification\":\"HOLD\"}}");
    for pair in fixtures.chunks_exact(2) {
        let (first, next) = (&pair[0], &pair[1]);
        assert_eq!(first.task, next.task);
        assert_ne!(first.challenge, next.challenge);
        for fixture in pair {
            emit(
                "raw_full",
                fixture,
                measured(|| {
                    pon_work::verify(fixture.challenge, fixture.task, [255; 32], &fixture.proof).unwrap()
                }),
                true,
            );
        }
        for (path, fixture, seed) in [
            ("work_fact_cold", first, false),
            ("work_fact_warm", first, true),
            ("work_fact_changed_challenge", next, true),
        ] {
            let cache = WorkFactCache::new(1).unwrap();
            if seed {
                parity(
                    &cache.verify(first.challenge, first.task, [255; 32], &first.proof).unwrap(),
                    &first.oracle,
                );
            }
            let before = cache.counters();
            let result = measured(|| {
                cache.verify(fixture.challenge, fixture.task, [255; 32], &fixture.proof).unwrap()
            });
            let replayed = cache.counters().full_replays - before.full_replays;
            assert_eq!(replayed, u64::from(path != "work_fact_warm"));
            emit(path, fixture, result, replayed == 1);
        }
        for (path, fixture, seed) in [
            ("arithmetic_cold", first, false),
            ("arithmetic_warm", first, true),
            ("arithmetic_changed_challenge", next, true),
        ] {
            let cache = ArithmeticFactCache::new(1).unwrap();
            if seed {
                parity(
                    &cache.verify(first.challenge, first.task, [255; 32], &first.proof).unwrap(),
                    &first.oracle,
                );
            }
            let mut observation = ArithmeticObservation::default();
            let result = measured(|| arithmetic(&cache, fixture, &mut observation));
            let replayed = path != "arithmetic_warm";
            assert_eq!(observation.transcript_completed, replayed);
            assert_eq!(observation.product_completed, replayed);
            assert_eq!(observation.product_reused, !replayed);
            assert_eq!(observation.exact_fact_found, !replayed);
            emit(path, fixture, result, replayed);
        }
    }
    println!("{{\"completed_calls\":24,\"scalar_parity_checks\":24,\"all_submitted_proofs_valid\":true,\"qualification\":\"HOLD\"}}");
}
