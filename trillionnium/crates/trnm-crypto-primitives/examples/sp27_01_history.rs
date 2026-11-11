//! Research-only full-history observations. No node admission or consensus credit.
//! Both retention policies use the same existing sparse preparation, FullLimb
//! transcript, lazy materialization, and single-threaded batch permission.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    fs::{self, File},
    hint::black_box,
    io::{self, Write},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};
use trnm_crypto_primitives::pon_work::{
    self,
    legal_attempt::{Arithmetic, Materialization, Preparation, Progress, Task},
    Hash, VerificationProgress, WorkError, CELLS, N, Q,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
static LIVE: AtomicUsize = AtomicUsize::new(0);
struct CountingAllocator;
// Counts requested live heap bytes, not allocator metadata, RSS or physical DRAM.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            System.dealloc(ptr, layout);
        }
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(ptr, layout, size) };
        if !result.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            LIVE.fetch_add(size, Ordering::Relaxed);
        }
        result
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn cpu() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
        let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
        u64::try_from(t.tv_sec)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(u64::try_from(t.tv_nsec).ok()?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
struct Clock {
    wall: Instant,
    cpu: Option<u64>,
}
impl Clock {
    fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: cpu(),
        }
    }
    fn finish(self) -> Value {
        json!({"wall_ns":self.wall.elapsed().as_nanos() as u64,
               "thread_cpu_ns":self.cpu.and_then(|s|cpu()?.checked_sub(s))})
    }
}
struct Journal {
    seq: u64,
}
impl Journal {
    fn emit(&mut self, mut row: Value) -> Result<()> {
        row["seq"] = self.seq.into();
        row["schema"] = "sp27-01-history-v1".into();
        self.seq += 1;
        let stdout = io::stdout();
        let mut out = stdout.lock();
        serde_json::to_writer(&mut out, &row)?;
        out.write_all(b"\n")?;
        out.flush()?;
        Ok(())
    }
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn matrices(family: &str, seed: u64, variant: u64) -> (Vec<u32>, Vec<u32>) {
    let mut a = Vec::with_capacity(CELLS);
    let mut b = Vec::with_capacity(CELLS);
    for i in 0..CELLS {
        let pair = match family {
            "zero" => (0, 0),
            "rank-one" => (
                ((i / N + 1) as u64 * (i % N + 1) as u64 * (seed + 1)) as u32,
                ((i / N + 2) as u64 * (i % N + 2) as u64 * (seed + 1)) as u32,
            ),
            "sparse" => (
                if i / N == i % N {
                    (i / N + 1) as u32 + seed as u32
                } else {
                    0
                },
                if i / N == i % N {
                    (i / N + 2) as u32 + seed as u32
                } else {
                    0
                },
            ),
            "dense" => {
                let h = pon_work::hash(
                    b"sp27-01-material-v1",
                    &[&seed.to_le_bytes(), &(i as u64).to_le_bytes()],
                );
                (
                    (u64::from_le_bytes(h[..8].try_into().unwrap()) % Q as u64) as u32,
                    (u64::from_le_bytes(h[8..16].try_into().unwrap()) % Q as u64) as u32,
                )
            }
            _ => unreachable!("validated family"),
        };
        a.push(pair.0);
        b.push(pair.1);
    }
    a[0] = ((u64::from(a[0]) + variant) % Q as u64) as u32;
    (a, b)
}
struct Cached {
    task: Task,
    id: Hash,
    heap_bytes: usize,
    retained_since: Instant,
}
fn release(cache: &mut Option<Cached>, j: &mut Journal, reason: &str, session: u64) -> Result<()> {
    if let Some(cached) = cache.take() {
        let life = cached.retained_since.elapsed().as_nanos();
        let bytes = cached.heap_bytes;
        let before = LIVE.load(Ordering::Relaxed);
        let c = Clock::start();
        drop(cached.task);
        let released = before
            .checked_sub(LIVE.load(Ordering::Relaxed))
            .ok_or("task release increased live allocation")?;
        let time = c.finish();
        if released != bytes {
            return Err("task heap allocation/release mismatch".into());
        }
        j.emit(json!({"kind":"release","session":session,"reason":reason,"timing":time,
            "task_heap_bytes":bytes,"heap_bytes_released":released,
            "retained_byte_ns":(bytes as u128*life).to_string(),
            "residency_scope":"task requested heap; includes interleaved verification and observation"}))?;
    }
    Ok(())
}
fn check_controls(task: &Task, id: Hash, j: &mut Journal) -> Result<()> {
    let clock = Clock::start();
    let challenge = pon_work::hash(b"sp27-01-controls-v1", &[&id]);
    let attempt = task
        .attempt(challenge, [255; 32], Materialization::TargetHit)
        .map_err(|e| format!("control generation {e:?}"))?;
    let proof = attempt.proof.ok_or("missing control proof")?;
    let mut other_challenge = challenge;
    other_challenge[0] ^= 1;
    let mut other_task = id;
    other_task[0] ^= 1;
    let mut corrupt = proof.clone();
    corrupt[4 + 8 * CELLS] ^= 1;
    let outcomes = [
        (
            "changed-challenge",
            pon_work::verify_reference(other_challenge, id, [255; 32], &proof).err(),
        ),
        (
            "changed-task",
            pon_work::verify_reference(challenge, other_task, [255; 32], &proof).err(),
        ),
        (
            "changed-product",
            pon_work::verify_reference(challenge, id, [255; 32], &corrupt).err(),
        ),
    ];
    for (name, error) in outcomes {
        if error.is_none() {
            return Err(format!("negative control accepted: {name}").into());
        }
        j.emit(json!({"kind":"negative-control","control":name,"error":format!("{error:?}"),"accepted":false}))?;
    }
    let mut tiles = 0usize;
    let cancelled =
        task.attempt_with_progress(challenge, [255; 32], Materialization::TargetHit, |p| {
            if matches!(
                p,
                Progress::Replay(VerificationProgress::TranscriptTile { .. })
            ) {
                tiles += 1;
                if tiles == 128 {
                    return Err(());
                }
            }
            Ok(())
        });
    if !matches!(cancelled, Err(pon_work::VerificationError::Cancelled(()))) {
        return Err("cancellation failed".into());
    }
    j.emit(json!({"kind":"negative-control","control":"cancel-before-tile-128","observed_tile_callbacks":tiles,"accepted":false}))?;
    let zero = vec![0; CELLS];
    let mut invalid = zero.clone();
    invalid[0] = Q as u32;
    if !matches!(
        Task::with_preparation(&invalid, &zero, Arithmetic::FullLimb, Preparation::Sparse),
        Err(WorkError::Field)
    ) {
        return Err("noncanonical preparation accepted".into());
    }
    j.emit(json!({"kind":"negative-control","control":"noncanonical-input","accepted":false}))?;
    let retry = task
        .attempt(challenge, [255; 32], Materialization::TargetHit)
        .map_err(|e| format!("retry {e:?}"))?;
    if retry.proof.as_deref() != Some(&proof) {
        return Err("cancel poisoned retry".into());
    }
    j.emit(
        json!({"kind":"control-end","timing":clock.finish(),"cancel_retry_equal":true,
        "extra_complete_control_generations":2,"not_workload_attempts":true,"node_credit":0}),
    )?;
    Ok(())
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().ok_or_else(|| format!("missing {k}").into())
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().ok_or_else(|| format!("missing {k}").into())
}
fn run() -> Result<()> {
    let config_path = std::env::args().nth(1).ok_or("one config path required")?;
    let config_bytes = fs::read(&config_path)?;
    let config: Value = serde_json::from_slice(&config_bytes)?;
    let family = string(&config, "family")?;
    let policy = string(&config, "policy")?;
    let scenario = string(&config, "scenario")?;
    let seed = number(&config, "seed")?;
    let cap = number(&config, "cap")?;
    let sessions = number(&config, "sessions")?;
    let base = number(&config, "base_session")?;
    let bits = number(&config, "target_bits")?;
    if !["dense", "zero", "sparse", "rank-one"].contains(&family)
        || !["retain", "reset-session"].contains(&policy)
        || !["steady", "alias", "mutate", "restart"].contains(&scenario)
        || ![1, 8, 32].contains(&cap)
        || sessions > 8
        || sessions == 0
        || seed > 64
        || bits > 7
    {
        return Err("configuration outside declared roster".into());
    }
    let output = PathBuf::from(string(&config, "output_dir")?);
    fs::create_dir_all(output.join("proofs"))?;
    fs::create_dir_all(output.join("delivery"))?;
    let mut target = [255u8; 32];
    target[0] >>= bits;
    let mut j = Journal { seq: 0 };
    j.emit(
        json!({"kind":"process-start","pid":std::process::id(),"config":config,
        "configuration_sha256":digest(&config_bytes),"target":hex::encode(target),
        "kernel":"existing FullLimb","preparation":"existing Sparse","materialization":"TargetHit",
        "node_credit":0,"timings":"diagnostic only; exclusive host not established"}),
    )?;
    let whole = Clock::start();
    let mut cache: Option<Cached> = None;
    let mut attempts = 0u64;
    let mut hits = 0u64;
    let mut preparations = 0u64;
    for local_session in 0..sessions {
        let session = base + local_session;
        j.emit(json!({"kind":"session-start","session":session}))?;
        let acquired = Clock::start();
        let variant = if scenario == "mutate" { session % 2 } else { 0 };
        let (a, b) = matrices(family, seed, variant);
        let id = pon_work::task_id(&a, &b).map_err(|e| format!("task {e:?}"))?;
        let acquisition = acquired.finish();
        let alias = if scenario == "alias" { session } else { 0 };
        j.emit(
            json!({"kind":"acquisition","session":session,"task":hex::encode(id),
            "job_alias":alias,"variant":variant,"matrix_input_bytes":2*CELLS*4,"timing":acquisition,
            "source":"deterministic synthetic recipe; not external demand"}),
        )?;
        if policy == "reset-session" || cache.as_ref().is_some_and(|c| c.id != id) {
            release(
                &mut cache,
                &mut j,
                "session-reset-or-content-change",
                session,
            )?;
        }
        if cache.is_none() {
            j.emit(json!({"kind":"prepare-start","session":session,"task":hex::encode(id)}))?;
            let before = LIVE.load(Ordering::Relaxed);
            let clock = Clock::start();
            let task = Task::with_preparation(&a, &b, Arithmetic::FullLimb, Preparation::Sparse)
                .map_err(|e| format!("prepare {e:?}"))?;
            let bytes = LIVE.load(Ordering::Relaxed) - before;
            let retained_since = Instant::now();
            let timing = clock.finish();
            let stack_bytes = std::mem::size_of::<Task>();
            let prefix_sha = digest(task.proof_prefix());
            cache = Some(Cached {
                task,
                id,
                heap_bytes: bytes,
                retained_since,
            });
            preparations += 1;
            j.emit(
                json!({"kind":"prepare-end","session":session,"task":hex::encode(id),
                "timing":timing,"task_heap_bytes":bytes,"task_inline_bytes":stack_bytes,
                "prefix_sha256":prefix_sha,"preparation_index":preparations}),
            )?;
        } else {
            j.emit(json!({"kind":"cache-hit","session":session,"task":hex::encode(id),"job_alias":alias}))?;
        }
        drop(a);
        drop(b);
        let task = &cache.as_ref().ok_or("cache missing")?.task;
        if local_session == 0 {
            check_controls(task, id, &mut j)?;
        }
        let mut session_hits = 0u64;
        for nonce in 0..cap {
            let challenge = pon_work::hash(
                b"sp27-01-history-challenge-v1",
                &[
                    &id,
                    &seed.to_le_bytes(),
                    &session.to_le_bytes(),
                    &alias.to_le_bytes(),
                    &nonce.to_le_bytes(),
                    &target,
                ],
            );
            j.emit(json!({"kind":"attempt-start","session":session,"nonce":nonce,"challenge":hex::encode(challenge)}))?;
            let clock = Clock::start();
            let mut tiles = 0usize;
            let attempt = black_box(task.attempt_with_progress(
                challenge,
                target,
                Materialization::TargetHit,
                |p| {
                    if matches!(
                        p,
                        Progress::Replay(VerificationProgress::TranscriptTile { .. })
                    ) {
                        tiles += 1;
                    }
                    Ok::<_, ()>(())
                },
            ))
            .map_err(|e| format!("attempt {e:?}"))?;
            let timing = clock.finish();
            attempts += 1;
            if tiles != 512 {
                return Err("incomplete transcript callback roster".into());
            }
            if attempt.target_hit != attempt.proof.is_some() {
                return Err("hit/materialization disagreement".into());
            }
            let proof_hash = attempt.proof.as_ref().map(|p| digest(p));
            j.emit(json!({"kind":"attempt-end","session":session,"nonce":nonce,"task":hex::encode(id),
                "challenge":hex::encode(challenge),"trace":hex::encode(attempt.trace),"ticket":hex::encode(attempt.ticket),
                "hit":attempt.target_hit,"transcript_tiles":tiles,"proof_sha256":proof_hash,"timing":timing,
                "node_credit":0,"target_hit_is_not_node_admission":true}))?;
            if let Some(proof) = attempt.proof {
                if !attempt.target_hit {
                    return Err("lazy miss unexpectedly materialized".into());
                }
                let name = format!("{}-{}-{}.pnw", std::process::id(), session, nonce);
                let delivery = output.join("delivery").join(name);
                let clock = Clock::start();
                let mut f = File::create(&delivery)?;
                f.write_all(&proof)?;
                f.sync_all()?;
                drop(f);
                let output_time = clock.finish();
                let clock = Clock::start();
                let received = fs::read(&delivery)?;
                let read_time = clock.finish();
                let clock = Clock::start();
                let v = pon_work::verify(challenge, id, target, &received)
                    .map_err(|e| format!("verify {e:?}"))?;
                let native_time = clock.finish();
                let clock = Clock::start();
                let r = pon_work::verify_reference(challenge, id, target, &received)
                    .map_err(|e| format!("reference {e:?}"))?;
                let reference_time = clock.finish();
                if v.ticket() != r.ticket() || received != proof {
                    return Err("receiver disagreement".into());
                }
                drop(v);
                drop(r);
                drop(received);
                let clock = Clock::start();
                fs::remove_file(&delivery)?;
                let cleanup_time = clock.finish();
                let sha = proof_hash.ok_or("missing hash")?;
                let artifact = output.join("proofs").join(format!("{sha}.pnw"));
                if !artifact.exists() {
                    fs::write(&artifact, &proof)?;
                }
                hits += 1;
                session_hits += 1;
                j.emit(json!({"kind":"verified-output","session":session,"nonce":nonce,"proof_sha256":sha,
                    "bytes":proof.len(),"output_fsync":output_time,"receiver_read":read_time,
                    "receiver_native_verify":native_time,"receiver_reference_verify":reference_time,
                    "delivery_unlink":cleanup_time,"artifact_copy":"separate retained instrumentation",
                    "eligible_target_weight_proxy":1u64<<bits,"node_credit":0,"monetary_reward":0}))?;
                break;
            }
        }
        j.emit(json!({"kind":"session-end","session":session,"status":if session_hits>0 {"verified-hit"} else {"exhausted"},"node_credit":0}))?;
    }
    release(&mut cache, &mut j, "normal-process-exit", base + sessions)?;
    j.emit(
        json!({"kind":"process-end","attempts":attempts,"hits":hits,"preparations":preparations,
        "sessions":sessions,"timing":whole.finish(),"complete":true,"node_credit":0,
        "whole_scope":"nested inclusive process body; do not add to stage timers"}),
    )?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("SP27_01_INCOMPLETE:{error}");
        std::process::exit(1);
    }
}
