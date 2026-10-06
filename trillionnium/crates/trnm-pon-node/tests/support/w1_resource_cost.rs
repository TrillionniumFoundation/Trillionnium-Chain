//! Test-only CPU accounting and the retained eight-arm maintenance comparison.
//! A fastest observed sample is not a cheapest-adversary or hardness bound.
use serde_json::{json, Value};
use std::{thread, time::Instant};
use trnm_crypto_primitives::pon_work::{
    maintenance_limb::MaintenanceLimbPreparedTask,
    maintenance_periodic::MaintenancePeriodicPreparedTask,
    maintenance_prefix::{MaintenanceIntegerPairedPreparedTask, MaintenancePrefixPreparedTask},
    paired_product::PairedPreparedTask,
    structured::{TileKernel, TiledPreparedTask},
    PreparedTask, WorkError,
};
use trnm_pon_node::Packet;
use trnm_protocol::pon_wire::{hash, Hash};

fn cpu_now() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
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
    {
        None
    }
}

pub struct Span {
    wall: Instant,
    thread: thread::ThreadId,
    cpu: Option<u64>,
}
impl Span {
    pub fn start() -> Self {
        Self {
            wall: Instant::now(),
            thread: thread::current().id(),
            cpu: cpu_now(),
        }
    }
    pub fn finish(self) -> Value {
        let same_thread = self.thread == thread::current().id();
        let cpu = if same_thread {
            self.cpu
                .zip(cpu_now())
                .and_then(|(start, end)| end.checked_sub(start))
        } else {
            None
        };
        json!({
            "wall_ns": u64::try_from(self.wall.elapsed().as_nanos()).ok(),
            "thread_cpu_ns": cpu, "same_thread": same_thread,
            "cpu_unknown": cpu.is_none(),
            "clock": "CLOCK_THREAD_CPUTIME_ID; calling thread only",
        })
    }
}

type Producer = Box<dyn Fn(Hash) -> Result<Vec<u8>, WorkError>>;
const NAMES: [&str; 8] = [
    "prepared-generic",
    "tiled-classical",
    "tiled-strassen-one-level",
    "paired-product",
    "maintenance-periodic-setup",
    "maintenance-integer-paired",
    "maintenance-periodic-prefix",
    "maintenance-split-limb",
];
fn prepare(index: usize, a: &[u32], b: &[u32]) -> Result<Producer, WorkError> {
    Ok(match index {
        0 => {
            let task = PreparedTask::new(a, b)?;
            Box::new(move |challenge| task.prove(challenge))
        }
        1 | 2 => {
            let kernel = if index == 1 {
                TileKernel::Classical
            } else {
                TileKernel::StrassenOneLevel
            };
            let task = TiledPreparedTask::new(a, b, kernel)?;
            Box::new(move |challenge| task.prove(challenge))
        }
        3 => {
            let task = PairedPreparedTask::new(a, b)?;
            Box::new(move |challenge| task.prove(challenge))
        }
        4 => {
            let task = MaintenancePeriodicPreparedTask::new(a, b)?.ok_or(WorkError::Task)?;
            Box::new(move |challenge| task.prove(challenge))
        }
        5 => {
            let task = MaintenanceIntegerPairedPreparedTask::new(a, b)?.ok_or(WorkError::Task)?;
            Box::new(move |challenge| task.prove(challenge))
        }
        6 => {
            let task = MaintenancePrefixPreparedTask::new(a, b)?.ok_or(WorkError::Task)?;
            Box::new(move |challenge| task.prove(challenge))
        }
        7 => {
            let task = MaintenanceLimbPreparedTask::new(a, b)?.ok_or(WorkError::Task)?;
            Box::new(move |challenge| task.prove(challenge))
        }
        _ => return Err(WorkError::Task),
    })
}

pub struct Roster {
    reused: Vec<Option<Producer>>,
    task: Option<Hash>,
}
impl Roster {
    pub fn new() -> Self {
        Self {
            reused: (0..NAMES.len()).map(|_| None).collect(),
            task: None,
        }
    }
    pub fn compare(&mut self, packet: &Packet, phase: u64, a: &[u32], b: &[u32]) -> Value {
        let complete = Span::start();
        let task = trnm_crypto_primitives::pon_work::task_id(a, b).unwrap();
        // Do not reuse a prepared task on a different material or hide oversized
        // searches. The selected native constructor searches nonce 0..4096.
        if packet.header.work_task != task
            || self.task.is_some_and(|original| original != task)
            || packet.header.nonce >= 4096
        {
            return json!({"all_equal": false, "error": "MATERIAL_OR_NONCE", "rows": []});
        }
        self.task = Some(task);
        let mut rows = Vec::new();
        let mut order: Vec<_> = (0..NAMES.len()).collect();
        if !phase.is_multiple_of(2) {
            order.reverse();
        }
        let modes = if phase.is_multiple_of(2) {
            [false, true]
        } else {
            [true, false]
        };
        for index in order {
            for reused in modes {
                let total = Span::start();
                let setup = Span::start();
                let setup_calls = usize::from(!reused || self.reused[index].is_none());
                let prepared = if setup_calls == 1 {
                    prepare(index, a, b).map(Some)
                } else {
                    Ok(None)
                };
                let setup_resources = setup.finish();
                let mut local = match prepared {
                    Ok(value) => value,
                    Err(error) => {
                        rows.push(json!({"producer": NAMES[index], "reused": reused,
                            "error": format!("{error:?}"), "setup_calls": setup_calls,
                            "setup_resources": setup_resources, "resources": total.finish(),
                            "equal_native_packet": false}));
                        continue;
                    }
                };
                if reused && local.is_some() {
                    self.reused[index] = local.take();
                }
                let producer = if reused {
                    self.reused[index].as_ref().unwrap()
                } else {
                    local.as_ref().unwrap()
                };
                let search = Span::start();
                let mut trials = Vec::new();
                let mut found = None;
                let mut error = None;
                // Reproduce the complete first-winner search, including every
                // preceding miss, for this exact actually admitted native header.
                for nonce in 0..=packet.header.nonce {
                    let mut header = packet.header.clone();
                    header.nonce = nonce;
                    let challenge = header.challenge();
                    let proof = match producer(challenge) {
                        Ok(proof) => proof,
                        Err(failure) => {
                            error = Some(format!("{failure:?}"));
                            break;
                        }
                    };
                    let ticket = hash(b"ticket", &[&challenge, &proof[proof.len() - 32..]]);
                    let hit = ticket <= header.target;
                    trials.push(json!({"nonce": nonce, "challenge": hex::encode(challenge),
                        "ticket": hex::encode(ticket), "target_hit": hit,
                        "proof_digest": hex::encode(hash(b"full-proof", &[&proof]))}));
                    if hit {
                        found = Some(Packet {
                            header,
                            transactions: packet.transactions.clone(),
                            proof,
                        });
                        break;
                    }
                }
                let search_resources = search.finish();
                let encoding = Span::start();
                let encoded = found.as_ref().map(|value| value.encode().unwrap());
                let encoding_resources = encoding.finish();
                // Constructor, full search, all misses, and packet encoding are
                // inside total. Independent verification below is a separate cost.
                let resources = total.finish();
                let check = Span::start();
                let verified = found.as_ref().is_some_and(|value| {
                    trnm_crypto_primitives::pon_work::verify(
                        value.header.challenge(),
                        task,
                        value.header.target,
                        &value.proof,
                    )
                    .is_ok()
                });
                let verifier_resources = check.finish();
                let equal = encoded.as_deref() == Some(packet.encode().unwrap().as_slice());
                rows.push(json!({"producer": NAMES[index], "reused": reused,
                    "setup_calls": setup_calls, "setup_resources": setup_resources,
                    "search_resources": search_resources, "encoding_resources": encoding_resources,
                    "resources": resources, "verifier_resources": verifier_resources,
                    "search_budget": packet.header.nonce + 1, "trials": trials,
                    "winner_packet": encoded.map(hex::encode), "error": error,
                    "equal_native_packet": equal && verified}));
            }
        }
        let all_equal = rows.len() == 16
            && rows.iter().all(|row| {
                row["equal_native_packet"] == true
                    && row["resources"]["thread_cpu_ns"].as_u64().is_some()
            });
        json!({"schema": "w1-eight-producer-cpu-v1", "phase": phase, "rows": rows,
            "all_equal": all_equal, "complete_resources": complete.finish(),
            "comparison_scope": "same actual header, A/B, target and complete first-winner nonce stream; all eight cold/reused constructors; phases reverse invocation order",
            "header_generation_included_in_arm": false,
            "header_generation_retained_separately": true,
            "comparison_inside_concurrent_service_interval": false,
            "universal_cheapest_producer_claim": false,
            "maintenance_compute_qualification": false})
    }
}

#[test]
fn cpu_span_cannot_cross_threads_or_turn_unknown_into_zero() {
    let span = Span::start();
    let cross_thread = thread::spawn(move || span.finish()).join().unwrap();
    assert_eq!(cross_thread["same_thread"], false);
    assert!(cross_thread["thread_cpu_ns"].is_null());
    let mut unknown = Span::start();
    unknown.cpu = None;
    assert!(unknown.finish()["thread_cpu_ns"].is_null());
    let mut reversed = Span::start();
    reversed.cpu = Some(u64::MAX);
    assert!(reversed.finish()["thread_cpu_ns"].is_null());
}
