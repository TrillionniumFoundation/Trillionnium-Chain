//! Shared diagnostic constructors and exact complete-proof search streams.
//! This module grants no consensus, task or resource authority.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{thread, time::Instant};
use trnm_crypto_primitives::pon_work::{
    self,
    blocked_one_zero::BlockedOneZeroRankOnePreparedTask,
    blocked_zero::BlockedZeroPreparedTask,
    blocked_zero_paired::BlockedZeroPairedPreparedTask,
    maintenance_limb::MaintenanceLimbPreparedTask,
    maintenance_periodic::MaintenancePeriodicPreparedTask,
    maintenance_prefix::{MaintenanceIntegerPairedPreparedTask, MaintenancePrefixPreparedTask},
    paired_product::PairedPreparedTask,
    structured::{StructuredPreparedTask, TileKernel, TiledPreparedTask},
    Hash, PreparedTask, WorkError, PROOF_BYTES,
};

pub(crate) type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(crate) const ARMS: [&str; 13] = [
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

pub(crate) struct Clock {
    wall: Instant,
    cpu: Option<u64>,
    owner: thread::ThreadId,
}
impl Clock {
    pub(crate) fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: cpu(),
            owner: thread::current().id(),
        }
    }
    pub(crate) fn finish(self) -> Timing {
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
pub(crate) struct Timing {
    pub(crate) cpu_ns: Option<u64>,
    pub(crate) wall_ns: Option<u64>,
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
pub(crate) fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(crate) fn raw(matrix: &[u32]) -> Vec<u8> {
    matrix.iter().flat_map(|n| n.to_le_bytes()).collect()
}
pub(crate) enum Producer {
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
    pub(crate) fn new(
        index: usize,
        a: &[u32],
        b: &[u32],
    ) -> std::result::Result<Option<Self>, WorkError> {
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
    pub(crate) fn prove(&self, value: Hash) -> std::result::Result<Vec<u8>, WorkError> {
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
pub(crate) struct Trial {
    pub(crate) nonce: u64,
    pub(crate) challenge: String,
    pub(crate) trace: String,
    pub(crate) ticket: String,
    pub(crate) proof_sha256: Option<String>,
    pub(crate) target_hit: bool,
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Winner {
    pub(crate) challenge: Hash,
    pub(crate) proof: Vec<u8>,
}
#[derive(Clone)]
pub(crate) struct Search {
    pub(crate) attempts: Vec<Trial>,
    pub(crate) winner: Option<Winner>,
}
/// A begin observation must commit before native generation starts. Observer
/// failures stop the search; an interrupted begin remains unfinished, not free.
pub(crate) trait SearchObserver {
    const MEASURE_ATTEMPTS: bool = true;
    fn attempt_started(&mut self, _nonce: u64, _challenge: Hash) -> Result<()> {
        Ok(())
    }
    fn attempt_finished(&mut self, _trial: &Trial, _timing: Timing) -> Result<()> {
        Ok(())
    }
    fn attempt_failed(&mut self, _nonce: u64, _reason: &str, _timing: Timing) -> Result<()> {
        Ok(())
    }
}
struct NoObserver;
impl SearchObserver for NoObserver {
    const MEASURE_ATTEMPTS: bool = false;
}

pub(crate) fn search(
    producer: &Producer,
    target: Hash,
    limit: u64,
    challenge: impl Fn(u64) -> Hash,
) -> Result<Search> {
    search_observed(producer, target, limit, challenge, &mut NoObserver)
}

/// The retained search wrapper uses the identical loop and a no-op observer.
/// Timing is local observation only and does not authenticate resource use.
pub(crate) fn search_observed<O: SearchObserver>(
    producer: &Producer,
    target: Hash,
    limit: u64,
    challenge: impl Fn(u64) -> Hash,
    observer: &mut O,
) -> Result<Search> {
    search_with_prover(
        |context| producer.prove(context),
        target,
        limit,
        challenge,
        observer,
    )
}

fn search_with_prover<O: SearchObserver>(
    mut prove: impl FnMut(Hash) -> std::result::Result<Vec<u8>, WorkError>,
    target: Hash,
    limit: u64,
    challenge: impl Fn(u64) -> Hash,
    observer: &mut O,
) -> Result<Search> {
    let mut result = Search {
        attempts: Vec::new(),
        winner: None,
    };
    for nonce in 0..limit {
        let context = challenge(nonce);
        // No proof work may start unless the observer has accepted this begin.
        observer.attempt_started(nonce, context)?;
        // The historical no-op wrapper adds no per-attempt clock sampling.
        let started = O::MEASURE_ATTEMPTS.then(Clock::start);
        let proof = match prove(context) {
            Ok(proof) => proof,
            Err(error) => {
                let reason = format!("GENERATION:{error:?}");
                observer.attempt_failed(nonce, &reason, finish_attempt(started))?;
                return Err(reason.into());
            }
        };
        if proof.len() != PROOF_BYTES {
            observer.attempt_failed(nonce, "GENERATED_PROOF_LENGTH", finish_attempt(started))?;
            return Err("GENERATED_PROOF_LENGTH".into());
        }
        let trace = &proof[PROOF_BYTES - 32..];
        let ticket = pon_work::hash(b"ticket", &[&context, trace]);
        let hit = ticket <= target;
        let trial = Trial {
            nonce,
            challenge: hex::encode(context),
            trace: hex::encode(trace),
            ticket: hex::encode(ticket),
            proof_sha256: Some(sha(&proof)),
            target_hit: hit,
        };
        observer.attempt_finished(&trial, finish_attempt(started))?;
        result.attempts.push(trial);
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

fn finish_attempt(started: Option<Clock>) -> Timing {
    started.map_or(
        Timing {
            cpu_ns: None,
            wall_ns: None,
        },
        Clock::finish,
    )
}

#[cfg(test)]
mod observed_search_tests {
    use super::*;
    use std::cell::Cell;

    #[derive(Default)]
    struct Observed {
        events: Vec<String>,
        refuse_start: bool,
        refuse_finish: bool,
    }
    impl SearchObserver for Observed {
        fn attempt_started(&mut self, nonce: u64, _: Hash) -> Result<()> {
            self.events.push(format!("start:{nonce}"));
            if self.refuse_start {
                Err("OBSERVER_START_REFUSED".into())
            } else {
                Ok(())
            }
        }
        fn attempt_finished(&mut self, trial: &Trial, _: Timing) -> Result<()> {
            self.events.push(format!("finish:{}", trial.nonce));
            if self.refuse_finish {
                Err("OBSERVER_FINISH_REFUSED".into())
            } else {
                Ok(())
            }
        }
        fn attempt_failed(&mut self, nonce: u64, reason: &str, _: Timing) -> Result<()> {
            self.events.push(format!("error:{nonce}:{reason}"));
            Ok(())
        }
    }

    #[test]
    fn observer_begin_refusal_precedes_native_generation() {
        let calls = Cell::new(0);
        let mut observer = Observed {
            refuse_start: true,
            ..Observed::default()
        };
        let result = search_with_prover(
            |_| {
                calls.set(calls.get() + 1);
                Err(WorkError::Length)
            },
            [0; 32],
            2,
            |_| [7; 32],
            &mut observer,
        );
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
        assert_eq!(observer.events, ["start:0"]);
    }

    #[test]
    fn native_failure_retains_completed_attempt_and_failed_begin() {
        let zero = vec![0; pon_work::CELLS];
        let prepared = Producer::new(7, &zero, &zero).unwrap().unwrap();
        let mut calls = 0;
        let mut observer = Observed::default();
        let result = search_with_prover(
            |context| {
                calls += 1;
                if calls == 2 {
                    Err(WorkError::NoiseBudget)
                } else {
                    prepared.prove(context)
                }
            },
            [0; 32],
            4,
            |nonce| pon_work::hash(b"observer-failure-control-v4", &[&nonce.to_le_bytes()]),
            &mut observer,
        );
        assert!(result.is_err());
        assert_eq!(calls, 2);
        assert_eq!(
            observer.events,
            [
                "start:0",
                "finish:0",
                "start:1",
                "error:1:GENERATION:NoiseBudget"
            ]
        );
    }

    #[test]
    fn malformed_generated_proof_has_started_and_failed_record() {
        let mut observer = Observed::default();
        let result =
            search_with_prover(|_| Ok(Vec::new()), [255; 32], 1, |_| [7; 32], &mut observer);
        assert!(result.is_err());
        assert_eq!(
            observer.events,
            ["start:0", "error:0:GENERATED_PROOF_LENGTH"]
        );
    }

    #[test]
    fn completion_observer_failure_never_starts_another_attempt() {
        let zero = vec![0; pon_work::CELLS];
        let prepared = Producer::new(7, &zero, &zero).unwrap().unwrap();
        let mut observer = Observed {
            refuse_finish: true,
            ..Observed::default()
        };
        let result = search_observed(&prepared, [0; 32], 4, |_| [19; 32], &mut observer);
        assert!(result.is_err());
        assert_eq!(observer.events, ["start:0", "finish:0"]);
    }

    #[test]
    fn complete_observed_stream_matches_retained_wrapper_byte_for_byte() {
        let zero = vec![0; pon_work::CELLS];
        let prepared = Producer::new(7, &zero, &zero).unwrap().unwrap();
        for target in [[0; 32], [255; 32]] {
            let challenges =
                |nonce: u64| pon_work::hash(b"observer-stream-control-v4", &[&nonce.to_le_bytes()]);
            let ordinary = search(&prepared, target, 3, challenges).unwrap();
            let mut observer = Observed::default();
            let observed =
                search_observed(&prepared, target, 3, challenges, &mut observer).unwrap();
            assert_eq!(ordinary.attempts, observed.attempts);
            assert!(ordinary.winner == observed.winner);
            assert_eq!(observer.events.len(), 2 * observed.attempts.len());
            for (nonce, pair) in observer.events.chunks_exact(2).enumerate() {
                assert_eq!(pair, [format!("start:{nonce}"), format!("finish:{nonce}")]);
            }
        }
    }
}
