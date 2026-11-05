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
pub(crate) fn search(
    producer: &Producer,
    target: Hash,
    limit: u64,
    challenge: impl Fn(u64) -> Hash,
) -> Result<Search> {
    let mut result = Search {
        attempts: Vec::new(),
        winner: None,
    };
    for nonce in 0..limit {
        let context = challenge(nonce);
        let proof = producer
            .prove(context)
            .map_err(|e| format!("GENERATION:{e:?}"))?;
        if proof.len() != PROOF_BYTES {
            return Err("GENERATED_PROOF_LENGTH".into());
        }
        let trace = &proof[PROOF_BYTES - 32..];
        let ticket = pon_work::hash(b"ticket", &[&context, trace]);
        let hit = ticket <= target;
        result.attempts.push(Trial {
            nonce,
            challenge: hex::encode(context),
            trace: hex::encode(trace),
            ticket: hex::encode(ticket),
            proof_sha256: Some(sha(&proof)),
            target_hit: hit,
        });
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
