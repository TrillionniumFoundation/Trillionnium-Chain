//! Public development intake: resource tickets confer no ledger/source authority.
//! Explicit development profile. No guest identity/replay row is persisted.
//! Pool writes are exact signed transaction facts, under the existing shared Node owner.
//! V2 retains separate signed domains; both select the current derived-index resource bound.
//! Work and bounded M06 transaction boundaries check cancellation; deep State/root/history/SQLite are not preempted.
use super::{
    digest, elapsed_ns, ensure, hash, lock_owner, DevelopmentIdentity, Node,
    Request as NativeRequest, Result, Settings, WorkCheckedPacket,
};
mod authentication_cpu;
pub use authentication_cpu::ClassicalAuthenticationCpuObservation;
#[cfg(test)]
mod input_decode_tests;
mod intake;
mod pq_identity;
use intake::{ConnectionLease, ListenerIntake};
pub use pq_identity::{
    call_public_history_pq_v4, PqAuthenticationCpuObservation, PqPublicIdentity, PQ_HISTORY_PROFILE,
};
use pq_identity::{Caller, ServerPin, SigningIdentity};
mod growth;
mod history_response;
pub(super) mod request_observation;
pub mod scalar_cpu;
mod work_arithmetic;
mod work_rejection;
use growth::ClientProfile;
pub use growth::{call_public_protected_growth_v1, GROWTH_PROFILE};
pub use request_observation::{
    ApplicationFrameBytes, ApplicationFramePhase, PublicCpuSettlementObservation,
    PublicRequestObservation, PublicRequestObservationSnapshot, PublicRequestObserver, SubmitPhase,
    SubmitPhaseObservation, MAX_REQUEST_OBSERVATION_RECORDS,
};
use request_observation::{ConnectionObservation, TaskObservation, ThreadCpuStamp};
#[cfg(test)]
use scalar_cpu::ScopedWorkerInterval;
use scalar_cpu::{
    LiveRequestCpu, PaidMutationCpuBudget, ScopedWorkerCpu, MUTATION_CPU_BURST_NS,
    MUTATION_CPU_REFILL_NS_PER_SECOND, MUTATION_CPU_START_RESERVE_NS, MUTATION_CPU_WORKERS,
};
pub use scalar_cpu::{
    ServiceCompletionWorkObservation, ServiceMutationCpuCheckpoint, ServiceMutationCpuDomain,
    ServiceMutationCpuOperation, ServiceMutationCpuSettlement,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, TryRecvError, TrySendError},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::verify_hex_strict;
use trnm_mvcc_fee::pon_executor::{ExecutionControl, ExecutionWorkerAccounting};
use trnm_protocol::pon_wire::Hash;
pub use work_arithmetic::{
    call_public_protected_v3_with_arithmetic_facts, PublicArithmeticFactObservation,
    PublicArithmeticWorkObservation,
};
pub use work_rejection::{PublicRejectionFactObservation, PublicRejectionWorkObservation};

/// Fresh signed/wire successor. V2 remains a separate unchanged byte contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Submit {
        packet: String,
    },
    Head,
    History {
        tip: String,
        after: String,
    },
    PoolSubmitBundle {
        pool_context: String,
        transactions: Vec<String>,
    },
    PoolStatus,
    GrowthSubmitV1 {
        packet: String,
    },
    GrowthPacketStatusV1 {
        packet: String,
    },
    GrowthHeadV1,
}
pub const PROFILE: &str = "public-protected-development-v3";
const HELLO_BYTES: usize = 108;
const SOLUTION_BYTES: usize = 108;
const MAX_PACKET: usize = 1_048_576;
const MAX_BODY: usize = 2 * MAX_PACKET + 64;
const MAX_READ_BODY: usize = 512;
const MIN_POOL_RAW: usize = 159;
const MAX_POOL_RAW: usize = 2048;
const MAX_POOL_MEMBERS: usize = 16;
const MAX_POOL_BUNDLE_BYTES: usize = MAX_POOL_RAW * MAX_POOL_MEMBERS;
const MAX_POOL_BODY: usize = MAX_POOL_BUNDLE_BYTES * 2 + 512;
const MAX_SERVICE_SECONDS: u64 = 72 * 3600;
const MAX_RESPONSE: usize = 2 * MAX_PACKET + 4096;
const MAX_CONNECTIONS: usize = 64;
// Each active V3 listener starts three worker threads and bounded proof/read
// channels; cap aggregate count per already-pinned Node service domain.
const MAX_LISTENERS_PER_CPU_DOMAIN: usize = 4;
const MAX_PAID_BODY_BYTES: usize = 8 * 1024 * 1024;
// Reservations partition the existing totals; they add no socket/worker/queue.
const READ_BODY_RESERVE: usize = 128 * 1024;
const CONTROL_OUTPUT_RESERVE: usize = 512 * 1024;
const MAX_MUTATING_GRANTS: usize = 8;
const MAX_READ_GRANTS: usize = 8;
const MAX_SPENT: usize = 1024;
const MAX_HISTORY_STEPS: u64 = 1024;
const PREFIX_MS: u64 = 2000;
const CHALLENGE_MS: u64 = 2000;
const BODY_MS: u64 = 5000;
const OVERALL_MS: u64 = 30000;
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const OUTPUT_MS: u64 = 5000;
const WORK_MS: u64 = 10_000;
const CHALLENGES_PER_SECOND: u64 = 128;
const CHALLENGE_BURST: u64 = 32;
const READ_CHALLENGE_RESERVE: u64 = 8;
const IO_QUANTUM: usize = 64 * 1024;
#[derive(Default)]
struct MutationCpuMeasurement {
    full_work_ns: Cell<Option<u64>>,
    body_decode_ns: Cell<Option<u64>>,
    response_ns: Cell<Option<u64>>,
    unavailable: Cell<bool>,
    workers: ScopedWorkerCpu,
    continuous_scope: RefCell<Option<crate::store::PublicContinuousScope>>,
}
impl MutationCpuMeasurement {
    fn for_permit(permit: Option<&PaidMutationCpuPermit>) -> Self {
        Self {
            workers: ScopedWorkerCpu {
                budget: permit.map(|permit| permit.budget.clone()),
                live: permit.map(|permit| permit.live.clone()),
                ..ScopedWorkerCpu::default()
            },
            ..Self::default()
        }
    }

    fn record_phase(&self, phase: &Cell<Option<u64>>, cpu: Option<u64>) {
        phase.set(cpu);
        if cpu.is_none() {
            self.unavailable.set(true);
            self.workers.unknown();
        }
    }
}
struct PaidMutationCpuPermit {
    budget: Arc<Mutex<PaidMutationCpuBudget>>,
    stamp: Option<ThreadCpuStamp>,
    live: Arc<LiveRequestCpu>,
    settled: bool,
}
impl PaidMutationCpuPermit {
    /// Keep this task's position in the existing mutation queue while waiting
    /// for the original shared epoch to refill. The caller holds only the
    /// dequeue-order lock, never the Node, CPU account, socket reactor or read
    /// queue. No new queue, reservation, caller preference or deadline is made.
    fn acquire_before(
        server: &PublicServer,
        metrics: &Mutex<PublicMetrics>,
        deadline: Instant,
        stop: &AtomicBool,
        cancelled: &AtomicBool,
    ) -> Result<Self> {
        loop {
            task_alive(deadline, stop, cancelled)?;
            let now = Instant::now();
            let mut budget = server
                .mutation_cpu
                .lock()
                .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
            budget.refill(now);
            let shortage = i128::from(MUTATION_CPU_START_RESERVE_NS)
                .saturating_sub(budget.credit_ns)
                .max(0);
            let remaining = deadline.saturating_duration_since(now).as_nanos();
            let possible_refill = remaining
                .saturating_mul(u128::from(MUTATION_CPU_REFILL_NS_PER_SECOND))
                / 1_000_000_000;
            let retry = !budget.unavailable
                && (budget.completion_pending()
                    || budget.in_flight >= MUTATION_CPU_WORKERS || shortage > 0)
                // With no live reservation to return, an impossible refill
                // should retain the original immediate budget refusal.
                && (budget.in_flight > 0 || shortage as u128 <= possible_refill);
            if retry {
                drop(budget);
                thread::sleep(
                    Duration::from_millis(1).min(deadline.saturating_duration_since(now)),
                );
                continue;
            }

            // Linearize readiness and ownership of the just-refilled start
            // reserve under one shared-account lock. Otherwise another active
            // mutation worker can consume that credit after this FIFO task
            // decides it is ready but before Self::acquire locks the account.
            // The lock is released before any native verification/dispatch.
            task_alive(deadline, stop, cancelled)?;
            let stamp = ThreadCpuStamp::start();
            #[cfg(test)]
            let stamp = if server.fail_next_cpu_start.swap(false, Ordering::AcqRel) {
                None
            } else {
                stamp
            };
            if stamp.is_none() {
                budget.unavailable = true;
            }
            let result = budget.reserve(now);
            drop(budget);
            if let Ok(mut m) = metrics.lock() {
                if result.is_err() {
                    m.mutation_cpu_refusals += 1;
                    m.mutation_cpu_clock_failures += u64::from(stamp.is_none());
                } else {
                    m.mutation_cpu_reservations += 1;
                }
            }
            result?;
            let owner = stamp
                .as_ref()
                .ok_or("PUBLIC_MUTATION_CPU_UNAVAILABLE")?
                .clone();
            return Ok(Self {
                budget: server.mutation_cpu.clone(),
                stamp,
                live: Arc::new(LiveRequestCpu::new(server.mutation_cpu.clone(), owner)),
                settled: false,
            });
        }
    }

    #[cfg(test)]
    fn acquire(server: &PublicServer, metrics: &Mutex<PublicMetrics>) -> Result<Self> {
        let stamp = ThreadCpuStamp::start();
        #[cfg(test)]
        let stamp = if server.fail_next_cpu_start.swap(false, Ordering::AcqRel) {
            None
        } else {
            stamp
        };
        let mut budget = server
            .mutation_cpu
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        if stamp.is_none() {
            budget.unavailable = true;
        }
        let result = budget.reserve(Instant::now());
        drop(budget);
        if let Ok(mut m) = metrics.lock() {
            if result.is_err() {
                m.mutation_cpu_refusals += 1;
                m.mutation_cpu_clock_failures += u64::from(stamp.is_none());
            } else {
                m.mutation_cpu_reservations += 1;
            }
        }
        result?;
        // reserve refused a missing start clock, so this is a real owner stamp.
        let owner = stamp
            .as_ref()
            .ok_or("PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .clone();
