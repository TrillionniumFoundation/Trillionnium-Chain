//! Durable metadata around the ORIGINAL scalar interval. No extra CPU debit.
//! Native outcomes are returned by their caller even when metadata fails late.
use crate::ingress::public_v3::{
    ServiceMutationCpuCheckpoint, ServiceMutationCpuDomain, ServiceMutationCpuOperation,
    ServiceMutationCpuSettlement,
};
use crate::operator_continuous_history::{CpuAllowance, FaultSink, Journal};
use crate::operator_task_policy::PolicyError;
use std::sync::{Arc, Mutex};
use trnm_mvcc_fee::pon_executor::ExecutionWorkerAccounting;
type Result<T> = std::result::Result<T, PolicyError>;
pub(crate) struct Start {
    pub scope: String,
    pub operation: String,
    pub linked_startup: Option<String>,
    pub task: String,
    pub class: String,
}
/// Short owner metadata locks end before Native, math or SQLite starts.
/// Workers receive only a separate Send+Sync checkpoint, never the journal.
pub(crate) struct DurableOperation {
    journal: Arc<Mutex<Journal>>,
    sink: Arc<FaultSink>,
    scope: String,
    operation: Option<ServiceMutationCpuOperation>,
    allowance: CpuAllowance,
    finished: bool,
}
#[derive(Clone)]
pub(crate) struct ContinuousCheckpoint {
    cpu: ServiceMutationCpuCheckpoint,
    allowance: CpuAllowance,
}
impl ContinuousCheckpoint {
    pub(crate) fn checkpoint(&self) -> crate::Result<()> {
        self.cpu.checkpoint()?;
        self.allowance
            .checkpoint(self.cpu.actual_live_paid_cpu_ns()?)
            .map_err(|_| crate::Error::from("OWNER_CONTINUOUS_CPU_BUDGET"))
    }
}
pub(crate) struct DurableSettlement {
    pub actual: ServiceMutationCpuSettlement,
    pub accounting_record_persisted: bool,
    pub accounting_fault_persistence_failed: bool,
}
impl DurableOperation {
    pub(crate) fn begin(
        journal: Arc<Mutex<Journal>>,
        cpu: &ServiceMutationCpuDomain,
        start: Start,
        sink: Arc<FaultSink>,
    ) -> Result<Self> {
        let allowance = match (|| -> Result<CpuAllowance> {
            journal
                .lock()
                .map_err(|_| PolicyError::Journal)?
                .cpu_allowance(&start.operation, start.linked_startup.as_deref())
        })() {
            Ok(value) => value,
            Err(error) => {
                sink.persist_unknown()?;
                return Err(error);
            }
        };
        let operation = match cpu.begin() {
            Ok(operation) => operation,
            Err(_) => {
                if !cpu.accounting_available() {
                    sink.persist_unknown()?;
                    return Err(PolicyError::CpuUnknown);
                }
                // The claim remains spent even on a known service-bucket refusal.
                return Err(PolicyError::Budget);
            }
        };
        let initialized = (|| -> Result<()> {
            journal
                .lock()
                .map_err(|_| PolicyError::Journal)?
                .start_cpu(
                    start.scope.clone(),
                    start.operation,
                    start.task,
                    start.class,
                )?;
            if let Some(linked) = start.linked_startup {
                journal
                    .lock()
                    .map_err(|_| PolicyError::Journal)?
                    .link_startup_claim(start.scope.clone(), linked)?;
            }
            Ok(())
        })();
        if let Err(error) = initialized {
            // Real interval already began. Even poisoned-lock initialization
            // retains actual settlement and an independent terminal fault file.
            let _actual = operation.finish();
            sink.persist_unknown()?;
            return Err(error);
        }
        Ok(Self {
            journal,
            sink,
            scope: start.scope,
            operation: Some(operation),
            allowance,
            finished: false,
        })
    }
    pub(crate) fn checkpoint_handle(&self) -> Result<ContinuousCheckpoint> {
        let operation = self.operation.as_ref().ok_or(PolicyError::CpuUnknown)?;
        Ok(ContinuousCheckpoint {
            cpu: operation.checkpoint_handle(),
            allowance: self.allowance.clone(),
        })
    }
    pub(crate) fn worker_accounting(&self) -> Result<&dyn ExecutionWorkerAccounting> {
        self.operation
            .as_ref()
            .map(|v| v.worker_accounting())
            .ok_or(PolicyError::CpuUnknown)
    }
    /// Call only after ALL real worker joins, on the original owner thread.
    /// No postcommit allowance/progress fence rewrites a Native result.
    pub(crate) fn scope(&self) -> &str {
        &self.scope
    }
    pub(crate) fn finish(mut self) -> Result<DurableSettlement> {
        let operation = self.operation.take().ok_or(PolicyError::CpuUnknown)?;
        let actual = operation.finish();
        let published = self
            .journal
            .lock()
            .ok()
            .is_some_and(|mut journal| journal.settle_cpu(self.scope.clone(), &actual).is_ok());
        let persistence_failed = if published {
            false
        } else {
            self.sink.persist_unknown().is_err()
        };
        self.finished = true;
        Ok(DurableSettlement {
            actual,
            accounting_record_persisted: published,
            accounting_fault_persistence_failed: persistence_failed,
        })
    }
}
impl Drop for DurableOperation {
    fn drop(&mut self) {
        if !self.finished {
            // CPU5's unfinished operation Drop latches its actual service epoch.
            // The independent held-FD sink survives initialization/native unwind.
            drop(self.operation.take());
            if self.sink.persist_unknown().is_err() {
                eprintln!("OWNER_CONTINUOUS_CPU_FAULT_PERSISTENCE_FAILED");
            }
        }
    }
}

/// Attached to an ALREADY running original public permit. This object never
/// starts, samples, debits or refunds another scalar CPU interval.
pub(crate) struct ObservedOperation {
    journal: Arc<Mutex<Journal>>,
    sink: Arc<FaultSink>,
    scope: String,
    checkpoint: ContinuousCheckpoint,
    finished: bool,
}
impl ObservedOperation {
    pub(crate) fn begin(
        journal: Arc<Mutex<Journal>>,
        start: Start,
        cpu: ServiceMutationCpuCheckpoint,
        sink: Arc<FaultSink>,
    ) -> Result<Self> {
        // The original public interval ALREADY exists. Any initialization error,
        // including a poisoned lock, must retain a terminal durable unknown.
        let initialized = (|| -> Result<CpuAllowance> {
            let allowance = journal
                .lock()
                .map_err(|_| PolicyError::Journal)?
                .cpu_allowance(&start.operation, start.linked_startup.as_deref())?;
            journal
                .lock()
                .map_err(|_| PolicyError::Journal)?
                .start_cpu(
                    start.scope.clone(),
                    start.operation,
                    start.task,
                    start.class,
                )?;
            if let Some(linked) = start.linked_startup {
                journal
                    .lock()
                    .map_err(|_| PolicyError::Journal)?
                    .link_startup_claim(start.scope.clone(), linked)?;
            }
            Ok(allowance)
        })();
        let allowance = match initialized {
            Ok(value) => value,
            Err(error) => {
                sink.persist_unknown()?;
                return Err(error);
            }
        };
        Ok(Self {
            journal,
            sink,
            scope: start.scope,
            checkpoint: ContinuousCheckpoint { cpu, allowance },
            finished: false,
        })
    }
    pub(crate) fn checkpoint_handle(&self) -> ContinuousCheckpoint {
        self.checkpoint.clone()
    }
    pub(crate) fn finish(mut self, actual: &ServiceMutationCpuSettlement) -> bool {
        let persisted = self
            .journal
            .lock()
            .ok()
            .is_some_and(|mut journal| journal.settle_cpu(self.scope.clone(), actual).is_ok());
        if !persisted && self.sink.persist_unknown().is_err() {
            eprintln!("OWNER_CONTINUOUS_CPU_FAULT_PERSISTENCE_FAILED");
        }
        self.finished = true;
        persisted
    }
}
impl Drop for ObservedOperation {
    fn drop(&mut self) {
        if !self.finished && self.sink.persist_unknown().is_err() {
            eprintln!("OWNER_CONTINUOUS_CPU_FAULT_PERSISTENCE_FAILED");
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "operator_continuous_cpu_tests.rs"]
mod tests;
