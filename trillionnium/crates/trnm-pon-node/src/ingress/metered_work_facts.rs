//! Mandatory shared-domain metering for the explicit local W1 fact path.
//! Reuses the existing owner/M06 worker accounting and never allocates a budget.
use super::public_v3::{ServiceMutationCpuDomain, ServiceMutationCpuSettlement};
use super::{dispatch_shared_with_execution_control, Request};
use crate::{ensure, Node, Result};
use serde_json::Value;
use std::sync::Mutex;
use trnm_crypto_primitives::pon_work::facts::WorkFactCache;
use trnm_mvcc_fee::pon_executor::ExecutionControl;

/// A native outcome and its separate resource settlement. An accounting failure
/// after commit cannot erase that commit or authorize blind redispatch. The shared
/// domain fences future mutation starts when its accounting is unavailable.
#[must_use]
pub struct MeteredWorkFactOutcome {
    pub native: Result<Value>,
    pub cpu: ServiceMutationCpuSettlement,
}

/// Explicit Submit-only native embedding. The caller supplies the SAME domain as
/// its existing public/continuous owner, not a new standalone domain per request.
/// Refusal before a reservation returns Err with no W1/M06/durable work entered.
/// Once reserved, native success/rejection/cancellation always receives a separate
/// complete settlement; all actual scoped M06 workers are joined before settling.
/// Panics retain the existing operation-drop behavior (unknown account, no refund).
/// V2/V3 transport policy and default listeners are unchanged. This function is
/// cooperative CPU accounting, not a kernel limit or a host-global budget owner.
pub fn dispatch_shared_with_metered_work_facts(
    node: &Mutex<Node>,
    request: Request,
    facts: &WorkFactCache,
    domain: &ServiceMutationCpuDomain,
    checkpoint: &(impl Fn() -> Result<()> + Sync),
) -> Result<MeteredWorkFactOutcome> {
    ensure(
        matches!(&request, Request::Submit { .. }),
        "WORK_FACT_SUBMIT_ONLY",
    )?;
    checkpoint()?;
    // Reject a foreign domain at the original Node owner BEFORE reserving or
    // carrying out any W1/M06 work. This is one checked in-memory identity,
    // not another operation journal or permission granted by the CPU meter.
    {
        let mut owner = super::lock_owner(node, &mut |_| checkpoint())?;
        owner.bind_public_service_cpu_domain(domain)?;
    }
    let operation = domain.begin()?;
    let live = operation.checkpoint_handle();
    let checked = || {
        checkpoint()?;
        live.checkpoint()
    };
    let native = dispatch_shared_with_execution_control(
        node,
        request,
        &mut |_| checked(),
        |packet| super::WorkCheckedPacket::verify_with_facts(packet, facts, &mut |_| checked()),
        &ExecutionControl::new(&|_| checked(), operation.worker_accounting()),
    );
    // No `?` on native: even a failed/cancelled call owes its actual CPU tail.
    let cpu = operation.finish();
    Ok(MeteredWorkFactOutcome { native, cpu })
}

/// Plain W1 analogue of the existing metered fact path: external owner supplies
/// the ORIGINAL shared CPU domain. No W1 cache, second node or minted allowance.
/// Both full proof verification and subsequent M06/scoped workers are measured
/// inside the one operation; a failed native result still pays its CPU tail.
/// This is an opt-in native integration seam, not a new public protocol/profile
/// and not a proof that unmetered legacy WAN callers have been eliminated.
pub fn dispatch_shared_with_metered_w1(
    node: &Mutex<Node>,
    request: Request,
    domain: &ServiceMutationCpuDomain,
    checkpoint: &(impl Fn() -> Result<()> + Sync),
) -> Result<MeteredWorkFactOutcome> {
    ensure(
        matches!(&request, Request::Submit { .. }),
        "METERED_W1_SUBMIT_ONLY",
    )?;
    checkpoint()?;
    {
        let mut owner = super::lock_owner(node, &mut |_| checkpoint())?;
        owner.bind_public_service_cpu_domain(domain)?;
    }
    let operation = domain.begin()?;
    let live = operation.checkpoint_handle();
    let checked = || {
        checkpoint()?;
        live.checkpoint()
    };
    let native = dispatch_shared_with_execution_control(
        node,
        request,
        &mut |_| checked(),
        |packet| super::WorkCheckedPacket::verify_with_progress(packet, &mut |_| checked()),
        &ExecutionControl::new(&|_| checked(), operation.worker_accounting()),
    );
    // A local refusal is separate from arithmetic invalidity. Never invent
    // a successful WorkCheckedPacket after an unmetered cancellation or panic.
    let cpu = operation.finish();
    Ok(MeteredWorkFactOutcome { native, cpu })
}
