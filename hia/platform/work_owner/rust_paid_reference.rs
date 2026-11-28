// Private cfg(test) observation of complete original service-account methods.
use super::*;
use serde_json::{json,Value};

#[derive(Clone)]
pub(crate) struct Domain(ServiceMutationCpuDomain);
pub(crate) struct Operation(Option<ServiceMutationCpuOperation>);
#[derive(Clone)]
pub(crate) struct Live(Arc<LiveRequestCpu>);

impl Domain {
    pub(crate) fn new() -> Self { Self(ServiceMutationCpuDomain::standalone()) }
    pub(crate) fn begin(&self) -> crate::Result<Operation> { self.0.begin().map(|v|Operation(Some(v))) }
    pub(crate) fn snapshot(&self) -> Value {
        let poisoned=self.0.budget.is_poisoned();
        let b=self.0.budget.lock().unwrap_or_else(|error|error.into_inner());
        json!({"poisoned":poisoned,"unavailable":b.unavailable,"in_flight":b.in_flight,
          "credit_ns":b.credit_ns.to_string(),"termination_reserved_ns":b.termination_reserved_ns,
          "verified_completions":b.verified_completions,
          "flow":b.flow.as_ref().map(|f|json!({
            "initial_credit_ns":f.initial_credit_ns.to_string(),
            "credited_refill_ns":f.credited_refill_ns,"discarded_refill_ns":f.discarded_refill_ns,
            "booked_reservation_ns":f.booked_reservation_ns,"live_debited_cpu_ns":f.live_debited_cpu_ns,
            "settlement_residual_cpu_ns":f.settlement_residual_cpu_ns,
            "settled_full_cpu_ns":f.settled_full_cpu_ns,"settlement_discard_ns":f.settlement_discard_ns}))})
    }
}
impl Operation {
    pub(crate) fn checkpoint(&self) -> crate::Result<()> { self.0.as_ref().unwrap().checkpoint() }
    pub(crate) fn live(&self) -> Live { Live(self.0.as_ref().unwrap().live.clone()) }
    pub(crate) fn finish(mut self) -> Value {
        serde_json::to_value(self.0.take().unwrap().finish()).expect("complete original settlement")
    }
}
// The Option owns the original operation. On panic it performs that original
// Drop, in Rust's actual unwind order; no copied settlement algorithm is used.
impl Live {
    pub(crate) fn snapshot(&self) -> Value {
        let poisoned=self.0.state.is_poisoned();
        let s=self.0.state.lock().unwrap_or_else(|error|error.into_inner());
        json!({"poisoned":poisoned,"unavailable":s.unavailable,"refused":s.refused,
          "charged_ns":s.charged_ns,"registered_threads":s.threads.len(),
          "termination_reserved":s.termination_reserved})
    }
}
