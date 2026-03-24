use super::*;

/// DA layer output consumed by ordering/consensus.
#[derive(Debug, Clone)]
pub(crate) struct DaBatch {
    pub(crate) tx_ids: Vec<u64>,
}

/// Ordering result passed into commit loop.
#[derive(Debug, Clone)]
pub(crate) struct OrderingDecision {
    pub(crate) ordered_ids: Vec<u64>,
    pub(crate) rejected: u64,
    pub(crate) preexec_elapsed_ms: u128,
    pub(crate) group_count: usize,
    pub(crate) critical_wait_blocks: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct RlAdviceContext {
    pub(crate) height: u64,
    pub(crate) ordered_ids: Vec<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct RlAdvice {
    pub(crate) suggested_ids: Vec<u64>,
    pub(crate) reason: &'static str,
}

pub(crate) trait DaProvider {
    fn batch_from_picked(&self, picked: &[MockTx]) -> DaBatch;
}

pub(crate) struct LegacyMempoolDaProvider;

impl DaProvider for LegacyMempoolDaProvider {
    fn batch_from_picked(&self, picked: &[MockTx]) -> DaBatch {
        DaBatch {
            tx_ids: (1..=(picked.len() as u64)).collect(),
        }
    }
}

pub(crate) trait OrderingEngine {
    fn decide(
        &self,
        snapshot: &StateStore,
        picked: &[MockTx],
        da_batch: &DaBatch,
        workers: usize,
        candidate_height: u64,
    ) -> OrderingDecision;
}

pub(crate) struct PreexecOrderingEngine;

impl OrderingEngine for PreexecOrderingEngine {
    fn decide(
        &self,
        snapshot: &StateStore,
        picked: &[MockTx],
        da_batch: &DaBatch,
        workers: usize,
        candidate_height: u64,
    ) -> OrderingDecision {
        let pool = PreExecPool::new(
            Arc::new(snapshot.clone()),
            Arc::new(picked.to_vec()),
            workers,
            candidate_height,
        );
        let preexec_started = Instant::now();
        let (ordered_ids, rejected) = pre_execute_group_parallel(&pool, da_batch.tx_ids.clone());
        OrderingDecision {
            ordered_ids,
            rejected,
            preexec_elapsed_ms: preexec_started.elapsed().as_millis(),
            group_count: usize::from(!da_batch.tx_ids.is_empty()),
            critical_wait_blocks: 0,
        }
    }
}

pub(crate) trait RlAdvisor {
    fn advise(&self, ctx: &RlAdviceContext) -> Option<RlAdvice>;
}

pub(crate) struct DisabledRlAdvisor;

impl RlAdvisor for DisabledRlAdvisor {
    fn advise(&self, _ctx: &RlAdviceContext) -> Option<RlAdvice> {
        None
    }
}

/// Shadow-only advisor: emits recommendation logs but never mutates commit ordering.
pub(crate) struct ShadowOnlyRlAdvisor {
    pub(crate) topk: usize,
}

impl RlAdvisor for ShadowOnlyRlAdvisor {
    fn advise(&self, ctx: &RlAdviceContext) -> Option<RlAdvice> {
        if ctx.ordered_ids.is_empty() {
            return None;
        }
        let mut suggested = ctx.ordered_ids.clone();
        suggested.reverse();
        suggested.truncate(self.topk.max(1));
        let _ = ctx.height;
        Some(RlAdvice {
            suggested_ids: suggested,
            reason: "shadow_reverse_baseline",
        })
    }
}
