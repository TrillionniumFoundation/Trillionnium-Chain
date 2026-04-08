use crate::types::{RlAdvice, RlAdviceContext};

pub(crate) trait RlAdvisor {
    fn advise(&self, ctx: &RlAdviceContext) -> Option<RlAdvice>;
}

struct DisabledRlAdvisor;

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

pub(crate) fn build_rl_advisor(shadow: bool, topk: usize) -> Box<dyn RlAdvisor> {
    if shadow {
        Box::new(ShadowOnlyRlAdvisor { topk })
    } else {
        Box::new(DisabledRlAdvisor)
    }
}
