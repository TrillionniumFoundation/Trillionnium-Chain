use crate::adapter_parse::context_matches_token;
use crate::state::MessageIngressRecord;
use crate::{RC_DUPLICATE, RC_NONCE_REJECTED, RC_SLO_VIOLATION};

use super::{AdapterError, AdapterErrorKind, ReputationSignal};

pub(crate) fn is_deterministic_rejection(rc: i32) -> bool {
    matches!(rc, RC_DUPLICATE | RC_NONCE_REJECTED | RC_SLO_VIOLATION)
}

pub(crate) fn is_idempotent_duplicate_ok(rc: i32) -> bool {
    rc == RC_DUPLICATE
}

pub(crate) fn classify_adapter_error(err: &AdapterError) -> (&'static str, &'static str) {
    if context_matches_token(&err.context, "proof-missing")
        || context_matches_token(&err.context, "missing-provider-request-id")
    {
        return ("ERR_M2V2_PROOF_MISSING", "proof_missing");
    }
    if context_matches_token(&err.context, "proof-invalid")
        || context_matches_token(&err.context, "missing-adapter-label")
        || context_matches_token(&err.context, "no-json-line")
        || context_matches_token(&err.context, "invalid-json")
    {
        return ("ERR_M2V2_PROOF_INVALID", "proof_invalid");
    }
    if context_matches_token(&err.context, "settlement-degraded") {
        return ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded");
    }
    if context_matches_token(&err.context, "proof-late")
        || context_matches_token(&err.context, "timeout")
    {
        return ("ERR_M2V2_PROOF_LATE", "proof_late");
    }

    match err.kind {
        AdapterErrorKind::Retriable => ("adapter_error", "retry_exhausted"),
        AdapterErrorKind::NonRetriable => ("adapter_error", "non_retriable"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReputationImpact {
    pub(crate) label: &'static str,
    pub(crate) delta: i32,
    pub(crate) tier: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReputationSurface {
    pub(crate) label: &'static str,
    pub(crate) delta: i32,
    pub(crate) tier: u8,
    pub(crate) weight_bps: u16,
    pub(crate) score_bps: i32,
    pub(crate) rank_ordinal: u8,
}

pub(crate) const CANONICAL_REPUTATION_SIGNAL_ORDER: [ReputationSignal; 4] = [
    ReputationSignal::Accepted,
    ReputationSignal::AdapterRetryExhausted,
    ReputationSignal::VerifierRejected,
    ReputationSignal::AdapterNonRetriable,
];

pub(crate) const CANONICAL_REPUTATION_IMPACTS: [(ReputationSignal, ReputationImpact); 4] = [
    (
        ReputationSignal::Accepted,
        ReputationImpact {
            label: "accepted",
            delta: 3,
            tier: 3,
        },
    ),
    (
        ReputationSignal::AdapterRetryExhausted,
        ReputationImpact {
            label: "adapter_retry_exhausted",
            delta: -1,
            tier: 2,
        },
    ),
    (
        ReputationSignal::VerifierRejected,
        ReputationImpact {
            label: "verifier_rejected",
            delta: -2,
            tier: 1,
        },
    ),
    (
        ReputationSignal::AdapterNonRetriable,
        ReputationImpact {
            label: "adapter_non_retriable",
            delta: -3,
            tier: 0,
        },
    ),
];

pub(crate) fn reputation_impact(signal: ReputationSignal) -> ReputationImpact {
    CANONICAL_REPUTATION_IMPACTS
        .iter()
        .find_map(|(candidate, impact)| (*candidate == signal).then_some(*impact))
        .expect("canonical reputation mapping must cover all reputation signals")
}

pub(crate) fn reputation_score_impact(signal: ReputationSignal) -> (&'static str, i32) {
    let impact = reputation_impact(signal);
    (impact.label, impact.delta)
}

pub(crate) fn reputation_signal_from_label(label: &str) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_IMPACTS
        .iter()
        .find_map(|(signal, impact)| (impact.label == label).then_some(*signal))
}

pub(crate) fn reputation_impact_from_label(label: &str) -> Option<ReputationImpact> {
    reputation_signal_from_label(label).map(reputation_impact)
}

pub(crate) fn reputation_signal_from_score_impact(
    label: &str,
    delta: i32,
) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_IMPACTS.iter().find_map(|(signal, impact)| {
        (impact.label == label && impact.delta == delta).then_some(*signal)
    })
}

pub(crate) fn reputation_impact_from_score_impact(
    label: &str,
    delta: i32,
) -> Option<ReputationImpact> {
    reputation_signal_from_score_impact(label, delta).map(reputation_impact)
}

pub(crate) fn reputation_signal_from_delta(delta: i32) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_IMPACTS
        .iter()
        .find_map(|(signal, impact)| (impact.delta == delta).then_some(*signal))
}

pub(crate) fn reputation_impact_from_delta(delta: i32) -> Option<ReputationImpact> {
    reputation_signal_from_delta(delta).map(reputation_impact)
}

pub(crate) fn reputation_signal_from_tier(tier: u8) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_IMPACTS
        .iter()
        .find_map(|(signal, impact)| (impact.tier == tier).then_some(*signal))
}

pub(crate) fn reputation_impact_from_tier(tier: u8) -> Option<ReputationImpact> {
    reputation_signal_from_tier(tier).map(reputation_impact)
}

pub(crate) fn reputation_rank_ordinal(signal: ReputationSignal) -> u8 {
    CANONICAL_REPUTATION_SIGNAL_ORDER
        .iter()
        .position(|candidate| *candidate == signal)
        .map(|idx| idx as u8)
        .expect("canonical reputation signal order must cover all reputation signals")
}

pub(crate) fn reputation_signal_from_rank_ordinal(rank_ordinal: u8) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER
        .get(rank_ordinal as usize)
        .copied()
}

pub(crate) fn reputation_impact_from_rank_ordinal(rank_ordinal: u8) -> Option<ReputationImpact> {
    reputation_signal_from_rank_ordinal(rank_ordinal).map(reputation_impact)
}

pub(crate) fn reputation_delta(signal: ReputationSignal) -> i32 {
    reputation_impact(signal).delta
}

pub(crate) fn reputation_tier(signal: ReputationSignal) -> u8 {
    reputation_impact(signal).tier
}

pub(crate) fn reputation_weight_bps(signal: ReputationSignal) -> u16 {
    let impact = reputation_impact(signal);
    let max_tier = CANONICAL_REPUTATION_IMPACTS
        .first()
        .map(|(_, impact)| impact.tier)
        .unwrap_or(0);
    if max_tier == 0 {
        return 10_000;
    }

    ((u32::from(impact.tier) * 10_000) / u32::from(max_tier)) as u16
}

pub(crate) fn reputation_score_bps(signal: ReputationSignal) -> i32 {
    let impact = reputation_impact(signal);
    let max_abs_delta = CANONICAL_REPUTATION_IMPACTS
        .iter()
        .map(|(_, impact)| impact.delta.abs())
        .max()
        .unwrap_or(0);
    if max_abs_delta == 0 {
        return 0;
    }

    (impact.delta * 10_000) / max_abs_delta
}

pub(crate) fn reputation_gap_bps_from_best(signal: ReputationSignal) -> i32 {
    let best_score_bps = CANONICAL_REPUTATION_SIGNAL_ORDER
        .first()
        .copied()
        .map(reputation_score_bps)
        .unwrap_or(0);
    best_score_bps - reputation_score_bps(signal)
}

pub(crate) fn reputation_signal_from_gap_bps_from_best(
    gap_bps_from_best: i32,
) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER.iter().find_map(|signal| {
        (reputation_gap_bps_from_best(*signal) == gap_bps_from_best).then_some(*signal)
    })
}

pub(crate) fn reputation_impact_from_gap_bps_from_best(
    gap_bps_from_best: i32,
) -> Option<ReputationImpact> {
    reputation_signal_from_gap_bps_from_best(gap_bps_from_best).map(reputation_impact)
}

pub(crate) fn reputation_gap_bps_from_worst(signal: ReputationSignal) -> i32 {
    let worst_score_bps = CANONICAL_REPUTATION_SIGNAL_ORDER
        .last()
        .copied()
        .map(reputation_score_bps)
        .unwrap_or(0);
    reputation_score_bps(signal) - worst_score_bps
}

pub(crate) fn reputation_signal_from_gap_bps_from_worst(
    gap_bps_from_worst: i32,
) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER.iter().find_map(|signal| {
        (reputation_gap_bps_from_worst(*signal) == gap_bps_from_worst).then_some(*signal)
    })
}

pub(crate) fn reputation_impact_from_gap_bps_from_worst(
    gap_bps_from_worst: i32,
) -> Option<ReputationImpact> {
    reputation_signal_from_gap_bps_from_worst(gap_bps_from_worst).map(reputation_impact)
}

pub(crate) fn reputation_signal_from_gap_pair(
    gap_bps_from_best: i32,
    gap_bps_from_worst: i32,
) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER.iter().find_map(|signal| {
        (reputation_gap_bps_from_best(*signal) == gap_bps_from_best
            && reputation_gap_bps_from_worst(*signal) == gap_bps_from_worst)
            .then_some(*signal)
    })
}

pub(crate) fn reputation_impact_from_gap_pair(
    gap_bps_from_best: i32,
    gap_bps_from_worst: i32,
) -> Option<ReputationImpact> {
    reputation_signal_from_gap_pair(gap_bps_from_best, gap_bps_from_worst).map(reputation_impact)
}

pub(crate) fn reputation_surface(signal: ReputationSignal) -> ReputationSurface {
    let impact = reputation_impact(signal);
    ReputationSurface {
        label: impact.label,
        delta: impact.delta,
        tier: impact.tier,
        weight_bps: reputation_weight_bps(signal),
        score_bps: reputation_score_bps(signal),
        rank_ordinal: reputation_rank_ordinal(signal),
    }
}

pub(crate) fn canonical_reputation_surfaces() -> [ReputationSurface; 4] {
    CANONICAL_REPUTATION_SIGNAL_ORDER.map(reputation_surface)
}

pub(crate) fn reputation_signal_from_weight_bps(weight_bps: u16) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER
        .iter()
        .find_map(|signal| (reputation_weight_bps(*signal) == weight_bps).then_some(*signal))
}

pub(crate) fn reputation_impact_from_weight_bps(weight_bps: u16) -> Option<ReputationImpact> {
    reputation_signal_from_weight_bps(weight_bps).map(reputation_impact)
}

pub(crate) fn reputation_signal_from_score_bps(score_bps: i32) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER
        .iter()
        .find_map(|signal| (reputation_score_bps(*signal) == score_bps).then_some(*signal))
}

pub(crate) fn reputation_impact_from_score_bps(score_bps: i32) -> Option<ReputationImpact> {
    reputation_signal_from_score_bps(score_bps).map(reputation_impact)
}

pub(crate) fn reputation_signal_from_surface(
    label: &str,
    delta: i32,
    tier: u8,
    weight_bps: u16,
    score_bps: i32,
    rank_ordinal: u8,
) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER.iter().find_map(|signal| {
        let surface = reputation_surface(*signal);
        (surface.label == label
            && surface.delta == delta
            && surface.tier == tier
            && surface.weight_bps == weight_bps
            && surface.score_bps == score_bps
            && surface.rank_ordinal == rank_ordinal)
            .then_some(*signal)
    })
}

pub(crate) fn reputation_impact_from_surface(
    label: &str,
    delta: i32,
    tier: u8,
    weight_bps: u16,
    score_bps: i32,
    rank_ordinal: u8,
) -> Option<ReputationImpact> {
    reputation_signal_from_surface(label, delta, tier, weight_bps, score_bps, rank_ordinal)
        .map(reputation_impact)
}

pub(crate) fn apply_reputation_signal(
    rec: &mut MessageIngressRecord,
    signal: ReputationSignal,
) -> ReputationSurface {
    let surface = reputation_surface(signal);
    rec.reputation_delta = Some(surface.delta);
    surface
}

pub(crate) fn adapter_error_signal(kind: AdapterErrorKind) -> ReputationSignal {
    match kind {
        AdapterErrorKind::Retriable => ReputationSignal::AdapterRetryExhausted,
        AdapterErrorKind::NonRetriable => ReputationSignal::AdapterNonRetriable,
    }
}
