#[path = "adapter_error_models.rs"]
mod adapter_error_models;
#[path = "adapter_error_ops.rs"]
mod adapter_error_ops;

pub(crate) use adapter_error_models::{AdapterError, AdapterErrorKind, ReputationSignal};
pub(crate) use adapter_error_ops::{
    adapter_error_signal, apply_reputation_signal, canonical_reputation_surfaces,
    classify_adapter_error, is_deterministic_rejection, is_idempotent_duplicate_ok,
    reputation_delta, reputation_gap_bps_from_best, reputation_gap_bps_from_worst,
    reputation_impact, reputation_impact_from_delta, reputation_impact_from_gap_bps_from_best,
    reputation_impact_from_gap_bps_from_worst, reputation_impact_from_gap_pair,
    reputation_impact_from_label,
    reputation_impact_from_rank_ordinal, reputation_impact_from_score_bps,
    reputation_impact_from_score_impact, reputation_impact_from_surface,
    reputation_impact_from_tier, reputation_impact_from_weight_bps, reputation_rank_ordinal,
    reputation_score_bps, reputation_score_impact, reputation_signal_from_delta,
    reputation_signal_from_gap_bps_from_best, reputation_signal_from_gap_bps_from_worst,
    reputation_signal_from_gap_pair, reputation_signal_from_label,
    reputation_signal_from_rank_ordinal,
    reputation_signal_from_score_bps, reputation_signal_from_score_impact,
    reputation_signal_from_surface, reputation_signal_from_tier,
    reputation_signal_from_weight_bps, reputation_surface, reputation_tier,
    reputation_weight_bps, ReputationImpact, ReputationSurface,
};
