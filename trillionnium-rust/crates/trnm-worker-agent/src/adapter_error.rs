#[path = "adapter_error_models.rs"]
mod adapter_error_models;
#[path = "adapter_error_ops.rs"]
mod adapter_error_ops;

pub(crate) use adapter_error_models::{AdapterError, AdapterErrorKind, ReputationSignal};
pub(crate) use adapter_error_ops::{
    adapter_error_signal, apply_reputation_signal, classify_adapter_error,
    is_deterministic_rejection, is_idempotent_duplicate_ok, reputation_delta,
};
