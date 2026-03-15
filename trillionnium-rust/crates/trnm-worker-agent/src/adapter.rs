pub(crate) use crate::adapter_error::{
    adapter_error_signal, classify_adapter_error, is_deterministic_rejection,
    is_idempotent_duplicate_ok, reputation_delta, AdapterError, AdapterErrorKind, ReputationSignal,
};
pub(crate) use crate::adapter_provenance::attach_llm_provenance;
