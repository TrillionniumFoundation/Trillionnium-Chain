use crate::proof_adapter::proof_adapter_core::ProofAdapter;
use crate::proof_adapter::StandardProofAdapter;
use crate::proof_adapter_utils::{
    last_balanced_json_object, normalize_adapter_label, normalize_adapter_value,
};

#[cfg(test)]
#[path = "proof_adapter_tests_normalization_label.rs"]
mod proof_adapter_tests_normalization_label;

#[cfg(test)]
#[path = "proof_adapter_tests_normalization_json.rs"]
mod proof_adapter_tests_normalization_json;

#[cfg(test)]
#[path = "proof_adapter_tests_normalization_parse.rs"]
mod proof_adapter_tests_normalization_parse;
