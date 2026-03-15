#[path = "proof_adapter_utils_json.rs"]
mod proof_adapter_utils_json;
#[path = "proof_adapter_utils_norm.rs"]
mod proof_adapter_utils_norm;

#[allow(unused_imports)]
pub(crate) use proof_adapter_utils_json::{
    last_balanced_json_object, parse_response_with_standard_rules,
};
#[allow(unused_imports)]
pub(crate) use proof_adapter_utils_norm::{
    collapse_adapter_delimiters, has_non_empty_auditable_value, is_invisible_receipt_filler,
    normalize_adapter_label, normalize_adapter_value, peel_outer_quote_wrappers,
};

#[cfg(test)]
#[path = "proof_adapter_utils_tests.rs"]
mod tests;
