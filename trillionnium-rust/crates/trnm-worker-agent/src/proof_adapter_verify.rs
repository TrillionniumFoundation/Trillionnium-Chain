#[path = "proof_adapter_verify_core.rs"]
mod proof_adapter_verify_core;

pub(crate) use proof_adapter_verify_core::{
    validate_receipt_adapter_response, verify_standard_adapter_output,
    verify_tee_receipt_adapter_output, verify_zk_receipt_adapter_output,
};

#[cfg(test)]
#[path = "proof_adapter_verify_tests.rs"]
mod tests;
