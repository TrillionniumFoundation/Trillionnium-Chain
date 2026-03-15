use crate::{
    proof_adapter_rules::{is_tee_receipt_adapter_label, is_zk_receipt_adapter_label},
    proof_adapter_selector::classify_proof_adapter,
    proof_adapter_utils::parse_response_with_standard_rules,
    proof_adapter_verify::{
        validate_receipt_adapter_response, verify_standard_adapter_output,
        verify_tee_receipt_adapter_output, verify_zk_receipt_adapter_output,
    },
    LlmAdapterResponse,
};

pub trait ProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String);
    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String>;
}

#[path = "proof_adapter_factory.rs"]
mod proof_adapter_factory;

use self::proof_adapter_factory::build_proof_adapter_of_kind;

pub const DEFAULT_PROOF_ADAPTER: &str = "standard";

pub struct StandardProofAdapter;
pub struct TeeReceiptProofAdapter;
pub struct ZkReceiptProofAdapter;

pub fn build_proof_adapter(name: &str) -> Result<Box<dyn ProofAdapter>, String> {
    let kind = classify_proof_adapter(name, DEFAULT_PROOF_ADAPTER)?;
    build_proof_adapter_of_kind(kind)
}

impl ProofAdapter for StandardProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String) {
        verify_standard_adapter_output(output, max_chars)
    }

    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String> {
        parse_response_with_standard_rules(stdout)
    }
}

impl ProofAdapter for TeeReceiptProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String) {
        verify_tee_receipt_adapter_output(output, max_chars)
    }

    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String> {
        let parsed = parse_response_with_standard_rules(stdout)?;
        validate_receipt_adapter_response("tee-receipt", &parsed, is_tee_receipt_adapter_label)?;
        Ok(parsed)
    }
}

impl ProofAdapter for ZkReceiptProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String) {
        verify_zk_receipt_adapter_output(output, max_chars)
    }

    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String> {
        let parsed = parse_response_with_standard_rules(stdout)?;
        validate_receipt_adapter_response("zk-receipt", &parsed, is_zk_receipt_adapter_label)?;
        Ok(parsed)
    }
}

#[cfg(test)]
#[path = "proof_adapter_tests.rs"]
mod tests;
