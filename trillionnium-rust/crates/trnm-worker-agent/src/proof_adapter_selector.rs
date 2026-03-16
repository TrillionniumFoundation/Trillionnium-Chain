use crate::proof_adapter_utils::normalize_adapter_label;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProofAdapterKind {
    Standard,
    TeeReceipt,
    ZkReceipt,
}

pub(crate) fn classify_proof_adapter(
    name: &str,
    default_adapter: &str,
) -> Result<ProofAdapterKind, String> {
    let normalized = normalize_adapter_label(name);

    if normalized.is_empty() || normalized == default_adapter {
        return Ok(ProofAdapterKind::Standard);
    }

    match normalized.as_str() {
        "fraud-proof" | "fraud_proof" | "fraud-proof-v1" | "fraud_proof_v1" | "fraudproof"
        | "fraudproofv1" => Ok(ProofAdapterKind::Standard),
        "tee-receipt" | "tee_receipt" | "tee-receipt-v1" | "tee_receipt_v1" | "tee-attestation"
        | "tee_attestation" | "tee-attestation-v1" | "tee_attestation_v1" | "teereceipt"
        | "teeattestation" | "teereceiptv1" | "teeattestationv1" => {
            Ok(ProofAdapterKind::TeeReceipt)
        }
        "zk-receipt" | "zk_receipt" | "zk-receipt-v1" | "zk_receipt_v1" | "zk-proof"
        | "zk_proof" | "zk-proof-v1" | "zk_proof_v1" | "zkreceipt" | "zkproof" | "zkproofv1"
        | "zkreceiptv1" => Ok(ProofAdapterKind::ZkReceipt),
        other => Err(format!("unsupported-proof-adapter:{other}")),
    }
}

#[cfg(test)]
#[path = "proof_adapter_selector_tests.rs"]
mod tests;
