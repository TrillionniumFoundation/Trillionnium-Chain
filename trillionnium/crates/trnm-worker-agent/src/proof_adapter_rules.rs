use crate::proof_adapter_utils::normalize_adapter_value;

pub(crate) fn is_tee_receipt_adapter_label(label: Option<&str>) -> bool {
    label
        .map(normalize_adapter_value)
        .map(|normalized| {
            matches!(
                normalized.as_str(),
                "tee-receipt"
                    | "tee_receipt"
                    | "tee-receipt-v1"
                    | "tee_receipt_v1"
                    | "tee-attestation"
                    | "tee_attestation"
                    | "tee-attestation-v1"
                    | "tee_attestation_v1"
                    | "teereceipt"
                    | "teereceiptv1"
                    | "teeattestation"
                    | "teeattestationv1"
            )
        })
        .unwrap_or(false)
}

pub(crate) fn is_zk_receipt_adapter_label(label: Option<&str>) -> bool {
    label
        .map(normalize_adapter_value)
        .map(|normalized| {
            matches!(
                normalized.as_str(),
                "zk-receipt"
                    | "zk_receipt"
                    | "zk-receipt-v1"
                    | "zk_receipt_v1"
                    | "zk-proof"
                    | "zk_proof"
                    | "zk-proof-v1"
                    | "zk_proof_v1"
                    | "zkreceipt"
                    | "zkreceiptv1"
                    | "zkproof"
                    | "zkproofv1"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
#[path = "proof_adapter_rules_tests.rs"]
mod tests;
