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
mod tests {
    use super::{classify_proof_adapter, ProofAdapterKind};

    #[test]
    fn classify_proof_adapter_keeps_default_aliases_as_standard() {
        let default = "standard";
        let inputs = [
            "",
            "standard",
            " STANDARD ",
            "\u{feff}standard",
            "fraud-proof",
            "FRAUD_PROOF",
            "fraud-proof-v1",
            "fraud proof",
        ];

        for input in inputs {
            let kind = classify_proof_adapter(input, default)
                .unwrap_or_else(|e| panic!("unexpected classify error for {input:?}: {e}"));
            assert_eq!(
                kind,
                ProofAdapterKind::Standard,
                "input {input:?} should classify to Standard"
            );
        }
    }

    #[test]
    fn classify_proof_adapter_maps_tee_aliases_to_tee_receipt() {
        let default = "standard";
        let inputs = [
            "tee-receipt",
            "tee_attestation",
            "TEE RECEIPT",
            "tee-attestation-v1",
            " tee\u{2000}receipt ",
        ];

        for input in inputs {
            let kind = classify_proof_adapter(input, default)
                .unwrap_or_else(|e| panic!("unexpected classify error for {input:?}: {e}"));
            assert_eq!(
                kind,
                ProofAdapterKind::TeeReceipt,
                "input {input:?} should classify to TeeReceipt"
            );
        }
    }

    #[test]
    fn classify_proof_adapter_maps_zk_aliases_to_zk_receipt() {
        let default = "standard";
        let inputs = [
            "zk-receipt",
            "zk_proof",
            "ZK RECEIPT",
            "zk-proof-v1",
            "\u{feff}zk receipt",
        ];

        for input in inputs {
            let kind = classify_proof_adapter(input, default)
                .unwrap_or_else(|e| panic!("unexpected classify error for {input:?}: {e}"));
            assert_eq!(
                kind,
                ProofAdapterKind::ZkReceipt,
                "input {input:?} should classify to ZkReceipt"
            );
        }
    }

    #[test]
    fn classify_proof_adapter_rejects_unsupported_names() {
        let default = "standard";
        let err =
            classify_proof_adapter("quantum-proof", default).expect_err("unsupported adapter");
        assert_eq!(err, "unsupported-proof-adapter:quantum-proof");
    }
}
