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
    let err = classify_proof_adapter("quantum-proof", default).expect_err("unsupported adapter");
    assert_eq!(err, "unsupported-proof-adapter:quantum-proof");
}
