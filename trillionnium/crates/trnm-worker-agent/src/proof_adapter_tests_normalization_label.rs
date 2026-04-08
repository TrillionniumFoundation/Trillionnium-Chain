use super::*;

#[test]
fn adapter_label_normalization_peels_nested_and_shell_escaped_quote_wrappers() {
    assert_eq!(
        normalize_adapter_label(" '\"TEE_RECEIPT\"' "),
        "tee-receipt"
    );
    assert_eq!(normalize_adapter_value(" '\"ZK_PROOF\"' "), "zk-proof");
    assert_eq!(
        normalize_adapter_label(r#"\"TEE-ATTESTATION\""#),
        "tee-attestation"
    );
    assert_eq!(normalize_adapter_value(r#"\"ZK-RECEIPT\""#), "zk-receipt");
}

#[test]
fn adapter_label_normalization_peels_smart_and_localized_quote_wrappers() {
    assert_eq!(normalize_adapter_label("“TEE_RECEIPT”"), "tee-receipt");
    assert_eq!(normalize_adapter_value("‘ZK_PROOF’"), "zk-proof");
    assert_eq!(
        normalize_adapter_label("«TEE-ATTESTATION»"),
        "tee-attestation"
    );
    assert_eq!(normalize_adapter_value("‹zk receipt›"), "zk-receipt");
    assert_eq!(normalize_adapter_label("「TEE_RECEIPT」"), "tee-receipt");
    assert_eq!(normalize_adapter_value("『ZK_PROOF』"), "zk-proof");
    assert_eq!(
        normalize_adapter_label("〈TEE-ATTESTATION〉"),
        "tee-attestation"
    );
    assert_eq!(normalize_adapter_value("《ZK_RECEIPT》"), "zk-receipt");
    assert_eq!(normalize_adapter_label("⟨TEE_RECEIPT⟩"), "tee-receipt");
    assert_eq!(normalize_adapter_value("⟨ZK_PROOF⟩"), "zk-proof");
    assert_eq!(normalize_adapter_label(r#"\“TEE_RECEIPT\”"#), "tee-receipt");
    assert_eq!(normalize_adapter_value(r#"\‘ZK_PROOF\’"#), "zk-proof");
}
