use super::{is_tee_receipt_adapter_label, is_zk_receipt_adapter_label};

#[test]
fn tee_receipt_aliases_are_normalized() {
    assert!(is_tee_receipt_adapter_label(Some("TEE_RECEIPT")));
    assert!(is_tee_receipt_adapter_label(Some(" tee-attestation ")));
    assert!(is_tee_receipt_adapter_label(Some(
        "\u{feff}TEE_RECEIPT\u{2000}"
    )));
    assert!(is_tee_receipt_adapter_label(Some("tee\u{2010}receipt")));
    assert!(!is_tee_receipt_adapter_label(Some("zk-receipt")));
    assert!(!is_tee_receipt_adapter_label(None));
}

#[test]
fn zk_receipt_aliases_are_normalized() {
    assert!(is_zk_receipt_adapter_label(Some("ZK_RECEIPT")));
    assert!(is_zk_receipt_adapter_label(Some(" zk-proof-v1 ")));
    assert!(is_zk_receipt_adapter_label(Some(
        "\u{feff}ZK\u{2000}RECEIPT\u{2003}"
    )));
    assert!(is_zk_receipt_adapter_label(Some("zk\u{2011}receipt")));
    assert!(!is_zk_receipt_adapter_label(Some("tee-receipt")));
    assert!(!is_zk_receipt_adapter_label(None));
}
