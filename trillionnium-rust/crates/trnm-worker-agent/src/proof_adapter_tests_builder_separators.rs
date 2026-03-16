use super::*;

#[test]
fn build_proof_adapter_accepts_separator_aliases_for_receipt_modes() {
    for label in [
        "FRAUD PROOF",
        "FRAUD/PROOF",
        "FRAUD:PROOF",
        " FRAUD / PROOF ",
        "FRAUD - PROOF",
        "FRAUD PROOF V1",
        "FRAUD/PROOF/V1",
        "FRAUD:PROOF:V1",
    ] {
        let adapter = build_proof_adapter(label)
            .unwrap_or_else(|_| panic!("fraud separator alias should parse: {label}"));
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok, "fraud separator alias should verify: {label}");
        assert_eq!(code, "ok", "fraud alias code mismatch: {label}");
    }

    for label in [
        "TEE RECEIPT",
        "TEE/RECEIPT",
        "TEE:RECEIPT",
        " TEE / RECEIPT ",
        "TEE - RECEIPT",
    ] {
        let adapter = build_proof_adapter(label)
            .unwrap_or_else(|_| panic!("tee separator alias should parse: {label}"));
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok, "tee separator alias should verify: {label}");
        assert_eq!(code, "tee_receipt_ok", "tee alias code mismatch: {label}");
    }

    for label in [
        "ZK RECEIPT",
        "ZK/RECEIPT",
        "ZK:RECEIPT",
        " ZK / RECEIPT ",
        "ZK - RECEIPT",
    ] {
        let adapter = build_proof_adapter(label)
            .unwrap_or_else(|_| panic!("zk separator alias should parse: {label}"));
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok, "zk separator alias should verify: {label}");
        assert_eq!(code, "zk_receipt_ok", "zk alias code mismatch: {label}");
    }
}
