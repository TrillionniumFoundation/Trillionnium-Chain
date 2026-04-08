use super::*;

#[test]
fn build_proof_adapter_accepts_default_and_fraud_and_tee_receipt_and_zk_aliases() {
    let adapter = build_proof_adapter(DEFAULT_PROOF_ADAPTER).expect("default adapter");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let adapter = build_proof_adapter(" \n\t ").expect("whitespace-only defaults to standard");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let adapter =
        build_proof_adapter("\u{feff} \n\t").expect("bom+whitespace defaults to standard");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let adapter = build_proof_adapter("\u{feff} STANDARD ").expect("bom+whitespace default");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let adapter = build_proof_adapter("fraud-proof").expect("fraud proof alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let adapter = build_proof_adapter("FRAUD_PROOF").expect("fraud proof underscore alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let adapter = build_proof_adapter("FRAUD\u{200d}_PROOF")
        .expect("fraud proof alias should strip zero-width joiner");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let adapter = build_proof_adapter("fraud-proof-v1").expect("fraud proof v1 alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let adapter = build_proof_adapter("FRAUD_PROOF_V1").expect("fraud proof underscore v1 alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let adapter = build_proof_adapter("fraudproof").expect("fraud proof compact alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let adapter = build_proof_adapter("fraudproofv1").expect("fraud proof compact v1 alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let adapter = build_proof_adapter("tee-receipt").expect("tee receipt alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("TEE_RECEIPT").expect("tee receipt underscore alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("  \u{feff}TEE_RECEIPT  ")
        .expect("tee receipt alias should tolerate whitespace+bom");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("TEE_RECEIPT_V1").expect("tee v1 alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("TEE‑RECEIPT").expect("tee non-breaking hyphen alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("TEE\u{200d}_RECEIPT")
        .expect("tee alias should strip zero-width joiner");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("TEE\u{2066}_RECEIPT\u{2069}")
        .expect("tee alias should strip directional isolates");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("TEE\u{202E}_RECEIPT")
        .expect("tee alias should strip bidi override controls");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter =
        build_proof_adapter("TEE\u{2062}_RECEIPT").expect("tee alias should strip invisible times");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter =
        build_proof_adapter("TEE\u{200F}_RECEIPT").expect("tee alias should strip rtl mark");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("TEE\u{feff}_RECEIPT").expect("tee embedded bom alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("TEE\\RECEIPT")
        .expect("tee backslash separator alias should normalize");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("zk-receipt").expect("zk receipt alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter = build_proof_adapter("ZK_RECEIPT").expect("zk receipt underscore alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter =
        build_proof_adapter("ZK\\RECEIPT").expect("zk backslash separator alias should normalize");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter = build_proof_adapter("zk_receipt_v1").expect("zk v1 alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter = build_proof_adapter("ZK‑RECEIPT").expect("zk non-breaking hyphen alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter =
        build_proof_adapter("ZK\u{200d}_RECEIPT").expect("zk alias should strip zero-width joiner");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter = build_proof_adapter("ZK\u{2066}_RECEIPT\u{2069}")
        .expect("zk alias should strip directional isolates");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter = build_proof_adapter("ZK\u{202A}_RECEIPT")
        .expect("zk alias should strip bidi embedding controls");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter =
        build_proof_adapter("ZK\u{2064}_RECEIPT").expect("zk alias should strip invisible plus");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter = build_proof_adapter("ZK\u{061C}_RECEIPT")
        .expect("zk alias should strip arabic letter mark");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter = build_proof_adapter("ZK\u{feff}_RECEIPT").expect("zk embedded bom alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter = build_proof_adapter("tee-attestation").expect("tee attestation alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("teeattestation").expect("tee compact alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("TEE_ATTESTATION_V1").expect("tee attestation v1 alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");

    let adapter = build_proof_adapter("zk-proof").expect("zk proof alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter = build_proof_adapter("zk-proof-v1").expect("zk proof v1 alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter = build_proof_adapter("ZK_PROOF_V1").expect("zk proof underscore v1 alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter = build_proof_adapter("zkproof").expect("zk compact alias");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");

    let adapter = build_proof_adapter("tee attestation")
        .expect("tee attestation space-separated alias should parse");
    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");
}
