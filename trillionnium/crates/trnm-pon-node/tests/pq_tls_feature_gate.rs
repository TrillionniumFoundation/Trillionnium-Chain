#![cfg(all(unix, not(feature = "pq-native-openssl")))]
#[test]
fn ordinary_binary_without_tls_feature_refuses_without_classical_fallback() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args(["pq-tls-serve", "--development"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("PQ_TLS_NATIVE_OPENSSL_FEATURE_REQUIRED"));
}
