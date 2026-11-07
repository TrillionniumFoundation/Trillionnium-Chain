//! Explicit new profile selection must fail closed without the Linux PQ backend.
#![cfg(not(all(target_os = "linux", feature = "pq-native-openssl")))]
#[test]
fn ordinary_npq6_explicit_configuration_has_no_feature_or_platform_fallback() {
    let root = tempfile::tempdir().unwrap();
    let store = root.path().join("not-created");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args([
            "submit",
            "--development",
            "--pq-application-config",
            "missing.json",
            "--pq-application-config-sha256",
            &"00".repeat(32),
        ])
        .arg("--store")
        .arg(&store)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("PQ_APPLICATION_LINUX_NATIVE_OPENSSL_REQUIRED"));
    assert!(!store.exists());
}
