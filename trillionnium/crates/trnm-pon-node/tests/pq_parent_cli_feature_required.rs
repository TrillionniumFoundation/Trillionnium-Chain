#![cfg(not(all(target_os = "linux", feature = "pq-native-openssl")))]
use std::process::Command;

#[test]
fn parent_recovery_commands_require_linux_and_native_pq_feature_before_files_or_network() {
    for command in [
        "pq-parent-tls-serve",
        "pq-parent-create",
        "pq-parent-resume",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
            .args([command, "--development"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("PQ_PARENT_LINUX_NATIVE_OPENSSL_REQUIRED"));
    }
}
