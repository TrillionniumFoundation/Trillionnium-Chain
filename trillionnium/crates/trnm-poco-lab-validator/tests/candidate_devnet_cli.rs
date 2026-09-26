#![forbid(unsafe_code)]

use std::{ffi::OsString, path::PathBuf};

use trnm_poco_lab_validator::candidate_devnet::{
    parse_candidate_devnet_args_v1, run_candidate_devnet_v1, CandidateDevnetCliActionV1,
    CandidateDevnetProcessModeV1, CANDIDATE_DEVNET_EXTERNAL_FENCE_REQUIRED_V1,
    CANDIDATE_DEVNET_HOST_ATTESTATION_V1, CANDIDATE_DEVNET_HSM_AUTHORITY_V1,
    CANDIDATE_DEVNET_LOCAL_TEST_KEYS_V1, CANDIDATE_DEVNET_PRODUCTION_ACTIVATION_V1,
    CANDIDATE_DEVNET_PUBLIC_TESTNET_READY_V1, CANDIDATE_DEVNET_VALIDATOR_CLI_V1,
};

fn run_arguments(socket: PathBuf) -> Vec<OsString> {
    [
        OsString::from("--acknowledge-candidate-only"),
        OsString::from("--run-root"),
        OsString::from("/tmp/trnm-candidate-devnet-ordering"),
        OsString::from("--config"),
        OsString::from("/tmp/trnm-candidate-devnet-ordering/public/configs/missing.json"),
        OsString::from("--peer-lease-socket"),
        socket.into_os_string(),
        OsString::from("--report"),
        OsString::from("/tmp/trnm-candidate-devnet-ordering/report.json"),
        OsString::from("--duration-seconds"),
        OsString::from("30"),
        OsString::from("--max-blocks"),
        OsString::from("12"),
        OsString::from("--lease-timeout-millis"),
        OsString::from("100"),
    ]
    .into_iter()
    .collect()
}

fn process2_arguments(socket: PathBuf) -> Vec<OsString> {
    let mut arguments = run_arguments(socket);
    arguments.extend([
        OsString::from("--resume-process2"),
        OsString::from("--recovery-ready-set-sha256"),
        OsString::from("41".repeat(32)),
        OsString::from("--recovery-start-certificate-sha256"),
        OsString::from("42".repeat(32)),
        OsString::from("--recovery-fence-token-sha256"),
        OsString::from("43".repeat(32)),
    ]);
    arguments
}

#[test]
fn external_fence_preflight_precedes_config_and_local_key_loading() {
    let socket = PathBuf::from(format!(
        "/tmp/trnm-candidate-devnet-absent-fence-{}-{}.sock",
        std::process::id(),
        std::thread::current().name().unwrap_or("unnamed")
    ));
    let parsed = parse_candidate_devnet_args_v1(run_arguments(socket))
        .expect("ordering-test arguments parse");
    let CandidateDevnetCliActionV1::Run(arguments) = parsed else {
        panic!("expected run action");
    };

    let error = run_candidate_devnet_v1(*arguments)
        .expect_err("absent external fence must fail before config loading");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("candidate peer-lease preflight failed"));
    assert!(!rendered.contains("load manifest-bound candidate validator configuration"));
    assert!(!rendered.contains("validator config"));
}

#[test]
fn process2_external_fence_preflight_precedes_recovery_and_key_loading() {
    let socket = PathBuf::from(format!(
        "/tmp/trnm-candidate-devnet-process2-absent-fence-{}-{}.sock",
        std::process::id(),
        std::thread::current().name().unwrap_or("unnamed")
    ));
    let parsed = parse_candidate_devnet_args_v1(process2_arguments(socket))
        .expect("process2 ordering-test arguments parse");
    let CandidateDevnetCliActionV1::Run(arguments) = parsed else {
        panic!("expected process2 run action");
    };
    assert_eq!(
        arguments.process_mode(),
        CandidateDevnetProcessModeV1::ResumeProcess2 {
            ready_set_artifact_sha256: [0x41; 32],
            start_certificate_artifact_sha256: [0x42; 32],
            fence_token_digest: [0x43; 32],
        }
    );

    let error = run_candidate_devnet_v1(*arguments)
        .expect_err("absent external fence must fail before process2 recovery");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("candidate peer-lease preflight failed"));
    assert!(!rendered.contains("load manifest-bound candidate validator configuration"));
    assert!(!rendered.contains("resume externally fenced candidate validator as process2"));
}

#[test]
fn candidate_devnet_contract_preserves_all_release_nonclaims() {
    const {
        assert!(CANDIDATE_DEVNET_VALIDATOR_CLI_V1);
        assert!(CANDIDATE_DEVNET_EXTERNAL_FENCE_REQUIRED_V1);
        assert!(CANDIDATE_DEVNET_LOCAL_TEST_KEYS_V1);
        assert!(!CANDIDATE_DEVNET_HSM_AUTHORITY_V1);
        assert!(!CANDIDATE_DEVNET_HOST_ATTESTATION_V1);
        assert!(!CANDIDATE_DEVNET_PRODUCTION_ACTIVATION_V1);
        assert!(!CANDIDATE_DEVNET_PUBLIC_TESTNET_READY_V1);
    }
}
