#![forbid(unsafe_code)]

use std::{ffi::OsString, path::PathBuf};

use trnm_poco_lab_validator::candidate_devnet::{
    parse_candidate_devnet_args_v1, run_candidate_devnet_v1, CandidateDevnetCliActionV1,
    CANDIDATE_DEVNET_EXTERNAL_FENCE_REQUIRED_V1, CANDIDATE_DEVNET_HSM_AUTHORITY_V1,
    CANDIDATE_DEVNET_HOST_ATTESTATION_V1, CANDIDATE_DEVNET_LOCAL_TEST_KEYS_V1,
    CANDIDATE_DEVNET_PRODUCTION_ACTIVATION_V1, CANDIDATE_DEVNET_PUBLIC_TESTNET_READY_V1,
    CANDIDATE_DEVNET_VALIDATOR_CLI_V1,
};

fn run_arguments(socket: PathBuf) -> Vec<OsString> {
    [
        OsString::from("--acknowledge-candidate-only"),
        OsString::from("--run-root"),
        OsString::from("/tmp/trnm-candidate-devnet-ordering"),
        OsString::from("--config"),
        OsString::from(
            "/tmp/trnm-candidate-devnet-ordering/public/configs/missing.json",
        ),
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

    let error = run_candidate_devnet_v1(arguments)
        .expect_err("absent external fence must fail before config loading");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("candidate peer-lease preflight failed"));
    assert!(!rendered.contains("load manifest-bound candidate validator configuration"));
    assert!(!rendered.contains("validator config"));
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
