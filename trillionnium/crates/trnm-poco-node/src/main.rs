#![forbid(unsafe_code)]

use std::{env, path::PathBuf, process::ExitCode};

use trnm_poco_node::{
    prepare_g2_manifest_bound_candidate_process_v2, production_activation_gate_v0,
    run_g2_manifest_bound_candidate_process_v2, HOST_IMPLEMENTATION_COMPLETE_V0,
    PRODUCTION_CANDIDATE_V0,
};

fn main() -> ExitCode {
    let arguments = env::args_os().collect::<Vec<_>>();
    if arguments.get(1).and_then(|value| value.to_str())
        == Some("prepare-g2-manifest-bound-candidate-v2")
    {
        if arguments.len() != 5 {
            eprintln!(
                "candidate prepare refused: expected <absolute-run-root> <absolute-manifest> <manifest-sha256>"
            );
            return ExitCode::FAILURE;
        }
        let Some(manifest_sha256) = arguments[4].to_str() else {
            eprintln!("candidate prepare refused: manifest SHA-256 is not UTF-8");
            return ExitCode::FAILURE;
        };
        return match prepare_g2_manifest_bound_candidate_process_v2(
            &PathBuf::from(arguments[2].as_os_str()),
            &PathBuf::from(arguments[3].as_os_str()),
            manifest_sha256,
        ) {
            Ok(facts) => {
                println!(
                    "PREPARED candidate_only=true manifest_sha256={} process_pin_checksum={} t0d_anchor_checksum={} network=false signing=false voting=false core=false production=false",
                    facts.manifest_sha256_hex_v2(),
                    facts.process_pin_checksum_hex_v2(),
                    facts.t0d_anchor_checksum_hex_v2(),
                );
                ExitCode::SUCCESS
            }
            Err(cause) => {
                eprintln!("candidate prepare refused: {cause}");
                ExitCode::FAILURE
            }
        };
    }
    if arguments.get(1).and_then(|value| value.to_str())
        == Some("run-g2-manifest-bound-candidate-v2")
    {
        if arguments.len() != 6 {
            eprintln!(
                "candidate run refused: expected <absolute-run-root> <absolute-manifest> <manifest-sha256> <process-pin-checksum>"
            );
            return ExitCode::FAILURE;
        }
        let (Some(manifest_sha256), Some(process_pin_checksum)) =
            (arguments[4].to_str(), arguments[5].to_str())
        else {
            eprintln!("candidate run refused: SHA-256 arguments are not UTF-8");
            return ExitCode::FAILURE;
        };
        return match run_g2_manifest_bound_candidate_process_v2(
            &PathBuf::from(arguments[2].as_os_str()),
            &PathBuf::from(arguments[3].as_os_str()),
            manifest_sha256,
            process_pin_checksum,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(cause) => {
                eprintln!("candidate run refused: {cause}");
                ExitCode::FAILURE
            }
        };
    }

    let blocker = production_activation_gate_v0()
        .expect_err("the incomplete PoCO node binary must remain fail-closed");
    eprintln!(
        "trnm-poco-node startup refused: production_candidate={PRODUCTION_CANDIDATE_V0} host_complete={HOST_IMPLEMENTATION_COMPLETE_V0}; {blocker}"
    );
    ExitCode::FAILURE
}
