//! Candidate-only Native PoCO bounded devnet validator entrypoint.
//!
//! This executable is intentionally distinct from `trnm-poco-node`. It can run
//! only a manifest-bound, bounded, single-LAN laboratory validator after an
//! external Unix peer-lease authority passes preflight and the operator supplies
//! an explicit non-production acknowledgement.

use std::{env, process::ExitCode};

use trnm_poco_lab_validator::{
    candidate_devnet::{
        parse_candidate_devnet_args_v1, run_candidate_devnet_v1, CandidateDevnetCliActionV1,
        CandidateDevnetRunOutcomeV1, CANDIDATE_DEVNET_USAGE_V1,
    },
    consensus_runtime::PROCESS1_TARGET_PARKED_EXIT_STATUS_V1,
    PRODUCTION_CANDIDATE, PRODUCTION_CONSENSUS_ACTIVATION,
};

fn main() -> ExitCode {
    let action = match parse_candidate_devnet_args_v1(env::args_os().skip(1)) {
        Ok(action) => action,
        Err(error) => {
            eprintln!("candidate devnet validator refused: {error}");
            eprint!("{CANDIDATE_DEVNET_USAGE_V1}");
            return ExitCode::from(2);
        }
    };

    match action {
        CandidateDevnetCliActionV1::Help => {
            print!("{CANDIDATE_DEVNET_USAGE_V1}");
            ExitCode::SUCCESS
        }
        CandidateDevnetCliActionV1::Run(arguments) => match run_candidate_devnet_v1(arguments) {
            Ok(CandidateDevnetRunOutcomeV1::CompletedReport(path)) => {
                println!(
                    "candidate_devnet_completed candidate_only=true single_lan=true external_peer_fence=true local_test_keys=true production_candidate={} production_consensus_activation={} report={}",
                    PRODUCTION_CANDIDATE,
                    PRODUCTION_CONSENSUS_ACTIVATION,
                    path.display(),
                );
                ExitCode::SUCCESS
            }
            Ok(CandidateDevnetRunOutcomeV1::Process1TargetParked(handoff)) => {
                println!(
                    "candidate_devnet_process1_parked candidate_only=true production_candidate={} production_consensus_activation={} handoff={handoff}",
                    PRODUCTION_CANDIDATE,
                    PRODUCTION_CONSENSUS_ACTIVATION,
                );
                ExitCode::from(PROCESS1_TARGET_PARKED_EXIT_STATUS_V1)
            }
            Err(error) => {
                eprintln!(
                    "candidate devnet validator halted: candidate_only=true production_candidate={} production_consensus_activation={}; {error:#}",
                    PRODUCTION_CANDIDATE,
                    PRODUCTION_CONSENSUS_ACTIVATION,
                );
                ExitCode::from(2)
            }
        },
    }
}
