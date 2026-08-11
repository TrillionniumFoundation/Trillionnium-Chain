#![forbid(unsafe_code)]

use std::process::ExitCode;

use trnm_poco_node::{
    production_activation_gate_v0, HOST_IMPLEMENTATION_COMPLETE_V0, PRODUCTION_CANDIDATE_V0,
};

fn main() -> ExitCode {
    let blocker = production_activation_gate_v0()
        .expect_err("the incomplete PoCO node binary must remain fail-closed");
    eprintln!(
        "trnm-poco-node startup refused: production_candidate={PRODUCTION_CANDIDATE_V0} host_complete={HOST_IMPLEMENTATION_COMPLETE_V0}; {blocker}"
    );
    ExitCode::FAILURE
}
