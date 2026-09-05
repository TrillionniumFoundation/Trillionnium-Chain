#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

use std::process::ExitCode;

#[allow(dead_code)]
mod finalization_intent_wal_process_v1 {
    include!(concat!(
        env!("OUT_DIR"),
        "/finalization_intent_wal_process_v1.rs"
    ));
}

use finalization_intent_wal_process_v1::run_finalization_intent_kill_helper_v1;

fn main() -> ExitCode {
    match run_finalization_intent_kill_helper_v1() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FINALIZATION_INTENT_KILL_HELPER_ERROR {error}");
            ExitCode::FAILURE
        }
    }
}
