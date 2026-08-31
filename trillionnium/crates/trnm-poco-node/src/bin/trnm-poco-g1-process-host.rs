#![forbid(unsafe_code)]

//! Candidate-only process entry point for the G1 CheckTx -> native AppHash
//! vertical slice.  The binary deliberately has no default production path;
//! Cargo only exposes it when `g1-process-test-support` is selected.

use std::{
    env,
    io::{self, BufReader, BufWriter},
    path::PathBuf,
    process::ExitCode,
};

use trnm_poco_node::g1_process_host::run_stdio_v0;

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(run_root) = args.next() else {
        eprintln!("usage: trnm-poco-g1-process-host <absolute-run-root>");
        return ExitCode::FAILURE;
    };
    if args.next().is_some() {
        eprintln!("usage: trnm-poco-g1-process-host <absolute-run-root>");
        return ExitCode::FAILURE;
    }

    match run_stdio_v0(
        PathBuf::from(run_root),
        BufReader::new(io::stdin()),
        BufWriter::new(io::stdout()),
    ) {
        Ok(summary) => {
            // stdout is a machine-readable newline protocol.  Keep the
            // process summary on stderr so callers can safely parse stdout.
            eprintln!("G1_PROCESS_SUMMARY {:?}", summary);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("G1_PROCESS_ERROR {error}");
            ExitCode::FAILURE
        }
    }
}
