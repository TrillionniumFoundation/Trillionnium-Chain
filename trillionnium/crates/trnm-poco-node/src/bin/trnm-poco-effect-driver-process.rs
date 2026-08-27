#![forbid(unsafe_code)]

//! Candidate-only OS process for the Core effect-driver seam.

use std::{
    env,
    io::{self, BufReader, BufWriter},
    path::PathBuf,
    process::ExitCode,
};

use trnm_poco_node::run_effect_driver_process_stdio_v1;

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(root) = args.next() else {
        eprintln!("usage: trnm-poco-effect-driver-process <absolute-run-root>");
        return ExitCode::FAILURE;
    };
    if args.next().is_some() {
        eprintln!("usage: trnm-poco-effect-driver-process <absolute-run-root>");
        return ExitCode::FAILURE;
    }

    match run_effect_driver_process_stdio_v1(
        PathBuf::from(root),
        BufReader::new(io::stdin()),
        BufWriter::new(io::stdout()),
    ) {
        Ok(summary) => {
            eprintln!(
                "EFFECT_DRIVER_PROCESS_SUMMARY generation={} ingress={} effects={} broadcasts={} status={:?}",
                summary.generation,
                summary.processed_ingress,
                summary.processed_effects,
                summary.broadcasts,
                summary.status,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("EFFECT_DRIVER_PROCESS_ERROR {error}");
            ExitCode::FAILURE
        }
    }
}
