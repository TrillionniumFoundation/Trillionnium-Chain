use std::{env, path::PathBuf, process::ExitCode};

use trnm_consensus_external_node_checkpoint::run_daemon;

fn usage() -> ! {
    eprintln!("usage: trnm-external-node-checkpoint-v0 <socket-path> <log-path>");
    std::process::exit(64);
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let socket = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    let log = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    if args.next().is_some() {
        usage();
    }
    match run_daemon(socket, log) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("external node-checkpoint authority failed: {error}");
            ExitCode::from(1)
        }
    }
}
