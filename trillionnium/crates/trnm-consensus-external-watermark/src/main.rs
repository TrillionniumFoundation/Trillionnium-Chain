use std::{env, process::ExitCode};

use trnm_consensus_external_watermark::run_daemon;

fn usage() -> ! {
    eprintln!("usage: trnm-external-watermark-v0 --socket ABS_PATH --log ABS_PATH");
    std::process::exit(2);
}

fn main() -> ExitCode {
    let mut socket = None;
    let mut log = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => socket = args.next(),
            "--log" => log = args.next(),
            "--help" => usage(),
            _ => usage(),
        }
    }
    let socket = socket.unwrap_or_else(|| usage());
    let log = log.unwrap_or_else(|| usage());
    match run_daemon(socket, log) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("external watermark authority failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}
