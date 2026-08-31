#![cfg(feature = "test-fixture")]

use std::{env, path::PathBuf, process::ExitCode};

use trnm_consensus_unix_fleet_signer::test_fixture::serve_durable_fixture;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let socket = match args.next() {
        Some(value) => PathBuf::from(value),
        None => return fail("missing socket path"),
    };
    let log = match args.next() {
        Some(value) => PathBuf::from(value),
        None => return fail("missing authority log path"),
    };
    let request_count = match args.next() {
        Some(value) => match value.parse::<usize>() {
            Ok(count) => count,
            Err(error) => return fail(&format!("invalid request count: {error}")),
        },
        None => return fail("missing request count"),
    };
    match serve_durable_fixture(socket, log, request_count) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&error),
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("trnm-fleet-root-signer-authority-fixture: {message}");
    ExitCode::from(2)
}
