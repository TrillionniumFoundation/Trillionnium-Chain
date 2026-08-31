#![cfg(feature = "test-fixture")]

use std::{env, path::PathBuf, process::ExitCode};

use trnm_consensus_unix_fleet_signer::test_fixture::{serve_fixture, FixtureModeV1};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let socket = match args.next() {
        Some(value) => PathBuf::from(value),
        None => return fail("missing socket path"),
    };
    let mode = match args.next() {
        Some(value) => match FixtureModeV1::parse(&value) {
            Ok(mode) => mode,
            Err(error) => return fail(&error),
        },
        None => return fail("missing fixture mode"),
    };
    let request_count = match args.next() {
        Some(value) => match value.parse::<usize>() {
            Ok(count) => count,
            Err(error) => return fail(&format!("invalid request count: {error}")),
        },
        None => return fail("missing request count"),
    };
    match serve_fixture(socket, mode, request_count) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&error),
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("trnm-fleet-root-signer-test-fixture: {message}");
    ExitCode::from(2)
}
