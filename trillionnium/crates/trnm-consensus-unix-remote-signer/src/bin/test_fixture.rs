#![cfg(feature = "test-fixture")]

use std::{env, path::PathBuf, process::ExitCode};

use trnm_consensus_unix_remote_signer::test_fixture::{serve_fixture, FixtureServerMode};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let socket = match args.next() {
        Some(value) => PathBuf::from(value),
        None => return fail("missing socket path"),
    };
    let mode = match args.next() {
        Some(value) => match FixtureServerMode::parse(&value) {
            Ok(mode) => mode,
            Err(error) => return fail(&error),
        },
        None => return fail("missing server mode"),
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
    eprintln!("trnm-remote-signer-test-fixture: {message}");
    ExitCode::from(2)
}
