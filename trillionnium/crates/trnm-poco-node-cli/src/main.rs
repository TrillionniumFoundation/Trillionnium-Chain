#![forbid(unsafe_code)]

use std::{
    env,
    io::{self, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let outcome = trnm_poco_node_cli::run_v0(&arguments);

    if !outcome.stdout().is_empty()
        && io::stdout()
            .write_all(outcome.stdout().as_bytes())
            .is_err()
    {
        return ExitCode::FAILURE;
    }
    if !outcome.stderr().is_empty()
        && io::stderr()
            .write_all(outcome.stderr().as_bytes())
            .is_err()
    {
        return ExitCode::FAILURE;
    }

    ExitCode::from(outcome.exit_code())
}
