use std::{env, ffi::OsString, path::PathBuf, process::ExitCode};

use trnm_consensus_external_node_checkpoint::run_daemon;

mod node_commit_ledger_v1;

use node_commit_ledger_v1::{
    read_checkpoint_file_v1, NodeCommitConvergenceV1, NodeCommitLedgerV1,
    NODE_COMMIT_LEDGER_EXACT_SOURCE_OR_TARGET_V1, NODE_COMMIT_LEDGER_IMPLEMENTED_V1,
    NODE_COMMIT_LEDGER_PRODUCTION_ACTIVATION_V1,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n  trnm-external-node-checkpoint-v0 <socket-path> <log-path>\n  trnm-external-node-checkpoint-v0 ledger-init <ledger-dir> <anchor-checkpoint-bin>\n  trnm-external-node-checkpoint-v0 ledger-advance <ledger-dir> <source-checkpoint-bin> <target-checkpoint-bin>\n  trnm-external-node-checkpoint-v0 ledger-resolve <ledger-dir> <source-checkpoint-bin> <target-checkpoint-bin>"
    );
    std::process::exit(64);
}

fn fail(error: impl std::fmt::Display) -> ExitCode {
    eprintln!("external node-checkpoint authority failed: {error}");
    ExitCode::from(1)
}

fn next_path(args: &mut impl Iterator<Item = OsString>) -> PathBuf {
    args.next().map(PathBuf::from).unwrap_or_else(|| usage())
}

fn main() -> ExitCode {
    let _candidate_contract = (
        NODE_COMMIT_LEDGER_IMPLEMENTED_V1,
        NODE_COMMIT_LEDGER_EXACT_SOURCE_OR_TARGET_V1,
        NODE_COMMIT_LEDGER_PRODUCTION_ACTIVATION_V1,
    );
    let mut args = env::args_os();
    let _program = args.next();
    let first = args.next().unwrap_or_else(|| usage());

    match first.to_str() {
        Some("ledger-init") => {
            let root = next_path(&mut args);
            let anchor_path = next_path(&mut args);
            if args.next().is_some() {
                usage();
            }
            let anchor = match read_checkpoint_file_v1(&anchor_path) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            match NodeCommitLedgerV1::initialize_new(root, anchor) {
                Ok(ledger) => {
                    let head = ledger.head();
                    println!(
                        "node_commit_ledger_v1 status=initialized sequence={} checkpoint_generation={} record_digest={}",
                        head.sequence,
                        head.checkpoint.generation(),
                        hex_digest(head.record_digest)
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(error),
            }
        }
        Some("ledger-advance") => {
            let root = next_path(&mut args);
            let source_path = next_path(&mut args);
            let target_path = next_path(&mut args);
            if args.next().is_some() {
                usage();
            }
            let source = match read_checkpoint_file_v1(&source_path) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let target = match read_checkpoint_file_v1(&target_path) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let mut ledger = match NodeCommitLedgerV1::open_existing(root) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            match ledger.append_exact_successor(source, target) {
                Ok(head) => {
                    println!(
                        "node_commit_ledger_v1 status=target sequence={} checkpoint_generation={} record_digest={}",
                        head.sequence,
                        head.checkpoint.generation(),
                        hex_digest(head.record_digest)
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(error),
            }
        }
        Some("ledger-resolve") => {
            let root = next_path(&mut args);
            let source_path = next_path(&mut args);
            let target_path = next_path(&mut args);
            if args.next().is_some() {
                usage();
            }
            let source = match read_checkpoint_file_v1(&source_path) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let target = match read_checkpoint_file_v1(&target_path) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let mut ledger = match NodeCommitLedgerV1::open_existing(root) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            match ledger.resolve_exact_source_or_target(source, target) {
                Ok(NodeCommitConvergenceV1::Source) => {
                    println!("node_commit_ledger_v1 convergence=source");
                    ExitCode::SUCCESS
                }
                Ok(NodeCommitConvergenceV1::Target) => {
                    println!("node_commit_ledger_v1 convergence=target");
                    ExitCode::SUCCESS
                }
                Err(error) => fail(error),
            }
        }
        _ => {
            let socket = PathBuf::from(first);
            let log = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            match run_daemon(socket, log) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(error),
            }
        }
    }
}

fn hex_digest(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
