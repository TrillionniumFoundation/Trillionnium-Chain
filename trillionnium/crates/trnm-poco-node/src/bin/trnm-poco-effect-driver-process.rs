#![forbid(unsafe_code)]

//! Candidate-only OS process for the Core effect-driver and P2P seams.

use std::{
    env,
    io::{self, BufReader, BufWriter},
    path::PathBuf,
    process::ExitCode,
};

use trnm_poco_node::run_effect_driver_process_stdio_v1;

#[cfg(unix)]
use trnm_poco_node::run_p2p_socket_once_v1;

#[cfg(unix)]
fn run_peer_lease_daemon(args: &mut impl Iterator<Item = std::ffi::OsString>) -> ExitCode {
    let (Some(socket), Some(journal)) = (args.next(), args.next()) else {
        eprintln!("usage: trnm-poco-effect-driver-process --peer-lease-daemon <socket> <journal>");
        return ExitCode::FAILURE;
    };
    if args.next().is_some() {
        eprintln!("usage: trnm-poco-effect-driver-process --peer-lease-daemon <socket> <journal>");
        return ExitCode::FAILURE;
    }
    match trnm_consensus_peer_lease::run_daemon(PathBuf::from(socket), PathBuf::from(journal)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("PEER_LEASE_DAEMON_ERROR {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(first) = args.next() else {
        eprintln!("usage: trnm-poco-effect-driver-process <absolute-run-root>");
        return ExitCode::FAILURE;
    };

    if first == "--peer-lease-daemon" {
        #[cfg(unix)]
        {
            return run_peer_lease_daemon(&mut args);
        }
        #[cfg(not(unix))]
        {
            eprintln!("peer lease daemon mode requires Unix");
            return ExitCode::FAILURE;
        }
    }

    if first == "--p2p-socket-once" {
        #[cfg(unix)]
        {
            let (
                Some(root),
                Some(socket),
                Some(lease_socket),
                Some(replay),
                Some(run_id),
                Some(generation),
            ) = (
                args.next(),
                args.next(),
                args.next(),
                args.next(),
                args.next(),
                args.next(),
            )
            else {
                eprintln!("usage: trnm-poco-effect-driver-process --p2p-socket-once <root> <socket> <lease-socket> <replay> <run-id> <lease-generation>");
                return ExitCode::FAILURE;
            };
            if args.next().is_some() {
                eprintln!("usage: trnm-poco-effect-driver-process --p2p-socket-once <root> <socket> <lease-socket> <replay> <run-id> <lease-generation>");
                return ExitCode::FAILURE;
            }
            let Ok(generation) = generation.to_string_lossy().parse::<u64>() else {
                eprintln!("p2p lease generation must be an integer");
                return ExitCode::FAILURE;
            };
            return match run_p2p_socket_once_v1(
                PathBuf::from(root),
                PathBuf::from(socket),
                PathBuf::from(lease_socket),
                PathBuf::from(replay),
                run_id.to_string_lossy().into_owned(),
                generation,
            ) {
                Ok(summary) => {
                    eprintln!(
                        "P2P_SOCKET_PROCESS_SUMMARY generation={} ingress={} effects={} broadcasts={} status={:?}",
                        summary.generation,
                        summary.processed_ingress,
                        summary.processed_effects,
                        summary.broadcasts,
                        summary.status,
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("P2P_SOCKET_PROCESS_ERROR {error}");
                    ExitCode::FAILURE
                }
            };
        }
        #[cfg(not(unix))]
        {
            eprintln!("p2p socket mode requires Unix");
            return ExitCode::FAILURE;
        }
    }

    if args.next().is_some() {
        eprintln!("usage: trnm-poco-effect-driver-process <absolute-run-root>");
        return ExitCode::FAILURE;
    }
    match run_effect_driver_process_stdio_v1(
        PathBuf::from(first),
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
