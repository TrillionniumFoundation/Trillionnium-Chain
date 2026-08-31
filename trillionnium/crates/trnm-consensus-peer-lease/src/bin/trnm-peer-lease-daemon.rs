use std::{
    env,
    path::PathBuf,
    process::ExitCode,
    sync::mpsc::{self, TryRecvError},
    time::Duration,
};

use trnm_consensus_peer_lease::UnixPeerLeaseDaemonV1;

fn usage() -> ! {
    eprintln!("usage: trnm-peer-lease-daemon --socket PATH --journal PATH [--ready-file PATH]");
    std::process::exit(2);
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let mut socket = None;
    let mut journal = None;
    let mut ready_file = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--socket" => socket = args.next().map(PathBuf::from),
            "--journal" => journal = args.next().map(PathBuf::from),
            "--ready-file" => ready_file = args.next().map(PathBuf::from),
            "--help" | "-h" => usage(),
            _ => usage(),
        }
    }
    let (Some(socket), Some(journal)) = (socket, journal) else {
        usage();
    };
    let daemon = UnixPeerLeaseDaemonV1::new(&socket, &journal);
    // `run` verifies the journal before binding.  To avoid advertising a
    // corrupt authority, write readiness only after the socket exists.
    let ready = ready_file.clone();
    let socket_for_ready = socket.clone();
    let (result_sender, result_receiver) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        let result = daemon.run();
        let _ = result_sender.send(result);
    });
    if let Some(path) = ready {
        loop {
            if socket_for_ready.exists() {
                if let Some(parent) = path.parent() {
                    if let Err(error) = std::fs::create_dir_all(parent) {
                        eprintln!("ready directory error: {error}");
                        return ExitCode::from(1);
                    }
                }
                if let Err(error) = std::fs::write(path, b"ready\n") {
                    eprintln!("ready file error: {error}");
                    return ExitCode::from(1);
                }
                break;
            }
            match result_receiver.try_recv() {
                Ok(result) => return report_result(result),
                Err(TryRecvError::Disconnected) => {
                    eprintln!("peer lease daemon worker disconnected");
                    return ExitCode::from(1);
                }
                Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }
    match thread.join() {
        Ok(()) => match result_receiver.recv() {
            Ok(result) => report_result(result),
            Err(_) => ExitCode::from(1),
        },
        Err(_) => {
            eprintln!("peer lease daemon panicked");
            ExitCode::from(1)
        }
    }
}

fn report_result(result: Result<(), trnm_consensus_peer_lease::PeerLeaseErrorV1>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("peer lease daemon stopped: {error}");
            ExitCode::from(1)
        }
    }
}
