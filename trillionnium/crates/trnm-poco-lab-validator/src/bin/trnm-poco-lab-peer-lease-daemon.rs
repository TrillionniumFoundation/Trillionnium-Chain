//! Test fixture process for the externally fenced mesh integration test.
//!
//! This binary is deliberately a thin wrapper around the standalone
//! `trnm-consensus-peer-lease` daemon.  It is not a validator, does not hold
//! consensus keys, and has no production activation surface.

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::mpsc::{self, TryRecvError},
    time::Duration,
};

use trnm_consensus_peer_lease::UnixPeerLeaseDaemonV1;

fn usage() -> ! {
    eprintln!(
        "usage: trnm-poco-lab-peer-lease-daemon --socket PATH --journal PATH [--ready-file PATH]"
    );
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
        usage()
    };
    let daemon = UnixPeerLeaseDaemonV1::new(&socket, &journal);
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
                let result = (|| -> std::io::Result<()> {
                    let parent = path.parent().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "ready parent")
                    })?;
                    ensure_private_ready_parent(parent)?;
                    let mut file = OpenOptions::new();
                    file.write(true)
                        .create_new(true)
                        .mode(0o600)
                        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
                    let mut file = file.open(&path)?;
                    file.write_all(b"ready\n")?;
                    file.sync_all()?;
                    let directory = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
                        .open(parent)?;
                    directory.sync_all()
                })();
                if let Err(error) = result {
                    eprintln!("ready file error: {error}");
                    return ExitCode::from(1);
                }
                break;
            }
            match result_receiver.try_recv() {
                Ok(result) => return report_result(result),
                Err(TryRecvError::Disconnected) => return ExitCode::from(1),
                Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }
    match thread.join() {
        Ok(()) => result_receiver
            .recv()
            .map(report_result)
            .unwrap_or_else(|_| ExitCode::from(1)),
        Err(_) => ExitCode::from(1),
    }
}

/// Ensure every component created for a ready marker is private. Existing
/// components are never chmod'd in place: a pre-existing non-private or
/// symlink component fails closed instead of silently changing an operator's
/// directory policy.
fn ensure_private_ready_parent(path: &Path) -> std::io::Result<()> {
    let mut missing = Vec::new();
    let mut cursor = path.to_path_buf();
    loop {
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) => {
                ensure_private_ready_directory(&metadata)?;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.clone());
                if !cursor.pop() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "ready parent has no existing ancestor",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }

    for directory in missing.iter().rev() {
        let created = match fs::create_dir(directory) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error),
        };
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "ready parent component is not a real directory",
            ));
        }
        if created {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let metadata = fs::symlink_metadata(directory)?;
        ensure_private_ready_directory(&metadata)?;
    }
    Ok(())
}

fn ensure_private_ready_directory(metadata: &fs::Metadata) -> std::io::Result<()> {
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ready parent must be a private directory",
        ));
    }
    Ok(())
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
