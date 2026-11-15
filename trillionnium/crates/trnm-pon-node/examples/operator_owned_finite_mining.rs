//! Root-owned finite stdin control pipe. No RPC, signing keys, network or grant
//! generation. Root must hold this child under the original 90/60 leaf guardian.
use std::{
    io::{self, Write},
    path::Path,
    time::{Duration, Instant},
};
use trnm_pon_node::{operator_mining_controller::Controller, Result};
fn ensure(ok: bool, label: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(label.into())
    }
}
fn next_frame(pending: &mut Vec<u8>, deadline: Instant) -> Result<Option<Vec<u8>>> {
    loop {
        if let Some(end) = pending.iter().position(|b| *b == b'\n') {
            let frame: Vec<_> = pending.drain(..=end).collect();
            ensure(frame.len() <= 262144, "OWNER_MINING_FRAME_LIMIT")?;
            return Ok(Some(frame));
        }
        ensure(
            pending.len() <= 262144 && Instant::now() < deadline,
            "OWNER_MINING_FRAME_LIMIT",
        )?;
        let mut descriptor = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(50));
        // SAFETY: the one initialized pollfd and its stack storage remain valid
        // across this synchronous Linux syscall. No borrowed descriptor is closed.
        let result = unsafe { libc::poll(&mut descriptor, 1, wait.as_millis().max(1) as i32) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if result == 0 {
            continue;
        }
        ensure(
            descriptor.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
            "OWNER_MINING_STDIN",
        )?;
        let mut bytes = [0u8; 4096];
        // SAFETY: bytes is initialized writable storage of exactly bytes.len();
        // stdin is the Root-owned input pipe and read never outlives this buffer.
        let n = unsafe { libc::read(libc::STDIN_FILENO, bytes.as_mut_ptr().cast(), bytes.len()) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if n == 0 {
            return if pending.is_empty() {
                Ok(None)
            } else {
                Ok(Some(std::mem::take(pending)))
            };
        }
        pending.extend_from_slice(&bytes[..n as usize]);
    }
}
fn publish(value: &serde_json::Value) -> Result<()> {
    let raw = serde_json::to_vec(value)?;
    ensure(raw.len() <= 2 * 1024 * 1024, "OWNER_MINING_RESULT_LIMIT")?;
    let mut output = io::stdout().lock();
    output.write_all(&raw)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
fn run() -> Result<()> {
    ensure(cfg!(target_os = "linux"), "OWNER_MINING_LINUX_REQUIRED")?;
    let started = Instant::now();
    let argv: Vec<_> = std::env::args().collect();
    ensure(argv.len() == 8, "OWNER_MINING_ARGUMENTS")?;
    // Seven public, externally fixed arguments: launch path/hash, two public
    // keys, current source commit, policy source SHA, Registry2 source package.
    let mut controller = Controller::open_pinned(
        Path::new(&argv[1]),
        &argv[2],
        &argv[3],
        &argv[4],
        &argv[5],
        &argv[6],
        &argv[7],
        started,
    )?;
    publish(
        &serde_json::json!({"schema":"restricted-owner-finite-mining-startup-v1",
        "cpu":controller.startup_cpu(),"public_network_ready":false}),
    )?;
    let mut pending = Vec::new();
    while let Some(frame) = next_frame(&mut pending, controller.deadline())? {
        publish(&controller.apply(&frame)?)?;
    }
    publish(
        &serde_json::json!({"schema":"restricted-owner-finite-mining-pipe-closed-v1",
        "control_pipe_closed":true,"scientific_acceptance":false,"public_network_ready":false}),
    )
}
fn main() {
    if run().is_err() {
        // Static label only: no unbounded config/body/token/error representation.
        eprintln!("OWNER_MINING_FINITE_CONTROLLER_FAILED");
        std::process::exit(1);
    }
}
