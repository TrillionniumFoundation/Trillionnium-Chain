#![forbid(unsafe_code)]

//! Candidate-only process entry point for the persistent payload-replay
//! recovery owner.  The namespace and exact target are fixed at startup; the
//! socket protocol cannot retarget an already-open owner.
//!
//! Socket schema: `trnm.payload-replay-recovery-owner-socket.v1`.

#[cfg(unix)]
use std::{
    env,
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

#[cfg(unix)]
use trnm_consensus_peer_lease::{
    PayloadReplayDirectionV1, PayloadReplayNamespaceV1, PayloadReplayRecoveryDaemonV1,
    PayloadReplayRecoveryTargetV1, PAYLOAD_REPLAY_RECOVERY_SOCKET_SCHEMA_V1,
};

#[cfg(unix)]
const ARGUMENT_COUNT_V1: usize = 19;

#[cfg(unix)]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "payload replay recovery owner refused: {error} schema={PAYLOAD_REPLAY_RECOVERY_SOCKET_SCHEMA_V1} candidate_only=true production=false atomic_with_core=false"
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("payload replay recovery owner requires a Unix socket");
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
fn run() -> Result<(), String> {
    let arguments = env::args().collect::<Vec<_>>();
    if arguments.len() != ARGUMENT_COUNT_V1 {
        return Err(usage());
    }
    let socket_path = PathBuf::from(&arguments[1]);
    let payload_path = PathBuf::from(&arguments[2]);
    let acknowledgement_root = PathBuf::from(&arguments[3]);
    validate_cli_path(&socket_path, "socket")?;
    validate_cli_path(&payload_path, "payload-wal")?;
    validate_cli_path(&acknowledgement_root, "ack-root")?;

    let namespace = PayloadReplayNamespaceV1::new(
        parse_hex32(&arguments[4], "local-id")?,
        parse_u64(&arguments[5], "epoch")?,
        parse_hex32(&arguments[6], "validator-set-id")?,
        parse_hex32(&arguments[7], "run-id-hash")?,
        parse_hex32(&arguments[8], "network-context-hash")?,
    )
    .map_err(|error| format!("invalid namespace: {error}"))?;
    let target = PayloadReplayRecoveryTargetV1::new(
        parse_u64(&arguments[9], "record-index")?,
        parse_hex32(&arguments[10], "record-hash")?,
        parse_hex32(&arguments[11], "remote-id")?,
        parse_direction(&arguments[12])?,
        parse_hex32(&arguments[13], "session-id")?,
        parse_u64(&arguments[14], "generation")?,
        parse_u64(&arguments[15], "sequence")?,
        parse_u8(&arguments[16], "frame-kind")?,
        parse_u32(&arguments[17], "payload-len")?,
        parse_hex32(&arguments[18], "frame-fingerprint")?,
    )
    .map_err(|error| format!("invalid target: {error}"))?;

    PayloadReplayRecoveryDaemonV1::new(
        socket_path,
        payload_path,
        acknowledgement_root,
        namespace,
        target,
    )
    .run()
    .map_err(|error| error.to_string())
}

#[cfg(unix)]
fn validate_cli_path(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "{label} must be a non-root absolute path without dot components"
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn parse_direction(value: &str) -> Result<PayloadReplayDirectionV1, String> {
    match value {
        "inbound" => Ok(PayloadReplayDirectionV1::Inbound),
        "outbound" => Ok(PayloadReplayDirectionV1::Outbound),
        _ => Err("direction must be inbound or outbound".to_owned()),
    }
}

#[cfg(unix)]
fn parse_u8(value: &str, name: &str) -> Result<u8, String> {
    value
        .parse::<u8>()
        .map_err(|_| format!("{name} must be an unsigned 8-bit integer"))
}

#[cfg(unix)]
fn parse_u32(value: &str, name: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("{name} must be an unsigned 32-bit integer"))
}

#[cfg(unix)]
fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an unsigned 64-bit integer"))
}

#[cfg(unix)]
fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!(
            "{name} must contain exactly 64 lowercase hex characters"
        ));
    }
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(pair[0], name)? << 4) | decode_nibble(pair[1], name)?;
    }
    Ok(output)
}

#[cfg(unix)]
fn decode_nibble(value: u8, name: &str) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(format!("{name} must use lowercase hexadecimal")),
    }
}

#[cfg(unix)]
fn usage() -> String {
    "usage: trnm-payload-replay-recovery-owner-v1 <socket> <payload-wal> <ack-root> \
<local-id-hex> <epoch> <validator-set-id-hex> <run-id-hash-hex> \
<network-context-hash-hex> <record-index> <record-hash-hex> <remote-id-hex> \
<inbound|outbound> <session-id-hex> <generation> <sequence> <frame-kind> \
<payload-len> <frame-fingerprint-hex>"
        .to_owned()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn startup_argument_shape_is_stable() {
        assert_eq!(ARGUMENT_COUNT_V1, 19);
        assert!(validate_cli_path(Path::new("/tmp/recovery.sock"), "socket").is_ok());
        assert!(validate_cli_path(Path::new("relative.sock"), "socket").is_err());
    }
}
