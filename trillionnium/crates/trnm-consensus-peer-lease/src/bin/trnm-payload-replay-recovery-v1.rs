#![forbid(unsafe_code)]

use std::{env, path::PathBuf, process::ExitCode};

use trnm_consensus_peer_lease::{
    PayloadReplayCoreAcknowledgementV1, PayloadReplayDirectionV1,
    PayloadReplayNamespaceV1, PayloadReplayRecoveryOwnerV1,
    PayloadReplayRecoveryStatusV1, PayloadReplayRecoveryTargetV1,
    PeerLeaseDirectionV1,
};

const BASE_ARGUMENT_COUNT: usize = 19;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("payload replay recovery refused: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().collect::<Vec<_>>();
    let operation = arguments.get(1).map(String::as_str).ok_or_else(usage)?;
    let expected_count = match operation {
        "status" | "recover" => BASE_ARGUMENT_COUNT,
        "ack" => BASE_ARGUMENT_COUNT + 2,
        _ => return Err(usage()),
    };
    if arguments.len() != expected_count {
        return Err(usage());
    }

    let payload_path = PathBuf::from(&arguments[2]);
    let acknowledgement_root = PathBuf::from(&arguments[3]);
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

    let mut owner = PayloadReplayRecoveryOwnerV1::open(
        payload_path,
        acknowledgement_root,
        namespace,
        target,
    )
    .map_err(|error| error.to_string())?;

    match operation {
        "status" => print_status(owner.status().map_err(|error| error.to_string())?),
        "recover" => print_status(
            owner
                .recover_payload_publication()
                .map_err(|error| error.to_string())?,
        ),
        "ack" => {
            let acknowledgement = PayloadReplayCoreAcknowledgementV1::new(
                target,
                parse_u64(&arguments[19], "core-safety-revision")?,
                parse_hex32(&arguments[20], "core-ack-digest")?,
            )
            .map_err(|error| error.to_string())?;
            let receipt = owner
                .acknowledge_core(acknowledgement)
                .map_err(|error| error.to_string())?;
            println!(
                "status=core_ack_recorded acknowledgement_hash={} idempotent_replay={} candidate_only=true atomic_with_core=false production=false",
                encode_hex32(receipt.acknowledgement_hash()),
                receipt.idempotent_replay(),
            );
        }
        _ => unreachable!("operation checked above"),
    }
    Ok(())
}

fn print_status(status: PayloadReplayRecoveryStatusV1) {
    match status {
        PayloadReplayRecoveryStatusV1::RecoverableHeadLag {
            payload_record_count,
            payload_head_count,
            retained_temporary_count,
        } => println!(
            "status=recoverable_head_lag payload_record_count={payload_record_count} payload_head_count={payload_head_count} retained_temporary_count={retained_temporary_count} candidate_only=true core_acknowledged=false production=false"
        ),
        PayloadReplayRecoveryStatusV1::RecoverableResidualTemporaries {
            payload_record_count,
            retained_temporary_count,
        } => println!(
            "status=recoverable_residual_temporaries payload_record_count={payload_record_count} retained_temporary_count={retained_temporary_count} candidate_only=true core_acknowledged=false production=false"
        ),
        PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged {
            payload_record_count,
            payload_head_hash,
        } => println!(
            "status=admitted_unacknowledged payload_record_count={payload_record_count} payload_head_hash={} candidate_only=true core_acknowledged=false production=false",
            encode_hex32(payload_head_hash),
        ),
        PayloadReplayRecoveryStatusV1::CoreAcknowledged {
            payload_record_count,
            payload_head_hash,
            core_safety_revision,
            core_ack_digest,
            acknowledgement_hash,
        } => println!(
            "status=core_acknowledged payload_record_count={payload_record_count} payload_head_hash={} core_safety_revision={core_safety_revision} core_ack_digest={} acknowledgement_hash={} candidate_only=true atomic_with_core=false production=false",
            encode_hex32(payload_head_hash),
            encode_hex32(core_ack_digest),
            encode_hex32(acknowledgement_hash),
        ),
    }
}

fn parse_direction(value: &str) -> Result<PayloadReplayDirectionV1, String> {
    match value {
        "inbound" => Ok(PeerLeaseDirectionV1::Inbound),
        "outbound" => Ok(PeerLeaseDirectionV1::Outbound),
        _ => Err("direction must be inbound or outbound".to_owned()),
    }
}

fn parse_u8(value: &str, name: &str) -> Result<u8, String> {
    value
        .parse::<u8>()
        .map_err(|_| format!("{name} must be an unsigned 8-bit integer"))
}

fn parse_u32(value: &str, name: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("{name} must be an unsigned 32-bit integer"))
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an unsigned 64-bit integer"))
}

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!(
            "{name} must contain exactly 64 lowercase hex characters"
        ));
    }
    let bytes = value.as_bytes();
    let mut output = [0u8; 32];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        output[index] = (decode_hex_nibble(chunk[0], name)? << 4)
            | decode_hex_nibble(chunk[1], name)?;
    }
    Ok(output)
}

fn decode_hex_nibble(value: u8, name: &str) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(format!("{name} must use lowercase hexadecimal")),
    }
}

fn encode_hex32(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn usage() -> String {
    "usage: trnm-payload-replay-recovery-v1 <status|recover|ack> \
<payload-wal> <ack-root> <local-id-hex> <epoch> <validator-set-id-hex> \
<run-id-hash-hex> <network-context-hash-hex> <record-index> \
<record-hash-hex> <remote-id-hex> <inbound|outbound> <session-id-hex> \
<generation> <sequence> <frame-kind> <payload-len> <frame-fingerprint-hex> \
[core-safety-revision core-ack-digest-hex]"
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_hex_parser_rejects_uppercase_and_wrong_length() {
        assert!(parse_hex32(&"a".repeat(64), "value").is_ok());
        assert!(parse_hex32(&"A".repeat(64), "value").is_err());
        assert!(parse_hex32(&"a".repeat(63), "value").is_err());
    }

    #[test]
    fn operation_argument_counts_are_stable() {
        assert_eq!(BASE_ARGUMENT_COUNT, 19);
        assert_eq!(BASE_ARGUMENT_COUNT + 2, 21);
    }
}
