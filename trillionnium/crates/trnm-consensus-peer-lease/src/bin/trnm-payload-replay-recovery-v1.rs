#![forbid(unsafe_code)]

use std::{
    env,
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use trnm_consensus_peer_lease::{
    PayloadReplayCoreAcknowledgementV1, PayloadReplayDirectionV1, PayloadReplayNamespaceV1,
    PayloadReplayRecoveryOwnerV1, PayloadReplayRecoveryStatusV1, PayloadReplayRecoveryTargetV1,
    PeerLeaseDirectionV1,
};

const BASE_ARGUMENT_COUNT: usize = 19;
const JSON_SCHEMA_V1: &str = "trnm.payload-replay-recovery.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormatV1 {
    KeyValue,
    Json,
}

fn main() -> ExitCode {
    // Keep the historical key=value stream as the default for existing
    // operators, while allowing an explicit machine-readable envelope.  The
    // format flag is accepted in any position so wrappers can append it
    // without having to reorder the long positional identity tuple.
    let requested_json = env::args().skip(1).any(|argument| argument == "--json");
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if requested_json {
                eprintln!("{}", json_error(&error));
            } else {
                eprintln!("payload replay recovery refused: {error}");
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let (format, arguments) = extract_output_format(env::args().collect::<Vec<_>>())?;
    run_with_format(arguments, format)
}

fn extract_output_format(arguments: Vec<String>) -> Result<(OutputFormatV1, Vec<String>), String> {
    let mut filtered = Vec::with_capacity(arguments.len());
    let mut format = OutputFormatV1::KeyValue;
    let mut explicit_format = false;
    for (index, argument) in arguments.into_iter().enumerate() {
        if index == 0 {
            filtered.push(argument);
            continue;
        }
        let requested = match argument.as_str() {
            "--json" => Some(OutputFormatV1::Json),
            "--key-value" => Some(OutputFormatV1::KeyValue),
            _ => None,
        };
        if let Some(requested) = requested {
            if explicit_format {
                return Err("--json and --key-value may not be repeated or combined".to_owned());
            }
            explicit_format = true;
            format = requested;
        } else {
            filtered.push(argument);
        }
    }
    Ok((format, filtered))
}

fn run_with_format(arguments: Vec<String>, format: OutputFormatV1) -> Result<(), String> {
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

    let acknowledgement = if operation == "ack" {
        Some(
            PayloadReplayCoreAcknowledgementV1::new(
                target,
                parse_u64(&arguments[19], "core-safety-revision")?,
                parse_hex32(&arguments[20], "core-ack-digest")?,
            )
            .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };

    let mut owner =
        PayloadReplayRecoveryOwnerV1::open(payload_path, acknowledgement_root, namespace, target)
            .map_err(|error| error.to_string())?;
    // The owner pins descriptors and path identities.  Keep this explicit at
    // the process boundary so a future operation added below cannot
    // accidentally bypass the same fail-closed check.
    owner
        .verify_bound_endpoint_identity()
        .map_err(|error| error.to_string())?;

    match operation {
        "status" => println!(
            "{}",
            render_status(
                format,
                operation,
                owner.status().map_err(|error| error.to_string())?,
            )
        ),
        "recover" => println!(
            "{}",
            render_status(
                format,
                operation,
                owner
                    .recover_payload_publication()
                    .map_err(|error| error.to_string())?,
            )
        ),
        "ack" => {
            let acknowledgement = acknowledgement.expect("ack operation parsed above");
            let receipt = owner
                .acknowledge_core(acknowledgement)
                .map_err(|error| error.to_string())?;
            println!("{}", render_ack(format, acknowledgement, receipt));
        }
        _ => unreachable!("operation checked above"),
    }
    Ok(())
}

/// Reject ambiguous path spellings before opening any authority.  The owner
/// performs the stronger descriptor/path identity and private-ancestry checks;
/// this lexical boundary prevents a CLI caller from smuggling `.`/`..` or a
/// relative path into an operation whose evidence is expected to be bound to a
/// single absolute pathname.
fn validate_cli_path(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(format!("{label} must be a non-root absolute path"));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::Prefix(_)
        )
    }) {
        return Err(format!(
            "{label} must not contain '.', '..', or platform prefix components"
        ));
    }
    Ok(())
}

fn render_status(
    format: OutputFormatV1,
    operation: &str,
    status: PayloadReplayRecoveryStatusV1,
) -> String {
    match format {
        OutputFormatV1::KeyValue => render_status_key_value(status),
        OutputFormatV1::Json => render_status_json(operation, status),
    }
}

fn render_status_key_value(status: PayloadReplayRecoveryStatusV1) -> String {
    match status {
        PayloadReplayRecoveryStatusV1::RecoverableHeadLag {
            payload_record_count,
            payload_head_count,
            retained_temporary_count,
        } => format!(
            "status=recoverable_head_lag payload_record_count={payload_record_count} payload_head_count={payload_head_count} retained_temporary_count={retained_temporary_count} candidate_only=true core_acknowledged=false production=false"
        ),
        PayloadReplayRecoveryStatusV1::RecoverableResidualTemporaries {
            payload_record_count,
            retained_temporary_count,
        } => format!(
            "status=recoverable_residual_temporaries payload_record_count={payload_record_count} retained_temporary_count={retained_temporary_count} candidate_only=true core_acknowledged=false production=false"
        ),
        PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged {
            payload_record_count,
            payload_head_hash,
        } => format!(
            "status=admitted_unacknowledged payload_record_count={payload_record_count} payload_head_hash={} candidate_only=true core_acknowledged=false production=false",
            encode_hex32(payload_head_hash),
        ),
        PayloadReplayRecoveryStatusV1::CoreAcknowledged {
            payload_record_count,
            payload_head_hash,
            core_safety_revision,
            core_ack_digest,
            acknowledgement_hash,
        } => format!(
            "status=core_acknowledged payload_record_count={payload_record_count} payload_head_hash={} core_safety_revision={core_safety_revision} core_ack_digest={} acknowledgement_hash={} candidate_only=true atomic_with_core=false production=false",
            encode_hex32(payload_head_hash),
            encode_hex32(core_ack_digest),
            encode_hex32(acknowledgement_hash),
        ),
    }
}

fn render_status_json(operation: &str, status: PayloadReplayRecoveryStatusV1) -> String {
    let mut output = String::from("{");
    let mut first = true;
    json_string_field(&mut output, &mut first, "schema", JSON_SCHEMA_V1);
    json_string_field(&mut output, &mut first, "operation", operation);
    json_string_field(&mut output, &mut first, "status", status.kind());
    match status {
        PayloadReplayRecoveryStatusV1::RecoverableHeadLag {
            payload_record_count,
            payload_head_count,
            retained_temporary_count,
        } => {
            json_u64_field(
                &mut output,
                &mut first,
                "payload_record_count",
                payload_record_count,
            );
            json_u64_field(
                &mut output,
                &mut first,
                "payload_head_count",
                payload_head_count,
            );
            json_u64_field(
                &mut output,
                &mut first,
                "retained_temporary_count",
                u64::from(retained_temporary_count),
            );
            json_bool_field(&mut output, &mut first, "core_acknowledged", false);
        }
        PayloadReplayRecoveryStatusV1::RecoverableResidualTemporaries {
            payload_record_count,
            retained_temporary_count,
        } => {
            json_u64_field(
                &mut output,
                &mut first,
                "payload_record_count",
                payload_record_count,
            );
            json_u64_field(
                &mut output,
                &mut first,
                "retained_temporary_count",
                u64::from(retained_temporary_count),
            );
            json_bool_field(&mut output, &mut first, "core_acknowledged", false);
        }
        PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged {
            payload_record_count,
            payload_head_hash,
        } => {
            json_u64_field(
                &mut output,
                &mut first,
                "payload_record_count",
                payload_record_count,
            );
            json_string_field(
                &mut output,
                &mut first,
                "payload_head_hash",
                &encode_hex32(payload_head_hash),
            );
            json_bool_field(&mut output, &mut first, "core_acknowledged", false);
        }
        PayloadReplayRecoveryStatusV1::CoreAcknowledged {
            payload_record_count,
            payload_head_hash,
            core_safety_revision,
            core_ack_digest,
            acknowledgement_hash,
        } => {
            json_u64_field(
                &mut output,
                &mut first,
                "payload_record_count",
                payload_record_count,
            );
            json_string_field(
                &mut output,
                &mut first,
                "payload_head_hash",
                &encode_hex32(payload_head_hash),
            );
            json_u64_field(
                &mut output,
                &mut first,
                "core_safety_revision",
                core_safety_revision,
            );
            json_string_field(
                &mut output,
                &mut first,
                "core_ack_digest",
                &encode_hex32(core_ack_digest),
            );
            json_string_field(
                &mut output,
                &mut first,
                "acknowledgement_hash",
                &encode_hex32(acknowledgement_hash),
            );
            json_bool_field(&mut output, &mut first, "core_acknowledged", true);
        }
    }
    append_truth_fields(&mut output, &mut first);
    output.push('}');
    output
}

fn render_ack(
    format: OutputFormatV1,
    acknowledgement: PayloadReplayCoreAcknowledgementV1,
    receipt: trnm_consensus_peer_lease::PayloadReplayCoreAckReceiptV1,
) -> String {
    match format {
        OutputFormatV1::KeyValue => format!(
            "status=core_ack_recorded acknowledgement_hash={} idempotent_replay={} candidate_only=true atomic_with_core=false production=false",
            encode_hex32(receipt.acknowledgement_hash()),
            receipt.idempotent_replay(),
        ),
        OutputFormatV1::Json => {
            let mut output = String::from("{");
            let mut first = true;
            json_string_field(&mut output, &mut first, "schema", JSON_SCHEMA_V1);
            json_string_field(&mut output, &mut first, "operation", "ack");
            json_string_field(&mut output, &mut first, "status", "core_ack_recorded");
            json_string_field(
                &mut output,
                &mut first,
                "acknowledgement_hash",
                &encode_hex32(receipt.acknowledgement_hash()),
            );
            json_bool_field(
                &mut output,
                &mut first,
                "idempotent_replay",
                receipt.idempotent_replay(),
            );
            json_u64_field(
                &mut output,
                &mut first,
                "core_safety_revision",
                acknowledgement.core_safety_revision(),
            );
            json_string_field(
                &mut output,
                &mut first,
                "core_ack_digest",
                &encode_hex32(acknowledgement.core_ack_digest()),
            );
            append_truth_fields(&mut output, &mut first);
            output.push('}');
            output
        }
    }
}

fn append_truth_fields(output: &mut String, first: &mut bool) {
    json_bool_field(output, first, "candidate_only", true);
    json_bool_field(output, first, "production", false);
    json_bool_field(output, first, "production_activation", false);
    json_bool_field(output, first, "atomic_with_core", false);
}

fn json_string_field(output: &mut String, first: &mut bool, key: &str, value: &str) {
    json_separator(output, first);
    output.push_str(&json_quote(key));
    output.push(':');
    output.push_str(&json_quote(value));
}

fn json_u64_field(output: &mut String, first: &mut bool, key: &str, value: u64) {
    json_separator(output, first);
    output.push_str(&json_quote(key));
    output.push(':');
    output.push_str(&value.to_string());
}

fn json_bool_field(output: &mut String, first: &mut bool, key: &str, value: bool) {
    json_separator(output, first);
    output.push_str(&json_quote(key));
    output.push(':');
    output.push_str(if value { "true" } else { "false" });
}

fn json_separator(output: &mut String, first: &mut bool) {
    if !*first {
        output.push(',');
    }
    *first = false;
}

fn json_quote(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn json_error(error: &str) -> String {
    let mut output = String::from("{");
    let mut first = true;
    json_string_field(&mut output, &mut first, "schema", JSON_SCHEMA_V1);
    json_string_field(&mut output, &mut first, "status", "error");
    json_string_field(&mut output, &mut first, "error", error);
    append_truth_fields(&mut output, &mut first);
    output.push('}');
    output
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
        output[index] =
            (decode_hex_nibble(chunk[0], name)? << 4) | decode_hex_nibble(chunk[1], name)?;
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
    "usage: trnm-payload-replay-recovery-v1 [--json|--key-value] <status|recover|ack> \
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

    #[test]
    fn output_flags_are_explicit_and_cannot_be_combined() {
        let (format, arguments) = extract_output_format(vec![
            "recovery".to_owned(),
            "status".to_owned(),
            "--json".to_owned(),
        ])
        .expect("json flag");
        assert_eq!(format, OutputFormatV1::Json);
        assert_eq!(arguments, ["recovery", "status"]);

        let (format, arguments) = extract_output_format(vec![
            "recovery".to_owned(),
            "status".to_owned(),
            "--key-value".to_owned(),
        ])
        .expect("key-value flag");
        assert_eq!(format, OutputFormatV1::KeyValue);
        assert_eq!(arguments, ["recovery", "status"]);
        assert!(extract_output_format(vec![
            "recovery".to_owned(),
            "--json".to_owned(),
            "--key-value".to_owned(),
        ])
        .is_err());
    }

    #[test]
    fn cli_paths_must_be_absolute_and_dot_free() {
        assert!(validate_cli_path(Path::new("relative.wal"), "wal").is_err());
        assert!(validate_cli_path(Path::new("/"), "wal").is_err());
        assert!(validate_cli_path(Path::new("/tmp/../wal"), "wal").is_err());
        assert!(validate_cli_path(Path::new("/tmp/.wal"), "wal").is_ok());
    }

    #[test]
    fn json_status_is_single_object_with_candidate_truth_fields() {
        let output = render_status_json(
            "status",
            PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged {
                payload_record_count: 2,
                payload_head_hash: [0xabu8; 32],
            },
        );
        assert!(output.starts_with('{') && output.ends_with('}'));
        assert!(!output.contains('='));
        assert!(output.contains("\"schema\":\"trnm.payload-replay-recovery.v1\""));
        assert!(output.contains("\"status\":\"admitted_unacknowledged\""));
        assert!(output.contains("\"candidate_only\":true"));
        assert!(output.contains("\"production\":false"));
        assert!(output.contains("\"atomic_with_core\":false"));
    }

    #[test]
    fn json_quote_escapes_control_and_delimiter_bytes() {
        assert_eq!(json_quote("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
    }
}
