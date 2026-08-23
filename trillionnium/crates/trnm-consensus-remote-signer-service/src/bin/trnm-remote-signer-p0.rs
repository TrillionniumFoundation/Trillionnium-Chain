//! Small standalone executable for the remote-signer P0 slice.
//!
//! This binary intentionally exposes only a deterministic fixture mode.  It
//! is useful for transport tests and local review, not a validator deployment
//! configuration or a consensus-runtime entry point.

use std::{env, path::PathBuf, process::ExitCode};

use trnm_consensus_remote_signer_service::{
    fixture_request, fixture_service_config_with_binding, Fixture, PurposePolicyV1,
    RemoteSignerService, REMOTE_SIGNER_SERVICE_CONSENSUS_RUNTIME_INTEGRATION_V1,
    REMOTE_SIGNER_SERVICE_PRODUCTION_SIGNATURE_PRODUCER_V1,
    REMOTE_SIGNER_SERVICE_RUNTIME_ACTIVATION_V1,
};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let result = match command.as_str() {
        "serve-fixture" => serve_fixture(args.collect()),
        "serve-external-timeout" => serve_external_timeout(args.collect()),
        "fixture-request" => fixture_request_hex(args.collect()),
        "truth" => print_truth(),
        _ => {
            eprintln!(
                "usage: trnm-remote-signer-p0 <serve-fixture|serve-external-timeout|fixture-request|truth> ..."
            );
            Err("unknown command".to_owned())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("trnm-remote-signer-p0: {error}");
            ExitCode::from(2)
        }
    }
}

/// Runs the explicit external-authority timeout daemon.
///
/// This mode is intentionally separate from `serve-fixture`: it requires a
/// second Unix authority socket and a response-binding log, fixes the signer
/// purpose policy to timeout-only, and never has a local SQLite fallback. The
/// deterministic fixture binding is only a test harness for constructing the
/// exact protocol context; it is not a credential/configuration loader for a
/// validator deployment.
fn serve_external_timeout(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_external_timeout_args(&args)?;
    let fixture = Fixture::new();
    let binding = fixture
        .binding_for_generation_and_lease(parsed.generation, parsed.lease_material.as_bytes())?;
    let config = fixture_service_config_with_binding(
        &parsed.watermark,
        PurposePolicyV1::timeout_vote_only(),
        fixture.validator_set,
        binding,
        fixture.signing_key,
    );
    let mut service = RemoteSignerService::open_with_external_timeout_authority(
        config,
        &parsed.authority_socket,
        &parsed.response_log,
        parsed.capability,
    )
    .map_err(|error| error.to_string())?;
    if let Some(expected_scope) = parsed.scope {
        if service.scope() != expected_scope {
            return Err("--scope does not match the derived signer binding".to_owned());
        }
    }
    service
        .serve_unix(&parsed.socket)
        .map_err(|error| error.to_string())
}

struct ExternalTimeoutArgs {
    socket: PathBuf,
    watermark: PathBuf,
    authority_socket: PathBuf,
    response_log: PathBuf,
    capability: [u8; 32],
    generation: u64,
    lease_material: String,
    scope: Option<[u8; 32]>,
}

fn parse_external_timeout_args(args: &[String]) -> Result<ExternalTimeoutArgs, String> {
    let mut socket = None;
    let mut watermark = None;
    let mut authority_socket = None;
    let mut response_log = None;
    let mut capability = None;
    let mut generation = None;
    let mut lease_material = None;
    let mut scope = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = match args.get(index + 1) {
            Some(value) if !value.starts_with('-') => value.clone(),
            _ => return Err(format!("missing value for {flag}")),
        };
        match flag {
            "--socket" => set_once(&mut socket, PathBuf::from(value), flag)?,
            "--watermark" => set_once(&mut watermark, PathBuf::from(value), flag)?,
            "--authority-socket" => set_once(&mut authority_socket, PathBuf::from(value), flag)?,
            "--response-log" => set_once(&mut response_log, PathBuf::from(value), flag)?,
            "--capability" => set_once(&mut capability, decode_hex32(&value)?, flag)?,
            "--generation" => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --generation: {error}"))?;
                if parsed == 0 {
                    return Err("--generation must be positive".to_owned());
                }
                set_once(&mut generation, parsed, flag)?;
            }
            "--lease-material" => set_once(&mut lease_material, value, flag)?,
            "--scope" => set_once(&mut scope, decode_hex32(&value)?, flag)?,
            _ => return Err(format!("unsupported argument {flag}")),
        }
        index += 2;
    }
    let require_path = |value: Option<PathBuf>, flag: &str| {
        value
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| format!("missing {flag}"))
    };
    Ok(ExternalTimeoutArgs {
        socket: require_path(socket, "--socket")?,
        watermark: require_path(watermark, "--watermark")?,
        authority_socket: require_path(authority_socket, "--authority-socket")?,
        response_log: require_path(response_log, "--response-log")?,
        capability: capability.ok_or_else(|| "missing --capability".to_owned())?,
        generation: generation.unwrap_or(1),
        lease_material: lease_material.unwrap_or_else(|| "p0-lease".to_owned()),
        scope,
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate argument {flag}"));
    }
    Ok(())
}

fn serve_fixture(args: Vec<String>) -> Result<(), String> {
    let socket = required_path(&args, "--socket")?;
    let watermark = required_path(&args, "--watermark")?;
    let generation = optional_value(&args, "--generation")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("invalid --generation: {error}"))
        })
        .transpose()?
        .unwrap_or(1);
    let lease_material =
        optional_value(&args, "--lease-material").unwrap_or_else(|| "p0-lease".to_owned());
    let policy = match optional_value(&args, "--purpose").as_deref() {
        None | Some("both") => PurposePolicyV1::both(),
        Some("vote") => PurposePolicyV1::vote_only(),
        Some("timeout") => PurposePolicyV1::timeout_vote_only(),
        Some(other) => return Err(format!("unsupported --purpose {other}")),
    };
    let fixture = Fixture::new();
    let binding =
        fixture.binding_for_generation_and_lease(generation, lease_material.as_bytes())?;
    let mut service = RemoteSignerService::open(fixture_service_config_with_binding(
        &watermark,
        policy,
        fixture.validator_set,
        binding,
        fixture.signing_key,
    ))
    .map_err(|error| error.to_string())?;
    service
        .serve_unix(&socket)
        .map_err(|error| error.to_string())
}

fn fixture_request_hex(args: Vec<String>) -> Result<(), String> {
    let kind = optional_value(&args, "--kind").ok_or_else(|| "missing --kind".to_owned())?;
    let view = optional_value(&args, "--view")
        .ok_or_else(|| "missing --view".to_owned())?
        .parse::<u64>()
        .map_err(|error| format!("invalid --view: {error}"))?;
    let nonce = optional_value(&args, "--nonce").ok_or_else(|| "missing --nonce".to_owned())?;
    let fixture = Fixture::new();
    let request = fixture_request(&fixture, &kind, view, nonce.as_bytes())
        .map_err(|error| error.to_string())?;
    let bytes = request
        .try_exact_bytes()
        .map_err(|error| format!("encode fixture request: {error}"))?;
    println!("{}", hex_encode(&bytes));
    Ok(())
}

fn print_truth() -> Result<(), String> {
    println!(
        "runtime_activation={}\nproduction_signature_producer={}\nconsensus_runtime_integration={}",
        REMOTE_SIGNER_SERVICE_RUNTIME_ACTIVATION_V1,
        REMOTE_SIGNER_SERVICE_PRODUCTION_SIGNATURE_PRODUCER_V1,
        REMOTE_SIGNER_SERVICE_CONSENSUS_RUNTIME_INTEGRATION_V1
    );
    Ok(())
}

fn required_path(args: &[String], flag: &str) -> Result<PathBuf, String> {
    optional_value(args, flag)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {flag}"))
}

fn optional_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}

fn decode_hex32(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 64 {
        return Err("expected exactly 64 hexadecimal characters");
    }
    let mut bytes = [0_u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let high = hex_nibble(value.as_bytes()[index * 2]).ok_or("non-hex capability")?;
        let low = hex_nibble(value.as_bytes()[index * 2 + 1]).ok_or("non-hex capability")?;
        *slot = (high << 4) | low;
    }
    if bytes == [0; 32] {
        return Err("capability must not be all zero");
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{decode_hex32, parse_external_timeout_args};

    fn required_args() -> Vec<String> {
        vec![
            "--socket".into(),
            "/tmp/signer.sock".into(),
            "--watermark".into(),
            "/tmp/signer.sqlite3".into(),
            "--authority-socket".into(),
            "/tmp/authority.sock".into(),
            "--response-log".into(),
            "/tmp/responses.log".into(),
            "--capability".into(),
            "11".repeat(32),
        ]
    }

    #[test]
    fn external_timeout_args_are_explicit_and_timeout_scoped() {
        let mut args = required_args();
        args.extend([
            "--generation".into(),
            "7".into(),
            "--lease-material".into(),
            "lease-seven".into(),
            "--scope".into(),
            "22".repeat(32),
        ]);
        let parsed = parse_external_timeout_args(&args).expect("parse explicit mode");
        assert_eq!(parsed.generation, 7);
        assert_eq!(parsed.lease_material, "lease-seven");
        assert_eq!(parsed.capability, [0x11; 32]);
        assert_eq!(parsed.scope, Some([0x22; 32]));
    }

    #[test]
    fn external_timeout_args_reject_missing_or_ambiguous_authority() {
        let mut missing = required_args();
        missing
            .iter_mut()
            .find(|value| value.as_str() == "--capability")
            .map(|value| *value = "--unknown".into());
        assert!(parse_external_timeout_args(&missing).is_err());

        let mut duplicate = required_args();
        duplicate.extend(["--capability".into(), "22".repeat(32)]);
        assert!(parse_external_timeout_args(&duplicate).is_err());

        let mut unknown = required_args();
        unknown.extend(["--purpose".into(), "both".into()]);
        assert!(parse_external_timeout_args(&unknown).is_err());
    }

    #[test]
    fn capability_hex_is_exact_nonzero_32_bytes() {
        assert_eq!(
            decode_hex32(&"Aa".repeat(32)).expect("mixed case hex"),
            [0xaa; 32]
        );
        assert!(decode_hex32("00").is_err());
        assert!(decode_hex32(&"00".repeat(32)).is_err());
        assert!(decode_hex32(&"gg".repeat(32)).is_err());
    }
}
