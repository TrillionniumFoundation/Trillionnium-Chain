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
        "fixture-request" => fixture_request_hex(args.collect()),
        "truth" => print_truth(),
        _ => {
            eprintln!("usage: trnm-remote-signer-p0 <serve-fixture|fixture-request|truth> ...");
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
