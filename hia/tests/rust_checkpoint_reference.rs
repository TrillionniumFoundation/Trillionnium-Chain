//! Test-only bridge to the retained original trnm-checkpoint-types crate.
//!
//! Compile its exact locked dependencies, then link this standalone fixture:
//!   cargo build --locked --manifest-path trillionnium/Cargo.toml \
//!       -p trnm-checkpoint-types --target-dir /tmp/checkpoint-reference
//!   rustc --edition=2021 -O hia/tests/rust_checkpoint_reference.rs \
//!       --extern trnm_checkpoint_types=/tmp/checkpoint-reference/debug/libtrnm_checkpoint_types.rlib \
//!       -L dependency=/tmp/checkpoint-reference/debug/deps -o /tmp/trnm-rust-checkpoint
//!
//! stdin: INPUT_HEX INITIAL_OUTPUT_HEX, using '-' for an empty buffer.
//! stdout: STATUS FULL_OUTPUT_HEX. CPV2 envelopes are documented in
//! test_checkpoint.py. All value checks, hashes and successor checks call the
//! original crate. There is no storage backend, CAS, frontier freshness or host
//! root reconciliation in this fixture; it is not a production dependency.

use std::io::{self, BufRead, Write};
use trnm_checkpoint_types::{
    BlockId, EffectWatermarkV2, ExternalCheckpointDecodeErrorV2,
    ExternalCheckpointFieldsV2, ExternalCheckpointV2, StateRoot,
};

fn error_code(error: ExternalCheckpointDecodeErrorV2) -> u32 {
    match error {
        ExternalCheckpointDecodeErrorV2::WrongLength => 1,
        ExternalCheckpointDecodeErrorV2::WrongMagic => 2,
        ExternalCheckpointDecodeErrorV2::UnsupportedSchema => 3,
        ExternalCheckpointDecodeErrorV2::ChecksumMismatch => 24,
        ExternalCheckpointDecodeErrorV2::InvalidField(field) => match field {
            "effect watermark" => 4,
            "signer watermark" => 5,
            "scope" => 6,
            "safety journal id" => 7,
            "safety verifier profile" => 8,
            "safety state record checksum" => 9,
            "safety record chain checksum" => 10,
            "application host config" => 11,
            "application projection profile" => 12,
            "application safety binding manifest checksum" => 13,
            "application committed head row checksum" => 14,
            "application recovery closure checksum" => 15,
            "signer journal id" => 16,
            "signer profile checksum" => 17,
            "application block id" => 18,
            "application state root" => 19,
            "generation-zero predecessor" => 20,
            "successor predecessor" => 21,
            "signer watermark scope" => 22,
            "signer watermark journal id" => 23,
            "successor scope" => 25,
            "successor generation overflow" => 26,
            "successor generation" => 27,
            "successor checkpoint checksum" => 28,
            other => panic!("unmapped original checkpoint field error: {other}"),
        },
    }
}

fn bytes32(raw: &[u8], offset: usize) -> [u8; 32] {
    raw[offset..offset + 32].try_into().expect("bounded envelope")
}

fn be64(raw: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(raw[offset..offset + 8].try_into().expect("bounded envelope"))
}

fn watermark(raw: &[u8]) -> Result<EffectWatermarkV2, u32> {
    EffectWatermarkV2::from_persisted_parts(
        bytes32(raw, 0), bytes32(raw, 32), be64(raw, 64), bytes32(raw, 72),
    )
    .map_err(error_code)
}

fn construct(fields: &[u8]) -> Result<ExternalCheckpointV2, u32> {
    // A layout adapter only: field validity and checksum construction are
    // exclusively delegated to the original public constructors.
    let mut prefix = vec![0_u8; 16];
    prefix.extend_from_slice(fields);
    let raw = prefix.as_slice();
    let effect_exact_watermark = watermark(&raw[536..640])?;
    ExternalCheckpointV2::new(ExternalCheckpointFieldsV2 {
        scope: bytes32(raw, 16),
        generation: be64(raw, 48),
        predecessor_checksum: bytes32(raw, 56),
        authority_journal_id: bytes32(raw, 88),
        authority_verifier_profile_ref: bytes32(raw, 120),
        authority_revision: be64(raw, 152),
        authority_state_record_checksum: bytes32(raw, 160),
        authority_record_chain_checksum: bytes32(raw, 192),
        application_host_config_ref: bytes32(raw, 224),
        application_projection_profile_ref: bytes32(raw, 256),
        application_authority_binding_manifest_checksum: bytes32(raw, 288),
        application_committed_head_row_checksum: bytes32(raw, 320),
        application_recovery_closure_checksum: bytes32(raw, 352),
        application_block_id: BlockId::new(bytes32(raw, 384)),
        application_height: be64(raw, 416),
        application_state_root: StateRoot::new(bytes32(raw, 424)),
        application_generation: be64(raw, 456),
        application_timestamp_ms: be64(raw, 464),
        effect_journal_id: bytes32(raw, 472),
        effect_profile_checksum: bytes32(raw, 504),
        effect_exact_watermark,
    })
    .map_err(error_code)
}

fn evaluate(raw: &[u8], output: &mut [u8]) -> Result<(), u32> {
    if raw.len() < 8 {
        return Err(100);
    }
    if &raw[..5] != b"CPV2\x01" || raw[5] > 3 || raw[6..8] != [0, 0] {
        return Err(101);
    }
    let operation = raw[5];
    let body = &raw[8..];
    if body.len() != [672, 624, 1344, 104][usize::from(operation)] {
        return Err(1);
    }
    let result_size = if operation == 3 { 104 } else { 672 };
    if output.len() < result_size {
        return Err(102);
    }
    if operation == 3 {
        let value = watermark(body)?;
        output[..32].copy_from_slice(&value.scope());
        output[32..64].copy_from_slice(&value.journal_id());
        output[64..72].copy_from_slice(&value.sequence().to_be_bytes());
        output[72..104].copy_from_slice(&value.chain_checksum());
    } else {
        let value = match operation {
            0 => ExternalCheckpointV2::decode_canonical_exact(body).map_err(error_code)?,
            1 => construct(body)?,
            2 => {
                let predecessor = ExternalCheckpointV2::decode_canonical_exact(&body[..672])
                    .map_err(error_code)?;
                let target = ExternalCheckpointV2::decode_canonical_exact(&body[672..])
                    .map_err(error_code)?;
                target.validate_successor_of(&predecessor).map_err(error_code)?;
                target
            }
            _ => unreachable!("operation checked above"),
        };
        output[..672].copy_from_slice(&value.encode_canonical());
    }
    Ok(())
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if text.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    fn nibble(byte: u8) -> Result<u8, String> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("expected lowercase ASCII hex".into()),
        }
    }
    text.as_bytes().chunks_exact(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn encode_hex(raw: &[u8]) -> String {
    if raw.is_empty() {
        return "-".into();
    }
    const HEX: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(raw.len() * 2);
    for &byte in raw {
        result.push(HEX[usize::from(byte >> 4)] as char);
        result.push(HEX[usize::from(byte & 15)] as char);
    }
    result
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && args[0] == "--describe" {
        println!("TRNM-HIA-RUST-CHECKPOINT/1 original-crate value-only");
        return Ok(());
    }
    if !args.is_empty() {
        return Err("only --describe or stdin requests are supported".into());
    }
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());
    for (number, line) in stdin.lock().lines().enumerate() {
        let line = line.map_err(|error| error.to_string())?;
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.len() != 2 {
            return Err(format!("line {}: expected input and output hex", number + 1));
        }
        let raw = decode_hex(fields[0])?;
        let mut output = decode_hex(fields[1])?;
        let status = evaluate(&raw, &mut output).err().unwrap_or(0);
        writeln!(writer, "{status} {}", encode_hex(&output)).map_err(|error| error.to_string())?;
    }
    writer.flush().map_err(|error| error.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Rust checkpoint reference fixture failed: {error}");
        std::process::exit(2);
    }
}
