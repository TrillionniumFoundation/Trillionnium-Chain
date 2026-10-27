//! Real segments of the unchanged complete W1 image. No partial receipt can
//! pass the final image/journal/claim-chain verifier or become a Chain permit.
use super::*;
use risc0_zkvm::sha::Sha256;
use risc0_zkvm::{ApiClient, Asset, AssetRequest, CompositeReceipt, ExitCode, ReceiptClaim};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

#[path = "segment_assemble.rs"]
mod assemble;
#[path = "segment_export.rs"]
mod export;

pub use assemble::assemble_segments;
pub use export::export_segments;

const MAX_SEGMENT_ASSET_BYTES: usize = 32 * 1024 * 1024;
const MAX_ALL_SEGMENT_ASSETS: u64 = 512 * 1024 * 1024;

fn sha(bytes: &[u8]) -> String {
    risc0_zkvm::sha::Impl::hash_bytes(bytes).to_string()
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut out = OpenOptions::new().write(true).create_new(true).open(path)?;
    out.write_all(bytes)?;
    out.sync_all()?;
    Ok(())
}

fn number(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .with_context(|| format!("missing unsigned {key}"))
}

fn session(dir: &Path) -> Result<Value> {
    let value: Value =
        serde_json::from_slice(&bounded_read(&dir.join("session.json"), 1024 * 1024)?)?;
    ensure!(
        value["schema"] == "pon-w1-full-session-assets-v1",
        "unknown session asset schema"
    );
    ensure!(
        value["segment_po2_limit"] == 18,
        "unreviewed segment profile"
    );
    ensure!(
        value["full_w1_guest_executed"] == true,
        "missing complete guest execution"
    );
    let manifest: Value = serde_json::from_str(include_str!("../../backend-manifest.json"))?;
    ensure!(
        value["image_id"] == manifest["guest_image_id"],
        "session image differs"
    );
    let segments = value["segments"]
        .as_array()
        .context("missing actual segment inventory")?;
    ensure!(
        !segments.is_empty() && segments.len() <= receipt_bounds::MAX_SEGMENTS,
        "session segment count budget"
    );
    ensure!(
        number(&value, "user_cycles")? <= MAX_SESSION_CYCLES,
        "session cycle budget"
    );
    ensure!(
        number(&value, "exported_segment_bytes")? <= MAX_ALL_SEGMENT_ASSETS,
        "session exported byte budget"
    );
    let mut asset_bytes = 0u64;
    let mut user_cycles = 0u64;
    let mut padded_cycles = 0u64;
    for (index, segment) in segments.iter().enumerate() {
        ensure!(
            number(segment, "index")? == index as u64,
            "segment order changed"
        );
        ensure!(
            (13..=18).contains(&number(segment, "po2")?),
            "segment dimension differs"
        );
        ensure!(
            number(segment, "bytes")? <= MAX_SEGMENT_ASSET_BYTES as u64,
            "segment asset byte budget"
        );
        ensure!(
            segment["file"] == format!("segment-{index}"),
            "segment filename changed"
        );
        asset_bytes = asset_bytes
            .checked_add(number(segment, "bytes")?)
            .context("segment bytes overflow")?;
        user_cycles = user_cycles
            .checked_add(number(segment, "user_cycles")?)
            .context("segment user cycles overflow")?;
        padded_cycles += 1u64 << number(segment, "po2")?;
        receipt_bounds::check_padded_cycles(padded_cycles)?;
    }
    ensure!(
        asset_bytes == number(&value, "exported_segment_bytes")?
            && user_cycles == number(&value, "user_cycles")?,
        "session inventory totals differ"
    );
    Ok(value)
}

fn segment_path(dir: &Path, index: usize, item: &Value) -> Result<PathBuf> {
    let path = dir.join(format!("segment-{index}"));
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "regular segment file required"
    );
    let bytes = bounded_read(&path, MAX_SEGMENT_ASSET_BYTES)?;
    ensure!(
        metadata.len() == number(item, "bytes")? && item["sha256"] == sha(&bytes),
        "exported segment changed"
    );
    Ok(path)
}

/// One independently waited host/r0vm child family. Its local successful
/// receipt is retained; only complete final assembly proves the W1 statement.
pub fn prove_segment(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 7,
        "prove-segment <r0vm> <session-dir> <index> <new-receipt> <new-report>"
    );
    let dir = Path::new(&args[3]);
    let session = session(dir)?;
    let index: usize = args[4].parse()?;
    let item = session["segments"]
        .as_array()
        .context("segment inventory")?
        .get(index)
        .context("segment index outside session")?;
    let path = segment_path(dir, index, item)?;
    let opts = ProverOpts::default()
        .with_dev_mode(false)
        .with_hashfn("poseidon2".to_owned())
        .with_receipt_kind(ReceiptKind::Composite);
    let context = VerifierContext::default().with_dev_mode(false);
    let start = Instant::now();
    let client = ApiClient::new_sub_process(&args[2])?;
    let receipt = client.prove_segment(&opts, Asset::Path(path), AssetRequest::Inline)?;
    ensure!(
        receipt.index as usize == index && receipt.hashfn == "poseidon2",
        "returned segment identity differs"
    );
    let cycles = receipt_bounds::check_seal(&receipt.seal)?;
    ensure!(
        cycles == 1u64 << number(item, "po2")?,
        "returned segment dimension differs"
    );
    let parameters = context
        .segment_verifier_parameters
        .as_ref()
        .context("missing segment verifier parameters")?
        .digest::<risc0_zkvm::sha::Impl>();
    ensure!(
        receipt.verifier_parameters == parameters,
        "changed segment verifier parameters"
    );
    receipt.verify_integrity_with_context(&context)?;
    let encoded = bincode::serialize(&receipt)?;
    receipt_bounds::preflight_segment(&encoded, index)?;
    write_new(Path::new(&args[5]), &encoded)?;
    let report = json!({"schema":"pon-w1-real-segment-proof-v1","index":index,
        "real_segment_stark_verified":true,"complete_w1_proof_verified":false,
        "segment_sha256":item["sha256"],"receipt_sha256":sha(&encoded),
        "receipt_bytes":encoded.len(),"prove_and_segment_verify_wall_ns":start.elapsed().as_nanos(),
        "po2":number(item,"po2")?,"hashfn":"poseidon2","dev_mode":false,
        "additional_grinding":false,"povw_requested":false,"consensus_authority":false});
    write_new(Path::new(&args[6]), &serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    Ok(())
}
