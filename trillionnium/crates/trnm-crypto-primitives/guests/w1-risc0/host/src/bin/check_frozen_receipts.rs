//! Additional v2 verification of frozen witnesses' real segment receipts.
//! The original host, guest, lockfile, proof profile and assembler stay pinned.
use anyhow::{ensure, Context, Result};
use bincode::Options;
use hex::FromHex;
use risc0_binfmt::Digestible;
use risc0_zkvm::{
    sha::Sha256, ExitCode, ReceiptClaim, SegmentReceipt, SystemState, VerifierContext,
};
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[allow(dead_code)]
#[path = "../receipt_bounds.rs"]
mod receipt_bounds;

fn read(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x800)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= cap as u64,
        "bounded regular file required"
    );
    let mut data = Vec::new();
    (&mut file).take((cap + 1) as u64).read_to_end(&mut data)?;
    let after = file.metadata()?;
    ensure!(
        data.len() <= cap
            && data.len() as u64 == meta.len()
            && after.len() == meta.len()
            && (
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            ) == (
                meta.mtime(),
                meta.mtime_nsec(),
                meta.ctime(),
                meta.ctime_nsec()
            ),
        "file length changed"
    );
    Ok(data)
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("missing {key}"))
}

fn digest(v: &Value, key: &str) -> Result<risc0_zkvm::sha::Digest> {
    Ok(risc0_zkvm::sha::Digest::from_hex(text(v, key)?)?)
}

fn state(v: &Value, key: &str) -> Result<risc0_zkvm::sha::Digest> {
    Ok(SystemState {
        pc: 0,
        merkle_root: digest(v, key)?,
    }
    .digest::<risc0_zkvm::sha::Impl>())
}

fn bind(receipt: &SegmentReceipt, expected: &Value, index: usize) -> Result<()> {
    ensure!(
        expected["index"].as_u64() == Some(index as u64)
            && receipt.index as usize == index
            && receipt.hashfn == "poseidon2",
        "segment index/hash suite differs"
    );
    ensure!(
        receipt.claim.pre.digest::<risc0_zkvm::sha::Impl>() == state(expected, "pre_state")?,
        "frozen segment pre-state differs"
    );
    let (post, exit, output) = if index == 61 {
        ensure!(
            expected["terminate_state"] == json!([0, 0, 0, 0]),
            "final termination differs"
        );
        (
            SystemState {
                pc: 0,
                merkle_root: risc0_zkvm::sha::Digest::ZERO,
            }
            .digest::<risc0_zkvm::sha::Impl>(),
            ExitCode::Halted(0),
            digest(expected, "output")?,
        )
    } else {
        ensure!(
            expected["terminate_state"].is_null() && expected["output"].is_null(),
            "nonfinal termination/output differs"
        );
        (
            state(expected, "post_state")?,
            ExitCode::SystemSplit,
            risc0_zkvm::sha::Digest::ZERO,
        )
    };
    ensure!(
        receipt.claim.post.digest::<risc0_zkvm::sha::Impl>() == post
            && receipt.claim.exit_code == exit,
        "frozen segment post-state/exit differs"
    );
    ensure!(
        receipt.claim.input.digest::<risc0_zkvm::sha::Impl>() == digest(expected, "input")?
            && receipt.claim.output.digest::<risc0_zkvm::sha::Impl>() == output,
        "frozen segment input/output differs"
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(
        args.len() == 6,
        "check_frozen_receipts <claims.json> <session-dir> <receipts-dir> <start> <end>"
    );
    let start: usize = args[4].parse()?;
    let end: usize = args[5].parse()?;
    ensure!(
        [(0, 26), (26, 44), (44, 62), (0, 62)].contains(&(start, end)),
        "unknown fixed receipt range"
    );
    let record_bytes = read(Path::new(&args[1]), 256 * 1024)?;
    let record: Value = serde_json::from_slice(&record_bytes)?;
    // Runner emits this exact closed JSON encoding. A re-encode equality check
    // also refuses duplicate object keys, alternative numeric forms and junk.
    let canonical = format!("{}\n", serde_json::to_string_pretty(&record)?);
    ensure!(
        canonical.as_bytes() == record_bytes,
        "noncanonical or duplicate-key claims JSON"
    );
    let keys: Vec<&str> = record
        .as_object()
        .context("claims object required")?
        .keys()
        .map(String::as_str)
        .collect();
    ensure!(
        keys == [
            "cryptographic_proof_verified",
            "image_id",
            "journal_hex",
            "schema",
            "segments",
            "session_claim_digest",
            "session_claim_sha256"
        ],
        "unknown claims fields"
    );
    ensure!(
        record["schema"] == "pon-w1-frozen-witness-claims-v2"
            && record["cryptographic_proof_verified"] == false,
        "unknown frozen claims namespace"
    );
    let segments = record["segments"].as_array().context("missing segments")?;
    ensure!(segments.len() == 62, "all frozen claims required");
    let session_dir = Path::new(&args[2]);
    let claim_bytes = read(&session_dir.join("session.claim.bin"), 16 * 1024)?;
    receipt_bounds::preflight_claim(&claim_bytes)?;
    ensure!(
        risc0_zkvm::sha::Impl::hash_bytes(&claim_bytes).to_string()
            == text(&record, "session_claim_sha256")?,
        "frozen session claim bytes differ"
    );
    let claim: ReceiptClaim = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024)
        .reject_trailing_bytes()
        .deserialize(&claim_bytes)?;
    ensure!(
        claim.exit_code == ExitCode::Halted(0)
            && claim.digest::<risc0_zkvm::sha::Impl>().to_string()
                == text(&record, "session_claim_digest")?
            && claim.pre.digest::<risc0_zkvm::sha::Impl>().to_string()
                == text(&record, "image_id")?
            && claim.pre.digest::<risc0_zkvm::sha::Impl>() == state(&segments[0], "pre_state")?,
        "frozen session/image binding differs"
    );
    let journal = hex::decode(text(&record, "journal_hex")?)?;
    ensure!(
        journal.len() == receipt_bounds::JOURNAL_BYTES,
        "fixed W1 journal required"
    );
    let expected_claim = ReceiptClaim::ok(digest(&record, "image_id")?, journal);
    ensure!(
        expected_claim.digest::<risc0_zkvm::sha::Impl>() == claim.digest::<risc0_zkvm::sha::Impl>()
            && claim.output.digest::<risc0_zkvm::sha::Impl>() == digest(&segments[61], "output")?,
        "complete W1 public journal/claim differs"
    );
    for (i, item) in segments.iter().enumerate() {
        let keys: Vec<&str> = item
            .as_object()
            .context("segment object required")?
            .keys()
            .map(String::as_str)
            .collect();
        ensure!(
            keys == [
                "bytes",
                "index",
                "input",
                "output",
                "post_state",
                "pre_state",
                "raw_sha256",
                "shutdown_cycle",
                "terminate_state"
            ],
            "unknown segment fields"
        );
        ensure!(
            item["index"].as_u64() == Some(i as u64) && item["shutdown_cycle"].is_null(),
            "frozen claim order/profile differs"
        );
        let raw = read(&session_dir.join(format!("segment-{i}")), 1024 * 1024)?;
        ensure!(
            item["bytes"].as_u64() == Some(raw.len() as u64)
                && risc0_zkvm::sha::Impl::hash_bytes(&raw).to_string() == text(item, "raw_sha256")?,
            "frozen witness raw bytes differ"
        );
        if i > 0 {
            ensure!(
                segments[i - 1]["post_state"] == item["pre_state"],
                "frozen boundary chain differs"
            );
        }
    }
    let context = VerifierContext::default().with_dev_mode(false);
    let parameters = context
        .segment_verifier_parameters
        .as_ref()
        .context("segment parameters missing")?
        .digest::<risc0_zkvm::sha::Impl>();
    let mut checked = Vec::new();
    for (index, expected) in segments.iter().enumerate().take(end).skip(start) {
        let raw = read(
            &Path::new(&args[3]).join(format!("segment-{index}.bin")),
            2 * 1024 * 1024,
        )?;
        ensure!(
            receipt_bounds::preflight_segment(&raw, index)? == 1 << 18,
            "segment dimension differs"
        );
        let receipt: SegmentReceipt = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(2 * 1024 * 1024)
            .reject_trailing_bytes()
            .deserialize(&raw)?;
        bind(&receipt, expected, index)?;
        ensure!(
            receipt.verifier_parameters == parameters,
            "segment verifier parameters differ"
        );
        ensure!(
            receipt.povw_nonce()?.to_bytes() == [0u8; 32],
            "PoVW receipt refused"
        );
        receipt.verify_integrity_with_context(&context)?;
        checked.push(index);
    }
    println!(
        "{}",
        json!({"schema":"pon-w1-frozen-receipts-verified-v2", "indexes":checked,
        "real_segment_stark_verified":true, "frozen_claim_bound":true,
        "whole_w1_proof_verified":false, "dev_mode":false, "additional_pow":false,
        "helper_sha256":risc0_zkvm::sha::Impl::hash_bytes(&read(&std::env::current_exe()?, 64 * 1024 * 1024)?).to_string()})
    );
    Ok(())
}
