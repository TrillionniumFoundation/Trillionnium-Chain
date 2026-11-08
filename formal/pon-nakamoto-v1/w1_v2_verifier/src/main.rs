//! Independent verification-only v2 gate. Expected A/B hashes belong to the
//! caller's checked manifest; neither receipt bytes nor CLI select a guest image.
mod image;
use anyhow::{ensure, Context, Result};
use risc0_zkvm::Receipt;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs::File, hint::black_box, io::Read, path::Path, time::Instant};
use trnm_w1_hardened_verifier::{profile, wire};
use trnm_w1_zk_relation::v2::{self, HEADER_BYTES};
const PROFILE_ID: &str = "trnm-w1-risc0-3.0.6-poseidon2-join-v2";
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn bounded(path: &str, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(Path::new(path))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "input size bound");
    Ok(bytes)
}
fn artifacts(bytes: &[u8]) -> Result<v2::ArtifactCommitments> {
    ensure!(
        bytes.len() == 64,
        "expected artifacts must be exactly model || input (64 bytes)"
    );
    Ok(v2::ArtifactCommitments {
        model: bytes[..32].try_into()?,
        input: bytes[32..].try_into()?,
    })
}
fn public(header: &[u8], expected: &v2::ArtifactCommitments, journal: &[u8]) -> Result<[u8; 32]> {
    v2::check_public_journal(header, expected, journal).map_err(|e| anyhow::anyhow!("{e:?}"))
}
fn verify(
    header: &[u8],
    expected: &v2::ArtifactCommitments,
    receipt: &Receipt,
) -> Result<[u8; 32]> {
    let identity =
        public(header, expected, &receipt.journal.bytes).context("W1_V2_PUBLIC_REJECT")?;
    profile::verify_image(receipt, image::IMAGE_ID).context("W1_V2_CRYPTO_REJECT")?;
    Ok(identity)
}
fn native(args: &[String]) -> Result<()> {
    ensure!(args.len() == 2, "--native INPUT EXPECTED_ARTIFACTS");
    let input = bounded(&args[0], v2::INPUT_BYTES)?;
    ensure!(input.len() == v2::INPUT_BYTES, "complete input size");
    let expected_bytes = bounded(&args[1], 64)?;
    let expected = artifacts(&expected_bytes)?;
    let started = Instant::now();
    let journal = v2::check_complete_relation(&input).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let identity = public(&input[..HEADER_BYTES], &expected, &journal)?;
    let first_ns = started.elapsed().as_nanos();
    let mut timings = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let started = Instant::now();
        let current =
            v2::check_complete_relation(black_box(&input)).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let id = public(&input[..HEADER_BYTES], black_box(&expected), &current)?;
        ensure!(
            id == identity && current == journal,
            "native identity changed"
        );
        drop(black_box(current));
        timings.push(started.elapsed().as_nanos());
    }
    println!(
        "{}",
        json!({"schema":"TRNM-W1-V2-NATIVE1", "profile_id":PROFILE_ID,
        "iterations":1000,"native_replay_ns":timings,"first_verify_ns":first_ns,
        "work_id":hex::encode(identity),"input_sha256":sha(&input),"header_sha256":sha(&input[..HEADER_BYTES]),
        "journal_sha256":sha(&journal),"expected_artifacts_sha256":sha(&expected_bytes),
        "input_bytes":input.len(),"journal_bytes":journal.len(),"full_replay_calls":1001,
        "sample_scope":"full native work replay, trusted artifact binding, identity/output equality, journal destruction",
        "parent_eligibility_checked":false,"admission_authorized":false})
    );
    Ok(())
}

/// One complete native replay with an independently supplied header, for the
/// same fresh-process receiver boundary as the single-receipt verifier. This
/// command never silently substitutes the existing 1,001-replay benchmark.
fn native_once(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 3,
        "--native-once INPUT HEADER EXPECTED_ARTIFACTS"
    );
    let input = bounded(&args[0], v2::INPUT_BYTES)?;
    ensure!(input.len() == v2::INPUT_BYTES, "complete input size");
    let header = bounded(&args[1], HEADER_BYTES)?;
    ensure!(header.len() == HEADER_BYTES, "header size");
    ensure!(
        input[..HEADER_BYTES] == header,
        "W1_V2_NATIVE_HEADER_REJECT"
    );
    let expected_bytes = bounded(&args[2], 64)?;
    let expected = artifacts(&expected_bytes)?;
    let started = Instant::now();
    let journal =
        v2::check_complete_relation(&input).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let identity = public(&header, &expected, &journal)?;
    let verify_ns = started.elapsed().as_nanos();
    println!(
        "{}",
        json!({
            "schema":"TRNM-W1-V2-NATIVE-ONCE1", "profile_id":PROFILE_ID,
            "iterations":1, "full_replay_calls":1, "full_native_verify_ns":[verify_ns],
            "work_id":hex::encode(identity), "input_sha256":sha(&input),
            "header_sha256":sha(&header), "journal_sha256":sha(&journal),
            "expected_artifacts_sha256":sha(&expected_bytes),
            "input_bytes":input.len(), "journal_bytes":journal.len(),
            "sample_scope":"one complete native replay and independent public statement binding; file reads, startup and destruction require the outer receiver observation",
            "parent_eligibility_checked":false, "admission_authorized":false
        })
    );
    Ok(())
}

fn run() -> Result<()> {
    for key in [
        "RISC0_DEV_MODE",
        "RISC0_PROVER",
        "BONSAI_API_URL",
        "BONSAI_API_KEY",
    ] {
        ensure!(
            std::env::var_os(key).is_none(),
            "unexpected proof environment: {key}"
        );
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--native") {
        return native(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("--native-once") {
        return native_once(&args[1..]);
    }
    let many = args.first().map(String::as_str) == Some("--verify-many");
    let args = if many { &args[1..] } else { &args[..] };
    ensure!(
        args.len() == 3,
        "[--verify-many] RECEIPT HEADER EXPECTED_ARTIFACTS"
    );
    let bytes = bounded(&args[0], wire::MAX_RECEIPT as usize)?;
    let header = bounded(&args[1], HEADER_BYTES)?;
    ensure!(header.len() == HEADER_BYTES, "header size");
    let expected_bytes = bounded(&args[2], 64)?;
    let expected = artifacts(&expected_bytes)?;
    let mut timings = Vec::with_capacity(if many { 100 } else { 1 });
    let mut identity = None;
    let mut journal_hash = None;
    for _ in 0..if many { 100 } else { 1 } {
        let started = Instant::now();
        let receipt = wire::decode(black_box(&bytes)).context("W1_V2_WIRE_REJECT")?;
        let work_id = verify(black_box(&header), black_box(&expected), &receipt)?;
        timings.push(started.elapsed().as_nanos());
        if let Some(previous) = identity {
            ensure!(previous == work_id, "proof identity changed");
        }
        identity = Some(work_id);
        journal_hash = Some(sha(&receipt.journal.bytes));
    }
    println!(
        "{}",
        json!({"schema":"TRNM-W1-V2-FULL-VERIFY1", "profile_id":PROFILE_ID,
        "sdk":"3.0.6","image_id":image::IMAGE_ID,"iterations":timings.len(),"decode_and_verify_ns":timings,
        "work_id":hex::encode(identity.context("verified identity")?),"header_sha256":sha(&header),
        "journal_sha256":journal_hash.context("verified journal")?,"receipt_sha256":sha(&bytes),
        "expected_artifacts_sha256":sha(&expected_bytes),"receipt_bytes":bytes.len(),
        "independent_proof_trials":1,
        "sample_scope":"bounded receipt decode, public statement binding and full cryptographic verify; receipt destruction follows sample",
        "parent_eligibility_checked":false,"admission_authorized":false})
    );
    Ok(())
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expected_artifacts_are_exact_and_never_derived_from_receipt() {
        for n in [0, 32, 63, 65] {
            assert!(artifacts(&vec![0; n]).is_err());
        }
        let mut bytes = [0; 64];
        bytes[0] = 1;
        bytes[63] = 2;
        let a = artifacts(&bytes).unwrap();
        assert_eq!(a.model[0], 1);
        assert_eq!(a.input[31], 2);
    }
    #[test]
    fn historical_full_receipt_cannot_satisfy_v2_statement() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../evidence/pon-w1-complete-succinct-20261028/full-proof");
        let receipt = wire::decode(&std::fs::read(root.join("succinct.bin")).unwrap()).unwrap();
        let input = std::fs::read(root.join("input.bin")).unwrap();
        let journal = v2::check_complete_relation(&input).unwrap();
        let a = artifacts(&journal[v2::MODEL_OFFSET..v2::PRODUCT_OFFSET]).unwrap();
        assert!(verify(&input[..HEADER_BYTES], &a, &receipt).is_err());
        assert!(profile::verify_image(&receipt, image::IMAGE_ID).is_err());
        // Public checks pass, but an old seal cannot be relabelled with a valid
        // v2 journal. Only full cryptographic verification may return identity.
        assert!(public(&input[..HEADER_BYTES], &a, &journal).is_ok());
        let mut relabelled = receipt;
        relabelled.journal.bytes = journal;
        assert!(verify(&input[..HEADER_BYTES], &a, &relabelled).is_err());
    }
}
