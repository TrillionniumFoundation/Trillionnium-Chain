//! Independent, verification-only gate for the frozen full W1 experiment.
//! No guest build, prover client, remote backend, dev mode, or admission path.
use anyhow::{ensure, Context, Result};
use bincode::Options;
use risc0_zkvm::{InnerReceipt, Receipt, ReceiptClaim, SuccinctReceipt};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    hint::black_box,
    io::{Read, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
    time::Instant,
};

const SDK_VERSION: &str = "3.0.6";
const IMAGE_ID: [u32; 8] = [
    4203990569, 1706128024, 889896351, 2751765305, 3434005897, 1411617246, 870515685, 3215144349,
];
const MAX_RECEIPT: u64 = 16 * 1024 * 1024;
const HEADER_BYTES: usize = 318;
const JOURNAL_BYTES: usize = 16818;
const DOMAIN: &[u8] = b"TRNM-W1-ZK-JOURNAL1\0";

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "file bound");
    Ok(bytes)
}

fn new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn decode(bytes: &[u8]) -> Result<Receipt> {
    ensure!(bytes.len() as u64 <= MAX_RECEIPT, "receipt bound");
    // Check BEFORE deserialization to rule out nested Composite assumption
    // objects, Fake and elliptic-curve Groth16 receipts at the wire boundary.
    ensure!(
        bytes.get(..4) == Some(1u32.to_le_bytes().as_slice()),
        "succinct receipt wire tag required"
    );
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_RECEIPT)
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}

fn decode_recursion(bytes: &[u8]) -> Result<SuccinctReceipt<ReceiptClaim>> {
    ensure!(bytes.len() as u64 <= MAX_RECEIPT, "recursion receipt bound");
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_RECEIPT)
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}

fn pon_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"TRNM-PON1\0");
    h.update((tag.len() as u16).to_le_bytes());
    h.update(tag);
    for part in parts {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// Independent public-statement decoding. This is called only AFTER proof
/// verification, and is not itself an implementation of the W1 relation.
fn journal(header: &[u8], bytes: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        header.len() == HEADER_BYTES
            && &header[..4] == b"PNH1"
            && header[4..6] == 1u16.to_le_bytes(),
        "canonical PNH1 header required"
    );
    ensure!(
        bytes.len() == JOURNAL_BYTES && bytes.starts_with(DOMAIN),
        "journal bound/domain"
    );
    let start = DOMAIN.len();
    ensure!(
        bytes[start..start + HEADER_BYTES] == *header,
        "public header mismatch"
    );
    let start = start + HEADER_BYTES;
    let trace: [u8; 32] = bytes[start..start + 32].try_into()?;
    let ticket: [u8; 32] = bytes[start + 32..start + 64].try_into()?;
    let work_id: [u8; 32] = bytes[start + 64..start + 96].try_into()?;
    let target: [u8; 32] = header[118..150].try_into()?;
    ensure!(target != [0; 32] && ticket <= target, "ticket target");
    let challenge = pon_hash(b"challenge", &[header]);
    ensure!(
        ticket == pon_hash(b"ticket", &[&challenge, &trace]),
        "ticket binding"
    );
    ensure!(
        work_id == pon_hash(b"block", &[header, &trace]),
        "unique work identity"
    );
    for word in bytes[start + 96..].chunks_exact(4) {
        ensure!(
            u32::from_le_bytes(word.try_into()?) < 4294967291,
            "noncanonical product field"
        );
    }
    Ok(work_id)
}

fn verify(header: &[u8], receipt: &Receipt) -> Result<[u8; 32]> {
    receipt
        .inner
        .succinct()
        .context("recursive STARK required")?;
    receipt
        .verify(IMAGE_ID)
        .context("full frozen image proof")?;
    journal(header, &receipt.journal.bytes)
}

fn classify(check: impl FnOnce() -> Result<()>) -> serde_json::Value {
    // A panic is a separate failure, never counted as controlled rejection.
    match catch_unwind(AssertUnwindSafe(check)) {
        Ok(Ok(())) => json!({"outcome":"ACCEPT"}),
        Ok(Err(e)) => json!({"outcome":"REJECT", "error":format!("{e:#}")}),
        Err(_) => json!({"outcome":"PANIC"}),
    }
}

fn controls(header: &[u8], bytes: &[u8], out: &Path) -> Result<()> {
    let original = decode(bytes)?;
    verify(header, &original)?;
    fs::create_dir(out).context("new control output directory required")?;
    let mut cases: Vec<(String, Vec<u8>, Vec<u8>, bool)> =
        vec![("valid".into(), header.to_vec(), bytes.to_vec(), true)];
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    cases.push(("trailing".into(), header.to_vec(), trailing, false));
    cases.push((
        "truncated".into(),
        header.to_vec(),
        bytes[..bytes.len() - 1].to_vec(),
        false,
    ));
    let mut oversized_seal_length = bytes.to_vec();
    oversized_seal_length[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    cases.push((
        "declared_seal_length_overflow".into(),
        header.to_vec(),
        oversized_seal_length,
        false,
    ));
    for (name, tag) in [("composite_tag", 0u32), ("groth16_tag", 2), ("fake_tag", 3)] {
        let mut bad = bytes.to_vec();
        bad[..4].copy_from_slice(&tag.to_le_bytes());
        cases.push((name.into(), header.to_vec(), bad, false));
    }
    let mut wrong_header = header.to_vec();
    wrong_header[310] ^= 1;
    cases.push(("wrong_header".into(), wrong_header, bytes.to_vec(), false));
    for offset in [
        0,
        DOMAIN.len(),
        DOMAIN.len() + HEADER_BYTES,
        DOMAIN.len() + HEADER_BYTES + 32,
        DOMAIN.len() + HEADER_BYTES + 64,
        JOURNAL_BYTES - 1,
    ] {
        let mut bad = original.clone();
        bad.journal.bytes[offset] ^= 1;
        cases.push((
            format!("journal_byte_{offset}"),
            header.to_vec(),
            bincode::serialize(&bad)?,
            false,
        ));
    }
    for mode in [
        "control_id",
        "verifier_parameters",
        "hash_function",
        "claim_digest",
        "seal_first",
        "seal_body",
        "seal_last",
        "seal_empty",
        "seal_short",
        "seal_invalid_field",
    ] {
        let mut bad = original.clone();
        let InnerReceipt::Succinct(ref mut inner) = bad.inner else {
            unreachable!()
        };
        match mode {
            "control_id" => {
                let mut words: [u32; 8] = inner.control_id.into();
                words[0] ^= 1;
                inner.control_id = words.into();
            }
            "verifier_parameters" => inner.verifier_parameters = [0u32; 8].into(),
            "hash_function" => inner.hashfn = "invalid-hash-suite".into(),
            "claim_digest" => inner.claim = risc0_zkvm::MaybePruned::Pruned([0u32; 8].into()),
            "seal_first" => inner.seal[0] ^= 1,
            "seal_body" => {
                let i = inner.seal.len() / 2;
                inner.seal[i] ^= 1;
            }
            "seal_last" => {
                let i = inner.seal.len() - 1;
                inner.seal[i] ^= 1;
            }
            "seal_empty" => inner.seal.clear(),
            "seal_short" => inner.seal.truncate(16),
            "seal_invalid_field" => inner.seal[0] = u32::MAX,
            _ => unreachable!(),
        }
        cases.push((
            mode.into(),
            header.to_vec(),
            bincode::serialize(&bad)?,
            false,
        ));
    }
    let mut rows = Vec::new();
    for (name, public, proof, expected_accept) in cases {
        new_file(&out.join(format!("{name}.header")), &public)?;
        new_file(&out.join(format!("{name}.receipt")), &proof)?;
        let started = Instant::now();
        let result = classify(|| {
            verify(&public, &decode(&proof)?)?;
            Ok(())
        });
        let expected = if expected_accept { "ACCEPT" } else { "REJECT" };
        let passed = result["outcome"] == expected;
        rows.push(json!({"name":name,"expected":expected,"observed":result,
            "passed":passed,"elapsed_ns":started.elapsed().as_nanos(),
            "receipt_sha256":sha(&proof),"header_sha256":sha(&public)}));
    }
    let all_passed = rows.iter().all(|r| r["passed"] == true);
    let report = json!({"schema":"TRNM-W1-HARDENED-VERIFIER-CONTROLS1",
        "sdk":SDK_VERSION,"image_id":IMAGE_ID,"cases":rows,"all_passed":all_passed,
        "fake_proofs_used":false,"consensus_admission":false});
    new_file(
        &out.join("result.json"),
        serde_json::to_string_pretty(&report)?.as_bytes(),
    )?;
    println!("{report}");
    ensure!(all_passed, "actual full-proof negative controls failed");
    Ok(())
}

fn main() -> Result<()> {
    for key in [
        "RISC0_DEV_MODE",
        "BONSAI_API_URL",
        "BONSAI_API_KEY",
        "RISC0_PROVER",
    ] {
        ensure!(
            std::env::var_os(key).is_none(),
            "unexpected proof-selection environment: {key}"
        );
    }
    let mut args = std::env::args().skip(1);
    let command = args
        .next()
        .context("verify|benchmark|controls HEADER RECEIPT [NEW_DIR] | verify-recursion RECEIPT")?;
    if command == "verify-recursion" {
        let path = args.next().context("recursive receipt")?;
        ensure!(args.next().is_none(), "unexpected arguments");
        let bytes = bounded(Path::new(&path), MAX_RECEIPT)?;
        let started = Instant::now();
        let receipt = decode_recursion(&bytes)?;
        let result = classify(|| {
            receipt.verify_integrity()?;
            Ok(())
        });
        println!(
            "{}",
            json!({"schema":"TRNM-W1-RECURSION-ONLY-VERIFY1", "sdk":SDK_VERSION,
            "receipt_sha256":sha(&bytes), "receipt_bytes":bytes.len(), "result":result,
            "elapsed_ns":started.elapsed().as_nanos(), "control_id":receipt.control_id.to_string(),
            "complete_w1_claim":false,"consensus_admission":false})
        );
        ensure!(
            result["outcome"] == "ACCEPT",
            "recursive-only verification failed"
        );
        return Ok(());
    }
    ensure!(
        matches!(command.as_str(), "verify" | "benchmark" | "controls"),
        "unknown command"
    );
    let header_path = args.next().context("expected canonical header")?;
    let receipt_path = args.next().context("saved full receipt")?;
    let control_dir = if command == "controls" {
        Some(args.next().context("new controls directory")?)
    } else {
        None
    };
    ensure!(args.next().is_none(), "unexpected arguments");
    let header = bounded(Path::new(&header_path), HEADER_BYTES as u64)?;
    let bytes = bounded(Path::new(&receipt_path), MAX_RECEIPT)?;
    if let Some(dir) = control_dir {
        return controls(&header, &bytes, Path::new(&dir));
    }
    let started = Instant::now();
    let receipt = decode(&bytes)?;
    let decode_ns = started.elapsed().as_nanos();
    let started = Instant::now();
    let id = verify(&header, &receipt)?;
    let verify_ns = started.elapsed().as_nanos();
    let succinct = receipt.inner.succinct()?;
    let mut verifier_ns = Vec::new();
    let mut decode_verify_ns = Vec::new();
    if command == "benchmark" {
        for _ in 0..100 {
            let started = Instant::now();
            black_box(verify(black_box(&header), black_box(&receipt))?);
            verifier_ns.push(started.elapsed().as_nanos());
            let started = Instant::now();
            let decoded = decode(black_box(&bytes))?;
            black_box(verify(black_box(&header), &decoded)?);
            decode_verify_ns.push(started.elapsed().as_nanos());
        }
    }
    println!(
        "{}",
        json!({"schema":"TRNM-W1-HARDENED-FULL-VERIFY1", "sdk":SDK_VERSION,
        "outcome":"SAVED_FULL_SUCCINCT_STARK_VERIFIED", "image_id":IMAGE_ID,
        "work_id":hex::encode(id), "receipt_sha256":sha(&bytes),"receipt_bytes":bytes.len(),
        "control_id":succinct.control_id.to_string(), "hash_function":succinct.hashfn,
        "verifier_parameters_digest":succinct.verifier_parameters.to_string(),
        "seal_words":succinct.seal.len(),
        "header_sha256":sha(&header),"journal_sha256":sha(&receipt.journal.bytes),
        "decode_ns":decode_ns,"first_verify_ns":verify_ns,"verifier_ns":verifier_ns,
        "decode_verify_ns":decode_verify_ns,"independent_proof_trials":1,
        "production_tail_established":false,"proof_randomness_tickets":0,"consensus_admission":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_succinct_tags_before_deserialization() {
        for tag in [0u32, 2, 3, u32::MAX] {
            assert!(decode(&tag.to_le_bytes())
                .unwrap_err()
                .to_string()
                .contains("wire tag"));
        }
        assert!(decode(&[1, 0, 0]).is_err());
    }
    #[test]
    fn short_public_statement_cannot_panic_or_authorize_work() {
        for n in [0, 3, 4, 5, 317, 318, 319] {
            assert!(journal(&vec![0; n], &vec![0; JOURNAL_BYTES]).is_err());
        }
        assert_eq!(classify(|| anyhow::bail!("reject"))["outcome"], "REJECT");
    }
}
