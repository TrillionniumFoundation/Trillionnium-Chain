//! Independent verification-only v2 gate. Expected A/B hashes belong to the
//! caller's checked manifest; neither receipt bytes nor CLI select a guest image.
mod image;
mod input;
use anyhow::{ensure, Context, Result};
use input::bounded;
use risc0_zkvm::Receipt;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fmt, hint::black_box, process::ExitCode, time::Instant};
use trnm_w1_hardened_verifier::{profile, wire};
use trnm_w1_zk_relation::v2::{self, HEADER_BYTES};
const PROFILE_ID: &str = "trnm-w1-risc0-3.0.6-poseidon2-join-v2";

// Only these typed statement failures may populate the research supervisor's
// exact-byte rejection cache. I/O, local profile initialization, panic, OOM and
// resource termination must never acquire consensus-invalid semantics.
#[derive(Clone, Copy, Debug)]
enum StatementRejected {
    Wire,
    Public,
    Crypto,
}
impl StatementRejected {
    fn exit_code(self) -> u8 {
        match self {
            Self::Wire => 20,
            Self::Public => 21,
            Self::Crypto => 22,
        }
    }
}
impl fmt::Display for StatementRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Wire => "W1_V2_WIRE_REJECT",
            Self::Public => "W1_V2_PUBLIC_REJECT",
            Self::Crypto => "W1_V2_CRYPTO_REJECT",
        })
    }
}
impl std::error::Error for StatementRejected {}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
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
        public(header, expected, &receipt.journal.bytes).context(StatementRejected::Public)?;
    profile::verify_image(receipt, image::IMAGE_ID).context(StatementRejected::Crypto)?;
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
    // A local SDK/profile mismatch is an operational refusal, even when a
    // remote receipt would otherwise reach the cryptographic stage.
    profile::context().context("W1_V2_PROFILE_UNAVAILABLE")?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--native") {
        return native(&args[1..]);
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
        let receipt = wire::decode(black_box(&bytes)).context(StatementRejected::Wire)?;
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
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:?}");
            ExitCode::from(
                error
                    .downcast_ref::<StatementRejected>()
                    .map_or(1, |rejected| rejected.exit_code()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    #[test]
    fn only_typed_statement_failures_select_rejection_exit_codes() {
        for (layer, code) in [
            (StatementRejected::Wire, 20),
            (StatementRejected::Public, 21),
            (StatementRejected::Crypto, 22),
        ] {
            let error = anyhow::anyhow!("underlying refusal").context(layer);
            assert_eq!(
                error
                    .downcast_ref::<StatementRejected>()
                    .unwrap()
                    .exit_code(),
                code
            );
        }
        let error = anyhow::anyhow!("W1_V2_CRYPTO_REJECT in ordinary operational text");
        assert!(error.downcast_ref::<StatementRejected>().is_none());
    }
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
