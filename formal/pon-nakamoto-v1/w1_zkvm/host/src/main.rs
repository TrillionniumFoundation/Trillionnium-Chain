//! Local cryptographic experiment; never selects a remote prover or dev mode.
use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use risc0_zkvm::{ExecutorEnv, ExternalProver, Prover, ProverOpts, Receipt, VerifierContext};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    hint::black_box,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use trnm_w1_zk_methods::{TRNM_W1_FULL_GUEST_ELF, TRNM_W1_FULL_GUEST_ID};
use trnm_w1_zk_relation::{
    check_complete_relation, check_public_journal, fixture, native_replay, JOURNAL_BYTES,
};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

const MAX_RECEIPT_BYTES: u64 = 16 * 1024 * 1024;
// Official v3.0.3 x86_64 Linux release, extracted only after checking archive
// 71a0adaa64235be13e9b8471bea5c4ded64bf97c6bd1eb9c2285b966c0b62fee.
// The backend is explicit, local and pinned; there is no environment fallback.
const R0VM_SHA256: &str = "2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6";
fn decode_receipt(bytes: &[u8]) -> Result<Receipt> {
    ensure!(bytes.len() as u64 <= MAX_RECEIPT_BYTES, "receipt bound");
    // Pinned SDK 3.0.3 Receipt starts with InnerReceipt. Fixed-int bincode
    // represents Succinct (the second variant) as LE u32(1). Reject every
    // other wire variant BEFORE deserialization: Composite can recursively
    // contain Composite assumption receipts, so a byte cap alone cannot
    // prevent deeply nested rejected input from exhausting the stack.
    ensure!(
        bytes.get(..4) == Some(1u32.to_le_bytes().as_slice()),
        "succinct receipt wire tag required"
    );
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_RECEIPT_BYTES)
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}

fn read_receipt(path: &Path) -> Result<Receipt> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    decode_receipt(&bytes)
}

fn verify(expected: &[u8], receipt: &Receipt) -> Result<[u8; 32]> {
    // An actual recursive STARK is mandatory. Fake, composite and Groth16
    // receipts cannot silently satisfy this experiment's succinct proof gate.
    receipt
        .inner
        .succinct()
        .context("succinct STARK required")?;
    receipt.verify(TRNM_W1_FULL_GUEST_ID)?;
    check_public_journal(expected, &receipt.journal.bytes).map_err(|e| anyhow::anyhow!("{e:?}"))
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
    let first = args.next().context(
        "usage: trnm-w1-zk-host --r0vm ABSOLUTE_PINNED_BINARY NEW_OUT_DIR [trials=3] | verify HEADER_FILE RECEIPT_FILE",
    )?;
    if first == "verify" {
        let header_path = args.next().context("expected header path")?;
        let receipt_path = args.next().context("expected receipt path")?;
        ensure!(args.next().is_none(), "unexpected arguments");
        let mut header = Vec::new();
        fs::File::open(header_path)?
            .take(319)
            .read_to_end(&mut header)?;
        ensure!(header.len() == 318, "header bound");
        let identity = verify(&header, &read_receipt(Path::new(&receipt_path))?)?;
        println!(
            "{}",
            json!({"outcome":"SAVED_SUCCINCT_STARK_VERIFIED","work_id":hex::encode(identity),"consensus_admission":false})
        );
        return Ok(());
    }
    ensure!(first == "--r0vm", "explicit pinned local prover required");
    let r0vm = PathBuf::from(args.next().context("local r0vm path")?);
    ensure!(
        r0vm.is_absolute() && r0vm.is_file(),
        "absolute local prover required"
    );
    ensure!(
        sha(&fs::read(&r0vm)?) == R0VM_SHA256,
        "local prover binary digest mismatch"
    );
    let out = PathBuf::from(args.next().context("new output directory")?);
    let trials: u32 = args.next().unwrap_or_else(|| "3".into()).parse()?;
    ensure!(
        (1..=100).contains(&trials) && args.next().is_none(),
        "trial bounds"
    );
    fs::create_dir(&out).context("output must be new; never overwrite failed observations")?;
    let mut log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(out.join("observations.jsonl"))?;
    let opts = ProverOpts::succinct();
    let prover = ExternalProver::new("pinned-local-r0vm-3.0.3", r0vm);
    let context = VerifierContext::default();
    let mut rows = Vec::new();
    for trial in 0..trials {
        let generation = Instant::now();
        let input = fixture(trial);
        let fixture_ns = generation.elapsed().as_nanos();
        fs::write(out.join(format!("input-{trial}.bin")), &input)?;
        fs::write(out.join(format!("header-{trial}.bin")), &input[..318])?;
        let mut native_ns = Vec::new();
        let expected = check_complete_relation(&input).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        for _ in 0..100 {
            let start = Instant::now();
            let value = native_replay(black_box(&input)).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            black_box(value);
            native_ns.push(start.elapsed().as_nanos());
        }
        let started = Instant::now();
        let env = ExecutorEnv::builder()
            .segment_limit_po2(18)
            .session_limit(Some(1 << 30))
            .write_slice(&input)
            .build()?;
        let result = prover.prove_with_ctx(env, &context, TRNM_W1_FULL_GUEST_ELF, &opts);
        let prover_ns = started.elapsed().as_nanos();
        let info = match result {
            Ok(info) => info,
            Err(error) => {
                let failed = json!({"trial":trial,"outcome":"PROVER_FAILED","error":error.to_string(),"prover_ns":prover_ns,"input_sha256":sha(&input)});
                writeln!(log, "{failed}")?;
                log.sync_all()?;
                bail!("prover failed; original observation retained: {error}");
            }
        };
        let receipt = info.receipt;
        ensure!(
            receipt.journal.bytes == expected,
            "guest/native full relation output mismatch"
        );
        let encoded = bincode::serialize(&receipt)?;
        fs::write(out.join(format!("receipt-{trial}.bin")), &encoded)?;
        // Measure and verify the actual saved bytes, not just the prover's
        // in-memory object. The separate verify command permits a fresh process.
        let read_started = Instant::now();
        let receipt = read_receipt(&out.join(format!("receipt-{trial}.bin")))?;
        let disk_read_and_decode_ns = read_started.elapsed().as_nanos();
        let mut trailing = encoded.clone();
        trailing.push(0);
        ensure!(
            decode_receipt(&trailing).is_err(),
            "trailing encoding accepted"
        );
        ensure!(
            decode_receipt(&encoded[..encoded.len() - 1]).is_err(),
            "truncated encoding accepted"
        );
        let fake = Receipt::new(
            risc0_zkvm::InnerReceipt::Fake(risc0_zkvm::FakeReceipt::new(receipt.claim()?)),
            receipt.journal.bytes.clone(),
        );
        ensure!(
            verify(&input[..318], &fake).is_err(),
            "fake receipt accepted"
        );
        let mut verifier_ns = Vec::new();
        for _ in 0..100 {
            let start = Instant::now();
            black_box(verify(&input[..318], &receipt)?);
            verifier_ns.push(start.elapsed().as_nanos());
        }
        let mut decode_verify_ns = Vec::new();
        for _ in 0..100 {
            let start = Instant::now();
            let decoded = decode_receipt(black_box(&encoded))?;
            black_box(verify(&input[..318], &decoded)?);
            decode_verify_ns.push(start.elapsed().as_nanos());
        }
        let mut wrong_header = input[..318].to_vec();
        wrong_header[310] ^= 1;
        ensure!(
            verify(&wrong_header, &receipt).is_err(),
            "wrong public statement accepted"
        );
        let mut wrong_journal = receipt.clone();
        wrong_journal.journal.bytes[JOURNAL_BYTES - 1] ^= 1;
        ensure!(
            verify(&input[..318], &wrong_journal).is_err(),
            "tampered product journal accepted"
        );
        let mut wrong_seal = receipt.clone();
        if let risc0_zkvm::InnerReceipt::Succinct(ref mut succinct) = wrong_seal.inner {
            ensure!(!succinct.seal.is_empty(), "empty seal");
            succinct.seal[0] ^= 1;
        }
        ensure!(
            verify(&input[..318], &wrong_seal).is_err(),
            "tampered seal accepted"
        );
        let succinct = receipt.inner.succinct()?;
        let row = json!({
            "trial":trial, "outcome":"REAL_SUCCINCT_STARK_VERIFIED",
            "input_sha256":sha(&input), "fixture_generation_ns":fixture_ns,
            "native_full_verifier_ns":native_ns, "prover_ns":prover_ns,
            "succinct_crypto_verify_ns":verifier_ns,
            "succinct_decode_and_verify_ns":decode_verify_ns,
            "disk_read_and_decode_ns":disk_read_and_decode_ns,
            "receipt_bytes":encoded.len(), "journal_bytes":receipt.journal.bytes.len(),
            "receipt_sha256":sha(&encoded),
            "work_id":hex::encode(verify(&input[..318], &receipt)?),
            "proof_hash_suite":succinct.hashfn,
            "control_id":succinct.control_id.to_string(),
            "verifier_parameters":succinct.verifier_parameters.to_string(),
            "stats":format!("{:?}",info.stats),
            "negative_controls": ["wrong_public_header","tampered_product_journal","tampered_seal","fake_receipt","truncated_encoding","trailing_encoding"],
            "consensus_admission":false
        });
        writeln!(log, "{row}")?;
        log.sync_all()?;
        println!("{row}");
        rows.push(row);
    }
    fs::write(
        out.join("summary.json"),
        serde_json::to_vec_pretty(
            &json!({"schema":"trnm-w1-full-zkvm-experiment-v1","sdk":"3.0.3","local_r0vm_sha256":R0VM_SHA256,"guest_elf_sha256":sha(TRNM_W1_FULL_GUEST_ELF),"image_id":TRNM_W1_FULL_GUEST_ID,"trials":rows,"fake_receipts_allowed":false,"remote_prover":false,"proof_randomness_affects_ticket":false,"native_integration":false,"hardness_qualified":false,"quantum_soundness_qualified":false,"production_activation":false}),
        )?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recursive_composite_is_rejected_before_general_deserialization() {
        // Canonical fixed-int shape of 4,096 nested Composite assumptions.
        // Construct bytes, never a recursively allocated Receipt object, and
        // never feed them to the original unguarded SDK decoder.
        let depth = 4096;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // outer Composite
        for _ in 0..depth {
            bytes.extend_from_slice(&0u64.to_le_bytes()); // no segments
            bytes.extend_from_slice(&1u64.to_le_bytes()); // one assumption
            bytes.extend_from_slice(&0u32.to_le_bytes()); // nested Composite
        }
        bytes.extend_from_slice(&0u64.to_le_bytes()); // terminal segments
        bytes.extend_from_slice(&0u64.to_le_bytes()); // terminal assumptions
        bytes.extend_from_slice(&[0; 32]); // terminal verifier parameters
        for _ in 0..depth {
            bytes.extend_from_slice(&[0; 32]); // enclosing verifier parameters
        }
        bytes.extend_from_slice(&0u64.to_le_bytes()); // journal
        bytes.extend_from_slice(&[0; 32]); // metadata
        assert_eq!(bytes.len(), 213_084);
        assert_eq!(
            decode_receipt(&bytes).unwrap_err().to_string(),
            "succinct receipt wire tag required"
        );
    }

    #[test]
    fn only_bounded_succinct_wire_enters_the_decoder() {
        for tag in [0u32, 2, 3, u32::MAX] {
            assert_eq!(
                decode_receipt(&tag.to_le_bytes()).unwrap_err().to_string(),
                "succinct receipt wire tag required"
            );
        }
        for length in 0..4 {
            assert_eq!(
                decode_receipt(&[1, 0, 0, 0][..length])
                    .unwrap_err()
                    .to_string(),
                "succinct receipt wire tag required"
            );
        }
        let error = decode_receipt(&1u32.to_le_bytes()).unwrap_err();
        assert_ne!(error.to_string(), "succinct receipt wire tag required");
        let mut oversized = vec![0u8; MAX_RECEIPT_BYTES as usize + 1];
        oversized[..4].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            decode_receipt(&oversized).unwrap_err().to_string(),
            "receipt bound"
        );
    }
}
