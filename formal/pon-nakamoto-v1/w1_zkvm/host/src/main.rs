//! Local cryptographic experiment; never selects a remote prover or dev mode.
use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use risc0_zkvm::{get_prover_server, ExecutorEnv, ProverOpts, Receipt, VerifierContext};
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
use trnm_w1_zk_relation::{check_complete_relation, check_public_journal, fixture, JOURNAL_BYTES};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

const MAX_RECEIPT_BYTES: u64 = 16 * 1024 * 1024;
fn decode_receipt(bytes: &[u8]) -> Result<Receipt> {
    ensure!(bytes.len() as u64 <= MAX_RECEIPT_BYTES, "receipt bound");
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
    let mut args = std::env::args().skip(1);
    let first = args.next().context(
        "usage: trnm-w1-zk-host NEW_OUT_DIR [trials=3] | verify HEADER_FILE RECEIPT_FILE",
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
    let out = PathBuf::from(first);
    let trials: u32 = args.next().unwrap_or_else(|| "3".into()).parse()?;
    ensure!(
        (1..=100).contains(&trials) && args.next().is_none(),
        "trial bounds"
    );
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
    fs::create_dir(&out).context("output must be new; never overwrite failed observations")?;
    let mut log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(out.join("observations.jsonl"))?;
    let opts = ProverOpts::succinct();
    let prover = get_prover_server(&opts)?;
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
            let value =
                check_complete_relation(black_box(&input)).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            black_box(value);
            native_ns.push(start.elapsed().as_nanos());
        }
        let started = Instant::now();
        let env = ExecutorEnv::builder()
            .segment_limit_po2(18)
            .session_limit(Some(1 << 30))
            .write_slice(&input)
            .build()?;
        let result = prover.prove_with_ctx(env, &context, TRNM_W1_FULL_GUEST_ELF);
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
        let receipt = read_receipt(&out.join(format!("receipt-{trial}.bin")))?;
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
        let row = json!({"trial":trial,"outcome":"REAL_SUCCINCT_STARK_VERIFIED", "input_sha256":sha(&input),"fixture_generation_ns":fixture_ns,"native_full_verifier_ns":native_ns,"prover_ns":prover_ns,"succinct_verifier_ns":verifier_ns,"receipt_bytes":encoded.len(),"journal_bytes":receipt.journal.bytes.len(),"receipt_sha256":sha(&encoded),"work_id":hex::encode(verify(&input[..318], &receipt)?),"stats":format!("{:?}",info.stats),"negative_controls": ["wrong_public_header","tampered_product_journal","tampered_seal","fake_receipt","truncated_encoding","trailing_encoding"],"consensus_admission":false});
        writeln!(log, "{row}")?;
        log.sync_all()?;
        println!("{row}");
        rows.push(row);
    }
    fs::write(
        out.join("summary.json"),
        serde_json::to_vec_pretty(
            &json!({"schema":"trnm-w1-full-zkvm-experiment-v1","sdk":"3.0.3","guest_elf_sha256":sha(TRNM_W1_FULL_GUEST_ELF),"image_id":TRNM_W1_FULL_GUEST_ID,"trials":rows,"fake_receipts_allowed":false,"remote_prover":false,"proof_randomness_affects_ticket":false,"native_integration":false,"hardness_qualified":false,"quantum_soundness_qualified":false,"production_activation":false}),
        )?,
    )?;
    Ok(())
}
