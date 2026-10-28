//! A separate, finite transparent recursion experiment. No Node admission path.
use anyhow::{anyhow, ensure, Context, Result};
use bincode::Options;
use risc0_binfmt::Digestible;
use risc0_zkvm::{
    compute_image_id, sha::Sha256, ApiClient, AssetRequest, CompositeReceipt, ExitCode,
    InnerReceipt, ProverOpts, Receipt, ReceiptClaim, SuccinctReceipt, VerifierContext,
};
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Instant;
use trnm_w1_guest_relation::full_relation;

mod bounds;
#[allow(dead_code)]
#[path = "../../w1-risc0/host/src/receipt_bounds.rs"]
mod composite_bounds;
#[path = "../../w1-risc0/host/src/process_cpu.rs"]
mod process_cpu;

const ORIGINAL_SHA: &str = "0a5336a797c51829ed25d4ec2f1a03f4f56fda4c737a230b493d4abbe96f0ec8";
const ORIGINAL_BYTES: usize = 15_862_780;
const INPUT_SHA: &str = "4babd290b10f7a68be27c2adf3b97448bb7bef04dba8bcb97f914acf4ac69020";
const ELF_SHA: &str = "b8f32cd9c1b1edbb0cde04acf9aab146b7ff1aeeeaee0188e4d6e80d077b0c0a";
const IMAGE: &str = "3ea1bcbf7900a32be73d7e78102de085562893732473667e1f3af07e585696b4";
const CLAIM: &str = "c717de185bfb18d3990dd7b31e4f94a2831dd159d8e9366740ea74e4c8e14a03";
const LIFT_ID: &str = "e7934a23ddce1423b425cf32aa23be29f48cd40e0b6ff9376dce6f3bf9d0bc35";
const JOIN_ID: &str = "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e";
const CONTROL_ROOT: &str = "a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56";
const WIRE_MAGIC: &[u8; 8] = b"PWSR0001";
const PACKET_BUDGET: usize = 1_048_576;

fn hash(raw: &[u8]) -> String {
    risc0_zkvm::sha::Impl::hash_bytes(raw).to_string()
}
fn read(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x800)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() <= cap as u64,
        "bounded regular input required"
    );
    let mut raw = Vec::new();
    (&mut file).take((cap + 1) as u64).read_to_end(&mut raw)?;
    let after = file.metadata()?;
    ensure!(
        raw.len() as u64 == before.len()
            && after.len() == before.len()
            && (
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            ) == (
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ),
        "input changed while read"
    );
    Ok(raw)
}
fn write_new(path: &Path, raw: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(raw)?;
    f.sync_all()?;
    Ok(())
}
fn context() -> VerifierContext {
    VerifierContext::default().with_dev_mode(false)
}
fn pinned_material(elf: &Path, input: &Path) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let elf = read(elf, 16 * 1024 * 1024)?;
    let input = read(input, full_relation::INPUT_BYTES)?;
    pinned_values(elf, input)
}
fn pinned_values(elf: Vec<u8>, input: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    ensure!(
        hash(&elf) == ELF_SHA
            && hash(&input) == INPUT_SHA
            && input.len() == full_relation::INPUT_BYTES,
        "original image/input bytes differ"
    );
    ensure!(
        compute_image_id(&elf)?.to_string() == IMAGE,
        "original image differs"
    );
    let journal =
        full_relation::unverified_claimed_journal(&input).map_err(|e| anyhow!("{e:?}"))?;
    Ok((elf, input, journal.to_vec()))
}
fn original(path: &Path) -> Result<Receipt> {
    let raw = read(path, ORIGINAL_BYTES)?;
    ensure!(
        raw.len() == ORIGINAL_BYTES && hash(&raw) == ORIGINAL_SHA,
        "original Composite bytes differ"
    );
    composite_bounds::preflight(&raw)?;
    let receipt: Receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(ORIGINAL_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(&raw)?;
    let InnerReceipt::Composite(c) = &receipt.inner else {
        anyhow::bail!("Composite input required")
    };
    ensure!(
        c.segments.len() == 62 && c.assumption_receipts.is_empty(),
        "original 62/no-assumptions profile"
    );
    for (i, segment) in c.segments.iter().enumerate() {
        ensure!(
            segment.index as usize == i
                && segment.hashfn == "poseidon2"
                && composite_bounds::check_seal(&segment.seal)? == 1 << 18
                && segment.povw_nonce()?.to_bytes() == [0u8; 32],
            "original segment profile differs"
        );
        ensure!(
            segment.claim.exit_code
                == if i == 61 {
                    ExitCode::Halted(0)
                } else {
                    ExitCode::SystemSplit
                },
            "original segment termination differs"
        );
    }
    ensure!(
        receipt
            .claim()?
            .digest::<risc0_zkvm::sha::Impl>()
            .to_string()
            == CLAIM,
        "original full claim differs"
    );
    Ok(receipt)
}
fn composite(receipt: &Receipt) -> Result<&CompositeReceipt> {
    if let InnerReceipt::Composite(c) = &receipt.inner {
        Ok(c)
    } else {
        anyhow::bail!("Composite input required")
    }
}
fn expected_claim(original: &Receipt, start: usize, end: usize) -> Result<ReceiptClaim> {
    ensure!(
        start < end && end <= 62,
        "invalid original contiguous range"
    );
    let c = composite(original)?;
    let mut claim = c.segments[start].claim.clone();
    for segment in &c.segments[start + 1..end] {
        ensure!(
            claim.post.digest::<risc0_zkvm::sha::Impl>()
                == segment.claim.pre.digest::<risc0_zkvm::sha::Impl>()
                && claim.exit_code == ExitCode::SystemSplit,
            "noncontiguous original claims"
        );
        claim = claim.join(&segment.claim);
    }
    Ok(claim)
}
fn check_profile(
    r: &SuccinctReceipt<ReceiptClaim>,
    claim: &ReceiptClaim,
    width: usize,
) -> Result<()> {
    bounds::seal(&r.seal)?;
    let ctx = context();
    let parameters = ctx
        .succinct_verifier_parameters
        .as_ref()
        .context("pinned recursion parameters")?;
    ensure!(
        parameters.control_root.to_string() == CONTROL_ROOT
            && parameters.inner_control_root.is_none(),
        "pinned control root differs"
    );
    ensure!(
        r.hashfn == "poseidon2"
            && r.verifier_parameters == parameters.digest::<risc0_zkvm::sha::Impl>()
            && r.control_id.to_string() == if width == 1 { LIFT_ID } else { JOIN_ID }
            && r.control_inclusion_proof.digests.len() == 8
            && r.control_inclusion_proof.index < 256,
        "unreviewed recursion program or verifier parameters"
    );
    ensure!(
        r.claim.as_value().is_ok()
            && r.claim.digest::<risc0_zkvm::sha::Impl>() == claim.digest::<risc0_zkvm::sha::Impl>(),
        "recursion claim differs from exact original range"
    );
    Ok(())
}
fn check_succinct(
    r: &SuccinctReceipt<ReceiptClaim>,
    claim: &ReceiptClaim,
    width: usize,
) -> Result<()> {
    check_profile(r, claim, width)?;
    r.verify_integrity_with_context(&context())?;
    Ok(())
}
fn read_succinct(path: &Path) -> Result<SuccinctReceipt<ReceiptClaim>> {
    let raw = read(path, bounds::MAX_BYTES)?;
    bounds::preflight(&raw, false)?;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bounds::MAX_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(&raw)?)
}
fn decode_outer(raw: &[u8]) -> Result<Receipt> {
    bounds::preflight(raw, true)?;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bounds::MAX_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(raw)?)
}
fn verify_outer(raw: &[u8], elf: &[u8], journal: &[u8]) -> Result<()> {
    let receipt = decode_outer(raw)?;
    ensure!(
        receipt.journal.bytes == journal,
        "complete W1 public journal differs"
    );
    let InnerReceipt::Succinct(s) = &receipt.inner else {
        anyhow::bail!("Succinct output required")
    };
    ensure!(
        s.claim.digest::<risc0_zkvm::sha::Impl>().to_string() == CLAIM,
        "complete W1 claim differs"
    );
    // Complete SDK verification binds image, successful exit, empty assumptions
    // and this exact journal. No original Composite verifier is relaxed.
    check_profile(s, s.claim.as_value()?, 62)?;
    receipt.verify_with_context(&context(), compute_image_id(elf)?)?;
    Ok(())
}
fn timed_verify(raw: &[u8], elf: &[u8], journal: &[u8]) -> Result<Value> {
    let started = Instant::now();
    let cpu = process_cpu::nanoseconds()?;
    verify_outer(raw, elf, journal)?;
    Ok(json!({"verify_wall_ns":started.elapsed().as_nanos(),
        "verify_process_cpu_ns":process_cpu::nanoseconds()?.checked_sub(cpu).context("CPU clock backwards")?}))
}
fn certificate_parts(wire: &[u8]) -> Result<(&[u8], &[u8])> {
    ensure!(
        wire.len() >= 16 && &wire[..8] == WIRE_MAGIC,
        "research certificate magic or header differs"
    );
    let input_len = u32::from_le_bytes(wire[8..12].try_into()?) as usize;
    let receipt_len = u32::from_le_bytes(wire[12..16].try_into()?) as usize;
    ensure!(
        input_len == full_relation::INPUT_BYTES
            && receipt_len <= bounds::MAX_BYTES
            && wire.len() == 16 + full_relation::INPUT_BYTES + receipt_len,
        "certificate lengths or trailing bytes differ"
    );
    Ok((&wire[16..16 + input_len], &wire[16 + input_len..]))
}
fn certificate(input: &[u8], receipt: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        input.len() == full_relation::INPUT_BYTES && receipt.len() <= bounds::MAX_BYTES,
        "certificate material budget"
    );
    let mut wire = WIRE_MAGIC.to_vec();
    wire.extend((input.len() as u32).to_le_bytes());
    wire.extend((receipt.len() as u32).to_le_bytes());
    wire.extend(input);
    wire.extend(receipt);
    Ok(wire)
}
fn verify_certificate(wire: &[u8], elf: &[u8]) -> Result<()> {
    let (input, receipt) = certificate_parts(wire)?;
    // These are the bytes actually received, not separately supplied local stdin.
    let (elf, _, journal) = pinned_values(elf.to_vec(), input.to_vec())?;
    verify_outer(receipt, &elf, &journal)
}
fn verify_certificate_command(args: &[String]) -> Result<()> {
    ensure!(args.len() == 4, "verify-certificate <elf> <certificate>");
    let elf = read(Path::new(&args[2]), 16 * 1024 * 1024)?;
    let wire = read(
        Path::new(&args[3]),
        16 + full_relation::INPUT_BYTES + bounds::MAX_BYTES,
    )?;
    let started = Instant::now();
    let cpu = process_cpu::nanoseconds()?;
    verify_certificate(&wire, &elf)?;
    let wall = started.elapsed().as_nanos();
    let used = process_cpu::nanoseconds()?
        .checked_sub(cpu)
        .context("CPU backwards")?;
    let (input, receipt) = certificate_parts(&wire)?;
    println!(
        "{}",
        json!({"schema":"pon-w1-succinct-certificate-verify-v1",
        "certificate_bytes":wire.len(),"certificate_sha256":hash(&wire),
        "receipt_bytes":receipt.len(),"receipt_sha256":hash(receipt),
        "public_input_bytes":input.len(),"public_input_sha256":hash(input),
        "image_id":IMAGE,"claim_digest":CLAIM,"real_succinct_stark_verified":true,
        "verify_certificate_wall_ns":wall,"verify_certificate_process_cpu_ns":used,
        "verification_uses_received_input_and_receipt":true,"native_w1_recomputed":false,
        "consensus_authority":false})
    );
    Ok(())
}
fn prepare(args: &[String]) -> Result<()> {
    ensure!(args.len() == 4, "prepare <original-dir> <new-manifest>");
    let d = Path::new(&args[2]);
    let (elf, input, journal) = pinned_material(&d.join("guest.bin"), &d.join("input.bin"))?;
    let receipt = original(&d.join("receipt.bin"))?;
    ensure!(
        receipt.journal.bytes == journal,
        "original public journal differs"
    );
    receipt.verify_with_context(&context(), compute_image_id(&elf)?)?;
    ensure!(
        full_relation::execute_input(&input)
            .map_err(|e| anyhow!("{e:?}"))?
            .journal()
            == journal,
        "independent full native W1 differs"
    );
    let record = json!({"schema":"pon-w1-succinct-prepare-v1","original_sha256":ORIGINAL_SHA,
        "original_bytes":ORIGINAL_BYTES,"segments":62,"image_id":IMAGE,"input_sha256":INPUT_SHA,
        "journal_sha256":hash(&journal),"claim_digest":CLAIM,"original_composite_verified":true,
        "native_full_w1_matches":true,"new_recursion_stages":123,"new_proof_generated":false,
        "additional_pow":false,"povw_requested":false,"consensus_authority":false});
    write_new(Path::new(&args[3]), &serde_json::to_vec_pretty(&record)?)?;
    println!("{record}");
    Ok(())
}
fn stage(args: &[String]) -> Result<()> {
    // Explicit range endpoints prevent a caller substituting a different
    // legal recursion tree, a duplicated leaf, or a neighbouring claim.
    ensure!(
        args.len() == 10,
        "stage <r0vm> <original> <start> <split> <end> <left-or-dash> <right-or-dash> <new-output>"
    );
    ensure!(
        std::env::var("RAYON_NUM_THREADS").as_deref() == Ok("2"),
        "two Rayon threads required"
    );
    let start: usize = args[4].parse()?;
    let split: usize = args[5].parse()?;
    let end: usize = args[6].parse()?;
    let original = original(Path::new(&args[3]))?;
    let expected = expected_claim(&original, start, end)?;
    let opts = ProverOpts::succinct().with_dev_mode(false);
    let started = Instant::now();
    let client = ApiClient::new_sub_process(&args[2])?;
    let (receipt, operation) = if end == start + 1 {
        ensure!(
            split == end && args[7] == "-" && args[8] == "-",
            "exact lift invocation required"
        );
        (
            client.lift(
                &opts,
                composite(&original)?.segments[start].clone().try_into()?,
                AssetRequest::Inline,
            )?,
            "lift",
        )
    } else {
        ensure!(
            start < split && split < end,
            "contiguous join ranges required"
        );
        let a = read_succinct(Path::new(&args[7]))?;
        let b = read_succinct(Path::new(&args[8]))?;
        check_succinct(&a, &expected_claim(&original, start, split)?, split - start)?;
        check_succinct(&b, &expected_claim(&original, split, end)?, end - split)?;
        ensure!(
            a.claim.as_value()?.post.digest::<risc0_zkvm::sha::Impl>()
                == b.claim.as_value()?.pre.digest::<risc0_zkvm::sha::Impl>(),
            "join pre/post mismatch"
        );
        (
            client.join(&opts, a.try_into()?, b.try_into()?, AssetRequest::Inline)?,
            "join",
        )
    };
    let raw = bincode::serialize(&receipt)?;
    ensure!(
        raw.len() <= bounds::MAX_BYTES,
        "returned recursion candidate byte cap"
    );
    write_new(Path::new(&args[9]), &raw)?; // Bounded failed candidates are retained too.
    bounds::preflight(&raw, false)?;
    check_succinct(&receipt, &expected, end - start)?;
    println!(
        "{}",
        json!({"schema":"pon-w1-succinct-stage-v1","operation":operation,
        "start":start,"split":split,"end":end,"receipt_bytes":raw.len(),"receipt_sha256":hash(&raw),
        "claim_digest":expected.digest::<risc0_zkvm::sha::Impl>().to_string(),"control_id":receipt.control_id.to_string(),
        "recursion_po2":18,"real_recursion_stark_verified":true,"complete_w1_proof_verified":false,
        "prove_and_check_wall_ns":started.elapsed().as_nanos(),"additional_pow":false,"povw_requested":false,
        "dev_mode":false,"consensus_authority":false})
    );
    Ok(())
}
fn finish(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 6,
        "finish <original-dir> <root-succinct> <new-receipt> <new-wire>"
    );
    let d = Path::new(&args[2]);
    let (elf, input, journal) = pinned_material(&d.join("guest.bin"), &d.join("input.bin"))?;
    let original = original(&d.join("receipt.bin"))?;
    let root = read_succinct(Path::new(&args[3]))?;
    check_succinct(&root, &expected_claim(&original, 0, 62)?, 62)?;
    let receipt = Receipt::new(InnerReceipt::Succinct(root), journal.clone());
    let raw = bincode::serialize(&receipt)?;
    write_new(Path::new(&args[4]), &raw)?;
    verify_outer(&raw, &elf, &journal)?;
    let wire = certificate(&input, &raw)?;
    write_new(Path::new(&args[5]), &wire)?;
    println!(
        "{}",
        json!({"schema":"pon-w1-succinct-finish-v1","real_succinct_stark_verified":true,
        "receipt_bytes":raw.len(),"receipt_sha256":hash(&raw),"certificate_wire_bytes":wire.len(),
        "certificate_wire_sha256":hash(&wire),"certificate_magic":"PWSR0001",
        "public_input_bytes":input.len(),"framing_bytes":16,"packet_budget":PACKET_BUDGET,
        "certificate_fits_one_mib":wire.len()<=PACKET_BUDGET,
        "legacy_empty_packet_budget_comparison_bytes":wire.len()+318+2,
        "legacy_256_transaction_2048_byte_profile_comparison_bytes":wire.len()+318+2+256*(2+2048),
        "transaction_size_assumption":"legacy profile only; not a general PQ transaction upper bound",
        "pq_transaction_capacity_qualified":false,
        "existing_pnw1_bytes":49188,"existing_packet_codec_accepts_succinct":false,
        "image_id":IMAGE,"claim_digest":CLAIM,"additional_pow":false,"povw_requested":false,
        "dev_mode":false,"consensus_authority":false})
    );
    Ok(())
}
fn rejection(name: &str, f: impl FnOnce() -> Result<()>) -> Result<Value> {
    let started = Instant::now();
    let cpu = process_cpu::nanoseconds()?;
    let result = f();
    let wall = started.elapsed().as_nanos();
    let used = process_cpu::nanoseconds()?
        .checked_sub(cpu)
        .context("CPU backwards")?;
    ensure!(
        result.is_err(),
        "invalid control unexpectedly accepted: {name}"
    );
    Ok(
        json!({"case":name,"rejected":true,"wall_ns":wall,"process_cpu_ns":used,"error":result.unwrap_err().to_string()}),
    )
}
fn audit(raw: &[u8], elf: &[u8], input: &[u8], journal: &[u8]) -> Result<()> {
    verify_outer(raw, elf, journal)?;
    let good = decode_outer(raw)?;
    let mut rows = Vec::new();
    for (name, kind) in [
        ("composite_kind", 0u32),
        ("groth16_kind", 2),
        ("fake_kind", 3),
        ("unknown_kind", u32::MAX),
    ] {
        let mut bad = raw.to_vec();
        bad[..4].copy_from_slice(&kind.to_le_bytes());
        rows.push(rejection(name, || verify_outer(&bad, elf, journal))?);
    }
    let mut bad = raw.to_vec();
    bad[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    rows.push(rejection("unbounded_seal_prefix", || {
        verify_outer(&bad, elf, journal)
    })?);
    let mut bad = raw.to_vec();
    bad.push(0);
    rows.push(rejection("trailing_byte", || {
        verify_outer(&bad, elf, journal)
    })?);
    rows.push(rejection("truncated_byte", || {
        verify_outer(&raw[..raw.len() - 1], elf, journal)
    })?);
    for name in [
        "last_seal_tamper",
        "first_seal_tamper",
        "excessive_po2",
        "wrong_control_id",
        "wrong_parameters",
        "wrong_hash_suite",
        "wrong_control_path",
        "empty_seal",
    ] {
        let mut receipt = good.clone();
        let InnerReceipt::Succinct(s) = &mut receipt.inner else {
            unreachable!()
        };
        match name {
            "last_seal_tamper" => {
                let last = s.seal.len() - 1;
                s.seal[last] ^= 1;
            }
            "first_seal_tamper" => s.seal[0] ^= 1,
            "excessive_po2" => s.seal[32] = 24,
            "wrong_control_id" => s.control_id = risc0_zkvm::sha::Digest::ZERO,
            "wrong_parameters" => s.verifier_parameters = risc0_zkvm::sha::Digest::ZERO,
            "wrong_hash_suite" => s.hashfn = "sha-256".into(),
            "wrong_control_path" => {
                s.control_inclusion_proof.digests[0] = risc0_zkvm::sha::Digest::ZERO
            }
            "empty_seal" => s.seal.clear(),
            _ => unreachable!(),
        }
        let bad = bincode::serialize(&receipt)?;
        rows.push(rejection(name, || verify_outer(&bad, elf, journal))?);
    }
    let mut bad = good.clone();
    bad.journal.bytes[0] ^= 1;
    let bad = bincode::serialize(&bad)?;
    rows.push(rejection("wrong_journal", || {
        verify_outer(&bad, elf, journal)
    })?);
    rows.push(rejection("wrong_expected_image", || {
        Ok(good.verify_with_context(&context(), risc0_zkvm::sha::Digest::ZERO)?)
    })?);
    let wire = certificate(input, raw)?;
    verify_certificate(&wire, elf)?;
    let mut certificate_cases = Vec::new();
    for name in [
        "certificate_wrong_magic",
        "certificate_input_length",
        "certificate_receipt_length",
        "certificate_trailing_byte",
        "certificate_truncated_byte",
        "certificate_changed_input",
        "certificate_changed_receipt",
    ] {
        let mut bad = wire.clone();
        match name {
            "certificate_wrong_magic" => bad[0] ^= 1,
            "certificate_input_length" => bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes()),
            "certificate_receipt_length" => bad[12..16].copy_from_slice(&u32::MAX.to_le_bytes()),
            "certificate_trailing_byte" => bad.push(0),
            "certificate_truncated_byte" => {
                bad.pop();
            }
            "certificate_changed_input" => bad[16] ^= 1,
            "certificate_changed_receipt" => {
                let last = bad.len() - 1;
                bad[last] ^= 1;
            }
            _ => unreachable!(),
        }
        certificate_cases.push(rejection(name, || verify_certificate(&bad, elf))?);
    }
    println!(
        "{}",
        json!({"schema":"pon-w1-succinct-audit-v1","cases":rows,"certificate_cases":certificate_cases,
        "actual_complete_certificate_positive_verified":true,"all_tested_rejected":true,
        "global_worst_invalid_proven":false,"consensus_authority":false})
    );
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(args.len() >= 2, "command required");
    match args[1].as_str() {
        "prepare" => prepare(&args),
        "stage" => stage(&args),
        "finish" => finish(&args),
        "verify-certificate" => verify_certificate_command(&args),
        "verify" | "audit" | "benchmark" => {
            ensure!(args.len() == 5, "verify/audit <elf> <input> <receipt>");
            let (elf, input, journal) = pinned_material(Path::new(&args[2]), Path::new(&args[3]))?;
            let raw = read(Path::new(&args[4]), bounds::MAX_BYTES)?;
            if args[1] == "audit" {
                return audit(&raw, &elf, &input, &journal);
            }
            if args[1] == "benchmark" {
                let mut samples = Vec::new();
                for _ in 0..31 {
                    samples.push(timed_verify(&raw, &elf, &journal)?);
                }
                println!(
                    "{}",
                    json!({"schema":"pon-w1-succinct-benchmark-v1",
                    "samples":samples,"receipt_sha256":hash(&raw),"receipt_bytes":raw.len(),
                    "real_succinct_stark_verified":true,"native_w1_recomputed":false,
                    "consensus_authority":false})
                );
                return Ok(());
            }
            let mut record = timed_verify(&raw, &elf, &journal)?;
            record["schema"] = json!("pon-w1-succinct-verify-v1");
            record["real_succinct_stark_verified"] = json!(true);
            record["receipt_sha256"] = json!(hash(&raw));
            record["receipt_bytes"] = json!(raw.len());
            record["image_id"] = json!(IMAGE);
            record["claim_digest"] = json!(CLAIM);
            record["native_w1_recomputed"] = json!(false);
            record["consensus_authority"] = json!(false);
            println!("{record}");
            Ok(())
        }
        _ => anyhow::bail!("unknown research-only command"),
    }
}

#[cfg(test)]
mod certificate_tests {
    use super::*;

    #[test]
    fn certificate_header_rejects_foreign_or_unbounded_material() {
        for raw in [Vec::new(), vec![0; 16], b"PWSR0001".to_vec()] {
            assert!(certificate_parts(&raw).is_err());
        }
        let mut raw = b"PWSR0001".to_vec();
        raw.extend(u32::MAX.to_le_bytes());
        raw.extend(u32::MAX.to_le_bytes());
        assert!(certificate_parts(&raw).is_err());
        raw[8..12].copy_from_slice(&(full_relation::INPUT_BYTES as u32).to_le_bytes());
        assert!(certificate_parts(&raw).is_err());
    }
}
