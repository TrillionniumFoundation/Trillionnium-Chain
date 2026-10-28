//! Checkpoint actual full-W1 STARK segments, then require recursive compression.
//! Checkpoints are experiment artifacts, never consensus admission capabilities.
use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use risc0_zkvm::{
    sha::Digestible, ApiClient, Asset, AssetRequest, CompositeReceipt, Digest, ExecutorEnv,
    ExitCode, InnerAssumptionReceipt, InnerReceipt, ProverOpts, Receipt, ReceiptClaim,
    SegmentReceipt, SuccinctReceipt, VerifierContext,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use trnm_w1_zk_methods::{TRNM_W1_FULL_GUEST_ELF, TRNM_W1_FULL_GUEST_ID};
use trnm_w1_zk_relation::{check_complete_relation, check_public_journal, INPUT_BYTES};

const SCHEMA: &str = "TRNM-W1-STAGED-PROOF1";
const R0VM_SHA256: &str = "2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6";
const MAX_ASSET: u64 = 64 * 1024 * 1024;
const MAX_RECEIPT: u64 = 16 * 1024 * 1024;
const MAX_SEGMENTS: usize = 4096;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Segment {
    index: usize,
    po2: u32,
    cycles: u32,
    bytes: usize,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    source_commit: String,
    runner_sha256: String,
    guest_sha256: String,
    image_id: [u32; 8],
    r0vm_sha256: String,
    input_sha256: String,
    journal_sha256: String,
    full_claim_digest: String,
    segment_limit_po2: u32,
    segments: Vec<Segment>,
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "artifact exceeds byte bound");
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().context("artifact parent")?)?.sync_all()?;
    Ok(())
}

fn event(out: &Path, value: serde_json::Value) -> Result<()> {
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(out.join("stages.jsonl"))?;
    let row =
        json!({"unix_ns":SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(), "event":value});
    writeln!(log, "{row}")?;
    log.sync_all()?;
    println!("{row}");
    Ok(())
}

fn source_commit() -> Result<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let status = Command::new("git")
        .current_dir(&root)
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()?;
    ensure!(
        status.status.success() && status.stdout.is_empty(),
        "source must be committed and clean before each stage"
    );
    let result = Command::new("git")
        .current_dir(&root)
        .args(["rev-parse", "HEAD"])
        .output()?;
    ensure!(result.status.success(), "source commit unavailable");
    let commit = String::from_utf8(result.stdout)?.trim().to_owned();
    ensure!(
        commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "source commit encoding"
    );
    // Git status alone can miss assume-unchanged/skip-worktree changes. Reuse
    // the repository's raw-byte/mode/symlink verifier on the exact commit.
    let verified = Command::new("python3")
        .current_dir(&root)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .args([
            "scripts/ci/verify_ci_source.py",
            "--kind",
            "head",
            "--expected-head",
            &commit,
        ])
        .output()?;
    ensure!(
        verified.status.success(),
        "raw committed source verification failed: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let identity: serde_json::Value = serde_json::from_slice(&verified.stdout)?;
    println!(
        "{}",
        json!({"stage":"RAW_COMMITTED_SOURCE_VERIFIED","identity":identity})
    );
    Ok(commit)
}

fn original_claim(journal: &[u8]) -> ReceiptClaim {
    ReceiptClaim::ok(TRNM_W1_FULL_GUEST_ID, journal.to_vec())
}

fn validate_manifest(
    manifest: &Manifest,
    input: &[u8],
    journal: &[u8],
    commit: &str,
    runner: &str,
) -> Result<()> {
    ensure!(manifest.schema == SCHEMA, "checkpoint schema");
    ensure!(
        manifest.source_commit == commit && manifest.runner_sha256 == runner,
        "checkpoint source/runner changed"
    );
    ensure!(
        manifest.guest_sha256 == sha(TRNM_W1_FULL_GUEST_ELF)
            && manifest.image_id == TRNM_W1_FULL_GUEST_ID,
        "checkpoint guest changed"
    );
    ensure!(
        manifest.r0vm_sha256 == R0VM_SHA256,
        "checkpoint backend changed"
    );
    ensure!(
        manifest.input_sha256 == sha(input) && manifest.journal_sha256 == sha(journal),
        "checkpoint input/journal changed"
    );
    ensure!(input.len() == INPUT_BYTES, "complete input length");
    ensure!(
        manifest.full_claim_digest == original_claim(journal).digest().to_string(),
        "full statement changed"
    );
    ensure!(
        (16..=18).contains(&manifest.segment_limit_po2),
        "bounded segment size"
    );
    ensure!(
        !manifest.segments.is_empty() && manifest.segments.len() <= MAX_SEGMENTS,
        "complete segment count"
    );
    for (index, row) in manifest.segments.iter().enumerate() {
        ensure!(
            row.index == index && row.po2 <= manifest.segment_limit_po2 && row.po2 >= 13,
            "segment order/size"
        );
        ensure!(
            row.bytes > 0 && row.bytes as u64 <= MAX_ASSET && row.sha256.len() == 64,
            "segment asset bound"
        );
    }
    let expected = check_complete_relation(input).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    ensure!(
        expected == journal,
        "checkpoint no longer equals original complete relation"
    );
    Ok(())
}

fn decode_segment(bytes: &[u8]) -> Result<SegmentReceipt> {
    ensure!(bytes.len() as u64 <= MAX_RECEIPT, "segment receipt bound");
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_RECEIPT)
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}

fn validate_segment(
    receipt: &SegmentReceipt,
    index: usize,
    count: usize,
    expected_pre: Digest,
    journal: &[u8],
    ctx: &VerifierContext,
) -> Result<Digest> {
    ensure!(
        receipt.index as usize == index,
        "segment receipt index mismatch"
    );
    receipt.verify_integrity_with_context(ctx)?;
    ensure!(
        receipt.claim.pre.digest() == expected_pre,
        "segment continuation mismatch"
    );
    if index + 1 == count {
        ensure!(
            receipt.claim.exit_code == ExitCode::Halted(0),
            "last segment must halt successfully"
        );
        ensure!(
            receipt.claim.output.digest() == original_claim(journal).output.digest(),
            "last segment full output/assumptions mismatch"
        );
    } else {
        ensure!(
            receipt.claim.exit_code == ExitCode::SystemSplit && receipt.claim.output.is_none(),
            "nonfinal segment cannot end or commit output"
        );
    }
    Ok(receipt.claim.post.digest())
}

fn prepare(
    r0vm: &Path,
    out: &Path,
    input_path: &Path,
    po2: u32,
    commit: String,
    runner: String,
) -> Result<()> {
    ensure!(
        (16..=18).contains(&po2),
        "explicit resource-bounded segment size 16..18"
    );
    let input = bounded(input_path, INPUT_BYTES as u64)?;
    let journal = check_complete_relation(&input).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    fs::create_dir(out).context("prepare output must be new; preserve failed observations")?;
    write_new(&out.join("input.bin"), &input)?;
    write_new(&out.join("header.bin"), &input[..318])?;
    write_new(&out.join("expected-journal.bin"), &journal)?;
    write_new(&out.join("guest.bin"), TRNM_W1_FULL_GUEST_ELF)?;
    let mut manifest = Manifest {
        schema: SCHEMA.into(),
        source_commit: commit,
        runner_sha256: runner,
        guest_sha256: sha(TRNM_W1_FULL_GUEST_ELF),
        image_id: TRNM_W1_FULL_GUEST_ID,
        r0vm_sha256: R0VM_SHA256.into(),
        input_sha256: sha(&input),
        journal_sha256: sha(&journal),
        full_claim_digest: original_claim(&journal).digest().to_string(),
        segment_limit_po2: po2,
        segments: Vec::new(),
    };
    write_new(
        &out.join("prepare-identity.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    event(
        out,
        json!({"stage":"EXECUTE_STARTED","segment_limit_po2":po2}),
    )?;
    let started = Instant::now();
    let env = ExecutorEnv::builder()
        .segment_limit_po2(po2)
        .session_limit(Some(1 << 30))
        .write_slice(&input)
        .build()?;
    let client = ApiClient::new_sub_process(r0vm)?;
    let session = client.execute(&env, Asset::Inline(TRNM_W1_FULL_GUEST_ELF.into()), AssetRequest::Inline, |info, asset| {
        let index = manifest.segments.len();
        ensure!(index < MAX_SEGMENTS, "segment count bound");
        let bytes = asset.as_bytes()?;
        ensure!(bytes.len() as u64 <= MAX_ASSET, "executor segment asset bound");
        write_new(&out.join(format!("segment-{index:04}.bin")), &bytes)?;
        manifest.segments.push(Segment{index, po2:info.po2, cycles:info.cycles, bytes:bytes.len(), sha256:sha(&bytes)});
        event(out, json!({"stage":"SEGMENT_EXPORTED","index":index,"po2":info.po2,"cycles":info.cycles,"bytes":bytes.len()}))
    })?;
    ensure!(
        session.exit_code == ExitCode::Halted(0) && session.journal.bytes == journal,
        "full guest/native output mismatch"
    );
    ensure!(
        session
            .receipt_claim
            .as_ref()
            .context("missing full execution claim")?
            .digest()
            == original_claim(&journal).digest(),
        "execution full claim mismatch"
    );
    ensure!(
        session.segments.len() == manifest.segments.len(),
        "missing exported segments"
    );
    for (expected, actual) in session.segments.iter().zip(&manifest.segments) {
        ensure!(
            expected.cycles == actual.cycles && expected.po2 == actual.po2,
            "exported segment order/metadata mismatch"
        );
    }
    validate_manifest(
        &manifest,
        &input,
        &journal,
        &manifest.source_commit,
        &manifest.runner_sha256,
    )?;
    write_new(
        &out.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    event(
        out,
        json!({"stage":"COMPLETE_RELATION_EXECUTED","elapsed_ns":started.elapsed().as_nanos(),"cycles":session.cycles(),"segments":manifest.segments.len(),"cryptographic_proof_complete":false}),
    )
}

fn load(out: &Path, commit: &str, runner: &str) -> Result<(Manifest, Vec<u8>, Vec<u8>)> {
    let manifest: Manifest =
        serde_json::from_slice(&bounded(&out.join("manifest.json"), 1024 * 1024)?)?;
    let input = bounded(&out.join("input.bin"), INPUT_BYTES as u64)?;
    let journal = bounded(&out.join("expected-journal.bin"), 64 * 1024)?;
    validate_manifest(&manifest, &input, &journal, commit, runner)?;
    Ok((manifest, input, journal))
}

fn prove(r0vm: &Path, out: &Path, max_new: usize, commit: &str, runner: &str) -> Result<()> {
    ensure!(max_new <= MAX_SEGMENTS, "new proof budget bound");
    let (manifest, _, journal) = load(out, commit, runner)?;
    let ctx = VerifierContext::default();
    let opts = ProverOpts::succinct();
    let mut expected_pre = Digest::from(TRNM_W1_FULL_GUEST_ID);
    let mut created = 0;
    for row in &manifest.segments {
        let path = out.join(format!("receipt-{:04}.bin", row.index));
        if path.exists() {
            let started = Instant::now();
            let receipt = decode_segment(&bounded(&path, MAX_RECEIPT)?)?;
            expected_pre = validate_segment(
                &receipt,
                row.index,
                manifest.segments.len(),
                expected_pre,
                &journal,
                &ctx,
            )?;
            event(
                out,
                json!({"stage":"CHECKPOINT_CRYPTOGRAPHICALLY_REVERIFIED","index":row.index,"elapsed_ns":started.elapsed().as_nanos()}),
            )?;
            continue;
        }
        if created == max_new {
            event(
                out,
                json!({"stage":"SEGMENT_BUDGET_EXHAUSTED","verified_prefix":row.index,"total_segments":manifest.segments.len(),"cryptographic_proof_complete":false}),
            )?;
            return Ok(());
        }
        let asset = bounded(
            &out.join(format!("segment-{:04}.bin", row.index)),
            MAX_ASSET,
        )?;
        ensure!(
            asset.len() == row.bytes && sha(&asset) == row.sha256,
            "frozen segment asset changed"
        );
        event(
            out,
            json!({"stage":"REAL_SEGMENT_PROVING_STARTED","index":row.index,"po2":row.po2,"rayon_threads":std::env::var("RAYON_NUM_THREADS").ok()}),
        )?;
        let started = Instant::now();
        let client = ApiClient::new_sub_process(r0vm)?;
        let receipt =
            client.prove_segment(&opts, Asset::Inline(asset.into()), AssetRequest::Inline)?;
        let prover_ns = started.elapsed().as_nanos();
        let verify_started = Instant::now();
        expected_pre = validate_segment(
            &receipt,
            row.index,
            manifest.segments.len(),
            expected_pre,
            &journal,
            &ctx,
        )?;
        let verifier_ns = verify_started.elapsed().as_nanos();
        let bytes = bincode::serialize(&receipt)?;
        // create_new + fsync makes a crash visible. A truncated file is rejected
        // on resumption; never erase it automatically or relabel it successful.
        write_new(&path, &bytes)?;
        let readback = decode_segment(&bounded(&path, MAX_RECEIPT)?)?;
        readback.verify_integrity_with_context(&ctx)?;
        event(
            out,
            json!({"stage":"REAL_SEGMENT_STARK_SAVED_VERIFIED","index":row.index,"prover_ns":prover_ns,"verifier_ns":verifier_ns,"receipt_bytes":bytes.len(),"receipt_sha256":sha(&bytes),"cryptographic_proof_complete":false}),
        )?;
        created += 1;
    }
    event(
        out,
        json!({"stage":"ALL_SEGMENT_STARKS_VERIFIED","segments":manifest.segments.len(),"new_segments":created,"succinct_proof_complete":false}),
    )
}

fn adopt_execution(out: &Path, previous: &Path, commit: &str, runner: &str) -> Result<()> {
    let old_bytes = bounded(&previous.join("manifest.json"), 1024 * 1024)?;
    let old: Manifest = serde_json::from_slice(&old_bytes)?;
    let (mut manifest, input, journal) = load(previous, &old.source_commit, &old.runner_sha256)?;
    ensure!(
        bounded(&previous.join("guest.bin"), MAX_ASSET)? == TRNM_W1_FULL_GUEST_ELF,
        "adopted guest bytes changed"
    );
    fs::create_dir(out).context("adoption output must be new")?;
    write_new(&out.join("input.bin"), &input)?;
    write_new(&out.join("header.bin"), &input[..318])?;
    write_new(&out.join("expected-journal.bin"), &journal)?;
    write_new(&out.join("guest.bin"), TRNM_W1_FULL_GUEST_ELF)?;
    // Adopt the ENTIRE original frozen execution, never mix segment assets
    // from different executions. SYS_RANDOM may change intermediate states.
    for row in &manifest.segments {
        let filename = format!("segment-{:04}.bin", row.index);
        let bytes = bounded(&previous.join(&filename), MAX_ASSET)?;
        ensure!(
            bytes.len() == row.bytes && sha(&bytes) == row.sha256,
            "adopted segment asset changed"
        );
        write_new(&out.join(filename), &bytes)?;
    }
    write_new(&out.join("adopted-execution-manifest.json"), &old_bytes)?;
    let record = json!({"schema":"TRNM-W1-FROZEN-EXECUTION-ADOPTION1","execution_source_commit":old.source_commit,"execution_runner_sha256":old.runner_sha256,"original_manifest_sha256":sha(&old_bytes),"new_runner_source_commit":commit,"new_runner_sha256":runner,"whole_original_session_retained":true,"segments":manifest.segments.len(),"fresh_execution_claimed":false,"full_proof_complete":false});
    write_new(
        &out.join("adoption.json"),
        &serde_json::to_vec_pretty(&record)?,
    )?;
    manifest.source_commit = commit.into();
    manifest.runner_sha256 = runner.into();
    validate_manifest(&manifest, &input, &journal, commit, runner)?;
    write_new(
        &out.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    event(
        out,
        json!({"stage":"COMPLETE_FROZEN_EXECUTION_ADOPTED","record":record}),
    )
}

fn import_prefix(out: &Path, previous: &Path, commit: &str, runner: &str) -> Result<()> {
    let (manifest, input, journal) = load(out, commit, runner)?;
    let old_bytes = bounded(&previous.join("manifest.json"), 1024 * 1024)?;
    let old: Manifest = serde_json::from_slice(&old_bytes)?;
    let (_, old_input, old_journal) = load(previous, &old.source_commit, &old.runner_sha256)?;
    ensure!(
        input == old_input && journal == old_journal && manifest.segments == old.segments,
        "imported complete execution differs"
    );
    // Explicit provenance transition. The previous source or manifest is not
    // itself a proof: each imported seal and continuation is verified again.
    let ctx = VerifierContext::default();
    let mut expected_pre = Digest::from(TRNM_W1_FULL_GUEST_ID);
    let mut imported = Vec::new();
    let mut missing = false;
    for row in &manifest.segments {
        for directory in [out, previous] {
            let bytes = bounded(
                &directory.join(format!("segment-{:04}.bin", row.index)),
                MAX_ASSET,
            )?;
            ensure!(
                bytes.len() == row.bytes && sha(&bytes) == row.sha256,
                "imported segment asset differs"
            );
        }
        let filename = format!("receipt-{:04}.bin", row.index);
        if !previous.join(&filename).exists() {
            missing = true;
            continue;
        }
        ensure!(!missing, "imported proof prefix has a gap");
        let bytes = bounded(&previous.join(&filename), MAX_RECEIPT)?;
        let receipt = decode_segment(&bytes)?;
        expected_pre = validate_segment(
            &receipt,
            row.index,
            manifest.segments.len(),
            expected_pre,
            &journal,
            &ctx,
        )?;
        write_new(&out.join(filename), &bytes)?;
        imported.push(json!({"index":row.index,"sha256":sha(&bytes),"bytes":bytes.len()}));
    }
    ensure!(!imported.is_empty(), "no actual checkpoint to import");
    write_new(&out.join("imported-manifest.json"), &old_bytes)?;
    let history = bounded(&previous.join("stages.jsonl"), MAX_ASSET)?;
    write_new(&out.join("imported-stages.jsonl"), &history)?;
    let record = json!({"schema":"TRNM-W1-VERIFIED-IMPORT1","previous_source_commit":old.source_commit,"previous_runner_sha256":old.runner_sha256,"previous_manifest_sha256":sha(&old_bytes),"previous_history_sha256":sha(&history),"receipts":imported,"prior_costs_must_be_included":true,"full_proof_complete":false});
    write_new(
        &out.join("import.json"),
        &serde_json::to_vec_pretty(&record)?,
    )?;
    event(
        out,
        json!({"stage":"ACTUAL_PREFIX_IMPORTED_AND_CRYPTOGRAPHICALLY_REVERIFIED","record":record}),
    )
}

fn recursive_checkpoint(
    out: &Path,
    name: &str,
    operation: &str,
    expected: Digest,
    create: impl FnOnce() -> Result<SuccinctReceipt<ReceiptClaim>>,
) -> Result<SuccinctReceipt<ReceiptClaim>> {
    let path = out.join(format!("{name}.bin"));
    if path.exists() {
        let bytes = bounded(&path, MAX_RECEIPT)?;
        let receipt: SuccinctReceipt<ReceiptClaim> = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_RECEIPT)
            .reject_trailing_bytes()
            .deserialize(&bytes)?;
        receipt.verify_integrity()?;
        ensure!(
            receipt.claim.digest() == expected,
            "recursive checkpoint statement mismatch"
        );
        event(
            out,
            json!({"stage":"RECURSIVE_CHECKPOINT_CRYPTOGRAPHICALLY_REVERIFIED","name":name,"eligible_as_final":false}),
        )?;
        return Ok(receipt);
    }
    event(
        out,
        json!({"stage":"REAL_RECURSION_STARTED","operation":operation,"name":name}),
    )?;
    let started = Instant::now();
    let receipt = create()?;
    let prover_ns = started.elapsed().as_nanos();
    let verify_started = Instant::now();
    receipt.verify_integrity()?;
    ensure!(
        receipt.claim.digest() == expected,
        "recursive result statement mismatch"
    );
    let verifier_ns = verify_started.elapsed().as_nanos();
    let bytes = bincode::serialize(&receipt)?;
    ensure!(bytes.len() as u64 <= MAX_RECEIPT, "recursive receipt bound");
    write_new(&path, &bytes)?;
    event(
        out,
        json!({"stage":"REAL_RECURSIVE_STARK_SAVED_VERIFIED","operation":operation,"name":name,"prover_ns":prover_ns,"verifier_ns":verifier_ns,"receipt_bytes":bytes.len(),"receipt_sha256":sha(&bytes),"eligible_as_final":false}),
    )?;
    Ok(receipt)
}

fn lift(r0vm: &Path, out: &Path, index: usize, commit: &str, runner: &str) -> Result<()> {
    let (manifest, _, journal) = load(out, commit, runner)?;
    ensure!(index < manifest.segments.len(), "lift index bound");
    let ctx = VerifierContext::default();
    let mut expected_pre = Digest::from(TRNM_W1_FULL_GUEST_ID);
    for ordinal in 0..=index {
        let segment = decode_segment(&bounded(
            &out.join(format!("receipt-{ordinal:04}.bin")),
            MAX_RECEIPT,
        )?)?;
        expected_pre = validate_segment(
            &segment,
            ordinal,
            manifest.segments.len(),
            expected_pre,
            &journal,
            &ctx,
        )?;
        if ordinal == index {
            let expected = segment.claim.digest();
            recursive_checkpoint(out, &format!("lift-{index:04}"), "lift", expected, || {
                ApiClient::new_sub_process(r0vm)?.lift(
                    &ProverOpts::succinct(),
                    segment.try_into()?,
                    AssetRequest::Inline,
                )
            })?;
        }
    }
    event(
        out,
        json!({"stage":"LIFT_CALIBRATION_COMPLETE","index":index,"full_proof_complete":false}),
    )
}

fn compress(r0vm: &Path, out: &Path, commit: &str, runner: &str) -> Result<()> {
    let (manifest, input, journal) = load(out, commit, runner)?;
    let ctx = VerifierContext::default();
    let mut segments = Vec::with_capacity(manifest.segments.len());
    let mut expected_pre = Digest::from(TRNM_W1_FULL_GUEST_ID);
    for row in &manifest.segments {
        let receipt = decode_segment(&bounded(
            &out.join(format!("receipt-{:04}.bin", row.index)),
            MAX_RECEIPT,
        )?)?;
        expected_pre = validate_segment(
            &receipt,
            row.index,
            manifest.segments.len(),
            expected_pre,
            &journal,
            &ctx,
        )?;
        segments.push(receipt);
    }
    // Open only a digest-equal final output, including the empty assumptions.
    // This does not change the statement authenticated by the segment seal.
    segments
        .last_mut()
        .context("empty continuation")?
        .claim
        .output = original_claim(&journal).output;
    // SDK 3.0.3 exposes a non-exhaustive struct without a constructor. Its pinned
    // serde struct encoding is precisely these three fields in this order.
    let encoded = bincode::serialize(&(
        &segments,
        Vec::<InnerAssumptionReceipt>::new(),
        ctx.composite_verifier_parameters()
            .context("composite verifier parameters")?
            .digest(),
    ))?;
    let composite: CompositeReceipt = bincode::deserialize(&encoded)?;
    ensure!(
        composite.claim()?.digest() == original_claim(&journal).digest(),
        "complete composite claim mismatch"
    );
    let receipt = Receipt::new(InnerReceipt::Composite(composite), journal.clone());
    receipt.verify(TRNM_W1_FULL_GUEST_ID)?;
    let composite_bytes = bincode::serialize(&receipt)?;
    let intermediate_path = out.join("intermediate-composite.bin");
    if intermediate_path.exists() {
        ensure!(
            bounded(&intermediate_path, MAX_ASSET)? == composite_bytes,
            "saved composite changed"
        );
    } else {
        write_new(&intermediate_path, &composite_bytes)?;
    }
    event(
        out,
        json!({"stage":"FULL_COMPOSITE_VERIFIED_INTERNAL_ONLY","bytes":composite_bytes.len(),"segments":manifest.segments.len(),"eligible_as_final":false}),
    )?;
    event(out, json!({"stage":"REAL_SUCCINCT_COMPRESSION_STARTED"}))?;
    let started = Instant::now();
    let client = ApiClient::new_sub_process(r0vm)?;
    let opts = ProverOpts::succinct();
    let mut accumulated: Option<SuccinctReceipt<ReceiptClaim>> = None;
    for (index, segment) in segments.iter().enumerate() {
        let lifted = recursive_checkpoint(
            out,
            &format!("lift-{index:04}"),
            "lift",
            segment.claim.digest(),
            || client.lift(&opts, segment.clone().try_into()?, AssetRequest::Inline),
        )?;
        accumulated = Some(match accumulated {
            None => lifted,
            Some(left) => {
                let claim = ReceiptClaim {
                    pre: segments[0].claim.pre.clone(),
                    post: segment.claim.post.clone(),
                    exit_code: segment.claim.exit_code,
                    input: segments[0].claim.input.clone(),
                    output: segment.claim.output.clone(),
                };
                recursive_checkpoint(
                    out,
                    &format!("join-through-{index:04}"),
                    "join",
                    claim.digest(),
                    || {
                        client.join(
                            &opts,
                            left.try_into()?,
                            lifted.try_into()?,
                            AssetRequest::Inline,
                        )
                    },
                )?
            }
        });
    }
    let final_inner = accumulated.context("missing recursive completion")?;
    ensure!(
        final_inner.claim.digest() == original_claim(&journal).digest(),
        "recursive completion omits original relation"
    );
    let succinct = Receipt::new(InnerReceipt::Succinct(final_inner), journal.clone());
    let prover_ns = started.elapsed().as_nanos();
    succinct
        .inner
        .succinct()
        .context("recursive STARK required; no fallback")?;
    succinct.verify(TRNM_W1_FULL_GUEST_ID)?;
    ensure!(
        succinct.journal.bytes == journal,
        "succinct full journal mismatch"
    );
    let work_id = check_public_journal(&input[..318], &succinct.journal.bytes)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let bytes = bincode::serialize(&succinct)?;
    ensure!(
        bytes.len() as u64 <= MAX_RECEIPT && bytes.get(..4) == Some(1u32.to_le_bytes().as_slice()),
        "strict final wire bound/tag"
    );
    write_new(&out.join("succinct.bin"), &bytes)?;
    event(
        out,
        json!({"stage":"FULL_SUCCINCT_STARK_SAVED_VERIFIED","compression_prover_ns":prover_ns,"receipt_bytes":bytes.len(),"receipt_sha256":sha(&bytes),"work_id":hex::encode(work_id),"proof_randomness_tickets":0,"consensus_admission":false,"fresh_process_verification_required":true}),
    )
}

fn run() -> Result<()> {
    for name in [
        "RISC0_DEV_MODE",
        "BONSAI_API_URL",
        "BONSAI_API_KEY",
        "RISC0_PROVER",
    ] {
        ensure!(
            std::env::var_os(name).is_none(),
            "unexpected proof-selection environment: {name}"
        );
    }
    let mut args = std::env::args().skip(1);
    ensure!(args.next().as_deref() == Some("--r0vm"), "usage: --r0vm PINNED_BINARY prepare NEW_DIR INPUT [po2=18] | prove DIR [max_new=1] | compress DIR");
    let r0vm = PathBuf::from(args.next().context("explicit local prover")?);
    ensure!(
        r0vm.is_absolute() && sha(&bounded(&r0vm, 256 * 1024 * 1024)?) == R0VM_SHA256,
        "pinned local prover mismatch"
    );
    let mode = args.next().context("stage")?;
    let out = PathBuf::from(args.next().context("checkpoint directory")?);
    let commit = source_commit()?;
    let runner = sha(&bounded(&std::env::current_exe()?, 256 * 1024 * 1024)?);
    match mode.as_str() {
        "prepare" => {
            let input = PathBuf::from(args.next().context("full input file")?);
            let po2 = args.next().unwrap_or_else(|| "18".into()).parse()?;
            ensure!(args.next().is_none(), "unexpected arguments");
            prepare(&r0vm, &out, &input, po2, commit, runner)
        }
        "prove" => {
            let max_new = args.next().unwrap_or_else(|| "1".into()).parse()?;
            ensure!(args.next().is_none(), "unexpected arguments");
            prove(&r0vm, &out, max_new, &commit, &runner)
        }
        "adopt-execution" => {
            let previous =
                PathBuf::from(args.next().context("original frozen execution directory")?);
            ensure!(args.next().is_none(), "unexpected arguments");
            adopt_execution(&out, &previous, &commit, &runner)
        }
        "import-prefix" => {
            let previous = PathBuf::from(args.next().context("previous checkpoint directory")?);
            ensure!(args.next().is_none(), "unexpected arguments");
            import_prefix(&out, &previous, &commit, &runner)
        }
        "lift" => {
            let index = args.next().context("segment index")?.parse()?;
            ensure!(args.next().is_none(), "unexpected arguments");
            lift(&r0vm, &out, index, &commit, &runner)
        }
        "compress" => {
            ensure!(args.next().is_none(), "unexpected arguments");
            compress(&r0vm, &out, &commit, &runner)
        }
        _ => bail!("unknown stage"),
    }
}

fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schema_is_strict_and_recursive_receipts_are_not_segment_receipts() {
        assert!(serde_json::from_str::<Manifest>(
            r#"{"schema":"TRNM-W1-STAGED-PROOF1","silent_fallback":true}"#
        )
        .is_err());
        assert!(decode_segment(&[0; 4]).is_err());
        assert!(decode_segment(&vec![0; MAX_RECEIPT as usize + 1]).is_err());
    }

    #[test]
    fn checkpoint_binds_source_input_journal_and_complete_order() {
        let input = trnm_w1_zk_relation::fixture(0);
        let journal = check_complete_relation(&input).unwrap();
        let mut manifest = Manifest {
            schema: SCHEMA.into(),
            source_commit: "commit".into(),
            runner_sha256: "runner".into(),
            guest_sha256: sha(TRNM_W1_FULL_GUEST_ELF),
            image_id: TRNM_W1_FULL_GUEST_ID,
            r0vm_sha256: R0VM_SHA256.into(),
            input_sha256: sha(&input),
            journal_sha256: sha(&journal),
            full_claim_digest: original_claim(&journal).digest().to_string(),
            segment_limit_po2: 18,
            segments: vec![Segment {
                index: 0,
                po2: 18,
                cycles: 1,
                bytes: 1,
                sha256: "0".repeat(64),
            }],
        };
        assert!(validate_manifest(&manifest, &input, &journal, "commit", "runner").is_ok());
        assert!(validate_manifest(&manifest, &input, &journal, "other", "runner").is_err());
        assert!(validate_manifest(&manifest, &input, &journal, "commit", "other").is_err());
        let mut changed = input.clone();
        changed[500] ^= 1;
        assert!(validate_manifest(&manifest, &changed, &journal, "commit", "runner").is_err());
        let mut changed = journal.clone();
        changed[500] ^= 1;
        assert!(validate_manifest(&manifest, &input, &changed, "commit", "runner").is_err());
        manifest.segments[0].index = 1;
        assert!(validate_manifest(&manifest, &input, &journal, "commit", "runner").is_err());
        manifest.segments.clear();
        assert!(validate_manifest(&manifest, &input, &journal, "commit", "runner").is_err());
    }
}
