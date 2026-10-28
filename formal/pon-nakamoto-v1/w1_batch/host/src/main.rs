//! A bounded local composition experiment, never a consensus admission path.
//! Every leaf and final receipt uses the hardened 3.0.6 verifier. No default
//! backend, caller-supplied image, claim-only assumption or fake proof is used.
mod staged;
use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use risc0_zkvm::{
    ExecutorEnv, ExternalProver, InnerReceipt, Prover, ProverOpts, Receipt, VerifierContext,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    hint::black_box,
    io::{Read, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use trnm_w1_batch_methods::{TRNM_W1_BATCH_GUEST_ELF, TRNM_W1_BATCH_GUEST_ID};
use trnm_w1_batch_statement::{
    build_journal, check_batch_journal, encode_input, leaf_identity, Leaf, BATCH_DOMAIN,
    BATCH_PREFIX_BYTES, FROZEN_LEAF_IMAGE_ID, HEADER_BYTES, LEAF_JOURNAL_BYTES,
    MAX_BATCH_JOURNAL_BYTES, MAX_LEAVES,
};

const MANIFEST_SCHEMA: &str = "TRNM-W1-BATCH-EXPERIMENT1";
const SDK_VERSION: &str = "3.0.6";
const R0VM_SHA256: &str = "2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6";
const MAX_MANIFEST: u64 = 128 * 1024;
const MAX_LEAF_RECEIPT: u64 = 1024 * 1024;
const MAX_ALL_LEAF_RECEIPTS: usize = 32 * 1024 * 1024;
const MAX_BATCH_RECEIPT: u64 = 4 * 1024 * 1024;
const SESSION_CYCLE_LIMIT: u64 = 1 << 24;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    leaves: Vec<LeafFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeafFile {
    header: PathBuf,
    receipt: PathBuf,
}

struct LoadedLeaf {
    header: Vec<u8>,
    receipt: Receipt,
    receipt_sha256: String,
    receipt_bytes: usize,
    identity: [u8; 32],
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "artifact byte bound: {}",
        path.display()
    );
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().context("output parent")?)?.sync_all()?;
    Ok(())
}

fn event(out: &Path, value: serde_json::Value) -> Result<()> {
    let row =
        json!({"unix_ns":SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),"event":value});
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(out.join("events.jsonl"))?;
    writeln!(file, "{row}")?;
    file.sync_all()?;
    println!("{row}");
    Ok(())
}

fn manifest(path: &Path) -> Result<(Manifest, Vec<u8>)> {
    let bytes = bounded(path, MAX_MANIFEST)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    ensure!(
        manifest.schema == MANIFEST_SCHEMA,
        "new batch experiment schema required"
    );
    ensure!(
        (1..=MAX_LEAVES).contains(&manifest.leaves.len()),
        "leaf count bound"
    );
    Ok((manifest, bytes))
}

fn decode(bytes: &[u8], limit: u64) -> Result<Receipt> {
    ensure!(bytes.len() as u64 <= limit, "receipt byte bound");
    // Reject recursive Composite allocations, Groth16 and Fake BEFORE decode.
    ensure!(
        bytes.get(..4) == Some(1u32.to_le_bytes().as_slice()),
        "succinct wire tag required"
    );
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}

fn relation<T>(value: Result<T, trnm_w1_batch_statement::Error>) -> Result<T> {
    value.map_err(|error| anyhow::anyhow!("batch public binding: {error:?}"))
}

fn headers(path: &Path, value: &Manifest) -> Result<Vec<Vec<u8>>> {
    let base = path.parent().context("manifest parent")?;
    value
        .leaves
        .iter()
        .map(|leaf| {
            let bytes = bounded(&base.join(&leaf.header), HEADER_BYTES as u64)?;
            ensure!(bytes.len() == HEADER_BYTES, "exact expected header");
            Ok(bytes)
        })
        .collect()
}

fn load_leaves(path: &Path, value: &Manifest) -> Result<Vec<LoadedLeaf>> {
    let expected = headers(path, value)?;
    let base = path.parent().context("manifest parent")?;
    let mut loaded = Vec::with_capacity(value.leaves.len());
    let mut total_bytes = 0usize;
    for (file, header) in value.leaves.iter().zip(expected) {
        let bytes = bounded(&base.join(&file.receipt), MAX_LEAF_RECEIPT)?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .context("receipt sum overflow")?;
        ensure!(
            total_bytes <= MAX_ALL_LEAF_RECEIPTS,
            "total leaf receipt bound"
        );
        let receipt = decode(&bytes, MAX_LEAF_RECEIPT)?;
        receipt.inner.succinct().context("leaf STARK kind")?;
        ensure!(
            receipt.journal.bytes.len() == LEAF_JOURNAL_BYTES,
            "complete leaf journal"
        );
        // verify(), not verify_integrity(): exact frozen image, successful
        // halt, zero input claim and EMPTY assumptions must all hold.
        receipt
            .verify(FROZEN_LEAF_IMAGE_ID)
            .context("unconditional full W1 leaf proof")?;
        let identity = relation(leaf_identity(&header, &receipt.journal.bytes))?;
        ensure!(
            !loaded
                .iter()
                .any(|leaf: &LoadedLeaf| leaf.identity == identity),
            "duplicate original work identity"
        );
        loaded.push(LoadedLeaf {
            header,
            receipt,
            receipt_sha256: sha(&bytes),
            receipt_bytes: bytes.len(),
            identity,
        });
    }
    Ok(loaded)
}

fn verify_batch(expected: &[Vec<u8>], receipt: &Receipt) -> Result<Vec<[u8; 32]>> {
    ensure!(
        receipt.journal.bytes.len() <= MAX_BATCH_JOURNAL_BYTES,
        "batch journal bound"
    );
    receipt
        .inner
        .succinct()
        .context("batch recursive STARK required")?;
    // Exact compiled image. A manifest can never replace this identity.
    // This also rejects an unresolved conditional receipt or nonzero halt.
    receipt
        .verify(TRNM_W1_BATCH_GUEST_ID)
        .context("unconditional batch proof")?;
    let headers: Vec<_> = expected.iter().map(Vec::as_slice).collect();
    relation(check_batch_journal(&headers, &receipt.journal.bytes))
}

fn source_identity() -> Result<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let status = Command::new("git")
        .current_dir(&root)
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()?;
    ensure!(
        status.status.success() && status.stdout.is_empty(),
        "source must be committed and clean"
    );
    let head = Command::new("git")
        .current_dir(&root)
        .args(["rev-parse", "HEAD"])
        .output()?;
    ensure!(head.status.success(), "source identity unavailable");
    let head = String::from_utf8(head.stdout)?.trim().to_owned();
    ensure!(
        head.len() == 40 && head.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "source identity encoding"
    );
    let check = Command::new("python3")
        .current_dir(&root)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .args([
            "scripts/ci/verify_ci_source.py",
            "--kind",
            "head",
            "--expected-head",
            &head,
        ])
        .output()?;
    ensure!(
        check.status.success(),
        "raw committed source identity failed"
    );
    Ok(head)
}

fn prepare(manifest_path: &Path, out: &Path, r0vm: Option<&Path>, staged: bool) -> Result<()> {
    // All costs in the caller's external CPU/RSS/wall observer are mandatory.
    // Starting this function is not authorization to run an unbudgeted campaign.
    let source = source_identity()?;
    fs::create_dir(out).context("new evidence directory required")?;
    event(
        out,
        json!({"stage":"START","source_commit":source,"sdk":SDK_VERSION,"prover_requested":r0vm.is_some()}),
    )?;
    let started = Instant::now();
    let result = (|| -> Result<()> {
        let (manifest, original) = manifest(manifest_path)?;
        write_new(&out.join("manifest-original.json"), &original)?;
        let loaded = load_leaves(manifest_path, &manifest)?;
        if staged {
            staged::require_pinned_leaf(&loaded)?;
        }
        let leaves: Vec<_> = loaded
            .iter()
            .map(|leaf| Leaf {
                header: &leaf.header,
                journal: &leaf.receipt.journal.bytes,
            })
            .collect();
        let input = relation(encode_input(&leaves))?;
        let journal = relation(build_journal(&leaves))?;
        write_new(&out.join("batch-input.bin"), &input)?;
        write_new(&out.join("expected-batch-journal.bin"), &journal)?;
        write_new(&out.join("batch-guest.bin"), TRNM_W1_BATCH_GUEST_ELF)?;
        let leaf_records: Vec<_> = loaded
            .iter()
            .map(|leaf| {
                json!({
                    "work_id":hex::encode(leaf.identity),"receipt_sha256":leaf.receipt_sha256,
                    "receipt_bytes":leaf.receipt_bytes,"header_sha256":sha(&leaf.header),
                    "journal_sha256":sha(&leaf.receipt.journal.bytes),
                    "original_leaf_prover_cost_included":false
                })
            })
            .collect();
        let declaration = json!({
            "schema":"TRNM-W1-BATCH-DECLARATION1","source_commit":source,
            "sdk":SDK_VERSION,"leaf_image_id":FROZEN_LEAF_IMAGE_ID,
            "batch_image_id":TRNM_W1_BATCH_GUEST_ID,"guest_sha256":sha(TRNM_W1_BATCH_GUEST_ELF),
            "host_sha256":sha(&bounded(&std::env::current_exe()?,256*1024*1024)?),
            "input_sha256":sha(&input),"journal_sha256":sha(&journal),
            "unique_work_count":loaded.len(),"leaves":leaf_records,
            "staged_conditional_resolve_calibration":staged,
            "leaf_verify_and_prepare_wall_ns":started.elapsed().as_nanos(),
            "session_cycle_limit":SESSION_CYCLE_LIMIT,"segment_limit_po2":18,
            "parent_task_window_m06_authorization_proven":false,
            "original_leaf_prover_costs":"MUST_JOIN_EXISTING_LEDGER_SEPARATELY",
            "benefit_gate":"NOT_EVALUATED","production_activation":false
        });
        write_new(
            &out.join("declaration.json"),
            &serde_json::to_vec_pretty(&declaration)?,
        )?;
        event(
            out,
            json!({"stage":"REAL_LEAVES_VERIFIED","unique_work_count":loaded.len()}),
        )?;
        let Some(r0vm) = r0vm else {
            return Ok(());
        };
        ensure!(r0vm.is_absolute(), "explicit absolute local r0vm required");
        ensure!(
            sha(&bounded(r0vm, 256 * 1024 * 1024)?) == R0VM_SHA256,
            "pinned local r0vm digest"
        );
        let mut builder = ExecutorEnv::builder();
        builder
            .segment_limit_po2(18)
            .session_limit(Some(SESSION_CYCLE_LIMIT))
            .write_slice(&input);
        if staged {
            let segments = out.join("session-segments");
            fs::create_dir(&segments)?;
            builder.segment_path(segments);
        }
        for leaf in &loaded {
            // Only actual already-verified Receipt values enter this API.
            // Never pass ReceiptClaim or an assumed claim digest here.
            builder.add_assumption(leaf.receipt.clone());
        }
        let env = builder.build()?;
        let prover = ExternalProver::new("pinned-local-r0vm-3.0.3-batch-research", r0vm);
        let proving = Instant::now();
        event(
            out,
            json!({"stage":"PROVER_STARTED","r0vm_sha256":R0VM_SHA256,"unique_work_count":loaded.len()}),
        )?;
        let opts = if staged {
            ProverOpts::composite()
        } else {
            ProverOpts::succinct()
        };
        let info = prover.prove_with_ctx(
            env,
            &VerifierContext::default(),
            TRNM_W1_BATCH_GUEST_ELF,
            &opts,
        )?;
        event(
            out,
            json!({"stage":"EXTERNAL_PROVER_RETURNED","stats":info.stats,
            "call_wall_ns":proving.elapsed().as_nanos(),"staged":staged}),
        )?;
        let receipt = if staged {
            staged::resolve_one(r0vm, &loaded[0], info.receipt, &journal, out)?
        } else {
            info.receipt
        };
        let proof_workflow_wall_ns = proving.elapsed().as_nanos();
        let bytes = bincode::serialize(&receipt)?;
        write_new(&out.join("succinct.bin"), &bytes)?;
        let saved = decode(
            &bounded(&out.join("succinct.bin"), MAX_BATCH_RECEIPT)?,
            MAX_BATCH_RECEIPT,
        )?;
        ensure!(
            saved.journal.bytes == journal,
            "complete ordered journal mismatch"
        );
        let expected: Vec<_> = loaded.iter().map(|leaf| leaf.header.clone()).collect();
        let identities = verify_batch(&expected, &saved)?;
        event(
            out,
            json!({
                "stage":"UNCONDITIONAL_BATCH_VERIFIED","unique_work_count":identities.len(),
                "proof_workflow_wall_ns":proof_workflow_wall_ns,"total_function_wall_ns":started.elapsed().as_nanos(),
                "receipt_bytes":bytes.len(),"receipt_sha256":sha(&bytes),
                "independent_batch_proof_trials":1,"sample_is_one_leaf_calibration":identities.len()==1,
                "prover_tail_established":false,"benefit_gate":"NOT_EVALUATED",
                "leaf_prover_costs_included":false,"production_activation":false
            }),
        )?;
        Ok(())
    })();
    if let Err(error) = &result {
        event(
            out,
            json!({"stage":"FAILED","error":format!("{error:#}"),"elapsed_ns":started.elapsed().as_nanos(),"production_activation":false}),
        )?;
    }
    result
}

fn verify_command(path: &Path, receipt_path: &Path, repeat: bool) -> Result<()> {
    let (manifest, _) = manifest(path)?;
    let expected = headers(path, &manifest)?;
    // No individual leaf receipts are read or reverified on this path.
    let bytes = bounded(receipt_path, MAX_BATCH_RECEIPT)?;
    let receipt = decode(&bytes, MAX_BATCH_RECEIPT)?;
    let identities = verify_batch(&expected, &receipt)?;
    let mut decode_verify_ns = Vec::new();
    if repeat {
        for _ in 0..100 {
            let start = Instant::now();
            let receipt = decode(black_box(&bytes), MAX_BATCH_RECEIPT)?;
            black_box(verify_batch(black_box(&expected), &receipt)?);
            decode_verify_ns.push(start.elapsed().as_nanos());
        }
    }
    println!(
        "{}",
        json!({
            "schema":"TRNM-W1-BATCH-VERIFY1","sdk":SDK_VERSION,
            "batch_image_id":TRNM_W1_BATCH_GUEST_ID,"unique_work_count":identities.len(),
            "work_ids":identities.iter().map(hex::encode).collect::<Vec<_>>(),
            "receipt_bytes":bytes.len(),"decode_verify_ns":decode_verify_ns,
            "independent_batch_proof_trials":1,"production_tail_established":false,
            "original_leaf_prover_costs_included":false,"benefit_gate":"NOT_EVALUATED",
            "parent_task_window_m06_authorization_proven":false,"production_activation":false
        })
    );
    Ok(())
}

fn controls(path: &Path, receipt_path: &Path, out: &Path) -> Result<()> {
    let (manifest, _) = manifest(path)?;
    let expected = headers(path, &manifest)?;
    let bytes = bounded(receipt_path, MAX_BATCH_RECEIPT)?;
    let receipt = decode(&bytes, MAX_BATCH_RECEIPT)?;
    verify_batch(&expected, &receipt)?;
    fs::create_dir(out).context("new control directory required")?;
    let mut cases = vec![("valid".to_owned(), expected.clone(), bytes.clone(), true)];
    let mut extra = bytes.clone();
    extra.push(0);
    cases.push(("trailing".into(), expected.clone(), extra, false));
    cases.push((
        "truncated".into(),
        expected.clone(),
        bytes[..bytes.len() - 1].to_vec(),
        false,
    ));
    for (name, tag) in [("composite", 0u32), ("groth16", 2), ("fake", 3)] {
        let mut bad = bytes.clone();
        bad[..4].copy_from_slice(&tag.to_le_bytes());
        cases.push((name.into(), expected.clone(), bad, false));
    }
    let mut wrong_header = expected.clone();
    wrong_header[0][310] ^= 1;
    cases.push((
        "wrong_expected_header".into(),
        wrong_header,
        bytes.clone(),
        false,
    ));
    if expected.len() > 1 {
        let mut reordered = expected.clone();
        reordered.swap(0, 1);
        cases.push((
            "reordered_expected_headers".into(),
            reordered,
            bytes.clone(),
            false,
        ));
    }
    for (name, offset) in [
        ("batch_domain", 0),
        ("leaf_image", BATCH_DOMAIN.len()),
        ("count", BATCH_PREFIX_BYTES - 4),
        ("complete_leaf_journal", BATCH_PREFIX_BYTES),
        ("product_tail", receipt.journal.bytes.len() - 1),
    ] {
        let mut bad = receipt.clone();
        bad.journal.bytes[offset] ^= 1;
        cases.push((
            name.into(),
            expected.clone(),
            bincode::serialize(&bad)?,
            false,
        ));
    }
    let mut wrong_claim = receipt.clone();
    if let InnerReceipt::Succinct(inner) = &mut wrong_claim.inner {
        ensure!(!inner.seal.is_empty(), "nonempty control seal");
        inner.seal[0] ^= 1;
    } else {
        bail!("succinct control required");
    }
    cases.push((
        "seal".into(),
        expected.clone(),
        bincode::serialize(&wrong_claim)?,
        false,
    ));
    let mut all_passed = true;
    for (name, headers, bytes, should_accept) in cases {
        write_new(&out.join(format!("{name}.bin")), &bytes)?;
        let (outcome, error) = match catch_unwind(AssertUnwindSafe(|| -> Result<()> {
            let receipt = decode(&bytes, MAX_BATCH_RECEIPT)?;
            verify_batch(&headers, &receipt)?;
            Ok(())
        })) {
            Ok(Ok(())) => ("ACCEPT", None),
            Ok(Err(error)) => ("REJECT", Some(format!("{error:#}"))),
            Err(_) => ("PANIC", None),
        };
        let pass =
            (outcome == "ACCEPT" && should_accept) || (outcome == "REJECT" && !should_accept);
        all_passed &= pass;
        event(
            out,
            json!({"control":name,"expected_accept":should_accept,"outcome":outcome,"error":error,"pass":pass}),
        )?;
    }
    ensure!(all_passed, "batch control failure or panic");
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
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["prepare",manifest,out] => prepare(Path::new(manifest),Path::new(out),None,false),
        ["prove","--r0vm",r0vm,manifest,out] => prepare(Path::new(manifest),Path::new(out),Some(Path::new(r0vm)),false),
        ["prove-staged","--r0vm",r0vm,manifest,out] => prepare(Path::new(manifest),Path::new(out),Some(Path::new(r0vm)),true),
        ["verify",manifest,receipt] => verify_command(Path::new(manifest),Path::new(receipt),false),
        ["verify-many",manifest,receipt] => verify_command(Path::new(manifest),Path::new(receipt),true),
        ["controls",manifest,receipt,out] => controls(Path::new(manifest),Path::new(receipt),Path::new(out)),
        _ => bail!("usage: prepare MANIFEST NEW_OUT | prove[-staged] --r0vm PINNED_LOCAL_BINARY MANIFEST NEW_OUT | verify[-many] MANIFEST RECEIPT | controls MANIFEST RECEIPT NEW_OUT"),
    }
}
