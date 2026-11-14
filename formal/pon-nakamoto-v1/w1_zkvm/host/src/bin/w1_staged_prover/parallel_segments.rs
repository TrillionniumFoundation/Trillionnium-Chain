//! Real independent segment proving, followed by ordered prefix verification.
//! A candidate seal is never a prefix, a full proof, or a funding capability.
use super::*;

const BATCH_SCHEMA: &str = "TRNM-W1-PARALLEL-SEGMENT-BATCH1";
const JOINED_SCHEMA: &str = "TRNM-W1-PARALLEL-SEGMENT-JOINED1";
const MAX_PLAN_BYTES: u64 = 64 * 1024;
const MAX_JOINED_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BatchPlan {
    schema: String,
    source_commit: String,
    runner_sha256: String,
    manifest_sha256: String,
    start: usize,
    end: usize,
    workers: usize,
    rayon_threads: usize,
}

impl BatchPlan {
    fn resources(&self) -> Result<schedule::Resources> {
        schedule::Resources::new(self.workers, self.rayon_threads)
    }

    fn validate(
        &self,
        file_start: usize,
        total: usize,
        manifest_sha256: &str,
        commit: &str,
        runner: &str,
    ) -> Result<()> {
        ensure!(self.schema == BATCH_SCHEMA, "parallel batch schema changed");
        ensure!(
            self.source_commit == commit
                && self.runner_sha256 == runner
                && self.manifest_sha256 == manifest_sha256,
            "parallel batch source, runner, or original manifest changed"
        );
        ensure!(
            (1..=MAX_SEGMENTS).contains(&total)
                && self.start == file_start
                && self.start < self.end
                && self.end <= total,
            "parallel batch range is invalid"
        );
        self.resources()?;
        Ok(())
    }

    fn candidate_path(&self, out: &Path, index: usize) -> Result<PathBuf> {
        ensure!(
            self.start <= index && index < self.end,
            "candidate index is outside its batch"
        );
        Ok(out.join(format!(
            "{}-batch-{:04}-{:04}-candidate-{index:04}.bin",
            self.resources()?.segment_candidate_namespace(),
            self.start,
            self.end,
        )))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    index: usize,
    bytes: u64,
    sha256: String,
    claim_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JoinedBatch {
    schema: String,
    plan_sha256: String,
    candidates: Vec<Candidate>,
    all_started_rust_workers_joined: bool,
    native_child_reaping_verified: bool,
}

impl JoinedBatch {
    fn validate(&self, plan: &BatchPlan, plan_bytes: &[u8]) -> Result<()> {
        let expected_candidates = plan
            .end
            .checked_sub(plan.start)
            .filter(|count| (1..=MAX_SEGMENTS).contains(count))
            .context("parallel completion range is invalid")?;
        ensure!(
            self.schema == JOINED_SCHEMA && self.plan_sha256 == sha(plan_bytes),
            "parallel batch completion does not bind its original plan"
        );
        ensure!(
            self.all_started_rust_workers_joined && !self.native_child_reaping_verified,
            "parallel batch completion has an unexpected worker-observation scope"
        );
        ensure!(
            self.candidates.len() == expected_candidates,
            "parallel batch completion omits or adds candidates"
        );
        for (offset, candidate) in self.candidates.iter().enumerate() {
            ensure!(
                candidate.index == plan.start + offset
                    && (1..=MAX_RECEIPT).contains(&candidate.bytes)
                    && candidate.sha256.len() == 64
                    && candidate
                        .sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                    && candidate.claim_digest.len() == 64
                    && candidate
                        .claim_digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit()),
                "parallel candidate identity, size, or order is invalid"
            );
        }
        Ok(())
    }
}

fn plan_path(out: &Path, start: usize) -> PathBuf {
    out.join(format!("parallel-segments-v1-batch-{start:04}.json"))
}

fn joined_path(out: &Path, start: usize) -> PathBuf {
    out.join(format!("parallel-segments-v1-batch-{start:04}-joined.json"))
}

fn load_joined(out: &Path, plan: &BatchPlan, plan_bytes: &[u8]) -> Result<JoinedBatch> {
    let path = joined_path(out, plan.start);
    ensure!(
        path.exists(),
        "parallel batch {}..{} is failed or pending: preserve its candidates; no promotion or automatic redispatch",
        plan.start, plan.end
    );
    let joined: JoinedBatch = serde_json::from_slice(&bounded(&path, MAX_JOINED_BYTES)?)?;
    joined.validate(plan, plan_bytes)?;
    Ok(joined)
}

fn read_candidate(
    out: &Path,
    plan: &BatchPlan,
    candidate: &Candidate,
) -> Result<(Vec<u8>, SegmentReceipt)> {
    let bytes = bounded(&plan.candidate_path(out, candidate.index)?, MAX_RECEIPT)?;
    ensure!(
        bytes.len() as u64 == candidate.bytes && sha(&bytes) == candidate.sha256,
        "candidate bytes changed after batch completion"
    );
    let receipt = decode_segment(&bytes)
        .context("parallel candidate is not a complete bounded segment receipt")?;
    ensure!(
        receipt.claim.digest().to_string() == candidate.claim_digest,
        "candidate full claim changed after batch completion"
    );
    // The caller must still verify the actual seal and its ordered state link.
    Ok((bytes, receipt))
}

fn verify_prior_prefix(
    out: &Path,
    end: usize,
    total: usize,
    journal: &[u8],
    ctx: &VerifierContext,
) -> Result<Digest> {
    let mut expected_pre = Digest::from(TRNM_W1_FULL_GUEST_ID);
    for index in 0..end {
        let receipt = decode_segment(&bounded(
            &out.join(format!("receipt-{index:04}.bin")),
            MAX_RECEIPT,
        )?)?;
        expected_pre = validate_segment(&receipt, index, total, expected_pre, journal, ctx)?;
    }
    Ok(expected_pre)
}

fn verified_prefix(out: &Path, total: usize, journal: &[u8]) -> Result<usize> {
    let ctx = VerifierContext::default();
    let mut expected_pre = Digest::from(TRNM_W1_FULL_GUEST_ID);
    let mut prefix = 0;
    let mut missing = false;
    for index in 0..total {
        let path = out.join(format!("receipt-{index:04}.bin"));
        if !path.exists() {
            missing = true;
            continue;
        }
        ensure!(
            !missing,
            "canonical receipts contain a gap; preserve the observation"
        );
        let receipt = decode_segment(&bounded(&path, MAX_RECEIPT)?)?;
        expected_pre = validate_segment(&receipt, index, total, expected_pre, journal, &ctx)?;
        prefix += 1;
    }
    Ok(prefix)
}

fn verify_candidate_chain(
    out: &Path,
    plan: &BatchPlan,
    joined: &JoinedBatch,
    total: usize,
    journal: &[u8],
) -> Result<()> {
    let ctx = VerifierContext::default();
    let mut expected_pre = verify_prior_prefix(out, plan.start, total, journal, &ctx)?;
    for candidate in &joined.candidates {
        let (_, receipt) = read_candidate(out, plan, candidate)?;
        expected_pre = validate_segment(
            &receipt,
            candidate.index,
            total,
            expected_pre,
            journal,
            &ctx,
        )?;
    }
    Ok(())
}

fn publish_canonical_prefix(
    out: &Path,
    plan: &BatchPlan,
    joined: &JoinedBatch,
    total: usize,
    journal: &[u8],
    cold_reconciliation: bool,
) -> Result<()> {
    // Check the entire original prefix and candidate batch before publishing
    // even its first canonical receipt. A joined JSON row is not a proof.
    verify_candidate_chain(out, plan, joined, total, journal)?;
    let ctx = VerifierContext::default();
    let mut expected_pre = verify_prior_prefix(out, plan.start, total, journal, &ctx)?;
    for candidate in &joined.candidates {
        let (bytes, receipt) = read_candidate(out, plan, candidate)?;
        expected_pre = validate_segment(
            &receipt,
            candidate.index,
            total,
            expected_pre,
            journal,
            &ctx,
        )?;
        let path = out.join(format!("receipt-{:04}.bin", candidate.index));
        if path.exists() {
            ensure!(
                bounded(&path, MAX_RECEIPT)? == bytes,
                "canonical receipt conflicts with its retained candidate"
            );
        } else {
            write_new(&path, &bytes)?;
            ensure!(
                bounded(&path, MAX_RECEIPT)? == bytes,
                "canonical receipt readback changed"
            );
        }
    }
    event(
        out,
        json!({
            "stage":"PARALLEL_BATCH_CANONICAL_PREFIX_PUBLISHED",
            "schema":BATCH_SCHEMA,"start":plan.start,"end":plan.end,
            "original_image_to_end_reverified":true,
            "cold_reconciliation":cold_reconciliation,
            "prior_costs_must_be_included":cold_reconciliation,
            "full_proof_complete":false,"consensus_admission":false
        }),
    )
}

fn reconcile_batches(
    out: &Path,
    total: usize,
    journal: &[u8],
    manifest_sha256: &str,
    commit: &str,
    runner: &str,
) -> Result<()> {
    let mut previous_end = 0;
    for start in 0..total {
        let path = plan_path(out, start);
        if !path.exists() {
            ensure!(
                !joined_path(out, start).exists(),
                "orphan parallel batch completion"
            );
            continue;
        }
        let plan_bytes = bounded(&path, MAX_PLAN_BYTES)?;
        let plan: BatchPlan = serde_json::from_slice(&plan_bytes)?;
        plan.validate(start, total, manifest_sha256, commit, runner)?;
        ensure!(start >= previous_end, "parallel batch ranges overlap");
        previous_end = plan.end;
        let joined = load_joined(out, &plan, &plan_bytes)?;
        publish_canonical_prefix(out, &plan, &joined, total, journal, true)?;
    }
    Ok(())
}

pub(super) fn prove_parallel(
    r0vm: &Path,
    out: &Path,
    max_new: usize,
    resources: schedule::Resources,
    commit: &str,
    runner: &str,
) -> Result<()> {
    ensure!(max_new <= MAX_SEGMENTS, "new parallel proof budget bound");
    // Hash exactly the bytes parsed and checked here, not a reserialization or
    // a second read of a possibly changed manifest.
    let manifest_bytes = bounded(&out.join("manifest.json"), 1024 * 1024)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    let input = bounded(&out.join("input.bin"), INPUT_BYTES as u64)?;
    let journal = bounded(&out.join("expected-journal.bin"), 64 * 1024)?;
    validate_manifest(&manifest, &input, &journal, commit, runner)?;
    let manifest_sha256 = sha(&manifest_bytes);
    let total = manifest.segments.len();
    // Reject malformed or noncontiguous canonical observations before deciding
    // whether there is a recoverable publication or any permission to dispatch.
    verified_prefix(out, total, &journal)?;
    reconcile_batches(out, total, &journal, &manifest_sha256, commit, runner)?;
    let prefix = verified_prefix(out, total, &journal)?;
    if prefix == total {
        return event(
            out,
            json!({
                "stage":"ALL_SEGMENT_STARKS_VERIFIED","segments":total,"new_segments":0,
                "prior_costs_must_be_included":true,"succinct_proof_complete":false
            }),
        );
    }
    if max_new == 0 {
        return event(
            out,
            json!({
                "stage":"SEGMENT_BUDGET_EXHAUSTED","verified_prefix":prefix,
                "total_segments":total,"cryptographic_proof_complete":false
            }),
        );
    }
    let end = total.min(prefix + max_new);
    let plan = BatchPlan {
        schema: BATCH_SCHEMA.into(),
        source_commit: commit.into(),
        runner_sha256: runner.into(),
        manifest_sha256,
        start: prefix,
        end,
        workers: resources.workers,
        rayon_threads: resources.rayon_threads,
    };
    plan.validate(prefix, total, &plan.manifest_sha256, commit, runner)?;
    let plan_bytes = serde_json::to_vec_pretty(&plan)?;
    write_new(&plan_path(out, prefix), &plan_bytes)?;
    ensure!(
        bounded(&plan_path(out, prefix), MAX_PLAN_BYTES)? == plan_bytes,
        "parallel plan readback changed"
    );
    event(
        out,
        json!({
            "stage":"PARALLEL_SEGMENT_BATCH_STARTED","schema":BATCH_SCHEMA,
            "start":prefix,"end":end,"max_new":max_new,
            "plan_sha256":sha(&plan_bytes),"workers":resources.workers,
            "rayon_threads_per_worker":resources.rayon_threads,
            "candidates_are_not_prefixes":true,"full_proof_complete":false
        }),
    )?;
    let opts = ProverOpts::succinct();
    let candidates = parallel_backend(
        r0vm,
        out,
        "segment",
        end - prefix,
        resources,
        |client, ordinal| {
            let index = prefix + ordinal;
            let row = &manifest.segments[index];
            let path = plan.candidate_path(out, index)?;
            ensure!(
                !path.exists(),
                "refusing to replace an earlier candidate observation"
            );
            let asset = bounded(&out.join(format!("segment-{index:04}.bin")), MAX_ASSET)?;
            ensure!(
                asset.len() == row.bytes && sha(&asset) == row.sha256,
                "frozen segment asset changed"
            );
            event(
                out,
                json!({
                    "stage":"REAL_SEGMENT_PROVING_STARTED","index":index,"po2":row.po2,
                    "batch_start":prefix,"batch_end":end,
                    "rayon_threads":resources.rayon_threads,
                    "candidate_linkage_verified":false
                }),
            )?;
            let started = Instant::now();
            let receipt = client
                .prove_segment(&opts, Asset::Inline(asset.into()), AssetRequest::Inline)
                .with_context(|| format!("parallel candidate {index}"))?;
            let prover_ns = started.elapsed().as_nanos();
            let verify_started = Instant::now();
            verify_unlinked_segment(
                &receipt,
                index,
                total,
                &journal,
                &VerifierContext::default(),
            )?;
            let verifier_ns = verify_started.elapsed().as_nanos();
            let bytes = bincode::serialize(&receipt)?;
            ensure!(bytes.len() as u64 <= MAX_RECEIPT, "candidate receipt bound");
            let candidate = Candidate {
                index,
                bytes: bytes.len() as u64,
                sha256: sha(&bytes),
                claim_digest: receipt.claim.digest().to_string(),
            };
            write_new(&path, &bytes)?;
            ensure!(
                bounded(&path, MAX_RECEIPT)? == bytes,
                "candidate receipt readback changed"
            );
            event(
                out,
                json!({
                    "stage":"REAL_SEGMENT_CANDIDATE_SAVED_VERIFIED_UNLINKED",
                    "index":index,"batch_start":prefix,"batch_end":end,
                    "prover_ns":prover_ns,"verifier_ns":verifier_ns,
                    "prover_ns_scope":"SDK proving call including per-call subprocess startup; excludes client constructor, verification and publication",
                    "receipt_bytes":candidate.bytes,"receipt_sha256":candidate.sha256,
                    "candidate_linkage_verified":false,"eligible_as_canonical":false,
                    "cryptographic_proof_complete":false
                }),
            )?;
            Ok(candidate)
        },
    )?;
    // The success marker is unreachable on any worker error, panic, failed
    // spawn, log failure, or omitted item. Failed candidates remain unpromoted.
    let joined = JoinedBatch {
        schema: JOINED_SCHEMA.into(),
        plan_sha256: sha(&plan_bytes),
        candidates,
        all_started_rust_workers_joined: true,
        native_child_reaping_verified: false,
    };
    joined.validate(&plan, &plan_bytes)?;
    verify_candidate_chain(out, &plan, &joined, total, &journal)?;
    let joined_bytes = serde_json::to_vec_pretty(&joined)?;
    ensure!(
        joined_bytes.len() as u64 <= MAX_JOINED_BYTES,
        "batch completion byte bound"
    );
    write_new(&joined_path(out, prefix), &joined_bytes)?;
    ensure!(
        bounded(&joined_path(out, prefix), MAX_JOINED_BYTES)? == joined_bytes,
        "batch completion readback changed"
    );
    publish_canonical_prefix(out, &plan, &joined, total, &journal, false)?;
    let published_prefix = verified_prefix(out, total, &journal)?;
    ensure!(
        published_prefix == end,
        "parallel publication did not produce its exact prefix"
    );
    if end == total {
        event(
            out,
            json!({
                "stage":"ALL_SEGMENT_STARKS_VERIFIED","segments":total,
                "new_segments":end-prefix,"succinct_proof_complete":false
            }),
        )
    } else {
        event(
            out,
            json!({
                "stage":"SEGMENT_BUDGET_EXHAUSTED","verified_prefix":end,
                "total_segments":total,"new_segments":end-prefix,
                "cryptographic_proof_complete":false
            }),
        )
    }
}

#[cfg(test)]
#[path = "parallel_segments_tests.rs"]
mod tests;
