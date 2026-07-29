//! Executable AppHash v4 scale gate.
//!
//! This module is feature-gated so production nodes do not carry benchmark
//! code. The gate measures exact JMT plan-and-apply batches, then compares an
//! early update window with a late update window. Initial population latency is
//! deliberately excluded from the growth threshold.

use std::time::Instant;

use anyhow::{ensure, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::auth_tree::{
    stored_object_key, verify_ics23_membership, AuthWrite, InMemoryAuthTree, PruneStats,
};

const REPORT_SCHEMA_V1: &str = "trnm_apphash_v4_scale_report_v1";
const MILLION: u64 = 1_000_000;

#[derive(Clone, Debug)]
pub struct AuthTreeScaleConfig {
    pub objects: u64,
    pub updates: u64,
    pub batch_size: u64,
    pub live_set: u64,
    pub window_batches: u64,
    pub max_late_p95_ratio: f64,
    pub latency_slack_us: u64,
    pub prune_retain_versions: u64,
}

impl Default for AuthTreeScaleConfig {
    fn default() -> Self {
        Self {
            objects: MILLION,
            updates: MILLION,
            batch_size: 10_000,
            live_set: 10_000,
            window_batches: 10,
            max_late_p95_ratio: 3.0,
            latency_slack_us: 5_000,
            prune_retain_versions: 64,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ScaleWorkload {
    pub objects: u64,
    pub updates: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ScaleCompleted {
    pub objects: u64,
    pub updates: u64,
    pub initial_load_batches: u64,
    pub update_batches: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScaleParameters {
    pub batch_size: u64,
    pub fixed_live_set: u64,
    pub update_window_batches: u64,
    pub max_late_update_p95_ratio: f64,
    pub late_update_p95_slack_us: u64,
    pub prune_retain_versions: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalePhase {
    InitialLoad,
    Update,
}

#[derive(Clone, Debug, Serialize)]
pub struct TreeCounts {
    pub version: u64,
    pub root_hash_hex: String,
    pub roots: u64,
    pub nodes: u64,
    pub stale_nodes: u64,
    pub value_versions: u64,
    pub key_preimages: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct BatchCommitMetric {
    pub phase: ScalePhase,
    pub batch_index: u64,
    pub version: u64,
    pub operations: u64,
    pub phase_operations_completed: u64,
    pub commit_us: u64,
    pub root_hash_hex: String,
    pub node_count: u64,
    pub stale_count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct LatencyStats {
    pub samples: u64,
    pub min_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub max_us: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateLatencyGate {
    pub baseline_phase: &'static str,
    pub comparison_phase: &'static str,
    pub initial_load_batches_excluded: bool,
    pub early_update_batch_start: u64,
    pub early_update_batch_end: u64,
    pub late_update_batch_start: u64,
    pub late_update_batch_end: u64,
    pub early: LatencyStats,
    pub late: LatencyStats,
    pub max_late_p95_ratio: f64,
    pub latency_slack_us: u64,
    pub allowed_late_p95_us: u64,
    pub passed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PruneRemovalCounts {
    pub nodes: u64,
    pub value_versions: u64,
    pub key_preimages: u64,
    pub stale_indices: u64,
    pub roots: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PruneProofReport {
    pub boundary_version: u64,
    pub latest_version: u64,
    pub proof_key_hex: String,
    pub boundary_root_hash_hex: String,
    pub latest_root_hash_hex: String,
    pub boundary_value_sha256_hex: String,
    pub latest_value_sha256_hex: String,
    pub boundary_commitment_proof_hex: String,
    pub latest_commitment_proof_hex: String,
    pub boundary_membership_verified_after_prune: bool,
    pub latest_membership_verified_after_prune: bool,
    pub version_before_boundary_rejected: Option<bool>,
    pub latest_root_unchanged: bool,
    pub removed: PruneRemovalCounts,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthTreeScaleReport {
    pub schema: &'static str,
    pub workload_class: &'static str,
    pub measurement_profile: &'static str,
    pub million_gate_eligible: bool,
    pub requested: ScaleWorkload,
    pub completed: ScaleCompleted,
    pub completed_exactly: bool,
    pub parameters: ScaleParameters,
    pub batch_commits: Vec<BatchCommitMetric>,
    pub update_latency_gate: Option<UpdateLatencyGate>,
    pub before_prune: Option<TreeCounts>,
    pub after_prune: Option<TreeCounts>,
    pub prune_proof: Option<PruneProofReport>,
    pub elapsed_us: u64,
    pub passed: bool,
    pub failure_reason: Option<String>,
}

impl AuthTreeScaleReport {
    fn new(config: &AuthTreeScaleConfig) -> Self {
        let at_least_million = config.objects >= MILLION && config.updates >= MILLION;
        Self {
            schema: REPORT_SCHEMA_V1,
            workload_class: if at_least_million {
                "at_least_1m_objects_and_1m_updates"
            } else {
                "smoke_or_custom_below_1m_not_a_million_gate"
            },
            measurement_profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            million_gate_eligible: at_least_million && !cfg!(debug_assertions),
            requested: ScaleWorkload {
                objects: config.objects,
                updates: config.updates,
            },
            completed: ScaleCompleted::default(),
            completed_exactly: false,
            parameters: ScaleParameters {
                batch_size: config.batch_size,
                fixed_live_set: config.live_set,
                update_window_batches: config.window_batches,
                max_late_update_p95_ratio: config.max_late_p95_ratio,
                late_update_p95_slack_us: config.latency_slack_us,
                prune_retain_versions: config.prune_retain_versions,
            },
            batch_commits: Vec::new(),
            update_latency_gate: None,
            before_prune: None,
            after_prune: None,
            prune_proof: None,
            elapsed_us: 0,
            passed: false,
            failure_reason: None,
        }
    }
}

/// Runs the deterministic AppHash v4 scale workload and always returns a
/// machine-readable report. A failed or incomplete report must be treated as a
/// failed gate by the caller.
pub fn run_auth_tree_scale_gate(config: AuthTreeScaleConfig) -> AuthTreeScaleReport {
    let started = Instant::now();
    let mut report = AuthTreeScaleReport::new(&config);
    if let Err(error) = execute_scale_gate(&config, &mut report) {
        report.failure_reason = Some(format!("{error:#}"));
    }
    report.completed_exactly = report.completed.objects == report.requested.objects
        && report.completed.updates == report.requested.updates;
    if report.failure_reason.is_none() && !report.completed_exactly {
        report.failure_reason = Some("requested workload was not completed exactly".to_string());
    }
    if report.failure_reason.is_none()
        && !report
            .update_latency_gate
            .as_ref()
            .is_some_and(|gate| gate.passed)
    {
        report.failure_reason =
            Some("late update P95 exceeded the update-stage threshold".to_string());
    }
    if report.failure_reason.is_none()
        && report.prune_proof.as_ref().is_none_or(|proof| {
            !proof.boundary_membership_verified_after_prune
                || !proof.latest_membership_verified_after_prune
                || !proof.latest_root_unchanged
                || proof.version_before_boundary_rejected == Some(false)
        })
    {
        report.failure_reason = Some("pruning/proof verification did not close".to_string());
    }
    report.elapsed_us = elapsed_us(started);
    report.passed = report.failure_reason.is_none() && report.completed_exactly;
    report
}

fn execute_scale_gate(
    config: &AuthTreeScaleConfig,
    report: &mut AuthTreeScaleReport,
) -> Result<()> {
    validate_config(config)?;
    let mut tree = InMemoryAuthTree::default();

    while report.completed.objects < config.objects {
        let count = config
            .batch_size
            .min(config.objects - report.completed.objects);
        let start_index = report.completed.objects;
        let mut writes = Vec::with_capacity(usize::try_from(count)?);
        for offset in 0..count {
            let object_index = start_index + offset;
            writes.push(AuthWrite::put(
                scale_object_key(object_index)?,
                scale_value(object_index, 0),
            )?);
        }
        let completed = report.completed.objects + count;
        apply_batch(
            &mut tree,
            ScalePhase::InitialLoad,
            report.completed.initial_load_batches,
            count,
            completed,
            writes,
            &mut report.batch_commits,
        )?;
        maybe_prune_scale_history(&mut tree, config.prune_retain_versions)?;
        report.completed.objects = completed;
        report.completed.initial_load_batches += 1;
    }

    let mut update_commit_us = Vec::new();
    while report.completed.updates < config.updates {
        let count = config
            .batch_size
            .min(config.updates - report.completed.updates);
        let start_sequence = report.completed.updates;
        let mut writes = Vec::with_capacity(usize::try_from(count)?);
        for offset in 0..count {
            let sequence = start_sequence + offset;
            let object_index = sequence % config.live_set;
            writes.push(AuthWrite::put(
                scale_object_key(object_index)?,
                scale_value(object_index, sequence.saturating_add(1)),
            )?);
        }
        let completed = report.completed.updates + count;
        let commit_us = apply_batch(
            &mut tree,
            ScalePhase::Update,
            report.completed.update_batches,
            count,
            completed,
            writes,
            &mut report.batch_commits,
        )?;
        maybe_prune_scale_history(&mut tree, config.prune_retain_versions)?;
        update_commit_us.push(commit_us);
        report.completed.updates = completed;
        report.completed.update_batches += 1;
    }

    report.update_latency_gate = Some(update_latency_gate(config, &update_commit_us)?);
    report.before_prune = Some(tree_counts(&tree)?);
    let prune = prune_and_prove(config, &mut tree)?;
    report.after_prune = Some(tree_counts(&tree)?);
    report.prune_proof = Some(prune);
    Ok(())
}

/// Bounds the executable gate's resident history using the same version
/// boundary that the final proof verifies. Pruning is periodic so the live
/// tree stays bounded without turning every measured commit into a retention
/// sweep.
fn maybe_prune_scale_history(tree: &mut InMemoryAuthTree, retain_versions: u64) -> Result<()> {
    let Some(latest) = tree.latest_version() else {
        return Ok(());
    };
    if latest.saturating_add(1) <= retain_versions
        || !latest.saturating_add(1).is_multiple_of(retain_versions)
    {
        return Ok(());
    }
    let retain_from = latest.saturating_sub(retain_versions.saturating_sub(1));
    tree.prune_versions_before(retain_from)?;
    Ok(())
}

fn validate_config(config: &AuthTreeScaleConfig) -> Result<()> {
    ensure!(config.objects > 0, "objects must be positive");
    ensure!(config.updates > 0, "updates must be positive");
    ensure!(config.batch_size > 0, "batch_size must be positive");
    ensure!(config.live_set > 0, "live_set must be positive");
    ensure!(
        config.live_set <= config.objects,
        "live_set must not exceed initial objects"
    );
    ensure!(
        config.batch_size <= config.live_set,
        "batch_size must not exceed live_set because a JMT version cannot update one key twice"
    );
    ensure!(config.window_batches > 0, "window_batches must be positive");
    ensure!(
        config.max_late_p95_ratio.is_finite() && config.max_late_p95_ratio > 0.0,
        "max_late_p95_ratio must be finite and positive"
    );
    ensure!(
        config.prune_retain_versions > 0,
        "prune_retain_versions must be positive"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_batch(
    tree: &mut InMemoryAuthTree,
    phase: ScalePhase,
    batch_index: u64,
    operations: u64,
    phase_operations_completed: u64,
    writes: Vec<AuthWrite>,
    metrics: &mut Vec<BatchCommitMetric>,
) -> Result<u64> {
    let version = tree.expected_next_version();
    let started = Instant::now();
    let plan = tree
        .plan_put_value_set(version, writes)
        .with_context(|| format!("plan {phase:?} batch {batch_index} at version {version}"))?;
    let root = tree
        .apply(plan)
        .with_context(|| format!("apply {phase:?} batch {batch_index} at version {version}"))?;
    let commit_us = elapsed_us(started);
    metrics.push(BatchCommitMetric {
        phase,
        batch_index,
        version,
        operations,
        phase_operations_completed,
        commit_us,
        root_hash_hex: hex::encode(<[u8; 32]>::from(root)),
        node_count: usize_to_u64(tree.nodes().len())?,
        stale_count: usize_to_u64(tree.stale_nodes().len())?,
    });
    Ok(commit_us)
}

fn update_latency_gate(config: &AuthTreeScaleConfig, samples: &[u64]) -> Result<UpdateLatencyGate> {
    ensure!(
        !samples.is_empty(),
        "update phase produced no latency samples"
    );
    let half = (samples.len() / 2).max(1);
    let requested_window = usize::try_from(config.window_batches)?;
    let window = requested_window.min(half);
    let late_start = samples.len() - window;
    let early = latency_stats(&samples[..window])?;
    let late = latency_stats(&samples[late_start..])?;
    let ratio_allowance = (early.p95_us as f64 * config.max_late_p95_ratio).ceil() as u64;
    let allowed_late_p95_us = ratio_allowance.saturating_add(config.latency_slack_us);
    Ok(UpdateLatencyGate {
        baseline_phase: "early_update_batches",
        comparison_phase: "late_update_batches",
        initial_load_batches_excluded: true,
        early_update_batch_start: 0,
        early_update_batch_end: usize_to_u64(window - 1)?,
        late_update_batch_start: usize_to_u64(late_start)?,
        late_update_batch_end: usize_to_u64(samples.len() - 1)?,
        early,
        late: late.clone(),
        max_late_p95_ratio: config.max_late_p95_ratio,
        latency_slack_us: config.latency_slack_us,
        allowed_late_p95_us,
        passed: late.p95_us <= allowed_late_p95_us,
    })
}

fn latency_stats(samples: &[u64]) -> Result<LatencyStats> {
    ensure!(!samples.is_empty(), "latency window is empty");
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    Ok(LatencyStats {
        samples: usize_to_u64(sorted.len())?,
        min_us: sorted[0],
        p50_us: nearest_rank(&sorted, 50),
        p95_us: nearest_rank(&sorted, 95),
        max_us: sorted[sorted.len() - 1],
    })
}

fn nearest_rank(sorted: &[u64], percentile: usize) -> u64 {
    let rank = sorted
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)]
}

fn prune_and_prove(
    config: &AuthTreeScaleConfig,
    tree: &mut InMemoryAuthTree,
) -> Result<PruneProofReport> {
    let latest = tree
        .latest_version()
        .context("scale tree has no committed version")?;
    let boundary = latest.saturating_sub(config.prune_retain_versions.saturating_sub(1));
    let proof_key = scale_object_key(0)?;
    let root_before = tree
        .root_hash(latest)
        .context("scale tree is missing latest root")?;
    let boundary_before = tree.prove(boundary, proof_key.clone())?;
    let expected_value = boundary_before
        .value
        .clone()
        .context("scale proof key is absent at pruning boundary")?;
    ensure!(
        verify_ics23_membership(&boundary_before, &expected_value),
        "boundary membership proof failed before pruning"
    );

    let removed = tree.prune_versions_before(boundary)?;
    let boundary_after = tree.prove(boundary, proof_key.clone())?;
    let latest_after = tree.prove(latest, proof_key.clone())?;
    let latest_value = latest_after
        .value
        .clone()
        .context("scale proof key is absent at latest version")?;
    let boundary_verified = boundary_after.value.as_ref() == Some(&expected_value)
        && verify_ics23_membership(&boundary_after, &expected_value);
    let latest_verified = verify_ics23_membership(&latest_after, &latest_value);
    let root_after = tree
        .root_hash(latest)
        .context("latest root disappeared during pruning")?;

    Ok(PruneProofReport {
        boundary_version: boundary,
        latest_version: latest,
        proof_key_hex: hex::encode(&proof_key),
        boundary_root_hash_hex: hex::encode(<[u8; 32]>::from(boundary_after.root_hash)),
        latest_root_hash_hex: hex::encode(<[u8; 32]>::from(root_after)),
        boundary_value_sha256_hex: hex::encode(Sha256::digest(&expected_value)),
        latest_value_sha256_hex: hex::encode(Sha256::digest(&latest_value)),
        boundary_commitment_proof_hex: hex::encode(boundary_after.encoded_commitment_proof()),
        latest_commitment_proof_hex: hex::encode(latest_after.encoded_commitment_proof()),
        boundary_membership_verified_after_prune: boundary_verified,
        latest_membership_verified_after_prune: latest_verified,
        version_before_boundary_rejected: boundary
            .checked_sub(1)
            .map(|version| tree.prove(version, proof_key).is_err()),
        latest_root_unchanged: root_before == root_after,
        removed: prune_removals(removed)?,
    })
}

fn tree_counts(tree: &InMemoryAuthTree) -> Result<TreeCounts> {
    let version = tree
        .latest_version()
        .context("scale tree has no committed version")?;
    let root = tree
        .root_hash(version)
        .context("scale tree is missing latest root")?;
    Ok(TreeCounts {
        version,
        root_hash_hex: hex::encode(<[u8; 32]>::from(root)),
        roots: usize_to_u64(tree.roots().len())?,
        nodes: usize_to_u64(tree.nodes().len())?,
        stale_nodes: usize_to_u64(tree.stale_nodes().len())?,
        value_versions: usize_to_u64(tree.values().len())?,
        key_preimages: usize_to_u64(tree.preimages().len())?,
    })
}

fn prune_removals(stats: PruneStats) -> Result<PruneRemovalCounts> {
    Ok(PruneRemovalCounts {
        nodes: usize_to_u64(stats.nodes_removed)?,
        value_versions: usize_to_u64(stats.value_versions_removed)?,
        key_preimages: usize_to_u64(stats.preimages_removed)?,
        stale_indices: usize_to_u64(stats.stale_indices_removed)?,
        roots: usize_to_u64(stats.roots_removed)?,
    })
}

fn scale_object_key(index: u64) -> Result<Vec<u8>> {
    stored_object_key(&format!("scale-object-{index:016x}"))
}

fn scale_value(object_index: u64, update_sequence: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(40);
    value.extend_from_slice(b"trnm-auth-tree-scale-v1");
    value.extend_from_slice(&object_index.to_be_bytes());
    value.extend_from_slice(&update_sequence.to_be_bytes());
    value
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn usize_to_u64(value: usize) -> Result<u64> {
    u64::try_from(value).context("scale counter exceeds u64")
}
