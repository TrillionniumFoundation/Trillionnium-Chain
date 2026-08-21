//! Runtime-owned signed metrics and terminal-state evidence for G3.
//!
//! The validator signs the measurements it alone can authoritatively observe:
//! finality latency, durable-sync boundary count, exact consensus/application
//! tip, signed event-journal head, restart state, and safety counters. CPU,
//! RSS, disk usage, and network byte counters are accepted as OS-observed
//! corroboration but are still bound into the validator signature. Neither
//! artifact asserts G3 completion, geo-WAN evidence, or production activation.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{ValidatorId, ValidatorSet};

use crate::{
    config::{LoadedValidatorConfig, PublicReportVerifierContext},
    consensus_report::SignedConsensusRunReportV1,
    process_event::CleanStoppedJournalCutV1,
};

pub const RUNTIME_METRICS_SCHEMA_VERSION_V1: u32 = 2;
pub const RUNTIME_FINAL_STATE_SCHEMA_VERSION_V1: u32 = 3;
pub const RUNTIME_METRICS_BODY_HASH_DOMAIN_V1: &[u8] = b"trnm.poco-g3.runtime-metrics.body.v2";
pub const RUNTIME_METRICS_SIGNATURE_DOMAIN_V1: &[u8] = b"trnm.poco-g3.runtime-metrics.signature.v2";
pub const RUNTIME_FINAL_STATE_BODY_HASH_DOMAIN_V1: &[u8] =
    b"trnm.poco-g3.runtime-final-state.body.v3";
pub const RUNTIME_FINAL_STATE_SIGNATURE_DOMAIN_V1: &[u8] =
    b"trnm.poco-g3.runtime-final-state.signature.v3";

const RUNTIME_METRICS_FILE: &str = "runtime-metrics.json";
const RUNTIME_FINAL_STATE_FILE: &str = "runtime-final-state.json";
const MAX_RUNTIME_EVIDENCE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FINALITY_SAMPLES: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvidenceContextV1 {
    run_id: String,
    validator_id: String,
    validator_set_sha256: String,
    topology_sha256: String,
    coordinator_manifest_sha256: String,
    candidate_source_sha256: String,
    binary_sha256: String,
    config_sha256: String,
    ordinary_start_height: u64,
}

impl RuntimeEvidenceContextV1 {
    fn from_loaded(config: &LoadedValidatorConfig) -> Self {
        Self {
            run_id: config.run_id().to_owned(),
            validator_id: hex::encode(config.local_validator().as_bytes()),
            validator_set_sha256: hex::encode(config.validator_set_sha256()),
            topology_sha256: hex::encode(config.topology_sha256()),
            coordinator_manifest_sha256: hex::encode(config.coordinator_manifest_sha256()),
            candidate_source_sha256: hex::encode(config.candidate_source_sha256()),
            binary_sha256: hex::encode(config.binary_sha256()),
            config_sha256: hex::encode(config.config_sha256()),
            ordinary_start_height: config.ordinary_start_height(),
        }
    }

    fn from_public(config: &PublicReportVerifierContext) -> Self {
        Self {
            run_id: config.run_id().to_owned(),
            validator_id: hex::encode(config.local_validator().as_bytes()),
            validator_set_sha256: hex::encode(config.validator_set_sha256()),
            topology_sha256: hex::encode(config.topology_sha256()),
            coordinator_manifest_sha256: hex::encode(config.coordinator_manifest_sha256()),
            candidate_source_sha256: hex::encode(config.candidate_source_sha256()),
            binary_sha256: hex::encode(config.binary_sha256()),
            config_sha256: hex::encode(config.config_sha256()),
            ordinary_start_height: config.ordinary_start_height(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedRuntimeMetricsV1 {
    pub schema_version: u32,
    pub run_id: String,
    pub validator_id: String,
    pub validator_set_sha256: String,
    pub topology_sha256: String,
    pub coordinator_manifest_sha256: String,
    pub candidate_source_sha256: String,
    pub binary_sha256: String,
    pub config_sha256: String,
    pub process_id: u32,
    pub process_instance_count: u64,
    pub ordinary_start_height: u64,
    pub runtime_event_sequence: u64,
    pub runtime_event_sha256: String,
    pub consensus_report_sha256: String,
    pub measurement_started_at: String,
    pub measurement_ended_at: String,
    pub runtime_started_monotonic_ns: u64,
    pub runtime_ended_monotonic_ns: u64,
    pub finality_samples_ms: Vec<f64>,
    /// Number of runtime durability boundaries whose underlying implementation
    /// completed an actual file/database sync before releasing authority.
    pub fsync_count: u64,
    pub cpu_seconds: f64,
    pub peak_rss_bytes: u64,
    pub disk_bytes: u64,
    pub network_tx_bytes: u64,
    pub network_rx_bytes: u64,
    pub os_metrics_corroboration: bool,
    pub validator_run_completed: bool,
    pub g3_evidence_complete: bool,
    pub geo_wan_evidence: bool,
    pub production_activation: bool,
    pub body_sha256: String,
    pub signature: String,
}

#[derive(Serialize)]
struct RuntimeMetricsBodyV1<'a> {
    schema_version: u32,
    run_id: &'a str,
    validator_id: &'a str,
    validator_set_sha256: &'a str,
    topology_sha256: &'a str,
    coordinator_manifest_sha256: &'a str,
    candidate_source_sha256: &'a str,
    binary_sha256: &'a str,
    config_sha256: &'a str,
    process_id: u32,
    process_instance_count: u64,
    ordinary_start_height: u64,
    runtime_event_sequence: u64,
    runtime_event_sha256: &'a str,
    consensus_report_sha256: &'a str,
    measurement_started_at: &'a str,
    measurement_ended_at: &'a str,
    runtime_started_monotonic_ns: u64,
    runtime_ended_monotonic_ns: u64,
    finality_samples_ms: &'a [f64],
    fsync_count: u64,
    cpu_seconds: f64,
    peak_rss_bytes: u64,
    disk_bytes: u64,
    network_tx_bytes: u64,
    network_rx_bytes: u64,
    os_metrics_corroboration: bool,
    validator_run_completed: bool,
    g3_evidence_complete: bool,
    geo_wan_evidence: bool,
    production_activation: bool,
}

impl SignedRuntimeMetricsV1 {
    fn body(&self) -> RuntimeMetricsBodyV1<'_> {
        RuntimeMetricsBodyV1 {
            schema_version: self.schema_version,
            run_id: &self.run_id,
            validator_id: &self.validator_id,
            validator_set_sha256: &self.validator_set_sha256,
            topology_sha256: &self.topology_sha256,
            coordinator_manifest_sha256: &self.coordinator_manifest_sha256,
            candidate_source_sha256: &self.candidate_source_sha256,
            binary_sha256: &self.binary_sha256,
            config_sha256: &self.config_sha256,
            process_id: self.process_id,
            process_instance_count: self.process_instance_count,
            ordinary_start_height: self.ordinary_start_height,
            runtime_event_sequence: self.runtime_event_sequence,
            runtime_event_sha256: &self.runtime_event_sha256,
            consensus_report_sha256: &self.consensus_report_sha256,
            measurement_started_at: &self.measurement_started_at,
            measurement_ended_at: &self.measurement_ended_at,
            runtime_started_monotonic_ns: self.runtime_started_monotonic_ns,
            runtime_ended_monotonic_ns: self.runtime_ended_monotonic_ns,
            finality_samples_ms: &self.finality_samples_ms,
            fsync_count: self.fsync_count,
            cpu_seconds: self.cpu_seconds,
            peak_rss_bytes: self.peak_rss_bytes,
            disk_bytes: self.disk_bytes,
            network_tx_bytes: self.network_tx_bytes,
            network_rx_bytes: self.network_rx_bytes,
            os_metrics_corroboration: self.os_metrics_corroboration,
            validator_run_completed: self.validator_run_completed,
            g3_evidence_complete: self.g3_evidence_complete,
            geo_wan_evidence: self.geo_wan_evidence,
            production_activation: self.production_activation,
        }
    }

    pub fn verify_for_config(&self, config: &LoadedValidatorConfig) -> Result<()> {
        verify_metrics(
            self,
            config.validator_set(),
            &RuntimeEvidenceContextV1::from_loaded(config),
        )
    }

    pub fn verify_for_public_context(&self, config: &PublicReportVerifierContext) -> Result<()> {
        verify_metrics(
            self,
            config.validator_set(),
            &RuntimeEvidenceContextV1::from_public(config),
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRuntimeFinalStateV1 {
    pub schema_version: u32,
    pub run_id: String,
    pub validator_id: String,
    pub validator_set_sha256: String,
    pub topology_sha256: String,
    pub coordinator_manifest_sha256: String,
    pub candidate_source_sha256: String,
    pub binary_sha256: String,
    pub config_sha256: String,
    pub process_id: u32,
    pub process_instance_count: u64,
    pub ordinary_start_height: u64,
    pub finalized_height: u64,
    pub finalized_ordinary_block_count: u64,
    pub finalized_block_id: String,
    pub finalized_state_root: String,
    pub finalized_chain_root: String,
    pub applied_height: u64,
    pub finalized_nonempty_ordinary_block_count: u64,
    pub runtime_event_sequence: u64,
    pub runtime_event_sha256: String,
    pub consensus_report_sha256: String,
    pub runtime_metrics_sha256: String,
    pub recovered_faults: Vec<String>,
    pub restart_completed: bool,
    pub double_sign_events: u64,
    pub duplicate_apply_events: u64,
    pub state_drift_events: u64,
    pub safety_halt_violations: u64,
    pub validator_run_completed: bool,
    pub g3_evidence_complete: bool,
    pub geo_wan_evidence: bool,
    pub production_activation: bool,
    pub body_sha256: String,
    pub signature: String,
}

#[derive(Serialize)]
struct RuntimeFinalStateBodyV1<'a> {
    schema_version: u32,
    run_id: &'a str,
    validator_id: &'a str,
    validator_set_sha256: &'a str,
    topology_sha256: &'a str,
    coordinator_manifest_sha256: &'a str,
    candidate_source_sha256: &'a str,
    binary_sha256: &'a str,
    config_sha256: &'a str,
    process_id: u32,
    process_instance_count: u64,
    ordinary_start_height: u64,
    finalized_height: u64,
    finalized_ordinary_block_count: u64,
    finalized_block_id: &'a str,
    finalized_state_root: &'a str,
    finalized_chain_root: &'a str,
    applied_height: u64,
    finalized_nonempty_ordinary_block_count: u64,
    runtime_event_sequence: u64,
    runtime_event_sha256: &'a str,
    consensus_report_sha256: &'a str,
    runtime_metrics_sha256: &'a str,
    recovered_faults: &'a [String],
    restart_completed: bool,
    double_sign_events: u64,
    duplicate_apply_events: u64,
    state_drift_events: u64,
    safety_halt_violations: u64,
    validator_run_completed: bool,
    g3_evidence_complete: bool,
    geo_wan_evidence: bool,
    production_activation: bool,
}

impl SignedRuntimeFinalStateV1 {
    fn body(&self) -> RuntimeFinalStateBodyV1<'_> {
        RuntimeFinalStateBodyV1 {
            schema_version: self.schema_version,
            run_id: &self.run_id,
            validator_id: &self.validator_id,
            validator_set_sha256: &self.validator_set_sha256,
            topology_sha256: &self.topology_sha256,
            coordinator_manifest_sha256: &self.coordinator_manifest_sha256,
            candidate_source_sha256: &self.candidate_source_sha256,
            binary_sha256: &self.binary_sha256,
            config_sha256: &self.config_sha256,
            process_id: self.process_id,
            process_instance_count: self.process_instance_count,
            ordinary_start_height: self.ordinary_start_height,
            finalized_height: self.finalized_height,
            finalized_ordinary_block_count: self.finalized_ordinary_block_count,
            finalized_block_id: &self.finalized_block_id,
            finalized_state_root: &self.finalized_state_root,
            finalized_chain_root: &self.finalized_chain_root,
            applied_height: self.applied_height,
            finalized_nonempty_ordinary_block_count: self.finalized_nonempty_ordinary_block_count,
            runtime_event_sequence: self.runtime_event_sequence,
            runtime_event_sha256: &self.runtime_event_sha256,
            consensus_report_sha256: &self.consensus_report_sha256,
            runtime_metrics_sha256: &self.runtime_metrics_sha256,
            recovered_faults: &self.recovered_faults,
            restart_completed: self.restart_completed,
            double_sign_events: self.double_sign_events,
            duplicate_apply_events: self.duplicate_apply_events,
            state_drift_events: self.state_drift_events,
            safety_halt_violations: self.safety_halt_violations,
            validator_run_completed: self.validator_run_completed,
            g3_evidence_complete: self.g3_evidence_complete,
            geo_wan_evidence: self.geo_wan_evidence,
            production_activation: self.production_activation,
        }
    }

    pub fn verify_for_config(&self, config: &LoadedValidatorConfig) -> Result<()> {
        verify_final_state(
            self,
            config.validator_set(),
            &RuntimeEvidenceContextV1::from_loaded(config),
        )
    }

    pub fn verify_for_public_context(&self, config: &PublicReportVerifierContext) -> Result<()> {
        verify_final_state(
            self,
            config.validator_set(),
            &RuntimeEvidenceContextV1::from_public(config),
        )
    }
}

pub(crate) struct RuntimeMetricsFactsV1 {
    pub(crate) measurement_started_at: String,
    pub(crate) measurement_ended_at: String,
    pub(crate) finality_samples_ms: Vec<f64>,
    pub(crate) fsync_count: u64,
    pub(crate) cpu_seconds: f64,
    pub(crate) peak_rss_bytes: u64,
    pub(crate) disk_bytes: u64,
    pub(crate) network_tx_bytes: u64,
    pub(crate) network_rx_bytes: u64,
}

pub(crate) struct RuntimeFinalStateFactsV1 {
    pub(crate) finalized_nonempty_ordinary_block_count: u64,
    pub(crate) double_sign_events: u64,
    pub(crate) duplicate_apply_events: u64,
    pub(crate) state_drift_events: u64,
    pub(crate) safety_halt_violations: u64,
}

pub(crate) fn sign_runtime_metrics_v1(
    config: &LoadedValidatorConfig,
    clean_stopped_journal: &CleanStoppedJournalCutV1,
    consensus_report: &SignedConsensusRunReportV1,
    facts: RuntimeMetricsFactsV1,
) -> Result<SignedRuntimeMetricsV1> {
    consensus_report.verify_for_config(config)?;
    if consensus_report.process_id != clean_stopped_journal.process_id()
        || consensus_report.process_instance != clean_stopped_journal.process_instance()
        || consensus_report.ended_monotonic_ns != clean_stopped_journal.clean_stop_monotonic_ns()
        || consensus_report.runtime_event_sequence != clean_stopped_journal.event_sequence()
        || consensus_report.runtime_event_sha256
            != hex::encode(clean_stopped_journal.event_sha256())
    {
        bail!("runtime metrics report differs from clean-stopped journal cut");
    }
    let report_sha256 = canonical_hex32(&consensus_report.report_sha256, "consensus report hash")?;
    let context = RuntimeEvidenceContextV1::from_loaded(config);
    let mut evidence = SignedRuntimeMetricsV1 {
        schema_version: RUNTIME_METRICS_SCHEMA_VERSION_V1,
        run_id: context.run_id,
        validator_id: context.validator_id,
        validator_set_sha256: context.validator_set_sha256,
        topology_sha256: context.topology_sha256,
        coordinator_manifest_sha256: context.coordinator_manifest_sha256,
        candidate_source_sha256: context.candidate_source_sha256,
        binary_sha256: context.binary_sha256,
        config_sha256: context.config_sha256,
        process_id: clean_stopped_journal.process_id(),
        process_instance_count: clean_stopped_journal.process_instance(),
        ordinary_start_height: context.ordinary_start_height,
        runtime_event_sequence: clean_stopped_journal.event_sequence(),
        runtime_event_sha256: hex::encode(clean_stopped_journal.event_sha256()),
        consensus_report_sha256: hex::encode(report_sha256),
        measurement_started_at: facts.measurement_started_at,
        measurement_ended_at: facts.measurement_ended_at,
        runtime_started_monotonic_ns: 0,
        runtime_ended_monotonic_ns: clean_stopped_journal.clean_stop_monotonic_ns(),
        finality_samples_ms: facts.finality_samples_ms,
        fsync_count: facts.fsync_count,
        cpu_seconds: facts.cpu_seconds,
        peak_rss_bytes: facts.peak_rss_bytes,
        disk_bytes: facts.disk_bytes,
        network_tx_bytes: facts.network_tx_bytes,
        network_rx_bytes: facts.network_rx_bytes,
        os_metrics_corroboration: true,
        validator_run_completed: true,
        g3_evidence_complete: false,
        geo_wan_evidence: false,
        production_activation: false,
        body_sha256: String::new(),
        signature: String::new(),
    };
    let body_hash = domain_hash(
        RUNTIME_METRICS_BODY_HASH_DOMAIN_V1,
        &serde_json::to_vec(&evidence.body()).context("encode runtime metrics body")?,
    );
    evidence.body_sha256 = hex::encode(body_hash);
    evidence.signature = hex::encode(
        config
            .consensus_signing_key()
            .sign(&domain_hash(
                RUNTIME_METRICS_SIGNATURE_DOMAIN_V1,
                &body_hash,
            ))
            .to_bytes(),
    );
    evidence.verify_for_config(config)?;
    Ok(evidence)
}

pub(crate) fn sign_runtime_final_state_v1(
    config: &LoadedValidatorConfig,
    clean_stopped_journal: &CleanStoppedJournalCutV1,
    consensus_report: &SignedConsensusRunReportV1,
    runtime_metrics: &SignedRuntimeMetricsV1,
    facts: RuntimeFinalStateFactsV1,
) -> Result<SignedRuntimeFinalStateV1> {
    consensus_report.verify_for_config(config)?;
    runtime_metrics.verify_for_config(config)?;
    let report_sha256 = canonical_hex32(&consensus_report.report_sha256, "consensus report hash")?;
    let metrics_sha256 = canonical_hex32(&runtime_metrics.body_sha256, "runtime metrics hash")?;
    if consensus_report.process_id != clean_stopped_journal.process_id()
        || consensus_report.process_instance != clean_stopped_journal.process_instance()
        || consensus_report.finalized_height != clean_stopped_journal.finalized_height()
        || consensus_report.application_committed_height != clean_stopped_journal.finalized_height()
        || consensus_report.application_head_block_id
            != hex::encode(clean_stopped_journal.finalized_block_id())
        || consensus_report.application_state_root
            != hex::encode(clean_stopped_journal.finalized_state_root())
        || consensus_report.runtime_event_sequence != clean_stopped_journal.event_sequence()
        || consensus_report.runtime_event_sha256
            != hex::encode(clean_stopped_journal.event_sha256())
        || runtime_metrics.process_id != clean_stopped_journal.process_id()
        || runtime_metrics.process_instance_count != clean_stopped_journal.process_instance()
        || runtime_metrics.runtime_event_sequence != clean_stopped_journal.event_sequence()
        || runtime_metrics.runtime_event_sha256 != hex::encode(clean_stopped_journal.event_sha256())
        || runtime_metrics.consensus_report_sha256 != consensus_report.report_sha256
    {
        bail!("runtime final state terminal evidence chain differs");
    }
    let context = RuntimeEvidenceContextV1::from_loaded(config);
    let finalized_ordinary_block_count = clean_stopped_journal
        .finalized_height()
        .checked_sub(context.ordinary_start_height)
        .and_then(|value| value.checked_add(1))
        .context("runtime final state has no finalized ordinary block")?;
    let mut evidence = SignedRuntimeFinalStateV1 {
        schema_version: RUNTIME_FINAL_STATE_SCHEMA_VERSION_V1,
        run_id: context.run_id,
        validator_id: context.validator_id,
        validator_set_sha256: context.validator_set_sha256,
        topology_sha256: context.topology_sha256,
        coordinator_manifest_sha256: context.coordinator_manifest_sha256,
        candidate_source_sha256: context.candidate_source_sha256,
        binary_sha256: context.binary_sha256,
        config_sha256: context.config_sha256,
        process_id: clean_stopped_journal.process_id(),
        process_instance_count: clean_stopped_journal.process_instance(),
        ordinary_start_height: context.ordinary_start_height,
        finalized_height: clean_stopped_journal.finalized_height(),
        finalized_ordinary_block_count,
        finalized_block_id: hex::encode(clean_stopped_journal.finalized_block_id()),
        finalized_state_root: hex::encode(clean_stopped_journal.finalized_state_root()),
        finalized_chain_root: hex::encode(clean_stopped_journal.finalized_chain_root()),
        applied_height: clean_stopped_journal.finalized_height(),
        finalized_nonempty_ordinary_block_count: facts.finalized_nonempty_ordinary_block_count,
        runtime_event_sequence: clean_stopped_journal.event_sequence(),
        runtime_event_sha256: hex::encode(clean_stopped_journal.event_sha256()),
        consensus_report_sha256: hex::encode(report_sha256),
        runtime_metrics_sha256: hex::encode(metrics_sha256),
        recovered_faults: clean_stopped_journal.recovered_faults().to_vec(),
        restart_completed: clean_stopped_journal.restart_completed(),
        double_sign_events: facts.double_sign_events,
        duplicate_apply_events: facts.duplicate_apply_events,
        state_drift_events: facts.state_drift_events,
        safety_halt_violations: facts.safety_halt_violations,
        validator_run_completed: true,
        g3_evidence_complete: false,
        geo_wan_evidence: false,
        production_activation: false,
        body_sha256: String::new(),
        signature: String::new(),
    };
    let body_hash = domain_hash(
        RUNTIME_FINAL_STATE_BODY_HASH_DOMAIN_V1,
        &serde_json::to_vec(&evidence.body()).context("encode runtime final-state body")?,
    );
    evidence.body_sha256 = hex::encode(body_hash);
    evidence.signature = hex::encode(
        config
            .consensus_signing_key()
            .sign(&domain_hash(
                RUNTIME_FINAL_STATE_SIGNATURE_DOMAIN_V1,
                &body_hash,
            ))
            .to_bytes(),
    );
    evidence.verify_for_config(config)?;
    Ok(evidence)
}

pub(crate) fn write_runtime_metrics_v1(
    config: &LoadedValidatorConfig,
    evidence: &SignedRuntimeMetricsV1,
) -> Result<PathBuf> {
    evidence.verify_for_config(config)?;
    let target = config.run_root().join(RUNTIME_METRICS_FILE);
    write_create_new_canonical(&target, evidence)?;
    let readback = load_signed_runtime_metrics_v1(&target)?;
    readback.verify_for_config(config)?;
    if &readback != evidence {
        bail!("runtime metrics fresh readback differs");
    }
    Ok(target)
}

pub(crate) fn write_runtime_final_state_v1(
    config: &LoadedValidatorConfig,
    evidence: &SignedRuntimeFinalStateV1,
) -> Result<PathBuf> {
    evidence.verify_for_config(config)?;
    let target = config.run_root().join(RUNTIME_FINAL_STATE_FILE);
    write_create_new_canonical(&target, evidence)?;
    let readback = load_signed_runtime_final_state_v1(&target)?;
    readback.verify_for_config(config)?;
    if &readback != evidence {
        bail!("runtime final-state fresh readback differs");
    }
    Ok(target)
}

pub fn load_signed_runtime_metrics_v1(path: &Path) -> Result<SignedRuntimeMetricsV1> {
    load_canonical(path, "runtime metrics")
}

pub fn load_signed_runtime_final_state_v1(path: &Path) -> Result<SignedRuntimeFinalStateV1> {
    load_canonical(path, "runtime final state")
}

fn verify_metrics(
    evidence: &SignedRuntimeMetricsV1,
    validator_set: &ValidatorSet,
    context: &RuntimeEvidenceContextV1,
) -> Result<()> {
    validate_context_fields(
        evidence.schema_version == RUNTIME_METRICS_SCHEMA_VERSION_V1,
        &evidence.run_id,
        &evidence.validator_id,
        &evidence.validator_set_sha256,
        &evidence.topology_sha256,
        &evidence.coordinator_manifest_sha256,
        &evidence.candidate_source_sha256,
        &evidence.binary_sha256,
        &evidence.config_sha256,
        context,
    )?;
    if evidence.process_id == 0
        || !(1..=2).contains(&evidence.process_instance_count)
        || evidence.ordinary_start_height != context.ordinary_start_height
        || evidence.runtime_event_sequence == 0
        || !canonical_utc_interval(
            &evidence.measurement_started_at,
            &evidence.measurement_ended_at,
        )
        || evidence.runtime_started_monotonic_ns != 0
        || evidence.runtime_ended_monotonic_ns == 0
        || evidence.finality_samples_ms.is_empty()
        || evidence.finality_samples_ms.len() > MAX_FINALITY_SAMPLES
        || evidence
            .finality_samples_ms
            .iter()
            .any(|sample| !sample.is_finite() || *sample <= 0.0)
        || evidence.fsync_count == 0
        || !evidence.cpu_seconds.is_finite()
        || evidence.cpu_seconds <= 0.0
        || evidence.peak_rss_bytes == 0
        || evidence.disk_bytes == 0
        || evidence.network_tx_bytes == 0
        || evidence.network_rx_bytes == 0
        || !evidence.os_metrics_corroboration
        || !evidence.validator_run_completed
        || evidence.g3_evidence_complete
        || evidence.geo_wan_evidence
        || evidence.production_activation
    {
        bail!("runtime metrics crosses its exact bounded semantic profile");
    }
    for (value, field) in [
        (&evidence.runtime_event_sha256, "runtime event hash"),
        (&evidence.consensus_report_sha256, "consensus report hash"),
    ] {
        if canonical_hex32(value, field)? == [0; 32] {
            bail!("runtime metrics contains zero {field}");
        }
    }
    let body_hash = domain_hash(
        RUNTIME_METRICS_BODY_HASH_DOMAIN_V1,
        &serde_json::to_vec(&evidence.body()).context("encode runtime metrics body")?,
    );
    verify_signature(
        &evidence.validator_id,
        validator_set,
        body_hash,
        RUNTIME_METRICS_SIGNATURE_DOMAIN_V1,
        &evidence.body_sha256,
        &evidence.signature,
    )
}

fn verify_final_state(
    evidence: &SignedRuntimeFinalStateV1,
    validator_set: &ValidatorSet,
    context: &RuntimeEvidenceContextV1,
) -> Result<()> {
    validate_context_fields(
        evidence.schema_version == RUNTIME_FINAL_STATE_SCHEMA_VERSION_V1,
        &evidence.run_id,
        &evidence.validator_id,
        &evidence.validator_set_sha256,
        &evidence.topology_sha256,
        &evidence.coordinator_manifest_sha256,
        &evidence.candidate_source_sha256,
        &evidence.binary_sha256,
        &evidence.config_sha256,
        context,
    )?;
    let faults: BTreeSet<_> = evidence.recovered_faults.iter().collect();
    if evidence.process_id == 0
        || !(1..=2).contains(&evidence.process_instance_count)
        || evidence.ordinary_start_height != context.ordinary_start_height
        || evidence.finalized_ordinary_block_count == 0
        || evidence.finalized_height
            != evidence
                .ordinary_start_height
                .checked_add(evidence.finalized_ordinary_block_count - 1)
                .unwrap_or(0)
        || evidence.applied_height != evidence.finalized_height
        || evidence.finalized_nonempty_ordinary_block_count
            != evidence.finalized_ordinary_block_count
        || evidence.runtime_event_sequence == 0
        || evidence.runtime_event_sha256 == "0".repeat(64)
        || evidence.consensus_report_sha256 == "0".repeat(64)
        || evidence.runtime_metrics_sha256 == "0".repeat(64)
        || faults.len() != evidence.recovered_faults.len()
        || !evidence
            .recovered_faults
            .windows(2)
            .all(|window| window[0] < window[1])
        || evidence.recovered_faults.iter().any(|fault| {
            !matches!(
                fault.as_str(),
                "leader_loss"
                    | "validator_process_kill"
                    | "host_loss"
                    | "asymmetric_partition"
                    | "bounded_delay_loss"
                    | "stale_snapshot"
                    | "rollback_attempt"
                    | "epoch_handoff"
            )
        })
        || (evidence.process_instance_count == 2) != evidence.restart_completed
        || evidence.double_sign_events != 0
        || evidence.duplicate_apply_events != 0
        || evidence.state_drift_events != 0
        || evidence.safety_halt_violations != 0
        || !evidence.validator_run_completed
        || evidence.g3_evidence_complete
        || evidence.geo_wan_evidence
        || evidence.production_activation
    {
        bail!("runtime final state crosses its exact bounded semantic profile");
    }
    for (value, field) in [
        (&evidence.finalized_block_id, "finalized block ID"),
        (&evidence.finalized_state_root, "finalized state root"),
        (&evidence.finalized_chain_root, "finalized chain root"),
        (&evidence.runtime_event_sha256, "runtime event hash"),
        (&evidence.consensus_report_sha256, "consensus report hash"),
        (&evidence.runtime_metrics_sha256, "runtime metrics hash"),
    ] {
        if canonical_hex32(value, field)? == [0; 32] {
            bail!("runtime final state contains zero {field}");
        }
    }
    let body_hash = domain_hash(
        RUNTIME_FINAL_STATE_BODY_HASH_DOMAIN_V1,
        &serde_json::to_vec(&evidence.body()).context("encode runtime final-state body")?,
    );
    verify_signature(
        &evidence.validator_id,
        validator_set,
        body_hash,
        RUNTIME_FINAL_STATE_SIGNATURE_DOMAIN_V1,
        &evidence.body_sha256,
        &evidence.signature,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_context_fields(
    correct_schema: bool,
    run_id: &str,
    validator_id: &str,
    validator_set_sha256: &str,
    topology_sha256: &str,
    coordinator_manifest_sha256: &str,
    candidate_source_sha256: &str,
    binary_sha256: &str,
    config_sha256: &str,
    expected: &RuntimeEvidenceContextV1,
) -> Result<()> {
    if !correct_schema
        || run_id != expected.run_id
        || validator_id != expected.validator_id
        || validator_set_sha256 != expected.validator_set_sha256
        || topology_sha256 != expected.topology_sha256
        || coordinator_manifest_sha256 != expected.coordinator_manifest_sha256
        || candidate_source_sha256 != expected.candidate_source_sha256
        || binary_sha256 != expected.binary_sha256
        || config_sha256 != expected.config_sha256
    {
        bail!("runtime evidence deployment context differs");
    }
    for (value, field) in [
        (validator_set_sha256, "validator set hash"),
        (topology_sha256, "topology hash"),
        (coordinator_manifest_sha256, "coordinator hash"),
        (candidate_source_sha256, "candidate hash"),
        (binary_sha256, "binary hash"),
        (config_sha256, "config hash"),
    ] {
        if canonical_hex32(value, field)? == [0; 32] {
            bail!("runtime evidence contains zero {field}");
        }
    }
    Ok(())
}

fn verify_signature(
    validator_id: &str,
    validator_set: &ValidatorSet,
    body_hash: [u8; 32],
    signature_domain: &[u8],
    encoded_body_hash: &str,
    encoded_signature: &str,
) -> Result<()> {
    if canonical_hex32(encoded_body_hash, "runtime evidence body hash")? != body_hash {
        bail!("runtime evidence body hash differs");
    }
    let author = ValidatorId::new(canonical_hex32(validator_id, "runtime evidence author")?);
    let validator = validator_set
        .validator(author)
        .ok_or_else(|| anyhow!("runtime evidence author is absent from validator set"))?;
    let key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
        .context("decode runtime evidence public key")?;
    let signature = Signature::from_bytes(&canonical_hex64(
        encoded_signature,
        "runtime evidence signature",
    )?);
    key.verify_strict(&domain_hash(signature_domain, &body_hash), &signature)
        .context("verify runtime evidence signature")
}

/// Accepts exactly second-resolution RFC 3339 UTC. Fixed width makes byte
/// ordering chronological after the calendar fields have been validated.
fn canonical_utc_interval(start: &str, end: &str) -> bool {
    canonical_utc_timestamp(start)
        && canonical_utc_timestamp(end)
        && start.as_bytes() < end.as_bytes()
}

fn canonical_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        std::str::from_utf8(&bytes[range]).ok()?.parse().ok()
    };
    let Some(year) = number(0..4) else {
        return false;
    };
    let Some(month) = number(5..7) else {
        return false;
    };
    let Some(day) = number(8..10) else {
        return false;
    };
    let Some(hour) = number(11..13) else {
        return false;
    };
    let Some(minute) = number(14..16) else {
        return false;
    };
    let Some(second) = number(17..19) else {
        return false;
    };
    if year == 0 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum_day = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=maximum_day).contains(&day)
}

fn write_create_new_canonical<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent_path = path
        .parent()
        .ok_or_else(|| anyhow!("runtime evidence parent is missing"))?
        .canonicalize()
        .context("canonicalize runtime evidence parent")?;
    let parent_metadata = fs::metadata(&parent_path).context("stat runtime evidence parent")?;
    if !parent_metadata.is_dir() || parent_metadata.permissions().mode() & 0o077 != 0 {
        bail!("runtime evidence parent is not private");
    }
    let target = parent_path.join(
        path.file_name()
            .ok_or_else(|| anyhow!("runtime evidence file name is missing"))?,
    );
    let bytes = serde_json::to_vec(value).context("encode canonical runtime evidence")?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RUNTIME_EVIDENCE_BYTES
    {
        bail!("runtime evidence crosses its size bound");
    }
    let parent = File::open(&parent_path).context("open runtime evidence parent")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&target)
        .context("create runtime evidence")?;
    file.write_all(&bytes).context("write runtime evidence")?;
    file.sync_all().context("sync runtime evidence")?;
    parent.sync_all().context("sync runtime evidence parent")?;
    let metadata = file.metadata().context("stat runtime evidence")?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.uid() != parent_metadata.uid()
        || metadata.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        bail!("runtime evidence identity differs after write");
    }
    Ok(())
}

fn load_canonical<T>(path: &Path, label: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {label}"))?;
    let metadata = file.metadata().with_context(|| format!("stat {label}"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_RUNTIME_EVIDENCE_BYTES {
        bail!("{label} crosses its size bound");
    }
    let capacity = usize::try_from(metadata.len()).context("runtime evidence size overflow")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    if bytes.len() != capacity {
        bail!("{label} changed length while read");
    }
    let value: T = serde_json::from_slice(&bytes).with_context(|| format!("decode {label}"))?;
    if serde_json::to_vec(&value).with_context(|| format!("re-encode {label}"))? != bytes {
        bail!("{label} is not canonical JSON");
    }
    Ok(value)
}

fn canonical_hex32(value: &str, field: &str) -> Result<[u8; 32]> {
    canonical_hex(value, field)
}

fn canonical_hex64(value: &str, field: &str) -> Result<[u8; 64]> {
    canonical_hex(value, field)
}

fn canonical_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} is not canonical lowercase hex");
    }
    let bytes = hex::decode(value).with_context(|| format!("decode {field}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{field} has the wrong length"))
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    fn fixture() -> (RuntimeEvidenceContextV1, ValidatorSet, SigningKey) {
        let key = SigningKey::from_bytes(&[0x31; 32]);
        let validator_id = ValidatorId::new([0x21; 32]);
        let validator = Validator::new(
            validator_id,
            ConsensusPublicKey::new(key.verifying_key().to_bytes()),
            VotingPower::new(1).unwrap(),
        )
        .unwrap();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([0x11; 32]),
            ChainId::new("trnm-g3-runtime-evidence-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            vec![validator],
        )
        .unwrap();
        (
            RuntimeEvidenceContextV1 {
                run_id: "poco-g3-7-20260814t010203z-abcdef0123456789".to_owned(),
                validator_id: hex::encode(validator_id.as_bytes()),
                validator_set_sha256: hex::encode([0x41; 32]),
                topology_sha256: hex::encode([0x42; 32]),
                coordinator_manifest_sha256: hex::encode([0x43; 32]),
                candidate_source_sha256: hex::encode([0x44; 32]),
                binary_sha256: hex::encode([0x45; 32]),
                config_sha256: hex::encode([0x46; 32]),
                ordinary_start_height: 4,
            },
            set,
            key,
        )
    }

    fn sign_metrics_for_test() -> (
        SignedRuntimeMetricsV1,
        RuntimeEvidenceContextV1,
        ValidatorSet,
    ) {
        let (context, set, key) = fixture();
        let mut evidence = SignedRuntimeMetricsV1 {
            schema_version: RUNTIME_METRICS_SCHEMA_VERSION_V1,
            run_id: context.run_id.clone(),
            validator_id: context.validator_id.clone(),
            validator_set_sha256: context.validator_set_sha256.clone(),
            topology_sha256: context.topology_sha256.clone(),
            coordinator_manifest_sha256: context.coordinator_manifest_sha256.clone(),
            candidate_source_sha256: context.candidate_source_sha256.clone(),
            binary_sha256: context.binary_sha256.clone(),
            config_sha256: context.config_sha256.clone(),
            process_id: 7,
            process_instance_count: 1,
            ordinary_start_height: 4,
            runtime_event_sequence: 77,
            runtime_event_sha256: hex::encode([0x51; 32]),
            consensus_report_sha256: hex::encode([0x52; 32]),
            measurement_started_at: "2026-08-14T01:00:00Z".to_owned(),
            measurement_ended_at: "2026-08-14T02:00:00Z".to_owned(),
            runtime_started_monotonic_ns: 0,
            runtime_ended_monotonic_ns: 1,
            finality_samples_ms: vec![1.0, 2.0],
            fsync_count: 3,
            cpu_seconds: 4.0,
            peak_rss_bytes: 5,
            disk_bytes: 6,
            network_tx_bytes: 7,
            network_rx_bytes: 8,
            os_metrics_corroboration: true,
            validator_run_completed: true,
            g3_evidence_complete: false,
            geo_wan_evidence: false,
            production_activation: false,
            body_sha256: String::new(),
            signature: String::new(),
        };
        let hash = domain_hash(
            RUNTIME_METRICS_BODY_HASH_DOMAIN_V1,
            &serde_json::to_vec(&evidence.body()).unwrap(),
        );
        evidence.body_sha256 = hex::encode(hash);
        evidence.signature = hex::encode(
            key.sign(&domain_hash(RUNTIME_METRICS_SIGNATURE_DOMAIN_V1, &hash))
                .to_bytes(),
        );
        (evidence, context, set)
    }

    #[test]
    fn metrics_signature_and_semantics_are_exact() {
        let (evidence, context, set) = sign_metrics_for_test();
        verify_metrics(&evidence, &set, &context).unwrap();
        let mut changed = evidence.clone();
        changed.fsync_count += 1;
        assert!(verify_metrics(&changed, &set, &context).is_err());
        let mut zero = evidence;
        zero.finality_samples_ms[0] = 0.0;
        assert!(verify_metrics(&zero, &set, &context).is_err());
    }

    #[test]
    fn metrics_requires_canonical_ordered_utc_interval() {
        assert!(canonical_utc_interval(
            "2024-02-29T23:59:58Z",
            "2024-02-29T23:59:59Z"
        ));
        assert!(!canonical_utc_interval(
            "2023-02-29T23:59:58Z",
            "2023-03-01T00:00:00Z"
        ));
        assert!(!canonical_utc_interval(
            "2026-08-14T02:00:00Z",
            "2026-08-14T01:00:00Z"
        ));
        assert!(!canonical_utc_interval(
            "2026-08-14T01:00:00+00:00",
            "2026-08-14T02:00:00+00:00"
        ));
    }

    #[test]
    fn final_state_signature_binds_roots_faults_and_restart() {
        let (context, set, key) = fixture();
        let mut evidence = SignedRuntimeFinalStateV1 {
            schema_version: RUNTIME_FINAL_STATE_SCHEMA_VERSION_V1,
            run_id: context.run_id.clone(),
            validator_id: context.validator_id.clone(),
            validator_set_sha256: context.validator_set_sha256.clone(),
            topology_sha256: context.topology_sha256.clone(),
            coordinator_manifest_sha256: context.coordinator_manifest_sha256.clone(),
            candidate_source_sha256: context.candidate_source_sha256.clone(),
            binary_sha256: context.binary_sha256.clone(),
            config_sha256: context.config_sha256.clone(),
            process_id: 7,
            process_instance_count: 2,
            ordinary_start_height: 4,
            finalized_height: 9,
            finalized_ordinary_block_count: 6,
            finalized_block_id: hex::encode([0x51; 32]),
            finalized_state_root: hex::encode([0x52; 32]),
            finalized_chain_root: hex::encode([0x53; 32]),
            applied_height: 9,
            finalized_nonempty_ordinary_block_count: 6,
            runtime_event_sequence: 77,
            runtime_event_sha256: hex::encode([0x54; 32]),
            consensus_report_sha256: hex::encode([0x55; 32]),
            runtime_metrics_sha256: hex::encode([0x56; 32]),
            recovered_faults: vec!["validator_process_kill".to_owned()],
            restart_completed: true,
            double_sign_events: 0,
            duplicate_apply_events: 0,
            state_drift_events: 0,
            safety_halt_violations: 0,
            validator_run_completed: true,
            g3_evidence_complete: false,
            geo_wan_evidence: false,
            production_activation: false,
            body_sha256: String::new(),
            signature: String::new(),
        };
        let hash = domain_hash(
            RUNTIME_FINAL_STATE_BODY_HASH_DOMAIN_V1,
            &serde_json::to_vec(&evidence.body()).unwrap(),
        );
        evidence.body_sha256 = hex::encode(hash);
        evidence.signature = hex::encode(
            key.sign(&domain_hash(RUNTIME_FINAL_STATE_SIGNATURE_DOMAIN_V1, &hash))
                .to_bytes(),
        );
        verify_final_state(&evidence, &set, &context).unwrap();
        let mut duplicate = evidence.clone();
        duplicate
            .recovered_faults
            .push("validator_process_kill".to_owned());
        assert!(verify_final_state(&duplicate, &set, &context).is_err());
        let mut wrong_count = evidence.clone();
        wrong_count.finalized_ordinary_block_count += 1;
        assert!(verify_final_state(&wrong_count, &set, &context).is_err());
        let mut empty_ordinary = evidence.clone();
        empty_ordinary.finalized_nonempty_ordinary_block_count -= 1;
        assert!(verify_final_state(&empty_ordinary, &set, &context).is_err());
        let mut wrong_restart = evidence;
        wrong_restart.restart_completed = false;
        assert!(verify_final_state(&wrong_restart, &set, &context).is_err());
    }
}
