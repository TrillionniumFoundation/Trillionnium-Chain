#![recursion_limit = "256"]
#![forbid(unsafe_code)]

use std::{
    env,
    path::PathBuf,
    process::ExitCode,
    sync::{
        mpsc::{self, TryRecvError},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use serde_json::json;
use trnm_poco_lab_validator::{
    config::{LoadedValidatorConfig, PublicReportVerifierContext},
    consensus_report::{
        load_signed_consensus_run_report_v1, validate_consensus_run_report_target_v1,
        MAX_CONSENSUS_RUN_BLOCKS_V1, MAX_CONSENSUS_RUN_DURATION_SECONDS_V1,
    },
    consensus_runtime::{
        commission_deployed_ordinary_runtime_for_cli_v1,
        run_bounded_consensus_with_external_fence_v1, run_deployed_bounded_consensus_v1,
        BoundedConsensusRunOutcomeV1, MINIMUM_CONSENSUS_RUN_BLOCKS_V1,
        PROCESS1_TARGET_PARKED_EXIT_STATUS_V1,
    },
    fleet_barrier_evidence::load_and_verify_fleet_start_certificate_v1,
    network::{load_signed_network_smoke_report, run_network_smoke},
    process_event::{verify_runtime_event_journal_v1, RuntimeEventJournalV1, RuntimeEventKindV1},
    runtime::positive_checkpoint_bootstrap_assessment_v1,
    runtime_control::send_runtime_control_request_v1,
    runtime_evidence::{load_signed_runtime_final_state_v1, load_signed_runtime_metrics_v1},
    signed_replay_archive::verify_replay_archive_v1,
    startup_rejection::{
        attempt_isolated_startup_rejection_v1,
        load_and_verify_isolated_startup_rejection_evidence_v1,
        load_local_fleet_start_certificate_for_isolated_rejection_v1,
        persist_isolated_startup_rejection_evidence_v1, IsolatedStartupFaultKindV1,
    },
    AUTHENTICATED_FRAME_RESTART_REPLAY_AUTHORITY, AUTHENTICATED_FRESH_SESSION_RUNTIME,
    BOUNDED_CONSENSUS_INGRESS_LOOP_SCAFFOLD, CONTINUOUS_CONSENSUS_RUNTIME,
    COORDINATOR_ANCHOR_CAUSAL_BINDING, EXTERNAL_WALL_CLOCK_TEMPORAL_PROVENANCE, GEO_WAN_EVIDENCE,
    NATIVE_EXECUTION_RUNTIME, ONE_SHOT_AUTHORITY_RUNTIME, PRODUCTION_CANDIDATE,
    PRODUCTION_CONSENSUS_ACTIVATION, REAL_CORE_CONFIG, REAL_CORE_RUNTIME, SAFETY_STORE_RUNTIME,
    SIGNED_PROCESS_EVENT_JOURNAL, SIGNER_JOURNAL_RUNTIME, SIMULATOR_DEPENDENCY,
    STRICT_CONSENSUS_INGRESS, TIMEOUT_TC_COLLECTOR, VALIDATOR_RUNTIME_STARTED,
    WEIGHTED_VOTE_QC_COLLECTOR,
};

#[cfg(unix)]
use trnm_poco_lab_validator::p2p_admission::UnixExternalPeerLeaseAuthorityV1;

#[cfg(unix)]
use trnm_consensus_peer_lease::{UnixPeerLeaseClientV1, UnixPeerLeaseDaemonV1};

#[cfg(unix)]
use std::{
    fs::Metadata,
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::Component,
};

#[cfg(unix)]
const UNIX_SOCKET_PATH_MAX_BYTES_V1: usize = 107;

fn main() -> ExitCode {
    match run() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("trnm-poco-lab-validator failed: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let mut arguments = env::args_os().skip(1);
    let command = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| anyhow::anyhow!(usage()))?;
    // The lease daemon is an independent candidate-only process.  Dispatch it
    // before the normal command envelope so this subcommand never parses a
    // validator run-root/config and therefore cannot load validator secrets.
    if command == "peer-lease-daemon" {
        return run_peer_lease_daemon(arguments);
    }
    let run_root = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
    let config = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
    if command == "verify-replay-archive" {
        let context_path = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let entries_path = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let head_path = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let terminal_seal_path =
            PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let expected_coordinator_manifest_sha256 = arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| anyhow::anyhow!(usage()))?;
        if arguments.next().is_some() {
            bail!(usage());
        }
        let public_context = PublicReportVerifierContext::load(
            run_root,
            config,
            &expected_coordinator_manifest_sha256,
        )?;
        let verified = verify_replay_archive_v1(
            &context_path,
            &entries_path,
            &head_path,
            &terminal_seal_path,
            &public_context,
        )?;
        println!("{}", serde_json::to_string(&verified)?);
        return Ok(ExitCode::SUCCESS);
    }
    if command == "verify-network-report" {
        let report_path = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let expected_coordinator_manifest_sha256 = arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| anyhow::anyhow!(usage()))?;
        if arguments.next().is_some() {
            bail!(usage());
        }
        let public_context = PublicReportVerifierContext::load(
            run_root,
            config,
            &expected_coordinator_manifest_sha256,
        )?;
        let signed = load_signed_network_smoke_report(&report_path)?;
        signed.verify_for_public_context(&public_context)?;
        println!(
            "{}",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "status": "network-smoke-report-signature-and-semantics-verified",
                "run_id": signed.report.run_id,
                "validator_id": signed.report.validator_id,
                "validator_set_id": signed.report.validator_set_id,
                "topology_sha256": signed.report.topology_sha256,
                "coordinator_manifest_sha256": signed.report.coordinator_manifest_sha256,
                "candidate_source_sha256": signed.report.candidate_source_sha256,
                "binary_sha256": signed.report.binary_sha256,
                "config_sha256": signed.report.config_sha256,
                "peer_session_count": signed.report.peer_sessions.len(),
                "validator_run_completed": false,
                "g3_evidence_complete": false,
                "geo_wan_evidence": false,
                "production_activation": false,
            }))?
        );
        return Ok(ExitCode::SUCCESS);
    }
    if command == "verify-consensus-report" {
        let report_path = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let expected_coordinator_manifest_sha256 = arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| anyhow::anyhow!(usage()))?;
        if arguments.next().is_some() {
            bail!(usage());
        }
        let public_context = PublicReportVerifierContext::load(
            run_root,
            config,
            &expected_coordinator_manifest_sha256,
        )?;
        let signed = load_signed_consensus_run_report_v1(&report_path)?;
        let verified = signed.verify_for_public_context(&public_context)?;
        println!("{}", serde_json::to_string(&verified)?);
        return Ok(ExitCode::SUCCESS);
    }
    if command == "verify-runtime-journal" {
        let journal_path = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let expected_coordinator_manifest_sha256 = arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| anyhow::anyhow!(usage()))?;
        if arguments.next().is_some() {
            bail!(usage());
        }
        let public_context = PublicReportVerifierContext::load(
            run_root,
            config,
            &expected_coordinator_manifest_sha256,
        )?;
        let verified = verify_runtime_event_journal_v1(&journal_path, &public_context)?;
        println!("{}", serde_json::to_string(&verified)?);
        return Ok(ExitCode::SUCCESS);
    }
    if command == "verify-runtime-metrics" || command == "verify-runtime-final-state" {
        let evidence_path =
            PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let expected_coordinator_manifest_sha256 = arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| anyhow::anyhow!(usage()))?;
        if arguments.next().is_some() {
            bail!(usage());
        }
        let public_context = PublicReportVerifierContext::load(
            run_root,
            config,
            &expected_coordinator_manifest_sha256,
        )?;
        if command == "verify-runtime-metrics" {
            let evidence = load_signed_runtime_metrics_v1(&evidence_path)?;
            evidence.verify_for_public_context(&public_context)?;
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "schema_version": evidence.schema_version,
                    "status": "runtime-metrics-signature-and-semantics-verified",
                    "run_id": evidence.run_id,
                    "validator_id": evidence.validator_id,
                    "process_instance_count": evidence.process_instance_count,
                    "ordinary_start_height": evidence.ordinary_start_height,
                    "runtime_event_sequence": evidence.runtime_event_sequence,
                    "runtime_event_sha256": evidence.runtime_event_sha256,
                    "consensus_report_sha256": evidence.consensus_report_sha256,
                    "finality_sample_count": evidence.finality_samples_ms.len(),
                    "fsync_count": evidence.fsync_count,
                    "body_sha256": evidence.body_sha256,
                    "signature_verified": true,
                    "semantics_verified": true,
                    "g3_evidence_complete": false,
                    "geo_wan_evidence": false,
                    "production_activation": false,
                }))?
            );
        } else {
            let evidence = load_signed_runtime_final_state_v1(&evidence_path)?;
            evidence.verify_for_public_context(&public_context)?;
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "schema_version": evidence.schema_version,
                    "status": "runtime-final-state-signature-and-semantics-verified",
                    "run_id": evidence.run_id,
                    "validator_id": evidence.validator_id,
                    "process_instance_count": evidence.process_instance_count,
                    "ordinary_start_height": evidence.ordinary_start_height,
                    "finalized_height": evidence.finalized_height,
                    "finalized_ordinary_block_count": evidence.finalized_ordinary_block_count,
                    "finalized_block_id": evidence.finalized_block_id,
                    "finalized_state_root": evidence.finalized_state_root,
                    "finalized_chain_root": evidence.finalized_chain_root,
                    "finalized_nonempty_ordinary_block_count": evidence.finalized_nonempty_ordinary_block_count,
                    "runtime_event_sequence": evidence.runtime_event_sequence,
                    "runtime_event_sha256": evidence.runtime_event_sha256,
                    "consensus_report_sha256": evidence.consensus_report_sha256,
                    "runtime_metrics_sha256": evidence.runtime_metrics_sha256,
                    "body_sha256": evidence.body_sha256,
                    "signature_verified": true,
                    "semantics_verified": true,
                    "g3_evidence_complete": false,
                    "geo_wan_evidence": false,
                    "production_activation": false,
                }))?
            );
        }
        return Ok(ExitCode::SUCCESS);
    }
    if command == "verify-fleet-start-certificate" {
        let certificate_path =
            PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let expected_coordinator_manifest_sha256 = arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| anyhow::anyhow!(usage()))?;
        let expected_duration_seconds = parse_bounded_u64(
            arguments.next(),
            "expected-duration-seconds",
            1,
            MAX_CONSENSUS_RUN_DURATION_SECONDS_V1,
        )?;
        let expected_max_blocks = parse_bounded_u64(
            arguments.next(),
            "expected-max-blocks",
            MINIMUM_CONSENSUS_RUN_BLOCKS_V1,
            MAX_CONSENSUS_RUN_BLOCKS_V1,
        )?;
        if arguments.next().is_some() {
            bail!(usage());
        }
        let public_context = PublicReportVerifierContext::load(
            run_root,
            config,
            &expected_coordinator_manifest_sha256,
        )?;
        let verified = load_and_verify_fleet_start_certificate_v1(
            &certificate_path,
            &public_context,
            expected_duration_seconds,
            expected_max_blocks,
        )?;
        println!("{}", serde_json::to_string(&verified)?);
        return Ok(ExitCode::SUCCESS);
    }
    if command == "verify-isolated-startup-rejection" {
        let evidence_path =
            PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let fleet_start_certificate_path =
            PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let expected_coordinator_manifest_sha256 = arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| anyhow::anyhow!(usage()))?;
        if arguments.next().is_some() {
            bail!(usage());
        }
        let public_context = PublicReportVerifierContext::load(
            run_root,
            config,
            &expected_coordinator_manifest_sha256,
        )?;
        let verified = load_and_verify_isolated_startup_rejection_evidence_v1(
            &evidence_path,
            &fleet_start_certificate_path,
            &public_context,
        )?;
        let evidence = verified.evidence();
        println!(
            "{}",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "status": "isolated-startup-rejection-signature-and-semantics-verified",
                "run_id": evidence.campaign().identity().run_id(),
                "validator_id": hex::encode(evidence.origin().as_bytes()),
                "target_config_sha256": hex::encode(evidence.target_config_sha256()),
                "fleet_start_certificate_sha256": hex::encode(evidence.fleet_start_certificate_sha256()),
                "fault_kind": evidence.fault_kind().as_str(),
                "changed_file_count": evidence.changed_file_count(),
                "attempt_nonce": hex::encode(evidence.attempt_nonce()),
                "node_error_class": evidence.node_error_class().as_str(),
                "node_error_stage": evidence.node_error_stage(),
                "primary_cut_sha256": hex::encode(evidence.source_primary_cut_digest()),
                "isolated_snapshot_sha256": hex::encode(evidence.isolated_snapshot_content_digest()),
                "isolated_snapshot_inventory_sha256": hex::encode(evidence.isolated_snapshot_inventory_digest()),
                "runtime_journal_sha256": hex::encode(evidence.runtime_journal_sha256()),
                "runtime_journal_bytes": evidence.runtime_journal_bytes(),
                "process_instance": evidence.process_instance(),
                "primary_unchanged": evidence.primary_unchanged(),
                "runtime_journal_unchanged": evidence.runtime_journal_unchanged(),
                "network_started": evidence.network_started(),
                "evidence_sha256": hex::encode(evidence.evidence_sha256()),
                "artifact_sha256": hex::encode(verified.artifact_sha256()),
                "signature_verified": true,
                "semantics_verified": true,
                "fault_campaign_observed": false,
                "g3_evidence_complete": false,
                "geo_wan_evidence": false,
                "production_activation": false,
            }))?
        );
        return Ok(ExitCode::SUCCESS);
    }
    if command == "run-consensus" {
        // Reject malformed public bounds before opening any deployment store.
        // This keeps the CLI's invalid-input path independent of topology size
        // and makes the no-effect contract observable even for 100 validators.
        let duration_seconds = parse_bounded_u64(
            arguments.next(),
            "duration-seconds",
            1,
            MAX_CONSENSUS_RUN_DURATION_SECONDS_V1,
        )?;
        let max_blocks = parse_bounded_u64(
            arguments.next(),
            "max-blocks",
            MINIMUM_CONSENSUS_RUN_BLOCKS_V1,
            MAX_CONSENSUS_RUN_BLOCKS_V1,
        )?;
        let report_path = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let peer_lease_socket = parse_optional_peer_lease_socket(&mut arguments)?;
        let report_path = validate_consensus_run_report_target_v1(&report_path)?;
        let binary = env::current_exe().context("resolve current executable")?;
        let loaded = LoadedValidatorConfig::load(run_root, config, binary)?;
        let outcome = match peer_lease_socket {
            Some(socket_path) => {
                #[cfg(unix)]
                {
                    // This is the sole CLI opt-in to the Unix external-fence
                    // seam.  The ordinary invocation below remains wired to
                    // the rejecting authority and therefore fail-closed.
                    let client = UnixPeerLeaseClientV1::connect(socket_path)
                        .with_timeout(Duration::from_secs(5));
                    let external_fence =
                        Arc::new(UnixExternalPeerLeaseAuthorityV1::from_client(client));
                    run_bounded_consensus_with_external_fence_v1(
                        loaded,
                        Duration::from_secs(duration_seconds),
                        max_blocks,
                        report_path,
                        external_fence,
                        commission_deployed_ordinary_runtime_for_cli_v1,
                    )?
                }
                #[cfg(not(unix))]
                {
                    let _ = (
                        socket_path,
                        loaded,
                        duration_seconds,
                        max_blocks,
                        report_path,
                    );
                    bail!("peer-lease socket opt-in is supported only on Unix")
                }
            }
            None => run_deployed_bounded_consensus_v1(
                loaded,
                Duration::from_secs(duration_seconds),
                max_blocks,
                report_path,
            )?,
        };
        return match outcome {
            BoundedConsensusRunOutcomeV1::CompletedReport(report_path) => {
                let report = load_signed_consensus_run_report_v1(&report_path)?;
                println!("{}", serde_json::to_string(&report)?);
                Ok(ExitCode::SUCCESS)
            }
            BoundedConsensusRunOutcomeV1::Process1TargetParked(handoff) => {
                println!("{}", serde_json::to_string(&handoff)?);
                Ok(ExitCode::from(PROCESS1_TARGET_PARKED_EXIT_STATUS_V1))
            }
        };
    }
    if command == "verify-external-config" {
        if arguments.next().is_some() {
            bail!(usage());
        }
        // This is the only CLI path that intentionally opens a deployment
        // without any validator role secret.  It is a preflight projection,
        // not a hidden fallback to the fixture signer and not a production
        // activation switch.  A future caller must supply every authority
        // object (including P2P, event/replay, proposal, Vote/Timeout, and
        // fleet producers) to
        // `run_deployed_bounded_consensus_with_external_authority_and_fleet_signer_v1`
        // explicitly; this command merely proves that the public bundle can
        // be authenticated without importing private key material here.
        let binary = env::current_exe().context("resolve current executable")?;
        let loaded = LoadedValidatorConfig::load_external_authority(run_root, config, binary)?;
        ensure!(
            !loaded.has_local_consensus_secret(),
            "external-authority loader unexpectedly retained a local consensus secret"
        );
        ensure!(
            !loaded.has_local_p2p_identity_secret() && !loaded.has_local_operator_recovery_secret(),
            "external-authority loader unexpectedly retained a non-consensus role secret"
        );
        let core = loaded.core_config()?;
        println!(
            "{}",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "status": "external-consensus-authority-config-secret-free",
                "run_id": loaded.run_id(),
                "host_id": loaded.host_id(),
                "validator_id": hex::encode(loaded.local_validator().as_bytes()),
                "validator_count": loaded.validator_set().validators().len(),
                "validator_set_id": hex::encode(loaded.validator_set().id().as_bytes()),
                "validator_set_sha256": hex::encode(loaded.validator_set_sha256()),
                "topology_sha256": hex::encode(loaded.topology_sha256()),
                "config_sha256": hex::encode(loaded.config_sha256()),
                "coordinator_manifest_sha256": hex::encode(loaded.coordinator_manifest_sha256()),
                "binary_sha256": hex::encode(loaded.binary_sha256()),
                "core_max_blocks": core.max_blocks(),
                "consensus_secret_loaded": false,
                "p2p_identity_secret_loaded": loaded.has_local_p2p_identity_secret(),
                "operator_recovery_secret_loaded": loaded.has_local_operator_recovery_secret(),
                "all_local_role_secrets_loaded": loaded.has_local_consensus_secret()
                    || loaded.has_local_p2p_identity_secret()
                    || loaded.has_local_operator_recovery_secret(),
                "external_peer_lease_required": true,
                "external_monotonic_watermark_required": true,
                "external_vote_timeout_producer_required": true,
                "external_proposal_producer_required": true,
                "external_fleet_signer_required": true,
                "complete_composition_api": "run_deployed_bounded_consensus_with_external_authority_and_fleet_signer_v1",
                "production_candidate": PRODUCTION_CANDIDATE,
                "production_consensus_activation": PRODUCTION_CONSENSUS_ACTIVATION,
                "validator_runtime_started": VALIDATOR_RUNTIME_STARTED,
                "g3_evidence_complete": false,
            }))?
        );
        return Ok(ExitCode::SUCCESS);
    }
    let binary = env::current_exe().context("resolve current executable")?;
    let loaded = LoadedValidatorConfig::load(run_root, config, binary)?;
    if command == "attempt-isolated-startup-rejection" {
        let fault_kind = arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| anyhow::anyhow!(usage()))?;
        let fault_kind = IsolatedStartupFaultKindV1::parse(&fault_kind)?;
        let isolated_authority_root =
            PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        let attempt_nonce = parse_canonical_hex32(arguments.next(), "attempt-nonce")?;
        let evidence_path =
            PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        if arguments.next().is_some() {
            bail!(usage());
        }
        let fleet_start = load_local_fleet_start_certificate_for_isolated_rejection_v1(&loaded)?;
        let campaign = fleet_start.ready_set().context().clone();
        let verified = attempt_isolated_startup_rejection_v1(
            &loaded,
            campaign,
            &fleet_start,
            fault_kind,
            &isolated_authority_root,
            attempt_nonce,
        )?;
        let persisted = persist_isolated_startup_rejection_evidence_v1(
            &evidence_path,
            verified,
            &fleet_start,
            loaded.validator_set(),
        )?;
        let verified = persisted.verified();
        let evidence = verified.evidence();
        println!(
            "{}",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "status": "isolated-startup-rejection-authenticated-and-persisted",
                "run_id": loaded.run_id(),
                "validator_id": hex::encode(loaded.local_validator().as_bytes()),
                "target_config_sha256": hex::encode(evidence.target_config_sha256()),
                "fleet_start_certificate_sha256": hex::encode(evidence.fleet_start_certificate_sha256()),
                "fault_kind": evidence.fault_kind().as_str(),
                "changed_file_count": evidence.changed_file_count(),
                "attempt_nonce": hex::encode(evidence.attempt_nonce()),
                "node_error_class": evidence.node_error_class().as_str(),
                "node_error_stage": evidence.node_error_stage(),
                "primary_cut_sha256": hex::encode(evidence.source_primary_cut_digest()),
                "isolated_snapshot_sha256": hex::encode(evidence.isolated_snapshot_content_digest()),
                "isolated_snapshot_inventory_sha256": hex::encode(evidence.isolated_snapshot_inventory_digest()),
                "runtime_journal_sha256": hex::encode(evidence.runtime_journal_sha256()),
                "runtime_journal_bytes": evidence.runtime_journal_bytes(),
                "process_instance": evidence.process_instance(),
                "primary_unchanged": evidence.primary_unchanged(),
                "runtime_journal_unchanged": evidence.runtime_journal_unchanged(),
                "network_started": evidence.network_started(),
                "evidence_sha256": hex::encode(evidence.evidence_sha256()),
                "artifact_sha256": hex::encode(verified.artifact_sha256()),
                "artifact_path": persisted.path().display().to_string(),
                "fault_campaign_observed": false,
                "g3_evidence_complete": false,
                "geo_wan_evidence": false,
                "production_activation": false,
            }))?
        );
        return Ok(ExitCode::SUCCESS);
    }
    if command == "runtime-control" {
        let process_instance =
            parse_canonical_positive_u64(arguments.next(), "process-instance", 1, 2)?;
        let generation = parse_canonical_positive_u64(arguments.next(), "generation", 1, 1_024)?;
        let nonce = parse_canonical_positive_u64(arguments.next(), "nonce", 1, u64::MAX)?;
        let verb = arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| anyhow::anyhow!(usage()))?;
        let fault = arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| anyhow::anyhow!(usage()))?;
        if arguments.next().is_some() {
            bail!(usage());
        }
        let response = send_runtime_control_request_v1(
            &loaded,
            process_instance,
            generation,
            nonce,
            &verb,
            &fault,
        )?;
        println!("{}", serde_json::to_string(&response)?);
        return Ok(ExitCode::SUCCESS);
    }
    if command == "start-runtime-event-journal" {
        let journal_path = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
        if arguments.next().is_some() {
            bail!(usage());
        }
        let journal = RuntimeEventJournalV1::start(&journal_path, &loaded)?;
        println!(
            "{}",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "status": "signed-process-start-durable",
                "run_id": loaded.run_id(),
                "validator_id": hex::encode(loaded.local_validator().as_bytes()),
                "process_instance": journal.process_instance(),
                "next_sequence": journal.next_sequence(),
                "coordinator_manifest_sha256": hex::encode(loaded.coordinator_manifest_sha256()),
                "causal_predecessor": "deployment-manifest-loaded-before-process-start",
                "external_wall_clock_temporal_provenance": false,
                "continuous_consensus_runtime": false,
                "production_activation": false,
            }))?
        );
        return Ok(ExitCode::SUCCESS);
    }
    if command == "network-smoke" {
        let rounds = parse_bounded_u64(arguments.next(), "rounds", 1, 10_000)?;
        let timeout_seconds = parse_bounded_u64(arguments.next(), "timeout-seconds", 1, 300)?;
        if arguments.next().is_some() {
            bail!(usage());
        }
        // The signed process-start is durably appended only after the closed
        // deployment bundle (including its coordinator digest) has been
        // authenticated, and before the first network effect. Retain the
        // journal owner for the complete process lane. This establishes a
        // causal code-path predecessor; it deliberately says nothing about
        // external wall-clock temporal provenance.
        let mut event_journal =
            RuntimeEventJournalV1::start(loaded.run_root().join("runtime-events.jsonl"), &loaded)?;
        let report = run_network_smoke(&loaded, rounds, Duration::from_secs(timeout_seconds))?;
        for peer in &report.report.peer_sessions {
            event_journal.append(
                RuntimeEventKindV1::PeerSessionEstablished,
                &format!(
                    "{}:{}:{}",
                    peer.direction, peer.remote_validator_id, peer.session_id
                ),
                peer.messages_received,
            )?;
        }
        println!("{}", serde_json::to_string(&report)?);
        return Ok(ExitCode::SUCCESS);
    }
    if arguments.next().is_some() {
        bail!(usage());
    }
    if command != "verify-config" {
        bail!("unknown command {command:?}; {}", usage());
    }
    let core = loaded.core_config()?;
    let bootstrap = positive_checkpoint_bootstrap_assessment_v1();
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema_version": 1,
            "status": "bounded-runtime-candidate-config-and-wire-verified",
            "run_id": loaded.run_id(),
            "host_id": loaded.host_id(),
            "validator_id": hex::encode(loaded.local_validator().as_bytes()),
            "validator_count": loaded.validator_set().validators().len(),
            "validator_set_id": hex::encode(loaded.validator_set().id().as_bytes()),
            "validator_set_sha256": hex::encode(loaded.validator_set_sha256()),
            "topology_sha256": hex::encode(loaded.topology_sha256()),
            "config_sha256": hex::encode(loaded.config_sha256()),
            "coordinator_manifest_sha256": hex::encode(loaded.coordinator_manifest_sha256()),
            "candidate_source_sha256": hex::encode(loaded.candidate_source_sha256()),
            "binary_sha256": hex::encode(loaded.binary_sha256()),
            "listen_addr": loaded.listen_addr().to_string(),
            "metrics_addr": loaded.metrics_addr().to_string(),
            "peer_count": loaded.peers().len(),
            "core_max_blocks": core.max_blocks(),
            "network_scope": "single-lan",
            "strict_ed25519": true,
            "real_core_config": REAL_CORE_CONFIG,
            "real_core_runtime": REAL_CORE_RUNTIME,
            "safety_store_runtime": SAFETY_STORE_RUNTIME,
            "signer_journal_runtime": SIGNER_JOURNAL_RUNTIME,
            "native_execution_runtime": NATIVE_EXECUTION_RUNTIME,
            "one_shot_authority_runtime": ONE_SHOT_AUTHORITY_RUNTIME,
            "strict_consensus_ingress": STRICT_CONSENSUS_INGRESS,
            "weighted_vote_qc_collector": WEIGHTED_VOTE_QC_COLLECTOR,
            "timeout_tc_collector": TIMEOUT_TC_COLLECTOR,
            "bounded_consensus_ingress_loop_scaffold": BOUNDED_CONSENSUS_INGRESS_LOOP_SCAFFOLD,
            "signed_process_event_journal": SIGNED_PROCESS_EVENT_JOURNAL,
            "coordinator_anchor_causal_binding": COORDINATOR_ANCHOR_CAUSAL_BINDING,
            "external_wall_clock_temporal_provenance": EXTERNAL_WALL_CLOCK_TEMPORAL_PROVENANCE,
            "continuous_consensus_runtime": CONTINUOUS_CONSENSUS_RUNTIME,
            "positive_checkpoint_bootstrap_ready": bootstrap.ordinary_runtime_ready,
            "authenticated_fresh_session_runtime": AUTHENTICATED_FRESH_SESSION_RUNTIME,
            "authenticated_frame_restart_replay_authority": AUTHENTICATED_FRAME_RESTART_REPLAY_AUTHORITY,
            "simulator_dependency": SIMULATOR_DEPENDENCY,
            "production_candidate": PRODUCTION_CANDIDATE,
            "production_consensus_activation": PRODUCTION_CONSENSUS_ACTIVATION,
            "geo_wan_evidence": GEO_WAN_EVIDENCE,
            "validator_runtime_started": VALIDATOR_RUNTIME_STARTED,
            "g3_evidence_complete": false,
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

fn parse_bounded_u64(
    value: Option<std::ffi::OsString>,
    field: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64> {
    let value = value
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| anyhow::anyhow!("missing {field}; {}", usage()))?;
    let parsed = value
        .parse::<u64>()
        .with_context(|| format!("invalid {field}"))?;
    if parsed < minimum || parsed > maximum {
        bail!("{field} must be in {minimum}..={maximum}");
    }
    Ok(parsed)
}

fn parse_optional_peer_lease_socket<I>(arguments: &mut I) -> Result<Option<PathBuf>>
where
    I: Iterator<Item = std::ffi::OsString>,
{
    let mut socket = None;
    while let Some(argument) = arguments.next() {
        if argument != "--peer-lease-socket" || socket.is_some() {
            bail!(usage());
        }
        let path = PathBuf::from(
            arguments
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing peer-lease socket path; {}", usage()))?,
        );
        ensure!(
            !path.as_os_str().is_empty(),
            "peer-lease socket path must not be empty"
        );
        validate_peer_lease_socket_path_v1(&path)?;
        socket = Some(path);
    }
    Ok(socket)
}

#[cfg(unix)]
fn validate_peer_lease_socket_path_v1(path: &PathBuf) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "peer-lease socket path must be absolute"
    );
    ensure!(
        path.as_os_str().as_bytes().len() <= UNIX_SOCKET_PATH_MAX_BYTES_V1,
        "peer-lease socket path exceeds Unix sun_path limit"
    );
    ensure!(
        path.components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir)),
        "peer-lease socket path contains a traversal component"
    );
    let _ = validate_private_parent_v1(path, "peer-lease socket")?;
    Ok(())
}

#[cfg(not(unix))]
fn validate_peer_lease_socket_path_v1(_path: &PathBuf) -> Result<()> {
    bail!("peer-lease socket opt-in is supported only on Unix")
}

#[cfg(unix)]
fn validate_private_parent_v1(path: &PathBuf, label: &str) -> Result<Metadata> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} path has no parent"))?;
    let metadata = std::fs::symlink_metadata(parent)
        .with_context(|| format!("{label} parent does not exist"))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "{label} parent must be a real directory"
    );
    ensure!(
        metadata.mode() & 0o7777 == 0o700,
        "{label} parent must have private mode 0700"
    );
    Ok(metadata)
}

#[cfg(unix)]
fn validate_peer_lease_data_path_v1(path: &PathBuf, label: &str) -> Result<()> {
    ensure!(path.is_absolute(), "{label} path must be absolute");
    ensure!(
        path.components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir)),
        "{label} path contains a traversal component"
    );
    let _ = validate_private_parent_v1(path, label)?;
    Ok(())
}

#[cfg(not(unix))]
fn validate_peer_lease_data_path_v1(_path: &PathBuf, _label: &str) -> Result<()> {
    bail!("peer-lease daemon is supported only on Unix")
}

#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
struct PeerLeaseDaemonArgsV1 {
    socket: PathBuf,
    journal: PathBuf,
    ready_file: Option<PathBuf>,
}

#[cfg(unix)]
fn parse_peer_lease_daemon_args<I>(arguments: I) -> Result<PeerLeaseDaemonArgsV1>
where
    I: Iterator<Item = std::ffi::OsString>,
{
    let mut socket = None;
    let mut journal = None;
    let mut ready_file = None;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        let value = argument.to_str().ok_or_else(|| anyhow::anyhow!(usage()))?;
        let destination = match value {
            "--socket" => &mut socket,
            "--journal" => &mut journal,
            "--ready-file" => &mut ready_file,
            "--help" | "-h" => bail!(usage()),
            _ => bail!(usage()),
        };
        ensure!(destination.is_none(), "duplicate peer-lease daemon option");
        let path = PathBuf::from(
            arguments
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing value for {value}; {}", usage()))?,
        );
        ensure!(
            !path.as_os_str().is_empty(),
            "peer-lease path must not be empty"
        );
        *destination = Some(path);
    }
    let socket = socket.ok_or_else(|| anyhow::anyhow!(usage()))?;
    let journal = journal.ok_or_else(|| anyhow::anyhow!(usage()))?;
    validate_peer_lease_socket_path_v1(&socket)?;
    validate_peer_lease_data_path_v1(&journal, "peer-lease journal")?;
    ensure!(
        socket != journal,
        "peer-lease socket and journal paths must differ"
    );
    if let Some(ready) = &ready_file {
        ensure!(
            ready != &socket && ready != &journal,
            "peer-lease ready path collides with socket or journal"
        );
        validate_peer_lease_data_path_v1(ready, "peer-lease ready file")?;
    }
    Ok(PeerLeaseDaemonArgsV1 {
        socket,
        journal,
        ready_file,
    })
}

#[cfg(unix)]
fn run_peer_lease_daemon<I>(arguments: I) -> Result<ExitCode>
where
    I: Iterator<Item = std::ffi::OsString>,
{
    let parsed = parse_peer_lease_daemon_args(arguments)?;
    ensure!(
        !parsed.socket.exists() && !parsed.socket.is_symlink(),
        "peer-lease socket path already exists"
    );
    if let Some(ready) = &parsed.ready_file {
        ensure!(
            !ready.exists() && !ready.is_symlink(),
            "peer-lease ready path already exists"
        );
    }
    let daemon = UnixPeerLeaseDaemonV1::new(&parsed.socket, &parsed.journal);
    let (result_sender, result_receiver) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        let result = daemon.run();
        let _ = result_sender.send(result);
    });

    if let Some(ready) = parsed.ready_file {
        loop {
            if parsed.socket.exists() {
                if let Some(parent) = ready.parent() {
                    std::fs::create_dir_all(parent)
                        .context("create peer-lease ready-file parent")?;
                }
                let mut ready_file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&ready)
                    .context("create peer-lease ready file")?;
                ready_file
                    .write_all(b"ready\n")
                    .context("write peer-lease ready file")?;
                ready_file
                    .sync_all()
                    .context("sync peer-lease ready file")?;
                break;
            }
            match result_receiver.try_recv() {
                Ok(result) => {
                    result
                        .map_err(|error| anyhow::anyhow!("peer-lease daemon stopped: {error}"))?;
                    return Ok(ExitCode::SUCCESS);
                }
                Err(TryRecvError::Disconnected) => {
                    bail!("peer-lease daemon thread disconnected before ready")
                }
                Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }

    match thread.join() {
        Ok(()) => {
            let result = result_receiver
                .recv()
                .context("receive peer-lease daemon result")?;
            result.map_err(|error| anyhow::anyhow!("peer-lease daemon stopped: {error}"))?;
            Ok(ExitCode::SUCCESS)
        }
        Err(_) => bail!("peer-lease daemon thread panicked"),
    }
}

#[cfg(not(unix))]
fn run_peer_lease_daemon<I>(_arguments: I) -> Result<ExitCode>
where
    I: Iterator<Item = std::ffi::OsString>,
{
    bail!("peer-lease daemon is supported only on Unix")
}

fn parse_canonical_positive_u64(
    value: Option<std::ffi::OsString>,
    field: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64> {
    let value = value
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| anyhow::anyhow!("missing {field}; {}", usage()))?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("{field} is not canonical unsigned decimal");
    }
    let parsed = value
        .parse::<u64>()
        .with_context(|| format!("invalid {field}"))?;
    if parsed < minimum || parsed > maximum {
        bail!("{field} must be in {minimum}..={maximum}");
    }
    Ok(parsed)
}

fn parse_canonical_hex32(value: Option<std::ffi::OsString>, field: &str) -> Result<[u8; 32]> {
    let value = value
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| anyhow::anyhow!("missing {field}; {}", usage()))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} must be exactly 64 lowercase hexadecimal characters");
    }
    let bytes = hex::decode(&value).with_context(|| format!("invalid {field}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must encode exactly 32 bytes"))
}

fn usage() -> &'static str {
    "usage: trnm-poco-lab-validator peer-lease-daemon --socket PATH --journal PATH [--ready-file PATH] | trnm-poco-lab-validator verify-config <private-run-root> <validator-config> | trnm-poco-lab-validator verify-external-config <private-run-root> <validator-config> | trnm-poco-lab-validator verify-replay-archive <observer-public-root> <validator-config> <absolute-archive-context> <absolute-archive-entries> <absolute-archive-head> <absolute-terminal-seal> <expected-coordinator-manifest-sha256> | trnm-poco-lab-validator verify-network-report <observer-public-root> <validator-config> <signed-report> <expected-coordinator-manifest-sha256> | trnm-poco-lab-validator verify-consensus-report <observer-public-root> <validator-config> <signed-report> <expected-coordinator-manifest-sha256> | trnm-poco-lab-validator verify-runtime-journal <observer-public-root> <validator-config> <signed-journal> <expected-coordinator-manifest-sha256> | trnm-poco-lab-validator verify-runtime-metrics <observer-public-root> <validator-config> <signed-metrics> <expected-coordinator-manifest-sha256> | trnm-poco-lab-validator verify-runtime-final-state <observer-public-root> <validator-config> <signed-final-state> <expected-coordinator-manifest-sha256> | trnm-poco-lab-validator verify-fleet-start-certificate <observer-public-root> <validator-config> <fleet-start-certificate> <expected-coordinator-manifest-sha256> <expected-duration-seconds> <expected-max-blocks> | trnm-poco-lab-validator verify-isolated-startup-rejection <observer-public-root> <validator-config> <signed-rejection> <fleet-start-certificate> <expected-coordinator-manifest-sha256> | trnm-poco-lab-validator network-smoke <private-run-root> <validator-config> <rounds> <timeout-seconds> | trnm-poco-lab-validator run-consensus <private-run-root> <validator-config> <duration-seconds> <max-blocks> <report-path> [--peer-lease-socket PATH] | trnm-poco-lab-validator runtime-control <private-run-root> <validator-config> <process-instance> <generation> <nonce> <verb> <fault> | trnm-poco-lab-validator start-runtime-event-journal <private-run-root> <validator-config> <absolute-journal-path> | trnm-poco-lab-validator attempt-isolated-startup-rejection <private-run-root> <validator-config> <stale_snapshot|rollback_attempt> <absolute-isolated-authority-root> <attempt-nonce-hex> <absolute-evidence-path>"
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    use tempfile::tempdir;

    use super::{parse_optional_peer_lease_socket, usage};

    #[test]
    fn external_config_command_is_explicit_and_keeps_activation_closed() {
        let source = include_str!("main.rs");
        assert!(source.contains("verify-external-config"));
        assert!(source.contains("LoadedValidatorConfig::load_external_authority"));
        assert!(source.contains("\"consensus_secret_loaded\": false"));
        assert!(source.contains("complete_composition_api"));
        assert!(
            source.contains("\"production_consensus_activation\": PRODUCTION_CONSENSUS_ACTIVATION")
        );
    }

    #[test]
    fn peer_lease_cli_seams_are_explicit_and_default_remains_rejecting() {
        let source = include_str!("main.rs");
        let daemon_dispatch = source
            .find("if command == \"peer-lease-daemon\"")
            .expect("daemon dispatch remains present");
        let run_root_parse = source
            .find("let run_root = PathBuf::from")
            .expect("normal command envelope remains present");
        assert!(daemon_dispatch < run_root_parse);
        assert!(source.contains("--peer-lease-socket"));
        assert!(source.contains("UnixPeerLeaseClientV1::connect"));
        assert!(source.contains("run_bounded_consensus_with_external_fence_v1"));
        assert!(source.contains("run_deployed_bounded_consensus_v1("));
        assert!(source.contains("UnixPeerLeaseDaemonV1::new"));
        assert!(source.contains("\"peer-lease-daemon\""));
        assert!(usage().contains("--peer-lease-socket PATH"));
    }

    #[cfg(unix)]
    #[test]
    fn peer_lease_daemon_args_require_private_absolute_noncolliding_paths() {
        let root = tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private temporary root");
        let socket = root.path().join("authority.sock");
        let journal = root.path().join("authority.journal");
        let ready = root.path().join("authority.ready");
        let args = vec![
            OsString::from("--socket"),
            socket.as_os_str().to_owned(),
            OsString::from("--journal"),
            journal.as_os_str().to_owned(),
            OsString::from("--ready-file"),
            ready.as_os_str().to_owned(),
        ];
        let parsed = super::parse_peer_lease_daemon_args(args.into_iter())
            .expect("private daemon paths parse");
        assert_eq!(parsed.socket, socket);
        assert_eq!(parsed.journal, journal);
        assert_eq!(parsed.ready_file, Some(ready));

        let relative = vec![
            OsString::from("--socket"),
            OsString::from("relative.sock"),
            OsString::from("--journal"),
            journal.as_os_str().to_owned(),
        ];
        assert!(super::parse_peer_lease_daemon_args(relative.into_iter()).is_err());

        let collision = vec![
            OsString::from("--socket"),
            socket.as_os_str().to_owned(),
            OsString::from("--journal"),
            socket.as_os_str().to_owned(),
        ];
        assert!(super::parse_peer_lease_daemon_args(collision.into_iter()).is_err());

        let broad_parent = vec![
            OsString::from("--socket"),
            OsString::from("/tmp/authority.sock"),
            OsString::from("--journal"),
            OsString::from("/tmp/authority.journal"),
        ];
        assert!(super::parse_peer_lease_daemon_args(broad_parent.into_iter()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn peer_lease_socket_option_parser_rejects_unknown_or_duplicate_options() {
        let root = tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private temporary root");
        let socket = root.path().join("authority.sock");
        let accepted = vec![
            OsString::from("--peer-lease-socket"),
            socket.as_os_str().to_owned(),
        ];
        assert_eq!(
            parse_optional_peer_lease_socket(&mut accepted.into_iter()).unwrap(),
            Some(socket.clone())
        );

        let duplicate = vec![
            OsString::from("--peer-lease-socket"),
            socket.as_os_str().to_owned(),
            OsString::from("--peer-lease-socket"),
            socket.as_os_str().to_owned(),
        ];
        assert!(parse_optional_peer_lease_socket(&mut duplicate.into_iter()).is_err());

        let unknown = vec![OsString::from("--unexpected")];
        assert!(parse_optional_peer_lease_socket(&mut unknown.into_iter()).is_err());
    }
}
