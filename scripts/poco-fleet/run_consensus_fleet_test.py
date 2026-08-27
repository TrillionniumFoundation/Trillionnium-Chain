#!/usr/bin/env python3
"""Focused contract tests for the G3 continuous-consensus fleet runner."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import types


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "run_consensus_fleet", HERE / "run_consensus_fleet.py"
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load consensus fleet module")
fleet = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fleet
SPEC.loader.exec_module(fleet)


def expect_failure(action, contains: str) -> None:
    try:
        action()
    except SystemExit as error:
        if contains not in str(error):
            raise AssertionError(f"unexpected failure: {error}") from error
    else:
        raise AssertionError("negative control unexpectedly succeeded")


def expect_value_error(action, contains: str) -> None:
    try:
        action()
    except ValueError as error:
        if contains not in str(error):
            raise AssertionError(f"unexpected failure: {error}") from error
    else:
        raise AssertionError("negative control unexpectedly succeeded")


def write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, sort_keys=True).encode("utf-8"))


def read_json(path: pathlib.Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def process(management: str) -> object:
    return fleet.base.ValidatorProcess(
        validator_id="11" * 32,
        host_id="desktop",
        management=management,
        deployment=pathlib.Path("/coordinator/deployments") / ("11" * 32),
        config_relative=pathlib.PurePosixPath("public/configs/local.json"),
        runtime_alias="v000",
    )


def verification() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 2,
        "status": "consensus-run-report-signature-and-semantics-verified",
        "run_id": "poco-g3-7-20260814T000000Z-1234abcd",
        "validator_id": "11" * 32,
        "validator_set_id": "12" * 32,
        "validator_set_sha256": "13" * 32,
        "topology_sha256": "14" * 32,
        "coordinator_manifest_sha256": "15" * 32,
        "candidate_source_sha256": "16" * 32,
        "binary_sha256": "17" * 32,
        "config_sha256": "18" * 32,
        "process_instance": 1,
        "ordinary_start_height": 4,
        "submitted_height": 11,
        "committed_height": 10,
        "finalized_height": 9,
        "submitted_ordinary_block_count": 8,
        "committed_ordinary_block_count": 7,
        "finalized_ordinary_block_count": 6,
        "application_state_root": "19" * 32,
        "safety_revision": 9,
        "application_store_sequence": 10,
        "whole_node_checkpoint_generation": 11,
        "signer_watermark_sequence": 12,
        "safety_halt_count": 0,
        "double_vote_count": 0,
        "double_timeout_count": 0,
        "conflicting_certificate_count": 0,
        "unresolved_obligation_count": 0,
        "clean_stop": True,
        "validator_run_completed": True,
        "continuous_consensus_runtime": True,
        "signature_verified": True,
        "semantics_verified": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    return value


def runtime_verification(kind: str) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 2 if kind == "runtime-metrics" else 3,
        "status": f"{kind}-signature-and-semantics-verified",
        "run_id": "poco-g3-7-20260814T000000Z-1234abcd",
        "validator_id": "11" * 32,
        "process_instance_count": 1,
        "ordinary_start_height": 4,
        "runtime_event_sequence": 9,
        "runtime_event_sha256": "21" * 32,
        "consensus_report_sha256": "22" * 32,
        "body_sha256": "23" * 32,
        "signature_verified": True,
        "semantics_verified": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    if kind == "runtime-metrics":
        value |= {"finality_sample_count": 8, "fsync_count": 9}
    else:
        value |= {
            "finalized_height": 9,
            "finalized_ordinary_block_count": 6,
            "finalized_nonempty_ordinary_block_count": 6,
            "finalized_block_id": "24" * 32,
            "finalized_state_root": "25" * 32,
            "finalized_chain_root": "26" * 32,
            "runtime_metrics_sha256": "27" * 32,
        }
    return value


def journal_verification() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "runtime-journal-signature-and-semantics-verified",
        "run_id": "poco-g3-7-20260814T000000Z-1234abcd",
        "validator_id": "11" * 32,
        "validator_set_sha256": "13" * 32,
        "coordinator_manifest_sha256": "15" * 32,
        "candidate_source_sha256": "16" * 32,
        "binary_sha256": "17" * 32,
        "config_sha256": "18" * 32,
        "barrier_round": 1,
        "fleet_ready_event_sequence": 3,
        "fleet_ready_event_sha256": "41" * 32,
        "fleet_ready_previous_event_sequence": 2,
        "fleet_ready_previous_event_sha256": "40" * 32,
        "fleet_ready_set_sha256": "42" * 32,
        "fleet_start_certificate_sha256": "30" * 32,
        "process_instance_count": 1,
        "event_count": 10,
        "runtime_event_sequence": 9,
        "runtime_event_sha256": "21" * 32,
        "finalized_height": 9,
        "finalized_block_id": "24" * 32,
        "finalized_state_root": "25" * 32,
        "finalized_chain_root": "26" * 32,
        "recovered_fault_count": 0,
        "restart_completed": False,
        "clean_stop": True,
        "signature_verified": True,
        "semantics_verified": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }


def certificate_verification(validator_id: str = "11" * 32) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "fleet-start-certificate-signature-and-semantics-verified",
        "run_id": "poco-g3-7-20260814T000000Z-1234abcd",
        "selected_validator_id": validator_id,
        "validator_count": 7,
        "validator_set_id": "12" * 32,
        "validator_set_sha256": "13" * 32,
        "topology_sha256": "14" * 32,
        "coordinator_manifest_sha256": "15" * 32,
        "candidate_source_sha256": "16" * 32,
        "binary_sha256": "17" * 32,
        "workload_corpus_sha256": "46" * 32,
        "workload_policy_sha256": "47" * 32,
        "ordinary_start_height": 4,
        "duration_seconds": 60,
        "max_blocks": 100,
        "target_height": 103,
        "barrier_round": 1,
        "transport": "direct",
        "relay_hop_budget": 0,
        "context_sha256": "43" * 32,
        "ready_set_sha256": "42" * 32,
        "fleet_start_certificate_digest": "44" * 32,
        "fleet_start_certificate_sha256": "30" * 32,
        "ready_statement_count": 7,
        "start_statement_count": 7,
        "mesh_session_count": 84,
        "selected_pre_ready_journal_sequence": 2,
        "selected_pre_ready_journal_sha256": "40" * 32,
        "selected_fleet_ready_event_sequence": 3,
        "selected_fleet_ready_event_sha256": "41" * 32,
        "initial_current_view": 4,
        "initial_high_qc_height": 3,
        "initial_finalized_height": 1,
        "initial_application_height": 1,
        "initial_proposal_parent_height": 3,
        "maximum_timeout_view_advances": 60,
        "maximum_local_vote_intents": 160,
        "maximum_local_timeout_intents": 60,
        "maximum_total_signer_intents": 220,
        "maximum_signed_replay_archive_entries": 321,
        "relay_admission_capacity": 108,
        "signature_verified": True,
        "semantics_verified": True,
        "exact_session_topology_verified": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }


def replay_archive_verification() -> tuple[
    dict[str, object], dict[str, object], set[str]
]:
    validator_id = "11" * 32
    validator_ids = {validator_id, *(f"{index:064x}" for index in range(1, 7))}
    artifact_facts = {
        "context": types.SimpleNamespace(sha256="51" * 32),
        "entries": types.SimpleNamespace(sha256="52" * 32),
        "head": types.SimpleNamespace(sha256="53" * 32),
        "terminal_seal": types.SimpleNamespace(sha256="54" * 32),
    }
    value: dict[str, object] = {
        "schema_version": 1,
        "status": "validator-signed-terminal-replay-archive-verified",
        "run_id": "poco-g3-7-20260814T000000Z-1234abcd",
        "validator_id": validator_id,
        "fleet_start_certificate_sha256": "30" * 32,
        "clean_stop_journal_sequence": 9,
        "clean_stop_journal_sha256": "21" * 32,
        "finalized_height": 9,
        "finalized_block_id": "24" * 32,
        "finalized_state_root": "25" * 32,
        "finalized_chain_root": "26" * 32,
        "archive_covers_signed_final_tip": True,
        "finality_proof_id": "55" * 32,
        "finality_child_block_id": "56" * 32,
        "finality_grandchild_block_id": "57" * 32,
        "archive_context_sha256": "58" * 32,
        "archive_context_file_sha256": "51" * 32,
        "archive_entries_file_sha256": "52" * 32,
        "archive_head_file_sha256": "53" * 32,
        "terminal_archive_sequence": 10,
        "terminal_archive_record_sha256": "59" * 32,
        "proposal_count": 8,
        "quorum_certificate_count": 2,
        "quorum_certificate_signature_share_count": 6,
        "unique_quorum_certificates": [
            {"certificate_id": "61" * 32, "signature_share_count": 3},
            {"certificate_id": "62" * 32, "signature_share_count": 3},
        ],
        "negative_control_certificate_id": "61" * 32,
        "negative_control_signer_id": validator_id,
        "invalid_signature_control_rejected": True,
        "input_sha256_unchanged": True,
        "observer_verified_nonempty_workload": False,
        "observer_verified_finality": False,
        "validator_run_completed": False,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    return value, artifact_facts, validator_ids


def test_local_and_remote_commands() -> None:
    local_stage = fleet.base.HostStage(
        "desktop", "local", "/tmp/tp3-local", pathlib.Path("/tmp")
    )
    local, report, journal, metrics, final_state, certificate = fleet.command_for(
        process("local"), local_stage, "/bin/v", 60, 100
    )
    assert local[1] == "run-consensus"
    assert local[-3:] == ["60", "100", report]
    assert report.endswith("/consensus-report.json")
    assert journal.endswith("/runtime-events.jsonl")
    assert metrics.endswith("/runtime-metrics.json")
    assert final_state.endswith("/runtime-final-state.json")
    assert certificate.endswith("/fleet-start-certificate.bin")

    local_lease_paths = fleet.peer_lease_paths(local_stage)
    assert local_lease_paths.socket.endswith("/bin/peer-lease.sock")
    assert local_lease_paths.journal.endswith("/bin/peer-lease.journal")
    assert local_lease_paths.ready.endswith("/bin/peer-lease.ready")
    local_daemon = fleet.peer_lease_daemon_command(
        local_stage, "/stage/validator", local_lease_paths
    )
    assert local_daemon[1:] == [
        "peer-lease-daemon",
        "--socket",
        local_lease_paths.socket,
        "--journal",
        local_lease_paths.journal,
        "--ready-file",
        local_lease_paths.ready,
    ]
    local_with_socket, *_ = fleet.command_for(
        process("local"),
        local_stage,
        "/bin/v",
        60,
        100,
        local_lease_paths.socket,
    )
    assert local_with_socket[-2:] == ["--peer-lease-socket", local_lease_paths.socket]

    remote_stage = fleet.base.HostStage(
        "desktop", "p4-desktop", "/tmp/tp3-remote", None
    )
    remote, remote_report, _, _, _, remote_certificate = fleet.command_for(
        process("p4-desktop"), remote_stage, "/stage/validator", 60, 100
    )
    assert remote[:3] == ["ssh", "-o", "BatchMode=yes"]
    assert "trap cleanup EXIT HUP INT TERM" in remote[-1]
    assert "run-consensus" in remote[-1]
    assert remote_report.endswith("/consensus-report.json")
    assert remote_certificate.endswith("/fleet-start-certificate.bin")
    expected_root = fleet.base.validator_stage_root(
        process("p4-desktop"), remote_stage
    )
    assert remote_report == f"{expected_root}/consensus-report.json"
    remote_lease_paths = fleet.peer_lease_paths(remote_stage)
    remote_daemon = fleet.peer_lease_daemon_command(
        remote_stage, "/stage/validator", remote_lease_paths
    )
    assert remote_daemon[:3] == ["ssh", "-o", "BatchMode=yes"]
    assert "peer-lease-daemon" in remote_daemon[-1]
    assert "--ready-file" in remote_daemon[-1]
    assert "trap cleanup EXIT HUP INT TERM" in remote_daemon[-1]
    remote_with_socket, *_ = fleet.command_for(
        process("p4-desktop"),
        remote_stage,
        "/stage/validator",
        60,
        100,
        remote_lease_paths.socket,
    )
    assert "--peer-lease-socket" in remote_with_socket[-1]
    assert remote_lease_paths.socket in remote_with_socket[-1]
    replay_sources = fleet.replay_archive_sources_v1(
        process("p4-desktop"), remote_stage
    )
    assert all(source.startswith(f"{expected_root}/") for source in replay_sources.values())


def test_observer_fleet_certificate_command_and_strict_summary() -> None:
    certificate = certificate_verification()
    observer_stage = fleet.base.HostStage(
        "p4-mac",
        "p4-mac",
        "/tmp/tp3-observer",
        None,
    )
    calls: list[list[str]] = []
    original_run_checked = fleet.base.run_checked
    original_sha256_file = fleet.base.sha256_file

    def fake_run_checked(command, **_kwargs):
        calls.append(command)
        stdout = b""
        if command[0] == "ssh" and "verify-fleet-start-certificate" in command[-1]:
            stdout = json.dumps(certificate, sort_keys=True).encode("utf-8")
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=b"")

    try:
        fleet.base.run_checked = fake_run_checked
        fleet.base.sha256_file = lambda _path: certificate[
            "fleet_start_certificate_sha256"
        ]
        observed = fleet.verify_fleet_start_certificate_on_observer(
            process=process("p4-desktop"),
            certificate_path=pathlib.Path("/coordinator/fleet-start-certificate.bin"),
            mac_binary="/observer/trnm-poco-lab-validator",
            observer_root="/observer/public-root",
            observer_stage=observer_stage,
            coordinator_anchor=certificate["coordinator_manifest_sha256"],
            run_id=certificate["run_id"],
            duration_seconds=60,
            max_blocks=100,
            validator_count=7,
        )
    finally:
        fleet.base.run_checked = original_run_checked
        fleet.base.sha256_file = original_sha256_file

    assert observed == certificate
    assert calls[0][0] == "scp"
    assert calls[1][:4] == ["ssh", "-o", "BatchMode=yes", "p4-mac"]
    assert calls[1][-1].startswith("chmod 600 -- ")
    assert calls[2][:4] == ["ssh", "-o", "BatchMode=yes", "p4-mac"]
    observer_command = calls[2][-1]
    assert "verify-fleet-start-certificate" in observer_command
    assert "/observer/public-root" in observer_command
    assert certificate["selected_validator_id"] in observer_command
    assert observer_command.endswith(" 60 100")


def test_run_bounds() -> None:
    minimum = fleet.validated_run_bounds(1, 3)
    assert minimum == {
        "journal_capacity": 4_096,
        "maximum_timeout_view_advances": 31,
        "maximum_local_vote_intents": 34,
        "maximum_local_timeout_intents": 31,
        "maximum_total_intents": 65,
        "signed_replay_archive_capacity": 8_192,
        "maximum_proposal_archive_entries": 34,
        "maximum_quorum_certificate_archive_entries": 35,
        "maximum_signed_replay_archive_entries": 69,
        "terminal_drain_allowance_seconds": 30,
        "timeout_view_budget_allowance_seconds": 30,
        "commissioning_allowance_seconds": 300,
        "fleet_launch_skew_allowance_seconds": 30,
        "mesh_setup_allowance_seconds": 330,
        "startup_allowance_seconds": 630,
        "process_completion_allowance_seconds": 660,
    }
    typical = fleet.validated_run_bounds(60, 100)
    assert typical["maximum_timeout_view_advances"] == 60
    assert typical["maximum_local_vote_intents"] == 160
    assert typical["maximum_local_timeout_intents"] == 60
    assert typical["maximum_total_intents"] == 220
    assert typical["maximum_signed_replay_archive_entries"] == 321
    assert typical["process_completion_allowance_seconds"] == 660
    capacity_edge = fleet.validated_run_bounds(1, fleet.MAX_BLOCKS)
    assert capacity_edge["maximum_local_vote_intents"] == 159
    assert capacity_edge["maximum_total_intents"] == 190
    assert capacity_edge["maximum_total_intents"] < fleet.MAX_SIGNER_INTENTS

    for duration in (False, 0, fleet.MAX_DURATION_SECONDS + 1):
        expect_failure(
            lambda duration=duration: fleet.validated_run_bounds(duration, 3),
            "duration crosses",
        )
    for max_blocks in (False, 0, 1, 2, fleet.MAX_BLOCKS + 1, 1 << 4096):
        expect_failure(
            lambda max_blocks=max_blocks: fleet.validated_run_bounds(1, max_blocks),
            "max-blocks",
        )
    assert fleet.validated_launch_skew_ns(10, 30_000_000_010) == 30_000_000_000
    for first, last, message in [
        (False, 1, "monotonic interval"),
        (2, 1, "monotonic interval"),
        (0, 30_000_000_001, "launch skew"),
    ]:
        expect_failure(
            lambda first=first, last=last: fleet.validated_launch_skew_ns(first, last),
            message,
        )
    assert fleet.validate_runtime_topology(7, plan_only=False) is True
    assert fleet.validate_runtime_topology(31, plan_only=True) is False
    assert fleet.validate_runtime_topology(100, plan_only=True) is False
    expect_failure(
        lambda: fleet.validate_runtime_topology(31, plan_only=False),
        "direct seven-validator Stage0 profile",
    )
    expect_failure(
        lambda: fleet.validate_runtime_topology(100, plan_only=False),
        "direct seven-validator Stage0 profile",
    )
    assert fleet.runtime_transport_profile(7) == {
        "mode": "direct",
        "peer_degree": 6,
        "relay_hop_budget": 0,
    }
    assert fleet.runtime_transport_profile(31) == {
        "mode": "origin-signed-sparse-relay",
        "peer_degree": 8,
        "relay_hop_budget": 4,
    }
    assert fleet.runtime_transport_profile(100) == {
        "mode": "origin-signed-sparse-relay",
        "peer_degree": 8,
        "relay_hop_budget": 13,
    }
    expect_failure(
        lambda: fleet.validate_runtime_topology(True, plan_only=False),
        "frozen 7/31/100 profiles",
    )
    expect_failure(
        lambda: fleet.validate_runtime_topology(30, plan_only=True),
        "frozen 7/31/100 profiles",
    )


def test_terminal_agreement() -> None:
    def result(marker: int) -> dict[str, object]:
        validator_id = f"{marker:064x}"
        return {
            "validator_id": validator_id,
            "fleet_start_certificate_sha256": "30" * 32,
            "observer_fleet_start_certificate_verification": certificate_verification(
                validator_id
            ),
            "observer_final_state_verification": {
                "finalized_height": 9,
                "finalized_ordinary_block_count": 6,
                "finalized_block_id": "31" * 32,
                "finalized_state_root": "32" * 32,
                "finalized_chain_root": "33" * 32,
            },
        }

    values = [result(index) for index in range(1, 8)]
    assert fleet.exact_terminal_agreement(values, 7) == {
        "finalized_height": 9,
        "finalized_ordinary_block_count": 6,
        "finalized_block_id": "31" * 32,
        "finalized_state_root": "32" * 32,
        "finalized_chain_root": "33" * 32,
        "fleet_start_certificate_sha256": "30" * 32,
        "fleet_start_certificate_digest": "44" * 32,
        "fleet_ready_set_sha256": "42" * 32,
        "fleet_context_sha256": "43" * 32,
    }
    expect_failure(
        lambda: fleet.exact_terminal_agreement(values[:-1], 7),
        "wrong validator count",
    )
    duplicate = [dict(value) for value in values]
    duplicate[-1]["validator_id"] = duplicate[0]["validator_id"]
    expect_failure(
        lambda: fleet.exact_terminal_agreement(duplicate, 7),
        "duplicate validator IDs",
    )
    divergent = [dict(value) for value in values]
    divergent[-1] = {
        **divergent[-1],
        "observer_final_state_verification": {
            **divergent[-1]["observer_final_state_verification"],
            "finalized_state_root": "34" * 32,
        },
    }
    expect_failure(
        lambda: fleet.exact_terminal_agreement(divergent, 7),
        "state-root divergence",
    )
    divergent_certificate = [dict(value) for value in values]
    divergent_certificate[-1]["fleet_start_certificate_sha256"] = "35" * 32
    expect_failure(
        lambda: fleet.exact_terminal_agreement(divergent_certificate, 7),
        "one exact fleet StartCertificate",
    )
    divergent_semantics = [dict(value) for value in values]
    divergent_semantics[-1] = {
        **divergent_semantics[-1],
        "observer_fleet_start_certificate_verification": {
            **divergent_semantics[-1][
                "observer_fleet_start_certificate_verification"
            ],
            "ready_set_sha256": "36" * 32,
        },
    }
    expect_failure(
        lambda: fleet.exact_terminal_agreement(divergent_semantics, 7),
        "certificate semantics diverge",
    )


def test_verification_profile() -> None:
    value = verification()
    accepted = fleet.exact_verified_summary(
        value,
        run_id=value["run_id"],
        validator_id=value["validator_id"],
        coordinator_anchor=value["coordinator_manifest_sha256"],
    )
    assert accepted is value

    unsafe = dict(value)
    unsafe["safety_halt_count"] = 1
    expect_failure(
        lambda: fleet.exact_verified_summary(
            unsafe,
            run_id=value["run_id"],
            validator_id=value["validator_id"],
            coordinator_anchor=value["coordinator_manifest_sha256"],
        ),
        "crosses the accepted profile",
    )

    forged = dict(value)
    forged["signature_verified"] = False
    expect_failure(
        lambda: fleet.exact_verified_summary(
            forged,
            run_id=value["run_id"],
            validator_id=value["validator_id"],
            coordinator_anchor=value["coordinator_manifest_sha256"],
        ),
        "crosses the accepted profile",
    )

    extra = dict(value)
    extra["uncommitted"] = True
    expect_failure(
        lambda: fleet.exact_verified_summary(
            extra,
            run_id=value["run_id"],
            validator_id=value["validator_id"],
            coordinator_anchor=value["coordinator_manifest_sha256"],
        ),
        "keys differ",
    )

    for kind in ("runtime-metrics", "runtime-final-state"):
        runtime = runtime_verification(kind)
        accepted = fleet.exact_runtime_verified_summary(
            runtime,
            kind=kind,
            run_id=runtime["run_id"],
            validator_id=runtime["validator_id"],
        )
        assert accepted is runtime

    unbound = runtime_verification("runtime-final-state")
    unbound["finalized_nonempty_ordinary_block_count"] = 5
    expect_failure(
        lambda: fleet.exact_runtime_verified_summary(
            unbound,
            kind="runtime-final-state",
            run_id=unbound["run_id"],
            validator_id=unbound["validator_id"],
        ),
        "tip/count binding differs",
    )

    certificate = certificate_verification()
    accepted_certificate = fleet.exact_fleet_start_certificate_summary(
        certificate,
        run_id=certificate["run_id"],
        validator_id=certificate["selected_validator_id"],
        coordinator_anchor=certificate["coordinator_manifest_sha256"],
        duration_seconds=60,
        max_blocks=100,
        validator_count=7,
        artifact_sha256=certificate["fleet_start_certificate_sha256"],
    )
    assert accepted_certificate is certificate

    wrong_duration = dict(certificate)
    wrong_duration["duration_seconds"] = 61
    expect_failure(
        lambda: fleet.exact_fleet_start_certificate_summary(
            wrong_duration,
            run_id=certificate["run_id"],
            validator_id=certificate["selected_validator_id"],
            coordinator_anchor=certificate["coordinator_manifest_sha256"],
            duration_seconds=60,
            max_blocks=100,
            validator_count=7,
            artifact_sha256=certificate["fleet_start_certificate_sha256"],
        ),
        "crosses accepted profile",
    )
    wrong_artifact = dict(certificate)
    wrong_artifact["fleet_start_certificate_sha256"] = "55" * 32
    expect_failure(
        lambda: fleet.exact_fleet_start_certificate_summary(
            wrong_artifact,
            run_id=certificate["run_id"],
            validator_id=certificate["selected_validator_id"],
            coordinator_anchor=certificate["coordinator_manifest_sha256"],
            duration_seconds=60,
            max_blocks=100,
            validator_count=7,
            artifact_sha256=certificate["fleet_start_certificate_sha256"],
        ),
        "crosses accepted profile",
    )


def test_journal_replay_and_terminal_chain_contract() -> None:
    journal = journal_verification()
    accepted = fleet.exact_journal_verified_summary(
        journal,
        run_id=journal["run_id"],
        validator_id=journal["validator_id"],
        coordinator_anchor=journal["coordinator_manifest_sha256"],
    )
    assert accepted is journal

    # A properly newline-terminated prefix is still a truncation attack; the
    # Rust verifier emits no success summary, and this synthetic impossible
    # summary also fails the exact sequence/cardinality contract.
    truncated = dict(journal)
    truncated["event_count"] = truncated["runtime_event_sequence"]
    expect_failure(
        lambda: fleet.exact_journal_verified_summary(
            truncated,
            run_id=journal["run_id"],
            validator_id=journal["validator_id"],
            coordinator_anchor=journal["coordinator_manifest_sha256"],
        ),
        "crosses the accepted profile",
    )

    restarted = dict(journal)
    restarted["process_instance_count"] = 2
    restarted["restart_completed"] = True
    expect_failure(
        lambda: fleet.exact_journal_verified_summary(
            restarted,
            run_id=journal["run_id"],
            validator_id=journal["validator_id"],
            coordinator_anchor=journal["coordinator_manifest_sha256"],
        ),
        "crosses the accepted profile",
    )

    faulted = dict(journal)
    faulted["recovered_fault_count"] = 1
    expect_failure(
        lambda: fleet.exact_journal_verified_summary(
            faulted,
            run_id=journal["run_id"],
            validator_id=journal["validator_id"],
            coordinator_anchor=journal["coordinator_manifest_sha256"],
        ),
        "crosses the accepted profile",
    )

    false_restart = dict(journal)
    false_restart["restart_completed"] = True
    expect_failure(
        lambda: fleet.exact_journal_verified_summary(
            false_restart,
            run_id=journal["run_id"],
            validator_id=journal["validator_id"],
            coordinator_anchor=journal["coordinator_manifest_sha256"],
        ),
        "crosses the accepted profile",
    )

    # A reordered, re-signed chain is rejected by Rust state-machine replay;
    # Python must never accept a response which does not attest that replay.
    reordered = dict(journal)
    reordered["semantics_verified"] = False
    expect_failure(
        lambda: fleet.exact_journal_verified_summary(
            reordered,
            run_id=journal["run_id"],
            validator_id=journal["validator_id"],
            coordinator_anchor=journal["coordinator_manifest_sha256"],
        ),
        "crosses the accepted profile",
    )

    report = verification()
    report["application_state_root"] = journal["finalized_state_root"]
    metrics = runtime_verification("runtime-metrics")
    final_state = runtime_verification("runtime-final-state")
    final_state["runtime_metrics_sha256"] = metrics["body_sha256"]
    report_document = {
        "report_sha256": metrics["consensus_report_sha256"],
        "process_instance": report["process_instance"],
        "runtime_event_sequence": journal["runtime_event_sequence"],
        "runtime_event_sha256": journal["runtime_event_sha256"],
        "application_head_block_id": journal["finalized_block_id"],
    }
    assert (
        fleet.exact_process_evidence_chain(
            certificate=certificate_verification(),
            journal=journal,
            report_document=report_document,
            report=report,
            metrics=metrics,
            final_state=final_state,
        )
        is None
    )

    head_mismatch = dict(metrics)
    head_mismatch["runtime_event_sha256"] = "29" * 32
    expect_value_error(
        lambda: fleet.exact_process_evidence_chain(
            certificate=certificate_verification(),
            journal=journal,
            report_document=report_document,
            report=report,
            metrics=head_mismatch,
            final_state=final_state,
        ),
        "journal head differs",
    )

    certificate_mismatch = certificate_verification()
    certificate_mismatch["selected_fleet_ready_event_sha256"] = "59" * 32
    expect_value_error(
        lambda: fleet.exact_process_evidence_chain(
            certificate=certificate_mismatch,
            journal=journal,
            report_document=report_document,
            report=report,
            metrics=metrics,
            final_state=final_state,
        ),
        "does not join the signed runtime journal",
    )


def test_replay_archive_observer_contract() -> None:
    replay, artifact_facts, validator_ids = replay_archive_verification()
    journal = journal_verification()
    certificate = certificate_verification()
    final_state = runtime_verification("runtime-final-state")
    bounds = fleet.validated_run_bounds(60, 100)

    def validate(value: object) -> dict[str, object]:
        return fleet.exact_replay_archive_verified_summary_v1(
            value,
            run_id=replay["run_id"],
            validator_id=replay["validator_id"],
            validator_ids=validator_ids,
            artifact_facts=artifact_facts,
            certificate=certificate,
            journal=journal,
            final_state=final_state,
            run_bounds=bounds,
        )

    assert validate(replay) is replay

    extra = copy.deepcopy(replay)
    extra["fixture_only"] = True
    expect_failure(lambda: validate(extra), "keys must be exactly")

    for field in (
        "archive_context_file_sha256",
        "archive_entries_file_sha256",
        "archive_head_file_sha256",
        "fleet_start_certificate_sha256",
        "clean_stop_journal_sha256",
        "finalized_block_id",
        "finalized_state_root",
        "finalized_chain_root",
    ):
        mismatch = copy.deepcopy(replay)
        mismatch[field] = "ff" * 32
        expect_failure(
            lambda mismatch=mismatch: validate(mismatch),
            "differs from terminal evidence",
        )

    duplicate_qc = copy.deepcopy(replay)
    duplicate_qc["unique_quorum_certificates"][1]["certificate_id"] = (
        duplicate_qc["unique_quorum_certificates"][0]["certificate_id"]
    )
    expect_failure(lambda: validate(duplicate_qc), "unique QC inventory differs")

    wrong_share_total = copy.deepcopy(replay)
    wrong_share_total["quorum_certificate_signature_share_count"] = 5
    expect_failure(
        lambda: validate(wrong_share_total),
        "counts or negative control differ",
    )

    wrong_terminal_sequence = copy.deepcopy(replay)
    wrong_terminal_sequence["terminal_archive_sequence"] = 11
    expect_failure(
        lambda: validate(wrong_terminal_sequence),
        "counts or negative control differ",
    )

    foreign_signer = copy.deepcopy(replay)
    foreign_signer["negative_control_signer_id"] = "ff" * 32
    expect_failure(
        lambda: validate(foreign_signer),
        "counts or negative control differ",
    )

    oversized = copy.deepcopy(replay)
    oversized["proposal_count"] = bounds["maximum_proposal_archive_entries"] + 1
    expect_failure(
        lambda: validate(oversized),
        "counts or negative control differ",
    )

    completion = copy.deepcopy(replay)
    completion["validator_run_completed"] = True
    expect_failure(lambda: validate(completion), "crosses its inert profile")

    export_source = inspect.getsource(fleet.copy_replay_archive_set_v1)
    observer_source = inspect.getsource(fleet.verify_replay_archive_on_observer_v1)
    assert "copy_sealed_stage_artifact_v1" in export_source
    assert "copy_observation_file" not in export_source
    assert "stage_sealed_artifact_on_observer_v1" in observer_source
    assert "scp" not in observer_source
    mac_stage = fleet.base.HostStage(
        "mac",
        "p4-mac",
        "/tmp/tp3-0123456789abcdef0123",
        None,
    )
    assert fleet.observer_sealed_reports_root_v1(mac_stage) == (
        "/private/tmp/tp3-0123456789abcdef0123/reports"
    )
    expect_failure(
        lambda: fleet.observer_sealed_reports_root_v1(
            fleet.base.HostStage("mac", "local", "/tmp/not-frozen", pathlib.Path("/tmp"))
        ),
        "not the frozen remote /tmp stage",
    )


def test_independent_anchor_and_output_boundary() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-runner-anchor-test-") as raw:
        workspace = pathlib.Path(raw)
        coordinator = workspace / "coordinator"
        coordinator.mkdir()
        manifest = coordinator / "manifest.json"
        manifest.write_bytes(b'{"run":"one"}')
        expected = hashlib.sha256(manifest.read_bytes()).hexdigest()
        output = workspace / "must-not-exist"

        expect_failure(
            lambda: fleet.checked_coordinator_anchor(coordinator, "00" * 32),
            "differs from the independent pre-run anchor",
        )
        assert not output.exists()
        expect_failure(
            lambda: fleet.checked_coordinator_anchor(coordinator, expected.upper()),
            "canonical SHA-256",
        )
        assert not output.exists()

        snapshot = fleet.checked_coordinator_anchor(coordinator, expected)
        assert snapshot.sha256 == expected
        manifest.write_bytes(b'{"run":"mutated"}')
        expect_failure(
            lambda: fleet.verify_coordinator_anchor(snapshot),
            "mutated after its independent anchor check",
        )
        assert not output.exists()

        linked = workspace / "linked-coordinator"
        linked.mkdir()
        target = workspace / "manifest-target.json"
        target.write_bytes(b'{"run":"linked"}')
        (linked / "manifest.json").symlink_to(target)
        linked_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        expect_failure(
            lambda: fleet.checked_coordinator_anchor(linked, linked_hash),
            "coordinator manifest",
        )

        original_argv = sys.argv
        original_preflight = fleet.mesh_resources.preflight_mesh_fleet_resources_v1
        preflight_called = False

        def forbidden_preflight(*_args, **_kwargs):
            nonlocal preflight_called
            preflight_called = True
            raise AssertionError("preflight crossed an anchor mismatch")

        try:
            fleet.mesh_resources.preflight_mesh_fleet_resources_v1 = forbidden_preflight
            sys.argv = [
                str(HERE / "run_consensus_fleet.py"),
                str(coordinator),
                str(workspace / "unused-deployments"),
                "--validators",
                "7",
                "--linux-binary",
                str(workspace / "unused-linux"),
                "--macos-binary",
                str(workspace / "unused-macos"),
                "--coordinator-manifest-sha256",
                "00" * 32,
                "--output",
                str(output),
                "--duration-seconds",
                "1",
                "--max-blocks",
                "3",
            ]
            expect_failure(fleet.main, "differs from the independent pre-run anchor")
        finally:
            sys.argv = original_argv
            fleet.mesh_resources.preflight_mesh_fleet_resources_v1 = original_preflight
        assert preflight_called is False
        assert not output.exists()

        required_arguments = [
            sys.executable,
            str(HERE / "run_consensus_fleet.py"),
            str(coordinator),
            str(workspace / "unused-deployments"),
            "--validators",
            "7",
            "--linux-binary",
            str(workspace / "unused-linux"),
            "--macos-binary",
            str(workspace / "unused-macos"),
            "--output",
            str(output),
            "--duration-seconds",
            "1",
            "--max-blocks",
            "3",
        ]
        for mode in ([], ["--plan-only"]):
            completed = subprocess.run(
                required_arguments + mode,
                check=False,
                capture_output=True,
                text=True,
            )
            assert completed.returncode == 2
            assert "--coordinator-manifest-sha256" in completed.stderr
            assert not output.exists()

        input_file = workspace / "validator.bin"
        input_file.write_bytes(b"validator")
        valid_output = workspace / "valid-output"
        assert fleet.validate_output_root(
            valid_output,
            input_paths=(coordinator, input_file),
        ) == valid_output
        assert not valid_output.exists()
        expect_failure(
            lambda: fleet.validate_output_root(
                coordinator / "nested-output",
                input_paths=(coordinator, input_file),
            ),
            "disjoint from every input path",
        )
        expect_failure(
            lambda: fleet.validate_output_root(
                HERE / ".runner-output-overlap-mutant",
                input_paths=(coordinator, input_file),
            ),
            "outside and disjoint from the source tree",
        )
        real_parent = workspace / "real-parent"
        real_parent.mkdir()
        linked_parent = workspace / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        expect_failure(
            lambda: fleet.validate_output_root(
                linked_parent / "output",
                input_paths=(coordinator, input_file),
            ),
            "symbolic-link ancestor",
        )
        existing = workspace / "existing-output"
        existing.mkdir()
        expect_failure(
            lambda: fleet.validate_output_root(
                existing,
                input_paths=(coordinator, input_file),
            ),
            "already exists",
        )

    source = (HERE / "run_consensus_fleet.py").read_text(encoding="utf-8")
    bounds = "run_bounds = validated_run_bounds("
    anchor = "anchor_snapshot = checked_coordinator_anchor("
    topology = "runtime_topology_supported = validate_runtime_topology("
    coordinator_input = "coordinator = base.require_private_directory("
    preflight = "mesh_resources.preflight_mesh_fleet_resources_v1("
    runtime_layout = "stage_plan = base.preflight_runtime_layout("
    output_effect = "output.mkdir("
    deployment_effect = "base.create_stages("
    assert '"--coordinator-manifest-sha256"' in source
    assert source.index(bounds) < source.index(coordinator_input)
    assert source.index(anchor) < source.index(preflight)
    assert source.index(topology) < source.index(coordinator_input)
    assert source.index(runtime_layout) < source.index("if args.plan_only:")
    assert source.index(runtime_layout) < source.index(output_effect)
    assert source.index(runtime_layout) < source.index(deployment_effect)
    assert source.index(anchor) < source.index(output_effect)
    assert source.index(anchor) < source.index(deployment_effect)
    rust_config = (
        HERE.parents[1]
        / "trillionnium/crates/trnm-poco-lab-validator/src/config.rs"
    ).read_text(encoding="utf-8")
    assert fleet.MAX_BLOCKS == 128
    assert "pub(crate) const DEPLOYED_CORE_MAX_BLOCKS_V1: usize = 128;" in rust_config
    rust_runtime = (
        HERE.parents[1]
        / "trillionnium/crates/trnm-poco-lab-validator/src/consensus_runtime.rs"
    ).read_text(encoding="utf-8")
    assert "validate_deployed_lab_core_record_envelope_v0(&core_config)" in rust_runtime
    assert rust_runtime.index(
        "let preflight = ConsensusRuntimePreflightV1::new("
    ) < rust_runtime.index("let owner = thread::Builder::new()")
    node_commissioning = (
        HERE.parents[1]
        / "trillionnium/crates/trnm-poco-node/src/deployed_lab_commissioning.rs"
    ).read_text(encoding="utf-8")
    assert node_commissioning.index(
        "let limits = validate_deployed_lab_core_record_envelope_v0(&core_config)?;"
    ) < node_commissioning.index(
        "let paths = prepare_paths_v0(authority_root.as_ref())?;"
    )


def lifecycle_fixture() -> tuple[str, str, list[dict[str, object]], dict[str, object]]:
    run_id = "poco-g3-7-20260814T000000Z-runnerlife"
    anchor = "ab" * 32
    events: list[dict[str, object]] = []
    for index, kind in enumerate(
        (
            "anchor_checked",
            "contract_loaded",
            "preflight_completed",
            "output_initialized",
            "cleanup_finished",
            "summary_sealed",
        )
    ):
        fleet.record_lifecycle_event(events, kind, monotonic_ns=100 + index)
    document = fleet.runner_lifecycle_document(
        run_id=run_id,
        validator_count=7,
        coordinator_anchor=anchor,
        events=events,
    )
    return run_id, anchor, events, document


def test_runner_lifecycle_contract() -> None:
    run_id, anchor, events, document = lifecycle_fixture()
    assert fleet.validate_runner_lifecycle(
        document,
        run_id=run_id,
        validator_count=7,
        coordinator_anchor=anchor,
    ) is document
    assert "replay_archives_exported" in fleet.RUNNER_LIFECYCLE_KINDS
    assert "replay_archives_observer_verified" in fleet.RUNNER_LIFECYCLE_KINDS
    assert "observer_process_started" not in fleet.RUNNER_LIFECYCLE_KINDS
    assert fleet.RUNNER_LIFECYCLE_KINDS.index(
        "validator_processes_exited"
    ) < fleet.RUNNER_LIFECYCLE_KINDS.index("replay_archives_exported")
    assert fleet.RUNNER_LIFECYCLE_KINDS.index(
        "replay_archives_exported"
    ) < fleet.RUNNER_LIFECYCLE_KINDS.index("replay_archives_observer_verified")
    assert fleet.RUNNER_LIFECYCLE_KINDS.index(
        "replay_archives_observer_verified"
    ) < fleet.RUNNER_LIFECYCLE_KINDS.index("signed_artifacts_sealed")

    reordered = copy.deepcopy(document)
    reordered["events"][1], reordered["events"][2] = (
        reordered["events"][2],
        reordered["events"][1],
    )
    expect_failure(
        lambda: fleet.validate_runner_lifecycle(
            reordered,
            run_id=run_id,
            validator_count=7,
            coordinator_anchor=anchor,
        ),
        "sequence/order/monotonic",
    )
    duplicated = copy.deepcopy(document)
    duplicated["events"][1]["kind"] = "anchor_checked"
    expect_failure(
        lambda: fleet.validate_runner_lifecycle(
            duplicated,
            run_id=run_id,
            validator_count=7,
            coordinator_anchor=anchor,
        ),
        "sequence/order/monotonic",
    )
    nonmonotonic = copy.deepcopy(document)
    nonmonotonic["events"][2]["monotonic_ns"] = nonmonotonic["events"][1][
        "monotonic_ns"
    ]
    expect_failure(
        lambda: fleet.validate_runner_lifecycle(
            nonmonotonic,
            run_id=run_id,
            validator_count=7,
            coordinator_anchor=anchor,
        ),
        "sequence/order/monotonic",
    )
    forged_observer_stage = copy.deepcopy(document)
    forged_observer_stage["events"][2]["kind"] = "observer_process_started"
    expect_failure(
        lambda: fleet.validate_runner_lifecycle(
            forged_observer_stage,
            run_id=run_id,
            validator_count=7,
            coordinator_anchor=anchor,
        ),
        "sequence/order/monotonic",
    )
    forged_observer_fact = copy.deepcopy(document)
    forged_observer_fact["observer_process_started"] = True
    expect_failure(
        lambda: fleet.validate_runner_lifecycle(
            forged_observer_fact,
            run_id=run_id,
            validator_count=7,
            coordinator_anchor=anchor,
        ),
        "non-completion boundary",
    )
    forged_completion = copy.deepcopy(document)
    forged_completion["validator_run_completed"] = True
    expect_failure(
        lambda: fleet.validate_runner_lifecycle(
            forged_completion,
            run_id=run_id,
            validator_count=7,
            coordinator_anchor=anchor,
        ),
        "non-completion boundary",
    )
    expect_failure(
        lambda: fleet.record_lifecycle_event(
            events, "contract_loaded", monotonic_ns=1_000
        ),
        "duplicated",
    )


def build_runner_output_fixture(root: pathlib.Path) -> tuple[str, str]:
    root.mkdir()
    run_id = "poco-g3-7-20260814T000000Z-outputmanifest"
    anchor = "cd" * 32
    validators = [f"{index:064x}" for index in range(1, 8)]
    preflight = {
        "schema_version": 1,
        "profile": "fixture-resource-preflight",
        "capacity_passed": True,
        "validator_run_completed": False,
        "g3_lan_multihost_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    plan = {
        "schema_version": 1,
        "profile": "frozen-v0-continuous-consensus-candidate",
        "evidence_profile": fleet.RUNNER_EVIDENCE_PROFILE,
        "run_id": run_id,
        "validator_count": 7,
        "coordinator_manifest_sha256": anchor,
        "validators": [
            {"validator_id": validator_id} for validator_id in validators
        ],
        "mesh_resource_preflight_required_before_effects": True,
        "mesh_resource_preflight": preflight,
        "requires_post_success_replay_archive_export": True,
        "requires_macos_full_replay_archive_verification": True,
        "validator_run_completed": False,
        "fault_matrix_completed": False,
        "performance_evidence": False,
        "g3_lan_multihost_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    summary = {
        "schema_version": 1,
        "profile": "frozen-v0-continuous-consensus-candidate",
        "run_id": run_id,
        "validator_count": 7,
        "coordinator_manifest_sha256": anchor,
        "all_six_hosts_participated": False,
        "fleet_launch_skew_capacity_authority": False,
        "failure": "fixture failure before validator launch",
        "validator_run_completed": False,
        "fault_matrix_completed": False,
        "performance_evidence": False,
        "g3_lan_multihost_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    write_json(root / "prestart-plan.json", plan)
    write_json(root / "mesh-resource-preflight.json", preflight)
    write_json(root / "consensus-run-summary.json", summary)
    (root / "coordinator-anchor.txt").write_text(f"{anchor}\n", encoding="ascii")
    lifecycle_run_id, lifecycle_anchor, _events, lifecycle = lifecycle_fixture()
    lifecycle["run_id"] = run_id
    lifecycle["coordinator_manifest_sha256"] = anchor
    assert lifecycle_run_id != run_id and lifecycle_anchor != anchor
    write_json(root / "runner-lifecycle.json", lifecycle)
    fleet.write_runner_output_manifest(
        root,
        run_id=run_id,
        validator_count=7,
        coordinator_anchor=anchor,
    )
    return run_id, anchor


def test_runner_output_manifest_contract() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-runner-manifest-test-") as raw:
        workspace = pathlib.Path(raw)
        baseline = workspace / "baseline"
        run_id, anchor = build_runner_output_fixture(baseline)
        document = fleet.validate_runner_output_manifest(
            baseline,
            expected_run_id=run_id,
            expected_validator_count=7,
            expected_coordinator_anchor=anchor,
        )
        assert document["profile"] == fleet.RUNNER_OUTPUT_PROFILE
        assert document["evidence_profile"] == fleet.RUNNER_EVIDENCE_PROFILE
        assert document["validator_run_completed"] is False
        assert all(
            item["path"] != fleet.RUNNER_OUTPUT_MANIFEST
            for item in document["artifacts"]
        )

        def reject(label: str, change, contains: str) -> None:
            root = workspace / label
            shutil.copytree(baseline, root)
            change(root)
            expect_failure(
                lambda: fleet.validate_runner_output_manifest(
                    root,
                    expected_run_id=run_id,
                    expected_validator_count=7,
                    expected_coordinator_anchor=anchor,
                ),
                contains,
            )

        def edit_manifest(root: pathlib.Path, change, *, refresh: bool = False) -> None:
            path = root / fleet.RUNNER_OUTPUT_MANIFEST
            value = read_json(path)
            change(value)
            if refresh:
                value["ordered_artifact_root"] = fleet.ordered_runner_artifact_root(
                    run_id=run_id,
                    validator_count=7,
                    coordinator_anchor=anchor,
                    artifacts=value["artifacts"],
                )
            write_json(path, value)

        reject(
            "manifest-profile-mutation",
            lambda root: edit_manifest(
                root, lambda value: value.__setitem__("profile", "mutated")
            ),
            "non-completion boundary",
        )
        reject(
            "manifest-root-mutation",
            lambda root: edit_manifest(
                root,
                lambda value: value.__setitem__(
                    "ordered_artifact_root", "00" * 32
                ),
            ),
            "ordered artifact root differs",
        )
        reject(
            "manifest-completion-mutation",
            lambda root: edit_manifest(
                root,
                lambda value: value.__setitem__(
                    "validator_run_completed", True
                ),
            ),
            "non-completion boundary",
        )
        reject(
            "artifact-omission",
            lambda root: edit_manifest(
                root,
                lambda value: value["artifacts"].pop(),
                refresh=True,
            ),
            "omits a file or output contains an extra file",
        )
        reject(
            "extra-artifact",
            lambda root: (root / "unowned-extra.txt").write_text(
                "extra", encoding="utf-8"
            ),
            "omits a file or output contains an extra file",
        )
        reject(
            "tampered-artifact",
            lambda root: (root / "prestart-plan.json").write_bytes(b"tampered"),
            "content address differs",
        )
        reject(
            "artifact-order",
            lambda root: edit_manifest(
                root, lambda value: value["artifacts"].reverse()
            ),
            "not canonically ordered",
        )
        def duplicate_artifact(value: dict[str, object]) -> None:
            value["artifacts"].append(copy.deepcopy(value["artifacts"][0]))
            value["artifacts"].sort(
                key=lambda item: (item["role"], item["subject"], item["path"])
            )

        reject(
            "artifact-duplicate",
            lambda root: edit_manifest(root, duplicate_artifact),
            "duplicate role/subject or path",
        )

        def escape_path(value: dict[str, object]) -> None:
            value["artifacts"][0]["path"] = "../escape"
            value["artifacts"].sort(
                key=lambda item: (item["role"], item["subject"], item["path"])
            )

        reject(
            "artifact-path",
            lambda root: edit_manifest(root, escape_path),
            "escapes the runner output root",
        )

        def self_reference(value: dict[str, object]) -> None:
            value["artifacts"].append(
                {
                    "role": "runner_summary",
                    "subject": "",
                    "path": fleet.RUNNER_OUTPUT_MANIFEST,
                    "sha256": "00" * 32,
                    "bytes": 1,
                }
            )
            value["artifacts"].sort(
                key=lambda item: (item["role"], item["subject"], item["path"])
            )

        reject(
            "manifest-self-reference",
            lambda root: edit_manifest(root, self_reference),
            "must not reference itself",
        )

        def replace_with_symlink(root: pathlib.Path) -> None:
            path = root / "prestart-plan.json"
            path.unlink()
            path.symlink_to("consensus-run-summary.json")

        reject(
            "artifact-symlink",
            replace_with_symlink,
            "contains symbolic link",
        )


def main() -> None:
    test_local_and_remote_commands()
    test_observer_fleet_certificate_command_and_strict_summary()
    test_run_bounds()
    test_terminal_agreement()
    test_verification_profile()
    test_journal_replay_and_terminal_chain_contract()
    test_replay_archive_observer_contract()
    test_independent_anchor_and_output_boundary()
    test_runner_lifecycle_contract()
    test_runner_output_manifest_contract()
    print(
        "poco_g3_consensus_fleet_test=passed positives=24 negatives=44 "
        "parallel_process_contract=true signed_journal_required=true "
        "fleet_start_certificate_required=true "
        "signed_report_required=true signed_metrics_required=true "
        "signed_final_state_required=true macos_independent_verifier_required=true "
        "sealed_replay_archive_export_required=true "
        "macos_replay_archive_verifier_required=true "
        "fault_matrix_completed=false performance_evidence=false "
        "g3_complete=false geo_wan=false production_activation=false"
    )


if __name__ == "__main__":
    main()
