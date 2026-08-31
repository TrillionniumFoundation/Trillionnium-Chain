#!/usr/bin/env python3
"""Fixture-only positive wiring check and fail-closed collector controls."""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import types


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_run_bundle  # noqa: E402
import check_run_bundle_test as bundle_fixture  # noqa: E402
import check_run_evidence  # noqa: E402
import collect_no_fault_run_bundle_v1 as collector  # noqa: E402
import evidence_bundle_profiles_v1 as profiles  # noqa: E402


def read(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: pathlib.Path, value: object, *, compact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, separators=(",", ":") if compact else None, sort_keys=not compact),
        encoding="utf-8",
    )


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def one(manifest: dict, role: str, subject: str = "") -> dict:
    return next(
        item
        for item in manifest["artifacts"]
        if item["role"] == role and item["subject"] == subject
    )


def copy_artifact(bundle: pathlib.Path, item: dict, target: pathlib.Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(bundle / item["path"], target)


def verification(status: str, run_id: str, validator_id: str, *, selected: bool = False) -> dict:
    return {
        "schema_version": 1,
        "status": status,
        "run_id": run_id,
        ("selected_validator_id" if selected else "validator_id"): validator_id,
        "signature_verified": True,
        "semantics_verified": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }


def active_prestart_plan(
    root: pathlib.Path,
    topology: dict,
    run_id: str,
    anchor: str,
) -> dict:
    duration_seconds = 600
    max_blocks = 3
    bounds = collector.consensus_runner.validated_run_bounds(
        duration_seconds, max_blocks
    )
    validator_processes = [
        types.SimpleNamespace(
            validator_id=item["validator_id"],
            host_id=item["host_id"],
            management=item["management"],
        )
        for item in topology["validators"]
    ]
    host_ids = {item.host_id for item in validator_processes}
    facts = {
        host_id: {
            "hostname": f"fixture-{host_id}",
            "os": "Linux",
            "arch": "x86_64",
            "epoch": "1787000000",
            "cpu_threads": "128",
            "memory_bytes": str(512 * 1024 * 1024 * 1024),
            "memory_available_bytes": str(400 * 1024 * 1024 * 1024),
            "nofile_soft": "65536",
            "nofile_hard": "65536",
            "nproc_soft": "1048576",
            "nproc_hard": "1048576",
            "threads_max": "1048576",
            "system_threads": "100",
            "file_nr_allocated": "1000",
            "file_nr_max": "1048576",
            "uid_threads": "100",
        }
        for host_id in host_ids
    }
    mesh_preflight = (
        collector.consensus_runner.mesh_resources.evaluate_mesh_fleet_resources_v1(
            validator_processes, 7, facts
        )
    )
    validators = [
        {
            "validator_id": item["validator_id"],
            "host_id": item["host_id"],
            "management": item["management"],
            "deployment": (root / "deployments" / item["validator_id"]).as_posix(),
            "config_relative": f"public/configs/{item['validator_id']}.json",
        }
        for item in topology["validators"]
    ]
    return {
        "schema_version": 1,
        "profile": "frozen-v0-continuous-consensus-candidate",
        "evidence_profile": profiles.NO_FAULT_V1,
        "run_id": run_id,
        "validator_count": 7,
        "linux_validator_host_count": len(host_ids),
        "observer_host_id": "mac",
        "coordinator_manifest_sha256": anchor,
        "duration_seconds": duration_seconds,
        "max_blocks": max_blocks,
        "runtime_topology_supported": True,
        "transport": collector.consensus_runner.runtime_transport_profile(7),
        "signer_lifetime": {
            "journal_capacity": bounds["journal_capacity"],
            "maximum_timeout_view_advances": bounds[
                "maximum_timeout_view_advances"
            ],
            "maximum_local_vote_intents": bounds["maximum_local_vote_intents"],
            "maximum_local_timeout_intents": bounds[
                "maximum_local_timeout_intents"
            ],
            "maximum_total_intents": bounds["maximum_total_intents"],
        },
        "signed_replay_archive_lifetime": {
            "archive_capacity": bounds["signed_replay_archive_capacity"],
            "maximum_proposal_entries": bounds[
                "maximum_proposal_archive_entries"
            ],
            "maximum_quorum_certificate_entries": bounds[
                "maximum_quorum_certificate_archive_entries"
            ],
            "maximum_total_entries": bounds[
                "maximum_signed_replay_archive_entries"
            ],
        },
        "commissioning_allowance_seconds": bounds[
            "commissioning_allowance_seconds"
        ],
        "fleet_launch_skew_allowance_seconds": bounds[
            "fleet_launch_skew_allowance_seconds"
        ],
        "fleet_launch_skew_capacity_authority": False,
        "mesh_setup_allowance_seconds": bounds["mesh_setup_allowance_seconds"],
        "startup_allowance_seconds": bounds["startup_allowance_seconds"],
        "terminal_drain_allowance_seconds": bounds[
            "terminal_drain_allowance_seconds"
        ],
        "timeout_view_budget_allowance_seconds": bounds[
            "timeout_view_budget_allowance_seconds"
        ],
        "process_completion_allowance_seconds": bounds[
            "process_completion_allowance_seconds"
        ],
        "validators": validators,
        "requires_signed_terminal_evidence_chain_per_validator": True,
        "requires_macos_independent_verification": True,
        "requires_macos_full_fleet_certificate_verification": True,
        "requires_macos_full_runtime_journal_replay": True,
        "requires_post_success_replay_archive_export": True,
        "requires_macos_full_replay_archive_verification": True,
        "mesh_resource_preflight_required_before_effects": True,
        "mesh_resource_preflight": mesh_preflight,
        "validator_run_completed": False,
        "fault_matrix_completed": False,
        "performance_evidence": False,
        "g3_lan_multihost_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }


def prepare(root: pathlib.Path) -> None:
    fixture = root / "source-fixture"
    original_signed_event = bundle_fixture.signed_test.signed_event

    def signed_event_with_active_bounds(context, *args, **kwargs):
        context["requested_max_blocks"] = 3
        return original_signed_event(context, *args, **kwargs)

    bundle_fixture.signed_test.signed_event = signed_event_with_active_bounds
    try:
        bundle_fixture.build(fixture, 7)
    finally:
        bundle_fixture.signed_test.signed_event = original_signed_event
    manifest = read(fixture / "manifest.json")
    summary = read(fixture / manifest["completed_run_summary"]["path"])
    run_id = summary["run_id"]

    coordinator = root / "coordinator"
    coordinator.mkdir(mode=0o700)
    copy_artifact(fixture, one(manifest, "coordinator_manifest"), coordinator / "manifest.json")
    for role, relative in profiles.COORDINATOR_PUBLIC_SINGLETON_PATHS.items():
        copy_artifact(
            fixture,
            one(manifest, role),
            coordinator.joinpath(*pathlib.PurePosixPath(relative).parts),
        )
    copy_artifact(
        fixture,
        one(manifest, "observer_config", "mac"),
        coordinator / "public/observer-configs/mac.json",
    )
    for validator in summary["validators"]:
        validator_id = validator["validator_id"]
        copy_artifact(
            fixture,
            one(manifest, "validator_config", validator_id),
            coordinator / f"public/configs/{validator_id}.json",
        )

    supplies = root / "supplies"
    supplies.mkdir(mode=0o700)
    supply_roles = {
        "candidate_source": "source.artifact",
        "linux_binary": "linux.bin",
        "macos_binary": "macos.bin",
        "material_builder_binary": "material-builder.bin",
        "build_report": "build-report.json",
    }
    for role, name in supply_roles.items():
        copy_artifact(fixture, one(manifest, role), supplies / name)
    copy_artifact(
        fixture,
        one(manifest, "observer_report", "mac"),
        root / "mac-observer-report.json",
    )

    runner = root / "runner"
    runner.mkdir(mode=0o700)
    layouts = {
        "validator_consensus_run_report": ("signed-reports", ".json"),
        "validator_runtime_event_journal": ("signed-runtime-journals", ".jsonl"),
        "validator_fleet_start_certificate": ("fleet-start-certificates", ".bin"),
        "validator_runtime_metrics": ("signed-runtime-metrics", ".json"),
        "validator_runtime_final_state": ("signed-runtime-final-states", ".json"),
        "validator_replay_archive_context": (
            "signed-replay-archive-contexts",
            ".json",
        ),
        "validator_replay_archive_entries": (
            "signed-replay-archive-entries",
            ".jsonl",
        ),
        "validator_replay_archive_head": (
            "signed-replay-archive-heads",
            ".json",
        ),
        "validator_replay_archive_terminal_seal": (
            "signed-replay-archive-terminal-seals",
            ".json",
        ),
    }
    for validator in summary["validators"]:
        validator_id = validator["validator_id"]
        for role, (directory, suffix) in layouts.items():
            target = runner / directory / f"{validator_id}{suffix}"
            if role.startswith("validator_replay_archive_"):
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(
                    json.dumps(
                        {"role": role, "validator_id": validator_id},
                        sort_keys=True,
                    ).encode("utf-8")
                    + (b"\n" if suffix == ".jsonl" else b"")
                )
                continue
            copy_artifact(
                fixture,
                one(manifest, role, validator_id),
                target,
            )
        process_io = runner / "process-io"
        process_io.mkdir(exist_ok=True)
        (process_io / f"{validator_id}.stdout").write_bytes(b"")
        (process_io / f"{validator_id}.stderr").write_bytes(b"")
    anchor = digest(coordinator / "manifest.json")
    (runner / "coordinator-anchor.txt").write_text(f"{anchor}\n", encoding="ascii")
    topology = read(coordinator / "topology.json")
    prestart_plan = active_prestart_plan(root, topology, run_id, anchor)
    write(
        runner / "prestart-plan.json",
        prestart_plan,
    )
    write(
        runner / "mesh-resource-preflight.json",
        prestart_plan["mesh_resource_preflight"],
    )
    write(
        runner / "fleet-launch-observation.json",
        {
            "schema_version": 1,
            "validator_count": 7,
            "allowance_seconds": collector.consensus_runner.FLEET_LAUNCH_SKEW_ALLOWANCE_SECONDS,
            "observed_launch_skew_ns": 1,
            "within_allowance": True,
        },
    )

    processes = []
    for validator in summary["validators"]:
        validator_id = validator["validator_id"]
        final_state_document = read(
            runner / f"signed-runtime-final-states/{validator_id}.json"
        )
        certificate_sha256 = digest(
            runner / f"fleet-start-certificates/{validator_id}.bin"
        )
        journal_verification = verification(
            "runtime-journal-signature-and-semantics-verified",
            run_id,
            validator_id,
        )
        journal_verification.update(
            {
                "runtime_event_sequence": 9,
                "runtime_event_sha256": "21" * 32,
                "finalized_height": final_state_document["finalized_height"],
                "finalized_block_id": final_state_document["finalized_block_id"],
                "finalized_state_root": final_state_document["finalized_state_root"],
                "finalized_chain_root": final_state_document["finalized_chain_root"],
            }
        )
        certificate_verification = verification(
            "fleet-start-certificate-signature-and-semantics-verified",
            run_id,
            validator_id,
            selected=True,
        )
        certificate_verification["fleet_start_certificate_sha256"] = (
            certificate_sha256
        )
        final_state_verification = verification(
            "runtime-final-state-signature-and-semantics-verified",
            run_id,
            validator_id,
        )
        final_state_verification.update(
            {
                "finalized_height": final_state_document["finalized_height"],
                "finalized_block_id": final_state_document["finalized_block_id"],
                "finalized_state_root": final_state_document["finalized_state_root"],
                "finalized_chain_root": final_state_document["finalized_chain_root"],
            }
        )
        replay_hashes = {
            "context": digest(
                runner / f"signed-replay-archive-contexts/{validator_id}.json"
            ),
            "entries": digest(
                runner / f"signed-replay-archive-entries/{validator_id}.jsonl"
            ),
            "head": digest(
                runner / f"signed-replay-archive-heads/{validator_id}.json"
            ),
            "terminal_seal": digest(
                runner
                / f"signed-replay-archive-terminal-seals/{validator_id}.json"
            ),
        }
        replay_verification = {
            "schema_version": 1,
            "status": "validator-signed-terminal-replay-archive-verified",
            "run_id": run_id,
            "validator_id": validator_id,
            "fleet_start_certificate_sha256": certificate_sha256,
            "clean_stop_journal_sequence": 9,
            "clean_stop_journal_sha256": "21" * 32,
            "finalized_height": final_state_document["finalized_height"],
            "finalized_block_id": final_state_document["finalized_block_id"],
            "finalized_state_root": final_state_document["finalized_state_root"],
            "finalized_chain_root": final_state_document["finalized_chain_root"],
            "archive_covers_signed_final_tip": True,
            "finality_proof_id": "54" * 32,
            "finality_child_block_id": "55" * 32,
            "finality_grandchild_block_id": "56" * 32,
            "archive_context_sha256": "57" * 32,
            "archive_context_file_sha256": replay_hashes["context"],
            "archive_entries_file_sha256": replay_hashes["entries"],
            "archive_head_file_sha256": replay_hashes["head"],
            "terminal_archive_sequence": 10,
            "terminal_archive_record_sha256": "58" * 32,
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
        processes.append(
            {
                "validator_id": validator_id,
                "host_id": validator["host_id"],
                "signed_report_sha256": digest(
                    runner / f"signed-reports/{validator_id}.json"
                ),
                "signed_runtime_journal_sha256": digest(
                    runner / f"signed-runtime-journals/{validator_id}.jsonl"
                ),
                "fleet_start_certificate_sha256": certificate_sha256,
                "signed_runtime_metrics_sha256": digest(
                    runner / f"signed-runtime-metrics/{validator_id}.json"
                ),
                "signed_runtime_final_state_sha256": digest(
                    runner / f"signed-runtime-final-states/{validator_id}.json"
                ),
                "replay_archive_context_sha256": replay_hashes["context"],
                "replay_archive_entries_sha256": replay_hashes["entries"],
                "replay_archive_head_sha256": replay_hashes["head"],
                "replay_archive_terminal_seal_sha256": replay_hashes[
                    "terminal_seal"
                ],
                "observer_journal_verification": journal_verification,
                "observer_fleet_start_certificate_verification": (
                    certificate_verification
                ),
                "observer_report_verification": verification(
                    "consensus-run-report-signature-and-semantics-verified",
                    run_id,
                    validator_id,
                ),
                "observer_metrics_verification": verification(
                    "runtime-metrics-signature-and-semantics-verified",
                    run_id,
                    validator_id,
                ),
                "observer_final_state_verification": final_state_verification,
                "observer_replay_archive_verification": replay_verification,
            }
        )
    first = summary["validators"][0]["validator_id"]
    final_state = read(runner / f"signed-runtime-final-states/{first}.json")
    terminal = {
        "finalized_height": final_state["finalized_height"],
        "finalized_ordinary_block_count": final_state[
            "finalized_ordinary_block_count"
        ],
        "finalized_block_id": final_state["finalized_block_id"],
        "finalized_state_root": final_state["finalized_state_root"],
        "finalized_chain_root": final_state["finalized_chain_root"],
        "fleet_start_certificate_sha256": processes[0][
            "fleet_start_certificate_sha256"
        ],
    }
    count_fields = {
        "signed_report_count": 7,
        "signed_runtime_journal_count": 7,
        "fleet_start_certificate_count": 7,
        "signed_runtime_metrics_count": 7,
        "signed_runtime_final_state_count": 7,
        "observer_verified_report_count": 7,
        "observer_verified_journal_count": 7,
        "observer_verified_fleet_start_certificate_count": 7,
        "observer_verified_metrics_count": 7,
        "observer_verified_final_state_count": 7,
        "signed_replay_archive_set_count": 7,
        "observer_verified_replay_archive_count": 7,
    }
    write(
        runner / "consensus-run-summary.json",
        {
            "schema_version": 1,
            "profile": "frozen-v0-continuous-consensus-candidate",
            "run_id": run_id,
            "validator_count": 7,
            "transport": collector.consensus_runner.runtime_transport_profile(7),
            **count_fields,
            "all_six_hosts_participated": False,
            "elapsed_monotonic_ns": 1,
            "observed_fleet_launch_skew_ns": 1,
            "fleet_launch_skew_within_allowance": True,
            "fleet_launch_skew_capacity_authority": False,
            "coordinator_manifest_sha256": anchor,
            "processes": processes,
            "terminal_agreement": terminal,
            "failure": None,
            "cleanup_failures": [],
            "validator_run_completed": False,
            "fault_matrix_completed": False,
            "performance_evidence": False,
            "g3_lan_multihost_evidence": False,
            "geo_wan_evidence": False,
            "production_activation": False,
        },
    )
    lifecycle_events: list[dict[str, object]] = []
    for index, kind in enumerate(
        collector.consensus_runner.RUNNER_LIFECYCLE_KINDS
    ):
        collector.consensus_runner.record_lifecycle_event(
            lifecycle_events,
            kind,
            monotonic_ns=1_000 + index,
        )
    lifecycle = collector.consensus_runner.runner_lifecycle_document(
        run_id=run_id,
        validator_count=7,
        coordinator_anchor=anchor,
        events=lifecycle_events,
    )
    write(runner / "runner-lifecycle.json", lifecycle)
    collector.consensus_runner.write_runner_output_manifest(
        runner,
        run_id=run_id,
        validator_count=7,
        coordinator_anchor=anchor,
    )


def arguments(root: pathlib.Path, label: str) -> dict:
    return {
        "coordinator_root": root / "coordinator",
        "runner_output": root / "runner",
        "validator_count": 7,
        "coordinator_manifest_sha256": digest(root / "coordinator/manifest.json"),
        "candidate_source": root / "supplies/source.artifact",
        "linux_binary": root / "supplies/linux.bin",
        "macos_binary": root / "supplies/macos.bin",
        "material_builder_binary": root / "supplies/material-builder.bin",
        "build_report": root / "supplies/build-report.json",
        "observer_report": root / "mac-observer-report.json",
        "collector_output": root / f"collector-{label}",
        "bundle_output": root / f"bundle-{label}",
        "fixture_test_only": collector._FIXTURE_TEST_ONLY_CAPABILITY,
    }


def reject(
    base: pathlib.Path,
    label: str,
    change,
    expected: str,
    *,
    adjust_arguments=None,
) -> None:
    root = base.parent / f"case-{label}"
    shutil.copytree(base, root)
    change(root)
    selected_arguments = arguments(root, label)
    if adjust_arguments is not None:
        adjust_arguments(selected_arguments)
    try:
        collector.collect(**selected_arguments)
    except SystemExit as error:
        if expected not in str(error):
            raise AssertionError(
                f"collector mutant {label!r} expected {expected!r}, observed {error!s}"
            ) from error
    else:
        raise AssertionError(f"collector mutant unexpectedly passed: {label}")
    if selected_arguments["collector_output"].exists():
        raise AssertionError(f"failed collector left derived output for {label}")
    if selected_arguments["bundle_output"].exists():
        raise AssertionError(f"failed collector left bundle output for {label}")


def edit_observer(root: pathlib.Path, field: str, value: object) -> None:
    path = root / "mac-observer-report.json"
    report = read(path)
    report[field] = value
    write(path, report)


def downgrade_build_report(root: pathlib.Path) -> None:
    path = root / "supplies/build-report.json"
    report = read(path)
    report["schema_version"] = 2
    for field in check_run_evidence.SOURCE_PROVENANCE_KEYS:
        report.pop(field)
    write(path, report)


def dirty_build_report_status(root: pathlib.Path) -> None:
    path = root / "supplies/build-report.json"
    report = read(path)
    report["source_git_status_sha256"] = hashlib.sha256(b"dirty").hexdigest()
    write(path, report)


def tamper_signature(root: pathlib.Path) -> None:
    summary_path = root / "runner/consensus-run-summary.json"
    runner_summary = read(summary_path)
    process = runner_summary["processes"][0]
    validator_id = process["validator_id"]
    report_path = root / f"runner/signed-reports/{validator_id}.json"
    report = read(report_path)
    report["signature"] = (
        ("00" if report["signature"][:2] != "00" else "01")
        + report["signature"][2:]
    )
    write(report_path, report, compact=True)
    process["signed_report_sha256"] = digest(report_path)
    write(summary_path, runner_summary)
    (root / "runner/runner-output-manifest.json").unlink()
    collector.consensus_runner.write_runner_output_manifest(
        root / "runner",
        run_id=runner_summary["run_id"],
        validator_count=runner_summary["validator_count"],
        coordinator_anchor=runner_summary["coordinator_manifest_sha256"],
    )


def remove_signature_fact(root: pathlib.Path) -> None:
    path = root / "runner/consensus-run-summary.json"
    summary = read(path)
    summary["processes"][0]["observer_report_verification"][
        "signature_verified"
    ] = False
    write(path, summary)


def set_plan_max_blocks(root: pathlib.Path, value: int) -> None:
    path = root / "runner/prestart-plan.json"
    plan = read(path)
    plan["max_blocks"] = value
    write(path, plan)


def add_plan_field(root: pathlib.Path) -> None:
    path = root / "runner/prestart-plan.json"
    plan = read(path)
    plan["fixture_only"] = True
    write(path, plan)


def set_plan_field(root: pathlib.Path, field: str, value: object) -> None:
    path = root / "runner/prestart-plan.json"
    plan = read(path)
    plan[field] = value
    write(path, plan)


def set_first_replay_verification_field(
    root: pathlib.Path, field: str, value: object
) -> None:
    path = root / "runner/consensus-run-summary.json"
    summary = read(path)
    summary["processes"][0]["observer_replay_archive_verification"][field] = value
    write(path, summary)


def expect_production_plan_only(base: pathlib.Path) -> None:
    active_arguments = arguments(base, "production-blocked")
    active_arguments.pop("fixture_test_only")
    try:
        collector.collect(**active_arguments)
    except SystemExit as error:
        if "active collection is unavailable" not in str(error):
            raise AssertionError(f"unexpected active-mode rejection: {error}") from error
    else:
        raise AssertionError("production collect unexpectedly assembled a bundle")
    if active_arguments["collector_output"].exists() or active_arguments[
        "bundle_output"
    ].exists():
        raise AssertionError("production collect created output before failing closed")

    planned_arguments = arguments(base, "production-plan")
    planned_arguments.pop("fixture_test_only")
    planned_arguments["observer_report"] = base / "not-produced-observer-report.json"
    plan = collector.plan_only(**planned_arguments)
    if (
        plan["mode"] != "plan-only"
        or plan["active_campaign_supported"] is not False
        or plan["outputs_created"] is not False
        or len(plan["blockers"]) != 2
        or plan["g3_complete"] is not False
    ):
        raise AssertionError("production plan-only result crossed its blocker boundary")
    if planned_arguments["collector_output"].exists() or planned_arguments[
        "bundle_output"
    ].exists():
        raise AssertionError("plan-only validation created an output root")

    for selected_profile, blocker_count in (
        (profiles.NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1, 2),
        (profiles.NO_FAULT_SIGNED_RUNTIME_EXTERNAL_LOAD_V1, 3),
    ):
        profile_arguments = arguments(base, selected_profile)
        profile_arguments.pop("fixture_test_only")
        profile_arguments["observer_report"] = (
            base / f"not-produced-{selected_profile}.json"
        )
        plan = collector.plan_only(
            profile=selected_profile, **profile_arguments
        )
        if (
            plan["profile"] != selected_profile
            or plan["active_campaign_supported"] is not False
            or len(plan["blockers"]) != blocker_count
            or plan["outputs_created"] is not False
        ):
            raise AssertionError(f"{selected_profile} crossed its plan-only boundary")
        active_profile_arguments = arguments(base, f"active-{selected_profile}")
        active_profile_arguments["profile"] = selected_profile
        try:
            collector.collect(**active_profile_arguments)
        except SystemExit as error:
            if selected_profile not in str(error) or "plan-only" not in str(error):
                raise AssertionError(
                    f"unexpected {selected_profile} active rejection: {error}"
                ) from error
        else:
            raise AssertionError(f"{selected_profile} fixture collection unexpectedly ran")
        if active_profile_arguments["collector_output"].exists() or active_profile_arguments[
            "bundle_output"
        ].exists():
            raise AssertionError(f"{selected_profile} created output before rejection")

    cli_collector = base / "collector-cli-default-plan"
    cli_bundle = base / "bundle-cli-default-plan"
    completed = subprocess.run(
        [
            sys.executable,
            str(HERE / "collect_no_fault_run_bundle_v1.py"),
            str(base / "coordinator"),
            str(base / "runner"),
            "--validators",
            "7",
            "--coordinator-manifest-sha256",
            digest(base / "coordinator/manifest.json"),
            "--candidate-source",
            str(base / "supplies/source.artifact"),
            "--linux-binary",
            str(base / "supplies/linux.bin"),
            "--macos-binary",
            str(base / "supplies/macos.bin"),
            "--material-builder-binary",
            str(base / "supplies/material-builder.bin"),
            "--build-report",
            str(base / "supplies/build-report.json"),
            "--observer-report",
            str(base / "not-produced-observer-report.json"),
            "--collector-output",
            str(cli_collector),
            "--bundle-output",
            str(cli_bundle),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 or "=plan-only" not in completed.stdout:
        raise AssertionError(
            "CLI default did not remain plan-only: "
            f"rc={completed.returncode} stdout={completed.stdout!r} "
            f"stderr={completed.stderr!r}"
        )
    if cli_collector.exists() or cli_bundle.exists():
        raise AssertionError("CLI default plan-only mode created output")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-no-fault-collector-test-") as raw:
        workspace = pathlib.Path(raw)
        base = workspace / "base"
        base.mkdir()
        prepare(base)

        expect_production_plan_only(base)
        reject(
            base,
            "independent-anchor",
            lambda _root: None,
            "differs from the independent pre-run anchor",
            adjust_arguments=lambda value: value.update(
                coordinator_manifest_sha256="ff" * 32
            ),
        )
        reject(
            base,
            "anchor-shape",
            lambda _root: None,
            "must be canonical lowercase SHA-256",
            adjust_arguments=lambda value: value.update(
                coordinator_manifest_sha256="FF" * 32
            ),
        )
        reject(
            base,
            "legacy-build-report-schema2",
            downgrade_build_report,
            "aggregate build report keys must be exactly",
        )
        reject(
            base,
            "dirty-build-report-status",
            dirty_build_report_status,
            "must bind an empty Git status",
        )
        reject(
            base,
            "max-blocks-two",
            lambda root: set_plan_max_blocks(root, 2),
            "max-blocks cannot produce one ordinary three-chain finality",
        )
        reject(
            base,
            "prestart-extra-field",
            add_plan_field,
            "runner prestart plan keys must be exactly",
        )
        reject(
            base,
            "prestart-replay-export-disabled",
            lambda root: set_plan_field(
                root, "requires_post_success_replay_archive_export", False
            ),
            "runner prestart plan differs from the exact active runner contract",
        )
        reject(
            base,
            "prestart-replay-observer-disabled",
            lambda root: set_plan_field(
                root, "requires_macos_full_replay_archive_verification", False
            ),
            "runner prestart plan differs from the exact active runner contract",
        )
        reject(
            base,
            "missing-bootstrap-public-file",
            lambda root: (
                root / "coordinator/public/bootstrap/bootstrap.json"
            ).unlink(),
            "cannot resolve coordinator public file public/bootstrap/bootstrap.json",
        )
        reject(
            base,
            "output-symlink-ancestor",
            lambda root: (root / "output-link").symlink_to(
                collector.assembler.SOURCE_ROOT, target_is_directory=True
            ),
            "must not traverse a symbolic-link ancestor",
            adjust_arguments=lambda value: value.update(
                collector_output=value["coordinator_root"].parent
                / "output-link"
                / "collector-symlink-boundary"
            ),
        )
        reject(
            base,
            "output-input-overlap",
            lambda _root: None,
            "must remain disjoint from every input root",
            adjust_arguments=lambda value: value.update(
                collector_output=value["runner_output"] / "derived-output"
            ),
        )

        reject(
            base,
            "missing-pid",
            lambda root: edit_observer(root, "process_id", 0),
            "process_id must be a positive integer",
        )
        reject(
            base,
            "external-window",
            lambda root: edit_observer(
                root, "ended_at", read(root / "mac-observer-report.json")["started_at"]
            ),
            "external time window is empty",
        )
        reject(
            base,
            "qc-cardinality",
            lambda root: edit_observer(root, "verified_qc_signatures", 6),
            "verified fewer QC signatures than validators",
        )
        reject(
            base,
            "invalid-control",
            lambda root: edit_observer(
                root, "rejected_invalid_signature_controls", 0
            ),
            "rejected_invalid_signature_controls must be a positive integer",
        )
        reject(
            base,
            "empty-workload",
            lambda root: edit_observer(
                root, "load_submitted_nonempty_blocks", 0
            ),
            "load_submitted_nonempty_blocks must be a positive integer",
        )
        reject(
            base,
            "missing-mac-signature-fact",
            remove_signature_fact,
            "not a successful, non-production macOS verification",
        )
        reject(
            base,
            "invalid-validator-signature",
            tamper_signature,
            "Ed25519 signature is invalid",
        )
        reject(
            base,
            "missing-signed-artifact",
            lambda root: next(
                (root / "runner/signed-runtime-metrics").iterdir()
            ).unlink(),
            "must contain exactly one artifact per validator",
        )
        reject(
            base,
            "missing-replay-artifact",
            lambda root: next(
                (root / "runner/signed-replay-archive-heads").iterdir()
            ).unlink(),
            "must contain exactly one artifact per validator",
        )
        reject(
            base,
            "replay-hash-mismatch",
            lambda root: set_first_replay_verification_field(
                root, "archive_entries_file_sha256", "ff" * 32
            ),
            "observer replay archive verification differs from terminal evidence",
        )
        reject(
            base,
            "replay-completion-claim",
            lambda root: set_first_replay_verification_field(
                root, "validator_run_completed", True
            ),
            "observer replay archive verification crosses its inert profile",
        )

        positive = workspace / "positive"
        shutil.copytree(base, positive)
        collector_root, bundle_root = collector.collect(**arguments(positive, "positive"))
        anchor = digest(positive / "coordinator/manifest.json")
        check_run_bundle.validate(
            bundle_root,
            7,
            profile=profiles.NO_FAULT_V1,
            coordinator_manifest_sha256=anchor,
            emit=False,
        )
        if not (collector_root / "assembly-spec.json").is_file():
            raise AssertionError("collector omitted the existing assembly-spec schema")
        if not (collector_root / "completed-run-summary.json").is_file():
            raise AssertionError("collector omitted the schema-3 completed-run summary")
        completed_summary = read(collector_root / "completed-run-summary.json")
        build_report = read(positive / "supplies/build-report.json")
        if completed_summary["schema_version"] != 3:
            raise AssertionError("collector emitted a legacy completed-run summary")
        for field in check_run_evidence.SOURCE_PROVENANCE_KEYS:
            if completed_summary["candidate"][field] != build_report[field]:
                raise AssertionError(
                    f"collector dropped aggregate build provenance field {field}"
                )
    print(
        "poco_g3_no_fault_bundle_collector_v1_test=passed "
        "positive_fixture_only=true production_active=blocked plan_only=no_outputs "
        "signed_observer_profile=plan-only external_load_profile=plan-only "
        "independent_anchor=required active_bounds=exact prestart_schema=exact "
        "real_public_inventory=exact "
        "symlink_ancestor=blocked input_overlap=blocked missing_pid=blocked external_window=blocked "
        "qc_n=blocked invalid_signature_control=blocked nonempty_workload=blocked "
        "mac_signature_fact=blocked validator_signature=blocked missing_artifact=blocked "
        "replay_export=required replay_observer=required replay_hash_join=exact "
        "truth_bits_changed=false fault_gate_released=false"
    )


if __name__ == "__main__":
    main()
