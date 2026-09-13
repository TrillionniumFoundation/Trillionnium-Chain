#!/usr/bin/env python3
"""Focused contract tests for the seven-validator fault/restart runner v1."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_fault_restart_fleet_v1 as fleet  # noqa: E402


def expect_failure(action, contains: str) -> None:
    try:
        action()
    except (SystemExit, RuntimeError) as error:
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


def processes() -> list[fleet.base.ValidatorProcess]:
    return [
        fleet.base.ValidatorProcess(
            validator_id=f"{index + 1:064x}",
            host_id=("local", "x230", "desktop", "rog", "rog", "j3160", "local")[index],
            management=(
                "local",
                "p4-x230",
                "p4-desktop",
                "p4-rog",
                "p4-rog",
                "p4-j3160",
                "local",
            )[index],
            deployment=pathlib.Path("/tmp/deployments") / f"{index + 1:064x}",
            config_relative=pathlib.PurePosixPath(
                f"public/configs/{index + 1:064x}.json"
            ),
            runtime_alias=f"v{index:03d}",
        )
        for index in range(7)
    ]


def status(instance: int = 1) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": "poco-g3-7-20260814T000000Z-deadbeef",
        "validator_id": "01" * 32,
        "process_id": 1234,
        "process_instance": instance,
        "generation": 17,
        "socket_basename": f"runtime-control.instance-{instance}.generation-17.sock",
        "journal_event_sequence": 9,
        "journal_event_sha256": "11" * 32,
        "production_activation": False,
    }


def response(
    control_status: dict[str, object],
    *,
    nonce: int,
    verb: str,
    expected_fault: str = "",
    active: list[str] | None = None,
    recovered: list[str] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": control_status["run_id"],
        "validator_id": control_status["validator_id"],
        "process_instance": control_status["process_instance"],
        "generation": control_status["generation"],
        "nonce": nonce,
        "verb": verb,
        "status": "ok",
        "expected_fault": expected_fault,
        "barrier_phase": "started",
        "fleet_ready_set_sha256": "42" * 32,
        "fleet_start_certificate_sha256": "30" * 32,
        "journal_event_sequence": 10,
        "journal_event_sha256": "12" * 32,
        "finalized_height": 8,
        "application_height": 8,
        "restart_pending_catchup": False,
        "restart_completed": control_status["process_instance"] == 2,
        "active_faults": active or [],
        "recovered_faults": recovered or [],
        "final_tip_recorded": False,
        "clean_stop_recorded": False,
        "safety_halted": False,
        "production_activation": False,
    }


def journal_summary(restarted: bool, fault_count: int) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "runtime-journal-signature-and-semantics-verified",
        "run_id": "poco-g3-7-20260814T000000Z-deadbeef",
        "validator_id": "01" * 32,
        "validator_set_sha256": "21" * 32,
        "coordinator_manifest_sha256": "22" * 32,
        "candidate_source_sha256": "23" * 32,
        "binary_sha256": "24" * 32,
        "config_sha256": "25" * 32,
        "barrier_round": 1,
        "fleet_ready_event_sequence": 3,
        "fleet_ready_event_sha256": "41" * 32,
        "fleet_ready_previous_event_sequence": 2,
        "fleet_ready_previous_event_sha256": "40" * 32,
        "fleet_ready_set_sha256": "42" * 32,
        "fleet_start_certificate_sha256": "30" * 32,
        "process_instance_count": 2 if restarted else 1,
        "event_count": 20,
        "runtime_event_sequence": 19,
        "runtime_event_sha256": "26" * 32,
        "finalized_height": 8,
        "finalized_block_id": "27" * 32,
        "finalized_state_root": "28" * 32,
        "finalized_chain_root": "29" * 32,
        "recovered_fault_count": fault_count,
        "restart_completed": restarted,
        "clean_stop": True,
        "signature_verified": True,
        "semantics_verified": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }


def certificate_summary() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "fleet-start-certificate-signature-and-semantics-verified",
        "run_id": "poco-g3-7-20260814T000000Z-deadbeef",
        "selected_validator_id": "01" * 32,
        "validator_count": 7,
        "validator_set_id": "20" * 32,
        "validator_set_sha256": "21" * 32,
        "topology_sha256": "31" * 32,
        "coordinator_manifest_sha256": "22" * 32,
        "candidate_source_sha256": "23" * 32,
        "binary_sha256": "24" * 32,
        "workload_corpus_sha256": "32" * 32,
        "workload_policy_sha256": "33" * 32,
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


def terminal_chain_inputs(
    *, restarted: bool
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    journal = journal_summary(restarted, 1)
    process_instance = 2 if restarted else 1
    report = {
        "validator_set_sha256": journal["validator_set_sha256"],
        "coordinator_manifest_sha256": journal["coordinator_manifest_sha256"],
        "candidate_source_sha256": journal["candidate_source_sha256"],
        "binary_sha256": journal["binary_sha256"],
        "config_sha256": journal["config_sha256"],
        "process_instance": process_instance,
        "finalized_height": journal["finalized_height"],
        "finalized_ordinary_block_count": 5,
        "application_state_root": journal["finalized_state_root"],
    }
    report_document = {
        "report_sha256": "45" * 32,
        "process_instance": process_instance,
        "runtime_event_sequence": journal["runtime_event_sequence"],
        "runtime_event_sha256": journal["runtime_event_sha256"],
        "application_head_block_id": journal["finalized_block_id"],
    }
    metrics = {
        "process_instance_count": process_instance,
        "runtime_event_sequence": journal["runtime_event_sequence"],
        "runtime_event_sha256": journal["runtime_event_sha256"],
        "consensus_report_sha256": report_document["report_sha256"],
        "body_sha256": "46" * 32,
    }
    final_state = {
        "process_instance_count": process_instance,
        "runtime_event_sequence": journal["runtime_event_sequence"],
        "runtime_event_sha256": journal["runtime_event_sha256"],
        "consensus_report_sha256": report_document["report_sha256"],
        "runtime_metrics_sha256": metrics["body_sha256"],
        "finalized_height": journal["finalized_height"],
        "finalized_ordinary_block_count": report["finalized_ordinary_block_count"],
        "finalized_block_id": journal["finalized_block_id"],
        "finalized_state_root": journal["finalized_state_root"],
        "finalized_chain_root": journal["finalized_chain_root"],
    }
    return report_document, report, metrics, final_state


def main() -> None:
    validators = processes()
    steps = fleet.fixed_fault_plan(validators)
    assert tuple(step.kind for step in steps) == fleet.FAULT_ORDER
    assert [step.ordinal for step in steps] == list(range(1, 9))
    assert sum(step.restart for step in steps) == 1
    assert next(step.kind for step in steps if step.restart) == "validator_process_kill"
    expect_failure(
        lambda: fleet.fixed_fault_plan(validators[:-1]), "exactly seven"
    )

    plan = fleet.campaign_plan(
        manifest={"run_id": "poco-g3-7-20260814T000000Z-deadbeef"},
        processes=validators,
        coordinator_anchor="31" * 32,
        driver_sha256="32" * 32,
        duration_seconds=16,
        max_blocks=3,
        fault_window_seconds=2,
    )
    assert plan["fault_order"][1]["restart"] is True
    assert plan["driver_output_is_runtime_evidence"] is False
    assert plan["active_campaign_supported"] is False
    assert plan["mesh_resource_preflight_required_before_effects"] is True
    assert plan["mesh_resource_preflight"] is None
    assert len(plan["authority_blockers"]) == 5
    policies = {item["kind"]: item for item in plan["fault_evidence_policy"]}
    assert policies["leader_loss"]["primary_journal_applied_recovered"] is True
    assert policies["host_loss"]["runtime_authority_supported"] is True
    assert policies["asymmetric_partition"]["runner_execution_supported"] is True
    assert policies["validator_process_kill"]["signed_restart_catchup_required"] is True
    assert policies["validator_process_kill"]["primary_journal_applied_recovered"] is False
    for kind in ("stale_snapshot", "rollback_attempt"):
        assert policies[kind]["isolated_startup_attempt"] is True
        assert policies[kind]["main_campaign_must_continue"] is True
        assert policies[kind]["exact_rejection_required"] is True
        assert policies[kind]["primary_journal_applied_recovered"] is False
    assert policies["bounded_delay_loss"]["signed_timeout_or_tc_required"] is True
    assert policies["bounded_delay_loss"]["recovered_finality_required"] is True
    assert policies["epoch_handoff"]["signed_epoch_handoff_required"] is True
    expect_failure(
        fleet.fault_semantics.require_active_campaign_supported,
        "process-instance-2-recovery-start-catchup-authority-unavailable",
    )
    assert plan["fault_matrix_completed"] is False
    assert plan["g3_lan_multihost_evidence"] is False
    expect_failure(
        lambda: fleet.campaign_plan(
            manifest={"run_id": plan["run_id"]},
            processes=validators,
            coordinator_anchor="31" * 32,
            driver_sha256="32" * 32,
            duration_seconds=15,
            max_blocks=3,
            fault_window_seconds=2,
        ),
        "cannot contain",
    )

    assert fleet.validate_management("p4-desktop") == "p4-desktop"
    expect_failure(lambda: fleet.validate_management("-ProxyCommand=x"), "unsafe")
    safe_root = "/tmp/tp3-0123456789abcdef0123"
    assert fleet.exact_remote_root(safe_root) == safe_root
    expect_failure(lambda: fleet.exact_remote_root("/tmp/../../escape"), "unsafe")
    safe_stage = fleet.base.HostStage("local", "local", safe_root, pathlib.Path(safe_root))
    assert fleet.validator_root(validators[0], safe_stage) == (
        fleet.base.validator_stage_root(validators[0], safe_stage)
    )

    accepted_status = fleet.exact_status(
        status(),
        run_id="poco-g3-7-20260814T000000Z-deadbeef",
        validator_id="01" * 32,
        process_instance=1,
    )
    assert accepted_status["generation"] == 17
    stale = status()
    stale["process_instance"] = 2
    expect_failure(
        lambda: fleet.exact_status(
            stale,
            run_id="poco-g3-7-20260814T000000Z-deadbeef",
            validator_id="01" * 32,
            process_instance=1,
        ),
        "exact context",
    )

    applied = response(
        accepted_status,
        nonce=1,
        verb="status",
        expected_fault="leader_loss",
        active=["leader_loss"],
    )
    assert (
        fleet.exact_response(
            applied, status=accepted_status, nonce=1, verb="status"
        )["active_faults"]
        == ["leader_loss"]
    )
    duplicate_fault = dict(applied)
    duplicate_fault["active_faults"] = ["leader_loss", "leader_loss"]
    expect_failure(
        lambda: fleet.exact_response(
            duplicate_fault, status=accepted_status, nonce=1, verb="status"
        ),
        "exact context",
    )
    halted = dict(applied)
    halted["safety_halted"] = True
    accepted_halted = fleet.exact_response(
        halted, status=accepted_status, nonce=1, verb="status"
    )
    assert accepted_halted["safety_halted"] is True

    for field, mutant in [
        ("barrier_phase", "ready"),
        ("fleet_ready_set_sha256", ""),
        ("fleet_start_certificate_sha256", "00" * 32),
    ]:
        drifted_barrier = dict(applied)
        drifted_barrier[field] = mutant
        expect_failure(
            lambda value=drifted_barrier: fleet.exact_response(
                value, status=accepted_status, nonce=1, verb="status"
            ),
            "exact context",
        )

    step = steps[0]
    driver_value = {
        "schema_version": 1,
        "phase": "apply",
        "kind": step.kind,
        "target_validator_id": step.target_validator_id,
        "status": "applied",
        "effect_id": "41" * 32,
        "production_activation": False,
    }
    assert fleet.exact_driver_response(driver_value, step=step, phase="apply") is driver_value
    forged_driver = dict(driver_value)
    forged_driver["production_activation"] = True
    expect_failure(
        lambda: fleet.exact_driver_response(forged_driver, step=step, phase="apply"),
        "exact request",
    )

    certificate = certificate_summary()
    assert (
        fleet.consensus.exact_fleet_start_certificate_summary(
            certificate,
            run_id=certificate["run_id"],
            validator_id=certificate["selected_validator_id"],
            coordinator_anchor=certificate["coordinator_manifest_sha256"],
            duration_seconds=60,
            max_blocks=100,
            validator_count=7,
            artifact_sha256=certificate["fleet_start_certificate_sha256"],
        )
        is certificate
    )
    raw_hash_substitution = dict(certificate)
    raw_hash_substitution["fleet_start_certificate_sha256"] = "55" * 32
    expect_failure(
        lambda: fleet.consensus.exact_fleet_start_certificate_summary(
            raw_hash_substitution,
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
    validator_substitution = dict(certificate)
    validator_substitution["selected_validator_id"] = "02" * 32
    expect_failure(
        lambda: fleet.consensus.exact_fleet_start_certificate_summary(
            validator_substitution,
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
    duration_mutation = dict(certificate)
    duration_mutation["duration_seconds"] = 61
    expect_failure(
        lambda: fleet.consensus.exact_fleet_start_certificate_summary(
            duration_mutation,
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
    ready_ancestry_mutation = dict(certificate)
    ready_ancestry_mutation["selected_pre_ready_journal_sequence"] = 1
    expect_failure(
        lambda: fleet.consensus.exact_fleet_start_certificate_summary(
            ready_ancestry_mutation,
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

    journal = journal_summary(True, 1)
    assert (
        fleet.fault_journal_summary(
            journal,
            certificate=certificate,
            run_id=journal["run_id"],
            validator_id=journal["validator_id"],
            coordinator_anchor=journal["coordinator_manifest_sha256"],
            expected_faults={"leader_loss"},
            restarted=True,
        )
        is journal
    )
    wrong_count = dict(journal)
    wrong_count["recovered_fault_count"] = 0
    expect_failure(
        lambda: fleet.fault_journal_summary(
            wrong_count,
            certificate=certificate,
            run_id=journal["run_id"],
            validator_id=journal["validator_id"],
            coordinator_anchor=journal["coordinator_manifest_sha256"],
            expected_faults={"leader_loss"},
            restarted=True,
        ),
        "campaign profile",
    )
    expect_failure(
        lambda: fleet.fault_journal_summary(
            journal,
            certificate=certificate,
            run_id=journal["run_id"],
            validator_id=journal["validator_id"],
            coordinator_anchor=journal["coordinator_manifest_sha256"],
            expected_faults={"validator_process_kill"},
            restarted=True,
        ),
        "only signed connectivity",
    )
    wrong_ready_hash = dict(journal)
    wrong_ready_hash["fleet_ready_event_sha256"] = "56" * 32
    expect_failure(
        lambda: fleet.fault_journal_summary(
            wrong_ready_hash,
            certificate=certificate,
            run_id=journal["run_id"],
            validator_id=journal["validator_id"],
            coordinator_anchor=journal["coordinator_manifest_sha256"],
            expected_faults={"leader_loss"},
            restarted=True,
        ),
        "does not join",
    )

    for restarted in (False, True):
        process_journal = journal_summary(restarted, 1)
        assert (
            fleet.fault_journal_summary(
                process_journal,
                certificate=certificate,
                run_id=process_journal["run_id"],
                validator_id=process_journal["validator_id"],
                coordinator_anchor=process_journal["coordinator_manifest_sha256"],
                expected_faults={"leader_loss"},
                restarted=restarted,
            )
            is process_journal
        )
        report_document, report, metrics, final_state = terminal_chain_inputs(
            restarted=restarted
        )
        assert (
            fleet.consensus.exact_process_evidence_chain(
                certificate=certificate,
                journal=process_journal,
                report_document=report_document,
                report=report,
                metrics=metrics,
                final_state=final_state,
            )
            is None
        )

    process_journal = journal_summary(True, 1)
    report_document, report, metrics, final_state = terminal_chain_inputs(
        restarted=True
    )
    config_mutation = dict(report)
    config_mutation["config_sha256"] = "57" * 32
    expect_value_error(
        lambda: fleet.consensus.exact_process_evidence_chain(
            certificate=certificate,
            journal=process_journal,
            report_document=report_document,
            report=config_mutation,
            metrics=metrics,
            final_state=final_state,
        ),
        "deployment context differs",
    )

    remote_stage = fleet.base.HostStage(
        "desktop", "p4-desktop", safe_root, None
    )
    remote = fleet.remote_or_local_command(
        validators[2], remote_stage, ["/stage/validator", "runtime-control", safe_root]
    )
    assert remote[:3] == ["ssh", "-o", "BatchMode=yes"]
    assert "exec /stage/validator runtime-control" in remote[-1]

    with tempfile.TemporaryDirectory(prefix="trnm-poco-g3-fault-v1-test-") as raw:
        root = pathlib.Path(raw)
        io_root = root / "io"
        io_root.mkdir(mode=0o700)
        certificate_process = fleet.base.ValidatorProcess(
            validator_id=certificate["selected_validator_id"],
            host_id="desktop",
            management="p4-desktop",
            deployment=root / "deployment",
            config_relative=pathlib.PurePosixPath(
                f"public/configs/{certificate['selected_validator_id']}.json"
            ),
            runtime_alias="v000",
        )
        observer_stage = fleet.base.HostStage(
            "mac",
            "p4-mac",
            "/tmp/tp3-0123456789abcdef0123",
            None,
        )
        observer_calls: list[list[str]] = []
        original_run_file_backed = fleet.run_file_backed
        original_sha256_file = fleet.base.sha256_file

        def fake_run_file_backed(arguments, **kwargs):
            observer_calls.append(arguments)
            stdout = b""
            if "verify-fleet-start-certificate" in arguments[-1]:
                stdout = (
                    json.dumps(certificate, separators=(",", ":")).encode("utf-8")
                    + b"\n"
                )
            return fleet.FileResultV1(
                0,
                stdout,
                b"",
                root / f"{kwargs['label']}.stdout",
                root / f"{kwargs['label']}.stderr",
            )

        try:
            fleet.run_file_backed = fake_run_file_backed
            fleet.base.sha256_file = lambda _path: certificate[
                "fleet_start_certificate_sha256"
            ]
            observed_certificate = fleet.observer_verify_fleet_start_certificate(
                process=certificate_process,
                source=root / "fleet-start-certificate.bin",
                mac_binary="/observer/trnm-poco-lab-validator",
                observer_root=(
                    "/tmp/tp3-0123456789abcdef0123/observer-public"
                ),
                observer_stage=observer_stage,
                coordinator_anchor=certificate["coordinator_manifest_sha256"],
                run_id=certificate["run_id"],
                duration_seconds=60,
                max_blocks=100,
                validator_count=7,
                io_root=io_root,
                label="observe-certificate",
            )
        finally:
            fleet.run_file_backed = original_run_file_backed
            fleet.base.sha256_file = original_sha256_file
        assert observed_certificate == certificate
        assert observer_calls[0][0] == "scp"
        assert observer_calls[1][-1].startswith("chmod 600 -- ")
        assert "verify-fleet-start-certificate" in observer_calls[2][-1]
        assert f"/{certificate['selected_validator_id']}.json" in observer_calls[2][-1]
        assert observer_calls[2][-1].endswith(" 60 100")

        command = root / "file-backed.py"
        command.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stdout.write('{\"ok\":true}\\n')\n"
            "sys.stderr.write('bounded\\n')\n",
            encoding="utf-8",
        )
        command.chmod(0o700)
        driver_hash = hashlib.sha256(command.read_bytes()).hexdigest()
        assert fleet.require_fault_driver(command) == command
        pinned = fleet.pin_fault_driver(command, root / "pinned-driver", driver_hash)
        assert pinned.read_bytes() == command.read_bytes()
        file_result = fleet.run_file_backed(
            [str(command)], io_root=io_root, label="file-backed", timeout=5
        )
        assert json.loads(file_result.stdout) == {"ok": True}
        assert file_result.stderr == b"bounded\n"
        assert file_result.stdout_path.is_file() and file_result.stderr_path.is_file()

        command.write_bytes(command.read_bytes() + b"# changed\n")
        expect_failure(
            lambda: fleet.pin_fault_driver(
                command, root / "rejected-driver", driver_hash
            ),
            "changed after",
        )

        artifact_root = root / "observations"
        artifact_root.mkdir(mode=0o700)
        observed = fleet.write_fault_artifacts(
            output=artifact_root,
            step=step,
            run_id=plan["run_id"],
            started_at="2026-08-14T00:00:01Z",
            ended_at="2026-08-14T00:00:02Z",
            transcript=[{"surface": "runtime-control", "status": "signed"}],
            fault_driver_sha256="42" * 32,
        )
        assert observed["signed_transition_observed"] is True
        assert (
            observed["evidence_mode"]
            == fleet.fault_semantics.SIGNED_CONNECTIVITY_TRANSITION
        )
        assert len(observed["schedule_sha256"]) == 64
        expect_failure(
            lambda: fleet.write_fault_artifacts(
                output=artifact_root,
                step=steps[5],
                run_id=plan["run_id"],
                started_at="2026-08-14T00:00:03Z",
                ended_at="2026-08-14T00:00:04Z",
                transcript=[{"surface": "process", "status": "rejected"}],
                fault_driver_sha256="42" * 32,
            ),
            "not primary-journal",
        )

        blocked_output = root / "blocked-active-campaign"
        expect_failure(
            lambda: fleet.execute_campaign(
                coordinator=root,
                deployments=root,
                manifest={"candidate": {}, "run_id": plan["run_id"]},
                processes=validators,
                linux_binary=command,
                macos_binary=command,
                fault_driver=command,
                output=blocked_output,
                duration_seconds=16,
                max_blocks=3,
                fault_window_seconds=2,
                plan=plan,
                stage_plan=fleet.base.preflight_runtime_layout(
                    validators, plan["run_id"], blocked_output
                ),
            ),
            "no fault effect was applied",
        )
        assert not blocked_output.exists()

        order: list[str] = []
        original_invoke = fleet.invoke_fault_driver

        def fake_invoke(**kwargs):
            order.append(kwargs["step"].kind)
            return ({}, None)

        fleet.invoke_fault_driver = fake_invoke
        active = [
            (candidate, validators[index], remote_stage, status())
            for index, candidate in enumerate(steps[:3])
        ]
        try:
            cleanup_failures = fleet.cleanup_fault_effects(
                active,
                driver=command,
                fault_window_seconds=2,
                io_root=io_root,
            )
        finally:
            fleet.invoke_fault_driver = original_invoke
        assert cleanup_failures == []
        assert order == [steps[2].kind, steps[1].kind, steps[0].kind]
        assert active == []

    source = (HERE / "run_fault_restart_fleet_v1.py").read_text(encoding="utf-8")
    main_layout = "stage_plan = base.preflight_runtime_layout("
    execute_layout = "expected_stage_plan = base.preflight_runtime_layout("
    assert source.index(main_layout) < source.index("if args.plan_only:")
    assert source.index(execute_layout) < source.index("output.mkdir(")
    assert source.index(execute_layout) < source.index("fault_driver = pin_fault_driver(")

    print(
        "poco_g3_fault_restart_fleet_v1_test=passed positives=36 negatives=19 "
        "fault_order=fixed-8 restart=exactly-1 runtime_control=exact "
        "mixed_fault_authority=exact active_campaign=fail-closed "
        "driver_not_evidence=true fault_driver_pinned=true safe_remote_paths=true file_backed_io=true "
        "plan_only_no_effect=true reverse_failure_cleanup=true "
        "fleet_start_certificate_required=true "
        "signed_journal_report_metrics_final_state_required=true "
        "fault_matrix_completed=false g3_complete=false geo_wan=false "
        "production_activation=false"
    )


if __name__ == "__main__":
    main()
