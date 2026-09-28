#!/usr/bin/env python3
"""Focused status-75 supervisor tests for the fault/restart runner."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import sys
import tempfile
import types


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_fault_restart_fleet_v1 as fleet  # noqa: E402


RUN_ID = "poco-g3-7-20260819T000000Z-deadbeef"


def expect_failure(action, contains: str) -> None:
    try:
        action()
    except (OSError, RuntimeError, SystemExit) as error:
        if contains not in str(error):
            raise AssertionError(f"unexpected failure: {error}") from error
    else:
        raise AssertionError("negative control unexpectedly succeeded")


def processes() -> list[fleet.base.ValidatorProcess]:
    return [
        fleet.base.ValidatorProcess(
            validator_id=f"{index + 1:064x}",
            host_id="local",
            management="local",
            deployment=pathlib.Path("/tmp/deployments") / f"{index + 1:064x}",
            config_relative=pathlib.PurePosixPath(
                f"public/configs/{index + 1:064x}.json"
            ),
            runtime_alias=f"v{index:03d}",
        )
        for index in range(7)
    ]


def control_status(
    process: fleet.base.ValidatorProcess,
    *,
    instance: int = 1,
    pid: int = 1234,
    sequence: int = 9,
    event_sha256: str = "11" * 32,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": RUN_ID,
        "validator_id": process.validator_id,
        "process_id": pid,
        "process_instance": instance,
        "generation": 17,
        "socket_basename": (
            f"runtime-control.instance-{instance}.generation-17.sock"
        ),
        "journal_event_sequence": sequence,
        "journal_event_sha256": event_sha256,
        "production_activation": False,
    }


def handoff(process: fleet.base.ValidatorProcess, pid: int = 1234) -> dict[str, object]:
    return {
        "schema_version": 2,
        "status": "process1-target-parked-ack-handoff",
        "run_id": RUN_ID,
        "validator_id": process.validator_id,
        "process1_pid": pid,
        "process1_instance": 1,
        "process2_instance": 2,
        "restart_park_event_sequence": 10,
        "restart_park_event_sha256": "21" * 32,
        "restart_parked_ack_event_sequence": 11,
        "restart_parked_ack_event_sha256": "22" * 32,
        "restart_cut_artifact_sha256": "23" * 32,
        "restart_park_artifact_sha256": "24" * 32,
        "restart_parked_ack_artifact_sha256": "25" * 32,
        "restart_parked_ack_admission_set_sha256": "26" * 32,
        "local_restart_parked_ack_statement_sha256": "27" * 32,
        "protocol_authority": False,
        "production_activation": False,
    }


def prepare_response(process: fleet.base.ValidatorProcess) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": RUN_ID,
        "validator_id": process.validator_id,
        "process_instance": 1,
        "generation": 17,
        "nonce": 3,
        "verb": "prepare_restart",
        "status": "ok",
        "expected_fault": "",
        "barrier_phase": "started",
        "fleet_ready_set_sha256": "31" * 32,
        "fleet_start_certificate_sha256": "32" * 32,
        "journal_event_sequence": 9,
        "journal_event_sha256": "11" * 32,
        "finalized_height": 8,
        "application_height": 8,
        "restart_quiesce_requested": True,
        "restart_pending_catchup": False,
        "restart_completed": False,
        "active_faults": [],
        "recovered_faults": ["leader_loss"],
        "final_tip_recorded": False,
        "clean_stop_recorded": False,
        "safety_halted": False,
        "production_activation": False,
    }


class FakeChild:
    def __init__(self, returncode: int | None) -> None:
        self.returncode = returncode
        self.poll_count = 0

    def poll(self) -> int | None:
        self.poll_count += 1
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout: int | None = None) -> int:
        del timeout
        assert self.returncode is not None
        return self.returncode


def runtime(
    process: fleet.base.ValidatorProcess,
    stage_root: pathlib.Path,
    child: FakeChild,
    capture,
    *,
    instance: int,
) -> fleet.RuntimeProcessV1:
    root = stage_root / "validators" / process.validator_id
    command = [
        "/stage/validator",
        "run-consensus",
        str(root),
        str(root / process.config_relative),
        "60",
        "100",
        str(root / "consensus-report.json"),
    ]
    return fleet.RuntimeProcessV1(
        process=process,
        command=command,
        child=child,
        capture=capture,
        report_source=str(root / "consensus-report.json"),
        journal_source=str(root / "runtime-events.jsonl"),
        metrics_source=str(root / "runtime-metrics.json"),
        final_state_source=str(root / "runtime-final-state.json"),
        fleet_start_certificate_source=str(root / "fleet-start-certificate.bin"),
        process_instance=instance,
    )


def main() -> None:
    assert fleet.PROCESS2_INERT_BOUNDARY_MESSAGE_V1 == (
        "continuous consensus process2 reached the durable zero-delta caught-up cut; "
        "RecoveryReady, RecoveryStart, pacemaker, mesh, and ordinary ingress remain "
        "unavailable"
    )
    validators = processes()
    target = validators[1]
    accepted = handoff(target)
    assert (
        fleet.exact_target_handoff(
            accepted,
            run_id=RUN_ID,
            validator_id=target.validator_id,
            process1_pid=1234,
        )
        is accepted
    )
    for field, mutant in (
        ("schema_version", 1),
        ("status", "process1-target-parked-handoff"),
        ("run_id", "foreign"),
        ("validator_id", validators[0].validator_id),
        ("process1_pid", 999),
        ("process1_instance", 2),
        ("process2_instance", 1),
        ("restart_parked_ack_event_sequence", 12),
        ("restart_cut_artifact_sha256", "0" * 64),
        ("restart_park_artifact_sha256", "not-hex"),
        ("protocol_authority", True),
        ("production_activation", True),
    ):
        changed = dict(accepted)
        changed[field] = mutant
        expect_failure(
            lambda value=changed: fleet.exact_target_handoff(
                value,
                run_id=RUN_ID,
                validator_id=target.validator_id,
                process1_pid=1234,
            ),
            "exact durable context",
        )
    extra = dict(accepted)
    extra["unexpected"] = False
    expect_failure(
        lambda: fleet.exact_target_handoff(
            extra,
            run_id=RUN_ID,
            validator_id=target.validator_id,
            process1_pid=1234,
        ),
        "keys differ",
    )
    for status in (0, 2, 101, 255, -9):
        expect_failure(
            lambda value=status: fleet.require_target_handoff_exit_status(value),
            "not exact handoff status 75",
        )
    fleet.require_target_handoff_exit_status(75)

    exact_inert_stderr = (
        "trnm-poco-lab-validator failed: "
        f"{fleet.PROCESS2_INERT_BOUNDARY_MESSAGE_V1}\n"
    ).encode("utf-8")
    inert_exit = fleet.exact_process2_inert_exit(2, b"\n", exact_inert_stderr)
    assert inert_exit["authenticated_inert_boundary"] is True
    for returncode, stdout, stderr in (
        (1, b"\n", exact_inert_stderr),
        (2, b"unexpected\n", exact_inert_stderr),
        (2, b"\n", b"context: " + exact_inert_stderr),
        (2, b"\n", exact_inert_stderr + b"extra\n"),
    ):
        expect_failure(
            lambda code=returncode, out=stdout, err=stderr: fleet.exact_process2_inert_exit(
                code, out, err
            ),
            "exact authenticated inert-recovery boundary",
        )

    saved_status = control_status(target)
    saved = fleet.SavedControlLocatorV1(dict(saved_status), "41" * 32)
    current = fleet.SavedControlLocatorV1(dict(saved_status), saved.raw_sha256)
    assert (
        fleet.exact_post_handoff_control_locator(
            current, saved=saved, handoff=accepted
        )
        is current
    )
    for field, mutant in (
        ("process_id", 999),
        ("generation", 18),
        ("journal_event_sequence", 12),
        ("journal_event_sha256", "43" * 32),
    ):
        changed_status = dict(saved_status)
        changed_status[field] = mutant
        changed = fleet.SavedControlLocatorV1(changed_status, current.raw_sha256)
        expect_failure(
            lambda value=changed: fleet.exact_post_handoff_control_locator(
                value, saved=saved, handoff=accepted
            ),
            "saved incarnation",
        )
    changed_digest = fleet.SavedControlLocatorV1(dict(saved_status), "42" * 32)
    expect_failure(
        lambda: fleet.exact_post_handoff_control_locator(
            changed_digest, saved=saved, handoff=accepted
        ),
        "saved incarnation",
    )

    with tempfile.TemporaryDirectory(
        prefix="tp3-handoff-test-", dir="/tmp"
    ) as raw:
        root = pathlib.Path(raw)
        stage_root = root
        validator_private = stage_root / "v" / target.runtime_alias
        validator_private.mkdir(parents=True, mode=0o700)
        stage = fleet.base.HostStage("local", "local", str(stage_root), stage_root)
        status_path = validator_private / fleet.CONTROL_STATUS_FILE
        status_bytes = json.dumps(
            saved_status, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        status_path.write_bytes(status_bytes)
        status_path.chmod(0o600)
        locator = fleet.SavedControlLocatorV1(
            dict(saved_status), hashlib.sha256(status_bytes).hexdigest()
        )
        io_root = root / "io"
        io_root.mkdir(mode=0o700)
        fleet.remove_exact_control_locator(
            process=target,
            stage=stage,
            locator=locator,
            io_root=io_root,
            label="remove-exact",
        )
        assert not status_path.exists() and not status_path.is_symlink()

        status_path.write_bytes(status_bytes)
        status_path.chmod(0o600)
        stale_locator = locator
        status_path.write_bytes(status_bytes + b" ")
        status_path.chmod(0o600)
        expect_failure(
            lambda: fleet.remove_exact_control_locator(
                process=target,
                stage=stage,
                locator=stale_locator,
                io_root=io_root,
                label="reject-mutated",
            ),
            "changed before exact unlink",
        )
        assert status_path.is_file()
        status_path.unlink()

        process_io = root / "process-io"
        process_io.mkdir(mode=0o700)
        target_capture = fleet.base.open_process_capture(
            process_io, target.validator_id
        )
        target_capture.stdout.write(
            json.dumps(accepted, separators=(",", ":")).encode("utf-8") + b"\n"
        )
        target_capture.stderr.write(b"bounded warning\n")
        target_runtime = runtime(
            target,
            stage_root,
            FakeChild(75),
            target_capture,
            instance=1,
        )
        runtimes = {target.validator_id: target_runtime}
        for peer in validators:
            if peer.validator_id == target.validator_id:
                continue
            runtimes[peer.validator_id] = runtime(
                peer,
                stage_root,
                FakeChild(None),
                types.SimpleNamespace(stdout=None, stderr=None),
                instance=1,
            )

        saved_locator = fleet.SavedControlLocatorV1(dict(saved_status), "51" * 32)
        current_locator = fleet.SavedControlLocatorV1(
            dict(saved_status), saved_locator.raw_sha256
        )
        successor_capture = fleet.base.open_process_capture(
            process_io, f"{target.validator_id}.instance-2"
        )
        successor_capture.stderr.write(
            (
                "trnm-poco-lab-validator failed: "
                f"{fleet.PROCESS2_INERT_BOUNDARY_MESSAGE_V1}\n"
            ).encode("utf-8")
        )
        successor = runtime(
            target,
            stage_root,
            FakeChild(2),
            successor_capture,
            instance=2,
        )
        successor.command = list(target_runtime.command)
        calls: list[tuple[str, str]] = []
        locator_reads = iter((saved_locator, current_locator))

        original_wait_locator = fleet.wait_control_locator
        original_send_control = fleet.send_control
        original_remove = fleet.remove_exact_control_locator
        original_launch = fleet.launch_runtime

        def fake_wait_locator(**kwargs):
            calls.append(("read", kwargs["process"].validator_id))
            return next(locator_reads)

        def fake_send_control(**kwargs):
            calls.append((kwargs["verb"], kwargs["process"].validator_id))
            assert kwargs["fault"] == ""
            return prepare_response(target)

        def fake_remove(**kwargs):
            calls.append(("remove", kwargs["process"].validator_id))
            assert kwargs["locator"] is current_locator

        def fake_launch(**kwargs):
            calls.append(("launch", kwargs["process"].validator_id))
            assert kwargs["process_instance"] == 2
            return successor

        try:
            fleet.wait_control_locator = fake_wait_locator
            fleet.send_control = fake_send_control
            fleet.remove_exact_control_locator = fake_remove
            fleet.launch_runtime = fake_launch
            observed_successor, observed_exit, observed_prepare, observed_handoff = (
                fleet.supervise_target_process1_handoff(
                    runtimes=runtimes,
                    process=target,
                    stage=stage,
                    binary="/stage/validator",
                    run_id=RUN_ID,
                    duration_seconds=60,
                    max_blocks=100,
                    process_io=process_io,
                    control_io=io_root,
                    command_nonce=3,
                    timeout_seconds=2,
                )
            )
            assert observed_successor is successor
            assert observed_exit["returncode"] == 2
            assert observed_exit["authenticated_inert_boundary"] is True
            assert len(observed_exit["stderr_sha256"]) == 64
            assert observed_prepare["verb"] == "prepare_restart"
            assert observed_handoff == accepted
            assert runtimes[target.validator_id] is successor
            assert calls == [
                ("read", target.validator_id),
                ("prepare_restart", target.validator_id),
                ("read", target.validator_id),
                ("remove", target.validator_id),
                ("launch", target.validator_id),
            ]
            expect_failure(
                lambda: fleet.supervise_target_process1_handoff(
                    runtimes=runtimes,
                    process=target,
                    stage=stage,
                    binary="/stage/validator",
                    run_id=RUN_ID,
                    duration_seconds=60,
                    max_blocks=100,
                    process_io=process_io,
                    control_io=io_root,
                    command_nonce=1,
                    timeout_seconds=1,
                ),
                "one exact process-1 runtime",
            )
        finally:
            fleet.wait_control_locator = original_wait_locator
            fleet.send_control = original_send_control
            fleet.remove_exact_control_locator = original_remove
            fleet.launch_runtime = original_launch

        peer_id = validators[0].validator_id
        runtimes[peer_id].child.returncode = 75
        expect_failure(
            lambda: fleet.require_non_target_processes_live(
                runtimes, target.validator_id
            ),
            "non-target validator",
        )
        runtimes[peer_id].child.returncode = None

        fleet.require_no_target_normal_terminal_artifacts(
            runtime=successor,
            stage=stage,
            io_root=io_root,
            label="no-artifacts",
        )
        forbidden_report = pathlib.Path(successor.report_source)
        forbidden_report.parent.mkdir(parents=True, exist_ok=True)
        forbidden_report.write_bytes(b"{}")
        expect_failure(
            lambda: fleet.require_no_target_normal_terminal_artifacts(
                runtime=successor,
                stage=stage,
                io_root=io_root,
                label="reject-report",
            ),
            "forbidden normal terminal artifact",
        )

        remote_process = fleet.base.ValidatorProcess(
            validator_id=validators[6].validator_id,
            host_id="x230",
            management="p4-x230",
            deployment=validators[6].deployment,
            config_relative=validators[6].config_relative,
            runtime_alias=validators[6].runtime_alias,
        )
        remote_stage = fleet.base.HostStage(
            "x230",
            "p4-x230",
            "/tmp/tp3-0123456789abcdef0123",
            None,
        )
        spawned_commands: list[list[str]] = []
        original_popen = fleet.subprocess.Popen

        class CapturingPopen(FakeChild):
            def __init__(self, command, **kwargs) -> None:
                del kwargs
                super().__init__(None)
                spawned_commands.append(command)

        try:
            fleet.subprocess.Popen = CapturingPopen
            remote_runtime = fleet.launch_runtime(
                process=remote_process,
                stage=remote_stage,
                binary="/stage/validator",
                duration_seconds=60,
                max_blocks=100,
                process_io=process_io,
                process_instance=1,
            )
        finally:
            fleet.subprocess.Popen = original_popen
        fleet.base.close_process_capture(remote_runtime.capture)
        assert len(spawned_commands) == 1
        remote_command = spawned_commands[0][-1]
        assert 'if wait "$child"; then status=0; else status=$?; fi' in remote_command
        assert 'exit "$status"' in remote_command

    # Process2 resume arguments are exact, canonical and never legal without
    # the instance-2/external-fence launch contract.
    resume = fleet.Process2ResumeArtifactsV1(
        ready_set_artifact_sha256="11" * 32,
        start_certificate_artifact_sha256="22" * 32,
        fence_token_digest="33" * 32,
    )
    assert fleet.process2_resume_arguments_v1(resume) == [
        "--resume-process2",
        "--recovery-ready-set-sha256",
        "11" * 32,
        "--recovery-start-certificate-sha256",
        "22" * 32,
        "--recovery-fence-token-sha256",
        "33" * 32,
    ]
    try:
        fleet.process2_resume_arguments_v1(
            dataclasses.replace(resume, fence_token_digest="0" * 64)
        )
    except SystemExit:
        pass
    else:
        raise AssertionError("zero process2 fence digest was accepted")

    material_result = {
        "schema_version": 1,
        "status": "recovery-ready",
        "run_id": RUN_ID,
        "validator_id": target.validator_id,
        "validator_set_id": "44" * 32,
        "path": "/stage/validator/recovery-material-v1/ready.bin",
        "artifact_sha256": "55" * 32,
        "context_digest": "66" * 32,
        "predecessor_artifact_sha256": None,
        "candidate_only": True,
        "production_activation": False,
    }
    assert fleet.exact_recovery_material_result_v1(
        material_result,
        command="recovery-ready",
        process=target,
        run_id=RUN_ID,
        expected_path=material_result["path"],
    ) == material_result
    for mutation in (
        {**material_result, "artifact_sha256": "0" * 64},
        {**material_result, "path": "/other"},
        {**material_result, "production_activation": True},
    ):
        try:
            fleet.exact_recovery_material_result_v1(
                mutation,
                command="recovery-ready",
                process=target,
                run_id=RUN_ID,
                expected_path=material_result["path"],
            )
        except SystemExit:
            pass
        else:
            raise AssertionError("invalid recovery material result was accepted")

    assert fleet.exact_peer_lease_binding_v1(
        {
            "schema_version": 1,
            "status": "peer-lease-binding",
            "binding_digest": "77" * 32,
            "candidate_only": True,
            "production_activation": False,
        }
    ) == "77" * 32

    restart_step = fleet.FaultStepV1(
        ordinal=1,
        kind=fleet.RESTART_FAULT,
        target_validator_id=target.validator_id,
        target_host_id=target.host_id,
        restart=True,
    )
    restart_temporary = tempfile.TemporaryDirectory(prefix="tp3-restart-evidence-", dir="/tmp")
    restart_output = pathlib.Path(restart_temporary.name) / "restart-output"
    restart_output.mkdir(mode=0o700)
    restart_result = fleet.write_restart_artifacts_v1(
        output=restart_output,
        step=restart_step,
        run_id=RUN_ID,
        started_at="2026-09-27T00:00:00Z",
        ended_at="2026-09-27T00:00:01Z",
        transcript=[
            {"surface": "process1-handoff"},
            {"surface": "process2-inert-cut"},
            {"surface": "recovery-material"},
            {"surface": "process2-control"},
            {"surface": "process2-catchup"},
        ],
    )
    assert restart_result["kind"] == fleet.RESTART_FAULT
    assert restart_result["restart"] is True
    assert restart_result["evidence_mode"] == fleet.fault_semantics.SIGNED_RESTART_CATCHUP

    resume_process_io = pathlib.Path(restart_temporary.name) / "process-io"
    resume_process_io.mkdir(mode=0o700)
    spawned_commands.clear()
    original_popen = fleet.subprocess.Popen
    fleet.subprocess.Popen = CapturingPopen
    try:
        inert_probe = fleet.launch_runtime(
            process=target,
            stage=remote_stage,
            binary="/stage/validator",
            duration_seconds=60,
            max_blocks=100,
            process_io=resume_process_io,
            process_instance=2,
            peer_lease_socket=f"{remote_stage.root}/peer.sock",
        )
        inert_probe.capture.stdout.write(b"\n")
        inert_probe.capture.stderr.write(exact_inert_stderr)
        fleet.base.close_process_capture(inert_probe.capture)
        resumed_runtime = fleet.launch_runtime(
            process=target,
            stage=remote_stage,
            binary="/stage/validator",
            duration_seconds=60,
            max_blocks=100,
            process_io=resume_process_io,
            process_instance=2,
            peer_lease_socket=f"{remote_stage.root}/peer.sock",
            process2_resume=resume,
        )
    finally:
        fleet.subprocess.Popen = original_popen
    fleet.base.close_process_capture(resumed_runtime.capture)
    assert len(spawned_commands) == 2
    assert inert_probe.process_instance == resumed_runtime.process_instance == 2
    assert inert_probe.capture.stdout_path != resumed_runtime.capture.stdout_path
    assert inert_probe.capture.stderr_path != resumed_runtime.capture.stderr_path
    assert inert_probe.capture.stdout_path.read_bytes() == b"\n"
    assert inert_probe.capture.stderr_path.read_bytes() == exact_inert_stderr
    # Both streams stay exclusive: retry cannot truncate old evidence or spawn.
    original_popen = fleet.subprocess.Popen
    fleet.subprocess.Popen = CapturingPopen
    try:
        for resume_input in (None, resume):
            try:
                fleet.launch_runtime(
                    process=target, stage=remote_stage, binary="/stage/validator",
                    duration_seconds=60, max_blocks=100, process_io=resume_process_io,
                    process_instance=2, peer_lease_socket=f"{remote_stage.root}/peer.sock",
                    process2_resume=resume_input,
                )
            except FileExistsError:
                pass
            else:
                raise AssertionError("duplicate capture unexpectedly overwrote retained evidence")
        assert len(spawned_commands) == 2
    finally:
        fleet.subprocess.Popen = original_popen
    assert inert_probe.capture.stderr_path.read_bytes() == exact_inert_stderr
    resumed_command = spawned_commands[1][-1]
    for token in (
        "--peer-lease-socket",
        "--resume-process2",
        "--recovery-ready-set-sha256",
        "--recovery-start-certificate-sha256",
        "--recovery-fence-token-sha256",
        "11" * 32,
        "22" * 32,
        "33" * 32,
    ):
        assert resumed_command.count(token) == 1

    # Control-path regression: six resident peers keep their process identity.
    # Admission alone is not completion; only subsequent completed journal views
    # count. These are fixture responses, never cryptographic run evidence.
    from unittest.mock import patch
    from types import SimpleNamespace
    peers = [SimpleNamespace(validator_id=str(i), host_id="fixture") for i in range(6)]
    peer_statuses = {p.validator_id: {"process_instance": 1} for p in peers}
    sent = []
    def peer_control(**kwargs):
        sent.append((kwargs["process"].validator_id, kwargs["verb"]))
        return {"safety_halted": False, "clean_stop_recorded": False,
                "restart_completed": kwargs["verb"] == "status",
                "restart_pending_catchup": False,
                "restart_quiesce_requested": kwargs["verb"] != "status"}
    with patch.object(fleet, "send_control", side_effect=peer_control):
        observed = fleet.resume_resident_peers_v1(
            processes=peers, stages={"fixture": None}, linux_paths={"fixture": "/fixture"},
            statuses=peer_statuses, command_nonces={str(i): 1 for i in range(6)},
            read_nonces={str(i): 1 for i in range(6)}, io_root=pathlib.Path("/fixture"),
            timeout_seconds=2,
        )
    assert len(observed) == 6
    assert [v for _, v in sent[:6]] == ["resume_restart_peer"] * 6
    assert [v for _, v in sent[6:]] == ["status"] * 6
    assert all(v != "clear_restart_quiesce" for _, v in sent)
    assert all(s["process_instance"] == 1 for s in peer_statuses.values())
    peer_statuses["0"]["process_instance"] = 2
    with patch.object(fleet, "send_control", side_effect=AssertionError("unexpected effect")):
        try:
            fleet.resume_resident_peers_v1(
                processes=peers, stages={"fixture": None}, linux_paths={"fixture": "/fixture"},
                statuses=peer_statuses, command_nonces={str(i): 1 for i in range(6)},
                read_nonces={str(i): 1 for i in range(6)}, io_root=pathlib.Path("/fixture"),
                timeout_seconds=2,
            )
        except RuntimeError as error:
            assert "process instance" in str(error)
        else:
            raise AssertionError("a process-2 target was accepted as a resident peer")

    restart_temporary.cleanup()

    print(
        "poco_fault_restart_handoff_v1_test=passed "
        "target_only=true exit75_exact=true exit75_ssh_preserved=true schema2_exact=true "
        "p1_locator_digest_unlink=true peer_liveness=true "
        "single_p2_launch=true normal_artifacts_absent=true resume_capture_no_overwrite=true "
        "truth_bits_unchanged=true"
    )


if __name__ == "__main__":
    main()
