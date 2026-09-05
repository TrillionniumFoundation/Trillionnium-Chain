#!/usr/bin/env python3
"""Focused status-75 supervisor tests for the fault/restart runner."""

from __future__ import annotations

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
        "continuous consensus RestartCut/RestartPark/RestartParkedAck-joined "
        "process2 is inert; authenticated start-catchup, RecoveryReady, and "
        "RecoveryStart remain unavailable"
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

    print(
        "poco_fault_restart_handoff_v1_test=passed "
        "target_only=true exit75_exact=true exit75_ssh_preserved=true schema2_exact=true "
        "p1_locator_digest_unlink=true peer_liveness=true "
        "single_p2_launch=true normal_artifacts_absent=true "
        "truth_bits_unchanged=true"
    )


if __name__ == "__main__":
    main()
