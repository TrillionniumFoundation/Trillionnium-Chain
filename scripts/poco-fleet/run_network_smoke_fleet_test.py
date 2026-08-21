#!/usr/bin/env python3
"""Focused failure-boundary tests for the six-host network-smoke runner."""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
from unittest import mock


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "run_network_smoke_fleet", HERE / "run_network_smoke_fleet.py"
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load network-smoke fleet module")
fleet = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fleet
SPEC.loader.exec_module(fleet)


def completed(stdout: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess([], 0, stdout=stdout, stderr=b"")


def expect_system_exit(action, contains: str) -> None:
    try:
        action()
    except SystemExit as error:
        if contains not in str(error):
            raise AssertionError(f"unexpected failure: {error}") from error
    else:
        raise AssertionError("negative control unexpectedly succeeded")


def process(host_id: str, management: str) -> object:
    return fleet.ValidatorProcess(
        validator_id=hashlib.sha256(host_id.encode("ascii")).hexdigest(),
        host_id=host_id,
        management=management,
        deployment=pathlib.Path("/tmp") / host_id,
        config_relative=pathlib.PurePosixPath("public/config.json"),
    )


def test_unique_json_and_remote_path() -> None:
    value = fleet.strict_json_bytes(b'{"a":1,"b":2}', "fixture")
    assert value == {"a": 1, "b": 2}
    expect_system_exit(
        lambda: fleet.strict_json_bytes(b'{"a":1,"a":2}', "fixture"),
        "duplicate JSON key",
    )
    assert fleet.shell_path(
        "/tmp/trnm-poco-g3-network-smoke-safe/path-1"
    ) == "/tmp/trnm-poco-g3-network-smoke-safe/path-1"
    expect_system_exit(
        lambda: fleet.shell_path("/tmp/trnm-poco-g3-network-smoke-x;touch-bad"),
        "unsafe",
    )


def test_input_symlinks_are_rejected_before_resolution() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-runner-symlink-test-") as raw:
        root = pathlib.Path(raw)
        real_directory = root / "real-directory"
        real_directory.mkdir()
        directory_link = root / "directory-link"
        directory_link.symlink_to(real_directory, target_is_directory=True)
        expect_system_exit(
            lambda: fleet.require_private_directory(directory_link, "directory"),
            "real directory",
        )

        real_binary = root / "real-binary"
        real_binary.write_bytes(b"binary")
        real_binary.chmod(0o500)
        binary_link = root / "binary-link"
        binary_link.symlink_to(real_binary)
        expected = hashlib.sha256(real_binary.read_bytes()).hexdigest()
        expect_system_exit(
            lambda: fleet.require_binary(binary_link, expected, "binary"),
            "non-symlink",
        )


def test_process_output_is_file_backed_without_pipe_pressure() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-process-capture-test-") as raw:
        root = pathlib.Path(raw)
        capture = fleet.open_process_capture(root, "11" * 32)
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys;"
                "sys.stdout.buffer.write(b'x' * 1048576);"
                "sys.stderr.buffer.write(b'y' * 1048576)",
            ],
            stdout=capture.stdout,
            stderr=capture.stderr,
        )
        assert child.stdout is None and child.stderr is None
        child.wait(timeout=10)
        stdout, stderr = fleet.finish_process_capture(capture)
        assert child.returncode == 0
        assert stdout == b"x" * 1048576
        assert stderr == b"y" * 1048576
        assert capture.stdout_path.stat().st_mode & 0o777 == 0o600
        assert capture.stderr_path.stat().st_mode & 0o777 == 0o600


def test_partial_stage_creation_cleans_exact_prior_root() -> None:
    calls: list[list[str]] = []

    def fake_run(arguments: list[str], **_kwargs) -> subprocess.CompletedProcess[bytes]:
        calls.append(arguments)
        if len(calls) == 2:
            raise subprocess.CalledProcessError(1, arguments)
        return completed()

    fixtures = [process("alpha", "alpha-route"), process("beta", "beta-route")]
    with mock.patch.object(fleet, "run_checked", side_effect=fake_run):
        try:
            fleet.create_stages(
                fixtures,
                "poco-g3-7-20260813T120000Z-00000000",
                pathlib.Path("/evidence/run"),
            )
        except subprocess.CalledProcessError:
            pass
        else:
            raise AssertionError("partial creation negative control succeeded")
    assert len(calls) == 4
    cleanup = calls[2:]
    assert all(call[0] == "ssh" and "rm -rf --" in call[-1] for call in cleanup)
    assert {call[-2] for call in cleanup} == {"alpha-route", "beta-route"}
    assert any("alpha" in call[-1] for call in cleanup)
    assert any("beta" in call[-1] for call in cleanup)


def test_local_stage_creates_private_deployment_directories() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-local-stage-test-") as raw:
        prefix = pathlib.Path(raw) / "stage"
        fixture = process("local", "local")
        with mock.patch.object(fleet, "REMOTE_STAGE_PREFIX", str(prefix)):
            stages = fleet.create_stages(
                [fixture],
                "poco-g3-7-20260813T120000Z-00000000",
                pathlib.Path(raw) / "evidence",
            )
            stage = stages["local"]
            assert stage.local_path is not None
            assert stage.local_path.stat().st_mode & 0o777 == 0o700
            for relative in ("bin", "validators"):
                child = stage.local_path / relative
                assert child.is_dir()
                assert child.stat().st_mode & 0o777 == 0o700
            fleet.clean_stages(stages)
            assert not stage.local_path.exists()


def test_remote_binary_hash_mismatch_is_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-network-smoke-test-") as raw:
        source = pathlib.Path(raw) / "validator"
        source.write_bytes(b"frozen-binary")
        source.chmod(0o500)
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        stage = fleet.HostStage(
            "remote",
            "remote-route",
            "/tmp/trnm-poco-g3-network-smoke-test",
            None,
        )
        with mock.patch.object(
            fleet,
            "run_checked",
            side_effect=(completed(), completed(b"0" * 64 + b"\n")),
        ):
            expect_system_exit(
                lambda: fleet.copy_binary(source, stage, "validator", expected),
                "hash differs",
            )


def test_observer_stage_is_registered_before_later_copy_failure() -> None:
    stages = {
        "local": fleet.HostStage(
            "local",
            "local",
            "/tmp/trnm-poco-g3-network-smoke-local",
            pathlib.Path("/tmp/trnm-poco-g3-network-smoke-local"),
        )
    }
    fixtures = [process("local", "local")]
    with mock.patch.object(fleet, "run_checked", return_value=completed()), mock.patch.object(
        fleet, "require_binary", side_effect=lambda path, _expected, _field: path
    ), mock.patch.object(
        fleet,
        "copy_binary",
        side_effect=("/tmp/linux-validator", OSError("observer copy failed")),
    ), mock.patch.object(fleet, "copy_directory"):
        try:
            fleet.deploy(
                stages,
                fixtures,
                pathlib.Path("/deployments"),
                pathlib.Path("/linux"),
                pathlib.Path("/macos"),
                "0" * 64,
                "0" * 64,
            )
        except OSError as error:
            assert str(error) == "observer copy failed"
        else:
            raise AssertionError("observer copy negative control succeeded")
    assert "mac" in stages
    assert stages["mac"].management == "p4-mac"


def main() -> None:
    test_unique_json_and_remote_path()
    test_input_symlinks_are_rejected_before_resolution()
    test_process_output_is_file_backed_without_pipe_pressure()
    test_partial_stage_creation_cleans_exact_prior_root()
    test_local_stage_creates_private_deployment_directories()
    test_remote_binary_hash_mismatch_is_rejected()
    test_observer_stage_is_registered_before_later_copy_failure()
    print(
        "poco_g3_network_smoke_fleet_test=passed positives=6 negatives=7 "
        "unique_json=true safe_remote_paths=true input_symlinks_rejected=true file_backed_process_io=true partial_cleanup=true "
        "local_stage_directories=true remote_binary_hash=true observer_stage_cleanup_registered=true "
        "validator_run_completed=false g3_complete=false geo_wan=false"
    )


if __name__ == "__main__":
    main()
