#!/usr/bin/env python3
"""Focused failure-boundary tests for the six-host network-smoke runner."""

from __future__ import annotations

import dataclasses
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


def process(
    host_id: str,
    management: str,
    *,
    runtime_alias: str = "v000",
    validator_id: str | None = None,
) -> object:
    return fleet.ValidatorProcess(
        validator_id=validator_id
        or hashlib.sha256(host_id.encode("ascii")).hexdigest(),
        host_id=host_id,
        management=management,
        deployment=pathlib.Path("/tmp") / host_id,
        config_relative=pathlib.PurePosixPath("public/config.json"),
        runtime_alias=runtime_alias,
    )


def process_set(routes: list[tuple[str, str]]) -> list[object]:
    identities = {
        host_id: hashlib.sha256(host_id.encode("ascii")).hexdigest()
        for host_id, _management in routes
    }
    aliases = {
        validator_id: f"v{ordinal:03d}"
        for ordinal, validator_id in enumerate(sorted(identities.values()))
    }
    return [
        process(
            host_id,
            management,
            runtime_alias=aliases[identities[host_id]],
            validator_id=identities[host_id],
        )
        for host_id, management in routes
    ]


def test_unique_json_and_remote_path() -> None:
    value = fleet.strict_json_bytes(b'{"a":1,"b":2}', "fixture")
    assert value == {"a": 1, "b": 2}
    expect_system_exit(
        lambda: fleet.strict_json_bytes(b'{"a":1,"a":2}', "fixture"),
        "duplicate JSON key",
    )
    assert fleet.shell_path("/tmp/tp3-safe/path-1") == "/tmp/tp3-safe/path-1"
    expect_system_exit(
        lambda: fleet.shell_path("/tmp/tp3-x;touch-bad"),
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

    fixtures = process_set([("alpha", "alpha-route"), ("beta", "beta-route")])
    plan = fleet.preflight_runtime_layout(
        fixtures,
        "poco-g3-7-20260813T120000Z-00000000",
        pathlib.Path("/evidence/run"),
    )
    plan.pop("mac")
    with mock.patch.object(fleet, "run_checked", side_effect=fake_run):
        try:
            fleet._materialize_stages(plan)
        except subprocess.CalledProcessError:
            pass
        else:
            raise AssertionError("partial creation negative control succeeded")
    assert len(calls) == 4
    cleanup = calls[2:]
    assert all(call[0] == "ssh" and "rm -rf --" in call[-1] for call in cleanup)
    assert {call[-2] for call in cleanup} == {"alpha-route", "beta-route"}
    assert {call[-1].split("rm -rf -- ", 1)[1] for call in cleanup} == {
        plan["alpha"].root,
        plan["beta"].root,
    }


def test_local_stage_creates_private_deployment_directories() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-local-stage-test-") as raw:
        fixture = process("local", "local")
        plan = fleet.preflight_runtime_layout(
            [fixture],
            "poco-g3-7-20260813T120000Z-00000000",
            pathlib.Path(raw) / "evidence",
        )
        stages = fleet._materialize_stages({"local": plan["local"]})
        stage = stages["local"]
        assert stage.local_path is not None
        assert stage.local_path.stat().st_mode & 0o777 == 0o700
        for relative in ("bin", "v"):
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
            "/tmp/tp3-test",
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


def test_deploy_uses_frozen_alias_and_observer_stage() -> None:
    fixtures = [process("local", "local")]
    stages = fleet.preflight_runtime_layout(
        fixtures,
        "poco-g3-7-20260813T120000Z-00000000",
        pathlib.Path("/evidence/deploy"),
    )
    copied: list[tuple[str, str]] = []
    with mock.patch.object(fleet, "run_checked", return_value=completed()), mock.patch.object(
        fleet, "require_binary", side_effect=lambda path, _expected, _field: path
    ), mock.patch.object(
        fleet,
        "copy_binary",
        side_effect=("/tmp/linux-validator", OSError("observer copy failed")),
    ), mock.patch.object(
        fleet,
        "copy_directory_as",
        side_effect=lambda _source, _stage, relative, name: copied.append(
            (relative, name)
        ),
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
    assert copied == [("v", "v000")]


def test_public_projection_and_remote_scp_land_at_exact_alias() -> None:
    fixture = process("alpha", "alpha-route")
    projection = fleet.public_process_projection(fixture)
    assert set(projection) == {
        "validator_id",
        "host_id",
        "management",
        "deployment",
        "config_relative",
    }
    assert "runtime_alias" not in projection
    with tempfile.TemporaryDirectory(prefix="poco-g3-scp-alias-test-") as raw:
        source = pathlib.Path(raw) / fixture.validator_id
        source.mkdir()
        (source / "manifest.json").write_text("{}", encoding="utf-8")
        stage = fleet.HostStage(
            "alpha",
            "alpha-route",
            "/tmp/tp3-0123456789abcdef0123",
            None,
        )
        calls: list[list[str]] = []

        def fake_run(arguments: list[str], **_kwargs) -> subprocess.CompletedProcess[bytes]:
            calls.append(arguments)
            return completed()

        with mock.patch.object(fleet, "run_checked", side_effect=fake_run):
            fleet.copy_directory_as(source, stage, "v", fixture.runtime_alias)
        exact = f"{stage.root}/v/{fixture.runtime_alias}"
        assert calls[0][-1] == f"set -eu; test ! -e {exact}"
        assert calls[1] == [
            "scp",
            "-q",
            "-r",
            str(source),
            f"alpha-route:{exact}",
        ]
        assert f"test -f {exact}/manifest.json" in calls[2][-1]
        assert f"test ! -e {exact}/{fixture.validator_id}" in calls[2][-1]


def test_runtime_layout_exact_bounds_aliases_and_old_207_bytes() -> None:
    fixtures = [
        process(
            "alpha",
            "alpha-route",
            runtime_alias=f"v{index:03d}",
            validator_id=f"{index:064x}",
        )
        for index in range(100)
    ]
    run_id = "poco-g3-100-20260813T120000Z-00000000"
    plan = fleet.preflight_runtime_layout(
        fixtures, run_id, pathlib.Path("/evidence/hundred")
    )
    assert fixtures[0].runtime_alias == "v000"
    assert fixtures[-1].runtime_alias == "v099"
    assert len({fleet.validator_stage_root(item, plan["alpha"]) for item in fixtures}) == 100
    assert run_id not in plan["alpha"].root
    maximum = fleet.runtime_control_socket_path(
        fleet.validator_stage_root(fixtures[-1], plan["alpha"]),
        2,
        fleet.MAX_RUNTIME_CONTROL_GENERATION,
    )
    assert len(maximum.encode("utf-8")) == 100
    assert len(
        fleet.runtime_control_socket_path(
            fleet.validator_stage_root(fixtures[-1], plan["alpha"]), 2, 17
        ).encode("utf-8")
    ) <= 100

    old_prefix = "/tmp/trnm-poco-g3-network-smoke"
    old_stage = (
        f"{old_prefix}-poco-g3-7-20260821T000000Z-1234abcd-"
        f"x230a-{'0' * 12}"
    )
    old_root = f"{old_stage}/validators/{'0' * 64}"
    old_socket = f"{old_root}/runtime-control.instance-1.generation-1.sock"
    assert len(old_socket.encode("utf-8")) == 207
    with mock.patch.object(fleet, "REMOTE_STAGE_PREFIX", old_prefix), mock.patch.object(
        fleet.pathlib.Path, "mkdir", side_effect=AssertionError("mkdir effect")
    ), mock.patch.object(
        fleet, "run_checked", side_effect=AssertionError("SSH/SCP effect")
    ), mock.patch.object(
        fleet, "write_new", side_effect=AssertionError("output effect")
    ), mock.patch.object(
        fleet.subprocess, "Popen", side_effect=AssertionError("Popen effect")
    ):
        expect_system_exit(
            lambda: fleet.runtime_control_socket_path(old_root, 1, 1),
            "portable bound",
        )

    fleet.require_runtime_control_socket_path_bound("a" * 100)
    expect_system_exit(
        lambda: fleet.require_runtime_control_socket_path_bound("a" * 101),
        "portable bound",
    )
    assert len(("é" * 50).encode("utf-8")) == 100
    fleet.require_runtime_control_socket_path_bound("é" * 50)
    expect_system_exit(
        lambda: fleet.require_runtime_control_socket_path_bound("é" * 51),
        "portable bound",
    )
    source = (HERE / "run_network_smoke_fleet.py").read_text(encoding="utf-8")
    layout = "stage_plan = preflight_runtime_layout("
    assert source.index(layout) < source.index("if args.plan_only:")
    assert source.index(layout) < source.index("output.mkdir(")
    assert source.index(layout) < source.index("stages = create_stages(")


def test_layout_tamper_collision_and_negative_preflight_have_no_effects() -> None:
    first = process("alpha", "alpha-route")
    tampered = process(
        "alpha",
        "alpha-route",
        runtime_alias="v001",
        validator_id=first.validator_id,
    )
    with mock.patch.object(
        fleet.pathlib.Path, "mkdir", side_effect=AssertionError("mkdir effect")
    ), mock.patch.object(
        fleet, "run_checked", side_effect=AssertionError("SSH/SCP effect")
    ), mock.patch.object(
        fleet, "write_new", side_effect=AssertionError("output effect")
    ), mock.patch.object(
        fleet.subprocess, "Popen", side_effect=AssertionError("Popen effect")
    ):
        expect_system_exit(
            lambda: fleet.preflight_runtime_layout(
                [tampered],
                "poco-g3-7-20260813T120000Z-00000000",
                pathlib.Path("/evidence/tampered"),
            ),
            "sorted fixed-width mapping",
        )

    duplicates = [first, first]
    expect_system_exit(
        lambda: fleet.preflight_runtime_layout(
            duplicates,
            "poco-g3-7-20260813T120000Z-00000000",
            pathlib.Path("/evidence/duplicate"),
        ),
        "duplicate validator IDs",
    )
    run_id = "poco-g3-7-20260813T120000Z-00000000"
    output = pathlib.Path("/evidence/frozen")
    frozen = fleet.preflight_runtime_layout([first], run_id, output)
    try:
        frozen["alpha"].root = "/tmp/tp3-ffffffffffffffffffff"
    except dataclasses.FrozenInstanceError:
        pass
    else:
        raise AssertionError("frozen host stage accepted mutation")
    tampered_plan = dict(frozen)
    tampered_plan["alpha"] = dataclasses.replace(
        frozen["alpha"], root="/tmp/tp3-ffffffffffffffffffff"
    )
    with mock.patch.object(
        fleet, "_materialize_stages", side_effect=AssertionError("materialized tamper")
    ):
        expect_system_exit(
            lambda: fleet.create_stages(
                tampered_plan, processes=[first], run_id=run_id, output=output
            ),
            "differs from the frozen runtime layout",
        )
    fixtures = process_set([("alpha", "alpha-route"), ("beta", "beta-route")])

    def colliding_stage(**values) -> object:
        return fleet.HostStage(
            values["host_id"],
            values["management"],
            f"{fleet.REMOTE_STAGE_PREFIX}-{'0' * fleet.REMOTE_STAGE_TOKEN_HEX}",
            None,
            values["children"],
        )

    with mock.patch.object(fleet, "_host_stage", side_effect=colliding_stage):
        expect_system_exit(
            lambda: fleet.preflight_runtime_layout(
                fixtures,
                "poco-g3-7-20260813T120000Z-00000000",
                pathlib.Path("/evidence/collision"),
            ),
            "roots collide",
        )


def main() -> None:
    test_unique_json_and_remote_path()
    test_input_symlinks_are_rejected_before_resolution()
    test_process_output_is_file_backed_without_pipe_pressure()
    test_partial_stage_creation_cleans_exact_prior_root()
    test_local_stage_creates_private_deployment_directories()
    test_remote_binary_hash_mismatch_is_rejected()
    test_deploy_uses_frozen_alias_and_observer_stage()
    test_public_projection_and_remote_scp_land_at_exact_alias()
    test_runtime_layout_exact_bounds_aliases_and_old_207_bytes()
    test_layout_tamper_collision_and_negative_preflight_have_no_effects()
    print(
        "poco_g3_network_smoke_fleet_test=passed positives=19 negatives=15 "
        "unique_json=true safe_remote_paths=true input_symlinks_rejected=true file_backed_process_io=true partial_cleanup=true "
        "local_stage_directories=true remote_binary_hash=true frozen_alias_deploy=true exact_scp_alias=true public_schema_unchanged=true "
        "runtime_stage_short=true aliases_100_unique=true socket_bytes_100_accepted=true "
        "socket_bytes_101_rejected=true generation_u64_max_bound=true old_207_rejected=true "
        "layout_collision_rejected=true frozen_stage_plan=true preflight_effects_zero=true plan_only_layout_frozen=true "
        "validator_run_completed=false fault_matrix_completed=false performance_evidence=false "
        "g3_complete=false geo_wan=false production_activation=false"
    )


if __name__ == "__main__":
    main()
