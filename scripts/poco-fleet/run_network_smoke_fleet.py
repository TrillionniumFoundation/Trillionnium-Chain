#!/usr/bin/env python3
"""Run the bounded authenticated TCP smoke profile on the six-host G3 fleet.

This is deliberately not a consensus runner.  It deploys one already-verified
least-authority validator root per Linux process, starts the existing
``network-smoke`` command concurrently, collects its validator-signed reports,
and has the frozen macOS observer binary verify every report from the
secret-free observer bundle.  The emitted summary always keeps validator,
fault, performance, production, and geo-WAN claims false.

The coordinator root is used only for an out-of-band manifest digest and the
deployment verifier.  It is never copied to a host.  Remote staging roots are
fresh, private, run-specific directories and are removed on every exit.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
CHECK_DEPLOYMENTS = HERE / "check_validator_deployments.py"
RUN_ID = re.compile(r"^poco-g3-(7|31|100)-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
VALIDATOR_ID = re.compile(r"^[0-9a-f]{64}$")
HOST_ID = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REMOTE_STAGE_PREFIX = "/tmp/trnm-poco-g3-network-smoke"
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_PROCESS_IO_BYTES = 16 * 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 network-smoke fleet failed: {message}")


def strict_json_bytes(raw: bytes, field: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError(f"{field} contains duplicate JSON key {key!r}")
            value[key] = child
        return value

    try:
        return json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        fail(f"cannot decode {field}: {error}")


def read_json(path: pathlib.Path, field: str) -> Any:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        fail(f"{field} is not one regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_REPORT_BYTES:
        fail(f"{field} size crosses its bound")
    return strict_json_bytes(path.read_bytes(), field)


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def write_new(path: pathlib.Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def require_private_directory(path: pathlib.Path, field: str) -> pathlib.Path:
    unresolved = path.absolute()
    metadata = unresolved.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail(f"{field} must be one real directory")
    resolved = unresolved.resolve(strict=True)
    if resolved != unresolved:
        fail(f"{field} must not traverse a symbolic link")
    return resolved


def require_binary(path: pathlib.Path, expected: str, field: str) -> pathlib.Path:
    unresolved = path.absolute()
    metadata = unresolved.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or not os.access(unresolved, os.X_OK)
    ):
        fail(f"{field} must be one executable regular non-symlink file")
    resolved = unresolved.resolve(strict=True)
    if resolved != unresolved:
        fail(f"{field} must not traverse a symbolic link")
    if not HEX64.fullmatch(expected) or sha256_file(resolved) != expected:
        fail(f"{field} differs from the frozen coordinator manifest")
    return resolved


def run_checked(arguments: list[str], *, timeout: int, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        arguments,
        input=input_bytes,
        check=True,
        capture_output=True,
        timeout=timeout,
    )


@dataclasses.dataclass(frozen=True)
class ValidatorProcess:
    validator_id: str
    host_id: str
    management: str
    deployment: pathlib.Path
    config_relative: pathlib.PurePosixPath


@dataclasses.dataclass
class HostStage:
    host_id: str
    management: str
    root: str
    local_path: pathlib.Path | None

    @property
    def remote(self) -> bool:
        return self.management != "local"


@dataclasses.dataclass
class ProcessCapture:
    stdout_path: pathlib.Path
    stderr_path: pathlib.Path
    stdout: Any
    stderr: Any


def open_process_capture(root: pathlib.Path, validator_id: str) -> ProcessCapture:
    """Open bounded per-process files before spawning a validator.

    Validators can emit output concurrently without filling coordinator-side
    pipes while another child is being awaited.  The output root is already a
    fresh mode-0700 evidence directory, and O_EXCL prevents accidental reuse.
    """

    stdout_path = root / f"{validator_id}.stdout"
    stderr_path = root / f"{validator_id}.stderr"
    streams: list[Any] = []
    try:
        for path in (stdout_path, stderr_path):
            descriptor = os.open(
                path,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            streams.append(os.fdopen(descriptor, "w+b", buffering=0))
    except BaseException:
        for stream in streams:
            stream.close()
        raise
    return ProcessCapture(
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        stdout=streams[0],
        stderr=streams[1],
    )


def close_process_capture(capture: ProcessCapture) -> None:
    """Durably close any still-open process output without reading it."""

    first_error: OSError | None = None
    for stream in (capture.stdout, capture.stderr):
        if stream.closed:
            continue
        try:
            stream.flush()
            os.fsync(stream.fileno())
        except OSError as error:
            if first_error is None:
                first_error = error
        finally:
            stream.close()
    if first_error is not None:
        raise first_error


def finish_process_capture(capture: ProcessCapture) -> tuple[bytes, bytes]:
    """Seal and return one child's bounded stdout/stderr observations."""

    values: list[bytes] = []
    for stream, field in (
        (capture.stdout, "validator stdout"),
        (capture.stderr, "validator stderr"),
    ):
        if stream.closed:
            raise RuntimeError("process output capture was finalized more than once")
        stream.flush()
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"{field} is not one regular file")
        if metadata.st_size == 0:
            stream.write(b"\n")
            metadata = os.fstat(stream.fileno())
        if metadata.st_size <= 0 or metadata.st_size > MAX_PROCESS_IO_BYTES:
            raise RuntimeError(f"{field} size crosses its bound")
        os.fsync(stream.fileno())
        stream.seek(0)
        raw = stream.read(MAX_PROCESS_IO_BYTES + 1)
        stream.close()
        if len(raw) != metadata.st_size:
            raise RuntimeError(f"{field} changed while it was being sealed")
        values.append(raw)
    return values[0], values[1]


def load_contract(
    coordinator: pathlib.Path,
    deployments: pathlib.Path,
    validator_count: int,
) -> tuple[dict[str, Any], dict[str, Any], list[ValidatorProcess]]:
    run_checked(
        [
            sys.executable,
            str(CHECK_DEPLOYMENTS),
            str(coordinator),
            str(deployments),
            "--validators",
            str(validator_count),
        ],
        timeout=180,
    )
    manifest = read_json(coordinator / "manifest.json", "coordinator manifest")
    topology = read_json(coordinator / "topology.json", "topology")
    if not isinstance(manifest, dict) or not isinstance(topology, dict):
        fail("coordinator manifest/topology must be JSON objects")
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        fail("coordinator run_id is not canonical")
    if manifest.get("validator_count") != validator_count:
        fail("coordinator validator count differs from command")
    candidate = manifest.get("candidate")
    if not isinstance(candidate, dict):
        fail("coordinator candidate is absent")
    participants = topology.get("participants")
    validators = topology.get("validators")
    if not isinstance(participants, list) or not isinstance(validators, list):
        fail("topology participant/validator inventory is absent")
    management: dict[str, str] = {}
    for participant in participants:
        if not isinstance(participant, dict):
            fail("topology participant is not an object")
        host_id = participant.get("host_id")
        selected = participant.get("management")
        if (
            not isinstance(host_id, str)
            or not HOST_ID.fullmatch(host_id)
            or not isinstance(selected, str)
            or not selected
            or host_id in management
        ):
            fail("topology management inventory is non-canonical")
        management[host_id] = selected
    processes: list[ValidatorProcess] = []
    for record in validators:
        if not isinstance(record, dict):
            fail("topology validator is not an object")
        validator_id = record.get("validator_id")
        host_id = record.get("host_id")
        if (
            not isinstance(validator_id, str)
            or not VALIDATOR_ID.fullmatch(validator_id)
            or not isinstance(host_id, str)
            or host_id not in management
        ):
            fail("topology validator identity is non-canonical")
        root = deployments / validator_id
        if root.resolve(strict=True).parent != deployments:
            fail("validator deployment escapes deployment root")
        processes.append(
            ValidatorProcess(
                validator_id=validator_id,
                host_id=host_id,
                management=management[host_id],
                deployment=root,
                config_relative=pathlib.PurePosixPath(
                    f"public/configs/{validator_id}.json"
                ),
            )
        )
    if len(processes) != validator_count:
        fail("topology process count differs from command")
    return manifest, topology, processes


def shell_path(value: str) -> str:
    if not value.startswith(f"{REMOTE_STAGE_PREFIX}-") or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-."
        for character in value
    ):
        fail("generated remote stage path is unsafe")
    return shlex.quote(value)


def create_stages(
    processes: list[ValidatorProcess],
    run_id: str,
    output: pathlib.Path,
) -> dict[str, HostStage]:
    stages: dict[str, HostStage] = {}
    try:
        for process in processes:
            if process.host_id in stages:
                if stages[process.host_id].management != process.management:
                    fail("one host has conflicting management routes")
                continue
            nonce = hashlib.sha256(
                f"{run_id}\0{process.host_id}\0{output}".encode("utf-8")
            ).hexdigest()[:12]
            name = f"{REMOTE_STAGE_PREFIX}-{run_id}-{process.host_id}-{nonce}"
            if process.management == "local":
                path = pathlib.Path(name)
                if path.exists() or path.is_symlink():
                    fail("local stage already exists")
                path.mkdir(mode=0o700)
                stage = HostStage(
                    process.host_id, process.management, str(path), path
                )
                # Register the root before creating children so any partial
                # local stage is removed by the shared exception cleanup.
                stages[process.host_id] = stage
                (path / "bin").mkdir(mode=0o700)
                (path / "validators").mkdir(mode=0o700)
            else:
                quoted = shell_path(name)
                # Register the attempted root before the remote mutation. A
                # failed compound mkdir may still have created its first
                # directory, so the outer exception handler must clean it.
                stages[process.host_id] = HostStage(
                    process.host_id, process.management, name, None
                )
                command = (
                    f"set -eu; umask 077; test ! -e {quoted}; "
                    f"mkdir -m 700 {quoted}; mkdir -m 700 {quoted}/bin {quoted}/validators"
                )
                run_checked(
                    [
                        "ssh",
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "ConnectTimeout=15",
                        process.management,
                        command,
                    ],
                    timeout=30,
                )
    except BaseException:
        clean_stages(stages)
        raise
    return stages


def copy_directory(source: pathlib.Path, stage: HostStage, relative: str) -> None:
    if stage.remote:
        destination = f"{stage.management}:{stage.root}/{relative}"
        run_checked(
            ["scp", "-q", "-r", str(source), destination],
            timeout=300,
        )
    else:
        assert stage.local_path is not None
        destination = stage.local_path / relative / source.name
        shutil.copytree(source, destination, symlinks=True)


def copy_binary(
    source: pathlib.Path,
    stage: HostStage,
    name: str,
    expected_sha256: str,
) -> str:
    if not HEX64.fullmatch(expected_sha256):
        fail("deployed binary hash is not canonical")
    relative = f"bin/{name}"
    if stage.remote:
        destination = f"{stage.management}:{stage.root}/{relative}"
        run_checked(["scp", "-q", str(source), destination], timeout=300)
        quoted = shell_path(f"{stage.root}/{relative}")
        verified = run_checked(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                stage.management,
                (
                    "set -eu; "
                    f"chmod 500 {quoted}; "
                    "if command -v sha256sum >/dev/null 2>&1; then "
                    f"sha256sum {quoted} | awk '{{print $1}}'; "
                    "else "
                    f"shasum -a 256 {quoted} | awk '{{print $1}}'; "
                    "fi"
                ),
            ],
            timeout=30,
        )
        if verified.stdout.decode("ascii", errors="strict").strip() != expected_sha256:
            fail(f"deployed binary hash differs on host {stage.host_id}")
        return f"{stage.root}/{relative}"
    assert stage.local_path is not None
    target = stage.local_path / relative
    shutil.copyfile(source, target)
    target.chmod(0o500)
    if sha256_file(target) != expected_sha256:
        fail(f"deployed binary hash differs on host {stage.host_id}")
    return str(target)


def deploy(
    stages: dict[str, HostStage],
    processes: list[ValidatorProcess],
    deployments: pathlib.Path,
    linux_binary: pathlib.Path,
    macos_binary: pathlib.Path,
    linux_expected_sha256: str,
    macos_expected_sha256: str,
) -> tuple[dict[str, str], str, str]:
    linux_binary = require_binary(
        linux_binary, linux_expected_sha256, "Linux binary at deployment"
    )
    macos_binary = require_binary(
        macos_binary, macos_expected_sha256, "macOS binary at deployment"
    )
    linux_paths: dict[str, str] = {}
    for host_id, stage in stages.items():
        linux_paths[host_id] = copy_binary(
            linux_binary,
            stage,
            "trnm-poco-lab-validator",
            linux_expected_sha256,
        )
    for process in processes:
        copy_directory(process.deployment, stages[process.host_id], "validators")

    mac_stage = HostStage(
        "mac",
        "p4-mac",
        f"{REMOTE_STAGE_PREFIX}-observer-{hashlib.sha256(str(deployments).encode()).hexdigest()[:16]}",
        None,
    )
    # Register the attempted observer root before its compound remote mkdir;
    # partial remote creation must still be cleaned by the caller.
    stages["mac"] = mac_stage
    quoted = shell_path(mac_stage.root)
    run_checked(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            mac_stage.management,
            (
                f"set -eu; umask 077; test ! -e {quoted}; mkdir -m 700 {quoted}; "
                f"mkdir -m 700 {quoted}/bin {quoted}/observer {quoted}/reports"
            ),
        ],
        timeout=30,
    )
    mac_binary_path = copy_binary(
        macos_binary,
        mac_stage,
        "trnm-poco-lab-validator",
        macos_expected_sha256,
    )
    copy_directory(deployments / "observer-public", mac_stage, "observer")
    observer_root = f"{mac_stage.root}/observer/observer-public"
    return linux_paths, mac_binary_path, observer_root


def command_for(
    process: ValidatorProcess,
    stage: HostStage,
    binary: str,
    rounds: int,
    timeout_seconds: int,
) -> list[str]:
    root = f"{stage.root}/validators/{process.validator_id}"
    config = f"{root}/{process.config_relative.as_posix()}"
    arguments = [
        binary,
        "network-smoke",
        root,
        config,
        str(rounds),
        str(timeout_seconds),
    ]
    if not stage.remote:
        return arguments
    command = " ".join(shlex.quote(value) for value in arguments)
    # Keep the remote process as a child of the SSH channel shell. If the
    # channel dies or the coordinator aborts, its EXIT/HUP/TERM trap kills and
    # reaps the exact child before the private stage is removed.
    remote = (
        "set -eu; child=''; "
        "cleanup() { if test -n \"$child\"; then kill \"$child\" 2>/dev/null || true; "
        "wait \"$child\" 2>/dev/null || true; fi; }; "
        "trap cleanup EXIT HUP INT TERM; "
        f"{command} & child=$!; wait \"$child\"; status=$?; child=''; exit \"$status\""
    )
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        process.management,
        remote,
    ]


def clean_stages(stages: dict[str, HostStage]) -> list[str]:
    failures: list[str] = []
    for stage in stages.values():
        try:
            if stage.remote:
                quoted = shell_path(stage.root)
                run_checked(
                    [
                        "ssh",
                        "-o",
                        "BatchMode=yes",
                        stage.management,
                        f"rm -rf -- {quoted}",
                    ],
                    timeout=60,
                )
            elif stage.local_path is not None:
                shutil.rmtree(stage.local_path)
        except (OSError, subprocess.SubprocessError) as error:
            failures.append(f"{stage.host_id}: {error}")
    return failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("coordinator_root", type=pathlib.Path)
    parser.add_argument("deployment_root", type=pathlib.Path)
    parser.add_argument("--validators", required=True, type=int, choices=(7, 31, 100))
    parser.add_argument("--linux-binary", required=True, type=pathlib.Path)
    parser.add_argument("--macos-binary", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.rounds <= 10_000 or not 10 <= args.timeout_seconds <= 300:
        fail("rounds/timeout cross the frozen bounded profile")

    coordinator = require_private_directory(args.coordinator_root, "coordinator root")
    deployments = require_private_directory(args.deployment_root, "deployment root")
    manifest, _topology, processes = load_contract(
        coordinator, deployments, args.validators
    )
    candidate = manifest["candidate"]
    linux_binary = require_binary(
        args.linux_binary, candidate["linux_x86_64_sha256"], "Linux binary"
    )
    macos_binary = require_binary(
        args.macos_binary, candidate["macos_arm64_sha256"], "macOS binary"
    )
    coordinator_anchor = sha256_file(coordinator / "manifest.json")
    run_id = manifest["run_id"]
    plan = {
        "schema_version": 1,
        "profile": "frozen-v0-authenticated-network-smoke",
        "run_id": run_id,
        "validator_count": args.validators,
        "linux_validator_host_count": len({item.host_id for item in processes}),
        "observer_host_id": "mac",
        "coordinator_manifest_sha256": coordinator_anchor,
        "rounds": args.rounds,
        "timeout_seconds": args.timeout_seconds,
        "validators": [dataclasses.asdict(value) | {"deployment": str(value.deployment), "config_relative": value.config_relative.as_posix()} for value in processes],
        "validator_run_completed": False,
        "fault_matrix_completed": False,
        "performance_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    if args.plan_only:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return

    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        fail("output root already exists; run observations are immutable")
    try:
        output.relative_to(pathlib.Path(__file__).resolve().parents[2])
    except ValueError:
        pass
    else:
        fail("output root must be outside the source tree")
    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)
    write_new(output / "prestart-plan.json", canonical_json(plan))
    # This O_EXCL/fsync record exists before any deployment or process start.
    # It proves local program order, not an external trusted wall clock.
    write_new(
        output / "coordinator-anchor.txt",
        f"{coordinator_anchor}\n".encode("ascii"),
    )

    stages: dict[str, HostStage] = {}
    process_results: list[dict[str, Any]] = []
    reports = output / "signed-reports"
    process_io = output / "process-io"
    for directory in (reports, process_io):
        directory.mkdir(mode=0o700)

    running: list[
        tuple[ValidatorProcess, subprocess.Popen[bytes], ProcessCapture]
    ] = []
    failure: str | None = None
    cleanup_failures: list[str] = []
    try:
        stages = create_stages(processes, run_id, output)
        linux_paths, mac_binary_path, observer_root = deploy(
            stages,
            processes,
            deployments,
            linux_binary,
            macos_binary,
            candidate["linux_x86_64_sha256"],
            candidate["macos_arm64_sha256"],
        )
        started_ns = time.monotonic_ns()
        for process in processes:
            command = command_for(
                process,
                stages[process.host_id],
                linux_paths[process.host_id],
                args.rounds,
                args.timeout_seconds,
            )
            capture = open_process_capture(process_io, process.validator_id)
            try:
                child = subprocess.Popen(
                    command,
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                )
            except BaseException:
                close_process_capture(capture)
                raise
            running.append(
                (
                    process,
                    child,
                    capture,
                )
            )
        deadline = time.monotonic() + args.timeout_seconds + 45
        for process, child, capture in running:
            remaining = deadline - time.monotonic()
            try:
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(child.args, 0)
                child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                child.kill()
                try:
                    child.wait(timeout=10)
                finally:
                    finish_process_capture(capture)
                raise RuntimeError(f"validator {process.validator_id} exceeded fleet deadline")
            stdout, stderr = finish_process_capture(capture)
            if child.returncode != 0:
                raise RuntimeError(
                    f"validator {process.validator_id} exited {child.returncode}: "
                    f"{stderr.decode('utf-8', errors='replace')[:400]}"
                )
            if len(stdout) <= 0 or len(stdout) > MAX_REPORT_BYTES:
                raise RuntimeError(f"validator {process.validator_id} report size is invalid")
            report = strict_json_bytes(stdout, f"signed report {process.validator_id}")
            if not isinstance(report, dict):
                raise RuntimeError(f"validator {process.validator_id} report is not an object")
            report_path = reports / f"{process.validator_id}.json"
            write_new(report_path, canonical_json(report))
            remote_report = f"{stages['mac'].root}/reports/{process.validator_id}.json"
            run_checked(
                ["scp", "-q", str(report_path), f"p4-mac:{remote_report}"],
                timeout=60,
            )
            observer_config = (
                f"{observer_root}/public/configs/{process.validator_id}.json"
            )
            verify = run_checked(
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    "p4-mac",
                    " ".join(
                        shlex.quote(value)
                        for value in (
                            mac_binary_path,
                            "verify-network-report",
                            observer_root,
                            observer_config,
                            remote_report,
                            coordinator_anchor,
                        )
                    ),
                ],
                timeout=60,
            )
            verification = strict_json_bytes(
                verify.stdout, f"observer verification {process.validator_id}"
            )
            report_body = report.get("report")
            if not isinstance(report_body, dict):
                raise RuntimeError(
                    f"signed report {process.validator_id} lacks its report body"
                )
            expected_verification = {
                "schema_version": 1,
                "status": "network-smoke-report-signature-and-semantics-verified",
                "run_id": run_id,
                "validator_id": process.validator_id,
                "validator_set_id": report_body.get("validator_set_id"),
                "topology_sha256": report_body.get("topology_sha256"),
                "coordinator_manifest_sha256": coordinator_anchor,
                "candidate_source_sha256": report_body.get("candidate_source_sha256"),
                "binary_sha256": report_body.get("binary_sha256"),
                "config_sha256": report_body.get("config_sha256"),
                "peer_session_count": len(report_body.get("peer_sessions", [])),
                "validator_run_completed": False,
                "g3_evidence_complete": False,
                "geo_wan_evidence": False,
                "production_activation": False,
            }
            if verification != expected_verification:
                raise RuntimeError(
                    f"observer verification {process.validator_id} lost its exact claim boundary"
                )
            process_results.append(
                {
                    "validator_id": process.validator_id,
                    "host_id": process.host_id,
                    "report_sha256": sha256_file(report_path),
                    "observer_verification": verification,
                }
            )
        elapsed_ns = time.monotonic_ns() - started_ns
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as error:
        failure = str(error)
        elapsed_ns = 0
    finally:
        for _process, child, capture in running:
            if child.poll() is None:
                child.kill()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
            try:
                close_process_capture(capture)
            except OSError:
                pass
        cleanup_failures = clean_stages(stages)

    summary = {
        "schema_version": 1,
        "profile": "frozen-v0-authenticated-network-smoke",
        "run_id": run_id,
        "validator_count": args.validators,
        "signed_report_count": len(process_results),
        "observer_verified_report_count": len(process_results),
        "all_six_hosts_participated": len(process_results) == args.validators,
        "elapsed_monotonic_ns": elapsed_ns,
        "coordinator_manifest_sha256": coordinator_anchor,
        "processes": process_results,
        "failure": failure,
        "cleanup_failures": cleanup_failures,
        "authenticated_fresh_session_multihost_observed": failure is None
        and not cleanup_failures
        and len(process_results) == args.validators,
        "validator_run_completed": False,
        "fault_matrix_completed": False,
        "performance_evidence": False,
        "g3_lan_multihost_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    write_new(output / "network-smoke-summary.json", canonical_json(summary))
    if failure is not None or cleanup_failures or len(process_results) != args.validators:
        fail(f"run failed; preserved evidence at {output}: {failure or cleanup_failures}")
    print(
        f"poco_g3_network_smoke_fleet=passed validators={args.validators} "
        "all_six_hosts=true signed_reports=true macos_cross_verified=true "
        "validator_run_completed=false g3_complete=false geo_wan=false "
        f"output={output}"
    )


if __name__ == "__main__":
    main()
