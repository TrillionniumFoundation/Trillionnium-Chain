#!/usr/bin/env python3
"""Place only an exact original campaign phase ELF under the fixed public Host.

The original controller and hostile children remain in the separately observed
400% / 16 GiB campaign process group. No build runs here. This launcher can
provision the reviewed fixed parent only on the explicitly selected hosted CI;
it never changes an existing parent or substitutes a successful native result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

from public_host_ci_observation import (
    PARENT,
    RUNTIME_UNIT,
    UNIT,
    UNIT_SHA256,
    capture,
    validate,
    write_new,
)

ROOT = Path(__file__).resolve().parents[2]
PROFILE = "fixed-public-phase-external-actors-v1"
SELECTOR = "multiprocess_phase_owner_entry"
PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "FragmentPath",
    "SourcePath",
    "DropInPaths",
    "ControlGroup",
    "Transient",
    "Job",
)
FIELDS = {
    "schema",
    "phase_path",
    "controller_cgroup",
    "binary_sha256",
    "state_backend",
    "work_profile",
    "mode",
    "method",
    "seed",
    "business",
}
JOB_LIMIT = 4 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def unique_object(pairs):
    value = {}
    for key, field in pairs:
        require(key not in value, "DUPLICATE_JOB_FIELD")
        value[key] = field
    return value


def validate_job(job_path, binary):
    for path in (job_path, binary):
        require(
            path.is_absolute()
            and not path.is_symlink()
            and path.is_file()
            and path.resolve(strict=True) == path,
            "REGULAR_EXACT_ABSOLUTE_INPUT",
        )
    require(not job_path.is_relative_to(ROOT), "OUTPUT_OUTSIDE_SOURCE")
    with job_path.open("rb") as stream:
        raw = stream.read(JOB_LIMIT + 1)
    require(len(raw) <= JOB_LIMIT, "BOUNDED_PHASE_JOB")
    value = json.loads(raw, object_pairs_hook=unique_object)
    require(
        type(value) is dict and set(value) == FIELDS and value["schema"] == PROFILE,
        "EXACT_PHASE_JOB_SCHEMA",
    )
    phase = Path(value["phase_path"])
    require(
        phase.is_absolute()
        and phase.parent == job_path.parent.parent
        and phase.name in ("baseline", "from-zero", "late-product")
        and job_path.parent.name == phase.name + "-host-control"
        and job_path.name == "phase-job.json",
        "OWNED_PHASE_PATH",
    )
    require(
        value["mode"] == (None if phase.name == "baseline" else phase.name),
        "ORIGINAL_PHASE_MODE",
    )
    require(
        value["state_backend"] in ("legacy-v2", "authenticated-v1")
        and value["work_profile"] in ("raw-r14", "arithmetic-facts-v1"),
        "ORIGINAL_PHASE_PROFILE",
    )
    require(
        type(value["method"]) is int and 0 <= value["method"] < 8,
        "ORIGINAL_PRODUCER_METHOD",
    )
    require(
        type(value["seed"]) is list
        and len(value["seed"]) == 4
        and type(value["business"]) is list
        and len(value["business"]) == 21,
        "ORIGINAL_COMPLETE_INPUT_DENOMINATOR",
    )
    require(
        all(
            type(packet) is str
            and len(packet) % 2 == 0
            and re.fullmatch("[0-9a-f]+", packet)
            for packet in value["seed"] + value["business"]
        ),
        "CANONICAL_PACKET_BYTES",
    )
    require(
        re.fullmatch("[0-9a-f]{64}", value["binary_sha256"]) is not None
        and digest(binary) == value["binary_sha256"],
        "EXACT_PREBUILT_ELF",
    )
    with binary.open("rb") as stream:
        require(stream.read(4) == b"\x7fELF", "NATIVE_ELF_REQUIRED")
    return value, hashlib.sha256(raw).hexdigest()


def unused_parent(raw):
    require(0 < len(raw) <= 65536 and "\x00" not in raw, "BOUNDED_PARENT_PROPERTIES")
    values = {}
    for line in raw.splitlines():
        name, separator, value = line.partition("=")
        require(
            separator and name in PROPERTIES and name not in values,
            "EXACT_PARENT_PROPERTIES",
        )
        values[name] = value
    require(set(values) == set(PROPERTIES), "COMPLETE_PARENT_PROPERTIES")
    require(
        values["Id"] == UNIT
        and values["LoadState"] in ("loaded", "not-found")
        and values["ActiveState"] == "inactive"
        and values["SubState"] == "dead"
        and values["Transient"] == "no"
        and values["Job"] in ("", "0"),
        "PARENT_ALREADY_OWNED",
    )
    require(
        all(
            values[name] == ""
            for name in ("FragmentPath", "SourcePath", "DropInPaths", "ControlGroup")
        ),
        "PARENT_ALREADY_CONFIGURED",
    )
    return values


def controller_context(expected):
    value = Path("/proc/thread-self/cgroup").read_text().strip()
    require(
        value == "0::" + expected
        and expected.startswith("/")
        and not expected.startswith("/trnmponpublic.slice")
        and not any(part in ("", ".", "..") for part in expected[1:].split("/")),
        "ORIGINAL_EXTERNAL_CONTROLLER_CGROUP",
    )
    path = Path("/sys/fs/cgroup") / expected.lstrip("/")
    limits = {
        name: (path / name).read_text().strip() for name in ("cpu.max", "memory.max")
    }
    require(
        limits == {"cpu.max": "400000 100000", "memory.max": "17179869184"},
        "ORIGINAL_EXTERNAL_CONTROLLER_LIMITS",
    )
    return {"actual_thread_cgroup": value, "limits": limits}


def command(job, binary, service, uid, gid):
    return [
        "sudo",
        "-n",
        "systemd-run",
        "--unit=" + service,
        "--wait",
        "--pipe",
        "--collect",
        "--service-type=exec",
        "--expand-environment=no",
        "--slice=" + UNIT,
        "--uid=" + str(uid),
        "--gid=" + str(gid),
        "--working-directory=" + str(ROOT),
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=20s",
        "--property=RuntimeMaxSec=300s",
        "--property=Nice=10",
        "--property=Delegate=no",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=",
        "--setenv=PATH=" + os.environ["PATH"],
        "--setenv=PYTHONDONTWRITEBYTECODE=1",
        sys.executable,
        str(Path(__file__).resolve()),
        "--inside",
        "--job",
        str(job),
        "--binary",
        str(binary),
        "--service",
        service,
        "--uid",
        str(uid),
        "--gid",
        str(gid),
    ]


def inside(job_path, binary, service, uid, gid):
    value, job_sha = validate_job(job_path, binary)
    output = job_path.parent / "host"
    before = capture("public-phase-before", service)
    errors = validate(before, inside=True, uid=uid, gid=gid, cwd=str(ROOT))
    if os.getpriority(os.PRIO_PROCESS, 0) != 10:
        errors.append("ORIGINAL_NICE_10_REQUIRED")
    write_new(output / "inside-before.json", before)
    result = {
        "schema": PROFILE,
        "job_sha256": job_sha,
        "binary_sha256": digest(binary),
        "host_errors": errors,
        "native_child_exit": None,
        "native_selector": SELECTOR,
        "runtime_business_deadline_changed": False,
        "consensus_or_model_authority": False,
    }
    native = [
        str(binary),
        "--exact",
        SELECTOR,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]
    result["native_argv"] = native
    try:
        require(not errors, "ACTUAL_FIXED_HOST_REQUIRED")
        # Entire original phase runs in this process domain; its broker sends
        # attacker lifecycle requests to the original external controller.
        env = dict(os.environ, TRNM_MULTIPROCESS_PHASE_JOB=str(job_path))
        with (
            (output / "native.stdout.txt").open("xb") as stdout,
            (output / "native.stderr.txt").open("xb") as stderr,
        ):
            process = subprocess.run(
                native, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, timeout=295
            )
        result["native_child_exit"] = process.returncode
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result["native_failure"] = str(error)
    finally:
        after = capture("public-phase-after", service)
        write_new(output / "inside-after.json", after)
        result["host_errors"] += validate(
            after, inside=True, uid=uid, gid=gid, cwd=str(ROOT), reference=before
        )
        result["binary_sha256_after"] = digest(binary)
        if (
            result["binary_sha256_after"] != value["binary_sha256"]
            or digest(job_path) != job_sha
        ):
            result["host_errors"].append("EXECUTED_INPUT_CHANGED")
        write_new(output / "child-result.json", result)
    return 0 if result["native_child_exit"] == 0 and not result["host_errors"] else 1


class Interrupted(Exception):
    def __init__(self, number):
        self.number = number


def outer(job_path, binary):
    value, job_sha = validate_job(job_path, binary)
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("CI") == "true"
        and Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve() == ROOT,
        "HOSTED_CI_ONLY_NO_LOCAL_PROVISION",
    )
    require(
        Path.cwd().resolve() == ROOT and os.getuid() != 0,
        "ORIGINAL_UNPRIVILEGED_CONTROLLER",
    )
    run, attempt, job = (
        os.environ.get(name, "")
        for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")
    )
    require(
        run.isdecimal()
        and attempt.isdecimal()
        and re.fullmatch("[A-Za-z0-9_-]{1,80}", job),
        "BOUNDED_CI_IDENTITY",
    )
    service = f"trnm-phase-{run}-{attempt}-{job}-{os.getpid()}.service"
    output = job_path.parent / "host"
    output.mkdir(exist_ok=False)
    uid, gid = os.getuid(), os.getgid()
    result = {
        "schema": PROFILE,
        "job_sha256": job_sha,
        "binary_sha256": digest(binary),
        "service": service,
        "failure": None,
        "systemd_run_exit": None,
        "passed": False,
        "host_readiness_only": True,
        "service_or_depletion_criteria_met": False,
        "consensus_or_model_authority": False,
    }
    owned = False
    reference = None

    def run_setup(args, name, check=True):
        with (output / (name + ".log")).open("xb") as stream:
            process = subprocess.run(
                args, stdout=stream, stderr=subprocess.STDOUT, timeout=30
            )
        require(not check or process.returncode == 0, name + "_FAILED")
        return process.returncode

    def interrupted(number, _frame):
        raise Interrupted(number)

    old_handlers = {
        number: signal.signal(number, interrupted)
        for number in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        result["controller_before"] = controller_context(value["controller_cgroup"])
        require(
            Path("/run/systemd/system").is_dir()
            and Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
            "SYSTEMD_CGROUP_V2_REQUIRED",
        )
        unit = ROOT / "config/systemd" / UNIT
        require(digest(unit) == UNIT_SHA256, "REVIEWED_FIXED_UNIT_BYTES")
        # Multiple phases reuse the SAME pre-existing checked parent. No new
        # budget, parent name, wider limits, replacement or local install path.
        if (
            PARENT.exists()
            or RUNTIME_UNIT.exists()
            or PARENT.is_symlink()
            or RUNTIME_UNIT.is_symlink()
        ):
            require(
                PARENT.exists()
                and RUNTIME_UNIT.is_file()
                and not PARENT.is_symlink()
                and not RUNTIME_UNIT.is_symlink(),
                "PARTIAL_OR_SYMLINK_PARENT",
            )
            result["parent_preexisting"] = True
        else:
            run_setup(
                [
                    "systemctl",
                    "show",
                    "--all",
                    "--property=" + ",".join(PROPERTIES),
                    UNIT,
                ],
                "unprovisioned-parent",
            )
            write_new(
                output / "unprovisioned-parent.json",
                unused_parent((output / "unprovisioned-parent.log").read_text()),
            )
            require(
                not PARENT.exists() and not RUNTIME_UNIT.exists(),
                "PARENT_CHANGED_BEFORE_INSTALL",
            )
            run_setup(
                [
                    "sudo",
                    "-n",
                    "install",
                    "-o",
                    "root",
                    "-g",
                    "root",
                    "-m",
                    "0644",
                    str(unit),
                    str(RUNTIME_UNIT),
                ],
                "install-reviewed-unit",
            )
            run_setup(["sudo", "-n", "systemctl", "daemon-reload"], "reload")
            run_setup(["sudo", "-n", "systemctl", "start", UNIT], "start-fixed-parent")
            result["parent_preexisting"] = False
        reference = capture("external-controller-before-public-phase", service)
        write_new(output / "outside-before.json", reference)
        require(
            not validate(reference, inside=False, uid=uid, gid=gid, cwd=str(ROOT)),
            "ACTUAL_FIXED_PARENT_REQUIRED",
        )
        run_setup(
            ["systemctl", "show", "--property=LoadState", "--value", service],
            "child-load-state",
            check=False,
        )
        require(
            (output / "child-load-state.log").read_text().strip() == "not-found",
            "UNIQUE_CHILD_SERVICE_REQUIRED",
        )
        owned = True
        args = command(job_path, binary, service, uid, gid)
        result["systemd_argv"] = args
        with (output / "systemd-run.log").open("xb") as stream:
            process = subprocess.run(
                args, stdout=stream, stderr=subprocess.STDOUT, timeout=325
            )
        result["systemd_run_exit"] = process.returncode
        child = json.loads((output / "child-result.json").read_text())
        require(
            child["job_sha256"] == job_sha
            and child["binary_sha256"]
            == value["binary_sha256"]
            == child["binary_sha256_after"]
            and not child["host_errors"]
            and child["native_selector"] == SELECTOR,
            "EXACT_CHILD_EXECUTION_REQUIRED",
        )
        for name in ("inside-before.json", "inside-after.json"):
            observed = json.loads((output / name).read_text())
            require(
                not validate(
                    observed,
                    inside=True,
                    uid=uid,
                    gid=gid,
                    cwd=str(ROOT),
                    reference=reference,
                ),
                "PUBLIC_PHASE_HOST_CHANGED",
            )
        result["passed"] = process.returncode == 0 and child["native_child_exit"] == 0
    except Interrupted as error:
        result.update(
            failure="SIGNAL_" + str(error.number),
            passed=False,
            systemd_run_exit=128 + error.number,
        )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as error:
        result.update(failure=str(error), passed=False)
    finally:
        for number, handler in old_handlers.items():
            signal.signal(number, handler)
        if owned:
            try:
                run_setup(
                    ["systemctl", "show", "--property=LoadState", "--value", service],
                    "child-final-load-state",
                    check=False,
                )
                if (
                    output / "child-final-load-state.log"
                ).read_text().strip() == "not-found":
                    result["cleanup"] = "already-collected"
                else:
                    run_setup(
                        ["sudo", "-n", "systemctl", "stop", service], "stop-owned-child"
                    )
                    result["cleanup"] = "owned-child-stopped"
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                result.update(cleanup=str(error), passed=False)
        after = capture("external-controller-after-public-phase", service)
        write_new(output / "outside-after.json", after)
        if reference is not None:
            result["final_host_errors"] = validate(
                after,
                inside=False,
                uid=uid,
                gid=gid,
                cwd=str(ROOT),
                reference=reference,
            )
            if result["final_host_errors"]:
                result["passed"] = False
        try:
            result["controller_after"] = controller_context(value["controller_cgroup"])
            require(
                digest(binary) == value["binary_sha256"]
                and digest(job_path) == job_sha,
                "CONTROLLER_INPUT_CHANGED",
            )
        except (OSError, ValueError) as error:
            result.update(final_input_error=str(error), passed=False)
        write_new(output / "controller-result.json", result)
    print(
        json.dumps(
            {
                "schema": PROFILE,
                "passed": result["passed"],
                "failure": result["failure"],
            }
        )
    )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--service")
    parser.add_argument("--uid", type=int)
    parser.add_argument("--gid", type=int)
    options = parser.parse_args()
    if options.inside:
        require(
            options.service is not None
            and options.uid is not None
            and options.gid is not None,
            "EXACT_INSIDE_CONTEXT",
        )
        raise SystemExit(
            inside(
                options.job, options.binary, options.service, options.uid, options.gid
            )
        )
    require(
        options.service is None and options.uid is None and options.gid is None,
        "NO_OUTSIDE_CONTEXT_OVERRIDE",
    )
    raise SystemExit(outer(options.job, options.binary))
