#!/usr/bin/env python3
"""Observe three existing fixed-task controls on the exact, unchanged C1 source.

Run only after the other C1 runner has released the shared target directory.
This runner does not create a checkout, change source, fetch, or publish.
Its successful tests establish arithmetic identity and accounting controls;
they do not establish learned model utility, public rewards, or activation.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time


HEAD = "c2d67c5cf1ebb4caac525802362d5746b8fd957d"
ROOT = Path("/home/qian-qi/work/chain-pon-outcome-7612-publish")
TARGET = Path("/home/qian-qi/work/chain-pon-outcome-7612-qualified-target")
OUT = Path("/home/qian-qi/work/chain-pon-outcome-7612-fixed-task-c1")
TOOLCHAIN = "1.95.0"
CONTROLS = (
    (
        "crypto-fixed-product-meter",
        "trnm-crypto-primitives",
        ("--test", "qualified_work_task"),
        "repeated_challenges_bind_one_product_meter_and_maintenance_produces_no_learning_credit",
    ),
    (
        "node-single-output-owner",
        "trnm-pon-node",
        ("--test", "qualified_tasks"),
        "registered_task_mines_real_work_and_counts_one_output_across_fresh_challenges",
    ),
    (
        "crypto-fresh-challenge-refusal",
        "trnm-crypto-primitives",
        ("--lib",),
        "pon_work::legal_attempt::tests::changed_challenge_and_task_never_gain_acceptance_from_cached_product",
    ),
)


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main():
    # Exclusive creation preserves every earlier attempt instead of replaying
    # into its logs. Keep this output outside the exact-source checkout.
    OUT.mkdir(mode=0o700)
    env = os.environ.copy()
    env["PATH"] = "/home/qian-qi/.cargo/bin:" + env.get("PATH", "")
    env["RUSTUP_TOOLCHAIN"] = TOOLCHAIN
    env["CARGO_TARGET_DIR"] = str(TARGET)
    env["CARGO_BUILD_JOBS"] = "2"
    env["CARGO_NET_OFFLINE"] = "true"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    records = []
    failure = None
    started = stamp()

    def manifest():
        value = {
            "schema": "pon-fixed-task-command-observation-v1",
            "source_head": HEAD,
            "source_root": str(ROOT),
            "target_directory": str(TARGET),
            "started_utc": started,
            "updated_utc": stamp(),
            "scope": "existing-native-arithmetic-and-output-accounting-controls",
            "model_training_exercised": False,
            "model_efficacy_certified": False,
            "public_reward_qualification": False,
            "production_activation": False,
            "failure": failure,
            "commands": records,
        }
        temporary = OUT / "commands.json.tmp"
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        temporary.replace(OUT / "commands.json")

    def run(label, command, *, timeout=1800, required=False, exact_test=False):
        stdout_path, stderr_path = OUT / (label + ".stdout"), OUT / (label + ".stderr")
        begin, clock = stamp(), time.monotonic()
        code, timed_out, interrupted, execution_error = None, False, False, None
        print("BEGIN", label, begin, flush=True)
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            try:
                child = subprocess.Popen(
                    command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr,
                    stdin=subprocess.DEVNULL, start_new_session=True,
                )
                try:
                    code = child.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    # Only this subprocess's new session belongs to this runner.
                    try:
                        os.killpg(child.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        code = child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        code = child.wait(timeout=10)
                except KeyboardInterrupt:
                    interrupted = True
                    try:
                        os.killpg(child.pid, signal.SIGINT)
                    except ProcessLookupError:
                        pass
                    try:
                        code = child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        code = child.wait(timeout=10)
            except OSError as error:
                execution_error = str(error)
                stderr.write((execution_error + "\n").encode())
            except subprocess.TimeoutExpired:
                execution_error = "owned command did not terminate within the cancellation bound"
                stderr.write((execution_error + "\n").encode())

        output = stdout_path.read_text(errors="replace")
        diagnostics = stderr_path.read_text(errors="replace")
        counts = re.findall(
            r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",
            output,
        )
        one_test_passed = not exact_test or counts == [("1", "0", "0")]
        unqualified = "trnm SQLite I/O boundary UNQUALIFIED:" in diagnostics
        accepted = code == 0 and not timed_out and not interrupted and execution_error is None and one_test_passed and not unqualified
        source_report = OUT / (label + ".json")
        row = {
            "label": label, "command": command, "cwd": str(ROOT),
            "started_utc": begin, "finished_utc": stamp(),
            "elapsed_seconds": round(time.monotonic() - clock, 6),
            "exit_code": code, "timed_out": timed_out, "interrupted": interrupted,
            "execution_error": execution_error,
            "exact_test_required": exact_test,
            "test_harness_counts": counts,
            "exactly_one_test_passed": one_test_passed if exact_test else None,
            "sqlite_unqualified_diagnostic": unqualified,
            "observation_accepted": accepted,
            "stdout": stdout_path.name, "stderr": stderr_path.name,
            "stdout_sha256": digest(stdout_path), "stderr_sha256": digest(stderr_path),
            "source_report_sha256": digest(source_report) if label.startswith("source-") and source_report.is_file() else None,
        }
        record_path = OUT / (label + ".command.json")
        with record_path.open("x") as stream:
            stream.write(json.dumps(row, indent=2, sort_keys=True) + "\n")
        records.append(dict(row, record=record_path.name, record_sha256=digest(record_path)))
        manifest()
        print("END", label, code, "timeout", timed_out, "accepted", accepted, flush=True)
        if interrupted or execution_error is not None:
            raise RuntimeError("command interrupted or unavailable: " + label)
        if required and not accepted:
            raise RuntimeError("required preparation/source check failed: " + label)
        return row

    def source(label):
        return run(label, [
            "python3", "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
            "--expected-head", HEAD, "--output", str(OUT / (label + ".json")),
        ], required=label == "source-before")

    manifest()
    try:
        run("project-boundary-before", ["bash", "scripts/project-preflight.sh"], required=True)
        source("source-before")
        tools = {}
        for name in ("cargo", "rustc", "rustdoc"):
            label = "locate-" + name
            run(label, ["rustup", "which", "--toolchain", TOOLCHAIN, name], required=True)
            path = Path((OUT / (label + ".stdout")).read_text().strip())
            if not path.is_absolute() or not path.is_file():
                raise RuntimeError("toolchain did not supply an existing absolute " + name)
            tools[name] = path.resolve(strict=True)
            if tools[name].name != name:
                raise RuntimeError("unexpected canonical toolchain binary: " + name)
        env["RUSTC"], env["RUSTDOC"] = str(tools["rustc"]), str(tools["rustdoc"])
        env["PATH"] = str(tools["cargo"].parent) + ":" + env["PATH"]
        environment = {key: env.get(key) for key in (
            "RUSTUP_TOOLCHAIN", "RUSTC", "RUSTDOC", "CARGO_HOME",
            "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_NET_OFFLINE",
        )}
        environment["lock_sha256"] = digest(ROOT / "trillionnium/Cargo.lock")
        environment["script_sha256"] = digest(Path(__file__))
        with (OUT / "environment.json").open("x") as stream:
            stream.write(json.dumps(environment, indent=2, sort_keys=True) + "\n")
        run("toolchain", [str(tools["rustc"]), "-Vv"], required=True)
        if "release: 1.95.0\n" not in (OUT / "toolchain.stdout").read_text():
            raise RuntimeError("unexpected rustc release")
        run("cargo-version", [str(tools["cargo"]), "-Vv"], required=True)
        prefix = [str(tools["cargo"]), "test", "--locked", "--offline",
                  "--manifest-path", "trillionnium/Cargo.toml"]
        for label, package, target, selector in CONTROLS:
            run(label, prefix + ["-p", package, *target, selector, "--", "--exact",
                                 "--nocapture", "--test-threads=1"],
                timeout=3600, exact_test=True)
    except Exception as error:
        failure = str(error)
        print("RUNNER_FAILURE", failure, file=sys.stderr, flush=True)
    finally:
        try:
            source("source-after")
        except Exception as error:
            failure = (failure + "; " if failure else "") + "source-after: " + str(error)
        manifest()

    completed = {row["label"] for row in records}
    passed = failure is None and all(row["observation_accepted"] for row in records)
    passed = passed and {row[0] for row in CONTROLS}.issubset(completed)
    summary = {
        "source_head": HEAD, "result": "PASS" if passed else "FAIL",
        "failed_commands": [row["label"] for row in records if not row["observation_accepted"]],
        "failure": failure, "model_efficacy_certified": False,
        "production_activation": False,
    }
    with (OUT / "summary.json").open("x") as stream:
        stream.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print("FIXED_TASK_CONTROLS_FINISHED", json.dumps(summary, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
