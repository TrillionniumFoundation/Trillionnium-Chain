#!/usr/bin/env python3
"""Run the exact C2 source gates with the original pinned PQ provider preparation.

Root advances the existing publish checkout before invoking this script. The
runner never fetches, checks out, edits source, changes build gates, or publishes.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

if not __debug__ or sys.flags.optimize != 0 or os.environ.get("PYTHONOPTIMIZE"):
    raise RuntimeError("optimized Python/PYTHONOPTIMIZE is refused before qualification")

ROOT = Path("/home/qian-qi/work/chain-pon-outcome-7612-publish")
TARGET = Path("/home/qian-qi/work/chain-pon-outcome-7612-qualified-target")
CARGO = "/home/qian-qi/.cargo/bin/cargo"
RUSTUP = "/home/qian-qi/.cargo/bin/rustup"
FENCE = "sqlite-3.54.0-normal-native-linux-layout-v4"
PROVIDER_SCRIPT = "scripts/ci/prepare_pq_provider.sh"
PROVIDER_SCRIPT_SHA256 = "ccdcf7e8bb9871607c73adc78624a607b616c227b7fe581b96c48761a3805bfa"
PROVIDER_VERSION = "3.5.9"
PROVIDER_ARCHIVE_SHA256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
PROVIDER_URL = "https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz"
PROVIDER_KEYS = {"OPENSSL_DIR", "OPENSSL_STATIC", "TRNM_PQ_OPENSSL", "TRNM_PQ_OPENSSL_SHA256",
                 "TRNM_PQ_OPENSSL_VERSION", "OPENSSL_CONF", "OPENSSL_MODULES"}
READERS = (
    "test_cell_adoption_readback.py",
    "test_cell_learning_scope_join.py",
    "test_cell_learning_completion_join.py",
    "test_cell_learning_iteration_join.py",
    "test_cell_learning_local_decision_join.py",
    "test_cell_learning_local_use_join.py",
)
NATIVE = (
    ("adoption-library", "trnm-data-availability", ["--lib", "cell::adoption::"], 25, False, False),
    ("adoption-cli", "trnm-data-availability", ["--test", "cell_adoption_cli"], 13, False, False),
    ("outcome-role-separation", "trnm-pon-node", ["--test", "outcome_role_separation"], 1, False, True),
    ("crypto-fixed-product-meter", "trnm-crypto-primitives", ["--test", "qualified_work_task", "repeated_challenges_bind_one_product_meter_and_maintenance_produces_no_learning_credit"], 1, True, False),
    ("node-single-output-owner", "trnm-pon-node", ["--test", "qualified_tasks", "registered_task_mines_real_work_and_counts_one_output_across_fresh_challenges"], 1, True, True),
    ("crypto-fresh-challenge-refusal", "trnm-crypto-primitives", ["--lib", "pon_work::legal_attempt::tests::changed_challenge_and_task_never_gain_acceptance_from_cached_product"], 1, True, False),
)


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def write_new(path, value):
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def regular_file(path):
    require(not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode), "not an ordinary file: " + str(path))
    require(path.resolve(strict=True) == path, "noncanonical provider path: " + str(path))
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)}


def inspect_provider(out, temporary, explicit_source):
    """Bind the original receipt and exported keys to the actual fresh artifacts."""
    exported = out / "provider.env"
    raw = exported.read_bytes()
    require(raw.endswith(b"\n") and b"\r" not in raw and b"\0" not in raw, "invalid provider environment encoding")
    values = {}
    for line in raw.decode().splitlines():
        key, separator, value = line.partition("=")
        require(separator == "=" and key in PROVIDER_KEYS and key not in values and value,
                "unexpected/duplicate provider environment entry")
        values[key] = value
    require(set(values) == PROVIDER_KEYS, "provider did not export exactly the original seven keys")
    path = out / "pq-provider/provider.json"
    receipt = json.loads(path.read_text())
    require(receipt.get("schema") == "trnm-ci-pq-provider-v3" and
            receipt.get("result") == "PREPARED_AND_SMOKE_VERIFIED" and
            type(receipt.get("exit_code")) is int and receipt["exit_code"] == 0 and
            receipt.get("last_stage") == "complete", "original provider preparation did not complete")
    require(receipt.get("version") == PROVIDER_VERSION and receipt.get("source_url") == PROVIDER_URL and
            receipt.get("source_archive_sha256_expected") == PROVIDER_ARCHIVE_SHA256 and
            receipt.get("preparation_script_sha256") == PROVIDER_SCRIPT_SHA256 and
            sha(ROOT / PROVIDER_SCRIPT) == PROVIDER_SCRIPT_SHA256, "original provider/source pin changed")
    for key in ("source_digest_verified", "static_build", "ml_dsa_65_sign_verify_and_wrong_message_rejection", "backend_exported"):
        require(receipt.get(key) is True, "original provider prerequisite is absent: " + key)
    for key in ("upstream_full_tests_run", "native_rust_pq_tests_run_by_preparation",
                "independent_cryptographic_implementation_claim", "whole_chain_quantum_security_qualified", "production_activation"):
        require(receipt.get(key) is False, "provider receipt overstates qualification: " + key)
    transport = "explicit-local-archive" if explicit_source is not None else "download"
    require(receipt.get("source_transport") == transport, "provider source transport differs from this invocation")
    build = Path(receipt["build_directory"])
    prefix = Path(receipt["install_prefix"])
    require(build.parent == temporary and build.name.startswith("trnm-pq-provider-3.5.9.") and
            build.resolve(strict=True) == build and prefix == build / "install" and prefix.resolve(strict=True) == prefix,
            "provider did not build into this invocation's fresh isolated directory")
    archive = regular_file(build / "openssl-3.5.9.tar.gz")
    require(archive["sha256"] == PROVIDER_ARCHIVE_SHA256, "actual provider source archive is not pinned")
    if explicit_source is not None:
        require(regular_file(explicit_source)["sha256"] == PROVIDER_ARCHIVE_SHA256, "explicit source archive changed")
    cli = regular_file(prefix / "bin/openssl")
    expected = {"OPENSSL_DIR": str(prefix), "OPENSSL_STATIC": "1", "TRNM_PQ_OPENSSL": cli["path"],
        "TRNM_PQ_OPENSSL_SHA256": cli["sha256"], "TRNM_PQ_OPENSSL_VERSION": PROVIDER_VERSION,
        "OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": str(prefix / "lib/ossl-modules")}
    require(values == expected and receipt.get("cli_executable") == cli["path"] and
            receipt.get("cli_sha256") == cli["sha256"] and receipt.get("openssl_conf") == "/dev/null" and
            receipt.get("openssl_modules") == values["OPENSSL_MODULES"] and
            isinstance(receipt.get("cli_version_output"), str) and
            receipt["cli_version_output"].startswith("OpenSSL 3.5.9 "), "provider environment/backend identity differs")
    identities = [regular_file(prefix / name) for name in ("bin/openssl", "include/openssl/opensslv.h",
                  "include/openssl/configuration.h", "lib/libcrypto.a", "lib/libssl.a")]
    require(receipt.get("native_backend_inputs") == identities, "installed provider bytes differ from original receipt")
    return {"schema": "chain-c2-provider-byte-observation-v1", "exported_environment": values,
            "environment_file": regular_file(exported), "original_receipt": regular_file(path),
            "original_build_and_smoke_log": regular_file(out / "pq-provider/build-and-smoke.log"),
            "source_archive": archive, "native_backend_inputs": identities,
            "preparation_script_sha256": PROVIDER_SCRIPT_SHA256,
            "fresh_build_and_original_smoke_verified": True,
            "private_smoke_material_archived": False, "production_activation": False}


def recursive_sums(out):
    files = []
    for directory, names, basenames in os.walk(out, followlinks=False):
        parent = Path(directory)
        for name in names:
            require(not (parent / name).is_symlink(), "symlink directory in evidence output")
        for name in basenames:
            path = parent / name
            if path == out / "SHA256SUMS":
                continue
            regular_file(path)
            files.append(path)
    with (out / "SHA256SUMS").open("x") as stream:
        for path in sorted(files):
            stream.write(sha(path) + "  " + path.relative_to(out).as_posix() + "\n")


def stop_owned_group(child, initial_signal):
    """Only signal the new session created for this exact subprocess."""
    try:
        os.killpg(child.pid, initial_signal)
    except ProcessLookupError:
        pass
    try:
        return child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return child.wait(timeout=10)


def scan_logs(stdout, stderr):
    result = {"rust_tests": [], "python_tests": [], "python_ok": False,
              "build_script_events": [], "cargo_json_errors": [], "unqualified": False}
    for path in (stdout, stderr):
        with path.open(errors="replace") as stream:
            for line in stream:
                result["unqualified"] |= "UNQUALIFIED" in line
                rust = re.search(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", line)
                if rust:
                    result["rust_tests"].append([rust[1], *map(int, rust.groups()[1:])])
                python = re.match(r"Ran (\d+) tests? in ", line.strip())
                if python:
                    result["python_tests"].append(int(python[1]))
                result["python_ok"] |= line.strip() == "OK"
                if path == stdout and line.startswith('{"reason":'):
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError as error:
                        result["cargo_json_errors"].append(str(error))
                        continue
                    if event.get("reason") == "build-script-executed":
                        result["build_script_events"].append(event)
    return result


class Recorder:
    def __init__(self, head, out, env):
        self.head, self.out, self.env = head, out, env
        self.records, self.sqlite_id = [], None
        self.provider_binding = None
        self.provider_prefix, self.openssl_id = None, None

    def save(self):
        value = {"schema": "pon-learning-outcome-c2-command-observation-v2",
                 "source_head": self.head, "source_root": str(ROOT),
                 "cargo_entry": CARGO, "target_directory": str(TARGET),
                 "output_directory": str(self.out), "provider_environment_sha256": self.provider_binding,
                 "model_efficacy_certified": False, "production_activation": False,
                 "commands": self.records}
        temporary = self.out / "commands.json.tmp"
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        temporary.replace(self.out / "commands.json")

    def run(self, label, command, *, timeout=1800, required=False,
            rust_count=None, python_count=None, python_suite=False,
            cargo_json=False, sqlite_required=False, source_snapshot=False,
            openssl_required=False):
        stdout, stderr = self.out / (label + ".stdout"), self.out / (label + ".stderr")
        started, clock = stamp(), time.monotonic()
        code, timed_out, interrupted, error = None, False, False, None
        print("BEGIN", label, started, flush=True)
        with stdout.open("xb") as output, stderr.open("xb") as diagnostics:
            try:
                child = subprocess.Popen(command, cwd=ROOT, env=self.env,
                                         stdin=subprocess.DEVNULL, stdout=output,
                                         stderr=diagnostics, start_new_session=True)
                try:
                    code = child.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    code = stop_owned_group(child, signal.SIGTERM)
                except KeyboardInterrupt:
                    interrupted = True
                    code = stop_owned_group(child, signal.SIGINT)
            except (OSError, subprocess.TimeoutExpired) as cause:
                error = str(cause)
                diagnostics.write((error + "\n").encode())
        observation = scan_logs(stdout, stderr)
        reasons = []
        if code != 0 or timed_out or interrupted or error:
            reasons.append("command did not complete successfully")
        if rust_count is not None and observation["rust_tests"] != [["ok", rust_count, 0, 0]]:
            reasons.append("native harness count/status differs from the required executed inventory")
        if python_suite and (len(observation["python_tests"]) != 1 or
                             observation["python_tests"][0] <= 0 or not observation["python_ok"]):
            reasons.append("Python suite did not report a positive, unskipped successful inventory")
        if python_count is not None and observation["python_tests"] != [python_count]:
            reasons.append("Python suite count differs from its required inventory")
        if cargo_json and (observation["unqualified"] or observation["cargo_json_errors"]):
            reasons.append("unqualified diagnostic or malformed Cargo event stream")
        sqlite_events = [event for event in observation["build_script_events"]
                         if self.sqlite_id is not None and event.get("package_id") == self.sqlite_id]
        witnesses = []
        for event in sqlite_events:
            pairs = event.get("env", [])
            valid_pairs = (isinstance(pairs, list) and all(isinstance(pair, list) and len(pair) == 2
                           and all(isinstance(item, str) for item in pair) for pair in pairs))
            values = dict(pairs) if valid_pairs else {}
            accepted = (valid_pairs and len(values) == len(pairs)
                        and "trnm_sqlite_layout_witness" in event.get("cfgs", [])
                        and values.get("TRNM_SQLITE3_BUILD_FENCE") == FENCE
                        and "TRNM_SQLITE3_UNQUALIFIED_REASON" not in values)
            witnesses.append({"accepted": accepted, "event": event})
        if sqlite_required and (not witnesses or not all(row["accepted"] for row in witnesses)):
            reasons.append("this Node invocation lacks the original qualified SQLite build-script facts")
        openssl_events = [event for event in observation["build_script_events"]
                          if self.openssl_id is not None and event.get("package_id") == self.openssl_id]
        openssl_witnesses = []
        for event in openssl_events:
            paths = event.get("linked_paths", [])
            expected_path = str(self.provider_prefix / "lib") if self.provider_prefix is not None else None
            accepted = (expected_path is not None and isinstance(paths, list)
                        and any(path in (expected_path, "native=" + expected_path) for path in paths)
                        and "ossl350" in event.get("cfgs", []))
            openssl_witnesses.append({"accepted": accepted, "event": event})
        if openssl_required and (not openssl_witnesses or not all(row["accepted"] for row in openssl_witnesses)):
            reasons.append("this all-features Clippy invocation lacks the newly built OpenSSL 3.5 provider binding")
        snapshot = self.out / (label + ".json")
        snapshot_sha = None
        if source_snapshot:
            try:
                source = json.loads(stdout.read_text())
                if (source.get("tested_commit") != self.head or source.get("candidate") != self.head
                        or source.get("tracked_worktree_verified") is not True
                        or source.get("tests_executed_by_identity_check") is not False
                        or snapshot.read_bytes() != stdout.read_bytes()):
                    raise ValueError("original source receipt or exact readback differs")
                if label == "source-after":
                    before = json.loads((self.out / "source-before.json").read_text())
                    if source["tested_tree"] != before["tested_tree"]:
                        raise ValueError("source tree changed between original gates")
                snapshot_sha = sha(snapshot)
            except (OSError, KeyError, ValueError) as cause:
                reasons.append("source snapshot: " + str(cause))
        row = {"label": label, "command": command, "cwd": str(ROOT),
               "started_utc": started, "finished_utc": stamp(),
               "elapsed_seconds": round(time.monotonic() - clock, 6),
               "exit_code": code, "timed_out": timed_out, "interrupted": interrupted,
               "execution_error": error, "accepted": not reasons, "rejections": reasons,
               "expected_rust_tests": rust_count, "expected_python_tests": python_count,
               "python_suite_required": python_suite, "sqlite_witness_required": sqlite_required,
               "sqlite_package_id": self.sqlite_id, "sqlite_witnesses": witnesses,
               "provider_environment_sha256": self.provider_binding,
               "openssl_witness_required": openssl_required, "openssl_package_id": self.openssl_id,
               "openssl_witnesses": openssl_witnesses,
               "observations": observation, "source_snapshot_sha256": snapshot_sha,
               "stdout": stdout.name, "stderr": stderr.name,
               "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)}
        path = self.out / (label + ".command.json")
        write_new(path, row)
        self.records.append(dict(row, record=path.name, record_sha256=sha(path)))
        self.save()
        print("END", label, code, "accepted", row["accepted"], flush=True)
        if interrupted or error or required and reasons:
            raise RuntimeError("required command or execution boundary failed: " + label)
        return row

    def source(self, label, required=False):
        return self.run(label, ["python3", "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
                               "--expected-head", self.head, "--output", str(self.out / (label + ".json"))],
                        required=required, source_snapshot=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--pq-source-archive", type=Path,
                        help="optional exact original pinned tarball; still performs a fresh build and smoke")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.head) is None:
        parser.error("--head must be an exact canonical 40-hex commit")
    out = args.out or ROOT.parent / ("chain-pon-outcome-7612-c2-gates-" + args.head[:12] + "-provider2")
    if not out.is_absolute() or out.parent.resolve(strict=True) != out.parent or ROOT in out.parents or TARGET in out.parents:
        parser.error("--out must have a canonical existing parent outside source and target")
    out.mkdir(mode=0o700)
    temporary = out.parent / (out.name + "-pq-build")
    temporary.mkdir(mode=0o700)
    (out / "provider.env").open("xb").close()
    with (out / "runner.py").open("xb") as stream:
        stream.write(Path(__file__).read_bytes())
    env = os.environ.copy()
    provider_overrides = [key for key in env if key.startswith(("OPENSSL_", "TRNM_PQ_")) or "_OPENSSL_" in key]
    inherited_provider = {key: env.pop(key) for key in sorted(provider_overrides)}
    env.update(PATH="/home/qian-qi/.cargo/bin:" + env.get("PATH", ""),
               RUSTUP_TOOLCHAIN="1.95.0", CARGO_TARGET_DIR=str(TARGET),
               CARGO_BUILD_JOBS="2", CARGO_NET_OFFLINE="true", PYTHONDONTWRITEBYTECODE="1",
               RUNNER_TEMP=str(temporary), GITHUB_ENV=str(out / "provider.env"), TRNM_CI_RECEIPT_DIR=str(out))
    explicit_source = args.pq_source_archive
    if explicit_source is not None:
        require(explicit_source.is_absolute() and regular_file(explicit_source)["sha256"] == PROVIDER_ARCHIVE_SHA256,
                "--pq-source-archive must be the exact ordinary pinned archive")
        env["TRNM_PQ_SOURCE_ARCHIVE"] = str(explicit_source)
    recorder, failure = Recorder(args.head, out, env), None
    provider_before = None
    planned = ["project-boundary-before", "source-before", "locate-rustc", "locate-rustdoc",
               "toolchain", "cargo-version", "prepare-pq-provider", "locked-metadata", "format", "source-integrity-negatives",
               "project-boundary-negatives", "repository-and-links"]
    planned += ["reader-" + name.removeprefix("test_").removesuffix(".py") for name in READERS]
    planned += [row[0] for row in NATIVE] + ["workspace-strict-clippy", "source-after"]
    write_new(out / "plan.json", {"head": args.head, "labels": planned, "native_test_total": 42,
                                 "reader_suites": list(READERS), "cargo_entry": CARGO,
                                 "provider_script": PROVIDER_SCRIPT, "provider_script_sha256": PROVIDER_SCRIPT_SHA256,
                                 "provider_version": PROVIDER_VERSION, "provider_source_sha256": PROVIDER_ARCHIVE_SHA256})
    recorder.save()
    try:
        recorder.run("project-boundary-before", ["bash", "scripts/project-preflight.sh"], required=True)
        recorder.source("source-before", required=True)
        for name in ("rustc", "rustdoc"):
            label = "locate-" + name
            recorder.run(label, [RUSTUP, "which", "--toolchain", "1.95.0", name], required=True)
            path = Path((out / (label + ".stdout")).read_text().strip())
            if not path.is_absolute() or not path.is_file() or path.resolve(strict=True).name != name:
                raise RuntimeError("unexpected absolute Rust tool: " + name)
            env[name.upper()] = str(path.resolve(strict=True))
        # Preserve the successful C1 Rustup shim entry. Do not prepend the real
        # toolchain bin or manufacture a loader path to satisfy the original gate.
        environment = {name: env.get(name) for name in (
            "RUSTUP_TOOLCHAIN", "RUSTC", "RUSTDOC", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS",
            "CARGO_NET_OFFLINE", "LD_LIBRARY_PATH", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CC", "CFLAGS", "RUSTC_WRAPPER")}
        environment.update(cargo_entry=CARGO, lock_sha256=sha(ROOT / "trillionnium/Cargo.lock"),
                           runner_sha256=sha(out / "runner.py"), artifact_output_directory=str(out),
                           RUNNER_TEMP=str(temporary), GITHUB_ENV=env["GITHUB_ENV"], TRNM_CI_RECEIPT_DIR=str(out),
                           TRNM_PQ_SOURCE_ARCHIVE=env.get("TRNM_PQ_SOURCE_ARCHIVE"),
                           inherited_provider_environment_removed=inherited_provider)
        write_new(out / "environment-before-provider.json", environment)
        recorder.run("toolchain", [env["RUSTC"], "-Vv"], required=True)
        recorder.run("cargo-version", [CARGO, "-Vv"], required=True)
        if "release: 1.95.0\n" not in (out / "toolchain.stdout").read_text() or not (out / "cargo-version.stdout").read_text().startswith("cargo 1.95.0 "):
            raise RuntimeError("unexpected Rust/Cargo release")
        require(sha(ROOT / PROVIDER_SCRIPT) == PROVIDER_SCRIPT_SHA256, "original PQ preparation script differs")
        recorder.run("prepare-pq-provider", ["bash", PROVIDER_SCRIPT], required=True, timeout=3600)
        provider_before = inspect_provider(out, temporary, explicit_source)
        write_new(out / "provider-observation-before.json", provider_before)
        env.update(provider_before["exported_environment"])
        environment.update(provider_before["exported_environment"])
        environment.update(provider_preparation_script_sha256=PROVIDER_SCRIPT_SHA256,
                           provider_receipt_sha256=sha(out / "pq-provider/provider.json"),
                           provider_env_sha256=sha(out / "provider.env"),
                           provider_observation_sha256=sha(out / "provider-observation-before.json"))
        write_new(out / "environment.json", environment)
        recorder.provider_binding = sha(out / "environment.json")
        recorder.provider_prefix = Path(env["OPENSSL_DIR"])
        common = ["--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml"]
        recorder.run("locked-metadata", [CARGO, "metadata", *common, "--format-version", "1", "--all-features"], required=True)
        metadata = json.loads((out / "locked-metadata.stdout").read_text())
        packages = [row for row in metadata["packages"] if row["name"] == "trnm-sqlite-io-boundary"
                    and row["manifest_path"] == str(ROOT / "trillionnium/crates/trnm-sqlite-io-boundary/Cargo.toml")]
        if len(packages) != 1:
            raise RuntimeError("locked graph lacks the exact original SQLite boundary package")
        recorder.sqlite_id = packages[0]["id"]
        openssl = [row for row in metadata["packages"] if row["name"] == "openssl-sys"]
        require(len(openssl) == 1, "locked graph lacks one exact openssl-sys package")
        recorder.openssl_id = openssl[0]["id"]
        recorder.run("format", [CARGO, "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"])
        recorder.run("source-integrity-negatives", ["python3", "-B", "scripts/ci/test_ci_source_integrity.py", "-v"], python_suite=True, python_count=43)
        recorder.run("project-boundary-negatives", ["python3", "-B", "scripts/ci/test_project_boundary.py", "-v"], python_suite=True, python_count=16)
        recorder.run("repository-and-links", ["python3", "-B", "scripts/ci/check_repository.py"])
        for name in READERS:
            recorder.run("reader-" + name.removeprefix("test_").removesuffix(".py"),
                         ["python3", "-B", "scripts/" + name, "-v"], python_suite=True)
        for label, package, target, count, exact, witness in NATIVE:
            command = [CARGO, "test", *common, "--message-format=json", "-p", package, *target,
                       "--", *(["--exact"] if exact else []), "--nocapture", "--test-threads=1"]
            recorder.run(label, command, timeout=3600, rust_count=count, cargo_json=True, sqlite_required=witness)
        recorder.run("workspace-strict-clippy", [CARGO, "clippy", *common, "--message-format=json",
                     "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"],
                     timeout=7200, cargo_json=True, openssl_required=True)
    except (Exception, KeyboardInterrupt) as cause:
        failure = type(cause).__name__ + ": " + str(cause)
        print("RUNNER_FAILURE", failure, file=sys.stderr, flush=True)
    finally:
        if provider_before is not None:
            try:
                provider_after = inspect_provider(out, temporary, explicit_source)
                write_new(out / "provider-observation-after.json", provider_after)
                require(provider_after == provider_before, "provider bytes/environment changed during qualification")
            except (Exception, KeyboardInterrupt) as cause:
                failure = (failure + "; " if failure else "") + "provider-after: " + str(cause)
        try:
            recorder.source("source-after")
        except (Exception, KeyboardInterrupt) as cause:
            failure = (failure + "; " if failure else "") + "source-after: " + str(cause)
        recorder.save()
    labels = [row["label"] for row in recorder.records]
    passed = failure is None and labels == planned and all(row["accepted"] for row in recorder.records)
    summary = {"source_head": args.head, "result": "PASS" if passed else "FAIL", "failure": failure,
               "planned_commands": len(planned), "recorded_commands": len(labels),
               "failed_commands": [row["label"] for row in recorder.records if not row["accepted"]],
               "missing_commands": [label for label in planned if label not in labels],
               "native_test_total_required": 42, "reader_suites_required": 6,
               "provider_prepared_and_unchanged": provider_before is not None and failure is None,
               "model_efficacy_certified": False, "production_activation": False}
    write_new(out / "summary.json", summary)
    recursive_sums(out)
    print("C2_GATES_FINISHED", json.dumps(summary, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    def interrupted(_number, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
