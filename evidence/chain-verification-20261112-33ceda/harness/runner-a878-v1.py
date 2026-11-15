#!/usr/bin/env python3
"""Run an explicitly frozen Chain candidate with retained Rust/provider settings.

This is an external orchestration artifact, never part of the candidate source.
The repository's own recorder owns physical source checks and command receipts.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time


GROUPS = (
    ("output-reservation", "ingress::public_v3::output_reservation_tests::", 2),
    ("auth-recovery", "ingress::tests::authenticated_activation_recovery::", 6),
    ("completion-deadline", "ingress::public_v3::completion_deadline_tests::", 10),
    ("growth", "ingress::public_v3::growth::tests::", 7),
    ("work-arithmetic", "ingress::public_v3::work_arithmetic::tests::", 5),
    ("public-v3-retained", "ingress::public_v3::tests::", 59),
)
PROVIDER_PATH = Path("/home/qq/chain-system-security-root-provider-20261112-306929/provider.env")
PROVIDER_SHA = "6de317bdd1826065aefeae7335a552dfae7b87e421a8f1aa66d32aa31adab2ed"
PROVIDER_KEYS = {"OPENSSL_DIR", "OPENSSL_STATIC", "TRNM_PQ_OPENSSL", "TRNM_PQ_OPENSSL_SHA256", "TRNM_PQ_OPENSSL_VERSION", "OPENSSL_CONF", "OPENSSL_MODULES"}
TOOLCHAIN = Path("/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu")
TARGET = "/home/qq/chain-system-security-20261112-306929/trillionnium/target"
VALIDATION = Path("/home/qq/chain-verification-validation-33ceda-20261112")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def environment():
    env = dict(os.environ)
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
        if env.get(key):
            raise RuntimeError("unreviewed build override: " + key)
    if any(key.startswith("CARGO_PROFILE_") for key in env):
        raise RuntimeError("unreviewed profile override")
    raw = PROVIDER_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROVIDER_SHA:
        raise RuntimeError("provider environment file changed")
    provider = {}
    for line in raw.decode().splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            key, value = line.removeprefix("export ").split("=", 1)
            provider[key] = value.strip("'\"")
    if set(provider) != PROVIDER_KEYS:
        raise RuntimeError("provider environment key set changed")
    if digest(provider["TRNM_PQ_OPENSSL"]) != provider["TRNM_PQ_OPENSSL_SHA256"]:
        raise RuntimeError("provider executable changed")
    env.update(provider)
    env.update(RUSTC=str(TOOLCHAIN / "bin/rustc"), RUSTDOC=str(TOOLCHAIN / "bin/rustdoc"),
               LD_LIBRARY_PATH=str(TOOLCHAIN / "lib"), CARGO_HOME="/home/qq/.cargo",
               CARGO_TARGET_DIR=TARGET, CARGO_BUILD_JOBS="1", RUST_TEST_THREADS="1",
               PATH=str(TOOLCHAIN / "bin") + ":" + env.get("PATH", "/usr/bin:/bin"))
    return env


def active_target_owners():
    owners = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            exe = (entry / "exe").resolve()
            if exe.name not in ("cargo", "rustc", "clippy-driver"):
                continue
            process_env = dict(item.split("=", 1) for item in
                               (entry / "environ").read_bytes().decode(errors="replace").split("\0") if "=" in item)
            if process_env.get("CARGO_TARGET_DIR") == TARGET:
                owners.append({"pid": int(entry.name), "executable": str(exe)})
        except (OSError, ValueError):
            continue
    return owners


def roster_from_list(text, prefix, count):
    names = [match[1] for line in text.splitlines()
             if (match := re.fullmatch(r"([A-Za-z0-9_:]+): test", line))]
    if len(names) != count or len(set(names)) != count or any(not name.startswith(prefix) for name in names):
        raise RuntimeError("native list differs from the reviewed complete group: " + prefix)
    return names


def verify_group(text, expected):
    names = []
    running = []
    summaries = []
    for line in text.splitlines():
        if line.startswith("running "):
            match = re.fullmatch(r"running ([0-9]+) tests?", line)
            if match is None:
                raise RuntimeError("noncanonical native running line")
            running.append(int(match[1]))
        if match := re.fullmatch(r"test ([A-Za-z0-9_:]+) \.\.\.(?: .*)?", line):
            names.append(match[1])
        if line.startswith("test result:"):
            match = re.fullmatch(r"test result: ok\. ([0-9]+) passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s", line)
            if match is None:
                raise RuntimeError("native result did not pass all tests without ignored cases")
            summaries.append(int(match[1]))
    if running != [len(expected)] or summaries != [len(expected)] or sorted(names) != sorted(expected):
        raise RuntimeError("native execution does not match its complete listed group")
    return {"result": "PASS", "executed_tests": len(expected), "tests": sorted(expected),
            "scope": "native-libtest-transcript-and-process-exit-only"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path("/home/qq/chain-verification-33ceda-20261112"))
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source):
        raise ValueError("exact frozen commit required")
    if not args.stage.is_absolute() or args.stage.resolve().is_relative_to(args.repo.resolve()):
        raise ValueError("external absolute evidence path required")
    args.stage.mkdir(parents=True, exist_ok=False)
    env = environment()
    lock = (VALIDATION / "native-target-owner.lock").open("a+b")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    owners = active_target_owners()
    save(args.stage / "target-owners-before.json", owners)
    if owners:
        raise RuntimeError("original target has active build owners")
    save(args.stage / "environment.json", {key: env.get(key) for key in
         ("RUSTC", "RUSTDOC", "LD_LIBRARY_PATH", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "RUST_TEST_THREADS", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", *sorted(PROVIDER_KEYS))})
    summary = {"source": args.source, "commands": [], "groups": [], "status": "running",
               "whole_chain_quantum_security_qualified": False, "performance_qualified": False}

    def record(label, command, timeout, native_pin=None):
        preflight = subprocess.run(["bash", "scripts/project-preflight.sh"], cwd=args.repo, env=env, capture_output=True)
        (args.stage / (label + ".preflight.stdout")).write_bytes(preflight.stdout)
        (args.stage / (label + ".preflight.stderr")).write_bytes(preflight.stderr)
        if preflight.returncode:
            raise RuntimeError("preflight failed for " + label)
        if native_pin and digest(command[0]) != native_pin:
            raise RuntimeError("compiled native bytes changed before " + label)
        argv = ["/usr/bin/python3", "scripts/ci/record_pq_native_command.py", "--kind", "head",
                "--candidate", args.source, "--tested", args.source, "--label", label,
                "--output", str(args.stage), "--", *command]
        emit({"event": "command-start", "label": label, "argv": command, "timeout_seconds": timeout})
        started = time.monotonic_ns()
        with (args.stage / (label + ".recorder.stdout")).open("xb") as out, (args.stage / (label + ".recorder.stderr")).open("xb") as err:
            process = subprocess.Popen(argv, cwd=args.repo, env=env, stdout=out, stderr=err, start_new_session=True)
            timed_out = False
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    code = process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    code = process.wait()
        row = {"label": label, "argv": command, "recorder_exit_code": code, "timed_out": timed_out,
               "elapsed_ns": time.monotonic_ns() - started, "pid": process.pid}
        summary["commands"].append(row)
        save(args.stage / "driver-summary.json", summary)
        emit({"event": "command-end", **row})
        if code or timed_out:
            raise RuntimeError("command failed; retained original observation: " + label)
        receipt = json.loads((args.stage / (label + ".json")).read_text())
        if receipt.get("status") != "command_succeeded" or receipt.get("exit_code") != 0:
            raise RuntimeError("incomplete original recorder receipt: " + label)
        if native_pin and digest(command[0]) != native_pin:
            raise RuntimeError("compiled native bytes changed after " + label)
        return (args.stage / (label + ".log")).read_text()

    try:
        cargo = str(TOOLCHAIN / "bin/cargo")
        manifest = ["--manifest-path", "trillionnium/Cargo.toml"]
        record("rustc-version", [str(TOOLCHAIN / "bin/rustc"), "-Vv"], 120)
        record("cargo-version", [cargo, "-V"], 120)
        record("locked-default-graph", [cargo, "metadata", "--locked", "--offline", *manifest, "--format-version", "1"], 300)
        record("locked-all-feature-graph", [cargo, "metadata", "--locked", "--offline", *manifest, "--all-features", "--format-version", "1"], 300)
        record("cargo-fmt", [cargo, "fmt", *manifest, "--all", "--", "--check"], 300)
        build = record("node-all-feature-test-build", [cargo, "test", "--locked", "--offline", *manifest,
                       "-p", "trnm-pon-node", "--lib", "--all-features", "--no-run", "--message-format=json"], 2400)
        artifacts = []
        for line in build.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "trnm_pon_node" and item.get("profile", {}).get("test") and item.get("executable"):
                artifacts.append(item)
        if len(artifacts) != 1:
            raise RuntimeError("ambiguous or absent native libtest artifact")
        original = Path(artifacts[0]["executable"])
        with original.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise RuntimeError("compiler artifact is not native ELF")
        native = args.stage / "trnm_pon_node-libtest"
        shutil.copy2(original, native)
        pin = digest(original)
        if digest(native) != pin:
            raise RuntimeError("native artifact copy differs")
        save(args.stage / "node-libtest.json", {"source": args.source, "executable": str(native),
             "compiler_executable": str(original), "sha256": pin, "bytes": native.stat().st_size,
             "compiler_artifact": artifacts[0], "original_profiles_retained": True})
        emit({"event": "native-build-ready", "source": args.source, "executable": str(native), "sha256": pin})
        for label, prefix, count in GROUPS:
            listed = record(label + "-list", [str(native), prefix, "--list", "--format", "pretty", "--include-ignored"], 120, pin)
            roster = roster_from_list(listed, prefix, count)
            raw = record(label, [str(native), prefix, "--test-threads=1", "--nocapture", "--format", "pretty", "--include-ignored"], 1800, pin)
            checked = verify_group(raw, roster)
            save(args.stage / (label + ".native-roster.json"), checked)
            summary["groups"].append({"label": label, **checked})
            save(args.stage / "driver-summary.json", summary)
            emit({"event": "native-group-complete", "label": label, "executed_tests": count})
        record("strict-workspace-clippy", [cargo, "clippy", "--locked", "--offline", *manifest,
               "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"], 2400)
        summary["status"] = "PASS"
    except BaseException as error:
        summary["status"] = "FAILED_OR_INCOMPLETE"
        summary["error"] = str(error)
        raise
    finally:
        summary["executed_tests"] = sum(group["executed_tests"] for group in summary["groups"])
        save(args.stage / "driver-summary.json", summary)
        emit({"event": "driver-final", "status": summary["status"], "executed_tests": summary["executed_tests"]})


if __name__ == "__main__":
    main()
