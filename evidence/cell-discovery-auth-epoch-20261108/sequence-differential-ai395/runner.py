#!/usr/bin/env python3
"""Run the frozen C2 sequence differential; never install tools or alter tests.

Read JSON from stdin (or --config FILE) with existing absolute directories
root, target, native_tmp; an existing provider_path JSON; and a new output
directory out outside the checkout. Optional rustup is an absolute executable
path, default /home/qq/.cargo/bin/rustup. Host preparation belongs to the caller.
All Cargo invocations explicitly use the already installed Rust 1.95.0.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import tomllib


COMMIT = "939aa069af41d31d41082272d7ae7367ef08f812"
TOOLCHAIN = "1.95.0"
AUTH_REL = "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/auth.rs"
TESTS_REL = "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/auth_tests.rs"
OLD_REL = "evidence/cell-discovery-auth-epoch-20261108/sequence-differential-desktop/auth-before-guard.rs"
FIXED_SHA = "1fac53a2a16ef8f6c5b2a8ed480ec5be8bebdec3a5c764585639e5a085659690"
OLD_SHA = "7214ea4e588a95cb0043d750123d7ad657ed7cba275ba54f1d4e62535ce7a30b"
TESTS_SHA = "7e46e97d7756f9fd5648ff43833ef9c35433366ae49a632ddf01bd414409ab43"
SEQUENCE_TESTS = {
    "authenticated_v3_newest_verified_expired_high_first_vetoes_later_low_sequence",
    "authenticated_v3_newest_verified_expired_high_later_removes_observed_low_sequence",
    "authenticated_v3_newest_verified_quota_rejected_withdrawal_vetoes_older_source",
}
TIMING_PREFIX = "authenticated-v3 sequence fixture: "
EXPIRED_TARGET = "expired newer signed sequence resurrected an older provider: Ok("
QUOTA_TARGET = "a quota-refused newer withdrawal allowed an older source: Ok("
PREMISE_FAILURE = "fixture did not receive both earlier authenticated replies before the newer lease expired:"
PREPARATION_FAILURE = "preparation failed before quota regression:"
PROVIDER_EXPORTS = {
    "OPENSSL_DIR", "OPENSSL_STATIC", "TRNM_PQ_OPENSSL", "TRNM_PQ_OPENSSL_SHA256",
    "TRNM_PQ_OPENSSL_VERSION", "OPENSSL_CONF", "OPENSSL_MODULES",
}
LOCAL_FILESYSTEMS = {"ext4", "xfs", "btrfs", "f2fs"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(root, *arguments):
    git_env, _ = scrub_environment(dict(os.environ))
    return subprocess.check_output(["git", *arguments], cwd=root, env=git_env)


def scrub_environment(inherited: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Use the exact-gates runner's cleanup policy; never record removed values."""
    environment = inherited.copy()
    removed = []
    for key in list(environment):
        if ((key.startswith("CARGO_") and key != "CARGO_HOME")
                or (key.startswith("RUST") and key != "RUSTUP_HOME")
                or key.startswith("GIT_") or "OPENSSL" in key
                or key in {"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}):
            removed.append(key)
            del environment[key]
    return environment, sorted(removed)


def file_identity(path: Path) -> dict:
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode), "input is not a regular file: " + str(path))
    fingerprint = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                                info.st_mtime_ns, info.st_ctime_ns)
    value = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                "input changed before hashing: " + str(path))
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                "input changed during hashing: " + str(path))
    require(fingerprint(path.stat(follow_symlinks=False)) == fingerprint(before),
            "input path changed during hashing: " + str(path))
    return {"path": str(path), "bytes": before.st_size, "sha256": value.hexdigest()}


def cargo_config_inputs(root: Path, cargo_home: Path) -> list[dict]:
    """Use the exact-gates Cargo config policy; never read credentials files."""
    directories = [cargo_home, *(parent / ".cargo" for parent in (root, *root.parents))]
    paths = sorted({directory / name for directory in directories for name in ("config", "config.toml")
                    if (directory / name).exists()}, key=str)
    identities = []
    for path in paths:
        raw = path.read_bytes()
        identity = file_identity(path)
        require(hashlib.sha256(raw).hexdigest() == identity["sha256"], "Cargo config changed during read")
        data = tomllib.loads(raw.decode("utf-8"))
        forbidden = []
        for key in ("profile", "unstable", "paths", "patch", "replace"):
            if data.get(key):
                forbidden.append(key)
        build = data.get("build", {})
        for key in ("rustc", "rustc-wrapper", "rustc-workspace-wrapper", "rustdoc", "rustflags",
                    "rustdocflags", "target"):
            if key in build:
                forbidden.append("build." + key)
        for target, settings in data.get("target", {}).items():
            if not isinstance(settings, dict):
                continue
            for key in ("runner", "linker", "rustflags", "rustdocflags"):
                if key in settings:
                    forbidden.append("target." + target + "." + key)
            for key, value in settings.items():
                if isinstance(value, dict):
                    forbidden.append("target." + target + "." + key + " (build-script override)")
        for key in data.get("env", {}):
            if (key.startswith(("CARGO_", "RUST", "GIT_")) or "OPENSSL" in key
                    or key in {"PATH", "TMPDIR", "TMP", "TEMP", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}):
                forbidden.append("env." + key)
        for key in ("metadata", "fmt", "test", "clippy"):
            if key in data.get("alias", {}):
                forbidden.append("alias." + key)
        require(not forbidden, "Cargo configuration changes native execution: " + str(path) + " keys=" + ",".join(forbidden))
        identities.append(identity)
    return identities


def resource_snapshot():
    data = {
        "sampled_unix": time.time(),
        "uname": list(os.uname()),
        "nice": os.getpriority(os.PRIO_PROCESS, 0),
        "logical_cpus": os.cpu_count(),
        "affinity_cpus": sorted(os.sched_getaffinity(0)),
        "load_average": list(os.getloadavg()),
    }
    files = {"proc_self_cgroup": Path("/proc/self/cgroup")}
    for name in ("cpu", "io", "memory"):
        files["host_pressure_" + name] = Path("/proc/pressure") / name
    membership = Path("/proc/self/cgroup").read_text()
    for line in membership.splitlines():
        if line.startswith("0::"):
            group = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
            data["cgroup_v2_path"] = str(group)
            for name in (
                "cpu.max", "cpu.stat", "cpu.pressure", "cpuset.cpus.effective",
                "io.stat", "io.pressure", "memory.max", "memory.current",
                "memory.peak", "memory.events", "memory.swap.max", "memory.pressure",
            ):
                files["task_" + name] = group / name
    for label, path in files.items():
        try:
            data[label] = path.read_text()
        except OSError as error:
            data[label] = {"unavailable": str(error)}
    return data


def timing_observations(text):
    observations = []
    pattern = re.compile(
        r"authenticated-v3 sequence fixture: newer_first=(true|false), "
        r"newer_expiry=(\d+), third_query=(.*?), observation="
    )
    duration = re.compile(r"Some\(\((\d+)(?:\.(\d{1,9}))?s, (\d+)\)\)")
    for line in text.splitlines():
        if TIMING_PREFIX not in line:
            continue
        entry = {"raw_line": line, "premise_valid": False}
        match = pattern.search(line)
        if match:
            entry.update(newer_first=match[1] == "true", newer_expiry=int(match[2]))
            sample = duration.fullmatch(match[3])
            if sample:
                nanos = int(sample[1]) * 1_000_000_000 + int((sample[2] or "").ljust(9, "0"))
                expiry = int(sample[3])
                entry.update(
                    observed_unix_nanoseconds=nanos,
                    observed_expiry=expiry,
                    margin_nanoseconds=expiry * 1_000_000_000 - nanos,
                    premise_valid=(expiry != 0 and expiry == int(match[2]) and nanos < expiry * 1_000_000_000),
                )
        observations.append(entry)
    return observations


def parse_native(stdout, stderr):
    combined = stdout + "\n" + stderr
    result_lines = [line for line in stdout.splitlines() if line.startswith("test result:")]
    counts = []
    for line in result_lines:
        match = re.search(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", line)
        if match:
            counts.append({"status": match[1], "passed": int(match[2]), "failed": int(match[3]), "ignored": int(match[4])})
    outcomes = []
    for line in stdout.splitlines():
        match = re.fullmatch(r"test (\S+) \.\.\. (ok|FAILED)", line)
        if match:
            outcomes.append({"test": match[1], "outcome": match[2]})
    observations = timing_observations(combined)
    two_premises = (
        len(observations) == 2
        and {entry.get("newer_first") for entry in observations} == {True, False}
        and all(entry["premise_valid"] for entry in observations)
    )
    return {
        "result_lines": result_lines,
        "result_counts": counts,
        "test_outcomes": outcomes,
        "timing_observations": observations,
        "both_timing_premises_valid": two_premises,
        "expired_target_assertions": combined.count(EXPIRED_TARGET),
        "quota_target_assertions": combined.count(QUOTA_TARGET),
        "timing_premise_failures": combined.count(PREMISE_FAILURE),
        "quota_preparation_failures": combined.count(PREPARATION_FAILURE),
        "quota_preparation_lines": [line for line in combined.splitlines() if "authenticated-v3 quota preparation:" in line],
    }


def has_counts(result, passed, failed):
    return (
        len(result["result_counts"]) == 1
        and result["result_counts"][0]["passed"] == passed
        and result["result_counts"][0]["failed"] == failed
        and result["result_counts"][0]["ignored"] == 0
    )


def sequence_outcomes(result, expected):
    outcomes = result["test_outcomes"]
    return (
        len(outcomes) == 3
        and {entry["test"].rsplit("::", 1)[-1] for entry in outcomes} == SEQUENCE_TESTS
        and all(entry["outcome"] == expected for entry in outcomes)
    )


class RunnerInterrupted(RuntimeError):
    pass


def interrupt(signum, _frame):
    raise RunnerInterrupted(f"runner received signal {signum}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="JSON configuration; stdin if omitted")
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text()) if args.config else json.load(sys.stdin)
    required = ("root", "out", "target", "provider_path", "native_tmp")
    require(all(isinstance(cfg.get(key), str) and Path(cfg[key]).is_absolute() for key in required), "all five path settings must be absolute strings")
    paths = {key: Path(cfg[key]).resolve() for key in required}
    rustup_setting = cfg.get("rustup", "/home/qq/.cargo/bin/rustup")
    require(isinstance(rustup_setting, str) and Path(rustup_setting).is_absolute(), "rustup must be an absolute executable path")
    paths["rustup"] = Path(rustup_setting).resolve()
    root, out, target = paths["root"], paths["out"], paths["target"]
    provider_path, native_tmp = paths["provider_path"], paths["native_tmp"]
    for key in ("root", "target", "native_tmp"):
        require(paths[key].is_dir(), f"host preparation must create {key}: {paths[key]}")
    require(provider_path.is_file(), "provider_path must be a prepared validation receipt")
    require(out.parent.is_dir() and not out.exists(), "out must be a new directory in an existing parent")
    for path in (out, target, native_tmp):
        require(path != root and root not in path.parents, "output, target and native temporary directories must be outside the checkout")
    require(Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() == root, "configured root is not the actual Git checkout")
    require(git(root, "rev-parse", "HEAD").decode().strip() == COMMIT, "checkout is not frozen C2")
    require(not git(root, "status", "--porcelain").strip(), "checkout must start completely clean")
    auth, tests = root / AUTH_REL, root / TESTS_REL
    fixed = git(root, "show", f"{COMMIT}:{AUTH_REL}")
    test_bytes = git(root, "show", f"{COMMIT}:{TESTS_REL}")
    old = git(root, "show", f"{COMMIT}:{OLD_REL}")
    require(sha_bytes(fixed) == FIXED_SHA and auth.read_bytes() == fixed, "fixed auth differs from committed 1fac source")
    require(sha_bytes(test_bytes) == TESTS_SHA and tests.read_bytes() == test_bytes, "C2 tests differ from committed 7e timing tests")
    require(sha_bytes(old) == OLD_SHA, "committed pre-guard evidence differs from 7214")
    out.mkdir()
    summary = {
        "schema": "cell-auth-sequence-ai395-differential-v1",
        "commit": COMMIT,
        "tree": git(root, "rev-parse", "HEAD^{tree}").decode().strip(),
        "scope": "Linux development differential; HOLD_NO_GO; not full-crate acceptance",
        "started_unix": time.time(),
        "configuration": {key: str(value) for key, value in paths.items()},
        "toolchain_required": TOOLCHAIN,
        "fixed_auth_sha256": FIXED_SHA,
        "old_auth_sha256": OLD_SHA,
        "tests_sha256": TESTS_SHA,
        "tests_were_never_written": True,
        "receipts": {},
        "commands": [],
        "passed": False,
    }
    (out / "auth-fixed.rs").write_bytes(fixed)
    (out / "auth-before-guard.rs").write_bytes(old)
    (out / "tests-observed-timing.rs").write_bytes(test_bytes)
    runner = Path(__file__).read_bytes()
    (out / "runner.py").write_bytes(runner)
    summary["runner_sha256"] = sha_bytes(runner)

    def save_summary():
        temporary = out / "summary.json.tmp"
        temporary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        temporary.replace(out / "summary.json")

    env, removed_environment = scrub_environment(dict(os.environ))
    summary["removed_inherited_environment_names"] = removed_environment
    cargo_home = None
    env.update(
        CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=str(target), CARGO_TERM_COLOR="never",
        RUST_TEST_THREADS="1", RUSTUP_TOOLCHAIN=TOOLCHAIN,
        TMPDIR=str(native_tmp), TMP=str(native_tmp), TEMP=str(native_tmp),
        PYTHONDONTWRITEBYTECODE="1",
    )

    def run(label, command, native=False, required_success=False):
        entry = {
            "label": label, "command": command,
            "auth_sha256": sha_file(auth), "tests_sha256": sha_file(tests),
            "started_unix": time.time(), "stats_before": resource_snapshot(),
        }
        stdout_path, stderr_path = out / (label + ".stdout.log"), out / (label + ".stderr.log")
        started, process = time.monotonic(), None
        print(json.dumps({"event": "start", "label": label, "command": command}), flush=True)
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(command, cwd=root, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    entry["exit_code"] = process.wait()
                except BaseException:
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            try:
                                os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            process.wait()
                    entry["exit_code"] = process.returncode
                    raise
        except BaseException as error:
            entry["runner_error"] = repr(error)
            raise
        finally:
            entry.update(elapsed_seconds=time.monotonic() - started, stats_after=resource_snapshot())
            texts = {}
            for stream, path in (("stdout", stdout_path), ("stderr", stderr_path)):
                data = path.read_bytes() if path.exists() else b""
                entry[stream + "_sha256"] = sha_bytes(data)
                entry[stream + "_bytes"] = len(data)
                texts[stream] = data.decode(errors="replace")
            if native:
                entry.update(parse_native(texts["stdout"], texts["stderr"]))
                summary["commands"].append(entry)
            else:
                summary["receipts"][label] = entry
            save_summary()
            print(json.dumps({"event": "finish", "label": label, "exit_code": entry.get("exit_code"), "elapsed_seconds": entry["elapsed_seconds"], "result_lines": entry.get("result_lines", [])}), flush=True)
        if required_success:
            require(entry["exit_code"] == 0, f"required receipt failed: {label}")
        return entry, texts["stdout"], texts["stderr"]

    def restore_auth():
        current = auth.read_bytes()
        if current == old:
            auth.write_bytes(fixed)
        elif current != fixed:
            (out / "unexpected-concurrent-auth.rs").write_bytes(current)
            raise RuntimeError("unexpected auth edit preserved; refusing to overwrite a concurrent change")

    save_summary()
    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        signal.signal(getattr(signal, name), interrupt)
    try:
        run("preflight-before", ["bash", "scripts/project-preflight.sh"], required_success=True)
        run("source-before", [sys.executable, "-B", "scripts/ci/verify_ci_source.py", "--kind", "head", "--expected-head", COMMIT, "--output", str(out / "source-before.json")], required_success=True)
        user_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        cargo_home = Path(env.get("CARGO_HOME", str(user_home / ".cargo")))
        require(cargo_home.is_absolute(), "CARGO_HOME must be absolute")
        cargo_home = cargo_home.resolve(strict=True)
        env["CARGO_HOME"] = str(cargo_home)
        summary["cargo_config_before"] = cargo_config_inputs(root, cargo_home)
        provider_bytes = provider_path.read_bytes()
        provider = json.loads(provider_bytes)
        require(provider.get("result") == "PASS", "provider preparation did not pass")
        exports = provider.get("exports")
        require(isinstance(exports, dict) and all(isinstance(key, str) and isinstance(value, str) for key, value in exports.items()), "provider exports must be string settings")
        require(set(exports) == PROVIDER_EXPORTS, "provider exports must be exactly the seven pinned preparation settings")
        require(exports["OPENSSL_STATIC"] == "1" and exports["OPENSSL_CONF"] == "/dev/null" and exports["TRNM_PQ_OPENSSL_VERSION"] == "3.5.9", "provider settings differ from the pinned static preparation")
        provider_binary = Path(exports["TRNM_PQ_OPENSSL"]).resolve()
        require(sha_file(provider_binary) == exports["TRNM_PQ_OPENSSL_SHA256"], "provider binary hash changed")
        require(str(provider.get("version", "")).startswith("OpenSSL 3.5.9 "), "receipt is not the prepared OpenSSL 3.5.9")
        env.update(exports)
        # Provider settings cannot replace the configured compiler, budget or
        # native-test storage; retain the complete receipt without dumping env.
        env.update(CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=str(target), CARGO_TERM_COLOR="never", RUST_TEST_THREADS="1", RUSTUP_TOOLCHAIN=TOOLCHAIN, TMPDIR=str(native_tmp), TMP=str(native_tmp), TEMP=str(native_tmp), PYTHONDONTWRITEBYTECODE="1")
        (out / "validated-provider.json").write_bytes(provider_bytes)
        summary["provider"] = {"receipt_sha256": sha_bytes(provider_bytes), "binary": str(provider_binary), "binary_sha256": sha_file(provider_binary), "validation": provider}
        _, version, _ = run("provider-version", [str(provider_binary), "version"], required_success=True)
        require(version.strip() == provider["version"].strip(), "provider executable version differs from its receipt")
        run("provider-version-all", [str(provider_binary), "version", "-a"], required_success=True)
        rustup = str(paths["rustup"])
        require(paths["rustup"].is_file() and os.access(rustup, os.X_OK), "the configured rustup must exist; Rust 1.95.0 installation belongs to host preparation")
        tools = {}
        for name in ("cargo", "rustc", "rustdoc"):
            _, tool_path, _ = run("toolchain-path-" + name, [rustup, "which", "--toolchain", TOOLCHAIN, name], required_success=True)
            path = Path(tool_path.strip()).resolve()
            tools[name] = {"path": str(path), "sha256": sha_file(path)}
        env.update(RUSTC=tools["rustc"]["path"], RUSTDOC=tools["rustdoc"]["path"])
        cargo = [rustup, "run", TOOLCHAIN, "cargo"]
        _, cargo_version, _ = run("cargo-version", cargo + ["--version"], required_success=True)
        _, rustc_version, _ = run("rustc-version", [rustup, "run", TOOLCHAIN, "rustc", "--version", "--verbose"], required_success=True)
        require(cargo_version.startswith("cargo 1.95.0 ") and rustc_version.startswith("rustc 1.95.0 "), "actual Rust toolchain is not 1.95.0")
        summary["toolchain"] = {"requested": TOOLCHAIN, "rustup_path": rustup, "tools": tools, "cargo_version": cargo_version, "rustc_version": rustc_version}
        summary["build_environment"] = {key: env[key] for key in sorted(set(exports) | {"PATH", "CARGO_HOME", "CARGO_BUILD_JOBS", "CARGO_TARGET_DIR", "CARGO_TERM_COLOR", "RUST_TEST_THREADS", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "RUSTC", "RUSTDOC", "TMPDIR", "TMP", "TEMP", "PYTHONDONTWRITEBYTECODE"}) if key in env}
        summary["filesystems"] = {}
        for name, path in (("root", root), ("out", out), ("target", target), ("native_tmp", native_tmp)):
            _, mount_text, _ = run("filesystem-" + name, ["findmnt", "--json", "--target", str(path), "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"], required_success=True)
            mounts = json.loads(mount_text)
            require(bool(mounts.get("filesystems")), f"missing filesystem receipt for {name}")
            summary["filesystems"][name] = mounts
            usage = shutil.disk_usage(path)
            summary["filesystems"][name]["capacity_bytes"] = dict(zip(("total", "used", "free"), usage))
            require(all(mount.get("fstype") in LOCAL_FILESYSTEMS and mount.get("source", "").startswith("/dev/") for mount in mounts["filesystems"]), f"{name} must use a prepared persistent local block filesystem")
        run("block-devices", ["lsblk", "--json", "--output", "NAME,PATH,TYPE,SIZE,ROTA,TRAN,MODEL,MOUNTPOINTS"], required_success=True)
        summary["resources_before"] = resource_snapshot()

        def native(label, selector, expected_auth):
            require(sha_file(auth) == expected_auth and tests.read_bytes() == test_bytes, "native source bytes changed unexpectedly")
            command = cargo + ["test", "--manifest-path", "trillionnium/Cargo.toml", "--locked", "--offline", "-p", "trnm-data-availability", "--lib", selector, "--", "--test-threads=1", "--nocapture"]
            return run(label, command, native=True)[0]

        classic = native("retained-classic", "cell::discovery::sequence_tests::", FIXED_SHA)
        # A failed classic observation is retained and does not suppress the
        # red/green differential. It will keep the aggregate result failed.
        run("preflight-before-old-auth", ["bash", "scripts/project-preflight.sh"], required_success=True)
        require(not git(root, "status", "--porcelain").strip(), "source changed before staging old implementation")
        auth.write_bytes(old)
        try:
            require(git(root, "diff", "--name-only").decode().splitlines() == [AUTH_REL], "red phase may change only auth.rs")
            red = native("observed-timing-old-implementation-red", "authenticated_v3_newest_verified_", OLD_SHA)
        finally:
            restore_auth()
        green = native("observed-timing-fixed-implementation-green", "authenticated_v3_newest_verified_", FIXED_SHA)
        summary["retained_classic_passed"] = classic["exit_code"] == 0 and has_counts(classic, 4, 0)
        summary["red_target_reproduced"] = (
            red["exit_code"] == 101 and has_counts(red, 0, 3) and sequence_outcomes(red, "FAILED")
            and red["both_timing_premises_valid"] and red["expired_target_assertions"] == 2
            and red["quota_target_assertions"] == 1 and red["timing_premise_failures"] == 0
            and red["quota_preparation_failures"] == 0
        )
        summary["green_three_passed"] = (
            green["exit_code"] == 0 and has_counts(green, 3, 0) and sequence_outcomes(green, "ok")
            and green["both_timing_premises_valid"] and green["timing_premise_failures"] == 0
            and green["quota_preparation_failures"] == 0
        )
    except BaseException as error:
        summary["runner_error"] = repr(error)
    finally:
        try:
            restore_auth()
            summary["auth_restored"] = auth.read_bytes() == fixed
            summary["tests_unchanged"] = tests.read_bytes() == test_bytes
            summary["final_head"] = git(root, "rev-parse", "HEAD").decode().strip()
            summary["final_status_porcelain"] = git(root, "status", "--porcelain").decode()
            summary["source_restored_exactly_C2"] = (
                summary["auth_restored"] and summary["tests_unchanged"]
                and summary["final_head"] == COMMIT and not summary["final_status_porcelain"]
            )
            if summary["source_restored_exactly_C2"]:
                receipt, _, _ = run("source-after", [sys.executable, "-B", "scripts/ci/verify_ci_source.py", "--kind", "head", "--expected-head", COMMIT, "--output", str(out / "source-after.json")])
                summary["source_after_passed"] = receipt["exit_code"] == 0
                before_path, after_path = out / "source-before.json", out / "source-after.json"
                summary["source_fingerprints_match"] = before_path.is_file() and after_path.is_file() and before_path.read_bytes() == after_path.read_bytes()
                summary["auth_restored"] = auth.read_bytes() == fixed
                summary["tests_unchanged"] = tests.read_bytes() == test_bytes
                summary["final_status_porcelain"] = git(root, "status", "--porcelain").decode()
                summary["source_restored_exactly_C2"] = (
                    summary["auth_restored"] and summary["tests_unchanged"]
                    and not summary["final_status_porcelain"]
                    and git(root, "rev-parse", "HEAD").decode().strip() == COMMIT
                )
            if cargo_home is not None:
                summary["cargo_config_after"] = cargo_config_inputs(root, cargo_home)
                summary["cargo_config_unchanged"] = summary.get("cargo_config_before") == summary["cargo_config_after"]
        except BaseException as error:
            summary["restoration_error"] = repr(error)
            summary["source_restored_exactly_C2"] = False
        summary["resources_after"] = resource_snapshot()
        summary["finished_unix"] = time.time()
        summary["passed"] = (
            not summary.get("runner_error") and not summary.get("restoration_error")
            and all(summary.get(key, False) for key in ("retained_classic_passed", "red_target_reproduced", "green_three_passed", "source_restored_exactly_C2", "source_after_passed", "source_fingerprints_match", "cargo_config_unchanged"))
        )
        save_summary()
        print(json.dumps({"event": "complete", **{key: summary.get(key) for key in ("retained_classic_passed", "red_target_reproduced", "green_three_passed", "auth_restored", "tests_unchanged", "source_restored_exactly_C2", "runner_error", "restoration_error", "passed")}}), flush=True)
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"event": "setup-failed", "error": repr(error)}), file=sys.stderr, flush=True)
        sys.exit(1)
