#!/usr/bin/env python3
"""Original-profile Node storage tests for this isolated ai395 candidate."""
import datetime
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

REPO = Path("/home/qq/work/chain-cell-capacity-dc0357-20261109")
EVIDENCE = Path("/home/qq/work/chain-cell-capacity-dc0357-20261109-validation")
TOOLCHAIN = Path("/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin")
PROVIDER = Path("/home/qq/work/chain-cell-discovery-provider-f2568-20261108/runner/trnm-pq-provider-3.5.9.ReYCJ9gV/install")
PROVIDER_SHA256 = "ed29dfe14c0686c876833e39fbeedb277846987f3728acc279c256b32259cf62"
PATCH_GZIP_SHA256 = "a4cce005c860dda57076be1138fe5dd4681ab85ca718bc71afb60dca39d75573"
label, expected_head, fmt_mode = sys.argv[1:]
if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,95}", label):
    raise SystemExit("invalid observation label")
if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
    raise SystemExit("invalid expected HEAD")
if fmt_mode not in ("format", "check-format"):
    raise SystemExit("expected format or check-format")
EVIDENCE.mkdir(exist_ok=True)
paths = {name: EVIDENCE / (label + suffix) for name, suffix in (
    ("start", "-start.json"), ("test_start", "-test-start.json"),
    ("log", ".log"), ("end", "-observation.json"))}
for path in paths.values():
    if path.exists():
        raise SystemExit("refusing to overwrite prior observation: " + str(path))
tmp_root = EVIDENCE / "tmp"
tmp_root.mkdir(exist_ok=True)
task_tmp = tmp_root / label
task_tmp.mkdir(mode=0o700)
env = os.environ.copy()
env.update({
    "PATH": str(TOOLCHAIN) + ":" + env.get("PATH", "/usr/bin:/bin"),
    "RUSTC": str(TOOLCHAIN / "rustc"),
    "RUSTDOC": str(TOOLCHAIN / "rustdoc"),
    "CARGO_HOME": "/home/qq/.cargo",
    "CARGO_TARGET_DIR": "/home/qq/work/chain-cell-capacity-dc0357-20261109-target",
    "CARGO_BUILD_JOBS": "2",
    "CARGO_INCREMENTAL": "0",
    "CARGO_TERM_COLOR": "never",
    "TMPDIR": str(task_tmp),
    "OPENSSL_DIR": str(PROVIDER),
    "OPENSSL_STATIC": "1",
    "OPENSSL_CONF": "/dev/null",
    "OPENSSL_MODULES": str(PROVIDER / "lib/ossl-modules"),
    "TRNM_PQ_OPENSSL": str(PROVIDER / "bin/openssl"),
    "TRNM_PQ_OPENSSL_SHA256": PROVIDER_SHA256,
    "TRNM_PQ_OPENSSL_VERSION": "3.5.9",
})
for name in ("RUSTC", "RUSTDOC"):
    path = Path(env[name])
    if not path.is_absolute() or not path.is_file() or path.resolve() != path:
        raise SystemExit(name + " must be a canonical absolute compiler tool")
toolchain_root = Path(env["RUSTC"]).resolve().parent.parent
toolchain_lib = (toolchain_root / "lib").resolve()
if not toolchain_lib.is_dir() or toolchain_lib.parent != toolchain_root:
    raise SystemExit("canonical toolchain lib directory required")
# Match scripts/ci/check_sqlite_build_requalification.py exactly: seed only
# Cargo 1.95\'s omitted canonical compiler lib. The original build fence still
# verifies Cargo\'s complete derived loader set and every other qualification.
env["LD_LIBRARY_PATH"] = str(toolchain_lib)
cargo = str(TOOLCHAIN / "cargo")

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for data in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()

def output(args):
    return subprocess.check_output(args, cwd=REPO, env=env, text=True).strip()

def source_hashes():
    raw = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=REPO, env=env)
    names = [os.fsdecode(value) for value in raw.split(b"\0") if value]
    result = {}
    for name in sorted(set(names)):
        if name.startswith("trillionnium/") or name in (
            "AGENTS.md", "scripts/project-preflight.sh",
            "config/portability-inventory-v1.json"):
            path = REPO / name
            if path.is_file():
                result[name] = digest(path)
    return result

def save(path, value):
    with path.open("x") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())

def capture_sqlite_build_outputs(tag):
    observations = []
    directory = Path(env["CARGO_TARGET_DIR"]) / "debug/build"
    for path in sorted(directory.glob("trnm-sqlite-io-boundary-*/output")):
        raw = path.read_bytes()
        retained = EVIDENCE / (label + "-" + tag + "-" + path.parent.name + "-output.txt")
        with retained.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        observations.append({
            "path": str(path), "retained": str(retained),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "mtime_ns": path.stat().st_mtime_ns,
            "qualified": b"cargo:rustc-cfg=trnm_sqlite_layout_witness\n" in raw,
            "unqualified_reason": next((line for line in raw.decode().splitlines()
                                         if "UNQUALIFIED:" in line), None),
        })
    return observations

def filesystem_capacity():
    result = {}
    for path in (Path("/tmp"), task_tmp):
        stat = os.statvfs(path)
        result[str(path)] = {"available_bytes": stat.f_bavail * stat.f_frsize,
                             "free_inodes": stat.f_favail, "device": os.stat(path).st_dev}
    return result

def disk():
    value = shutil.disk_usage(REPO)
    return {"total_bytes": value.total, "used_bytes": value.used,
            "available_bytes": value.free}

head = output(["git", "rev-parse", "HEAD"])
tree = output(["git", "rev-parse", "HEAD^{tree}"])
require_clean = fmt_mode == "check-format"
if head != expected_head:
    raise SystemExit("HEAD differs from the authorized candidate")
actual_provider_sha = digest(Path(env["TRNM_PQ_OPENSSL"]))
if actual_provider_sha != PROVIDER_SHA256:
    raise SystemExit("original provider binary SHA256 mismatch")
provider_version = output([env["TRNM_PQ_OPENSSL"], "version"])
if not provider_version.startswith("OpenSSL 3.5.9 "):
    raise SystemExit("original provider version mismatch")
rustc_version = output([env["RUSTC"], "--version"])
if not rustc_version.startswith("rustc 1.95.0 "):
    raise SystemExit("Rust toolchain version mismatch")
preflight = ["bash", "scripts/project-preflight.sh"]
format_command = [cargo, "fmt", "--all"]
if fmt_mode == "check-format":
    format_command += ["--", "--check"]
test_command = [cargo, "test", "--locked", "--offline", "--jobs", "2",
                "-p", "trnm-pon-node", "--features", "pq-native-openssl",
                "--lib", "storage_service", "--", "--test-threads=1"]
before = source_hashes()
previous_build_outputs = capture_sqlite_build_outputs("previous")
started = now()
clock = time.monotonic()
start = {
    "started_at_utc": started, "label": label, "head": head, "tree": tree,
    "clean_commit_required": require_clean,
    "branch": output(["git", "branch", "--show-current"]),
    "working_tree_status": output(["git", "status", "--short"]),
    "initial_candidate_patch_gzip_sha256": PATCH_GZIP_SHA256,
    "preparation_dirty_candidate": fmt_mode == "format",
    "original_package_profile": True,
    "profile_overrides": [],
    "incremental_enabled": False,
    "test_command": test_command, "format_command": format_command,
    "cwd": str(REPO / "trillionnium"),
    "rustc_version": rustc_version,
    "cargo_version": output([cargo, "--version"]),
    "provider_binary_sha256": actual_provider_sha,
    "provider_version": provider_version,
    "loader_path_seed": str(toolchain_lib),
    "previous_sqlite_build_outputs": previous_build_outputs,
    "selected_environment": {name: env[name] for name in (
        "RUSTC", "RUSTDOC", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS",
        "CARGO_INCREMENTAL", "LD_LIBRARY_PATH", "TMPDIR", "OPENSSL_DIR", "OPENSSL_STATIC", "OPENSSL_CONF",
        "OPENSSL_MODULES", "TRNM_PQ_OPENSSL", "TRNM_PQ_OPENSSL_SHA256",
        "TRNM_PQ_OPENSSL_VERSION")},
    "disk_before": disk(), "filesystem_capacity_before": filesystem_capacity(),
    "source_sha256_before_format": before,
}
save(paths["start"], start)
print(json.dumps({"observation_started": label, "start": str(paths["start"]),
                  "log": str(paths["log"]), "command": test_command}), flush=True)
phase = "preflight"
exit_code = None
failure = None
interrupted = False
process = None
test_before = None
test_head = None
test_status = None
try:
    with paths["log"].open("xb", buffering=0) as log:
        phases = (("preflight", preflight, REPO),
                  ("format", format_command, REPO / "trillionnium"),
                  ("cargo-test", test_command, REPO / "trillionnium"))
        for phase, command, cwd in phases:
            if phase == "cargo-test":
                test_before = source_hashes()
                test_head = output(["git", "rev-parse", "HEAD"])
                if test_head != expected_head:
                    raise RuntimeError("HEAD changed before Cargo test")
                test_status = output(["git", "status", "--short"])
                if require_clean and test_status:
                    raise RuntimeError("exact-commit mode requires a clean working tree")
                save(paths["test_start"], {
                    "started_at_utc": now(), "head": test_head, "tree": tree,
                    "working_tree_status": test_status,
                    "clean_commit_required": require_clean,
                    "source_sha256": test_before, "command": test_command,
                    "format_changed_files": sorted(
                        name for name in before.keys() | test_before.keys()
                        if before.get(name) != test_before.get(name)),
                    "original_package_profile": True,
                    "profile_overrides": [], "incremental_enabled": False,
                })
            marker = ("\n=== " + phase + " " + now() + " ===\n").encode()
            log.write(marker)
            sys.stdout.buffer.write(marker)
            sys.stdout.buffer.flush()
            process = subprocess.Popen(command, cwd=cwd, env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                for line in process.stdout:
                    log.write(line)
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
                exit_code = process.wait()
            except KeyboardInterrupt:
                interrupted = True
                os.killpg(process.pid, signal.SIGINT)
                try:
                    exit_code = process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    exit_code = process.wait(timeout=10)
                break
            finally:
                process.stdout.close()
            if exit_code != 0:
                break
        os.fsync(log.fileno())
except Exception as error:
    failure = {"type": type(error).__name__, "detail": str(error)}
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
    if exit_code is None:
        exit_code = 125
after = source_hashes()
final_head = output(["git", "rev-parse", "HEAD"])
final_tree = output(["git", "rev-parse", "HEAD^{tree}"])
final_status = output(["git", "status", "--short"])
final_build_outputs = capture_sqlite_build_outputs("final")
# Cargo test and Clippy can have separate build-script units in this target.
# A previously refused Node unit must itself reexecute and qualify; another
# unit's positive cfg is not evidence that this original refusal recovered.
previous_by_path = {row["path"]: row for row in previous_build_outputs}
final_by_path = {row["path"]: row for row in final_build_outputs}
qualified_now = bool(final_build_outputs) and all(
    row["qualified"] for row in final_build_outputs)
reexecuted_paths = sorted(path for path, row in final_by_path.items()
    if path not in previous_by_path or
    row["mtime_ns"] != previous_by_path[path]["mtime_ns"])
required_requalification_paths = sorted(path for path, row in previous_by_path.items()
    if not row["qualified"])
requalified_paths = sorted(path for path in required_requalification_paths
    if path in final_by_path and final_by_path[path]["qualified"]
    and path in reexecuted_paths)
build_reexecuted = bool(reexecuted_paths)
requalification_valid = qualified_now and (
    requalified_paths == required_requalification_paths)
changed = [] if test_before is None else sorted(
    name for name in test_before.keys() | after.keys()
    if test_before.get(name) != after.get(name))
result = {
    "started_at_utc": started, "completed_at_utc": now(),
    "elapsed_seconds": time.monotonic() - clock, "phase": phase,
    "exit_code": exit_code, "interrupted": interrupted, "wrapper_failure": failure,
    "test_command": test_command, "original_package_profile": True,
    "profile_overrides": [], "incremental_enabled": False,
    "head_at_test_start": test_head, "head_at_completion": final_head,
    "tree_at_start": tree, "tree_at_completion": final_tree,
    "clean_commit_required": require_clean,
    "loader_path_seed": str(toolchain_lib),
    "sqlite_build_outputs": final_build_outputs,
    "sqlite_gate_qualified": qualified_now,
    "sqlite_build_reexecuted": build_reexecuted,
    "sqlite_reexecuted_paths": reexecuted_paths,
    "sqlite_required_requalification_paths": required_requalification_paths,
    "sqlite_requalified_paths": requalified_paths,
    "sqlite_requalification_valid": requalification_valid,
    "working_tree_status_at_test_start": test_status,
    "working_tree_status_at_completion": final_status,
    "source_changed_during_test": changed, "source_sha256_at_completion": after,
    "unchanged_source_pass": phase == "cargo-test" and exit_code == 0
        and not interrupted and failure is None and not changed
        and final_head == test_head == expected_head and final_tree == tree
        and (not require_clean or (test_status == "" and final_status == ""))
        and requalification_valid,
    "disk_after": disk(), "filesystem_capacity_after": filesystem_capacity(),
    "log_sha256": digest(paths["log"]),
}
save(paths["end"], result)
print(json.dumps({key: value for key, value in result.items()
                  if key != "source_sha256_at_completion"}), flush=True)
raise SystemExit(0 if result["unchanged_source_pass"] else
                 (exit_code if isinstance(exit_code, int) and 0 < exit_code < 126 else 125))
