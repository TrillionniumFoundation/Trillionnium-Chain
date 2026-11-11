#!/usr/bin/env python3
"""Working-tree native ancestry-clock regression; preserve negative observations."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import time
import traceback

ROOT = Path("/home/qian-qi/work/chain-quantum-daa-20261111-qdaa")
EVIDENCE = Path("/home/qian-qi/work/chain-quantum-daa-20261111-qdaa-evidence/native-precommit")
TARGET = Path("/home/qian-qi/work/chain-quantum-daa-20261111-qdaa-native-target")
BUNDLE = Path("/home/qian-qi/chain-qdaa-clock-guard-prepared-20261111.json")
EXPECTED_BUNDLE = "7beac224da1f78281a9e565bbf0872da79dd27e9d64a2250c0b2ff4f3ef2887d"
BASE = "e4abb172147e941b62483652b0ceabaae4317624"
NEW_TEST = "public_growth_v1_future_ancestor_defers_fresh_and_duplicate_before_work"
RETAINED_TEST = "public_growth_v1_rechecks_future_ancestry_before_new_and_duplicate_activation"
TEST_PATH = "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/growth/tests.rs"
record = {
    "scope": "precommit-working-tree-three-native-files",
    "is_committed_source_validation": False,
    "status": "STARTING",
    "started_unix": time.time(),
    "base_commit": BASE,
    "root": str(ROOT),
    "cargo_target_dir": str(TARGET),
    "cargo_environment_overrides": {"CARGO_TARGET_DIR": str(TARGET), "CARGO_BUILD_JOBS": "2"},
    "repository_manifest_profile_overrides": "unchanged",
    "commands": [],
    "limitations": [
        "Other agents may concurrently edit unrelated files; no full-tree clean assertion is made.",
        "This validates native current-eligibility ordering and fixture behavior, not a quantum security theorem.",
        "The retained postcommit test is independent of the new pre-W1 guard.",
        "No fixture here directly forces wall-clock rollback during unlocked W1 and owner reacquisition.",
    ],
}
env = os.environ.copy()
env.update(record["cargo_environment_overrides"])

def save():
    tmp = EVIDENCE / "02-native-run.json.tmp"
    tmp.write_text(json.dumps(record, indent=2) + "\n")
    os.replace(tmp, EVIDENCE / "02-native-run.json")

def hashes(path):
    data = (ROOT / path).read_bytes()
    return {
        "path": path,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "git_blob_sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
    }

def run(label, argv, *, expected_exit=None):
    item = {
        "label": label,
        "argv": argv,
        "cwd": str(ROOT),
        "environment_overrides": record["cargo_environment_overrides"],
        "started_unix": time.time(),
        "log": label + ".log",
    }
    record["commands"].append(item)
    record["status"] = "RUNNING_" + label
    save()
    print("NATIVE_PHASE_START " + label, flush=True)
    with (EVIDENCE / item["log"]).open("x") as log:
        completed = subprocess.run(argv, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    item["exit_code"] = completed.returncode
    item["seconds"] = time.time() - item["started_unix"]
    item["finished_unix"] = time.time()
    item["log_sha256"] = hashlib.sha256((EVIDENCE / item["log"]).read_bytes()).hexdigest()
    save()
    print("NATIVE_PHASE_END " + label + " exit=" + str(completed.returncode), flush=True)
    if expected_exit is not None and completed.returncode != expected_exit:
        raise RuntimeError(label + " returned " + str(completed.returncode))
    return completed.returncode, (EVIDENCE / item["log"]).read_text(errors="replace")

def cargo_command(test):
    return [
        "cargo", "test", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml",
        "-p", "trnm-pon-node", test, "--", "--nocapture", "--test-threads=1",
    ]

try:
    preflight = json.loads((EVIDENCE / "01-preflight.json").read_text())
    assert preflight["preflight_exit_code"] == 0
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == BASE
    bundle_bytes = BUNDLE.read_bytes()
    assert hashlib.sha256(bundle_bytes).hexdigest() == EXPECTED_BUNDLE
    bundle = json.loads(bundle_bytes)
    assert bundle["status"] == "PREPARED_NOT_EXECUTED"
    files = {entry["path"]: entry for entry in bundle["files"]}
    assert len(files) == 3
    record["bundle_sha256"] = EXPECTED_BUNDLE
    record["before_files"] = [hashes(path) for path in files]
    for item in record["before_files"]:
        assert item["git_blob_sha"] == files[item["path"]]["original_git_blob_sha"], item
        backup = EVIDENCE / "originals" / item["path"]
        backup.parent.mkdir(parents=True, exist_ok=True)
        with backup.open("xb") as destination:
            destination.write((ROOT / item["path"]).read_bytes())
    record["cargo_lock_before"] = hashes("trillionnium/Cargo.lock")
    record["cargo_manifest_before"] = hashes("trillionnium/Cargo.toml")
    if TARGET.exists():
        raise RuntimeError("Independent target already exists; refusing to assume ownership.")
    TARGET.mkdir(parents=True)
    (TARGET / "native-qdaa-owner.json").write_text(json.dumps({
        "task": "native-precommit-clock-guard", "root": str(ROOT),
        "created_unix": time.time(), "base": BASE,
    }, indent=2) + "\n")
    # Test-only change first: both production files must stay at the original blobs.
    test_text = files[TEST_PATH]["complete_replacement_text"]
    (ROOT / TEST_PATH).write_text(test_text)
    record["baseline_files"] = [hashes(path) for path in files]
    for item in record["baseline_files"]:
        if item["path"] != TEST_PATH:
            assert item["git_blob_sha"] == files[item["path"]]["original_git_blob_sha"]
    needle = "assert_eq!(run.metrics.lock().unwrap().work_started, work_before);"
    at = test_text.index(needle, test_text.index("fn " + NEW_TEST))
    work_assert_line = test_text[:at].count("\n") + 1
    record["baseline_expected_assertion"] = {
        "test": NEW_TEST,
        "path": TEST_PATH,
        "line": work_assert_line,
        "assertion": needle,
        "meaning": "work_started must remain unchanged when retained ancestry is currently future-ineligible",
    }
    save()
    baseline_exit, baseline_text = run("03-baseline-new-regression", cargo_command(NEW_TEST))
    offline_missing = (
        baseline_exit != 0
        and "offline" in baseline_text.lower()
        and (
            "attempting to make an HTTP request" in baseline_text
            or "no matching package named" in baseline_text
            or "failed to download" in baseline_text
        )
        and "test result:" not in baseline_text
    )
    if offline_missing:
        record["offline_cache_miss_preserved"] = True
        save()
        run("03a-locked-fetch", ["cargo", "fetch", "--locked", "--manifest-path", "trillionnium/Cargo.toml"], expected_exit=0)
        assert hashes("trillionnium/Cargo.lock")["sha256"] == record["cargo_lock_before"]["sha256"]
        baseline_exit, baseline_text = run("03b-baseline-new-regression-after-fetch", cargo_command(NEW_TEST))
    expected_failure = (
        baseline_exit != 0
        and "test result: FAILED" in baseline_text
        and NEW_TEST in baseline_text
        and ("tests.rs:" + str(work_assert_line) + ":") in baseline_text
        and "assertion " in baseline_text
    )
    record["baseline_behavioral_counterexample_verified"] = expected_failure
    record["baseline_actual_exit_code"] = baseline_exit
    record["baseline_observed_failure_kind"] = (
        "expected_work_started_assertion" if expected_failure else
        "build_or_runtime_killed" if ("signal: 9" in baseline_text or "SIGKILL" in baseline_text or "Killed" in baseline_text) else
        "unexpected_failure_or_unexpected_pass"
    )
    save()
    if not expected_failure:
        raise RuntimeError("Baseline did not establish the expected behavioral counterexample; production sources remain unchanged.")
    for path, entry in files.items():
        if path != TEST_PATH:
            assert hashes(path)["git_blob_sha"] == entry["original_git_blob_sha"], path
    assert (ROOT / TEST_PATH).read_text() == test_text
    # Apply only the two production files; the reviewed test file is already present.
    for path, entry in files.items():
        if path != TEST_PATH:
            (ROOT / path).write_text(entry["complete_replacement_text"])
    record["applied_files_before_format"] = [hashes(path) for path in files]
    save()
    run("04-rustfmt-three-files", [
        "rustfmt", "--edition", "2021", "--config", "skip_children=true", *files.keys(),
    ], expected_exit=0)
    record["after_files"] = [hashes(path) for path in files]
    save()
    run("05-diff-check-three-files", ["git", "diff", "--check", "--", *files.keys()], expected_exit=0)
    with (EVIDENCE / "native-three-files.diff").open("x") as log:
        diff_result = subprocess.run(["git", "diff", "--", *files.keys()], cwd=ROOT, text=True, stdout=log, stderr=subprocess.STDOUT)
    assert diff_result.returncode == 0
    run("06-after-new-regression", cargo_command(NEW_TEST), expected_exit=0)
    run("07-after-retained-postcommit", cargo_command(RETAINED_TEST), expected_exit=0)
    run("08-after-public-growth-v1-subtree", cargo_command("public_growth_v1"), expected_exit=0)
    record["after_files"] = [hashes(path) for path in files]
    record["cargo_lock_after"] = hashes("trillionnium/Cargo.lock")
    record["cargo_manifest_after"] = hashes("trillionnium/Cargo.toml")
    assert record["cargo_lock_after"]["sha256"] == record["cargo_lock_before"]["sha256"]
    assert record["cargo_manifest_after"]["sha256"] == record["cargo_manifest_before"]["sha256"]
    record["status"] = "PASSED_WITH_BASELINE_BEHAVIORAL_COUNTEREXAMPLE"
    record["finished_unix"] = time.time()
    save()
    print("NATIVE_VALIDATION_COMPLETE " + json.dumps({
        "status": record["status"], "target": str(TARGET),
        "baseline_actual_exit_code": record["baseline_actual_exit_code"],
        "after_files": record["after_files"],
    }), flush=True)
except BaseException as error:
    record["status"] = "STOPPED_ERROR"
    record["error"] = repr(error)
    record["finished_unix"] = time.time()
    save()
    traceback.print_exc()
    raise
