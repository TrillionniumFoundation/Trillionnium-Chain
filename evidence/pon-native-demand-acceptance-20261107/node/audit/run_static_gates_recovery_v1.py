#!/usr/bin/env python3
"""Re-execute three explicit Python selections on H; no old receipt is recovered.

Only new files under recovery-static-690f-v1 are written. Original source,
recorder, Node job, Git branches and publication are untouched. Actual committed
source bytes/modes are checked before and after every selection. No Cargo,
repository/link gate or negative source-integrity suite is launched.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

BASE = Path("/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2")
SOURCE = BASE / "chain-source-bounded"
ORIGINAL_RUN = BASE / "build-receipts/complete-node-690f710c-v1"
OUT = BASE / "recovery-static-690f-v1"
COMMIT = "690f710c1b6808787996e86aa4c36bd53e1f3939"
TREE = "b9ff2e5c4ca6e465b86cb4b2bd466ad831147899"
SELECTIONS = [
    ("new-references", ["-m", "unittest", "-v",
                        "test_demand_evidence", "test_upgrade_policy"], True),
    ("retained-model", ["-m", "unittest", "-v", "test_reward_budget_oracle",
                       "test_model_evolution_oracle", "test_model_task_windows_oracle",
                       "test_work_utility", "test_public_evaluation_lifecycle",
                       "test_evaluation", "test_evaluation_bundle", "test_model_acceptance"], True),
    ("ci-contract", ["scripts/ci/test_ci_contract.py"], False),
]
RECOVERY = ("New H execution after scratch became unavailable. Prior local raw logs "
            "and receipts were not recovered and their counts are not reused.")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def artifact(path):
    raw = path.read_bytes()
    return {"path": str(path.relative_to(OUT)), "bytes": len(raw), "sha256": sha(raw)}


def create_json(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(raw)
    return artifact(path)


def git(*args):
    return subprocess.check_output(
        ["/usr/bin/git", "--no-replace-objects", *args], cwd=SOURCE)


def source_snapshot():
    commit = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    if commit != COMMIT or tree != TREE:
        raise RuntimeError("source identity changed")
    if git("status", "--porcelain=v1", "-z", "--untracked-files=all"):
        raise RuntimeError("source worktree is not clean")
    materialized, omitted = [], []
    for row in git("ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0"):
        if not row:
            continue
        meta, name = row.split(b"\t", 1)
        mode, kind, blob = meta.decode().split()
        relative = name.decode()
        if kind != "blob":
            raise RuntimeError("unexpected tracked object type: " + relative)
        path = SOURCE / relative
        if not path.exists() and not path.is_symlink():
            if not relative.startswith(("evidence/", "qualification/")):
                raise RuntimeError("missing runtime source: " + relative)
            omitted.append({"path": relative, "mode": mode, "blob": blob})
            continue
        raw = os.readlink(path).encode() if mode == "120000" else path.read_bytes()
        observed_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if observed_blob != blob:
            raise RuntimeError("tracked content changed: " + relative)
        if mode != "120000" and bool(path.stat().st_mode & 0o111) != (mode == "100755"):
            raise RuntimeError("tracked mode changed: " + relative)
        materialized.append({"path": relative, "mode": mode, "blob": blob,
                             "bytes": len(raw), "sha256": sha(raw)})
    value = {"head": commit, "tree": tree, "materialized": materialized,
             "omitted_historical_archive_blobs": omitted}
    encoded = canonical(value)
    digest = sha(encoded)
    original = json.loads((ORIGINAL_RUN / "started.json").read_text())
    if original["expected_commit"] != COMMIT or digest != original["source_sha256"]:
        raise RuntimeError("current full sparse source differs from original Node run snapshot")
    name = "source-" + digest + ".json"
    path = OUT / name
    try:
        with path.open("xb") as stream:
            stream.write(encoded + b"\n")
    except FileExistsError:
        if path.read_bytes() != encoded + b"\n":
            raise RuntimeError("retained new source manifest differs")
    return {"commit": commit, "tree": tree, "canonical_sha256": digest,
            "manifest": artifact(path), "materialized_entries": len(materialized),
            "materialized_bytes": sum(row["bytes"] for row in materialized),
            "omitted_historical_archive_entries": len(omitted),
            "clean": True, "matches_original_node_run": True}


def unittest_counts(stdout, stderr):
    combined = stdout.decode("utf-8", errors="strict") + "\n" + stderr.decode("utf-8", errors="strict")
    matches = list(re.finditer(
        r"(?m)^Ran ([0-9]+) tests? in ([0-9]+(?:\.[0-9]+)?)s\s*\n\s*\n"
        r"(OK(?: \([^\r\n]*\))?|FAILED \([^\r\n]*\))\s*$", combined))
    if len(matches) != 1:
        return {"verified": False, "reason": "expected exactly one complete unittest summary",
                "matching_summary_count": len(matches), "tests_run": None}
    match = matches[0]
    verdict = match[3]
    numbers = {name.strip(): int(value) for name, value in
               re.findall(r"([A-Za-z ]+)=([0-9]+)", verdict)}
    allowed = {"failures", "errors", "skipped", "expected failures", "unexpected successes"}
    if set(numbers) - allowed:
        return {"verified": False, "reason": "unrecognized unittest summary category",
                "verdict": verdict, "tests_run": int(match[1])}
    count = int(match[1])
    category = {key: numbers.get(key, 0) for key in allowed}
    normal_passes = count - sum(category.values())
    if normal_passes < 0:
        return {"verified": False, "reason": "inconsistent unittest category counts",
                "tests_run": count, "categories": category}
    return {"verified": True, "tests_run": count, "passed": normal_passes,
            "failed": category["failures"], "errors": category["errors"],
            "skipped": category["skipped"], "expected_failures": category["expected failures"],
            "unexpected_successes": category["unexpected successes"],
            "framework_outcome": verdict, "framework_seconds": match[2],
            "ignored": None, "ignored_note": "unittest uses skipped; no Rust ignored count inferred"}


def run_gate(selection):
    label, arguments, use_pythonpath = selection
    directory = OUT / label
    directory.mkdir()
    before = source_snapshot()
    command = [sys.executable] + arguments
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if use_pythonpath:
        env["PYTHONPATH"] = "formal/pon-nakamoto-v1"
    else:
        env.pop("PYTHONPATH", None)
    environment = {"PYTHONDONTWRITEBYTECODE": "1",
                   "PYTHONPATH": env.get("PYTHONPATH"),
                   "python_executable": sys.executable, "python_version": sys.version}
    started = time.time()
    timeout = False
    exit_code = None
    with (directory / "stdout.log").open("xb") as stdout, (directory / "stderr.log").open("xb") as stderr:
        try:
            process = subprocess.run(command, cwd=SOURCE, env=env, stdout=stdout, stderr=stderr,
                                     check=False, timeout=300)
            exit_code = process.returncode
        except subprocess.TimeoutExpired:
            timeout = True
    elapsed = time.time() - started
    after = None
    source_error = None
    try:
        after = source_snapshot()
    except Exception as failure:
        source_error = {"type": type(failure).__name__, "message": str(failure)}
    stdout = (directory / "stdout.log").read_bytes()
    stderr = (directory / "stderr.log").read_bytes()
    counts = unittest_counts(stdout, stderr)
    unchanged = before == after and source_error is None
    passed = (exit_code == 0 and not timeout and unchanged and counts.get("verified") is True
              and counts["framework_outcome"].startswith("OK"))
    receipt = {
        "schema": "pon-python-gate-recovery-v1", "label": label, "recovery_provenance": RECOVERY,
        "command": command, "cwd": str(SOURCE), "environment": environment,
        "started_unix_seconds": started, "elapsed_seconds": elapsed,
        "exit_code": exit_code, "timed_out": timeout, "source_before": before,
        "source_after": after, "source_unchanged": unchanged, "source_error": source_error,
        "stdout": artifact(directory / "stdout.log"), "stderr": artifact(directory / "stderr.log"),
        "unittest": counts, "result": "PASS" if passed else "FAIL_OR_UNQUALIFIED",
        "filters_added": False, "tests_skipped_by_runner": False,
        "cargo_invoked_by_runner": False, "original_node_job_modified": False,
        "original_recorder_modified": False, "independent_acceptance": False,
        "production_activation": False,
    }
    reference = create_json(directory / "receipt.json", receipt)
    return {"label": label, "result": receipt["result"], "exit_code": exit_code,
            "source_unchanged": unchanged, "unittest": counts, "receipt": reference}


def main():
    OUT.mkdir()
    initial = source_snapshot()
    with (OUT / "preflight.stdout.log").open("xb") as stdout, (OUT / "preflight.stderr.log").open("xb") as stderr:
        checked = subprocess.run(["/usr/bin/bash", "scripts/project-preflight.sh", "--audit"],
                                 cwd=SOURCE, stdout=stdout, stderr=stderr, check=False, timeout=60)
    preflight = {"command": ["/usr/bin/bash", "scripts/project-preflight.sh", "--audit"],
                 "exit_code": checked.returncode, "stdout": artifact(OUT / "preflight.stdout.log"),
                 "stderr": artifact(OUT / "preflight.stderr.log")}
    create_json(OUT / "preflight.receipt.json", preflight)
    if checked.returncode != 0:
        print(json.dumps({"result": "PREFLIGHT_FAILED", "exit_code": checked.returncode}))
        return checked.returncode
    results = []
    failures = []
    with ThreadPoolExecutor(max_workers=3) as workers:
        pending = {workers.submit(run_gate, selection): selection[0] for selection in SELECTIONS}
        for future in as_completed(pending):
            label = pending[future]
            try:
                result = future.result()
                results.append(result)
                print(json.dumps(result, sort_keys=True), flush=True)
            except Exception as failure:
                record = {"label": label, "error": type(failure).__name__, "message": str(failure),
                          "recovery_provenance": RECOVERY, "qualification": False}
                create_json(OUT / (label + "-runner-failure.json"), record)
                failures.append(record)
                print(json.dumps(record, sort_keys=True), flush=True)
    final = source_snapshot()
    script_raw = Path(__file__).read_bytes()
    summary = {
        "schema": "pon-static-gates-recovery-v1", "recovery_provenance": RECOVERY,
        "source_before": initial, "source_after": final, "source_unchanged": initial == final,
        "selections": [{"label": label, "python_args": args,
                        "pythonpath": "formal/pon-nakamoto-v1" if use else None}
                       for label, args, use in SELECTIONS],
        "results": sorted(results, key=lambda row: row["label"]), "runner_failures": failures,
        "preflight": preflight, "script": {"path": str(Path(__file__)), "bytes": len(script_raw),
                                          "sha256": sha(script_raw)},
        "all_selected_gates_passed": len(results) == 3 and not failures
                                     and all(row["result"] == "PASS" for row in results),
        "old_local_receipts_recovered": False, "cargo_started": False,
        "complete_repository_or_links_or_source_integrity_started": False,
        "production_activation": False, "independent_acceptance": False,
    }
    reference = create_json(OUT / "recovery-static-summary.json", summary)
    print(json.dumps({"summary": reference, "all_selected_gates_passed":
                      summary["all_selected_gates_passed"]}, sort_keys=True))
    return 0 if summary["all_selected_gates_passed"] and initial == final else 1


if __name__ == "__main__":
    raise SystemExit(main())
