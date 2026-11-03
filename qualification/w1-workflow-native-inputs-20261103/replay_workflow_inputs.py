#!/usr/bin/env python3
"""Replay two workflow input failures without provisioning Host or running Rust."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if sys.flags.optimize:
    raise SystemExit("Qualification requires Python assertions; optimized mode is refused")
BASE = "8543bd9f9777d3ef97dbbe55459fa6cb11ec5c2f"
WORKFLOW = ".github/workflows/pon-w1-work-security.yml"
sys.path.insert(0, str(ROOT / "scripts/ci"))
import public_fixture_host_lease as lease


def run(argv, cwd, env=None):
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=30)
    return {"argv": list(map(str, argv)), "cwd": str(cwd), "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def native_validator(workflow):
    start = '          python3 - "$OUT" <<\'PYTEST\'\n'
    assert workflow.count(start) == 1
    body = workflow.split(start, 1)[1].split("          PYTEST\n", 1)[0]
    return textwrap.dedent(body)


def source_preparation(workflow):
    fresh = workflow.split("  fresh-challenge-service:\n", 1)[1]
    step = fresh.split("      - name: Reserve observations and verify ordered source identity\n", 1)[1]
    body = step.split("        run: |\n", 1)[1].split("      - name:", 1)[0]
    body = textwrap.dedent(body)
    audit = 'bash scripts/project-preflight.sh --audit 2>&1 | tee "$out/preflight.log"\n'
    assert body.endswith(audit)
    # Only execute the source-receipt preparation prefix. The real CI retains
    # this audit command, compiler setup, Host provisioning and native tests.
    return body[:-len(audit)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    old = subprocess.check_output(["git", "show", BASE + ":" + WORKFLOW], cwd=ROOT).decode()
    new = (ROOT / WORKFLOW).read_text()
    expected = old.replace('"history-import-tests": (22, 1)',
                           '"history-import-tests": (25, 1)', 1)
    first, fresh = expected.split("  fresh-challenge-service:\n", 1)
    source = '          python3 scripts/ci/verify_ci_source.py "${args[@]}" --output "$out/source-before.json"\n'
    expected = first + "  fresh-challenge-service:\n" + fresh.replace(
        source, source + '          cp -- "$out/source-before.json" "$out/source.json"\n', 1)
    assert new == expected
    observed_path = Path(__file__).with_name("OBSERVED_NATIVE_CONTROLS.json")
    observed = json.loads(observed_path.read_text())
    summaries = observed["summaries"]
    records = []
    with tempfile.TemporaryDirectory(prefix="w1-workflow-input-replay-") as temporary:
        temporary = Path(temporary)
        logs = temporary / "logs"
        logs.mkdir()
        for name, value in summaries.items():
            (logs / (name + ".log")).write_text(value["summary"] + "\n")
        for label, workflow, expected_exit in (("old-real-counts", old, 1),
                                               ("new-real-counts", new, 0)):
            result = run([sys.executable, "-c", native_validator(workflow), str(logs)], ROOT)
            assert result["exit_code"] == expected_exit
            if expected_exit:
                assert "history-import-tests: exact native controls did not execute" in result["stderr"]
            records.append({"case": label, "process": result, "expectation_met": True})
        history = logs / "history-import-tests.log"
        original = history.read_text()
        malformed = {
            "missing-original-test": "test result: ok. 24 passed; 0 failed; 1 ignored;\n",
            "unexpected-extra-test": "test result: ok. 26 passed; 0 failed; 1 ignored;\n",
            "lost-ignored-fixture": "test result: ok. 25 passed; 0 failed; 0 ignored;\n",
            "additional-ignore": "test result: ok. 25 passed; 0 failed; 2 ignored;\n",
            "duplicate-summary": original + original,
            "native-failure": "test result: FAILED. 24 passed; 1 failed; 1 ignored;\n",
        }
        for label, value in malformed.items():
            history.write_text(value)
            result = run([sys.executable, "-c", native_validator(new), str(logs)], ROOT)
            assert result["exit_code"] == 1
            records.append({"case": label, "process": result, "expectation_met": True})
        history.write_text(original)

        fixture = temporary / "repository"
        fixture.mkdir()
        verify = fixture / "scripts/ci/verify_ci_source.py"
        verify.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/ci/verify_ci_source.py", verify)
        git_env = os.environ.copy()
        git_env.update({"GIT_AUTHOR_NAME": "Workflow input control",
                        "GIT_COMMITTER_NAME": "Workflow input control",
                        "GIT_AUTHOR_EMAIL": "workflow-control@example.invalid",
                        "GIT_COMMITTER_EMAIL": "workflow-control@example.invalid"})

        def git(*argv):
            result = run(["git", *argv], fixture, git_env)
            assert result["exit_code"] == 0, result
            return result["stdout"].strip()

        git("init", "-q", "-b", "base")
        git("add", ".")
        git("commit", "-q", "-m", "common")
        common = git("rev-parse", "HEAD")
        (fixture / "base.txt").write_text("base\n")
        git("add", ".")
        git("commit", "-q", "-m", "base")
        base = git("rev-parse", "HEAD")
        git("checkout", "-q", "-b", "candidate", common)
        (fixture / "candidate.txt").write_text("candidate\n")
        git("add", ".")
        git("commit", "-q", "-m", "candidate")
        candidate = git("rev-parse", "HEAD")
        git("checkout", "-q", "base")
        git("merge", "-q", "--no-ff", "-m", "ordered merge", "candidate")
        merge = git("rev-parse", "HEAD")
        assert git("show", "-s", "--format=%P", merge) == base + " " + candidate
        for kind, commit in (("head", candidate), ("prospective-merge", merge)):
            git("checkout", "-q", "--detach", commit)
            for version, workflow in (("old", old), ("new", new)):
                temp = temporary / (kind + "-" + version)
                temp.mkdir()
                env = os.environ.copy()
                env.update({"SOURCE_KIND": kind, "EXPECTED_HEAD": candidate,
                            "EXPECTED_BASE": base, "EXPECTED_SOURCE": commit,
                            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                            "RUNNER_TEMP": str(temp), "GITHUB_ENV": str(temp / "env")})
                result = run(["bash", "-c", source_preparation(workflow)], fixture, env)
                assert result["exit_code"] == 0, result
                receipts = temp / ("w1-fresh-service-" + kind + "-123-1")
                receipt = json.loads((receipts / "source-before.json").read_text())
                assert receipt["tested_commit"] == commit
                with patch.object(lease, "ROOT", fixture), patch.dict(os.environ, {
                    "TRNM_EXPECTED_SOURCE_SHA": commit, "TRNM_CI_RECEIPT_DIR": str(receipts),
                }):
                    error = None
                    try:
                        actual = lease.workflow_source()
                    except (OSError, ValueError) as caught:
                        error = type(caught).__name__ + ": " + str(caught)
                    if version == "old":
                        assert error and "FileNotFoundError" in error and "source.json" in error
                    else:
                        assert error is None and actual == receipt
                        assert (receipts / "source.json").read_bytes() == (receipts / "source-before.json").read_bytes()
                    records.append({"case": kind + "-" + version + "-source-receipt",
                                    "process": result, "reader_error": error,
                                    "expectation_met": True, "receipt": receipt})
                    if version == "new":
                        wrong = copy.deepcopy(receipt)
                        wrong["tested_commit"] = "0" * 40
                        (receipts / "source.json").write_text(json.dumps(wrong))
                        try:
                            lease.workflow_source()
                        except ValueError as caught:
                            assert str(caught) == "FIXTURE_PARENT_WORKFLOW_SOURCE_REQUIRED"
                            records.append({"case": kind + "-wrong-receipt-sha", "reader_error": str(caught),
                                            "expectation_met": True})
                        else:
                            raise AssertionError("wrong source was accepted")
                        (receipts / "source.json").write_bytes((receipts / "source-before.json").read_bytes())
                        tracked = fixture / "candidate.txt"
                        saved = tracked.read_bytes()
                        tracked.write_bytes(saved + b"changed\n")
                        try:
                            lease.workflow_source()
                        except ValueError as caught:
                            assert str(caught) == "source is not clean"
                            records.append({"case": kind + "-changed-tracked-source", "reader_error": str(caught),
                                            "expectation_met": True})
                        else:
                            raise AssertionError("changed tracked source was accepted")
                        finally:
                            tracked.write_bytes(saved)
        inputs = [WORKFLOW, "scripts/ci/public_fixture_host_lease.py", "scripts/ci/verify_ci_source.py",
                  "scripts/ci/run_from_zero_host.py", "scripts/ci/run_history_native.py",
                  "trillionnium/crates/trnm-pon-node/src/ingress/history_import_tests.rs",
                  "trillionnium/crates/trnm-pon-node/src/ingress/history_import_deadline_tests.rs"]
        receipt = {"schema": "w1-workflow-input-replay-v1", "base": BASE,
                   "scope": "Exact workflow validator and source-preparation prefix; real small Git head/ordered-merge receipts; real lease source reader. No Host provisioning, Rust build, native gate or performance qualification.",
                   "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "observed_native_controls_sha256": hashlib.sha256(observed_path.read_bytes()).hexdigest(),
                   "old_workflow_sha256": hashlib.sha256(old.encode()).hexdigest(),
                   "inputs": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in inputs},
                   "conditions": records, "conditions_matched": len(records), "all_expectations_met": True,
                   "host_qualified": False, "native_qualified": False, "performance_qualified": False}
        (args.output / "RECEIPT.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
