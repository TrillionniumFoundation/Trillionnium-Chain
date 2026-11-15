#!/usr/bin/env python3
"""Archive observed qualification and commit evidence; never push or create a PR."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

if not __debug__ or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE"):
    raise RuntimeError("optimized Python refused")

ROOT = Path("/home/qian-qi/work/chain-pon-outcome-7612-final")
HEAD = "04f5b5515774aab6663bb80cf7831fe07367ba81"
RUNNER_SHA = "01fcfb229fba3f6dae4d8709e18a23992c472b2eb3844880b5d301ee904d2ba6"
EVIDENCE = "evidence/pon-learning-outcome-composition-20261111"
PLAN = "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
BRANCH = "fix/chain-pon-learning-outcome-composition-20261111-7612"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(path.read_bytes())


def write_json(path, value):
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def inventory(directory):
    rows = []
    for path in sorted(directory.rglob("*")):
        require(not path.is_symlink(), "symlink in evidence")
        if path.is_file():
            rows.append({"path": path.relative_to(directory).as_posix(),
                         "bytes": path.stat().st_size, "sha256": sha(path)})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terminal-json", required=True, type=Path)
    parser.add_argument("--hepta-payload", required=True, type=Path)
    parser.add_argument("--gate-dir", required=True, type=Path)
    args = parser.parse_args()
    audit = ROOT.parent / "chain-pon-outcome-7612-c3-finalization"
    audit.mkdir(mode=0o700)
    calls = []

    def run(label, command, *, data=None):
        print("BEGIN", label, flush=True)
        result = subprocess.run(command, cwd=ROOT, input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (audit / (label + ".stdout")).write_bytes(result.stdout)
        (audit / (label + ".stderr")).write_bytes(result.stderr)
        calls.append({"label": label, "command": command, "exit_code": result.returncode,
                      "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr)})
        (audit / "commands.json").write_text(json.dumps(calls, indent=2) + "\n")
        print("END", label, result.returncode, flush=True)
        require(result.returncode == 0, "finalization command failed: " + label)
        return result.stdout

    require(run("head-before", ["git", "rev-parse", "HEAD"]).decode().strip() == HEAD, "unexpected final checkout")
    require(run("branch-before", ["git", "branch", "--show-current"]).decode().strip() == BRANCH, "wrong branch")
    require(not run("tracked-diff-before", ["git", "diff", "HEAD", "--name-only"]), "tracked changes before archive")
    run("preflight-before", ["bash", "scripts/project-preflight.sh"])

    source = args.gate_dir
    require(source.is_absolute() and source.parent == ROOT.parent and source.resolve(strict=True) == source
            and source.name.startswith("chain-pon-outcome-7612-c2-gates-04f5b5515774-"), "unexpected gate output directory")
    summary = json.loads((source / "summary.json").read_text())
    require(summary["source_head"] == HEAD and summary["result"] == "PASS" and
            summary["planned_commands"] == summary["recorded_commands"] == 26 and
            not summary["failed_commands"] and not summary["missing_commands"] and
            summary["failure"] is None and summary["provider_prepared_and_unchanged"] is True,
            "provider-qualified C2 did not pass")
    require(sha(source / "runner.py") == RUNNER_SHA, "qualified runner changed")
    original_members = []
    for line in (source / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        relative = Path(name)
        require(not relative.is_absolute() and ".." not in relative.parts, "unsafe checksum path")
        path = source / relative
        require(path.is_file() and not path.is_symlink() and sha(path) == expected, "raw checksum differs: " + name)
        original_members.append(name)
    require(len(original_members) == len(set(original_members)), "duplicate checksum members")
    require(set(original_members) == {row["path"] for row in inventory(source)} - {"SHA256SUMS"}, "incomplete raw checksum manifest")
    bundle = json.loads((source / "commands.json").read_text())
    rows = bundle["commands"]
    plan = json.loads((source / "plan.json").read_text())
    require(bundle["source_head"] == plan["head"] == HEAD and
            [row["label"] for row in rows] == plan["labels"] and len(rows) == 26,
            "command plan differs")
    for row in rows:
        require(row["accepted"] is True and row["exit_code"] == 0 and not row["timed_out"] and
                not row["interrupted"] and row["execution_error"] is None, "failed command in qualified record")
        for stream in ("stdout", "stderr"):
            require(sha(source / row[stream]) == row[stream + "_sha256"], "command bytes differ")
        require(sha(source / row["record"]) == row["record_sha256"], "command record differs")
    native = {r["label"]: r["expected_rust_tests"] for r in rows if r["expected_rust_tests"] is not None}
    require(sum(native.values()) == 42 and len(native) == 6, "native inventory differs")
    readers = {r["label"]: r["observations"]["python_tests"][0] for r in rows if r["label"].startswith("reader-")}
    require(len(readers) == 6 and readers["reader-cell_learning_local_use_join"] == 19, "reader inventory differs")
    before = json.loads((source / "source-before.json").read_text())
    after = json.loads((source / "source-after.json").read_text())
    require(before == after and before["tested_commit"] == HEAD and before["tracked_worktree_verified"] is True,
            "source identity changed during native gates")

    original_terminal = args.terminal_json.read_bytes()
    terminal = json.loads(original_terminal)
    raw = bytes.fromhex(terminal["bytes_hex"])
    require(terminal["offset"] == 0 and terminal["next_offset"] == terminal["available_end"] == len(raw), "terminal page incomplete")
    require(terminal["status"]["state"] == "exited" and terminal["status"]["exit_code"] == 0 and
            terminal["status"]["capture_error"] is None and terminal["status"]["output_complete"] is True and
            terminal["output_complete"] is True and digest(raw) == terminal["chunk_sha256"], "terminal not complete success")
    finished = [line for line in raw.decode().splitlines() if line.startswith("C2_GATES_FINISHED ")]
    require(len(finished) == 1 and json.loads(finished[0].split(" ", 1)[1]) == summary, "original completion marker differs")

    evidence = ROOT / EVIDENCE
    for name, pin, failures in (
        ("native-c2-attempt1", "bd84f0e75104d5bbc27ce9ea02aa281fd0c731c29572b0ceee41cb6c5a7b93b5", ["workspace-strict-clippy"]),
        ("native-c2-attempt2", "8671856a9ab7f0a33b6729894527a3a451e1d866627da4587d2ed9dfaf0312de", ["source-before", "source-after"]),
    ):
        failed = evidence / name / "ARCHIVE_MANIFEST.json"
        require(sha(failed) == pin, "failed attempt archive changed: " + name)
        failed_manifest = json.loads(failed.read_text())
        require(failed_manifest["source_head"] == HEAD and failed_manifest["original_summary_result"] == "FAIL"
                and failed_manifest["failed_commands"] == failures, "failed archive identity differs")
        expected_failed = {row["path"]: row for row in failed_manifest["files"]}
        require(len(expected_failed) == len(failed_manifest["files"]), "duplicate failed archive members")
        actual_failed = {row["path"]: row for row in inventory(failed.parent) if row["path"] != failed.name}
        require(actual_failed == expected_failed, "failed archive original bytes differ")
    destination = evidence / "native-c2"
    require(not destination.exists(), "qualified archive already exists; inspect before retrying")
    shutil.copytree(source, destination)
    for line in (source / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        require(sha(destination / name) == expected and
                (destination / name).read_bytes() == (source / name).read_bytes(), "copied original bytes differ: " + name)
    require((destination / "SHA256SUMS").read_bytes() == (source / "SHA256SUMS").read_bytes(), "copied raw checksum manifest differs")
    (destination / "terminal-original-read.json").write_bytes(original_terminal)
    (destination / "terminal-output.log").write_bytes(raw)
    write_json(destination / "terminal-observation.json", {
        "schema": "pon-learning-outcome-terminal-observation-v1", "derived_from": "terminal-original-read.json",
        "session_id": terminal["session_id"], "state": "exited", "exit_code": 0, "output_complete": True,
        "output_log_bytes": len(raw), "output_log_sha256": digest(raw), "qualified_head": HEAD,
        "finished_marker_observed": True, "result": "PASS", "production_activation": False})
    write_json(destination / "ARCHIVE_MANIFEST.json", {
        "schema": "pon-learning-outcome-archive-manifest-v1", "source_head": HEAD,
        "original_summary_result": "PASS", "files": inventory(destination)})

    payload = json.loads(args.hepta_payload.read_text())
    hepta = evidence / "hepta-postpublication"
    hepta.mkdir()
    for member in payload["files"]:
        relative = Path(member["path"])
        require(not relative.is_absolute() and ".." not in relative.parts, "unsafe Hepta member")
        data = base64.b64decode(member["base64"], validate=True)
        require(len(data) == member["bytes"] and digest(data) == member["sha256"], "Hepta transfer bytes differ")
        path = hepta / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    hepta_result = json.loads((hepta / "postpublication/postpublication-readback.json").read_text())
    require(hepta_result["verification"] == "PASS" and
            hepta_result["published_head"] == "ef3a398d460574813957a25f5455e12c60db6d5d" and
            hepta_result["runtime_source"] == "93fc43f6e87c4514485adcb01a7ffec8ad3b632f" and
            hepta_result["native7_exit"] == hepta_result["native8_exit"] == 0 and
            hepta_result["output_ack_event_verified"] is False and
            hepta_result["original_publisher_optimization_mode_verified"] is False, "Hepta postpublication scope differs")
    write_json(hepta / "ARCHIVE_MANIFEST.json", {"schema": "hepta-postpublication-transfer-v1", "files": inventory(hepta)})

    qualification = {"schema": "pon-learning-outcome-component-qualification-v1", "result": "PASS",
        "tested_source": HEAD, "tested_tree": before["tested_tree"], "evidence_commit_contains_no_code_changes": True,
        "commands": 26, "native_tests": native, "native_test_total": 42, "reader_tests": readers,
        "reader_test_total": sum(readers.values()), "source_negative_tests": 43, "project_boundary_negative_tests": 16,
        "strict_clippy": "workspace/all-targets/all-features/-D warnings", "provider": "original pinned OpenSSL 3.5.9 fresh build and smoke",
        "hepta_runtime_source": hepta_result["runtime_source"], "hepta_evidence_head": hepta_result["published_head"],
        "hepta_native_tests": 8, "hepta_pr": 6062, "output_ack_event_verified": False,
        "model_efficacy_certified": False, "independent_evaluation_certified": False,
        "ordinary_daemon_qualified": False, "independent_B_C_qualified": False,
        "authority": "DENY_ALL", "current_permission": "NOT_EXPORTED", "production_qualification": "HOLD_NO_GO"}
    write_json(evidence / "QUALIFICATION.json", qualification)
    table = "\n".join("| " + name + " | " + str(count) + " |" for name, count in readers.items())
    section = f'''## Final committed-source component qualification

Exact Chain source `{HEAD}` (tree `{before["tested_tree"]}`) completed all
26 recorded commands. The [original final run](native-c2/summary.json),
[command records](native-c2/commands.json) and
[terminal observation](native-c2/terminal-observation.json) bind 42 native
tests, six Python reader suites ({sum(readers.values())} tests), 43 source-negative
and 16 project-boundary controls. All selected native tests had zero failures
and zero ignored entries. Formatting, the locked all-features graph, complete
repository links and workspace/all-targets/all-features Clippy with `-D warnings`
passed. Source identities before and after are identical.

| Reader suite | Executed tests |
| --- | ---: |
{table}

The preceding [same-source attempt](native-c2-attempt1/summary.json) remains
`FAIL`: system OpenSSL 3.0.13 could not compile the existing optional PQ test
API. The final run used the unchanged original provider preparation, fixed
OpenSSL 3.5.9 archive, fresh static build and real sign/verify/wrong-message
smoke. [Provider observations](native-c2/provider-observation-before.json)
and this Clippy invocation's Cargo event bind its actual install prefix.
No repository gate, loader path or qualification cfg was weakened. Cached
Cargo artifacts can be used; this is not a claim that every Rust crate was
recompiled from scratch.

The second [attempt](native-c2-attempt2/summary.json) stopped at the original
source checks before provider preparation or native tests. A later readback
found 109 historical archive entries marked skip-worktree. The original
refusals and that separately timed diagnostic remain intact. The final pass
requires the complete physical source and an index with no hidden entries;
absent files are never treated as checked bytes.

Hepta [Draft #6062](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/6062)
publishes `ef3a398d460574813957a25f5455e12c60db6d5d`, whose runtime code tree
equals executed `93fc43f6e87c4514485adcb01a7ffec8ad3b632f`. All seven initial
selected tests and the separate eighth actual trainer/retained-task/cold-recovery
test passed, as did scoped fmt/fix/final-fmt. The eighth test leaves the distinct
input C output pending; it is not a completed-delivery or output-ACK positive.
The [read-only postpublication result](hepta-postpublication/postpublication/postpublication-readback.json)
binds original logs to published blobs and exact PR head/base. Its first gh
field-compatibility failure is preserved. It cannot retrospectively prove the
original publisher's optimization mode or historical Git push identity.
The [hosted CI snapshot](hepta-postpublication/postpublication/hosted-ci-observation.json)
is separately timed and was still pending; local passes do not imply all hosted
checks completed. This evidence-only commit does not change the executed Rust,
Python readers, CI workflow or pinned native corpus.

'''
    readme = evidence / "README.md"
    text = readme.read_text()
    require(text.count("## Retained observations") == 1 and "## Final committed-source component qualification" not in text,
            "unexpected evidence README state")
    text = text.replace("## Retained observations", section + "## Retained observations", 1)
    readme.write_text(text)
    plan_path = ROOT / PLAN
    plan_text = plan_path.read_text()
    marker = "\n**Throughput budget continuation"
    require(marker in plan_text and "Final component qualification on `04f5b551" not in plan_text, "unexpected sole plan state")
    update = f'''\nFinal component qualification on `{HEAD}` passed 26 commands:
42 native tests, six Python reader suites ({sum(readers.values())} tests), 43/16 negative
controls and strict whole-workspace Clippy with the original pinned provider.
Hepta's separate executed source `93fc43f6` passed seven original selected tests
plus the real trainer/retained-task cold-recovery control; Draft #6062 binds its
published evidence. The [exact-source qualification](../../{EVIDENCE}/QUALIFICATION.json)
preserves earlier failed runs and all existing authority/production HOLDs.
The eighth Hepta test still has pending C output and is not an output-ACK proof.
'''
    plan_path.write_text(plan_text.replace(marker, update + marker, 1))
    shutil.copyfile(Path(__file__), evidence / "finalize_evidence.py")
    write_json(evidence / "EVIDENCE_MANIFEST.json", {"schema": "pon-learning-outcome-evidence-inventory-v1", "tested_source": HEAD,
        "files": inventory(evidence), "independent_attestation_claimed": False, "production_activation": False})
    with (evidence / "EVIDENCE_SHA256SUMS").open("x") as stream:
        for row in inventory(evidence):
            if row["path"] != "EVIDENCE_SHA256SUMS":
                stream.write(row["sha256"] + "  " + row["path"] + "\n")

    run("stage-owned-evidence", ["git", "add", "--", EVIDENCE, PLAN])
    logs = [str(path.relative_to(ROOT)) for path in sorted(evidence.rglob("*.log"))]
    if logs:
        run("stage-original-logs", ["git", "add", "-f", "--", *logs])
    staged = run("staged-paths", ["git", "diff", "--cached", "--name-only"]).decode().splitlines()
    require(staged and all(path == PLAN or path.startswith(EVIDENCE + "/") for path in staged), "unowned staged changes")
    for path in staged:
        original = (ROOT / path).read_bytes()
        blob = subprocess.run(["git", "show", ":" + path], cwd=ROOT, check=True, capture_output=True).stdout
        require(blob == original, "staged bytes differ: " + path)
    run("staged-whitespace", ["git", "--no-pager", "diff", "--cached", "--check"])
    run("preflight-staged", ["bash", "scripts/project-preflight.sh", "--staged"])
    run("commit", ["git", "commit", "-m", "docs(chain): record qualified PoN and learning outcome composition"])
    published = run("head-after", ["git", "rev-parse", "HEAD"]).decode().strip()
    require(run("parent-after", ["git", "rev-parse", "HEAD^"]).decode().strip() == HEAD, "unexpected evidence commit parent")
    require(not run("clean-after", ["git", "status", "--porcelain=v1", "--untracked-files=all"]), "final tree is dirty")
    for tree in ("trillionnium", "scripts", ".github", "evidence/heplcp04-completed-use-20261111"):
        values = run("tree-" + tree.replace("/", "-"), ["git", "rev-parse", HEAD + ":" + tree, published + ":" + tree]).decode().splitlines()
        require(len(values) == 2 and values[0] == values[1], "executed code or native corpus changed")
    run("source-after-commit", ["python3", "-B", "scripts/ci/verify_ci_source.py", "--kind", "head", "--expected-head", published,
                                 "--output", str(audit / "source-after-commit.json")])
    run("repository-after-commit", ["python3", "-B", "scripts/ci/check_repository.py"])
    result = {"result": "PASS", "qualified_head": HEAD, "evidence_head": published,
              "evidence_tree": run("tree-after", ["git", "rev-parse", "HEAD^{tree}"]).decode().strip(),
              "code_and_corpus_unchanged": True, "native_tests": 42, "reader_tests": readers,
              "remote_write_performed": False, "production_activation": False}
    write_json(audit / "summary.json", result)
    print("C3_EVIDENCE_COMMITTED", json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
