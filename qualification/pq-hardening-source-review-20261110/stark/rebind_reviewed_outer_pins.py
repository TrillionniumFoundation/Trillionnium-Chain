#!/usr/bin/env python3
"""Prepare a reviewable four-file patch for exactly two reviewed source changes.

No checkout file, historical report, other source pin, or qualification is
rewritten. Run after committing the final reviewed source bytes, then review
and apply the emitted patch. Corpus pins must be updated separately, last.
"""
from __future__ import annotations

import argparse
import ast
from copy import deepcopy
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from types import ModuleType

BASE_COMMIT = "da1374a200022bc14dc2bd325cc9ba29dbcd24ab"
NETWORK = "trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs"
QUANTUM = "formal/pon-nakamoto-v1/quantum_daa_model.py"
QUANTUM_REVIEWED_SHA256 = "1cc69a5d58350ce0ffcc21f7030473f7be9e5a9baeea024da0f589447dcd14b7"
LOCK = "config/pon/pq128-source-lock-v1.json"
BUDGET = "config/pon/pq128-lifetime-budget-v1.json"
LEDGER = "scripts/w1_lifetime_ledger.py"
INPUT = "evidence/pon-w1-lifetime-current-20261109/project-input.json"
REPORT = "evidence/pon-w1-lifetime-current-20261109/project-report.json"
BASE_SHA256 = {
    LOCK: "29ba9abdbb39d96bece885a0cd821fd9ad428413974cd530d26434f5a7daf84a",
    BUDGET: "639a283d352b713b1373161099649d251ed5c14172b71f6955a7ab22d2618719",
    LEDGER: "a09b37a7187ceaee515ee37cceef09df6a6d337f670862d7cf2f3d75368c8303",
    INPUT: "a6e43a5c55e71154592a3489f566995e7961b91611e15d40a18a948a495f9f89",
    REPORT: "8ee20462d669a0e21b0fe964585f85fa2a49e7e58273459ab2501b4a2e39dfc0",
}
MAX_BYTES = 2 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("nonfinite JSON constant")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def ledger_declarations(raw):
    result = {}
    for node in ast.parse(raw).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in {"SOURCE_BASE", "SOURCE_PINS"}):
            name = node.targets[0].id
            require(name not in result, "duplicate ledger declaration")
            result[name] = ast.literal_eval(node.value)
    require(set(result) == {"SOURCE_BASE", "SOURCE_PINS"}, "missing ledger declarations")
    return result


def replace_once(raw, old, new):
    require(raw.count(old) == 1, "source edit anchor is not unique")
    return raw.replace(old, new, 1)


def validated_baseline(baseline):
    require(set(baseline) == set(BASE_SHA256), "baseline input roster differs")
    for path, expected in BASE_SHA256.items():
        require(type(baseline[path]) is bytes and sha(baseline[path]) == expected,
                "immutable baseline differs: " + path)
    lock = strict_json(baseline[LOCK])
    budget = strict_json(baseline[BUDGET])
    ledger = ledger_declarations(baseline[LEDGER])
    require(len(lock["files"]) == 15 and len(ledger["SOURCE_PINS"]) == 20,
            "reviewed selected-source roster differs")
    require(lock["source_revision"] == budget["experiment"]["source_revision"],
            "baseline experiment and source lock disagree")
    require({p for event in budget["events"] for p in event["source_paths"]}
            == set(lock["files"]), "baseline event paths differ")
    return lock, budget, ledger


def build_plan(baseline, selected, source_commit, expected_network_sha256):
    """Pure selected-byte planning; the CLI separately verifies real Git objects."""
    require(re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None,
            "source checkpoint must be an exact commit")
    require(re.fullmatch(r"[0-9a-f]{64}", expected_network_sha256) is not None,
            "network digest must be explicitly supplied after source review")
    lock, budget, ledger = validated_baseline(baseline)
    paths = set(lock["files"]) | set(ledger["SOURCE_PINS"])
    require(set(selected) == paths and len(paths) == 31,
            "selected bytes differ from the exact 31-path union")
    new_digests = {NETWORK: expected_network_sha256, QUANTUM: QUANTUM_REVIEWED_SHA256}
    require(expected_network_sha256 != lock["files"][NETWORK]
            and QUANTUM_REVIEWED_SHA256 != ledger["SOURCE_PINS"][QUANTUM],
            "both reviewed changes must actually be present")
    for roster in (lock["files"], ledger["SOURCE_PINS"]):
        for path, old_digest in roster.items():
            value = selected[path]
            require(type(value) is bytes and len(value) <= MAX_BYTES,
                    "selected input is invalid: " + path)
            require(sha(value) == new_digests.get(path, old_digest),
                    "unreviewed source difference: " + path)

    outputs = {}
    old_network = lock["files"][NETWORK]
    outputs[LOCK] = replace_once(
        baseline[LOCK],
        json.dumps(NETWORK).encode() + b': "' + old_network.encode() + b'"',
        json.dumps(NETWORK).encode() + b': "' + expected_network_sha256.encode() + b'"')
    outputs[LOCK] = replace_once(outputs[LOCK],
        b'"source_revision": "' + lock["source_revision"].encode() + b'"',
        b'"source_revision": "' + source_commit.encode() + b'"')
    outputs[BUDGET] = replace_once(baseline[BUDGET],
        b'"source_revision": "' + budget["experiment"]["source_revision"].encode() + b'"',
        b'"source_revision": "' + source_commit.encode() + b'"')
    old_quantum = ledger["SOURCE_PINS"][QUANTUM]
    outputs[LEDGER] = replace_once(baseline[LEDGER],
        b'SOURCE_BASE = "' + ledger["SOURCE_BASE"].encode() + b'"',
        b'SOURCE_BASE = "' + source_commit.encode() + b'"')
    outputs[LEDGER] = replace_once(outputs[LEDGER],
        json.dumps(QUANTUM).encode() + b': "' + old_quantum.encode() + b'"',
        json.dumps(QUANTUM).encode() + b': "' + QUANTUM_REVIEWED_SHA256.encode() + b'"')

    expected_lock = deepcopy(lock)
    expected_lock["files"][NETWORK] = expected_network_sha256
    expected_lock["source_revision"] = source_commit
    expected_budget = deepcopy(budget)
    expected_budget["experiment"]["source_revision"] = source_commit
    expected_ledger = deepcopy(ledger)
    expected_ledger["SOURCE_PINS"][QUANTUM] = QUANTUM_REVIEWED_SHA256
    expected_ledger["SOURCE_BASE"] = source_commit
    require(strict_json(outputs[LOCK]) == expected_lock
            and strict_json(outputs[BUDGET]) == expected_budget
            and ledger_declarations(outputs[LEDGER]) == expected_ledger,
            "planned edits exceed the two selected pins and provenance metadata")

    module = ModuleType("_reviewed_rebound_lifetime_ledger")
    module.__file__ = LEDGER
    # This is the exact pinned baseline program plus the two checked literals.
    # It executes no selected Rust/source file, fetched code, or upstream helper.
    exec(compile(outputs[LEDGER], LEDGER, "exec"), module.__dict__)
    with tempfile.TemporaryDirectory(prefix="trnm-reviewed-ledger-") as temp:
        view = Path(temp)
        for path, raw in selected.items():
            target = view / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        actual_report = module.make_report(module.strict_json(baseline[INPUT]), view)

    expected_report = strict_json(baseline[REPORT])
    expected_report["selected_source_survey"]["base_commit"] = source_commit
    records = expected_report["selected_source_survey"]["sources"]
    record = [row for row in records if row["path"] == QUANTUM]
    require(len(record) == 1, "current report source record differs")
    record[0].update(sha256=QUANTUM_REVIEWED_SHA256, bytes=str(len(selected[QUANTUM])))
    observation = expected_report["selected_source_survey"]["observations"]["sqrt_cost_is_assumption"]
    require(observation["path"] == QUANTUM, "current report source anchor differs")
    text = selected[QUANTUM].decode("utf-8")
    observation.update(sha256=QUANTUM_REVIEWED_SHA256,
                       anchor_line=str(text[:text.index("def cost_ratio(")].count("\n") + 1))
    require(actual_report == expected_report,
            "recomputed report changes arithmetic, qualification or an unreviewed observation")
    outputs[REPORT] = (json.dumps(actual_report, indent=2, sort_keys=True,
                                  allow_nan=False) + "\n").encode()
    require(set(outputs) == {LOCK, BUDGET, LEDGER, REPORT}, "unexpected output roster")
    return outputs


def regular(root, relative):
    require(not relative.startswith("/") and all(p not in {"", ".", ".."}
            for p in relative.split("/")), "unsafe selected path")
    path = root
    for part in relative.split("/")[:-1]:
        path /= part
        require(stat.S_ISDIR(path.lstat().st_mode), "nonregular source ancestor")
    path = root / relative
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_BYTES,
                "nonregular or oversized source: " + relative)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        after, visible = os.fstat(fd), path.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(identity(before) == identity(after) == identity(visible)
                and len(raw) == before.st_size, "source changed while reading: " + relative)
        return raw
    finally:
        os.close(fd)


def git(root, *args):
    return subprocess.check_output(
        ["git", "--no-replace-objects", "--literal-pathspecs", *args],
        cwd=root, env=dict(os.environ, GIT_NO_LAZY_FETCH="1"), timeout=30)


def git_file(root, revision, path):
    entry = git(root, "ls-tree", "-z", revision, "--", path)
    require(entry.count(b"\0") == 1 and entry.endswith(b"\0"),
            "Git path is missing or ambiguous: " + path)
    metadata, name = entry[:-1].split(b"\t")
    mode, kind, oid = metadata.split()
    require(mode in {b"100644", b"100755"} and kind == b"blob"
            and name.decode() == path and re.fullmatch(rb"[0-9a-f]{40}", oid),
            "Git source is not an exact regular blob: " + path)
    raw = git(root, "cat-file", "blob", oid.decode())
    require(len(raw) <= MAX_BYTES, "oversized Git source: " + path)
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--expected-pq-network-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.absolute()
    require(root == root.resolve(strict=True), "checkout path is an alias")
    require(re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is not None,
            "source checkpoint must be a full commit")
    require(git(root, "rev-parse", "HEAD").decode().strip() == args.source_commit,
            "HEAD is not the reviewed source checkpoint")
    require(git(root, "cat-file", "-t", args.source_commit) == b"commit\n",
            "selected checkpoint is not a commit")
    git(root, "merge-base", "--is-ancestor", BASE_COMMIT, args.source_commit)
    baseline = {path: git_file(root, BASE_COMMIT, path) for path in BASE_SHA256}
    lock, _budget, ledger = validated_baseline(baseline)
    for path, raw in baseline.items():
        require(regular(root, path) == raw, "binding/input was already edited: " + path)
    selected = {}
    for path in sorted(set(lock["files"]) | set(ledger["SOURCE_PINS"])):
        raw = regular(root, path)
        require(raw == git_file(root, args.source_commit, path),
                "working bytes differ from the reviewed checkpoint: " + path)
        selected[path] = raw
    outputs = build_plan(baseline, selected, args.source_commit,
                         args.expected_pq_network_sha256)
    for path, raw in {**baseline, **selected}.items():
        require(regular(root, path) == raw, "source changed during preparation: " + path)
    require(git(root, "rev-parse", "HEAD").decode().strip() == args.source_commit,
            "source checkpoint moved during preparation")
    out = args.output.absolute()
    require(not out.exists() and not out.is_symlink(), "output must be a new directory")
    parent = out.parent.resolve(strict=True)
    require(not parent.is_relative_to(root), "review output must be outside checkout")
    out = parent / out.name
    out.mkdir()
    patch = "".join("".join(difflib.unified_diff(
        baseline[path].decode().splitlines(True), outputs[path].decode().splitlines(True),
        fromfile="a/" + path, tofile="b/" + path)) for path in outputs)
    (out / "outer-pins.patch").write_text(patch, encoding="utf-8")
    for category, records in (("before", baseline), ("after", outputs)):
        for path, raw in records.items():
            target = out / category / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    review = {
        "baseline_commit": BASE_COMMIT, "selected_source_checkpoint": args.source_commit,
        "selected_regular_git_blobs_compared": len(selected),
        "changed_source_pins": {NETWORK: args.expected_pq_network_sha256,
                                QUANTUM: QUANTUM_REVIEWED_SHA256},
        "output_files": {path: {"before_sha256": sha(baseline[path]),
                                "after_sha256": sha(raw), "after_bytes": len(raw)}
                         for path, raw in outputs.items()},
        "patch_sha256": sha(patch.encode()), "checkout_modified": False,
        "historical_reports_modified": False, "other_source_pins_modified": False,
        "lifetime_arithmetic_unchanged": True, "independent_acceptance_unchanged": True,
        "security_disposition": "HOLD_NO_GO", "production_activation": False,
        "scope": "selected source and report correspondence; no native execution or theorem",
    }
    (out / "REVIEW.json").write_text(json.dumps(review, indent=2, sort_keys=True) + "\n")
    git(root, "apply", "--check", str(out / "outer-pins.patch"))
    print(json.dumps({"prepared": str(out), "patch_sha256": review["patch_sha256"],
                      "source_pins_changed": 2, "checkout_modified": False,
                      "security_disposition": "HOLD_NO_GO"}, sort_keys=True))


if __name__ == "__main__":
    main()
