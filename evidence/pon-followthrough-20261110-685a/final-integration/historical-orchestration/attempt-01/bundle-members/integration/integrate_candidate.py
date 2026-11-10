#!/usr/bin/env python3
"""Integrate reviewed PoN patches after the real native-v3 checkpoint completes.

External orchestration only.  This file is not installed in the repository.
Phases: prepare (stage), commit (one child), validate (actual checks), or all.
No network, push, PR, activation, native rerun, or historical evidence rewrite.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid


BASE = "da1374a200022bc14dc2bd325cc9ba29dbcd24ab"
BASE_TREE = "00479a98dabc6b1fd91a0ceef82ffbdbffb78067"
C1 = "11c9562252d3cf56b423c7756569be0c669d9606"
C1_TREE = "94e1b4f1718dec1b88bccd7e1996ba83ca29ff8a"
EVIDENCE = "evidence/pon-followthrough-20261110-685a"
LEDGER_EVIDENCE = "evidence/pon-w1-lifetime-current-20261110-685a"
PLAN = "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
PLAN_MARKER = "## 2026-11-10: PoN native checkpoint and binding follow-through"
CORPUS = "config/pon/pq-cross-branch-corpus-v1.json"
INVENTORY = "trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs"
VERIFY_SOURCE = "scripts/ci/verify_ci_source.py"
NODE_TEST = "trillionnium/crates/trnm-pon-node/src/store/confirmation_chainwork_tests.rs"
READER = "scripts/pon_fresh_rejection_report.py"
INPUT_SHA256 = {
    "ci-fixes/ci-native-evidence-fixes.patch": "3af253fa2c6828f3aa61e44554402a60e26172530f9cf16d07af40a3985f013b",
    "qrom-port/qrom-current-ci.patch": "db3fcd65c427d297f308568ebb6889344b00b86e3e343a840fe4384152ceb7c0",
    "qrom-port/additional-ci-registrations.patch": "73cd46b5b29ff24f1d1d6fbc0acf9a31576a2840a5a8841475097a1a00f50da8",
    "qrom-port/fresh-rejection-ci-registration.patch": "2afcdfa4cb5321f8c5eeeaff2992214f65ce0e18b5d51a484d20d8721f475c94",
    "binding-update-v2/required-paths.patch": "aafae62ab0f5f7920af757b0c2645b70348b0dda3486207f22182d7771aaa8a1",
    "binding-update-v2/update_corpus.py": "1e80cad195fb03a18f57387575b4b89e4ef7eb4be697c0887263ee682fb9a6d9",
    "binding-tool/prepare_authority_pq128_binding.py": "13bfaee99dd91cdc73d6a05a89663a1e75ad0ac70a55f6b97f1e6051ae6aedb1",
    "integration/update_w1_ledger_binding.py": "86589db5540576e00c4d4e7bad14082114a4dce9a6ed559969ed7996ffc8ab42",
    "qrom-successor/prepare_qrom_successor_binding.py": "f635eca914d72845b6b6753e34365d245bea586aebc74c76b994afc942b1449d",
}
PATCHES = tuple(path for path in INPUT_SHA256 if path.endswith(".patch"))
AUTHORITY_TARGETS = (
    "config/pon/pq-authority-effects-v1.json",
    "scripts/ci/pq_authority_effect_register.py",
    "scripts/ci/test_pq_authority_effect_register.py",
    "config/pon/pq128-source-lock-v1.json",
    "config/pon/pq128-lifetime-budget-v1.json",
    "docs/security/PQ_AUTHORITY_EFFECT_REGISTER_V1.md",
    "docs/security/PQ128_LIFETIME_BUDGET_V1.md",
)
LEDGER_TARGETS = (
    "scripts/w1_lifetime_ledger.py",
    "scripts/ci/test_w1_lifetime_ledger.py",
    ".github/workflows/pon-w1-qrom-closure.yml",
    LEDGER_EVIDENCE + "/README.md",
    LEDGER_EVIDENCE + "/project-input.json",
    LEDGER_EVIDENCE + "/project-report.json",
)
QROM_EVIDENCE = "evidence/pon-w1-qrom-current-20261110-685a"
QROM_TARGETS = (
    "config/pon/w1-qrom-implementation-current-v2.json",
    "scripts/w1_qrom_current_implementation_audit.py",
    "scripts/ci/test_w1_qrom_current_implementation_audit.py",
    "docs/security/W1_QROM_CURRENT_SOURCE_MAPPING_V2.md",
    *(QROM_EVIDENCE + "/" + name for name in (
        "README.md", "source-binding.json", "current-report.json",
        "prior-v2-on-c2.command.json", "prior-v2-on-c2.stdout.log", "prior-v2-on-c2.stderr.log",
        "historical/current-v2.json", "historical/current-auditor.py", "historical/current-tests.py",
        "historical/current-mapping.md.txt",
    )),
)
NATIVE_OWNERS = tuple("trillionnium/crates/" + name + "/" for name in
                      ("trnm-pon-node", "trnm-service-settlement", "trnm-crypto-primitives"))
NATIVE_PATHS = {
    "trillionnium/crates/trnm-pon-node/src/store.rs", NODE_TEST,
    "trillionnium/crates/trnm-service-settlement/src/native_budget.rs",
    "trillionnium/crates/trnm-service-settlement/src/native_budget/tests.rs",
    "trillionnium/crates/trnm-service-settlement/src/native_generation_budget_v2.rs",
    "trillionnium/crates/trnm-service-settlement/src/native_generation_budget_v2/tests.rs",
    "trillionnium/crates/trnm-crypto-primitives/examples/pon_fresh_rejection_cost.rs",
    READER, "scripts/ci/test_fresh_rejection_report.py",
    "docs/research/PON_FRESH_REJECTION_COST_V1.md",
}
MAX_FILE = 64 * 1024 * 1024
MAX_NATIVE_TOTAL = 512 * 1024 * 1024
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", GIT_NO_LAZY_FETCH="1",
           GIT_NO_REPLACE_OBJECTS="1", CARGO_TERM_COLOR="never", CARGO_NET_OFFLINE="true")


class Refusal(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refusal(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob_id(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw,
                        usedforsecurity=False).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(Refusal("nonfinite JSON: " + value)))


def safe_relative(value):
    require(type(value) is str and "\\" not in value and "\0" not in value,
            "unsafe relative path")
    parts = value.split("/")
    require(all(part not in ("", ".", "..") for part in parts)
            and not Path(value).is_absolute(), "unsafe relative path: " + value)
    return value


def whitespace_paths(raw_members):
    """Exclude only enumerated original streams/patches, never a directory glob."""
    paths = sorted(raw_members)
    require(len(paths) == len(set(paths)), "duplicate raw whitespace exemption")
    require(all(safe_relative(path).startswith(EVIDENCE + "/native/") and path.endswith((".log", ".patch"))
                for path in paths), "whitespace exemption is not an original native stream or patch")
    return [".", *(":(exclude,literal)" + path for path in paths)]


def directory(path, *, exists=True):
    require(path.is_absolute() and str(path) == os.path.normpath(path), "absolute normalized path required")
    for item in reversed((path, *path.parents)):
        if not item.exists():
            require(not exists and item == path, "missing directory ancestor: " + str(item))
            require(not item.is_symlink(), "symlink directory: " + str(item))
            continue
        require(not item.is_symlink() and item.is_dir(), "nonregular directory ancestry: " + str(item))
    return path


def read_regular(path, limit=MAX_FILE):
    """Open each component without following links; never block on a FIFO."""
    require(path.is_absolute(), "absolute file path required")
    parts = path.parts[1:]
    require(parts and all(part not in ("", ".", "..") for part in parts), "unsafe file path")
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "nonregular or oversized file: " + str(path))
        chunks, count = [], 0
        while count <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        after = os.fstat(descriptor)
        current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        require(count == before.st_size and count <= limit and identity(before) == identity(after) == identity(current),
                "file changed while reading: " + str(path))
        return b"".join(chunks), stat.S_IMODE(before.st_mode)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def fingerprint(path):
    raw, mode = read_regular(path)
    return {"bytes": len(raw), "sha256": sha(raw), "git_blob": blob_id(raw),
            "git_mode": "100755" if mode & 0o111 else "100644"}


def make_parents(path):
    if not path.exists():
        make_parents(path.parent)
        path.mkdir(mode=0o755)
    directory(path)


def write_new(path, raw, mode=0o644):
    make_parents(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def replace_expected(path, before, after):
    current, mode = read_regular(path)
    require(current == before, "independent edit before replacement: " + str(path))
    temporary = path.parent / (".pon-integrate-" + uuid.uuid4().hex)
    write_new(temporary, after, mode)
    try:
        require(read_regular(path)[0] == before, "independent edit while staging: " + str(path))
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def atomic_json(path, value):
    raw = encoded(value)
    if path.exists():
        replace_expected(path, read_regular(path)[0], raw)
    else:
        write_new(path, raw)


def git(root, *args, env_extra=None):
    result = subprocess.run(["git", "--no-replace-objects", *args], cwd=root, env=dict(ENV, **(env_extra or {})),
                            capture_output=True, timeout=90, check=False)
    require(result.returncode == 0, "git " + " ".join(args) + " refused: " + result.stderr.decode(errors="replace")[-2000:])
    return result.stdout


def git_text(root, *args, env_extra=None):
    return git(root, *args, env_extra=env_extra).decode().strip()


def tree_entries(root, revision):
    result = {}
    for row in git(root, "ls-tree", "-r", "-z", revision).split(b"\0"):
        if not row:
            continue
        metadata, path = row.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        result[path.decode()] = {"mode": mode, "kind": kind, "blob": oid}
    return result


def patch_paths(raw):
    paths = []
    for line in raw.decode().splitlines():
        if line.startswith("+++ b/"):
            paths.append(safe_relative(line[6:]))
        require(line != "+++ /dev/null", "patch deletes a path")
    require(paths and len(set(paths)) == len(paths), "empty or duplicate patch path set")
    return paths


def native_snapshot(native):
    directory(native)
    files, total = {}, 0
    for path in sorted(native.iterdir()):
        name = safe_relative(path.name)
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None
                and name.endswith((".json", ".log", ".patch")),
                "unreviewed native output member: " + name)
        raw, mode = read_regular(path)
        total += len(raw)
        require(total <= MAX_NATIVE_TOTAL, "native output exceeds reviewed total bound")
        files[name] = {"raw": raw, "record": {"bytes": len(raw), "sha256": sha(raw), "git_blob": blob_id(raw),
                                               "original_mode": oct(mode)}}
    required = {"commands.json", "commands-before-v3.json", "summary-v3.json", "source.json", "source-v3.json",
                "source-before-v3.json", "source-after-v3.json", "red-source.patch", "red-v3-source.json",
                "fresh-profile-before-v3.json", "fresh-profile-after-v3.json"}
    require(required <= files.keys(), "native v3 evidence missing: " + repr(sorted(required - files.keys())))
    return files


def validate_native(native):
    files = native_snapshot(native)
    parsed = lambda name: strict_json(files[name]["raw"])
    summary, source = parsed("summary-v3.json"), parsed("source-v3.json")
    require(summary.get("complete") is True and summary.get("open_consensus_qualified") is False
            and summary.get("production_activation") is False, "native v3 is incomplete or promotes qualification")
    require(summary.get("source") == source and source.get("baseline") == BASE
            and source.get("prior_code_commit") == C1 and source.get("clean") is True,
            "native v3 source identities do not match")
    require(all(re.fullmatch(r"[0-9a-f]{40}", source.get(key, "")) for key in ("commit", "tree")),
            "native v3 needs full commit/tree identities")
    require(source.get("changed_from_c1") == [NODE_TEST, READER], "unexpected C2 source delta")
    old_source = parsed("source.json")
    require(old_source.get("commit") == C1 and old_source.get("tree") == C1_TREE
            and old_source.get("baseline") == BASE and old_source.get("clean") is True
            and set(old_source.get("changed_paths", [])) == NATIVE_PATHS, "C1 source identity or path scope differs")
    require(files["source-before-v3.json"]["raw"] == files["source-after-v3.json"]["raw"], "native v3 source bracket differs")
    bracket = parsed("source-before-v3.json")
    require(bracket.get("schema") == "trnm-ci-source-v1" and bracket.get("kind") == "head"
            and bracket.get("tested_commit") == bracket.get("candidate") == source["commit"]
            and bracket.get("tested_tree") == source["tree"] and bracket.get("base") is None
            and bracket.get("prospective_merge") is None and bracket.get("tracked_worktree_verified") is True
            and bracket.get("tests_executed_by_identity_check") is False
            and type(bracket.get("tracked_entries")) is int and bracket["tracked_entries"] > 0
            and type(bracket.get("tracked_bytes")) is int and bracket["tracked_bytes"] > 0,
            "native v3 original source verifier identity is incomplete")
    require(re.fullmatch(r"[0-9a-f]{64}", summary.get("binary_sha256", "")) is not None,
            "native binary digest missing")
    commands = parsed("commands.json")
    require(type(commands) is list and type(summary.get("commands")) is int and summary["commands"] == len(commands),
            "native command denominator differs")
    rows = {}
    for row in commands:
        require(type(row) is dict and type(row.get("label")) is str and row["label"] not in rows,
                "missing or duplicate native command label")
        label = row["label"]
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", label) is not None, "unsafe native command label")
        require(type(row.get("argv")) is list and all(type(arg) is str for arg in row["argv"])
                and type(row.get("exit_code")) is int and type(row.get("cwd")) is str,
                "malformed native command: " + label)
        for stream in ("stdout", "stderr"):
            report = row.get(stream, {})
            name = label + "." + stream + ".log"
            require(report.get("file") == name and name in files, "missing original native stream: " + name)
            require(type(report.get("bytes")) is int and report["bytes"] == files[name]["record"]["bytes"]
                    and report.get("sha256") == files[name]["record"]["sha256"], "native stream digest differs: " + name)
        rows[label] = row
    prior = parsed("commands-before-v3.json")
    require(type(prior) is list and prior and commands[:len(prior)] == prior
            and prior[-1]["label"] == "green-confirmation" and prior[-1]["exit_code"] == 101,
            "C1 failed observations were replaced or truncated")
    failures = {"red-settlement", "red-settlement-r2", "red-confirmation-r2", "green-confirmation", "red-confirmation-v3"}
    require({name for name, row in rows.items() if row["exit_code"] != 0} == failures
            and all(rows[name]["exit_code"] == 101 for name in failures), "unexpected native failure set")
    require("test result:" not in files["red-settlement.stdout.log"]["raw"].decode(errors="replace")
            and b"--offline" in encoded(rows["red-settlement"]["argv"]), "initial offline observation scope differs")
    offline_error = files["red-settlement.stderr.log"]["raw"].decode(errors="replace").lower()
    require("offline" in offline_error and any(reason in offline_error for reason in
            ("no matching package", "failed to download", "attempting to make an http request")),
            "initial failure is not the retained offline dependency observation")
    cargo = ["cargo", "test", "--manifest-path", "trillionnium/Cargo.toml", "--locked", "--offline"]
    expected = {
        "green-confirmation-v3": cargo + ["-p", "trnm-pon-node", "--lib", "confirmation_chainwork_tests", "--", "--nocapture"],
        "green-settlement-v3": cargo + ["-p", "trnm-service-settlement", "--lib", "readback_rejects", "--", "--nocapture"],
        "settlement-all-features-v3": cargo + ["-p", "trnm-service-settlement", "--all-features"],
        "crypto-library-v3": cargo + ["-p", "trnm-crypto-primitives", "--lib"],
        "node-library-v3": cargo + ["-p", "trnm-pon-node", "--lib"],
        "fresh-probe-tests-v3": cargo + ["--release", "-p", "trnm-crypto-primitives", "--example", "pon_fresh_rejection_cost"],
        "changed-owner-clippy-v3": ["cargo", "clippy", "--manifest-path", "trillionnium/Cargo.toml", "--locked", "--offline", "-p", "trnm-pon-node", "-p", "trnm-service-settlement", "-p", "trnm-crypto-primitives", "--all-targets", "--", "-D", "warnings"],
        "format-check-v3": ["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"],
        "fresh-probe-native-v3": [summary.get("binary")],
        "fresh-probe-reader-v3": ["python3", "-B", READER, rows.get("fresh-probe-reader-v3", {}).get("argv", [None] * 4)[3],
                                   "--raw-sha256", files.get("fresh-probe-native-v3.stdout.log", {}).get("record", {}).get("sha256")],
        "fresh-reader-tests-v3": ["python3", "-B", "scripts/ci/test_fresh_rejection_report.py", "-v"],
    }
    for label, argv in expected.items():
        require(label in rows and rows[label]["exit_code"] == 0 and rows[label]["argv"] == argv,
                "missing or different successful native-v3 command: " + label)
    required_success = {"v3-committed-preflight", "v3-source-before", "v3-locked-graph", "v3-rustc", "v3-cargo",
                        "v3-source-after", "v3-source-identical", "fresh-probe-build-v3"}
    require(all(label in rows and rows[label]["exit_code"] == 0 for label in required_success),
            "native-v3 source/toolchain/graph bracket is incomplete")
    require(commands[-1]["label"] == "v3-source-identical", "native v3 completion is not the final observation")
    corrected = parsed("red-v3-source.json")
    require(corrected.get("dependency_checkpoint") == C1 and corrected.get("node_production_base") == BASE
            and corrected.get("complete_baseline_checkout_claimed") is False
            and corrected.get("production_activation") is False, "v3 counterfactual scope changed")
    expected_counts = {"red-settlement-r2": (2, 6), "red-confirmation-r2": (0, 4),
                       "green-settlement": (8, 0), "green-confirmation": (3, 1),
                       "red-confirmation-v3": (0, 4), "green-confirmation-v3": (4, 0), "green-settlement-v3": (8, 0)}
    counts = {}
    for label, wanted in expected_counts.items():
        text = files[label + ".stdout.log"]["raw"].decode(errors="replace")
        matches = re.findall(r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", text, re.M)
        require(len(matches) == 1 and tuple(map(int, matches[0][:2])) == wanted,
                "native targeted result denominator differs: " + label)
        counts[label] = dict(zip(("passed", "failed", "ignored"), map(int, matches[0])))
    require(re.search(rb"^Ran 26 tests in ", files["fresh-reader-tests-v3.stderr.log"]["raw"], re.M) is not None,
            "native-v3 reader did not execute its reviewed 26-test suite")
    observations = {"schema": "pon-followthrough-native-observations-v1", "code_checkpoint": source,
                    "prior_code_checkpoint": old_source, "targeted_results": counts,
                    "original_command_count": len(commands), "failure_labels": sorted(failures),
                    "raw_member_count": len(files), "binary_sha256": summary["binary_sha256"],
                    "complete_native_v3": True, "binding_child_tests_recorded_here": False,
                    "open_consensus_qualified": False, "production_activation": False,
                    "security_status": "HOLD", "counterfactual": corrected}
    return files, observations


class Controller:
    def __init__(self, args):
        self.owns_output = False
        self.args = args
        self.controller_sha256 = sha(read_regular(Path(__file__).absolute())[0])
        self.root, self.inputs, self.native, self.out = args.root, args.inputs, args.native_validation, args.output
        for path in (self.root, self.inputs, self.native):
            directory(path)
        require(not any(os.environ.get(name) for name in
                        ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                         "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_COUNT")),
                "external Git repository/index/config environment override refused")
        require(not self.inputs.is_relative_to(self.root) and not self.native.is_relative_to(self.root)
                and not self.out.is_relative_to(self.root), "inputs, native output and controller receipts must be outside ROOT")
        directory(self.out, exists=args.phase not in ("prepare", "all"))
        self.check_inputs()
        self.native_files, self.observations = validate_native(self.native)
        self.c2 = self.observations["code_checkpoint"]["commit"]
        self.c2_tree = self.observations["code_checkpoint"]["tree"]
        require(git_text(self.root, "rev-parse", "--show-toplevel") == str(self.root), "ROOT is not the full worktree root")
        require(git_text(self.root, "rev-parse", "--is-shallow-repository") == "false", "shallow checkout refused")
        sparse = subprocess.run(["git", "config", "--bool", "core.sparseCheckout"], cwd=self.root,
                                env=ENV, capture_output=True, timeout=60)
        require(sparse.returncode in (0, 1) and sparse.stdout.strip() in (b"", b"false"), "sparse checkout refused")
        require(all(not line or line.startswith(b"H ") for line in git(self.root, "ls-files", "-v", "-z").split(b"\0")),
                "hidden, sparse or nonordinary index entries refused")
        require(git_text(self.root, "rev-parse", BASE + "^{tree}") == BASE_TREE
                and git_text(self.root, "rev-parse", C1 + "^{tree}") == C1_TREE
                and git_text(self.root, "rev-parse", self.c2 + "^{tree}") == self.c2_tree, "actual Git checkpoint tree differs")
        require(git_text(self.root, "rev-list", "--parents", "-n", "1", self.c2).split() == [self.c2, C1],
                "C2 is not the recorded single child of C1")
        git(self.root, "merge-base", "--is-ancestor", BASE, C1)
        require(set(git_text(self.root, "diff", "--name-only", C1, self.c2).splitlines()) == {NODE_TEST, READER}, "actual C2 path delta differs")
        require(set(git_text(self.root, "diff", "--name-only", BASE, self.c2).splitlines()) == NATIVE_PATHS, "actual native source scope differs")
        require(git(self.root, "show", BASE + ":" + VERIFY_SOURCE) == git(self.root, "show", self.c2 + ":" + VERIFY_SOURCE),
                "original source verifier changed before integration")
        if args.phase in ("prepare", "all"):
            require(not self.out.exists(), "output already exists; inspect it or use the exact next phase")
            require(git_text(self.root, "rev-parse", "HEAD") == self.c2 and not git(self.root, "status", "--porcelain"),
                    "prepare requires HEAD = complete native-v3 C2 and a clean checkout")
            self.out.mkdir(mode=0o755)
            self.owns_output = True
            self.commands = []
            self.state = {"schema": "pon-followthrough-controller-state-v1", "phase": "starting", "root": str(self.root),
                          "inputs": str(self.inputs), "native_validation": str(self.native), "source_c2": self.c2,
                          "source_c2_tree": self.c2_tree, "expected_head": self.c2, "expected_index": self.c2_tree,
                          "expected_files": {}, "input_sha256": INPUT_SHA256,
                          "controller_sha256": self.controller_sha256,
                          "native_members": {name: value["record"] for name, value in self.native_files.items()},
                          "open_consensus_qualified": False, "production_activation": False, "security_status": "HOLD"}
            self.save()
            write_new(self.out / "input-manifest.json", encoded(INPUT_SHA256))
            write_new(self.out / "native-preflight.json", encoded(self.observations))
        else:
            self.state = strict_json(read_regular(self.out / "state.json")[0])
            self.commands = strict_json(read_regular(self.out / "commands.json")[0])
            require(self.state.get("schema") == "pon-followthrough-controller-state-v1"
                    and self.state.get("source_c2") == self.c2 and self.state.get("input_sha256") == INPUT_SHA256
                    and self.state.get("controller_sha256") == self.controller_sha256
                    and self.state.get("root") == str(self.root) and self.state.get("inputs") == str(self.inputs)
                    and self.state.get("native_validation") == str(self.native), "controller resume identity differs")
            require(self.state["native_members"] == {name: value["record"] for name, value in self.native_files.items()},
                    "native evidence changed between phases")
        self.lock = os.open(self.out / "controller.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.owns_output = True
        self.guard()
        self.phase_started = time.time_ns()
        self.status("preflight", "finished", started=self.phase_started, exit_code=0)

    def check_inputs(self):
        for relative, expected in INPUT_SHA256.items():
            require(sha(read_regular(self.inputs / relative)[0]) == expected, "reviewed integration input changed: " + relative)

    def save(self):
        atomic_json(self.out / "state.json", self.state)
        atomic_json(self.out / "commands.json", self.commands)

    def status(self, stage, phase, *, started=None, exit_code=None):
        now = time.time_ns()
        try:
            head = git_text(self.root, "rev-parse", "HEAD")
        except (OSError, Refusal, subprocess.SubprocessError):
            head = None
        value = {"schema": "pon-followthrough-controller-status-v1", "stage": stage, "phase": phase,
                 "requested_phase": self.args.phase, "started_unix_ns": started or now,
                 "end_unix_ns": None if phase == "running" else now, "last_exit": exit_code,
                 "current_head": head, "code_checkpoint_c2": self.c2,
                 "binding_child_c3": self.state.get("source_c3"), "security_status": "HOLD"}
        atomic_json(self.out / "status.json", value)

    def run(self, label, argv, *, required=True, timeout=900, env_extra=None):
        require(not any(row["label"] == label for row in self.commands), "command label already recorded: " + label)
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", label) is not None, "unsafe controller command label")
        stdout, stderr = self.out / (label + ".stdout.log"), self.out / (label + ".stderr.log")
        start = time.time_ns()
        self.status(label, "running", started=start)
        print("START", label, flush=True)
        launch_error = None
        with stdout.open("xb") as out, stderr.open("xb") as err:
            try:
                result = subprocess.run(argv, cwd=self.root, env=dict(ENV, **(env_extra or {})), stdout=out, stderr=err,
                                        timeout=timeout, check=False)
                code = result.returncode
            except (OSError, subprocess.TimeoutExpired) as error:
                launch_error = str(error)
                err.write(("controller execution failure: " + launch_error + "\n").encode())
                code = 124 if isinstance(error, subprocess.TimeoutExpired) else 127
        row = {"label": label, "argv": [str(arg) for arg in argv], "cwd": str(self.root), "exit_code": code,
               "explicit_environment": env_extra or {},
               "start_unix_ns": start, "end_unix_ns": time.time_ns(), "launch_error": launch_error,
               "stdout": {"file": stdout.name, **fingerprint(stdout)}, "stderr": {"file": stderr.name, **fingerprint(stderr)}}
        self.commands.append(row)
        self.save()
        self.status(label, "finished" if code == 0 else "failed", started=start, exit_code=code)
        print("END", label, code, flush=True)
        require(not required or code == 0, "command failed; original logs retained: " + label)
        return row

    def changed(self):
        tracked = git(self.root, "diff", "--name-only", "--no-renames", "-z", "HEAD", "--")
        untracked = git(self.root, "ls-files", "--others", "--exclude-standard", "-z")
        return {safe_relative(item.decode()) for item in (tracked + untracked).split(b"\0") if item}

    def guard(self):
        self.check_inputs()
        require(all(not row or row.startswith(b"H ") for row in git(self.root, "ls-files", "-v", "-z").split(b"\0")),
                "hidden, sparse or nonordinary index flag changed; no flag repair is performed")
        require(git_text(self.root, "rev-parse", "HEAD") == self.state["expected_head"], "HEAD changed outside the controller")
        require(git_text(self.root, "write-tree") == self.state["expected_index"], "index changed outside the controller")
        require(self.changed() <= self.state["expected_files"].keys(), "unreviewed working-tree or untracked change")
        for path, expected in self.state["expected_files"].items():
            require(fingerprint(self.root / path) == expected, "independent file change: " + path)

    def accept(self, allowed, *, index_changed=False):
        require(git_text(self.root, "rev-parse", "HEAD") == self.state["expected_head"], "HEAD changed during operation")
        allowed = set(allowed)
        prior = self.state["expected_files"]
        require(self.changed() <= prior.keys() | allowed, "operation changed an unreviewed path")
        for path, expected in prior.items():
            if path not in allowed:
                require(fingerprint(self.root / path) == expected, "operation or external writer changed an unrelated path: " + path)
        for path in allowed:
            prior[path] = fingerprint(self.root / path)
        index = git_text(self.root, "write-tree")
        require(index_changed or index == self.state["expected_index"], "operation unexpectedly staged changes")
        self.state["expected_index"] = index
        self.save()

    def mutate(self, label, argv, allowed, *, expected_entries=None):
        self.guard()
        self.run(label, argv)
        if expected_entries is not None:
            for path, expected in expected_entries.items():
                actual = fingerprint(self.root / path)
                require(expected == {"mode": actual["git_mode"], "kind": "blob", "blob": actual["git_blob"]},
                        "applied patch differs from independently staged prediction: " + path)
        self.accept(allowed)

    def preview_patches(self):
        """Predict exact patch bytes in an external index, without touching ours."""
        environment = {"GIT_INDEX_FILE": str(self.out / "patch-preview.index")}
        self.run("preview-index-from-c2", ["git", "read-tree", self.c2], env_extra=environment)
        previous = tree_entries(self.root, self.c2)
        predictions = []
        for number, relative in enumerate(PATCHES, 1):
            paths = patch_paths(read_regular(self.inputs / relative)[0])
            self.run(f"preview-patch-{number}", ["git", "apply", "--cached", str(self.inputs / relative)], env_extra=environment)
            predicted_tree = git_text(self.root, "write-tree", env_extra=environment)
            predicted = tree_entries(self.root, predicted_tree)
            delta = {path for path in previous.keys() | predicted.keys() if previous.get(path) != predicted.get(path)}
            require(delta == set(paths), "preview patch changed an unexpected path set")
            predictions.append({path: predicted[path] for path in paths})
            previous = predicted
        self.guard()
        write_new(self.out / "patch-predictions.json", encoded(predictions))
        return predictions

    def verify_evidence_tree(self, revision):
        entries = tree_entries(self.root, revision)
        for path in self.state["evidence_paths"]:
            expected = self.state["expected_files"][path]
            require(entries.get(path) == {"mode": expected["git_mode"], "kind": "blob", "blob": expected["git_blob"]},
                    "evidence was omitted/filtered from Git: " + path)
            require(sha(git(self.root, "show", revision + ":" + path)) == expected["sha256"], "Git evidence bytes differ: " + path)

    def review_native_delta(self, candidate_tree):
        candidate_tree = git_text(self.root, "rev-parse", candidate_tree + "^{tree}")
        before, after = tree_entries(self.root, self.c2), tree_entries(self.root, candidate_tree)
        changed = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
        rust = [path for path in changed if path.endswith(".rs")]
        cargo = [path for path in changed if Path(path).name in
                 ("Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml") or ".cargo" in Path(path).parts]
        owner = [path for path in changed if path.startswith(NATIVE_OWNERS) and path != INVENTORY]
        require(set(rust) <= {INVENTORY}, "C2-to-child Rust delta exceeds the generated inventory: " + repr(rust))
        require(not cargo and not owner, "C2-to-child Cargo graph or owner inputs changed: " + repr(cargo + owner))
        return {"schema": "pon-followthrough-native-source-delta-v1", "code_checkpoint_c2": self.c2,
                "code_tree_c2": self.c2_tree, "candidate_tree": candidate_tree,
                "rust_changed_paths": rust, "cargo_input_changed_paths": cargo,
                "other_three_owner_changed_paths": owner, "three_owner_scopes": list(NATIVE_OWNERS),
                "all_cargo_inputs_and_other_owner_git_entries_equal": True,
                "final_native_policy": "Root runs the original three-crate --all-targets strict Clippy plus locked offline graph and actual C3 source bracket; no 4/8/3 or full library suite repeat is credited.",
                "native_executed_by_this_review": False, "production_activation": False}

    def copy_native_evidence(self):
        self.guard()
        stage_started = time.time_ns()
        self.status("copy-native-evidence", "running", started=stage_started)
        destination = self.root / EVIDENCE
        require(not destination.exists() and not destination.is_symlink(), "new follow-through evidence directory already exists")
        directory(destination.parent)
        destination.mkdir()
        (destination / "native").mkdir()
        members, paths = [], []
        for name, item in self.native_files.items():
            relative = EVIDENCE + "/native/" + name
            require(fingerprint(self.native / name)["sha256"] == item["record"]["sha256"], "native source changed before copying: " + name)
            write_new(self.root / relative, item["raw"])
            members.append({"path": "native/" + name, **item["record"]})
            paths.append(relative)
        latest = native_snapshot(self.native)
        require({name: item["record"] for name, item in latest.items()} == self.state["native_members"], "native output changed while copying")
        manifest = {"schema": "pon-followthrough-native-members-v1", "selected_code_commit": self.c2,
                    "selected_code_tree": self.c2_tree, "original_directory": str(self.native), "members": members,
                    "all_original_stdout_stderr_retained": True, "binary_or_target_copied": False,
                    "binding_child_validated": False, "production_activation": False}
        for name, value in (("native-members.json", manifest), ("native-observations.json", self.observations)):
            relative = EVIDENCE + "/" + name
            write_new(self.root / relative, encoded(value))
            paths.append(relative)
        readme = f"""# PoN native follow-through observations, 2026-11-10

Status: **native checkpoint observed; open-consensus security HOLD**.

The native-v3 source is [`{self.c2}`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/{self.c2}), tree `{self.c2_tree}`. The [original summary](native/summary-v3.json), [complete command records](native/commands.json), [source before](native/source-before-v3.json) and [source after](native/source-after-v3.json) retain their original bytes. Each stdout/stderr member is included in Git and identified by bytes, SHA256 and Git blob in the [member manifest](native-members.json). This is an execution record from the stated environment, not independently authenticated hardware cost or a cost lower bound.

## Retained failures and counterfactual scope

The first offline `red-settlement` attempt ended before executing its test suite because dependencies were unavailable; its original stdout/stderr and the later dependency-fetch command are retained. The initial C1 checkpoint `{C1}` observed node red **0 passed / 4 failed**, then green **3 passed / 1 failed**. The green failure was a test expecting `STORAGE_PACKET` where the authenticated tip already returns `NATIVE_STATE_PARENT`; it is not relabeled as a successful initial run. Settlement red observed **2 passed / 6 failed**, then green **8 passed / 0 failed**.

The corrected v3 node counterfactual keeps C1 dependencies, uses the old node production file plus the test-module declaration, and executes the four corrected tests. It is **not a complete baseline-checkout rerun**; [its source record](native/red-v3-source.json) and the [earlier red patch](native/red-source.patch) retain that boundary. V3 observed node red **0/4**, C2 node green **4/0**, and C2 settlement green **8/0**. The complete three-owner suites, strict Clippy, format check, release probe, independently checked reader and 26 reader tests have their actual C2 command records. The [derived observation index](native-observations.json) only indexes those retained records.

## Code checkpoint and binding child

The CI fixes, authority/PQ128/W1 source bindings, refreshed corpus and generated distributed source inventory are added in the later child commit containing this directory. They did not exist in C2. Actual checks of that child are recorded separately by the integration controller outside the checkout, with its actual commit/tree and original source-verifier bracket. Creating this directory is not evidence that those later checks passed; C2's full native suites are not silently credited to the child. The generated inventory can affect examples, so any additional child native check must carry its own command/source receipt.

No historical evidence, qualification result, protocol parent/status field or acceptance condition is upgraded. Cheapest legal work cost, worst-case rejection/service liveness, QROM closure, public-prefix/liveness/chain-quality bounds, confirmation failure probabilities, model benefit and production activation remain unproved or disabled as before. The original failed hosted CI observations are not imported or represented as repaired hosted runs by this recorder.
"""
        write_new(destination / "README.md", readme.encode())
        paths.append(EVIDENCE + "/README.md")
        self.accept(paths)
        self.status("copy-native-evidence", "finished", started=stage_started, exit_code=0)
        return paths

    def prepare(self):
        require(self.state["phase"] == "starting", "prepare cannot overwrite a prior run")
        phase_started = time.time_ns()
        self.status("prepare", "running", started=phase_started)
        self.run("prepare-preflight", ["bash", "scripts/project-preflight.sh"])
        self.guard()
        baseline = tree_entries(self.root, BASE)
        predictions = self.preview_patches()
        for number, relative in enumerate(PATCHES, 1):
            raw = read_regular(self.inputs / relative)[0]
            paths = patch_paths(raw)
            self.run(f"patch-{number}-check", ["git", "apply", "--check", str(self.inputs / relative)])
            self.mutate(f"patch-{number}-apply", ["git", "apply", str(self.inputs / relative)], paths,
                        expected_entries=predictions[number - 1])
        self.mutate("authority-pq128-bindings", [sys.executable, "-B", str(self.inputs / "binding-tool/prepare_authority_pq128_binding.py"),
                    "--root", str(self.root), "--checkpoint", self.c2, "--output", str(self.out / "authority-pq128"),
                    "--apply", "--defer-validation"], AUTHORITY_TARGETS)
        self.mutate("w1-ledger-binding", [sys.executable, "-B", str(self.inputs / "integration/update_w1_ledger_binding.py"),
                    "--root", str(self.root), "--source", self.c2, "--receipt", str(self.out / "w1-ledger-receipt.json")], LEDGER_TARGETS)
        self.mutate("qrom-successor-binding", [sys.executable, "-B", str(self.inputs / "qrom-successor/prepare_qrom_successor_binding.py"),
                    "--root", str(self.root), "--checkpoint", self.c2, "--output", str(self.out / "qrom-successor"), "--apply"], QROM_TARGETS)
        evidence_paths = self.copy_native_evidence() + [path for path in (*LEDGER_TARGETS, *QROM_TARGETS) if path.startswith("evidence/")]
        self.guard()
        old_plan = read_regular(self.root / PLAN)[0]
        require(old_plan == git(self.root, "show", self.c2 + ":" + PLAN), "development plan differs from C2 before append")
        require(PLAN_MARKER.encode() not in old_plan, "follow-through plan entry already exists")
        appendix = f"""\n\n{PLAN_MARKER}

Status: **HOLD**. Native checkpoint `{self.c2}` (tree `{self.c2_tree}`) has the retained source-bracketed v3 observations. C1 `{C1}` keeps its initial node green failure (3 passed / 1 failed) and the initial offline dependency failure. The corrected node counterfactual changes only the old node owner plus its test declaration over C1 dependencies: red 0 passed / 4 failed, C2 green 4 passed / 0 failed. Settlement red remains 2 passed / 6 failed and C2 green 8 passed / 0 failed. The three owner suites, strict Clippy, release cost probe and 26 reader tests are recorded on C2; their exact commands and original streams are in the [native evidence](../../{EVIDENCE}/README.md).

The child integrates the exact CI roster/artifact/QROM-current registrations, preserves the historical QROM lane, rebinds selected source surveys to C2, retains every previous corpus dependency and adds the new implementation inputs. Its actual source/corpus/ledger/CI/repository/Markdown/format checks are separate controller receipts on the eventual child commit; this entry does not assert those checks or hosted CI passed. All false/null qualification fields, existing historical evidence and open work-cost/service/consensus/model-benefit obligations remain unchanged. No activation is authorized by this observation.
""".encode()
        replace_expected(self.root / PLAN, old_plan, old_plan + appendix)
        self.accept([PLAN])
        self.mutate("refresh-distributed-source-inventory", [sys.executable, "-B", "scripts/refresh_distributed_source_inventory.py"], [INVENTORY])
        self.state["evidence_paths"] = sorted(evidence_paths)
        self.state["raw_whitespace_exclusions"] = sorted(EVIDENCE + "/native/" + name for name in self.native_files
                                                        if name.endswith((".log", ".patch")))
        write_new(self.out / "raw-whitespace-exclusions.json", encoded({"paths": self.state["raw_whitespace_exclusions"],
                  "scope": "only original manifested native streams/patch; every JSON, document and source remains checked"}))
        self.save()
        self.guard()
        source_paths = sorted(set(self.state["expected_files"]) - set(evidence_paths))
        self.run("stage-explicit-source", ["git", "add", "--", *source_paths])
        self.accept([], index_changed=True)
        self.guard()
        self.run("stage-explicit-evidence-including-ignored-logs", ["git", "add", "-f", "--", *sorted(evidence_paths)])
        self.accept([], index_changed=True)
        candidate = self.state["expected_index"]
        self.verify_evidence_tree(candidate)
        args = ["--repo-root", str(self.root), "--checkpoint", self.c2, "--checkpoint-tree", self.c2_tree,
                "--candidate-tree", candidate, "--plan", str(self.out / "corpus-path-plan.json")]
        helper = str(self.inputs / "binding-update-v2/update_corpus.py")
        self.guard()
        self.run("corpus-path-inventory", [sys.executable, "-B", helper, "inventory", *args])
        self.guard()
        self.run("corpus-refresh-output", [sys.executable, "-B", helper, "update", *args,
                 "--output", str(self.out / "refreshed-corpus.json"), "--receipt", str(self.out / "corpus-receipt.json")])
        self.guard()
        original = git(self.root, "show", BASE + ":" + CORPUS)
        replacement = read_regular(self.out / "refreshed-corpus.json")[0]
        replace_expected(self.root / CORPUS, original, replacement)
        self.accept([CORPUS])
        self.run("stage-corpus", ["git", "add", "--", CORPUS])
        self.accept([], index_changed=True)
        final = tree_entries(self.root, self.state["expected_index"])
        require(baseline.keys() <= final.keys(), "candidate deleted an existing tracked path")
        require(all(final[path] == entry for path, entry in baseline.items() if path.startswith(("evidence/", "qualification/"))),
                "candidate changed historical evidence or qualification")
        self.verify_evidence_tree(self.state["expected_index"])
        self.run("prepared-source-diff-check", ["git", "diff", "--cached", "--check", "--",
                                               *whitespace_paths(self.state["raw_whitespace_exclusions"])])
        self.guard()
        require(not git(self.root, "diff", "--name-only"), "unstaged changes remain after prepare")
        self.state["phase"] = "prepared"
        self.state["candidate_index_tree_before_corpus"] = candidate
        self.state["prepared_tree"] = self.state["expected_index"]
        self.state["native_source_delta"] = self.review_native_delta(self.state["prepared_tree"])
        write_new(self.out / "native-source-delta-prepared.json", encoded(self.state["native_source_delta"]))
        self.save()
        self.status("prepare", "finished", started=phase_started, exit_code=0)
        print("PREPARED", self.state["prepared_tree"], "SECURITY_HOLD", flush=True)

    def commit(self):
        require(self.state["phase"] == "prepared", "commit needs the exact prepared candidate")
        phase_started = time.time_ns()
        self.status("commit", "running", started=phase_started)
        attempt = self.state.get("commit_attempts", 0) + 1
        self.state["commit_attempts"] = attempt
        self.save()
        label = f"commit-{attempt:02}"
        self.guard()
        self.verify_evidence_tree(self.state["prepared_tree"])
        self.run(label + "-preflight", ["bash", "scripts/project-preflight.sh"])
        self.guard()
        self.run(label + "-binding-child", ["git", "commit", "-m", "fix(pon): retain native receipts and bind reviewed CI source dependencies"])
        c3 = git_text(self.root, "rev-parse", "HEAD")
        require(git_text(self.root, "rev-list", "--parents", "-n", "1", c3).split() == [c3, self.c2], "binding commit has unexpected parent")
        require(git_text(self.root, "rev-parse", c3 + "^{tree}") == self.state["prepared_tree"]
                and not git(self.root, "status", "--porcelain"), "committed tree differs or checkout is dirty")
        self.state.update(phase="committed", expected_head=c3, expected_index=self.state["prepared_tree"], source_c3=c3)
        self.save()
        self.verify_evidence_tree(c3)
        self.guard()
        delta = self.review_native_delta(c3)
        require(delta == self.state["native_source_delta"],
                "committed native dependency delta differs from the prepared review")
        delta.update(binding_child_c3=c3, binding_child_tree=self.state["prepared_tree"])
        write_new(self.out / "native-source-delta.json", encoded(delta))
        write_new(self.out / "committed-source.json", encoded({"code_checkpoint_c2": self.c2, "binding_child_c3": c3,
                  "tree": self.state["prepared_tree"], "native_execution_source": self.c2, "child_checks_complete": False,
                  "open_consensus_qualified": False, "production_activation": False, "security_status": "HOLD"}))
        self.status("commit", "finished", started=phase_started, exit_code=0)
        print("COMMITTED", c3, "SECURITY_HOLD", flush=True)

    def validate(self):
        require(self.state["phase"] in ("committed", "validated", "validation_failed"), "validate needs the committed binding child")
        phase_started = time.time_ns()
        self.status("validate", "running", started=phase_started)
        self.guard()
        require(not git(self.root, "status", "--porcelain"), "validation requires a clean committed child")
        require(git(self.root, "show", BASE + ":" + VERIFY_SOURCE) == read_regular(self.root / VERIFY_SOURCE)[0],
                "the original source verifier was modified")
        c3 = self.state["source_c3"]
        index = len(self.state.get("validation_runs", [])) + 1
        prefix = f"validation-{index:02}"
        attempt = {"summary": prefix + "-summary.json", "complete": False,
                   "started_unix_ns": phase_started, "state": "running"}
        self.state.setdefault("validation_runs", []).append(attempt)
        self.save()
        before, after = self.out / (prefix + "-source-before.json"), self.out / (prefix + "-source-after.json")
        qrom = self.out / (prefix + "-qrom-current")
        qrom.mkdir(mode=0o755)
        source = [sys.executable, "-B", VERIFY_SOURCE, "--kind", "head", "--expected-head", c3, "--output"]
        first = len(self.commands)
        self.run(prefix + "-source-before", source + [str(before)])
        suites = (
            "scripts/ci/test_pq_research_integration.py", "scripts/ci/test_ci_source_integrity.py",
            "scripts/ci/test_ci_contract.py", "scripts/ci/test_w1_factorial_native_gate.py",
            "scripts/ci/test_prepare_artifact_upload.py", "scripts/ci/test_cell_storage_convergence_ci.py",
            "scripts/ci/test_cell_discovery_v3_ci.py", "scripts/ci/test_fresh_rejection_report.py",
            "scripts/ci/test_w1_qrom_current_ci.py", "scripts/ci/test_pq_authority_effect_register.py",
            "scripts/ci/test_pq_lifetime_budget.py", "scripts/ci/test_w1_lifetime_ledger.py",
        )
        checks = [("preflight", ["bash", "scripts/project-preflight.sh"])]
        checks += [(Path(path).stem, [sys.executable, "-B", path, "-v"]) for path in suites]
        checks += [("corpus", [sys.executable, "-B", "scripts/ci/check_pq_research_integration.py"]),
                   ("ci-contract", [sys.executable, "-B", "scripts/ci/check_ci_contract.py"]),
                   ("qrom-current-named", [sys.executable, "-B", "scripts/ci/w1_qrom_current_ci.py", "named",
                                           "--repo-root", str(self.root), "--out", str(qrom)]),
                   ("qrom-historical-drift", [sys.executable, "-B", "scripts/ci/w1_qrom_current_ci.py", "drift",
                                              "--repo-root", str(self.root), "--out", str(qrom)]),
                   ("qrom-current-implementation", [sys.executable, "-B", "scripts/w1_qrom_current_implementation_audit.py",
                                                    "--repo-root", str(self.root), "--output", str(qrom / "implementation.json")]),
                   ("authority-register", [sys.executable, "-B", "scripts/ci/pq_authority_effect_register.py"]),
                   ("pq128-lifetime", [sys.executable, "-B", "scripts/ci/pq_lifetime_budget.py"]),
                   ("w1-lifetime-report", [sys.executable, "-B", "scripts/w1_lifetime_ledger.py", "--input", LEDGER_EVIDENCE + "/project-input.json"]),
                   ("w1-lifetime-report-identical", ["cmp", str(self.out / (prefix + "-w1-lifetime-report.stdout.log")),
                                                    str(self.root / LEDGER_EVIDENCE / "project-report.json")]),
                   ("distributed-inventory", [sys.executable, "-B", "scripts/refresh_distributed_source_inventory.py", "--check"]),
                   ("repository-and-markdown-links", [sys.executable, "-B", "scripts/ci/check_repository.py"]),
                   ("source-diff-whitespace", ["git", "diff", "--check", self.c2, c3, "--",
                                               *whitespace_paths(self.state["raw_whitespace_exclusions"])]),
                   ("format", ["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"])]
        write_new(self.out / (prefix + "-planned-checks.json"), encoded({"source": c3, "checks": checks,
                  "native_full_suites_repeated": False, "checks_already_passed": False}))
        for label, argv in checks:
            self.guard()
            self.run(prefix + "-" + label, argv, required=False)
        self.run(prefix + "-source-after", source + [str(after)], required=False)
        self.run(prefix + "-source-identical", ["cmp", str(before), str(after)], required=False)
        self.guard()
        self.verify_evidence_tree(c3)
        require(not git(self.root, "status", "--porcelain"), "checks changed the committed checkout")
        actual = self.commands[first:]
        before_source = strict_json(read_regular(before)[0])
        after_source = strict_json(read_regular(after)[0])
        source_valid = (before_source == after_source and before_source.get("schema") == "trnm-ci-source-v1"
                        and before_source.get("kind") == "head" and before_source.get("tested_commit") == c3
                        and before_source.get("candidate") == c3 and before_source.get("tested_tree") == self.state["prepared_tree"]
                        and before_source.get("tracked_worktree_verified") is True
                        and before_source.get("tests_executed_by_identity_check") is False)
        complete = all(row["exit_code"] == 0 for row in actual) and source_valid
        result = {"schema": "pon-followthrough-binding-child-checks-v1", "code_checkpoint_c2": self.c2,
                  "binding_child_c3": c3, "binding_child_tree": self.state["prepared_tree"], "source_bracket_identical":
                  actual[-1]["exit_code"] == 0 and source_valid, "complete": complete,
                  "commands": [{"label": row["label"], "exit_code": row["exit_code"]} for row in actual],
                  "native_execution_source": self.c2, "native_full_suites_repeated": False,
                  "remaining_native_child_checks": self.state["native_source_delta"]["final_native_policy"],
                  "hosted_ci_observed_complete": False, "open_consensus_qualified": False,
                  "production_activation": False, "security_status": "HOLD"}
        write_new(self.out / (prefix + "-summary.json"), encoded(result))
        attempt.update(complete=complete, state="finished", end_unix_ns=time.time_ns())
        self.state["phase"] = "validated" if complete else "validation_failed"
        self.save()
        self.status("validate", "finished" if complete else "failed", started=phase_started,
                    exit_code=0 if complete else 2)
        print("VALIDATION", json.dumps(result, sort_keys=True), flush=True)
        require(complete, "one or more actual C3 checks failed; no push or qualification performed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("prepare", "commit", "validate", "all"), required=True)
    parser.add_argument("--root", type=Path, required=True, help="complete real C2 checkout; never a partial staging directory")
    parser.add_argument("--inputs", type=Path, required=True, help="external bundle with the nine exact relative paths in INPUT_SHA256")
    parser.add_argument("--native-validation", type=Path, required=True, help="original stable native OUT containing complete summary-v3.json")
    parser.add_argument("--output", type=Path, required=True, help="fresh external receipts directory for prepare/all; same directory for later phases")
    args = parser.parse_args()
    controller = None
    try:
        controller = Controller.__new__(Controller)
        controller.__init__(args)
        if args.phase in ("prepare", "all"):
            controller.prepare()
        if args.phase in ("commit", "all"):
            controller.commit()
        if args.phase in ("validate", "all"):
            controller.validate()
        atomic_json(controller.out / "summary.json", {"schema": "pon-followthrough-controller-summary-v1",
                    "recorded_unix_ns": time.time_ns(), "requested_phase": args.phase,
                    "requested_phase_complete": True, "state": controller.state["phase"],
                    "integration_complete": controller.state["phase"] == "validated",
                    "code_checkpoint_c2": controller.c2, "code_tree_c2": controller.c2_tree,
                    "binding_child_c3": controller.state.get("source_c3"),
                    "binding_child_tree": controller.state.get("prepared_tree"),
                    "commands_recorded": len(controller.commands), "validation_runs": controller.state.get("validation_runs", []),
                    "native_full_suites_repeated": False, "hosted_ci_observed_complete": False,
                    "open_consensus_qualified": False, "production_activation": False, "security_status": "HOLD"})
    except (Refusal, OSError, ValueError, KeyError, IndexError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        message = {"status": "REFUSE_OR_ACTUAL_FAILURE", "reason": str(error), "security_status": "HOLD",
                   "recorded_unix_ns": time.time_ns(), "requested_phase": args.phase,
                   "no_automatic_rollback": True, "no_push_or_activation": True}
        if controller is not None and getattr(controller, "owns_output", False):
            if args.phase in ("all", "validate") and controller.state.get("validation_runs"):
                attempt = controller.state["validation_runs"][-1]
                if attempt.get("state") == "running":
                    attempt.update(state="interrupted_or_failed", complete=False, reason=str(error),
                                   end_unix_ns=message["recorded_unix_ns"])
                    controller.state["phase"] = "validation_failed"
                    controller.save()
            failure = controller.out / ("failure-" + str(time.time_ns()) + ".json")
            write_new(failure, encoded(message))
            atomic_json(controller.out / "failure.json", message)
            controller.status(args.phase, "failed", started=getattr(controller, "phase_started", message["recorded_unix_ns"]), exit_code=2)
        elif args.phase in ("prepare", "all") and not args.output.exists():
            # A refused preflight still leaves the known small failure file, but
            # never overwrites a directory from another or an earlier run.
            try:
                directory(args.output, exists=False)
                require(not args.output.is_relative_to(args.root), "receipt path is inside ROOT")
                args.output.mkdir(mode=0o755)
                write_new(args.output / "failure.json", encoded(message))
                write_new(args.output / "status.json", encoded({"stage": "preflight", "phase": "failed", "last_exit": 2,
                          "started_unix_ns": message["recorded_unix_ns"], "end_unix_ns": message["recorded_unix_ns"],
                          "current_head": None, "security_status": "HOLD"}))
            except (OSError, Refusal):
                pass
        print(json.dumps(message, sort_keys=True), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
