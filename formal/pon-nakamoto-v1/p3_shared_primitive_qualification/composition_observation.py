"""Bind a composition observation without converting a failed scope gate to PASS.

This is local evidence bookkeeping, not an authenticated attestation or a
runtime/cryptographic qualification. The normal runner still rejects any
runtime difference from the original research baseline.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess


RUNTIME_BASE = "cc836dfc13ef0006eb0878abd8cb5eca9a76bec0"
CRYPTO_BASE = "ebc31f07f96060fe1e9fb165aae0123de0fcbc1a"
RUNTIME_PATHS = ("trillionnium", "config", "qualification")
CRATE = "formal/pon-nakamoto-v1/w1_public_stark_research"
CRYPTO_FILES = tuple(f"{CRATE}/{name}" for name in (
    "Cargo.toml", "Cargo.lock", "src/tagged_sha3.rs", "src/tagged_sha3_wire.rs",
    "examples/tagged_sha3_mmcs_binding.rs",
))
REQUIRED_GATES = (
    "preflight", "source-before", "evidence-git-closure", "repository-and-markdown",
    "repository-negatives", "source-integrity-negatives", "historical-hash-audit",
    "model-budget", "ordinary-path-extractor", "evidence-closure-negatives",
    "composition-observation-negatives", "finite-origin-control",
    "independent-reference-vectors", "locked-offline-graph",
    "pruned-mmcs-source-identity", "format", "strict-clippy", "rust-tests",
    "doc-tests", "build", "tagged-pruned-mmcs-binding", "historical-native-hash-probe",
    "unchanged-runtime-scope", "pruned-mmcs-source-after", "source-after",
)


class ObservationError(ValueError):
    """A composition observation is missing or inconsistent with its inputs."""


def require(value: bool, message: str) -> None:
    if not value:
        raise ObservationError(message)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=root)


def runtime_scope_command() -> list[str]:
    # --exit-code remains mandatory in BOTH modes. The extra flags preserve a
    # complete deterministic patch and disallow external diff/text converters.
    return ["git", "--no-replace-objects", "diff", "--exit-code", "--no-ext-diff",
            "--no-textconv", "--full-index", "--binary", RUNTIME_BASE, "HEAD",
            "--", *RUNTIME_PATHS]


def accepted_exit_codes(name: str, composition_observation: bool) -> tuple[int, ...]:
    if name == "unchanged-runtime-scope" and composition_observation:
        return (0, 1)
    return (0,)


def frozen_crypto_sources(root: Path) -> dict:
    """Keep the exact #803 example as well as the four existing #795 pins."""
    result = {}
    for path in CRYPTO_FILES:
        actual_path = root / path
        require(not actual_path.is_symlink() and actual_path.is_file(),
                "missing or non-regular frozen cryptographic source: " + path)
        actual = actual_path.read_bytes()
        expected = git(root, "show", f"{CRYPTO_BASE}:{path}")
        require(actual == expected, "frozen cryptographic source differs: " + path)
        result[path] = {"bytes": len(actual), "sha256": digest(actual)}
    return result


def build_observation(root: Path, expected_head: str, output: Path,
                      records: list[dict]) -> dict:
    """Recheck source/patch/receipts; never infer a passed original scope gate.

    The runner, its files, and the local account are trusted execution inputs.
    These receipts cannot establish independent execution by an adversarial
    operator who controls both the runner and its evidence directory.
    """
    root = root.resolve(strict=True)
    require(re.fullmatch(r"[0-9a-f]{40}", expected_head) is not None,
            "expected current source must be an exact commit")
    require(git(root, "rev-parse", "HEAD").decode().strip() == expected_head,
            "current source does not equal the expected commit")
    require(not git(root, "status", "--porcelain", "--untracked-files=all").strip(),
            "current worktree is not clean")
    tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    require([row["name"] for row in records] == list(REQUIRED_GATES),
            "original gate roster is missing, duplicated, changed, or reordered")
    for row in records:
        code = row["exit_code"]
        require(type(code) is int and code in accepted_exit_codes(row["name"], True),
                "required gate failed: " + row["name"])
        for stream in ("stdout", "stderr"):
            raw = (output / (row["name"] + "." + stream + ".txt")).read_bytes()
            require(digest(raw) == row[stream + "_sha256"],
                    "recorded gate stream differs: " + row["name"] + "/" + stream)
    before = (output / "source-before.json").read_bytes()
    after = (output / "source-after.json").read_bytes()
    require(before == after, "complete source receipts differ")
    identity = json.loads(before)
    require(identity.get("schema") == "trnm-ci-source-v1"
            and identity.get("kind") == "head"
            and identity.get("tested_commit") == expected_head
            and identity.get("candidate") == expected_head
            and identity.get("tested_tree") == tree
            and identity.get("base") is None
            and identity.get("prospective_merge") is None
            and identity.get("tracked_worktree_verified") is True
            and type(identity.get("tracked_entries")) is int
            and identity["tracked_entries"] > 0
            and type(identity.get("tracked_bytes")) is int
            and identity["tracked_bytes"] > 0,
            "complete source receipt does not bind the current source")
    for name in ("source-before", "source-after"):
        row = next(row for row in records if row["name"] == name)
        require(row["argv"] == ["python3", "-B", "scripts/ci/verify_ci_source.py",
                               "--kind", "head", "--expected-head", expected_head,
                               "--output", str(output / (name + ".json"))]
                and row["cwd"] == str(root), "source verification command differs")
        require(json.loads((output / (name + ".stdout.txt")).read_bytes()) == identity,
                "source output differs from its complete source receipt")
    scope = next(row for row in records if row["name"] == "unchanged-runtime-scope")
    require(scope["argv"] == runtime_scope_command() and scope["cwd"] == str(root),
            "original unchanged-runtime guard was replaced")
    observed = subprocess.run(runtime_scope_command(), cwd=root, capture_output=True)
    require(observed.returncode in (0, 1), "cannot reproduce original runtime comparison")
    require(observed.returncode == scope["exit_code"]
            and observed.stdout == (output / "unchanged-runtime-scope.stdout.txt").read_bytes()
            and observed.stderr == (output / "unchanged-runtime-scope.stderr.txt").read_bytes(),
            "recorded runtime difference does not match the actual source")
    require(bool(observed.stdout) == (observed.returncode == 1),
            "runtime comparison exit code and actual patch disagree")
    frozen = frozen_crypto_sources(root)
    return {
        "schema": "p3.shared-primitive.composition-observation.v1",
        "current_commit": expected_head, "current_tree": tree,
        "fixed_runtime_reference": RUNTIME_BASE,
        "fixed_runtime_reference_tree": git(root, "rev-parse", RUNTIME_BASE + "^{tree}").decode().strip(),
        "runtime_paths": list(RUNTIME_PATHS),
        "original_unchanged_runtime_scope_passed": observed.returncode == 0,
        "original_unchanged_runtime_scope_exit_code": observed.returncode,
        "runtime_diff": {"file": "unchanged-runtime-scope.stdout.txt",
                         "bytes": len(observed.stdout), "sha256": digest(observed.stdout)},
        "frozen_crypto_reference": CRYPTO_BASE, "frozen_crypto_files": frozen,
        "source_receipt_sha256": digest(before),
        "required_gate_roster": list(REQUIRED_GATES),
        "required_gate_records_sha256": digest(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()),
        "observation_checks_completed": True,
        "runtime_changes_qualified": False,
        "cryptographic_qualification": False,
        "complete_noninteractive_security_bits": None,
        "lifetime_quantum_bound_established": False,
        "complete_repository_ci": False,
        "qualification": "HOLD_NO_GO", "production_activation": False,
    }
