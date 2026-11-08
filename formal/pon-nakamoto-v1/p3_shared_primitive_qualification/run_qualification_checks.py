#!/usr/bin/env python3
"""Run focused research gates on an exact clean commit; never grant qualification.

Run from a complete repository checkout with the pinned Rust toolchain and
dependencies already available. Outputs must be outside the checkout. No
network installation, Git mutation, production node, or publishing is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target-dir", required=True, type=Path)
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    research = root / "formal/pon-nakamoto-v1/w1_public_stark_research"
    scope = Path(__file__).resolve().parent
    output, target = args.output.resolve(), args.target_dir.resolve()
    if output.is_relative_to(root) or target.is_relative_to(root):
        raise SystemExit("Outputs and build target must be outside the checkout")
    if re.fullmatch(r"[0-9a-f]{40}", args.expected_head) is None:
        raise SystemExit("Expected head must be an exact commit SHA")
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env.update(PYTHONDONTWRITEBYTECODE="1", GIT_TERMINAL_PROMPT="0", CARGO_TERM_COLOR="never")
    records = []

    def sha(path: Path) -> str:
        with path.open("rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()

    def git(*argv: str) -> str:
        return subprocess.check_output(["git", *argv], cwd=root, env=env, text=True).strip()

    def save(name: str, value: object) -> None:
        with (output / name).open("x") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")

    def run(name: str, argv: list, cwd: Path = root) -> str:
        argv = list(map(str, argv))
        print(json.dumps({"start": name}), flush=True)
        started = time.perf_counter()
        stdout, stderr = output / (name + ".stdout.txt"), output / (name + ".stderr.txt")
        with stdout.open("xb") as a, stderr.open("xb") as b:
            result = subprocess.run(argv, cwd=cwd, env=env, stdout=a, stderr=b)
        record = {"name": name, "argv": argv, "cwd": str(cwd),
                  "exit_code": result.returncode, "wall_seconds": time.perf_counter() - started,
                  "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)}
        records.append(record)
        save(name + ".status.json", record)
        print(json.dumps(record), flush=True)
        if result.returncode:
            print(stdout.read_text(errors="replace")[-5000:], flush=True)
            print(stderr.read_text(errors="replace")[-5000:], flush=True)
            raise SystemExit(result.returncode)
        return stdout.read_text(errors="replace") + stderr.read_text(errors="replace")

    if git("rev-parse", "HEAD") != args.expected_head:
        raise SystemExit("Head changed before checks")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise SystemExit("Exact-commit checks require a clean worktree")
    run("preflight", ["bash", "scripts/project-preflight.sh"])
    source = ["python3", "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
              "--expected-head", args.expected_head, "--output"]
    run("source-before", source + [output / "source-before.json"])
    run("repository-and-markdown", ["python3", "-B", "scripts/ci/check_repository.py"])
    counts = {}
    for label, command, directory, minimum in (
        ("repository-negatives", ["python3", "-B", "scripts/ci/test_repository.py"], root, 50),
        ("source-integrity-negatives", ["python3", "-B", "scripts/ci/test_ci_source_integrity.py"], root, 43),
        ("historical-hash-audit", ["python3", "-B", "-m", "unittest", "-v", "test_hash_role_audit.py"], research / "security_model_audit", 10),
        ("model-budget", ["python3", "-B", "-m", "unittest", "discover", "-s", ".", "-p", "test_*.py", "-v"], scope / "budget", 40),
        ("ordinary-path-extractor", ["python3", "-B", "-m", "unittest", "-v", "test_opening_collision_extractor.py"], scope / "restricted_tree", 6),
    ):
        log = run(label, command, directory)
        matches = re.findall(r"Ran\s+(\d+)\s+tests?\b", log)
        if len(matches) != 1 or int(matches[0]) < minimum or re.search(r"\nOK\s*\Z", log) is None:
            raise SystemExit("Unexpected test result: " + label)
        counts[label] = int(matches[0])
    run("finite-origin-control", ["python3", "-B", "finite_origin_check.py"], scope / "restricted_tree")
    enumeration = json.loads((output / "finite-origin-control.stdout.txt").read_text())
    run("independent-reference-vectors", ["python3", "-B", scope / "reference_vectors.py"])
    regenerated = (output / "independent-reference-vectors.stdout.txt").read_bytes()
    fixture = research / "tests/tagged_sha3_reference_vectors.json"
    if regenerated != fixture.read_bytes():
        raise SystemExit("Independent reference vectors differ from the Rust fixture")
    cargo = [args.cargo, "+1.95.0"]
    manifest = ["--manifest-path", research / "Cargo.toml"]
    run("locked-offline-graph", cargo + ["metadata", *manifest, "--locked", "--offline", "--format-version", "1"])
    graph = json.loads((output / "locked-offline-graph.stdout.txt").read_text())
    p3 = [p for p in graph["packages"] if p["name"].startswith("p3-")]
    if not p3 or any(p["version"] != "0.8.0" for p in p3):
        raise SystemExit("P3 graph drift")
    sha3 = [p for p in graph["packages"] if p["name"] == "sha3"]
    if len(sha3) != 1 or sha3[0]["version"] != "0.10.9":
        raise SystemExit("SHA3 graph drift")
    run("format", cargo + ["fmt", *manifest, "--", "--check"])
    flags = [*manifest, "--release", "--all-targets", "--all-features", "--locked", "--offline", "--target-dir", target]
    run("strict-clippy", cargo + ["clippy", *flags, "--", "-D", "warnings"])
    log = run("rust-tests", cargo + ["test", *flags])
    rust = [tuple(map(int, row)) for row in re.findall(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", log)]
    if not rust or any(any(row[1:]) for row in rust) or sum(row[0] for row in rust) < 56:
        raise SystemExit("Unexpected Rust test result")
    if "independent_python_hashlib_vectors_match_actual_hash_roles ... ok" not in log:
        raise SystemExit("Independent Rust role-vector test did not pass")
    counts["rust"] = sum(row[0] for row in rust)
    run("doc-tests", cargo + ["test", *manifest, "--release", "--all-features", "--locked", "--offline", "--target-dir", target, "--doc"])
    run("build", cargo + ["build", *flags])
    run("historical-native-hash-probe", [target / "release/examples/hash_role_probe"])
    probe = json.loads((output / "historical-native-hash-probe.stdout.txt").read_text())
    if not (probe["actual_p3_api"] and probe["arbitrary_compressor_collision"]
            and not probe["merkle_or_w1_forgery"] and probe["qualification"] == "HOLD_NO_GO"):
        raise SystemExit("Historical audit outcome drift")
    run("unchanged-runtime-scope", ["git", "diff", "--exit-code", "cc836dfc13ef0006eb0878abd8cb5eca9a76bec0", "HEAD", "--", "trillionnium", "config", "qualification"])
    run("source-after", source + [output / "source-after.json"])
    if (output / "source-before.json").read_bytes() != (output / "source-after.json").read_bytes():
        raise SystemExit("Source changed while checking")
    if git("rev-parse", "HEAD") != args.expected_head or git("status", "--porcelain", "--untracked-files=all"):
        raise SystemExit("Head/worktree changed while checking")
    summary = {
        "schema": "p3.shared-primitive.focused-gates.v1", "commit": args.expected_head,
        "tree": git("rev-parse", "HEAD^{tree}"), "records": records, "tests": counts,
        "finite_origin_control": enumeration, "source_receipts_equal": True,
        "independent_reference_vectors_sha256": sha(fixture),
        "source_receipt_sha256": sha(output / "source-after.json"),
        "binary_sha256": {name: sha(target / "release/examples" / name)
                          for name in ("tagged_sha3_backend", "packed_carry_backend")},
        "qualification": "HOLD_NO_GO", "complete_repository_ci": False,
        "production_activation": False, "production_node_invocations": 0,
    }
    save("focused-gates.json", summary)
    print(json.dumps({"result": "FOCUSED_CHECKS_PASS", "commit": args.expected_head,
                      "tests": counts, "summary_sha256": sha(output / "focused-gates.json"),
                      "qualification": "HOLD_NO_GO"}), flush=True)


if __name__ == "__main__":
    main()
