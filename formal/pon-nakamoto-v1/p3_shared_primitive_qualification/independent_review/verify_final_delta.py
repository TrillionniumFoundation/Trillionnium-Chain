#!/usr/bin/env python3
"""Reproduce finite reference-vector and runner-parser observations only.

This does not build or execute Rust, touch the native worktree, or evaluate a
cryptographic security bound. All written evidence stays in this directory.
"""
from __future__ import annotations

import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

BASE = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
FIELD = 18446744069414584321
PROFILE = b"TRNM-W1-P3-SHA3-512-TAGGED-R1"
MAGIC = b"TRNM-W1-SHARED-HASH\0"
DESCRIPTOR = b"p3=0.8.0;sha3=512;r=576;c=1024;F=18446744069414584321;E=X^2-7;binary;cap=0;log_blowup=2;log_final_poly=0;max_log_arity=1;queries=64;pow=0;zk=0;sha=d13,w7728,p27,q2,next1;carry=d14,w370,p180,q1,next0"
ROLES = {"leaf": 1, "branch": 2, "transcript": 3, "statement_context": 4}


def unsigned(value: int, width: int) -> bytes:
    return value.to_bytes(width, byteorder="little", signed=False)


def main() -> None:
    fixture_path = BASE / "tagged_profile_impl/tests/tagged_sha3_reference_vectors.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture = json.loads(fixture_bytes)
    assert fixture_bytes == (BASE / "root_docs/tagged_sha3_reference_vectors.json").read_bytes()
    assert fixture["descriptor"].encode("ascii") == DESCRIPTOR
    assert fixture["profile_id"].encode("ascii") == PROFILE
    assert fixture["security_claim"] is False
    assert len(fixture["cases"]) == 31
    rust = (BASE / "tagged_profile_impl/src/tagged_sha3.rs").read_text()
    for name, expected in (("PROFILE_ID", PROFILE), ("FRAME_MAGIC", MAGIC), ("DESCRIPTOR", DESCRIPTOR)):
        match = re.search(r"pub const " + name + r": &\[u8\] = (b\"[^\"]*\");", rust)
        assert match is not None, name
        assert ast.literal_eval(match[1]) == expected, name
    previous = json.loads((HERE / "source_receipt.json").read_text())
    previous_files = {item["path"]: item for item in previous["subject_files"]}
    profile_path = BASE / "tagged_profile_impl/src/tagged_sha3.rs"
    test_path = BASE / "tagged_profile_impl/tests/tagged_sha3_profile.rs"
    old_profile = previous_files[str(profile_path)]
    old_test = previous_files[str(test_path)]
    undo_descriptor_labels = profile_path.read_bytes().replace(
        b";log_blowup=2;log_final_poly=0;max_log_arity=1;",
        b";blowup=2;final=0;arity=1;",
    )
    assert hashlib.sha256(undo_descriptor_labels).hexdigest() == old_profile["sha256"]
    test_prefix = test_path.read_bytes()[:old_test["bytes"]]
    assert hashlib.sha256(test_prefix).hexdigest() == old_test["sha256"]

    coverage = Counter()
    names = set()
    for case in fixture["cases"]:
        assert case["name"] not in names
        names.add(case["name"])
        role, component = case["role"], case["component"]
        context = bytes.fromhex(case["context_hex"])
        payload = bytes.fromhex(case["payload_hex"])
        assert len(context) == 64
        assert (component == 0) == (role == "statement_context")
        assert component in (0, 1, 4)
        if role == "statement_context":
            assert context == bytes(64)
            fields = [bytes.fromhex(case[key]) for key in
                      ("public_hex", "expected_header_hex", "expected_artifacts_hex")]
            typed = unsigned(3, 4)
            for tag, value in enumerate(fields, 1):
                typed += unsigned(tag, 1) + unsigned(len(value), 8) + value
            assert typed == payload
        elif role == "leaf":
            assert len(payload) % 8 == 0
            assert all(int.from_bytes(payload[i:i + 8], "little") < FIELD
                       for i in range(0, len(payload), 8))
        elif role == "branch":
            assert len(payload) == 128
        elif role != "transcript":
            raise AssertionError("unexpected role")
        # Independent concatenation using integer byte conversion, with no call
        # to the generator's frame() or the Rust frame_header().
        message = (MAGIC + unsigned(1, 2) + unsigned(len(PROFILE), 2) + PROFILE
                   + unsigned(len(DESCRIPTOR), 2) + DESCRIPTOR
                   + unsigned(component, 4) + unsigned(ROLES[role], 1) + context
                   + payload + unsigned(len(payload), 8))
        assert len(message) == case["framed_message_bytes"], case["name"]
        assert hashlib.sha3_512(message).hexdigest() == case["sha3_512_hex"], case["name"]
        coverage[f"component_{component}_{role}"] += 1

    regeneration = subprocess.run(
        [sys.executable, "-B", str(BASE / "root_docs/reference_vectors.py")],
        capture_output=True, check=False,
    )
    (HERE / "reference_regeneration.stdout.txt").write_bytes(regeneration.stdout)
    (HERE / "reference_regeneration.stderr.txt").write_bytes(regeneration.stderr)
    assert regeneration.returncode == 0
    assert regeneration.stdout == fixture_bytes

    # Real unittest output demonstrates the former runner predicate's gap.
    # This is deliberately a skipped suite, not a successful test execution.
    skipped_program = """import unittest
def skip(self): self.skipTest('parser counterexample; no test body executed')
case = type('SkippedControls', (unittest.TestCase,),
            {f'test_{i:02d}': skip for i in range(40)})
suite = unittest.defaultTestLoader.loadTestsFromTestCase(case)
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(not result.wasSuccessful())
"""
    skipped = subprocess.run([sys.executable, "-B", "-c", skipped_program],
                             capture_output=True, check=False)
    (HERE / "skipped_parser_control.stdout.txt").write_bytes(skipped.stdout)
    (HERE / "skipped_parser_control.stderr.txt").write_bytes(skipped.stderr)
    skipped_log = (skipped.stdout + skipped.stderr).decode("utf-8")
    matches = re.findall(r"Ran\s+(\d+)\s+tests?\b", skipped_log)
    former_acceptance = (skipped.returncode == 0 and len(matches) == 1
                         and int(matches[0]) >= 40 and "\nOK" in skipped_log)
    assert former_acceptance and "OK (skipped=40)" in skipped_log

    # Evaluate only the relevant current-source guard expressions, not main().
    # No Git, native Cargo, benchmark, or full qualification command is run.
    runner_path = BASE / "root_docs/run_qualification_checks.py"
    runner_bytes = runner_path.read_bytes()
    runner_tree = ast.parse(runner_bytes)
    guards = [node for node in ast.walk(runner_tree) if isinstance(node, ast.If)]
    python_guard = next(node.test for node in guards
                        if "Unexpected test result: " in ast.unparse(node.body))
    rust_guard = next(node.test for node in guards
                      if "Unexpected Rust test result" in ast.unparse(node.body))
    rust_assignment = next(node.value for node in ast.walk(runner_tree)
                           if isinstance(node, ast.Assign)
                           and any(isinstance(target, ast.Name) and target.id == "rust"
                                   for target in node.targets))

    def python_accepts(log: str) -> bool:
        namespace = {"re": re, "log": log, "minimum": 40,
                     "matches": re.findall(r"Ran\s+(\d+)\s+tests?\b", log)}
        return not eval(compile(ast.Expression(python_guard), str(runner_path), "eval"), namespace)

    def rust_accepts(counts: tuple[int, int, int, int, int]) -> bool:
        a, b, c, d, e = counts
        log = (f"test result: ok. {a} passed; {b} failed; {c} ignored; "
               f"{d} measured; {e} filtered out; finished in 1.0s\n")
        namespace = {"re": re, "log": log}
        namespace["rust"] = eval(compile(ast.Expression(rust_assignment), str(runner_path), "eval"), namespace)
        return not eval(compile(ast.Expression(rust_guard), str(runner_path), "eval"), namespace)

    assert python_accepts("Ran 40 tests in 0.1s\n\nOK\n")
    assert not python_accepts(skipped_log)
    assert not python_accepts("Ran 40 tests in 0.1s\n\nOK (expected failures=40)\n")
    assert not python_accepts("Ran 40 tests in 0.1s\n\nFAILED (unexpected successes=1)\n")
    assert not python_accepts("Ran 39 tests in 0.1s\n\nOK\n")
    assert rust_accepts((56, 0, 0, 0, 0))
    assert not rust_accepts((55, 0, 0, 0, 0))
    for column in range(1, 5):
        counts = [56, 0, 0, 0, 0]
        counts[column] = 1
        assert not rust_accepts(tuple(counts))
    print(json.dumps({
        "schema": "p3.tagged.sha3.final_delta.observations.v1",
        "reference_vectors_recomputed": 31,
        "reference_case_coverage": dict(sorted(coverage.items())),
        "reference_fixture_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
        "regenerated_fixture_byte_identical": True,
        "delta_identity_checks": {
            "profile_diff_exactly_descriptor_label_change": True,
            "test_previous_snapshot_is_unchanged_prefix": True,
        },
        "former_runner_accepts_all_skipped_control": former_acceptance,
        "all_skipped_control_tests_executed": 0,
        "current_runner_parser_controls": {
            "python_cases": 5, "rust_cases": 6, "all_passed": True,
            "runner_sha256": hashlib.sha256(runner_bytes).hexdigest(),
            "source_guard_expressions_evaluated_only": True,
            "full_runner_executed": False,
        },
        "native_rust_execution_by_reviewer": False,
        "qualification": "HOLD_NO_GO", "qualified": False,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
