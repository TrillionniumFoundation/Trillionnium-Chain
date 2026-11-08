#!/usr/bin/env python3
"""Extend the exact retained 32-command validation without replacing any gate.

Run only on a clean committed source with the original pinned Rust/OpenSSL
environment. The original runner owns execution, timeouts, raw logs, source and
provider checks, and failed-result retention. The previous five additional checks
are retained, followed by four exact owner tests and their individual transcript
readbacks before the final raw-source guard. --list-commands executes no validation.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "evidence/pq-authority-preflight-20261108-9d315/authority-final-validation-runner.py"
BASE_SHA256 = "d81437a1cef461666b9103cc3f9e8f8ab0c67a90903b5802f582d2c52cd82710"
BOUNDARY_TEST = (
    "ingress::pq_network::tests::"
    "pq_account_profile_rejects_classical_listeners_with_inconsistent_backend_before_effects"
)
OWNER_TESTS = (
    ("node-pq-task-owner-rejection",
     "store::pq_owner_rejection_tests::"
     "pq_account_rejects_classical_task_owner_before_any_durable_effect"),
    ("node-pq-mining-owner-rejection",
     "store::pq_owner_rejection_tests::"
     "pq_account_rejects_classical_mining_owner_before_any_durable_effect"),
    ("node-classical-task-owner-positive",
     "store::pq_owner_rejection_tests::classical_task_owner_with_signed_catalog_still_opens"),
    ("node-classical-mining-owner-positive",
     "store::pq_owner_rejection_tests::classical_mining_owner_with_signed_catalog_still_opens"),
)
OWNER_TEST_READERS = {"owner-exact:" + label: name for label, name in OWNER_TESTS}
OWNER_READBACK_READERS = {"owner-readback:" + label: name for label, name in OWNER_TESTS}


def load_base():
    if hashlib.sha256(BASE_PATH.read_bytes()).hexdigest() != BASE_SHA256:
        raise ValueError("the inherited 32-command runner differs from its exact reviewed bytes")
    spec = importlib.util.spec_from_file_location("authority_validation_base", BASE_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load the inherited validation runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load_base()
BASE_COMMANDS = BASE.command_list
BASE_VALIDATE = BASE.validate_output


def command_list(expected_head: str, out: Path) -> list[tuple[str, list[str], str]]:
    original = BASE_COMMANDS(expected_head, out)
    if len(original) != 32 or original[-1][0] != "source-guard-after":
        raise ValueError("the exact inherited command inventory changed")
    locked = ["--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml"]
    node = [BASE.CARGO, "test", *locked, "-p", "trnm-pon-node", "--lib", "--all-features"]
    py = [BASE.PYTHON, "-B"]
    extra = [
        ("pq-authority-trace", py + ["scripts/ci/pq_authority_trace.py", "--summary-only"],
         "authority-trace"),
        ("pq-authority-trace-negatives", py + ["scripts/ci/test_pq_authority_trace.py", "-v"],
         "trace-unittest"),
        ("node-pq-network", node + ["ingress::pq_network::", "--", "--show-output",
         "--test-threads=1"], "pq-network-tests"),
        ("node-pq-profile-boundary", node + [BOUNDARY_TEST, "--", "--exact",
         "--show-output", "--test-threads=1"], "pq-boundary-test"),
        ("node-pq-profile-boundary-readback", py + ["scripts/ci/check_required_native_test.py",
         str(out / "node-pq-profile-boundary.stdout.log"), "--test", BOUNDARY_TEST],
         "native-test-readback"),
    ]
    owner_commands = []
    for label, name in OWNER_TESTS:
        owner_commands.extend([
            (label, node + [name, "--", "--exact", "--show-output", "--test-threads=1"],
             "owner-exact:" + label),
            (label + "-readback", py + ["scripts/ci/check_required_native_test.py",
             str(out / (label + ".stdout.log")), "--test", name], "owner-readback:" + label),
        ])
    prior = [*original[:-1], *extra, original[-1]]
    result = [*original[:-1], *extra, *owner_commands, original[-1]]
    labels = [item[0] for item in result]
    inherited_labels = {item[0] for item in original}
    if len(labels) != len(set(labels)) or [
        item for item in result if item[0] in inherited_labels
    ] != original:
        raise ValueError("the extension changed an inherited command or its ordering")
    prior_labels = {item[0] for item in prior}
    if (len(prior) != 37 or len(owner_commands) != 8 or len(result) != 45
            or [item for item in result if item[0] in prior_labels] != prior):
        raise ValueError("the owner checks changed the prior 37 commands or final 45-command inventory")
    return result


def validate_output(kind: str, stdout: str, stderr: str, repo: Path) -> dict:
    if kind in OWNER_TEST_READERS:
        expected = OWNER_TEST_READERS[kind]
        value = BASE_VALIDATE("rust-tests", stdout, stderr, repo)
        if (re.findall(r"^running (\d+) tests?$", stdout, re.M) != ["1"]
                or BASE.LIBTEST_NAME.findall(stdout) != [(expected, "ok")]
                or value["passed_names"] != [expected]
                or len(value["summaries"]) != 1
                or value["summaries"][0][:4] != (1, 0, 0, 0)
                or value["ignored_names"]):
            raise ValueError("the exact owner control must pass once with zero failed, ignored or measured tests")
        return value
    if kind in OWNER_READBACK_READERS:
        value = json.loads(stdout)
        if (not isinstance(value, dict)
                or value.get("result") != "PASS"
                or value.get("test") != OWNER_READBACK_READERS[kind]
                or type(value.get("executed_tests")) is not int
                or value.get("executed_tests") != 1
                or value.get("scope") != "named-libtest-execution-only"):
            raise ValueError("the owner transcript readback does not match its one exact test")
        return value
    if kind == "trace-unittest":
        value = BASE_VALIDATE("unittest", stdout, stderr, repo)
        combined = stdout + "\n" + stderr
        outcomes = re.findall(r"^(?:OK(?: \(.*\))?|FAILED(?: \(.*\))?)$", combined, re.M)
        refused = re.search(
            r"\.\.\. (?:skipped(?: .*)?|expected failure|unexpected success)$", combined, re.M
        )
        if value["reported_test_counts"] != [30] or outcomes != ["OK"] or refused:
            raise ValueError("trace suite must execute exactly 30 tests with no skipped or exceptional outcomes")
        return value
    if kind in ("pq-network-tests", "pq-boundary-test"):
        value = BASE_VALIDATE("rust-tests", stdout, stderr, repo)
        names = value["passed_names"]
        if kind == "pq-network-tests":
            all_names = BASE.LIBTEST_NAME.findall(stdout)
            if (len(value["summaries"]) != 1
                    or value["summaries"][0][0] != len(names)
                    or len(names) != len(set(names))
                    or names.count(BOUNDARY_TEST) != 1
                    or any(not name.startswith("ingress::pq_network::") for name, _ in all_names)):
                raise ValueError("the full PQ network module or new boundary control was not executed")
        elif (names != [BOUNDARY_TEST] or len(value["summaries"]) != 1
              or value["summaries"][0][:4] != (1, 0, 0, 0)
              or value["ignored_names"]):
            raise ValueError("the exact new boundary control did not pass once without ignored tests")
        return value
    if kind == "authority-trace":
        value = BASE_VALIDATE("authority-hold", stdout, stderr, repo)
        if (value.get("source_trace_integrity_passed") is not True
                or value.get("whole_chain_pq_qualified") is not False
                or value.get("all_authority_paths_traced") is not False
                or value.get("completed_authority_traces") != 0
                or value.get("runtime_tests_executed") != 0):
            raise ValueError("source trace integrity cannot promote runtime authority qualification")
        return value
    if kind == "native-test-readback":
        value = json.loads(stdout)
        if (value.get("result") != "PASS" or value.get("test") != BOUNDARY_TEST
                or value.get("executed_tests") != 1):
            raise ValueError("exact native boundary transcript was not accepted by the existing reader")
        return value
    return BASE_VALIDATE(kind, stdout, stderr, repo)


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--expected-head")
    parser.add_argument("--list-commands", action="store_true")
    args, _ = parser.parse_known_args()
    BASE.command_list = command_list
    BASE.validate_output = validate_output
    result = BASE.main()
    if args.list_commands:
        return result
    out = args.out
    if out is None or args.expected_head is None:
        raise ValueError("the base runner did not receive the expected output/source identity")
    retained = out / "authority-effects-validation-runner.py"
    shutil.copyfile(Path(__file__).resolve(), retained)
    inherited = BASE_COMMANDS(args.expected_head, out)
    extended = command_list(args.expected_head, out)
    contract = {
        "schema": "trnm-pq-authority-validation-extension-v1",
        "inherited_runner": BASE.file_record(BASE_PATH),
        "inherited_runner_sha256_required": BASE_SHA256,
        "extension_runner": BASE.file_record(retained),
        "inherited_command_count": len(inherited),
        "prior_extension_command_count": 37,
        "prior_extension_commands_preserved_exactly": True,
        "extended_command_count": len(extended),
        "inherited_commands_preserved_exactly": True,
        "inherited_commands": [
            {"label": label, "argv": argv, "reader": kind} for label, argv, kind in inherited
        ],
        "required_boundary_test": BOUNDARY_TEST,
        "required_owner_tests": [name for _, name in OWNER_TESTS],
        "whole_chain_pq_qualified": False,
        "production_activation": False,
    }
    BASE.save(out / "extension-contract.json", contract)
    print(json.dumps({"extension_contract": str(out / "extension-contract.json"),
                      "inherited_commands": len(inherited), "total_commands": len(extended)}),
          flush=True)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
