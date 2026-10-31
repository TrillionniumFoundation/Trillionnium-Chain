#!/usr/bin/env python3
"""Reproduce the metadata-reader RED/GREEN and retained real-receipt binding.

No native verifier or prover is run. Forged records are adversarial metadata,
not fresh receiver observations. Output must be a new directory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parents[2]
BACKEND = "trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0"
BASE = "c16507147b65285ea94dead22d3b93c5db7295af"
OLD_READER_SHA256 = "1e65011b0d14173da05280ec769ae1850545a51bda4277fd71492fc4af8351ab"
RECEIPT_SHA256 = "0a5336a797c51829ed25d4ec2f1a03f4f56fda4c737a230b493d4abbe96f0ec8"
INPUT_SHA256 = "4babd290b10f7a68be27c2adf3b97448bb7bef04dba8bcb97f914acf4ac69020"
REGRESSIONS = (
    "test_middle_seal_cannot_be_labelled_last",
    "test_other_last_seal_word_cannot_be_labelled_last",
    "test_nonparameter_digest_cannot_be_labelled_verifier_parameters",
    "test_partial_parameter_zeroing_cannot_be_labelled_whole_digest",
    "test_declared_shape_must_match_actual_receipt",
    "test_malformed_original_receipt_cannot_gain_bound_layout",
    "test_receipt_journal_must_match_input",
)
RECORD_SHA256 = {
    "first-seal-tamper": "a011f4bc6aa63f76b695a6d3beb46662776fa16f848a72f46454274d5f310bf7",
    "last-seal-tamper": "d832d9b9a81cfe5cfffc554f788a97fba5919d3d851f2f5db14ebb3a1f65856c",
    "seal-length-allocation-bomb": "a38fe2313a9d6db11eaab4b4d357cf2142c8dd7f0fbf63b429fc1c589dd3190b",
    "trailing-receipt-bytes": "cb0b2e9e2d9b3122160b0bf7f7f3aaccdb87998826f8cd41efd1ac996d1c585a",
    "truncated-receipt": "c7b91b054b58c592e1c93812cb74c36d963382ded0eec1a95287ec0b6b1f6f06",
    "valid": "a7a73344892b2261dc8fdf164c8de84a877811b8742344a8a4d2ee3a5fa6dd9b",
    "wrong-statement-miner": "a2768c8f9be5f748a08c92b4907d45efde106d21d4c1b184ffd1980f6a596211",
    "wrong-verifier-parameters": "48cd156766ba6e60a3ee891f800514890db71444e43f2528345d461d2e79cb7f",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--records", type=Path, default=ROOT /
                        "evidence/pon-pure-security-20261030-rebuild/complete-w1/actual-cases")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(ROOT / BACKEND))
    import check_audit_one as fixed
    import test_check_audit_one as controls
    old_bytes = subprocess.run(["git", "show", BASE + ":" + BACKEND + "/check_audit_one.py"],
                               cwd=ROOT, check=True, capture_output=True, timeout=10).stdout
    if sha(old_bytes) != OLD_READER_SHA256:
        raise ValueError("baseline reader source hash differs")
    old = types.ModuleType("baseline_checker")
    old.__file__ = str(ROOT / BACKEND / "check_audit_one.py")
    exec(compile(old_bytes, old.__file__, "exec"), vars(old))
    controls.reader = old
    with (args.out / "red.stderr.log").open("x") as output:
        red = unittest.TextTestRunner(stream=output, verbosity=2).run(
            unittest.TestSuite(controls.ReaderControls(name) for name in REGRESSIONS))
    failed = {test.id().rsplit(".", 1)[-1] for test, _ in red.failures}
    if red.errors or failed != set(REGRESSIONS) or red.testsRun != len(REGRESSIONS):
        raise ValueError("baseline no longer reproduces exactly the seven rejected assertions")
    controls.reader = fixed
    with (args.out / "green.stderr.log").open("x") as output:
        green = unittest.TextTestRunner(stream=output, verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromModule(controls))
    if not green.wasSuccessful():
        raise ValueError("fixed reader control suite failed")
    receipt = fixed.bounded_raw(args.fixture / "receipt.bin", fixed.CAPS["receipt_bytes"])
    input_bytes = fixed.bounded_raw(args.fixture / "input.bin", fixed.CAPS["input_bytes"])
    if sha(receipt) != RECEIPT_SHA256 or sha(input_bytes) != INPUT_SHA256:
        raise ValueError("historical fixture bytes differ")
    cases = []
    for name, expected_sha in sorted(RECORD_SHA256.items()):
        raw = fixed.bounded_raw(args.records / ("case-" + name + ".stdout.log"), 512 * 1024)
        if sha(raw) != expected_sha:
            raise ValueError("original c165 case record differs: " + name)
        record = fixed.decode_json(raw)
        baseline = old.validate(record, input_bytes, receipt)
        result = fixed.validate(record, input_bytes, receipt)
        save(args.out / ("case-" + name + ".binding-v2.json"), result)
        cases.append({"case": record["case"], "original_record_sha256": sha(raw),
                      "baseline_pass": baseline["metadata_and_byte_bindings_pass"],
                      "fixed_pass": result["metadata_and_byte_bindings_pass"]})
    forged = fixed.decode_json((args.records / "case-last-seal-tamper.stdout.log").read_bytes())
    changed = bytearray(receipt)
    changed[424] ^= 1
    forged["receipt_mutation"]["byte_changes"] = [
        {"offset": 424, "before": receipt[424], "after": changed[424]}]
    forged["case_receipt"]["sha256"] = sha(changed)
    save(args.out / "forged-early-as-last.case.json", forged)
    if not old.validate(forged, input_bytes, receipt)["metadata_and_byte_bindings_pass"]:
        raise ValueError("baseline unexpectedly refused the adversarial record")
    try:
        fixed.validate(forged, input_bytes, receipt)
    except ValueError as error:
        refusal = str(error)
    else:
        raise ValueError("fixed reader accepted the adversarial record")
    paths = [BACKEND + "/" + name for name in (
        "check_audit_one.py", "receipt_layout.py", "test_check_audit_one.py", "README.md")]
    paths.append(str(Path(__file__).resolve().relative_to(ROOT)))
    sources = []
    for name in paths:
        raw = (ROOT / name).read_bytes()
        sources.append({"path": name, "bytes": len(raw), "sha256": sha(raw)})
    report = {
        "schema": "pon-w1-receiver-layout-recheck-v1", "original_record_source": BASE,
        "baseline_reader_sha256": sha(old_bytes), "changed_source_inputs": sources,
        "red_expected_failures": sorted(failed), "red_errors": len(red.errors),
        "green_tests_run": green.testsRun, "green_pass": green.wasSuccessful(),
        "input_sha256": sha(input_bytes), "receipt_sha256": sha(receipt), "receipt_bytes": len(receipt),
        "layout": fixed.parse_receipt_layout(receipt, fixed.CAPS), "historical_cases": cases,
        "forged_early_as_last": {"actual_mutation_offset": 424, "baseline_reader_accepted": True,
                                 "fixed_reader_accepted": False, "fixed_reader_reason": refusal,
                                 "adversarial_metadata_only": True,
                                 "host_executed_on_forged_input": False},
        "new_proof_generated": False, "proof_reverified_by_reader": False,
        "timings_independently_remeasured": False, "consensus_authority": False,
    }
    save(args.out / "actual-layout-recheck.json", report)
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
