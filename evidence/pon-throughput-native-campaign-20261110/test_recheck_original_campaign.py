#!/usr/bin/env python3
"""Synthetic adversarial controls only; no synthetic result is native evidence."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile

import recheck_original_campaign as reader

HEAD = "1" * 40
TREE = "2" * 40
TX = "c6" * 32
TIP = "a3" * 32
BLOCK = "b4" * 32


def encoding(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode()


def positive():
    return {"round": 0, "started_ns": 10, "ended_ns": 20,
            "confirmed_inside_pressure_window": True,
            "transaction": TX, "tip": TIP, "included_block": BLOCK,
            "observation": {"confirmed": True, "reorged": False,
                            "finalized": False, "execution_authority": False,
                            "depth": 6, "included_height": 3,
                            "observed_height": 9, "transaction": TX,
                            "included_block": BLOCK, "observed_tip": TIP,
                            "work_delta": f"{12:0128x}",
                            "required_work_delta": f"{12:0128x}"}}


def phase(name):
    return {"mode": name, "state_backend": "authenticated-v1", "duration_seconds": 30,
            "attacker_processes_requested": 0 if name == "baseline" else 24,
            "attacker_processes_ready": 0 if name == "baseline" else 24,
            "confirmations": ([positive(), {"round": 1, "started_ns": 10,
                            "ended_ns": reader.WINDOW_NS,
                            "confirmed_inside_pressure_window": False}]
                            if name == "baseline" else
                            [{"round": 0, "started_ns": 10,
                              "ended_ns": reader.WINDOW_NS + 1,
                              "confirmed_inside_pressure_window": False}]),
            "service_outcome": {"Ok": {"accepted_connections": 1,
                                        "mutation_cpu_charged_ns": 4}},
            "finite_phase_criteria_met": False,
            "receiver_client_state_equal": False,
            "genuine_budget_depletion_observed": False,
            "verifier_errors": ["PUBLIC_REQUEST_DEADLINE"]}


def sample():
    reports = {i: {"schema": "native-public-v3-separate-process-campaign-v2",
                   "state_backend": "authenticated-v1",
                   "phases": [phase(m) for m in reader.MODES]} for i in (1, 2, 3)}
    result = {"schema": "pon-original-native-campaign-ci-v1",
              "expected_head": HEAD, "expected_tree": TREE,
              "source_after": {"tested_commit": HEAD, "tested_tree": TREE},
              "planned_complete_runs": 3, "complete_success": False,
              "original_inputs": {"attacker_processes": [0, 24, 24],
                                  "phase_seconds": 30,
                                  "modes": list(reader.MODES),
                                  "seed_blocks": 4, "seed_transfers": 1024,
                                  "business_blocks": 21},
              "attempts": [{"number": i, "report_directory": f"run-{i}-raw",
                            "report_sha256": hashlib.sha256(encoding(reports[i])).hexdigest()}
                           for i in (1, 2, 3)]}
    return result, reports


def bundle(path, result, reports, *, extras=None, mutate=None, double=None,
           preserve_receipts=False):
    if not preserve_receipts:
        for attempt in result["attempts"]:
            attempt["report_sha256"] = hashlib.sha256(
                encoding(reports[attempt["number"]])).hexdigest()
    records = {"results.json": encoding(result)}
    records.update({f"run-{i}-raw/report.json": encoding(reports[i]) for i in (1, 2, 3)})
    manifest = {"scope": "SYNTHETIC CONTROL NOT NATIVE EVIDENCE",
                "files": [{"path": name, "bytes": len(data),
                           "sha256": hashlib.sha256(data).hexdigest()}
                          for name, data in records.items()]}
    if mutate is not None:
        mutate(records, manifest)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for name, data in records.items():
                zip_file.writestr(name, data)
            zip_file.writestr("artifact-files.json", encoding(manifest))
            for name, data in (extras or {}).items():
                zip_file.writestr(name, data)
            if double is not None:
                zip_file.writestr(double, records[double])
    return reader.bytes_sha(path)


class OriginalNativeZipControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "original.zip"
        self.result, self.reports = sample()

    def read(self, mutate=None, extras=None, double=None, preserve_receipts=False):
        sha = bundle(self.path, self.result, self.reports,
                     extras=extras, mutate=mutate, double=double,
                     preserve_receipts=preserve_receipts)
        return reader.recheck(self.path, sha, HEAD, TREE)

    def test_full_original_denominator_and_repeated_id(self):
        value = self.read()
        self.assertEqual(value["planned_confirmation_rounds"], 27)
        self.assertEqual(value["reported_positive_native_rounds"], 3)
        self.assertEqual(value["full_window_not_timely_rounds"], 9)
        self.assertEqual(value["unobserved_round_slots"], 15)
        self.assertEqual(value["distinct_reported_positive_transaction_hashes"], 1)
        self.assertEqual(value["archive"]["listed_member_count"], 4)
        self.assertEqual(value["qualification"], "HOLD_NO_GO")
        self.assertIsNone(value["confirmed_unique_business_tps"])
        self.assertIsNone(value["actual_4s_host_gate"])

    def test_unlisted_member_refused(self):
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.read(extras={"extra.json": b"{}"})

    def test_duplicate_archive_path_refused(self):
        with self.assertRaisesRegex(ValueError, "duplicate ZIP member"):
            self.read(double="results.json")

    def test_member_sha_mutation_refused_even_when_outer_zip_sha_matches(self):
        def mut(records, manifest):
            records["results.json"] += b" "
        with self.assertRaisesRegex(ValueError, "length mismatch"):
            self.read(mutate=mut)

    def test_invalid_external_zip_digest_refused(self):
        sha = bundle(self.path, self.result, self.reports)
        with self.assertRaisesRegex(ValueError, "ZIP SHA256 mismatch"):
            reader.recheck(self.path, "0" * 64, HEAD, TREE)
        self.assertNotEqual(sha, "0" * 64)

    def test_workload_cannot_shift_from_0_24_24(self):
        self.result["original_inputs"]["attacker_processes"] = [0, 24, 23]
        with self.assertRaisesRegex(ValueError, "workload"):
            self.read()

    def test_duplicate_and_absent_rounds_refused(self):
        b = self.reports[1]["phases"][0]["confirmations"]
        b.append(copy.deepcopy(b[0]))
        with self.assertRaisesRegex(ValueError, "duplicate/unplanned"):
            self.read()

    def test_out_of_window_positive_refused(self):
        self.reports[2]["phases"][0]["confirmations"][0]["ended_ns"] = reader.WINDOW_NS
        with self.assertRaisesRegex(ValueError, "strict window"):
            self.read()

    def test_forged_positive_depth_and_work_refused(self):
        native = self.reports[3]["phases"][0]["confirmations"][0]["observation"]
        native["work_delta"] = "0" * 128
        with self.assertRaisesRegex(ValueError, "descendant work"):
            self.read()

    def test_claim_cannot_change_transaction_identity(self):
        native = self.reports[1]["phases"][0]["confirmations"][0]["observation"]
        native["transaction"] = "f0" * 32
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self.read()

    def test_original_report_receipt_sha_enforced(self):
        self.result["attempts"][0]["report_sha256"] = "1" * 64
        with self.assertRaisesRegex(ValueError, "report SHA256"):
            self.read(preserve_receipts=True)

    def test_source_head_and_tree_mismatch_refused(self):
        with self.assertRaisesRegex(ValueError, "source identity mismatch"):
            reader.inspect(self.result, self.reports, "3" * 40, TREE, {})

    def test_early_negative_retains_unknown_not_zero(self):
        self.reports[1]["phases"][1]["confirmations"][0]["ended_ns"] = 20
        value = self.read()
        self.assertEqual(value["full_window_not_timely_rounds"], 8)
        self.assertEqual(value["incomplete_or_conflicting_rounds"], 1)

    def test_boolean_cannot_be_u64_or_time(self):
        self.reports[1]["phases"][0]["confirmations"][0]["ended_ns"] = True
        with self.assertRaisesRegex(ValueError, "integer u64"):
            self.read()


if __name__ == "__main__":
    unittest.main()
