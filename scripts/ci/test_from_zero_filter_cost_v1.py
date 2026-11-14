#!/usr/bin/env python3
"""Controls for the actual native stream; absent native input is an explicit skip."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

import run_from_zero_filter_cost_v1 as reader


class InputBoundaryTests(unittest.TestCase):
    def test_duplicate_and_inexact_json_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.jsonl"
            for raw in (b'{"a":1,"a":2}\n', b'{"n":NaN}\n', b'{"n":0.0}\n'):
                with self.subTest(raw=raw):
                    path.write_bytes(raw)
                    with self.assertRaises(ValueError):
                        reader.load_records(path)

    def test_missing_directory_symlink_and_fifo_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "actual.jsonl"
            regular.write_text('{}\n')
            linked = root / "linked.jsonl"
            linked.symlink_to(regular)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            for path in (root / "missing", root, linked, fifo):
                with self.subTest(path=path):
                    with self.assertRaises(ValueError):
                        reader.load_records(path)

    def test_target_probabilities_are_exact_integer_relations(self):
        for bits in reader.BITS:
            threshold = int.from_bytes(reader.target(bits), 'big')
            self.assertEqual((threshold + 1) * (1 << bits), 1 << 256)

    def test_empty_and_truncated_stream_cannot_pass(self):
        for rows in ([], [{}], [{"schema": reader.SCHEMA, "kind": "failure"}]):
            with self.subTest(rows=rows):
                with self.assertRaises(ValueError):
                    reader.analyze_rows(rows)


class NativeTamperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get("TRNM_FROM_ZERO_FILTER_NATIVE_LOG")
        if not path:
            raise unittest.SkipTest("TRNM_FROM_ZERO_FILTER_NATIVE_LOG actual execution is required")
        cls.original, cls.digest = reader.load_records(Path(path))
        cls.checked = reader.analyze_rows(cls.original)

    def setUp(self):
        self.rows = copy.deepcopy(self.original)

    def row(self, kind, **key):
        return next(row for row in self.rows if row["kind"] == kind and
                    all(row.get("key", {}).get(name) == value for name, value in key.items()))

    def reject(self):
        with self.assertRaises(ValueError):
            reader.analyze_rows(self.rows)

    def test_complete_actual_grid_has_no_security_promotion(self):
        self.assertEqual(self.checked["samples"], 96)
        self.assertEqual(self.checked["stage_observations"], 576)
        for flag in reader.FALSE_FLAGS:
            self.assertIs(self.checked[flag], False)

    def test_dropping_a_loser_cannot_become_a_cheaper_success(self):
        construction = next(row for row in self.rows if row["kind"] == "construction"
                            and len(row["trials"]) > 1)
        del construction["trials"][0]
        self.reject()

    def test_later_hit_is_not_the_declared_first_hit(self):
        row = self.row("construction", arm="from-zero")
        row["trials"].append(copy.deepcopy(row["trials"][-1]))
        self.reject()

    def test_fake_proof_cannot_borrow_the_independent_legal_product(self):
        row = self.row("construction", arm="from-zero", **{"class": "full-rank-field"})
        raw = bytearray.fromhex(row["winner"]["proof_hex"])
        raw[4 + 8 * reader.CELLS] ^= 1
        row["winner"]["proof_hex"] = raw.hex()
        row["winner"]["proof_sha256"] = hashlib.sha256(raw).hexdigest()
        self.reject()

    def test_changed_challenge_cannot_reuse_a_winner(self):
        row = self.row("construction", arm="from-zero")
        row["winner"]["challenge"] = "00" * 32
        self.reject()

    def test_target_and_sample_identity_are_frozen(self):
        for field, value in (("bits", 2), ("sample", True), ("arm", "unknown")):
            with self.subTest(field=field):
                self.rows = copy.deepcopy(self.original)
                self.row("construction")["key"][field] = value
                self.reject()

    def test_missing_precheck_or_duplicate_verifier_is_refused(self):
        index = next(i for i, row in enumerate(self.rows) if row["kind"] == "verification")
        del self.rows[index]
        self.reject()
        self.rows = copy.deepcopy(self.original)
        self.rows.insert(index, copy.deepcopy(self.rows[index]))
        self.reject()

    def test_cache_hit_must_report_zero_transcript_tiles(self):
        row = next(row for row in self.rows if row["kind"] == "verification"
                   and row["path"] == "arithmetic-hot")
        row["transcript_tiles"] = 512
        self.reject()

    def test_cold_cache_cannot_be_relabelled_as_free_reuse(self):
        row = next(row for row in self.rows if row["kind"] == "verification"
                   and row["path"] == "arithmetic-cold")
        row["transcript_tiles"] = 0
        self.reject()

    def test_from_zero_precheck_success_is_not_accepted_work(self):
        row = next(row for row in self.rows if row["kind"] == "verification"
                   and row["path"] == "raw-first" and row["key"]["arm"] == "from-zero")
        row["outcome"] = "Accepted"
        self.reject()

    def test_unknown_negative_boolean_and_float_costs_are_refused(self):
        for value in (None, -1, True, 0.0):
            with self.subTest(value=value):
                self.rows = copy.deepcopy(self.original)
                self.row("construction")["search"]["cpu_ns"] = value
                self.reject()

    def test_fake_failure_or_missing_terminal_is_not_a_complete_campaign(self):
        self.rows.pop()
        self.reject()
        self.rows = copy.deepcopy(self.original)
        self.rows[-1]["all_expected_outcomes"] = False
        self.reject()

    def test_header_or_footer_cannot_grant_production(self):
        for index in (0, -1):
            with self.subTest(index=index):
                self.rows = copy.deepcopy(self.original)
                self.rows[index]["production_activation"] = True
                self.reject()

    def test_reordered_arms_cannot_change_selected_samples(self):
        row = self.row("sample-start")
        row["key"]["arm"] = "legal"
        self.reject()

    def test_extra_or_unrecognized_fields_are_refused(self):
        self.row("construction")["unreported_trial_discount"] = 1
        self.reject()

    def test_disjoint_component_costs_cannot_exceed_the_whole_campaign(self):
        for axis in ("cpu_ns", "wall_ns"):
            with self.subTest(axis=axis):
                self.rows = copy.deepcopy(self.original)
                self.row("construction")["search"][axis] = self.rows[-1]["total_before_terminal"][axis]
                self.reject()


if __name__ == "__main__":
    unittest.main()
