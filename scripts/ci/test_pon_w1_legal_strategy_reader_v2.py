#!/usr/bin/env python3
"""V2 evidence-reader negatives; synthetic CPU/verdicts never qualify native work."""
import copy
from dataclasses import FrozenInstanceError
from itertools import zip_longest
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_w1_legal_strategy_reader_v1 as v1
import pon_w1_legal_strategy_reader_v2 as reader
from test_pon_w1_legal_strategy_reader_v1 import fixture, stamp


class LegalStrategyV2ReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = fixture(reader_api=reader)

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="legal-strategy-v2-reader-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def save(self, rows, name="synthetic.jsonl"):
        path = self.root / name
        with path.open("w") as output:
            for record in rows:
                output.write(json.dumps(record, separators=(",", ":")) + "\n")
        return path

    @staticmethod
    def first(rows, kind, **fields):
        return next(r for r in rows if r["kind"] == kind and all(r.get(k) == v for k, v in fields.items()))

    def test_v2_freezes_eight_samples_and_evidence_only_capacity(self):
        self.assertEqual((v1.SAMPLES, reader.SAMPLES), (2, 8))
        self.assertEqual(reader.ATTEMPT_BUDGET, 4096)
        self.assertEqual(reader.HORIZONS, (1, 8, 64))
        self.assertEqual(len(reader.CLASSES) * len(reader.TARGETS) * len(reader.HORIZONS), 30)
        self.assertEqual((v1.MAX_BYTES, reader.MAX_BYTES), (512 * 1024**2, 2 * 1024**3))
        self.assertEqual(reader.MAX_LINE, v1.MAX_LINE)
        self.assertEqual(reader.SELECTOR, "--legal-strategy-v2")
        with self.assertRaises(FrozenInstanceError):
            reader.PROFILE.samples = 2

    def test_all_eight_samples_pay_setup_search_and_all_verifiers(self):
        result = reader.analyze_shard(self.save(self.original))
        self.assertEqual(result["schema"], "pon-w1-legal-strategy-shard-readback-v2")
        self.assertEqual(result["record_counts"]["cohort"], 16)
        self.assertEqual(result["record_counts"]["verifier"], 128)
        self.assertEqual({x["sample"] for x in result["search_fingerprints"]}, set(range(8)))
        self.assertEqual(result["semantic_alerts"], [])
        for costs in result["strategy_costs"]:
            self.assertEqual(costs["actual_setup_calls"], 8)
            self.assertEqual(costs["actual_searches"], 8)
            self.assertEqual(costs["target_hits"], 8)
            self.assertEqual(costs["separate_product_mutation_total"], stamp(160))
        for flag in (*reader.FALSE_FLAGS, "complete_fixed_grid", "native_execution_authenticated", "w1_transcript_replayed"):
            self.assertIs(result[flag], False)

    def test_versions_reject_each_others_records_and_mixed_streams(self):
        old = self.save(fixture(), "v1.jsonl")
        new = self.save(self.original, "v2.jsonl")
        with self.assertRaisesRegex(ValueError, "explicit legal-strategy schema"):
            reader.analyze_shard(old)
        with self.assertRaisesRegex(ValueError, "explicit legal-strategy schema"):
            v1.analyze_shard(new)
        mixed = copy.deepcopy(self.original)
        self.first(mixed, "verifier")["schema"] = v1.SCHEMA
        with self.assertRaisesRegex(ValueError, "explicit legal-strategy schema"):
            reader.analyze_shard(self.save(mixed))

    def test_relabeling_eight_historical_domain_samples_does_not_create_v2(self):
        # Forge a syntactically V2 envelope around eight V1-domain fixtures.
        # This is deliberately not a mutable override of either actual reader.
        old_domain = SimpleNamespace(**{key: getattr(reader, key) for key in (
            "SCHEMA", "SELECTOR", "SAMPLES", "TARGETS", "ATTEMPT_BUDGET", "CLASSES", "HORIZONS",
            "STRATEGIES", "PATHS", "CASES", "DISPATCH_ARMS", "PRODUCER_SCOPE", "VERIFY_SCOPE",
            "MUTATION_SCOPE", "FALSE_FLAGS", "dispatch_probes", "product_last")}, challenge=v1.challenge)
        forged = fixture(reader_api=old_domain)
        with self.assertRaisesRegex(ValueError, "challenge binding mismatch"):
            reader.analyze_shard(self.save(forged))
        task, target = bytes([19]) * 32, bytes([127]) * 32
        contexts = {reader.challenge(task, target, sample, 3, 5) for sample in range(8)}
        self.assertEqual(len(contexts), 8)
        self.assertTrue(contexts.isdisjoint({v1.challenge(task, target, sample, 3, 5) for sample in range(8)}))

    def test_two_seven_nine_or_boolean_samples_are_not_eight(self):
        for count in (2, 7, 9, True):
            rows = copy.deepcopy(self.original)
            rows[0]["samples"] = count
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "fixed parameter|bounded nonnegative"):
                reader.analyze_shard(self.save(rows))

    def test_missing_or_repeated_last_sample_cannot_be_hidden_by_end_counts(self):
        for duplicate in (False, True):
            rows = copy.deepcopy(self.original)
            if duplicate:
                for row in rows:
                    if row.get("sample") == 7:
                        row["sample"] = 6
            else:
                rows = [row for row in rows if row.get("sample") != 7]
                for kind in ("cohort", "search", "candidate", "product_mutation", "verifier"):
                    rows[-1][kind + "_count"] = sum(row["kind"] == kind for row in rows)
            with self.subTest(duplicate=duplicate), self.assertRaisesRegex(ValueError, "cohort coverage/order|shard grid incomplete"):
                reader.analyze_shard(self.save(rows))

    def test_missing_misses_hidden_preparation_and_late_negative_are_retained(self):
        rows = copy.deepcopy(self.original)
        searched = next(r for r in rows if r["kind"] == "search" and len(r["attempts"]) > 1)
        searched["attempts"].pop(0)
        with self.assertRaisesRegex(ValueError, "nonconsecutive"):
            reader.analyze_shard(self.save(rows))
        for kind, field, value, message in (("cohort", "setup_calls", 0, "one actual setup"),
                ("search", "setup_calls", 1, "hidden setup"),
                ("cohort", "total", stamp(1), "exceed inclusive total"),
                ("product_mutation", "offset", 4, "canonical final product")):
            rows = copy.deepcopy(self.original)
            self.first(rows, kind, sample=7)[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                reader.analyze_shard(self.save(rows))
        for case, outcome in (("legal", "Transcript"), ("product-last", "Accepted")):
            rows = copy.deepcopy(self.original)
            self.first(rows, "verifier", sample=7, case=case)["outcome"] = outcome
            result = reader.analyze_shard(self.save(rows))
            self.assertEqual(result["semantic_alerts"][0]["sample"], 7)
            self.assertIsNone(result["generic_over_frozen_dispatch_cpu"])

    def test_eighth_sample_exhaustion_keeps_every_miss_and_no_winner(self):
        rows = fixture(exhausted=(7, 0), reader_api=reader)
        result = reader.analyze_shard(self.save(rows))
        for costs in result["strategy_costs"]:
            self.assertEqual(costs["exhausted_searches"], 1)
            self.assertEqual(costs["target_hits"], 7)
            self.assertGreaterEqual(costs["attempts"], 4096 + 7)
        self.first(rows, "search", sample=7)["attempts"].pop()
        with self.assertRaisesRegex(ValueError, "exhaustion/misses incomplete"):
            reader.analyze_shard(self.save(rows))

    def test_versioned_records_can_be_interleaved_without_global_switching(self):
        old_rows = fixture()
        old, new = v1.Records(), v1.Records(reader.PROFILE)
        for left, right in zip_longest(old_rows, self.original):
            if left is not None:
                old.add(left)
            if right is not None:
                new.add(right)
        self.assertTrue(old.ended and new.ended)
        self.assertEqual((old.counts["cohort"], new.counts["cohort"]), (4, 16))
        self.assertEqual(v1.SAMPLES, 2)
        self.assertEqual(v1.SCHEMA, "pon-w1-legal-strategy-v1")
        self.assertEqual(reader.SAMPLES, 8)

    def test_framing_duplicate_fields_truncation_and_qualification_still_fail(self):
        path = self.save(self.original)
        raw = path.read_bytes()
        for broken, message in ((raw[:-1], "bounded complete"),
                (raw.replace(b'"schema":', b'"schema":"duplicate","schema":', 1), "duplicate JSON key")):
            path.write_bytes(broken)
            with self.assertRaisesRegex(ValueError, message):
                reader.analyze_shard(path)
        for flag in reader.FALSE_FLAGS:
            rows = copy.deepcopy(self.original)
            rows[0][flag] = True
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, "qualification flag"):
                reader.analyze_shard(self.save(rows))

    def test_actual_thirty_shard_grid_has_eight_new_samples_and_strict_prefixes(self):
        # Complete synthetic byte fixtures, including all 1/8/64 horizons. These
        # invented times and verdicts are reader controls, not native evidence.
        paths = []
        for name in reader.CLASSES:
            for target in range(len(reader.TARGETS)):
                for horizon in reader.HORIZONS:
                    paths.append(self.save(fixture(name, target, horizon, reader_api=reader),
                                           f"{name}-{target}-{horizon}.jsonl"))
        result = reader.analyze(paths)
        self.assertEqual(result["schema"], "pon-w1-legal-strategy-readback-v2")
        self.assertEqual(len(result["shards"]), 30)
        self.assertEqual(result["observed_samples_per_class"], 8)
        self.assertEqual(result["required_policy_samples_per_class"], 8)
        self.assertTrue(result["policy_sample_count_satisfied"])
        self.assertEqual(result["unique_search_streams"], 5 * 2 * 8 * 64)
        self.assertFalse(result["all_policy_materials_or_targets_covered"])
        self.assertFalse(result["work_profile_qualified"])
        with self.assertRaisesRegex(ValueError, "complete fixed shard grid"):
            reader.analyze(paths[:-1])
        with self.assertRaisesRegex(ValueError, "duplicate/unknown shard"):
            reader.analyze([paths[0], paths[0], *paths[2:]])
        altered = self.save(fixture(reader.CLASSES[0], 0, 8, salt=1, reader_api=reader), "changed-prefix.jsonl")
        with self.assertRaisesRegex(ValueError, "cross-horizon matched search prefix"):
            reader.analyze([paths[0], altered, *paths[2:]])


if __name__ == "__main__":
    unittest.main()
