#!/usr/bin/env python3
"""Finite counting and contract controls for the conditional sampling reader."""
from fractions import Fraction
import hashlib
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import w1_p3_sampling_audit as audit


def fraction(value):
    return Fraction(int(value["numerator"]), int(value["denominator"]))


class SamplingCounts(unittest.TestCase):
    def test_exact_preimage_and_variation_counts_match_finite_enumeration(self):
        for cardinality in range(2, 130):
            for bits in range(1, min(6, cardinality.bit_length())):
                size = 1 << bits
                if size > cardinality:
                    continue
                counts = [sum(value % size == index for value in range(cardinality))
                          for index in range(size)]
                report = audit.mask_distribution(cardinality, bits)
                self.assertEqual(fraction(report["minimum_atom"]), Fraction(min(counts), cardinality))
                self.assertEqual(fraction(report["maximum_atom"]), Fraction(max(counts), cardinality))
                variation = sum(abs(Fraction(count, cardinality) - Fraction(1, size)) for count in counts) / 2
                self.assertEqual(fraction(report["total_variation_from_uniform"]), variation)

    def test_raw_u64_masks_are_exactly_balanced_at_the_two_fixed_widths(self):
        for bits in (15, 16):
            report = audit.mask_distribution(1 << 64, bits)
            self.assertTrue(report["exactly_uniform"])
            self.assertEqual(fraction(report["total_variation_from_uniform"]), 0)
            self.assertEqual(fraction(report["maximum_atom"]), Fraction(1, 1 << bits))

    def test_goldilocks_mask_has_one_higher_mass_index(self):
        p = (1 << 64) - (1 << 32) + 1
        for bits in (15, 16):
            report = audit.mask_distribution(p, bits)
            self.assertEqual(report["higher_count_indices"], "1")
            self.assertFalse(report["exactly_uniform"])
            self.assertEqual(fraction(report["total_variation_from_uniform"]), Fraction((1 << bits) - 1, (1 << bits) * p))

    def test_duplicate_probability_matches_exhaustive_small_draws(self):
        from itertools import product
        for size, draws in ((2, 2), (3, 2), (3, 3), (4, 3)):
            sequences = list(product(range(size), repeat=draws))
            count = sum(len(set(sequence)) < draws for sequence in sequences)
            report = audit.with_replacement(size, draws)
            self.assertEqual(fraction(report["probability_at_least_one_duplicate"]), Fraction(count, len(sequences)))
            self.assertLessEqual(fraction(report["probability_at_least_one_duplicate"]), fraction(report["duplicate_probability_union_bound"]))

    def test_goldilocks_rejection_identity_is_distinct_from_query_masking(self):
        p = (1 << 64) - (1 << 32) + 1
        r = Fraction((1 << 64) - p, 1 << 64)
        # Sum of the geometric series for an individual accepted field value.
        self.assertEqual(Fraction(1, 1 << 64) / (1 - r), Fraction(1, p))
        self.assertEqual(Fraction(2, 1 - r), Fraction(2 * (1 << 64), p))
        self.assertNotEqual(Fraction(1, p), Fraction(1, 1 << 16))

    def test_invalid_cardinalities_widths_and_counts_are_rejected(self):
        for cardinality, bits in ((True, 4), (0, 4), (7, 0), (7, True), (3, 3), (5, 33)):
            with self.subTest(cardinality=cardinality, bits=bits), self.assertRaises(audit.SamplingAuditError):
                audit.mask_distribution(cardinality, bits)
        for size, draws in ((True, 1), (3, True), (3, 4), (3, 0)):
            with self.subTest(size=size, draws=draws), self.assertRaises(audit.SamplingAuditError):
                audit.with_replacement(size, draws)


class SamplingSourceContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_root = Path(__file__).resolve().parents[2]
        registry = cls.source_root / "config/pon/w1-stark-route-registry-v1.json"
        if not registry.is_file():
            raise AssertionError("exact repository source fixture is required")
        cls.registry = json.loads(registry.read_text())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        paths = [row["path"] for row in self.registry["source_inputs"]]
        paths += ["config/pon/w1-stark-route-registry-v1.json"]
        paths += [audit.VENDOR + "/" + name + "-0.8.0.crate" for name in audit.CHECKSUMS]
        for relative in paths:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.source_root / relative, destination)

    def test_actual_source_report_keeps_the_two_sampling_models_and_security_hold(self):
        report = audit.build_report(self.root)
        self.assertEqual(report["status"], "PINNED_ADAPTERS_AND_CONDITIONAL_COUNTS_REPRODUCED_SECURITY_HOLD")
        self.assertEqual(len(report["dependency_sources"]), 2)
        self.assertEqual([row["index_bits"] for row in report["components"]], [15, 16])
        for row in report["components"]:
            self.assertTrue(row["tagged_raw_byte_sampler"]["exactly_uniform"])
            self.assertFalse(row["legacy_field_mask_comparison_at_same_width"]["exactly_uniform"])
            self.assertFalse(row["tagged_iid_index_draw_accounting"]["draws_are_guaranteed_distinct"])
        self.assertIsNone(report["tagged_field_sampling"]["finite_worst_case_candidate_limit_in_adapter"])
        for key in ("concrete_hash_uniformity_proved", "fiat_shamir_knowledge_soundness_proved",
                    "complete_fri_or_pcs_soundness_proved", "native_sampler_executed_by_this_reader",
                    "production_qualified", "consensus_admission"):
            self.assertFalse(report["qualification"][key])
        self.assertIsNone(report["qualification"]["quantum_security_bits"])

    def test_missing_dependency_archive_is_rejected(self):
        (self.root / audit.VENDOR / "p3-challenger-0.8.0.crate").unlink()
        with self.assertRaises((ValueError, OSError)):
            audit.build_report(self.root)

    def test_mutated_complete_dependency_archive_is_rejected(self):
        for name in audit.CHECKSUMS:
            path = self.root / audit.VENDOR / (name + "-0.8.0.crate")
            original = path.read_bytes()
            path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            with self.subTest(package=name), self.assertRaises((ValueError, OSError)):
                audit.build_report(self.root)
            path.write_bytes(original)

    def test_lockfile_change_is_rejected_by_the_actual_pinned_route_reader(self):
        path = self.root / audit.P3 / "Cargo.lock"
        raw = path.read_bytes()
        changed = raw.replace(audit.CHECKSUMS["p3-challenger"].encode(), b"0" * 64)
        self.assertNotEqual(changed, raw)
        path.write_bytes(changed)
        with self.assertRaises((ValueError, OSError)):
            audit.build_report(self.root)

    def test_changed_archive_and_changed_lock_checksum_cannot_repin_together(self):
        lock = tomllib.loads((self.root / audit.P3 / "Cargo.lock").read_text())
        package = next(row for row in lock["package"] if row["name"] == "p3-challenger")
        path = self.root / audit.VENDOR / "p3-challenger-0.8.0.crate"
        raw = path.read_bytes()
        changed = raw[:-1] + bytes([raw[-1] ^ 1])
        self.assertNotEqual(raw, changed)
        path.write_bytes(changed)
        package["checksum"] = hashlib.sha256(changed).hexdigest()
        self.assertNotEqual(package["checksum"], audit.CHECKSUMS["p3-challenger"])
        with self.assertRaises(audit.SamplingAuditError):
            audit.archive_sources(self.root, "p3-challenger", ["src/hash_challenger.rs"], lock)

    def test_symlink_dependency_archive_is_rejected(self):
        relative = audit.VENDOR + "/p3-challenger-0.8.0.crate"
        path = self.root / relative
        path.unlink()
        path.symlink_to(self.source_root / relative)
        with self.assertRaises((ValueError, OSError)):
            audit.build_report(self.root)

    def test_missing_archive_cli_returns_nonzero_and_no_qualification(self):
        (self.root / audit.VENDOR / "p3-challenger-0.8.0.crate").unlink()
        child = subprocess.run([sys.executable, "-B", str(self.source_root / "scripts/w1_p3_sampling_audit.py"),
                                "--repository", str(self.root)], capture_output=True, text=True, check=False)
        self.assertEqual(child.returncode, 2)
        report = json.loads(child.stdout)
        self.assertEqual(report["status"], "INPUT_REJECTED")
        self.assertFalse(report["production_qualified"])
        self.assertFalse(report["consensus_admission"])


if __name__ == "__main__":
    unittest.main()
