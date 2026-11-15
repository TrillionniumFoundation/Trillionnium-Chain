"""Adversarial scope/source and normalized-subset controls for the MU1 audit."""
import copy
from fractions import Fraction
from itertools import combinations
import json
from pathlib import Path
import tempfile
import unittest

import fixed_probability_contract as contract


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.value = contract.load_contract(contract.DEFAULT_CONTRACT)

    def reject(self, value, reason):
        with self.assertRaisesRegex(contract.ContractError, "^" + reason + "$"):
            contract.audit_contract(value)

    def test_actual_mu1_sources_bind_without_promoting_the_cost_gate(self):
        result = contract.audit_contract(self.value)
        self.assertEqual(result["binding_validation"], "PASS")
        self.assertEqual(result["source_binding_scope"], "four_relation_source_files_only")
        self.assertFalse(result["full_execution_identity_verified"])
        self.assertEqual(result["qualification"], "HOLD_NO_GO")
        self.assertEqual(len(result["unknown_cost_points"]), 16)
        self.assertFalse(result["production_activation"])

    def test_scope_cannot_change_probability_credit_units_or_context_fields(self):
        for key, changed in (("target_hex", "ff" * 32), ("research_credit_per_unit", 17),
                             ("maximum_units", 9), ("context_fields", ["nonce"]),
                             ("inclusive_target", 1), ("native_consensus_credit", True)):
            with self.subTest(key=key):
                value = copy.deepcopy(self.value)
                value["relation"][key] = changed
                self.reject(value, "RELATION_BINDING")

    def test_no_unknown_cost_is_replaced_by_zero_or_observed_time(self):
        for lower in (0, False, {"numerator": 1, "denominator": 1}):
            value = copy.deepcopy(self.value)
            value["cost_envelopes"]["quantum"][7]["lower"] = lower
            self.reject(value, "UNSUPPORTED_COST_CERTIFICATE")

    def test_missing_scale_class_or_duplicate_scale_is_rejected(self):
        value = copy.deepcopy(self.value)
        value["cost_envelopes"]["quantum"].pop()
        self.reject(value, "COST_GRID")
        value = copy.deepcopy(self.value)
        value["cost_envelopes"]["quantum"][1]["units"] = 1
        self.reject(value, "COST_UNITS")
        value = copy.deepcopy(self.value)
        del value["cost_envelopes"]["classical"]
        self.reject(value, "COST_CLASSES")

    def test_lifecycle_reset_and_omitted_strategies_are_rejected(self):
        value = copy.deepcopy(self.value)
        value["accounting"]["epoch_restart_or_profile_resets_account"] = True
        self.reject(value, "ACCOUNTING_CONTRACT")
        value = copy.deepcopy(self.value)
        value["required_strategy_classes"].remove("shared-work-across-scales")
        self.reject(value, "STRATEGY_COVERAGE_SCOPE")

    def test_open_proof_obligation_cannot_be_deleted(self):
        self.value["unclosed_obligations"].pop()
        self.reject(self.value, "UNPROVED_OBLIGATION_PROMOTION")

    def test_source_path_cannot_escape_the_exact_source_set(self):
        self.value["source_sha256"]["../foreign"] = "0" * 64
        self.reject(self.value, "SOURCE_SET")

    def test_changed_actual_source_is_detected_even_with_unchanged_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in contract.SOURCE_PATHS:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((contract.ROOT / name).read_bytes())
            changed = root / contract.SOURCE_PATHS[-1]
            changed.write_bytes(changed.read_bytes() + b"\n// mutation\n")
            with self.assertRaisesRegex(contract.ContractError, "SOURCE_DIGEST_MISMATCH"):
                contract.audit_contract(self.value, root=root)

    def test_duplicate_nested_keys_and_float_tokens_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            for text, reason in (('{"a":{"p":1,"p":2}}', "DUPLICATE_JSON_KEY"),
                                 ('{"p":NaN}', "NONINTEGER_JSON_NUMBER"),
                                 ('{"p":1e999}', "NONINTEGER_JSON_NUMBER"),
                                 ('{"p":0.5}', "NONINTEGER_JSON_NUMBER")):
                path.write_text(text)
                with self.assertRaisesRegex(contract.ContractError, reason):
                    contract.load_contract(path)

    def test_contract_byte_limit_preserves_exact_boundary_and_refuses_extra_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_bytes(b"{}" + b" " * (65536 - 2))
            self.assertEqual(contract.load_contract(path), {})
            with path.open("ab") as stream:
                stream.write(b"\n")
            with self.assertRaisesRegex(contract.ContractError, "^CONTRACT_TOO_LARGE$"):
                contract.load_contract(path)


class SubsetTests(unittest.TestCase):
    def subset(self, q=Fraction(1, 8), g=Fraction(1, 2), a=Fraction(2, 5), **changes):
        values = dict(baseline_probability=Fraction(1, 16), retained_winner_fraction=q,
                      retained_domain_fraction=g, classical_attempt_ratio=a,
                      coherent_query_ratio=a)
        values.update(changes)
        return contract.normalized_subset(**values)

    def test_classical_negative_screen_can_miss_quantum_advantage(self):
        row = self.subset()
        self.assertEqual(row["ratio_semantics"],
                         "assumed-inverse-p-and-inverse-sqrt-p-cost-laws;"
                         "not-finite-grover-or-fixed-success-exact-runtime")
        self.assertEqual(row["normalized_probability"], contract.ratio(Fraction(1, 64)))
        self.assertEqual(row["classical_winner_cost_ratio"], contract.ratio(Fraction(8, 5)))
        self.assertEqual(row["quantum_winner_cost_ratio_squared"], contract.ratio(Fraction(16, 25)))
        self.assertEqual(row["classical_comparison"], "dearer")
        self.assertEqual(row["quantum_comparison"], "cheaper")

    def test_quarter_winners_quarter_domain_does_not_quarter_density(self):
        row = self.subset(q=Fraction(1, 4), g=Fraction(1, 4), a=Fraction(1))
        self.assertEqual(row["normalized_probability_ratio"], contract.ratio(Fraction(1)))
        self.assertEqual(row["quantum_comparison"], "equal")

    def test_impossible_inside_and_outside_winner_masses_rejected(self):
        for q, g in ((Fraction(1), Fraction(1, 32)), (Fraction(1, 2), Fraction(1))):
            with self.assertRaisesRegex(contract.ContractError, "IMPOSSIBLE_SUBSET_MASSES"):
                self.subset(q=q, g=g)

    def test_eight_point_domain_subset_mass_feasibility_by_actual_enumeration(self):
        # Obtain possible winner counts by constructing every subset, rather
        # than reusing the arithmetic inequalities enforced by the reader.
        domain = tuple(range(8))
        checked = 0
        for winner_count in range(1, 9):
            winners = frozenset(range(winner_count))
            for domain_count in range(1, 9):
                attainable = {
                    len(winners.intersection(subset))
                    for subset in combinations(domain, domain_count)
                }
                for retained in range(1, winner_count + 1):
                    with self.subTest(winners=winner_count, domain=domain_count,
                                      retained=retained):
                        arguments = dict(
                            baseline_probability=Fraction(winner_count, 8),
                            retained_winner_fraction=Fraction(retained, winner_count),
                            retained_domain_fraction=Fraction(domain_count, 8),
                            classical_attempt_ratio=Fraction(1),
                            coherent_query_ratio=Fraction(1),
                        )
                        if retained in attainable:
                            row = contract.normalized_subset(**arguments)
                            self.assertEqual(row["normalized_probability"],
                                             contract.ratio(Fraction(retained, domain_count)))
                        else:
                            with self.assertRaisesRegex(contract.ContractError,
                                                        "^IMPOSSIBLE_SUBSET_MASSES$"):
                                contract.normalized_subset(**arguments)
                    checked += 1
        self.assertEqual(checked, 288)

    def test_exact_boundary_comparison_does_not_round_an_irrational_root(self):
        for a, result in ((Fraction(1, 2), "equal"),
                          (Fraction(1, 2) - Fraction(1, 10**50), "cheaper"),
                          (Fraction(1, 2) + Fraction(1, 10**50), "dearer")):
            self.assertEqual(self.subset(a=a)["quantum_comparison"], result)
        row = self.subset(q=Fraction(1, 3), g=Fraction(1, 2), a=Fraction(4, 5))
        self.assertEqual(row["quantum_comparison"], "cheaper")
        self.assertEqual(row["quantum_winner_cost_ratio_squared"], contract.ratio(Fraction(24, 25)))

    def test_non_rational_zero_and_boolean_inputs_rejected(self):
        for bad in (0, False, 0.25, Fraction(0), Fraction(-1)):
            with self.assertRaisesRegex(contract.ContractError, "SUBSET_EXACT_POSITIVE_RATIONAL"):
                self.subset(a=bad)


if __name__ == "__main__":
    unittest.main()
