"""Regression tests for arithmetic, accounting and refusal boundaries."""

from copy import deepcopy
from fractions import Fraction
import json
from pathlib import Path
import subprocess
import sys
import unittest

import sponge_query_budget as budget


HERE = Path(__file__).resolve().parent
EXAMPLE = json.loads((HERE / "example_sha3_512.json").read_text(encoding="utf-8"))


def request(q=0, unit="swap"):
    value = deepcopy(EXAMPLE)
    for role in value["queries"]["by_role"].values():
        for phase in role.values():
            for direction in phase:
                phase[direction] = 0
    value["queries"]["by_role"]["other"]["online"]["forward"] = q
    value["queries"]["unit"] = unit
    value["candidate_outputs"] = {
        "preimage_total_padded_blocks_bound": 1,
        "collision_pair_total_padded_blocks_bound": 2,
    }
    return value


def frac(value):
    return Fraction(int(value["numerator"]), int(value["denominator"]))


class BoundTests(unittest.TestCase):
    def admitted(self, value):
        result = budget.evaluate(value)
        self.assertEqual(result["status"], "conditional_model_only", result)
        self.assertIs(result["qualified"], False)
        return result

    def test_default_parameters_are_only_sha3_512_dimensions(self):
        value = request()
        del value["parameters"]
        result = self.admitted(value)
        self.assertEqual(result["parameters"], {
            "rate_bits": 576, "capacity_bits": 1024,
            "digest_bits": 512, "state_bits": 1600,
        })
        self.assertEqual(result["model"], "uniform_random_bitstring_permutation")
        self.assertEqual(result["assumption_status"], "caller_assertions_not_verified")

    def test_hand_computed_fraction_vector(self):
        value = request()
        value["parameters"] = {"rate_bits": 32, "capacity_bits": 32, "digest_bits": 32}
        result = self.admitted(value)["bounds"]
        pre, col = result["preimage"], result["collision"]
        # T_pre=2 and T_col=4; constants below are separately simplified.
        self.assertEqual(frac(pre["terms"]["digest"]), Fraction(1, 2**24))
        self.assertEqual(frac(pre["terms"]["capacity"]), Fraction(1, 2**22))
        self.assertEqual(frac(pre["terms"]["permutation_simulation"]), Fraction(1, 2**47))
        self.assertEqual(frac(pre["unclipped_upper_bound"]), Fraction(41943041, 140737488355328))
        self.assertEqual(frac(col["terms"]["digest"]), Fraction(1, 2**21))
        self.assertEqual(frac(col["terms"]["capacity"]), Fraction(1, 2**19))
        self.assertEqual(frac(col["terms"]["permutation_simulation"]), Fraction(1, 2**45))
        self.assertEqual(frac(col["unclipped_upper_bound"]), Fraction(83886081, 35184372088832))

    def test_tiny_nonzero_term_never_underflows(self):
        result = self.admitted(request())
        value = frac(result["bounds"]["preimage"]["terms"]["permutation_simulation"])
        self.assertEqual(value, Fraction(1, 2**1583))
        self.assertGreater(value, 0)

    def test_example_total_is_exactly_two_to_64(self):
        result = self.admitted(deepcopy(EXAMPLE))
        accounting = result["query_accounting"]
        self.assertEqual(int(accounting["q_swap_upper_bound"]), 2**64)
        self.assertEqual(int(accounting["input_queries_by_phase"]["precomputation"]), 2**63)
        self.assertEqual(int(accounting["input_queries_by_direction"]["inverse"]), 2**61)

    def test_all_roles_directions_and_phases_are_added_once(self):
        value = request()
        counter = 0
        for entry in value["queries"]["by_role"].values():
            for phase in entry.values():
                for direction in phase:
                    counter += 1
                    phase[direction] = counter
        result = self.admitted(value)["query_accounting"]
        self.assertEqual(result["q_swap_upper_bound"], "136")
        self.assertEqual(sum(map(int, result["input_queries_by_role"].values())), 136)
        self.assertEqual(sum(map(int, result["input_queries_by_phase"].values())), 136)
        self.assertEqual(sum(map(int, result["input_queries_by_direction"].values())), 136)

    def test_added_role_is_charged_to_shared_budget(self):
        value = request(7)
        value["queries"]["by_role"]["recursive_backend"] = {
            "precomputation": {"forward": 0, "inverse": 11},
            "online": {"forward": 13, "inverse": 17},
        }
        result = self.admitted(value)["query_accounting"]
        self.assertEqual(result["q_swap_upper_bound"], "48")
        self.assertEqual(result["input_queries_by_phase"]["precomputation"], "11")
        self.assertEqual(result["input_queries_by_direction"]["inverse"], "28")

    def test_role_bucket_allocation_does_not_change_total_budget(self):
        # Seven coherent cross-domain calls may all be charged to "other".
        # Labels describe a chosen upper bound, not a measurement of a role.
        other = self.admitted(request(7))
        renamed = request()
        renamed["queries"]["by_role"]["leaf"]["online"]["forward"] = 7
        leaf = self.admitted(renamed)
        self.assertEqual(other["bounds"], leaf["bounds"])
        self.assertEqual(other["query_accounting"]["q_swap_upper_bound"], "7")

    def test_conservative_cross_role_overcount_never_lowers_bound(self):
        once = self.admitted(request(7))
        overcount = request()
        for role in ("leaf", "branch", "transcript"):
            overcount["queries"]["by_role"][role]["online"]["forward"] = 7
        repeated = self.admitted(overcount)
        self.assertEqual(repeated["query_accounting"]["q_swap_upper_bound"], "21")
        for kind in ("preimage", "collision"):
            self.assertGreater(
                frac(repeated["bounds"][kind]["upper_bound"]),
                frac(once["bounds"][kind]["upper_bound"]),
            )

    def test_xor_simulation_converts_q_but_not_2l(self):
        xor = request(7, "standard_xor")
        xor["candidate_outputs"] = {
            "preimage_total_padded_blocks_bound": 3,
            "collision_pair_total_padded_blocks_bound": 4,
        }
        swap = deepcopy(xor)
        swap["queries"]["unit"] = "swap"
        swap["queries"]["by_role"]["other"]["online"]["forward"] = 14
        result = self.admitted(xor)
        self.assertEqual(result["bounds"], self.admitted(swap)["bounds"])
        self.assertEqual(result["bounds"]["preimage"]["T_swap_queries"], "20")
        self.assertEqual(result["bounds"]["collision"]["T_swap_queries"], "22")

    def test_message_bound_increase_is_not_a_query_discount(self):
        small = self.admitted(request(11))["bounds"]
        value = request(11)
        value["candidate_outputs"]["collision_pair_total_padded_blocks_bound"] = 100
        larger = self.admitted(value)["bounds"]
        self.assertEqual(larger["preimage"], small["preimage"])
        self.assertGreater(frac(larger["collision"]["upper_bound"]), frac(small["collision"]["upper_bound"]))
        self.assertEqual(larger["collision"]["T_swap_queries"], "211")

    def test_shared_budget_monotonicity(self):
        previous = None
        for q in range(16):
            bounds = self.admitted(request(q))["bounds"]
            current = tuple(frac(bounds[kind]["upper_bound"]) for kind in ("preimage", "collision"))
            if previous is not None:
                self.assertTrue(all(a < b for a, b in zip(previous, current)))
            previous = current

    def test_multiple_targets_use_entire_q_and_only_enlarge_preimage(self):
        single = self.admitted(request(17))
        value = request(17)
        value["targets"]["fixed_preimage_target_count"] = 5
        many = self.admitted(value)
        self.assertEqual(single["query_accounting"], many["query_accounting"])
        self.assertEqual(single["bounds"]["collision"], many["bounds"]["collision"])
        self.assertEqual(single["bounds"]["preimage"]["T_swap_queries"], many["bounds"]["preimage"]["T_swap_queries"])
        self.assertEqual(
            frac(many["bounds"]["preimage"]["fixed_target_union"]["upper_bound"]),
            5 * frac(single["bounds"]["preimage"]["upper_bound"]),
        )

    def test_all_probability_outputs_clip_but_keep_raw_terms(self):
        value = request(60)
        value["parameters"] = {"rate_bits": 8, "capacity_bits": 8, "digest_bits": 8}
        value["candidate_outputs"]["preimage_total_padded_blocks_bound"] = 2
        value["targets"]["fixed_preimage_target_count"] = 3
        bounds = self.admitted(value)["bounds"]
        for kind in ("preimage", "collision"):
            self.assertGreater(frac(bounds[kind]["unclipped_upper_bound"]), 1)
            self.assertEqual(frac(bounds[kind]["upper_bound"]), 1)
        self.assertEqual(frac(bounds["preimage"]["fixed_target_union"]["upper_bound"]), 1)

    def test_union_can_clip_when_single_target_does_not(self):
        value = request()
        value["parameters"] = {"rate_bits": 32, "capacity_bits": 32, "digest_bits": 32}
        value["targets"]["fixed_preimage_target_count"] = 2**24
        pre = self.admitted(value)["bounds"]["preimage"]
        self.assertLess(frac(pre["upper_bound"]), 1)
        self.assertEqual(frac(pre["fixed_target_union"]["upper_bound"]), 1)

    def test_large_exact_domain_boundary(self):
        value = request(2**798 - 16)
        value["candidate_outputs"] = {
            "preimage_total_padded_blocks_bound": 4,
            "collision_pair_total_padded_blocks_bound": 8,
        }
        result = self.admitted(value)
        self.assertEqual(int(result["bounds"]["collision"]["T_swap_queries"]), 2**798)
        value["queries"]["by_role"]["other"]["online"]["forward"] += 1
        rejected = budget.evaluate(value)
        self.assertEqual(rejected["reason"]["code"], "OUTSIDE_SIMPLIFIED_BOUND_DOMAIN")
        self.assertIs(rejected["qualified"], False)

    def test_odd_state_width_boundary_uses_no_square_root_rounding(self):
        value = request(23166)
        value["parameters"] = {"rate_bits": 17, "capacity_bits": 16, "digest_bits": 16}
        value["candidate_outputs"]["preimage_total_padded_blocks_bound"] = 2
        self.admitted(value)  # 16*23170**2 <= 2**33 < 16*23171**2.
        value["queries"]["by_role"]["other"]["online"]["forward"] += 1
        self.assertEqual(budget.evaluate(value)["status"], "unsupported")


class RefusalTests(unittest.TestCase):
    def refused(self, value, code=None):
        result = budget.evaluate(value)
        self.assertEqual(result["status"], "unsupported", result)
        self.assertIs(result["qualified"], False)
        self.assertNotIn("bounds", result)
        if code:
            self.assertEqual(result["reason"]["code"], code)
        return result

    def test_missing_assumptions_never_default(self):
        for key in ("claim", "construction", "queries", "initial_state", "candidate_outputs", "targets"):
            with self.subTest(key=key):
                value = request()
                del value[key]
                self.refused(value, "MISSING_FIELD")

    def test_fixed_primitives_field_model_and_unknown_primitive_refused(self):
        for model in ("Keccak-f[1600]", "Poseidon2", "uniform_random_field_permutation", "unknown"):
            with self.subTest(model=model):
                value = request()
                value["construction"]["model"] = model
                self.refused(value)

    def test_fs_binding_and_protocol_claims_refused(self):
        for claim in ("multi_stage_fiat_shamir", "restricted_tree_binding", "recursive_w1", "pq128"):
            with self.subTest(claim=claim):
                value = request()
                value["claim"] = claim
                self.refused(value)

    def test_raw_truncation_and_duplex_are_not_sponge_mode(self):
        for mode in ("full_width_permutation_truncation", "duplex", "multi_stage_transcript"):
            with self.subTest(mode=mode):
                value = request()
                value["construction"]["sponge_mode"] = mode
                self.refused(value)

    def test_unknown_or_free_construct_dependent_advice_refused(self):
        for advice in ("unknown", "free_classical", "free_quantum", "bounded_but_uncounted", None):
            with self.subTest(advice=advice):
                value = request()
                value["initial_state"]["construction_dependent_advice"] = advice
                self.refused(value)

    def test_uncounted_initial_correlations_refused(self):
        value = request()
        value["initial_state"]["at_start_of_counted_lifetime"] = "permutation_dependent"
        self.refused(value)
        value = request()
        value["initial_state"]["later_permutation_dependent_state"] = "external_advice_allowed"
        self.refused(value)

    def test_honest_ledger_does_not_become_adversary_bound(self):
        value = request()
        value["queries"]["basis"] = "measured_honest_ledger"
        self.refused(value)

    def test_online_only_and_per_attempt_budgets_refused(self):
        for scope in ("online_only", "per_attempt", "per_proof", "one_receiver"):
            with self.subTest(scope=scope):
                value = request()
                value["queries"]["scope"] = scope
                self.refused(value)

    def test_each_incomplete_coverage_flag_is_refused(self):
        for flag in budget.COVERAGE:
            with self.subTest(flag=flag):
                value = request()
                value["queries"]["coverage"][flag] = False
                self.refused(value)

    def test_all_role_phase_and_direction_counts_are_required(self):
        for role in budget.REQUIRED_ROLES:
            with self.subTest(role=role):
                value = request()
                del value["queries"]["by_role"][role]
                self.refused(value, "MISSING_ROLES")
        value = request()
        del value["queries"]["by_role"]["other"]["precomputation"]
        self.refused(value, "MISSING_FIELD")
        value = request()
        del value["queries"]["by_role"]["leaf"]["online"]["inverse"]
        self.refused(value, "MISSING_FIELD")

    def test_unknown_or_high_level_query_units_refused(self):
        for unit in ("hash_calls", "sponge_calls", "cpu_cycles", None, ["swap"]):
            with self.subTest(unit=unit):
                self.refused(request(unit=unit), "UNSUPPORTED_QUERY_UNIT")

    def test_noninjective_and_unknown_encoding_or_padding_refused(self):
        for field in ("message_encoding", "padding"):
            for state in ("noninjective", "unknown"):
                with self.subTest(field=field, state=state):
                    value = request()
                    value["construction"][field] = state
                    self.refused(value)

    def test_unbounded_missing_or_impossible_message_bounds_refused(self):
        for bad in (None, "unbounded", -1, True, 1.5):
            with self.subTest(bad=bad):
                value = request()
                value["candidate_outputs"]["preimage_total_padded_blocks_bound"] = bad
                self.refused(value)
        value = request()
        value["candidate_outputs"]["collision_pair_total_padded_blocks_bound"] = 1
        self.refused(value)
        value = request()
        del value["candidate_outputs"]["collision_pair_total_padded_blocks_bound"]
        self.refused(value)

    def test_targets_cannot_be_chosen_after_permutation(self):
        value = request()
        value["targets"]["selection"] = "adaptively_from_permutation"
        self.refused(value)

    def test_union_cannot_divide_or_reset_lifetime_q(self):
        value = request()
        value["targets"]["budget_per_event"] = "q_divided_by_target_count"
        self.refused(value)
        value["targets"]["budget_per_event"] = "new_q_for_each_attempt"
        self.refused(value)

    def test_invalid_counts_never_coerce_to_integers(self):
        for bad in (True, False, 1.0, -1, "01", "+1", "1e10", " 1", "1 ", "-0", None, [], {}):
            with self.subTest(bad=bad):
                self.refused(request(q=bad), "INVALID_INTEGER")

    def test_parameters_are_positive_bounded_and_first_block_only(self):
        for field, bad in (("rate_bits", 0), ("capacity_bits", -1), ("digest_bits", True), ("rate_bits", 5000)):
            with self.subTest(field=field, bad=bad):
                value = request()
                value["parameters"][field] = bad
                self.refused(value)
        value = request()
        value["parameters"]["digest_bits"] = 577
        self.refused(value, "DIGEST_EXCEEDS_RATE")
        value = request()
        value["construction"]["output"] = "multiple_squeeze_blocks"
        self.refused(value)

    def test_large_inputs_and_unknown_fields_do_not_get_ignored(self):
        self.refused(request(q=2**2048), "INPUT_LIMIT")
        value = request()
        value["security_bits"] = 128
        self.refused(value, "UNKNOWN_FIELD")
        value = request()
        value["queries"]["by_role"]["other"]["online"]["unaccounted"] = 1
        self.refused(value, "UNKNOWN_FIELD")


class JsonAndCliTests(unittest.TestCase):
    def test_json_preserves_large_canonical_decimal_counts(self):
        result = budget.evaluate_json(json.dumps(request(q=str(2**120 + 1))).encode())
        self.assertEqual(result["query_accounting"]["q_swap_upper_bound"], str(2**120 + 1))

    def test_duplicate_json_keys_nonfinite_and_float_numbers_refused(self):
        for data in (b'{"schema":"a","schema":"b"}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e3}', b'{"x":1.0}'):
            with self.subTest(data=data):
                result = budget.evaluate_json(data)
                self.assertEqual(result["status"], "unsupported")
                self.assertIs(result["qualified"], False)
                self.assertNotIn("bounds", result)

    def test_malformed_unicode_depth_and_size_refused(self):
        for data in (b"{", b"\xff", b"[" * 2000 + b"]" * 2000, b" " * (budget.MAX_INPUT_BYTES + 1)):
            with self.subTest(length=len(data)):
                result = budget.evaluate_json(data)
                self.assertEqual(result["status"], "unsupported")
                self.assertIs(result["qualified"], False)

    def test_cli_file_exit_zero_is_only_conditional(self):
        process = subprocess.run(
            [sys.executable, str(HERE / "sponge_query_budget.py"), str(HERE / "example_sha3_512.json")],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["status"], "conditional_model_only")
        self.assertIs(result["qualified"], False)

    def test_cli_stdin_refusal_has_nonzero_status_and_no_bound(self):
        process = subprocess.run(
            [sys.executable, str(HERE / "sponge_query_budget.py")],
            input=b'{"schema":"unsupported"}', capture_output=True, check=False,
        )
        self.assertEqual(process.returncode, 2, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["status"], "unsupported")
        self.assertIs(result["qualified"], False)
        self.assertNotIn("bounds", result)

    def test_cli_io_error_is_explicit(self):
        process = subprocess.run(
            [sys.executable, str(HERE / "sponge_query_budget.py"), str(HERE / "missing-input.json")],
            capture_output=True, check=False,
        )
        self.assertEqual(process.returncode, 2)
        result = json.loads(process.stdout)
        self.assertEqual(result["reason"]["code"], "INPUT_IO")
        self.assertIs(result["qualified"], False)


if __name__ == "__main__":
    unittest.main()
