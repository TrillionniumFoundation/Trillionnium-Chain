"""Independent amplitudes, exact probability flow and finite native-shaped DAG controls."""
from copy import deepcopy
from dataclasses import replace
from decimal import Decimal, localcontext
from fractions import Fraction
import unittest
from unittest.mock import patch

import contract_wire as wire
from quantum_oracle_resources import ClassicalCosts, example
from reference import retarget, work
from test_w1_quantum_oracle import fixture as oracle_fixture
from w1_finite_consensus import (
    FIXTURE_SCHEMA, POW_LIMIT, FiniteModel, analyze_finite_consensus,
    digest, exact_nonce_probabilities, rational, sample_finite_policy,
    verify_finite_certificate,
)
from w1_marked_domain import enumerate_domain
from w1_machine_envelope import LifecycleModel, NOISE_CONTRACT
from w1_quantum_oracle import FixedTemplate


def reduced_native_shaped_dag():
    """Small actual SHA/noise predicates; prefix admission is an explicit premise.

    No reduced matrix or synthetic prefix is called native-accepted. The bridge
    campaign supplies real native packets using the very same input schema.
    """
    template = oracle_fixture(nonce_bits=4)
    base = wire.header_decode(template.header)
    genesis = "01" * 32
    rows = [{"block_id": genesis, "parent_id": None, "height": 0, "timestamp": 1000,
             "target_hex": f"{POW_LIMIT:064x}", "chainwork_hex": "00" * 64, "header_hex": None}]
    parent, credit = genesis, 0
    for height in range(1, 16):
        raw = wire.header_encode({**base, "parent": bytes.fromhex(parent), "height": height,
                                  "timestamp": 1000 + height, "target": POW_LIMIT.to_bytes(32, "big")})
        identifier = wire.H("block", raw, bytes(32)).hex()
        credit += work(POW_LIMIT)
        rows.append({"block_id": identifier, "parent_id": parent, "height": height,
                     "timestamp": 1000 + height, "target_hex": f"{POW_LIMIT:064x}",
                     "chainwork_hex": f"{credit:0128x}", "header_hex": raw.hex()})
        parent = identifier
    target = retarget(POW_LIMIT, 1000, 1015, 16, 10, POW_LIMIT)
    public_raw = wire.header_encode({**base, "parent": bytes.fromhex(parent), "height": 16,
                                    "timestamp": 1160, "target": target.to_bytes(32, "big")})
    public_trace = bytes([9]) * 32
    public_id = wire.H("block", public_raw, public_trace).hex()
    public = {"block_id": public_id, "parent_id": parent, "height": 16,
              "timestamp": 1160, "target_hex": f"{target:064x}", "chainwork_hex": f"{credit + work(target):0128x}",
              "header_hex": public_raw.hex(), "trace": public_trace.hex(), "publication_at_seconds": "0"}
    contexts = []

    def context(identifier, previous, height):
        raw = wire.header_encode({**base, "parent": bytes.fromhex(previous), "height": height,
                                  "timestamp": 1000 + height, "target": target.to_bytes(32, "big")})
        local = FixedTemplate.from_header(raw, template.a, template.b, template.nonce_bits, template.shape)
        domain = enumerate_domain(local)
        children, next_contexts = [], []
        for nonce in domain["marked_nonces"]:
            header = local.header_for(nonce)
            block = wire.H("block", header, bytes.fromhex(domain["outcomes"][nonce]["trace"])).hex()
            following = "child-" + block if height == 16 else None
            children.append({"nonce": nonce, "block_id": block, "header_hex": header.hex(),
                             "child_context_id": following})
            if following is not None:
                next_contexts.append((following, block, height + 1))
        contexts.append({"context_id": identifier, "parent_id": previous,
                         "template_spec": local.spec(), "winner_children": children})
        for args in next_contexts:
            context(*args)

    context("root", parent, 16)
    return {"schema": FIXTURE_SCHEMA, "interval": 16, "spacing_seconds": 10,
            "future_skew_seconds": 120, "pow_limit_hex": f"{POW_LIMIT:064x}",
            "clock_origin_timestamp": 1160, "root_context_id": "root",
            "prefix": {"tip_id": parent, "height": 15, "chainwork_hex": f"{credit:0128x}",
                       "parent_first_headers": list(reversed(rows))},
            "public_tip": public, "contexts": contexts,
            "initial_resources": {"scope": "reduced test controls, assumed prefix, no native admission",
                                  "preexisting_quantum_state": False, "offline_census_is_miner_advice": False}}


def resign(record):
    record["certificate_sha256"] = digest({key: value for key, value in record.items() if key != "certificate_sha256"})


def finite_lifecycle():
    return LifecycleModel(
        name="finite-conditional-control", noise_contract=NOISE_CONTRACT,
        initialization_cycles_per_distance=2, initialization_parallel_patches=10**9,
        readout_cycles_per_distance=3, readout_parallel_bits=2,
        controller_cycles_per_command=2, transfer_fixed_ns=5, transfer_ns_per_byte=3,
        factory_startup_cycles_per_distance=11, factory_attempts_per_state=16,
        factory_discard_reset_cycles_per_distance=13,
        factory_reject_probability_bound="0.01", initialization_failure_bound="1e-40",
        readout_failure_bound="1e-40", transfer_byte_failure_bound="1e-40",
        controller_command_failure_bound="1e-50", host_call_failure_bound="1e-30",
        propagation_failure_bound="1e-30")


class ExactAmplitudeTests(unittest.TestCase):
    def test_complete_dense_state_independent_of_two_dimensional_recurrence(self):
        comparisons = 0
        for size in (1, 2, 4, 8):
            for mask in range(1 << size):
                marked = tuple(i for i in range(size) if (mask >> i) & 1)
                amplitudes = [Fraction(1)] * size
                for count in range(6):
                    expected = tuple(value * value / size for value in amplitudes)
                    self.assertEqual(exact_nonce_probabilities(size, marked, count), expected)
                    after_oracle = [-value if i in marked else value for i, value in enumerate(amplitudes)]
                    mean = sum(after_oracle) / size
                    amplitudes = [2 * mean - value for value in after_oracle]
                    comparisons += 1
        self.assertEqual(comparisons, 1668)

    def test_exact_overshoot_and_phase_unmarked_legal_winners(self):
        self.assertEqual(exact_nonce_probabilities(4, (0,), 1), (1, 0, 0, 0))
        self.assertEqual(exact_nonce_probabilities(4, (0, 1, 2), 1), (0, 0, 0, 1))
        self.assertEqual(sum(exact_nonce_probabilities(2, (), 7)), 1)
        self.assertEqual(sum(exact_nonce_probabilities(8, (4, 7), 7)), 1)

    def test_noncanonical_or_unbounded_kernel_inputs_refused(self):
        for args in ((0, (), 0), (4, (0, 0), 0), (4, (4,), 0), (4, (), 65), (True, (), 0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                exact_nonce_probabilities(*args)


class FiniteCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = reduced_native_shaped_dag()
        cls.classical = tuple(ClassicalCosts(11, 13, 17, 19, 23, 29) for _ in cls.fixture["contexts"])
        cls.physical = replace(example(True).physical_models[0], magic_state_error="0")
        cls.report = analyze_finite_consensus(cls.fixture, cls.classical, cls.physical, 1 << 100)

    def build(self, fixture=None, **kwargs):
        fixture = self.fixture if fixture is None else fixture
        return analyze_finite_consensus(fixture, self.classical, self.physical, 1 << 100, **kwargs)

    def test_real_literal_domains_retarget_and_positive_exact_fork_path(self):
        report = self.report
        result = verify_finite_certificate(report, self.fixture)
        self.assertTrue(result["bellman_checked"])
        self.assertGreater(rational(report["risk_upper"]), 0)
        self.assertGreater(rational(report["fixed_policy_risks"]["0"]), 0)
        self.assertEqual(rational(report["fixed_policy_risks"]["1"]), 0)
        witness = report["positive_path"]
        blocks = [step["edge"]["observation"]["block_id"] for step in witness["trajectory"]
                  if step["edge"]["observation"].get("proof_complete")]
        self.assertEqual(len(blocks), 2)
        self.assertFalse(witness["sampled_execution"])
        self.assertEqual(witness["trajectory"][-1]["edge"]["terminal_risk"], 1)
        self.assertTrue(all(not row["native_shape"] for row in report["literal_domain_summaries"]))

    def test_q_zero_probability_matches_hand_count_of_complete_nonce_paths(self):
        counts = {row["context_id"]: len(row["winner_children"]) for row in self.fixture["contexts"]}
        root = self.fixture["contexts"][0]
        expected = sum(Fraction(counts[row["child_context_id"]], 16 * 16) for row in root["winner_children"])
        self.assertEqual(rational(self.report["fixed_policy_risks"]["0"]), expected)

    def test_one_attempt_cannot_replace_equal_required_work(self):
        record = self.build(max_attempts=1)
        self.assertEqual(rational(record["risk_upper"]), 0)
        self.assertIsNone(record["positive_path"])
        self.assertTrue(verify_finite_certificate(record, self.fixture)["bellman_checked"])

    def test_zero_horizon_and_incomplete_state_cap_have_distinct_meanings(self):
        zero = self.build(horizon_seconds="0")
        self.assertEqual(zero["status"], "COMPLETE")
        self.assertEqual(rational(zero["risk_upper"]), 0)
        incomplete = self.build(max_states=1)
        self.assertEqual(incomplete["status"], "INCOMPLETE")
        self.assertIsNone(incomplete["risk_upper"])
        self.assertFalse(verify_finite_certificate(incomplete, self.fixture)["bellman_checked"])
        incomplete["risk_upper"] = {"numerator": 0, "denominator": 1}
        resign(incomplete)
        with self.assertRaisesRegex(ValueError, "INCOMPLETE_CANNOT_CERTIFY"):
            verify_finite_certificate(incomplete, self.fixture)

    def test_omitted_winner_branch_and_tampered_parent_or_target_refused(self):
        modified = deepcopy(self.fixture)
        modified["contexts"][0]["winner_children"].pop()
        with self.assertRaisesRegex(ValueError, "COMPLETE_WINNER_BRANCHES"):
            self.build(modified)
        modified = deepcopy(self.fixture)
        modified["contexts"][1]["parent_id"] = "ab" * 32
        with self.assertRaisesRegex(ValueError, "CONTEXT_PARENT_BINDING"):
            self.build(modified)
        modified = deepcopy(self.fixture)
        raw = bytearray.fromhex(modified["contexts"][0]["template_spec"]["header_hex"])
        raw[118:150] = POW_LIMIT.to_bytes(32, "big")
        modified["contexts"][0]["template_spec"]["header_hex"] = raw.hex()
        with self.assertRaisesRegex(ValueError, "CONTEXT_REQUIRED_HEADER"):
            self.build(modified)

    def test_self_consistent_forged_certificate_cannot_hide_actions_or_probability_mass(self):
        initial = digest(FiniteModel(self.fixture, self.report["parameters"]).initial())
        for mutation, error in (("drop-action", "ACTION_COVERAGE"), ("probability", "TRANSITION_MISMATCH"),
                                ("value", "BELLMAN_INEQUALITY"), ("fixed", "FIXED_POLICY_FLOW_MISMATCH")):
            record = deepcopy(self.report)
            node = record["nodes"][initial]
            if mutation == "drop-action":
                node["actions"].pop()
            elif mutation == "probability":
                node["actions"][0]["edges"][0]["probability"] = {"numerator": 0, "denominator": 1}
            elif mutation == "value":
                node["value"] = {"numerator": 0, "denominator": 1}
            else:
                record["fixed_policy_risks"]["0"] = {"numerator": 0, "denominator": 1}
            resign(record)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, error):
                verify_finite_certificate(record, self.fixture)

    def test_uniform_fixed_seed_sample_keeps_misses_and_is_deterministic(self):
        first = sample_finite_policy(self.report, self.fixture, iterations=0, seed=9)
        second = sample_finite_policy(self.report, self.fixture, iterations=0, seed=9)
        self.assertEqual(first, second)
        self.assertFalse(first["policy_reads_marked_count_or_bellman_values"])
        searches = [step for step in first["trajectory"] if step["action"]["kind"] == "search"]
        self.assertTrue(searches)
        self.assertTrue(all(step["edge"]["observation"]["nonce"] is not None for step in searches))
        one = sample_finite_policy(self.report, self.fixture, iterations=1, seed=9)
        self.assertEqual(len(one["trajectory"]), 1)
        self.assertIsNone(one["trajectory"][0]["edge"]["observation"]["nonce"])
        self.assertFalse(one["strict_work_replacement"])

    def test_common_provisioning_and_false_scope_flags_remain_explicit(self):
        binding = self.report["constructed_binding"]
        self.assertEqual(binding["envelope"]["planned_trials_per_processor"], 2 * len(self.fixture["contexts"]))
        self.assertEqual(binding["envelope"]["planned_iterations_per_processor"], 2 * len(self.fixture["contexts"]))
        scope = self.report["scope"]
        for key in ("physical_clock_calibrated", "whole_machine_error_bound_composed", "attacker_minimum_cost_proved",
                    "quantum_hardware_executed", "mixed_quantum_classical_consensus_security_proved",
                    "quantum_mining_qualified", "production_activation"):
            self.assertIs(scope[key], False)

    def test_exact_publication_deadline_and_partial_phase_ledger(self):
        witness = self.report["positive_path"]["trajectory"]
        delivered_at = rational(witness[-1]["edge"]["observation"]["time"])
        with localcontext() as context:
            context.prec = 300
            exact = str(Decimal(delivered_at.numerator) / Decimal(delivered_at.denominator))
            before = delivered_at - Fraction(1, 10**25)
            earlier = str(Decimal(before.numerator) / Decimal(before.denominator))
        complete = self.build(horizon_seconds=exact)
        censored = self.build(horizon_seconds=earlier)
        self.assertGreater(rational(complete["risk_upper"]), 0)
        self.assertEqual(rational(censored["risk_upper"]), 0)
        self.assertTrue(verify_finite_certificate(censored, self.fixture)["bellman_checked"])
        model = FiniteModel(self.fixture, self.report["parameters"])
        state = model.initial()
        clock = model.clocks[model.root_context]
        # Stop halfway through readout: no measurement nonce is exposed, and
        # elapsed setup/preparation/readout are all retained as exact charges.
        model.limit = clock["domain_setup_seconds"] + clock["prepare_seconds"] + clock["measurement_seconds"] / 2
        edge = model.transition(state, {"kind": "search", "iterations": 0})[0]
        observation = edge["observation"]
        self.assertIsNone(observation["nonce"])
        self.assertFalse(observation["measurement_complete"])
        self.assertEqual(sum(rational(row["paid"]) for row in observation["phases"]), model.limit)
        self.assertEqual(edge["terminal_risk"], 0)

    def test_misses_reuse_only_the_same_resident_template_and_preserve_nonce(self):
        model = FiniteModel(self.fixture, self.report["parameters"])
        edges = model.transition(model.initial(), {"kind": "search", "iterations": 0})
        missed = next(edge for edge in edges if edge["observation"]["winner"] is False)
        retried = model.transition(missed["next_state"], {"kind": "search", "iterations": 0})
        self.assertTrue(all(rational(edge["observation"]["phases"][0]["planned"]) == 0 for edge in retried))
        won = next(edge for edge in edges if edge["observation"]["winner"] is True)
        extended = model.transition(won["next_state"], {"kind": "search", "iterations": 0})
        self.assertTrue(all(rational(edge["observation"]["phases"][0]["planned"]) > 0 for edge in extended))
        self.assertTrue(all(edge["observation"]["parent_id"] == won["observation"]["block_id"] for edge in extended))

    def test_publication_wait_uses_declared_public_visibility_and_excludes_early_win(self):
        fixture = deepcopy(self.fixture)
        fixture["public_tip"]["publication_at_seconds"] = "3"
        record = self.build(fixture)
        model = FiniteModel(fixture, record["parameters"])
        path = record["positive_path"]["trajectory"]
        self.assertGreaterEqual(rational(path[-1]["edge"]["observation"]["time"]), 3)
        first = next(edge for edge in model.transition(model.initial(), {"kind": "search", "iterations": 0})
                     if edge["observation"]["winner"])
        second = next(edge for edge in model.transition(first["next_state"], {"kind": "search", "iterations": 0})
                      if edge["observation"]["winner"])
        prematurely_published = model.transition(second["next_state"], {"kind": "publish"})[0]
        self.assertTrue(prematurely_published["observation"]["publication_complete"])
        self.assertEqual(prematurely_published["terminal_risk"], 0)
        self.assertTrue(verify_finite_certificate(record, fixture)["bellman_checked"])

    def test_forged_qualification_and_witness_scope_fields_are_refused(self):
        record = deepcopy(self.report)
        record["quantum_mining_qualified"] = True
        resign(record)
        with self.assertRaisesRegex(ValueError, "FINITE_CERTIFICATE_FIELDS"):
            verify_finite_certificate(record, self.fixture)
        record = deepcopy(self.report)
        record["positive_path"]["selection"] = "measured quantum execution"
        resign(record)
        with self.assertRaisesRegex(ValueError, "POSITIVE_WITNESS_SCOPE"):
            verify_finite_certificate(record, self.fixture)

    def test_full_lifecycle_covers_k_winners_and_composes_exact_conditional_risk(self):
        record = self.build(lifecycle_model=finite_lifecycle())
        self.assertTrue(verify_finite_certificate(record, self.fixture)["bellman_checked"])
        self.assertTrue(record["scope"]["whole_machine_error_bound_composed"])
        self.assertEqual(record["scope"]["clock_model"], "full conditional machine lifecycle")
        envelope = record["machine_envelope"]["envelope"]
        events = envelope["events_all_processors"]
        self.assertEqual(events["proofs_reserved"], 2)
        self.assertEqual(events["propagations"], 2)
        epsilon = rational(envelope["whole_plan_failure_union_upper"])
        bounds = record["conditional_machine_risk_bounds"]
        value = rational(record["risk_upper"])
        self.assertEqual(rational(bounds["census_advised_action_envelope"]["lower"]), max(0, value - epsilon))
        self.assertEqual(rational(bounds["census_advised_action_envelope"]["upper"]), min(1, value + epsilon))
        forged = deepcopy(record)
        forged["conditional_machine_risk_bounds"]["failure_union_upper"] = {"numerator": 0, "denominator": 1}
        resign(forged)
        with self.assertRaisesRegex(ValueError, "FINITE_MACHINE_COUPLING_BOUND"):
            verify_finite_certificate(forged, self.fixture)

    def test_full_lifecycle_action_clocks_keep_common_distance_and_no_q_zero_factory(self):
        record = self.build(lifecycle_model=finite_lifecycle())
        model = FiniteModel(self.fixture, record["parameters"])
        distance = record["machine_envelope"]["envelope"]["code_distance_for_whole_schedule"]
        for key in model.ordered:
            zero, one = (model.action_clocks[key, q, True] for q in (0, 1))
            for row in (zero, one):
                self.assertEqual(row["code_distance_for_whole_schedule"], distance)
            for name in ("factory_startup", "factory_attempt_service", "factory_discard_reset"):
                self.assertEqual(rational(zero["quantum_phase_seconds_exact"][name]), 0)
                self.assertGreater(rational(one["quantum_phase_seconds_exact"][name]), 0)
            # Independently rederive all d-scaled and fixed controller times.
            unit = Fraction(1000, 10**9)
            for row in (zero, one):
                expected = sum(row["cycles_per_distance_per_processor"].values()) * distance * unit
                expected += row["controller_fixed_cycles_per_processor"] * unit
                classical = row["classical_nanoseconds"]
                expected += Fraction(sum(classical.values()) - classical["winner_proof"] - classical["winner_propagation"], 10**9)
                self.assertEqual(rational(row["search_seconds_exact"]), expected)
        state = model.initial()
        edge = model.transition(state, {"kind": "search", "iterations": 0})[0]
        names = [row["phase"] for row in edge["observation"]["phases"]]
        for phase in ("initialize", "input_transfer", "controller_waits", "terminal_readout", "output_transfer"):
            self.assertIn(phase, names)
        sample = sample_finite_policy(record, self.fixture, iterations=0, seed=9)
        self.assertEqual(sample["machine_envelope_sha256"], record["machine_envelope"]["record_sha256"])

    def test_classical_costs_follow_fixture_context_ids_when_input_order_changes(self):
        fixture = deepcopy(self.fixture)
        fixture["contexts"].reverse()
        costs = tuple(replace(self.classical[0], per_winner_proof_ns=101 + i) for i in range(len(fixture["contexts"])))
        expected = {row["context_id"]: cost.per_winner_proof_ns for row, cost in zip(fixture["contexts"], costs)}
        record = analyze_finite_consensus(fixture, costs, self.physical, 1 << 100)
        for key, row in zip(record["context_order"], record["constructed_binding"]["domain_resources"]):
            self.assertEqual(row["classical_costs_ns"]["per_winner_proof_ns"], expected[key])

    def test_classical_uniform_implementation_never_builds_or_initializes_a_qpu(self):
        with patch("w1_finite_consensus.bind_constructed_search", side_effect=AssertionError("QPU construction")), \
                patch("w1_finite_consensus.build_machine_envelope", side_effect=AssertionError("QPU lifecycle")):
            record = self.build(iterations=(0,), execution_kind="classical-uniform-q0", lifecycle_model=finite_lifecycle())
            self.assertTrue(verify_finite_certificate(record, self.fixture)["bellman_checked"])
            sample = sample_finite_policy(record, self.fixture, iterations=0, seed=9)
        self.assertIsNone(record["constructed_binding"])
        self.assertIsNone(record["machine_envelope"])
        self.assertEqual(record["scope"]["quantum_processors"], 0)
        envelope = record["classical_host_envelope"]
        self.assertEqual(envelope["physical_qubits"], 0)
        self.assertEqual(rational(envelope["quantum_fault_probability"]), 0)
        self.assertEqual(record["fixed_policy_risks"]["0"], self.report["fixed_policy_risks"]["0"])
        for step in sample["trajectory"]:
            if step["action"]["kind"] == "search":
                observation = step["edge"]["observation"]
                self.assertTrue(observation["nonce_available"])
                self.assertFalse(observation["measurement_complete"])
                self.assertEqual(observation["nonce_source"], "classical-uniform-q0")
                phases = observation["phases"]
                self.assertEqual([row["phase"] for row in phases[:3]],
                                 ["classical_task_and_template_setup", "classical_nonce_generation", "candidate_check"])
        self.assertFalse(record["conditional_machine_risk_bounds"]["common_quantum_code_distance_used"])

    def test_classical_host_fault_union_and_all_declared_costs_are_retained(self):
        record = self.build(iterations=(0,), execution_kind="classical-uniform-q0", lifecycle_model=finite_lifecycle())
        model = FiniteModel(self.fixture, record["parameters"])
        envelope = record["classical_host_envelope"]
        contexts, attempts = len(self.fixture["contexts"]), 2
        host_calls = 2 * contexts + 2 * contexts * attempts + attempts
        self.assertEqual(envelope["events"]["host_calls_including_proofs"], host_calls)
        expected = (host_calls + attempts) * Fraction(1, 10**30)
        self.assertEqual(rational(envelope["envelope"]["whole_plan_failure_union_upper"]), expected)
        winner = next(edge for edge in model.transition(model.initial(), {"kind": "search", "iterations": 0})
                      if edge["observation"]["winner"])
        self.assertEqual(rational(winner["observation"]["time"]), Fraction(11 + 13 + 17 + 19 + 23, 10**9))
        publication = model.transition(winner["next_state"], {"kind": "publish"})[0]
        self.assertEqual(rational(publication["observation"]["time"]), Fraction(11 + 13 + 17 + 19 + 23 + 29, 10**9))
        self.assertEqual(publication["terminal_risk"], 0)

    def test_classical_uniform_mode_refuses_nonzero_q_and_phase_oracle_variants(self):
        for options in ({"iterations": (0, 1)}, {"iterations": (0,), "predicate": "prefix-restricted"}):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, "CLASSICAL_UNIFORM_Q_ZERO_ONLY"):
                self.build(execution_kind="classical-uniform-q0", **options)

    def test_native_clock_overflow_refused_and_edge_limit_is_incomplete(self):
        fixture = deepcopy(self.fixture)
        fixture["clock_origin_timestamp"] = (1 << 64) - 1
        with self.assertRaisesRegex(ValueError, "FINITE_CLOCK_U64_OVERFLOW"):
            self.build(fixture)
        with patch("w1_finite_consensus.MAX_TRANSITION_EDGES", 1):
            record = self.build()
            self.assertEqual(record["status"], "INCOMPLETE")
            self.assertEqual(record["reason"], "FINITE_EDGE_CAP_INCOMPLETE")
            self.assertIsNone(record["risk_upper"])
            self.assertFalse(verify_finite_certificate(record, self.fixture)["bellman_checked"])


if __name__ == "__main__":
    unittest.main()
