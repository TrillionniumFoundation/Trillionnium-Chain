#!/usr/bin/env python3
"""Synthetic evidence-reader controls; these execute no miner or native gate."""
import copy
import unittest

from check_legal_ticket_cost_v5 import (
    ALL_ARMS, ARMS, COHORTS, HORIZONS, LEGAL_INDICES, PHASES, RECURRING,
    SCHEMA, parsed, summed, validate,
)


def control():
    zero = dict(wall_ns=0, process_cpu_ns=0)
    step = dict(wall_ns=1, process_cpu_ns=1)
    begin = dict(schema=SCHEMA, kind="begin", horizons=list(HORIZONS),
        arms=list(ALL_ARMS), legal_arm_indices=list(LEGAL_INDICES),
        support_probe=[dict(strategy=arm, strategy_index=i, supported=i in LEGAL_INDICES,
                            preparation=dict(step)) for i, arm in enumerate(ALL_ARMS)],
        support_matrix_material=dict(step), attempts=8, rounds=2, seed=1,
        budget_seconds=600, native_workers=1, positive_legal_tickets_only=True,
        standalone_verifier_added_to_native_admission=False, settings_setup=zero)
    for key in ("gpu_measured", "energy_measured", "hardware_batching_measured",
                "hardware_authenticated", "exclusive_host", "global_minimum_proved"):
        begin[key] = False
    rows = [begin]
    for round_id in (0, 1):
        for horizon_index, horizon in enumerate(HORIZONS):
            for reuse in (False, True):
                arms = list(ARMS if round_id == 0 else ARMS[::-1])
                rotation = (horizon_index + int(reuse)) % len(arms)
                arms = arms[rotation:] + arms[:rotation]
                for order, arm in enumerate(arms):
                    searches, retained = [], []
                    for i in range(horizon):
                        pid = f"{1 + round_id * (1 << 24) + horizon * 4096 + i:064x}"
                        searches.append(dict(search=i, won=True, trials=[dict(trial=0,
                            nonce=(1 << 32) + round_id * (1 << 24) + horizon * 4096 + i * 8,
                            challenge="01" * 32, proof_sha256="02" * 32, ticket="03" * 32,
                            target_hit=True, generation=dict(step), native_admission=dict(step),
                            packet_id=pid, packet_bytes=50000)]))
                        retained.append(dict(id=pid, sha256="04" * 32, bytes=50000))
                    phases = {name: dict(step) for name in PHASES}
                    for name in ("all_attempt_generation", "first_native_admission"):
                        phases[name] = dict(wall_ns=horizon, process_cpu_ns=horizon)
                    rows.append(dict(schema=SCHEMA, kind="cohort", status="complete", round=round_id,
                        reuse=reuse, strategy=arm, strategy_index=ALL_ARMS.index(arm), order=order,
                        fresh_store=True, template_seed_admitted=False,
                        standalone_verifier_added_to_native_admission=False, explicit_activation_calls=0,
                        hot_active_before_close=dict(id="10" * 32, generation=1),
                        cold_recovery_active=dict(id=retained[0]["id"], generation=2),
                        cold_recovery_selected_height=1, search_horizon=horizon, attempt_budget=8,
                        producer_setup_calls=1 if reuse else horizon,
                        parent="10" * 32, target="ff" * 32, task="11" * 32,
                        native_template_header="12" * 318,
                        stream_sha256=f"{round_id * 1000 + horizon:064x}",
                        phases=phases, all_exclusive_phases=summed(phases.values()),
                        recurring_producer_encode_admission=summed(phases[name] for name in RECURRING),
                        observed_outer=dict(wall_ns=10000, process_cpu_ns=10000), searches=searches,
                        retained_packets=retained, attempts=horizon, winners=horizon, exhausted=0,
                        first_native_admissions=horizon, cold_packet_readbacks=horizon))
    rows.append(dict(schema=SCHEMA, kind="terminal", status="complete", cohorts=COHORTS,
        wall_ns=100000, production_qualified=False, global_minimum_proved=False,
        active_chain_rewards_measured=False))
    return rows


class Reader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = control()

    def reject(self, change):
        rows = copy.deepcopy(self.original)
        change(rows)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            validate(rows)

    def test_complete_roster_distinct_horizons_and_paired_denominators(self):
        result = validate(copy.deepcopy(self.original))
        self.assertEqual(result["cohorts"], 144)
        self.assertEqual(result["first_admission_calls"], 2 * 329 * 2 * 9)
        self.assertEqual(result["distinct_fixture_packet_ids_across_paired_cohorts"], 658)
        self.assertEqual(len(result["comparisons"]), 8)
        self.assertTrue(result["global_probe_charged_by_full_native_capture"])
        self.assertFalse(result["global_probe_arbitrarily_amortized_per_strategy"])

    def test_missing_slow_arm_or_horizon_cannot_shrink_complete_grid(self):
        self.reject(lambda r: r.pop(2))
        self.reject(lambda r: r[0].update(horizons=[1, 8, 64]))
        self.reject(lambda r: r[0].update(legal_arm_indices=list(LEGAL_INDICES[1:])))

    def test_unsupported_constructor_cannot_be_omitted_or_fallback(self):
        self.reject(lambda r: r[0]["support_probe"].pop(2))
        self.reject(lambda r: r[0]["support_probe"][2].update(supported=True))
        self.reject(lambda r: r[0]["support_probe"][2].update(strategy="prepared-generic"))

    def test_original_ticket_predicate_and_failed_attempt_denominator(self):
        self.reject(lambda r: r[1].update(target="00" * 32))
        self.reject(lambda r: r[1]["searches"][0].update(won=False))
        self.reject(lambda r: r[1].update(attempts=0))

    def test_setup_reuse_is_actual_and_balanced_order_is_frozen(self):
        self.reject(lambda r: r[19].update(producer_setup_calls=1))
        self.reject(lambda r: r[1].update(order=1))
        self.reject(lambda r: r.__setitem__(slice(1, 3), [r[2], r[1]]))

    def test_cross_horizon_nonce_reuse_and_changed_stream_are_rejected(self):
        self.reject(lambda r: r[19]["searches"][0]["trials"][0].update(
            nonce=r[1]["searches"][0]["trials"][0]["nonce"]))
        self.reject(lambda r: r[2].update(stream_sha256="ff" * 32))

    def test_duplicate_admission_and_missing_cold_bytes(self):
        self.reject(lambda r: r[19]["searches"][1]["trials"][0].update(
            packet_id=r[19]["searches"][0]["trials"][0]["packet_id"]))
        self.reject(lambda r: r[1]["retained_packets"].pop())
        self.reject(lambda r: r[1]["retained_packets"][0].update(bytes=49999))
        self.reject(lambda r: r[1]["cold_recovery_active"].update(id=r[1]["parent"]))

    def test_omitted_setup_and_double_counted_verifier_are_rejected(self):
        self.reject(lambda r: r[1]["phases"]["template_acquisition"].update(wall_ns=0))
        self.reject(lambda r: r[1]["observed_outer"].update(wall_ns=1))
        self.reject(lambda r: r[1].update(standalone_verifier_added_to_native_admission=True))

    def test_unknown_cpu_stays_unknown_and_cannot_win_ranking(self):
        rows = copy.deepcopy(self.original)
        for row in rows[1:-1]:
            if row["strategy"] == "maintenance-limb":
                row["phases"]["node_open"]["process_cpu_ns"] = None
                row["all_exclusive_phases"]["process_cpu_ns"] = None
        result = validate(rows)
        for comparison in result["comparisons"]:
            self.assertNotIn("maintenance-limb", comparison["observed_cpu_order"])
            self.assertIsNone(comparison["arms_ms_per_first_admission"]
                              ["maintenance-limb"]["all_phases"]["process_cpu_ms"])

    def test_false_hardware_reward_optimum_or_late_success_is_rejected(self):
        self.reject(lambda r: r[0].update(hardware_batching_measured=True))
        self.reject(lambda r: r[0].update(global_minimum_proved=True))
        self.reject(lambda r: r[-1].update(active_chain_rewards_measured=True))
        self.reject(lambda r: r[-1].update(wall_ns=600_000_000_001))
        self.reject(lambda r: r[-1].update(status="failed"))

    def test_duplicate_keys_nonfinite_json_and_boolean_horizon_are_rejected(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                parsed(raw)
        self.reject(lambda r: r[1].update(search_horizon=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
