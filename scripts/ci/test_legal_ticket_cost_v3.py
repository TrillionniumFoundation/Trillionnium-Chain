#!/usr/bin/env python3
"""Synthetic reader controls only; these do not execute or qualify a miner."""
import copy
import unittest

from check_legal_ticket_cost_v3 import ARMS, PHASES, RECURRING, SCHEMA, parsed, summed, validate


def control():
    zero = {"wall_ns": 0, "process_cpu_ns": 0}
    step = {"wall_ns": 1, "process_cpu_ns": 1}
    begin = dict(schema=SCHEMA, kind="begin", searches=64, attempts=8, rounds=2, seed=1,
                 budget_seconds=240, native_workers=1, positive_legal_tickets_only=True,
                 standalone_verifier_added_to_native_admission=False, settings_setup=zero)
    for key in ("gpu_measured", "energy_measured", "hardware_batching_measured",
                "hardware_authenticated", "exclusive_host", "global_minimum_proved"):
        begin[key] = False
    rows = [begin]
    for round_id in (0, 1):
        for reuse in (False, True):
            for order, arm in enumerate(ARMS if round_id == 0 else ARMS[::-1]):
                searches, retained = [], []
                for i in range(64):
                    pid = f"{1 + i + round_id * 64:064x}"
                    searches.append(dict(search=i, won=True, trials=[dict(trial=0,
                        nonce=(1 << 32) + round_id * (1 << 24) + i * 8,
                        challenge="01" * 32, proof_sha256="02" * 32, ticket="03" * 32,
                        target_hit=True, generation=step, native_admission=step,
                        packet_id=pid, packet_bytes=50000)]))
                    retained.append(dict(id=pid, sha256="04" * 32, bytes=50000))
                phases = {name: dict(step) for name in PHASES}
                phases["all_attempt_generation"] = {"wall_ns": 64, "process_cpu_ns": 64}
                phases["first_native_admission"] = {"wall_ns": 64, "process_cpu_ns": 64}
                rows.append(dict(schema=SCHEMA, kind="cohort", status="complete", round=round_id,
                    reuse=reuse, strategy=arm, order=order, fresh_store=True, template_seed_admitted=False,
                    standalone_verifier_added_to_native_admission=False, explicit_activation_calls=0,
                    hot_active_before_close=dict(id="10" * 32, generation=1),
                    cold_recovery_active=dict(id=f"{1 + round_id * 64:064x}", generation=2),
                    cold_recovery_selected_height=1,
                    search_horizon=64, attempt_budget=8, producer_setup_calls=1 if reuse else 64,
                    parent="10" * 32, target="ff" * 32, task="11" * 32,
                    native_template_header="12" * 318, stream_sha256=f"{round_id+1:064x}",
                    phases=phases, all_exclusive_phases=summed(phases.values()),
                    recurring_producer_encode_admission=summed(phases[name] for name in RECURRING),
                    observed_outer=dict(wall_ns=1000, process_cpu_ns=1000), searches=searches,
                    retained_packets=retained, attempts=64, winners=64, exhausted=0,
                    first_native_admissions=64, cold_packet_readbacks=64))
    rows.append(dict(schema=SCHEMA, kind="terminal", status="complete", cohorts=8, wall_ns=10000,
                     production_qualified=False, global_minimum_proved=False, active_chain_rewards_measured=False))
    return rows


class Reader(unittest.TestCase):
    def test_positive_and_explicit_cross_cohort_repeats(self):
        result = validate(control())
        self.assertEqual(result["first_admission_calls"], 512)
        self.assertEqual(result["distinct_fixture_packet_ids_across_paired_cohorts"], 128)

    def reject(self, change):
        rows = copy.deepcopy(control())
        change(rows)
        with self.assertRaises((ValueError, KeyError)):
            validate(rows)

    def test_duplicate_and_missing_first_admission(self):
        self.reject(lambda r: r[1]["searches"][1]["trials"][0].update(packet_id=r[1]["searches"][0]["trials"][0]["packet_id"]))
        self.reject(lambda r: r[1].update(first_native_admissions=63))

    def test_omitted_cost_or_overlapping_total(self):
        self.reject(lambda r: r[1]["phases"]["template_acquisition"].update(wall_ns=0))
        self.reject(lambda r: r[1]["observed_outer"].update(wall_ns=1))
        self.reject(lambda r: r[1].update(standalone_verifier_added_to_native_admission=True))

    def test_partial_grid_late_terminal_and_false_success(self):
        self.reject(lambda r: r.pop(2))
        self.reject(lambda r: r[-1].update(wall_ns=240_000_000_001))
        self.reject(lambda r: r[-1].update(status="failed"))

    def test_changed_stream_invalid_ticket_or_short_miss(self):
        self.reject(lambda r: r[2].update(stream_sha256="00" * 32))
        self.reject(lambda r: r[1].update(target="00" * 32))
        self.reject(lambda r: r[1]["searches"][0].update(won=False))

    def test_missing_cold_bytes_and_false_rewards(self):
        self.reject(lambda r: r[1]["retained_packets"].pop())
        self.reject(lambda r: r[1].update(explicit_activation_calls=64))
        self.reject(lambda r: r[1]["cold_recovery_active"].update(id=r[1]["parent"]))
        self.reject(lambda r: r[1]["retained_packets"][0].update(bytes=1))
        self.reject(lambda r: r[0].update(global_minimum_proved=True))

    def test_unknown_cpu_remains_unknown(self):
        rows = control()
        for row in rows[1:-1]:
            row["phases"]["node_open"]["process_cpu_ns"] = None
            row["all_exclusive_phases"]["process_cpu_ns"] = None
        result = validate(rows)
        self.assertIsNone(result["groups"][0]["all_phases"]["process_cpu_ns"])

    def test_duplicate_keys_and_nonfinite_json(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                parsed(raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
