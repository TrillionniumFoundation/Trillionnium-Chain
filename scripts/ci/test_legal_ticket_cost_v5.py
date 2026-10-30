#!/usr/bin/env python3
"""Synthetic evidence-reader controls; these execute no miner or native gate."""
import copy
import hashlib
import unittest

from check_legal_ticket_cost_v5 import (
    ALL_ARMS, ARMS, COHORTS, HORIZONS, LEGAL_INDICES, PHASES, RECURRING,
    SCHEMA, NATIVE_TEMPLATE_SHA256, PACKET_BYTES, parsed, summed, validate,
)


# Exact native fixture from the original source-bound x64 V5 capture. Synthetic
# controls below change timings/tickets, not this fixed original header identity.
NATIVE_TEMPLATE = bytes.fromhex(
    "504e483101009842a2a7d6bcae8d68f2617468764e21254b1cf9172e617e9973e9af10b5b728"
    "19f7b4296c8fa634c406d72ede52645f036b0ae8508e5f8be6cba71ba821540b"
    "b9c8aac2d0a09a9ad0d5074499d2e6083ae1c94d81014c84d7e2fae001de3550"
    "01000000000000001bf9496b00000000"
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "bcf78c3e466a88caea8cf400afcf0dbe72054b679a4c78d49f293c08912afbf8"
    "60b273ffeb6f5a0a175febce9cb53af426cfc39b6ea148f7388787d5820f03f9c"
    "738299e3c7e1e83c1e16a0879aa81298cb07e3ce97f8be632f79ebea850ec58"
    "46a9bb54c0007a11eec350e7d89cf977fab719cc8add711d9aa7b431616c4be6"
    "c982eea0545c228d0bf48d6d06e623020b4031f2ba79da56cc6bdccde2c63496"
    "0300000000000000")


def fixture_challenge(nonce, template=NATIVE_TEMPLATE):
    # Independent literal framing and one actual native golden challenge below;
    # do not use the reader's challenge function to build its positive controls.
    raw = template[:-8] + nonce.to_bytes(8, "little")
    return hashlib.sha256(b"TRNM-PON1\0\x09\x00challenge\x3e\x01\x00\x00" + raw).hexdigest()


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
                        nonce = (1 << 32) + round_id * (1 << 24) + horizon * 4096 + i * 8
                        searches.append(dict(search=i, won=True, trials=[dict(trial=0,
                            nonce=nonce, challenge=fixture_challenge(nonce),
                            proof_sha256="02" * 32, ticket="03" * 32,
                            target_hit=True, generation=dict(step), native_admission=dict(step),
                            packet_id=pid, packet_bytes=PACKET_BYTES)]))
                        retained.append(dict(id=pid, sha256="04" * 32, bytes=PACKET_BYTES))
                    phases = {name: dict(step) for name in PHASES}
                    for name in ("all_attempt_generation", "first_native_admission"):
                        phases[name] = dict(wall_ns=horizon, process_cpu_ns=horizon)
                    rows.append(dict(schema=SCHEMA, kind="cohort", status="complete", round=round_id,
                        reuse=reuse, strategy=arm, strategy_index=ALL_ARMS.index(arm), order=order,
                        fresh_store=True, template_seed_admitted=False,
                        standalone_verifier_added_to_native_admission=False, explicit_activation_calls=0,
                        hot_active_before_close=dict(id=NATIVE_TEMPLATE[70:102].hex(), generation=1),
                        cold_recovery_active=dict(id=retained[0]["id"], generation=2),
                        cold_recovery_selected_height=1, search_horizon=horizon, attempt_budget=8,
                        producer_setup_calls=1 if reuse else horizon,
                        parent=NATIVE_TEMPLATE[70:102].hex(), target=NATIVE_TEMPLATE[118:150].hex(),
                        task=NATIVE_TEMPLATE[278:310].hex(), native_template_header=NATIVE_TEMPLATE.hex(),
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


def exhausted_control(rounds=(0,)):
    """A whole paired horizon exhausts; none of its eight misses disappears."""
    rows = control()
    for row in rows[1:-1]:
        if row["round"] not in rounds or row["search_horizon"] != 1:
            continue
        first = row["searches"][0]["trials"][0]
        trials = []
        for trial in range(8):
            attempted = {key: copy.deepcopy(value) for key, value in first.items()
                         if key not in ("packet_id", "packet_bytes", "native_admission")}
            attempted.update(trial=trial, nonce=first["nonce"] + trial,
                             challenge=fixture_challenge(first["nonce"] + trial),
                             ticket="ff" * 32, target_hit=False)
            trials.append(attempted)
        row.update(searches=[dict(search=0, won=False, trials=trials)],
                   retained_packets=[], attempts=8, winners=0, exhausted=1,
                   first_native_admissions=0, cold_packet_readbacks=0,
                   cold_recovery_active=dict(id=row["parent"], generation=2),
                   cold_recovery_selected_height=0)
        for name, value in (("all_attempt_generation", 8), ("packet_encoding", 0),
                            ("first_native_admission", 0), ("cold_packet_readback", 0)):
            row["phases"][name] = dict(wall_ns=value, process_cpu_ns=value)
        row["all_exclusive_phases"] = summed(row["phases"].values())
        row["recurring_producer_encode_admission"] = summed(row["phases"][name] for name in RECURRING)
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

    def test_original_native_header_and_challenge_golden(self):
        self.assertEqual(len(NATIVE_TEMPLATE), 318)
        self.assertEqual(hashlib.sha256(NATIVE_TEMPLATE).hexdigest(), NATIVE_TEMPLATE_SHA256)
        self.assertEqual(fixture_challenge((1 << 32) + 4096),
                         "67d66bedd57a60045b72ef27467b980c3acab5fba118c3447eb396b379ea02a0")

    def test_coordinated_wrong_challenges_cannot_hide_in_agreeing_arms(self):
        def change(rows):
            for row in rows[1:-1]:
                for search in row["searches"]:
                    for trial in search["trials"]:
                        trial["challenge"] = "ab" * 32
        self.reject(change)

    def test_coordinated_wrong_target_task_or_header_refuse(self):
        for field, value in (("target", "03" * 32), ("task", "ab" * 32),
                             ("native_template_header", "00" * 318)):
            with self.subTest(field=field):
                self.reject(lambda rows: [row.update({field: value}) for row in rows[1:-1]])

    def test_all_fixed_header_fields_remain_bound_after_challenges_are_rehashed(self):
        for offset in (6, 38, 70, 102, 110, 118, 150, 182, 214, 246, 278, 310):
            def change(rows):
                raw = bytearray(NATIVE_TEMPLATE)
                raw[offset] ^= 1
                for row in rows[1:-1]:
                    row.update(native_template_header=raw.hex(), parent=raw[70:102].hex(),
                               target=raw[118:150].hex(), task=raw[278:310].hex())
                    for search in row["searches"]:
                        for trial in search["trials"]:
                            trial["challenge"] = fixture_challenge(trial["nonce"], bytes(raw))
            with self.subTest(offset=offset):
                self.reject(change)

    def test_exhausted_miss_challenge_is_independently_bound(self):
        rows = exhausted_control()
        for row in rows[1:-1]:
            if row["round"] == 0 and row["search_horizon"] == 1:
                row["searches"][0]["trials"][7]["challenge"] = "ab" * 32
        with self.assertRaisesRegex(ValueError, "attempt challenge"):
            validate(rows)

    def test_all_arms_cannot_replace_complete_packet_length_with_a_short_claim(self):
        def change(rows):
            for row in rows[1:-1]:
                for search in row["searches"]:
                    search["trials"][0]["packet_bytes"] = PACKET_BYTES - 1
                for packet in row["retained_packets"]:
                    packet["bytes"] = PACKET_BYTES - 1
        self.reject(change)

    def test_conditional_target_work_cannot_credit_repeated_siblings_or_claim_replay(self):
        result = validate(copy.deepcopy(self.original))
        binding = result["context_binding"]
        self.assertEqual(binding["required_work_per_ticket"], 2)
        self.assertEqual(binding["conditional_sibling_work_units_across_repeated_cohorts"],
                         2 * result["first_admission_calls"])
        for name in ("repeated_sibling_observations_are_chainwork_credit",
                     "independent_genesis_application_replay", "full_work_transcripts_replayed",
                     "native_consensus_admission_reexecuted"):
            self.assertIs(binding[name], False)

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

    def test_unchanged_claimed_stream_cannot_hide_different_attempt_records(self):
        for field, value in (("challenge", "a1" * 32), ("proof_sha256", "a2" * 32),
                             ("ticket", "a3" * 32)):
            with self.subTest(field=field):
                self.reject(lambda rows: rows[2]["searches"][0]["trials"][0].update(
                    {field: value}))

    def test_unchanged_claimed_stream_cannot_hide_different_retained_bytes(self):
        self.reject(lambda rows: rows[2]["retained_packets"][0].update(sha256="a4" * 32))

        def change_packet_length(rows):
            rows[2]["searches"][0]["trials"][0]["packet_bytes"] = 50001
            rows[2]["retained_packets"][0]["bytes"] = 50001

        self.reject(change_packet_length)

    def test_exhausted_search_keeps_every_paired_missed_proof(self):
        rows = exhausted_control()
        self.assertEqual(validate(rows)["cohorts"], COHORTS)
        for trial in (0, 7):
            changed = copy.deepcopy(rows)
            changed[2]["searches"][0]["trials"][trial]["proof_sha256"] = "a5" * 32
            with self.subTest(trial=trial), self.assertRaisesRegex(ValueError, "paired attempted"):
                validate(changed)

    def test_paired_observation_allows_different_measured_clocks(self):
        rows = copy.deepcopy(self.original)
        row = rows[2]
        row["searches"][0]["trials"][0]["generation"]["wall_ns"] += 7
        row["phases"]["all_attempt_generation"]["wall_ns"] += 7
        row["all_exclusive_phases"]["wall_ns"] += 7
        row["recurring_producer_encode_admission"]["wall_ns"] += 7
        self.assertEqual(validate(rows)["cohorts"], COHORTS)

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
