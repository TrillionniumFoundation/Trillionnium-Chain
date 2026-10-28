#!/usr/bin/env python3
"""Synthetic negative controls for the independent reader, never native evidence."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import check_pure_pon_pressure_v2 as reader


def cpu_flow(paid=0, credited=0, owners=0):
    return {"schema": "public-v3-local-actual-cpu-flow-v1", "initial_credit_ns": 0,
            "credited_refill_ns": credited, "discarded_refill_ns": 0,
            "booked_reservation_ns": owners * reader.RESERVE,
            "live_debited_cpu_ns": 0, "settlement_residual_cpu_ns": paid,
            "settled_full_cpu_ns": paid, "unsettled_known_live_cpu_ns": 0,
            "paid_cpu_debit_ns": paid, "settlement_discard_ns": 0,
            "remaining_paid_credit_ns": credited - paid,
            "stored_credit_ns": credited - paid - owners * reader.RESERVE,
            "live_owners": owners, "balance_identity_verified": True}


def budget(flow):
    return {"stored_credit_ns": flow["stored_credit_ns"], "in_flight": flow["live_owners"],
            "accounting_unavailable": False, "burst_ns": reader.BURST,
            "start_reserve_ns": reader.RESERVE, "refill_ns_per_second": reader.REFILL,
            "worker_limit": 2}


def admission():
    return {"schema": "public-pure-pon-admission-observation-v2", "waiting": 0,
            "registered": 0, "started": 0, "cancelled": 0,
            "fifo_capacity": 4, "arithmetic_slots": 64, "retained_software_bytes": 3_200_000}


def policy():
    return {"transport_profile": reader.PROFILE, "ticket_bits": 0, "lifetime_ms": 2000,
            "call_deadline_ns": 2_000_000_000, "policy_id": reader.POLICY_ID}


def basic_call(digest, started, ok=False):
    return {"body_digest": digest, "started_ns": started, "ended_ns": started + 100_000_000,
            "deadline_ns": min(reader.WINDOW, started + 2_000_000_000), "thread_cpu_ns": 1000,
            "status": "ok" if ok else "refused", "metrics": {"solution_trials": 0},
            "response": {"solve_trials": 0, "ok": ok}}


def prepared():
    # The reader validates associations, not consensus or signature authority.
    # These intentionally synthetic envelopes must never be used as native proof.
    prefix = b"PNW1" + bytes(reader.PREFIX_BYTES - 4)
    parent, seeds, business = bytes(32), [], []
    for height in range(1, 26):
        header = (b"PNH1\1\0" + bytes(64) + parent + struct.pack("<QQ", height, height * 10)
                  + b"\xff" * 32 + bytes(128) + reader.wire_hash(b"task", bytes(16384), bytes(16384))
                  + struct.pack("<Q", height))
        count = 256 if height <= 4 else (1 if (height - 5) % 7 == 0 else 0)
        transactions = [bytes([height]) * 159 for _ in range(count)]
        raw = (header + struct.pack("<H", count)
               + b"".join(struct.pack("<H", len(tx)) + tx for tx in transactions)
               + prefix + bytes([height]) * 32)
        parent = reader.wire_hash(b"block", header, raw[-32:])
        (seeds if height <= 4 else business).append(raw.hex())
    return {"schema": reader.SCHEMA, "seed_transfers": 1024, "seed_blocks": 4, "business_blocks": 21,
            "seed": seeds, "business": business}


def native_record(digest, connection, accepted):
    return {"connection_id": connection, "operation": 1, "body_digest": list(bytes.fromhex(digest)),
            "complete": True, "observation_failed": False, "dispatch_accepted": accepted,
            "dispatch_thread_cpu_ns": 1_000_000, "full_work_accepted": accepted,
            "full_work_thread_cpu_ns": 500_000,
            "work_arithmetic": {"completed": True, "slots": 64, "retained_software_bytes": 3_200_000,
                                "arithmetic": {"exact_fact_found": False, "transcript_entered": True, "transcript_completed": True,
                                               "publication": "trace"}}}


def phase(name, business):
    initial, final = cpu_flow(), cpu_flow(6_000_000_000, 7_500_000_000)
    result = {"schema": reader.SCHEMA, "phase": name, "window_ns": reader.WINDOW,
              "epoch_monotonic_ns": 100 + reader.PHASES.index(name), "policy": policy(),
              "listeners": 2, "shared_cpu_domain": True, "ready_actors": 0 if name == "baseline" else 24,
              "initial_budget": budget(initial), "initial_flow": initial, "initial_admission": admission(),
              "final_budget": budget(final), "final_flow": final, "final_admission": admission(),
              "services": [{"Ok": {"mutation_cpu_clock_failures": 0}} for _ in range(2)],
              "actors": [], "submissions": [], "history": [], "rounds": [], "samples": [],
              "observations": [], "receiver_tip": business[-1]["id"], "client_tip": business[-1]["id"],
              "receiver_height": 25, "client_height": 25, "errors": [],
              "public_fairness_qualified": False, "production_qualified": False,
              "work_hardness_qualified": False, "installation_authorized": False}
    native, rejected = [[], []], [[], [], []]
    if name != "baseline":
        for actor in range(24):
            rows = []
            for sequence in range(3):
                nonce = 10_000_000 + actor * 1_000_000 + (0 if name == "from-zero" else sequence)
                header = business[0]["header"][:310] + struct.pack("<Q", nonce)
                challenge = reader.wire_hash(b"challenge", header)
                trace = reader.wire_hash(b"pure-pressure-false-trace-v2", challenge,
                                         struct.pack("<Q", sequence), bytes(8))
                txs = business[0]["transactions"]
                raw = (header + struct.pack("<H", len(txs))
                       + b"".join(struct.pack("<H", len(tx)) + tx for tx in txs)
                       + business[0]["proof"][:-32] + trace)
                digest = reader.body_digest({"op": "submit", "packet": raw.hex()})
                row = basic_call(digest, 1_400_000_000 + sequence * 4_000_000_000)
                row.update(sequence=sequence, header=header.hex(), trace=trace.hex(), generation_trials=1,
                           packet_sha256=hashlib.sha256(raw).hexdigest())
                rows.append(row)
                connection, listener = actor * 3 + sequence, actor % 2
                native[listener].append(native_record(digest, connection, False))
                rejected[sequence].append({"listener": listener, "connection_id": connection,
                                           "body_digest": digest, "dispatch_thread_cpu_ns": 1_000_000})
            value = {"actor": actor, "mode": name, "policy": policy(), "finished_ns": reader.WINDOW,
                     "acquisition": {"proof_prefix": business[0]["proof"][:-32].hex(),
                                     "correct_product_acquired_once": name != "from-zero"},
                     "diagnostic_rejection": "Transcript", "calls": rows, "attempt_cap_reached": False}
            result["actors"].append({"exit_success": True, "parent_forced_kill": False,
                                     "report": {"error": None, "result": value}})
    cumulative = []
    for index in range(3):
        start, end = 1_000_000_000 + index * 4_000_000_000, 3_000_000_000 + index * 4_000_000_000
        for j in range(7):
            n = index * 7 + j
            row = basic_call(business[n]["body"], start + 100_000_000 + j * 100_000_000, True)
            row["packet_index"] = n
            result["submissions"].append(row)
            native[n % 2].append(native_record(business[n]["body"], 1000 + n, True))
        request = {"op": "history", "tip": business[index * 7 + 6]["id"], "after": "00" * 32}
        history = basic_call(reader.body_digest(request), start + 1_000_000_000, True)
        history.update(request=request,
                       client_import={"started_ns": start + 1_200_000_000,
                                      "ended_ns": start + 1_300_000_000, "succeeded": True},
                       client_confirmation={"started_ns": start + 1_400_000_000,
                                            "ended_ns": start + 1_500_000_000, "succeeded": True})
        result["history"].append(history)
        sample_flow = cpu_flow(2_300_000_000, 2_350_000_000) if index == 2 else cpu_flow(100_000_000, 200_000_000)
        sample = {"started_ns": start + 500_000_000, "ended_ns": start + 501_000_000,
                  "budget": budget(sample_flow), "flow": sample_flow, "admission": admission(),
                  "clock_failures": 0, "depleted": index == 2}
        result["samples"].append(sample)
        before = {"started_ns": start, "ended_ns": start + 1, "rejections": cumulative.copy()}
        cumulative.extend(rejected[index])
        after = {"started_ns": end - 1, "ended_ns": end, "rejections": cumulative.copy()}
        result["rounds"].append({"round": index, "scheduled_ns": start, "started_ns": start, "ended_ns": end,
                                  "tip": business[index * 7 + 6]["id"], "included_block": business[index * 7]["id"],
                                  "transaction": reader.wire_hash(b"tx-id", business[index * 7]["transactions"][0]).hex(),
                                  "observation": {"confirmed": True, "finalized": False,
                                                  "execution_authority": False, "depth": 6, "reorged": False,
                                                  "transaction": reader.wire_hash(b"tx-id", business[index * 7]["transactions"][0]).hex(),
                                                  "included_block": business[index * 7]["id"],
                                                  "observed_tip": business[index * 7 + 6]["id"],
                                                  "included_height": business[index * 7]["height"],
                                                  "observed_height": business[index * 7 + 6]["height"],
                                                  "network": business[index * 7]["header"][6:38].hex(),
                                                  "parameters": business[index * 7]["header"][38:70].hex()},
                                  "confirmed_inside_pressure_window": True, "hostile_before": before,
                                  "hostile_after": after, "depletion_observed_during_round": index == 2,
                                  "overlapping_attack_calls": 0 if name == "baseline" else 24})
    for records in native:
        result["observations"].append({"coverage_complete": True, "snapshot": {
            "capacity": 16384, "records": records, "accepted_connections_seen": len(records),
            "records_not_retained": 0, "measurement_failures": 0, "counter_overflow": False}})
    return result


class QualificationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = prepared()
        cls.business = reader.preparation(cls.prepared)
        cls.base = phase("correct-product-false-trace", cls.business)

    def test_synthetic_complete_fixture_and_fixed_churn(self):
        report = reader.check_phase(self.base, self.business)
        self.assertTrue(report["finite_qualification"])
        self.assertEqual(report["fresh_challenges_actually_published"], 72)

    def test_complete_campaign_roundtrips_sorted_report_maps(self):
        phases = [phase(name, self.business) for name in reader.PHASES]
        manifest = {"schema": reader.SCHEMA, "window_ns": reader.WINDOW, "attackers": 24,
                    "actor_call_cap": 480, "rounds": 3, "policy": policy(),
                    "phases": [{"phase": name, "file": name + ".json", "all_rounds_confirmed": True}
                               for name in reader.PHASES], "public_fairness_qualified": False,
                    "production_qualified": False, "work_hardness_qualified": False,
                    "installation_authorized": False}
        actual = json.loads(json.dumps(phases, sort_keys=True))
        self.assertTrue(reader.check(manifest, self.prepared, actual)["finite_qualification"])

    def test_reservations_are_not_paid_exhaustion(self):
        value = copy.deepcopy(self.base)
        f = cpu_flow(2_000_000_000, 2_150_000_000, 2)
        value["samples"][2].update(flow=f, budget=budget(f))
        with self.assertRaisesRegex(ValueError, "reservation-only"):
            reader.check_phase(value, self.business)

    def test_depletion_after_honest_work_does_not_qualify(self):
        value = copy.deepcopy(self.base)
        value["samples"][2].update(started_ns=12_000_000_000, ended_ns=12_001_000_000)
        value["rounds"][2]["depletion_observed_during_round"] = False
        report = reader.check_phase(value, self.business)
        self.assertTrue(report["service_qualified"])
        self.assertFalse(report["finite_qualification"])

    def test_aggregate_attack_totals_do_not_establish_overlap(self):
        value = copy.deepcopy(self.base)
        value["rounds"][0]["hostile_after"]["rejections"] = []
        report = reader.check_phase(value, self.business)
        self.assertFalse(report["finite_qualification"])

    def test_client_overlap_without_receiver_paid_work_is_insufficient(self):
        value = copy.deepcopy(self.base)
        for row in value["rounds"]:
            for snapshot in (row["hostile_before"], row["hostile_after"]):
                for rejection in snapshot["rejections"]:
                    rejection["dispatch_thread_cpu_ns"] = 0
        for captured in value["observations"]:
            for row in captured["snapshot"]["records"]:
                if not row["dispatch_accepted"]:
                    row["dispatch_thread_cpu_ns"] = 0
        self.assertFalse(reader.check_phase(value, self.business)["finite_qualification"])

    def test_only_64_published_contexts_cannot_claim_churn(self):
        value = copy.deepcopy(self.base)
        erased = 0
        for captured in value["observations"]:
            for row in captured["snapshot"]["records"]:
                if row["dispatch_accepted"] is False and erased < 8:
                    row["work_arithmetic"]["arithmetic"]["publication"] = "contended"
                    erased += 1
        report = reader.check_phase(value, self.business)
        self.assertTrue(report["service_qualified"])
        self.assertEqual(report["fresh_challenges_actually_published"], 64)
        self.assertFalse(report["finite_qualification"])

    def test_repeat_trace_class_is_not_fresh_header_churn(self):
        value = phase("from-zero", self.business)
        result = reader.check_phase(value, self.business)
        self.assertEqual(result["fresh_challenges_actually_published"], 24)
        self.assertFalse(result["fixed_64_slot_churn_qualified"])
        self.assertFalse(result["fixed_64_slot_churn_required"])
        self.assertTrue(result["finite_qualification"])

    def test_late_confirmation_cannot_be_relabelled_on_time(self):
        value = copy.deepcopy(self.base)
        value["rounds"][2]["ended_ns"] = reader.WINDOW
        with self.assertRaisesRegex(ValueError, "late or invented"):
            reader.check_phase(value, self.business)

    def test_late_successful_submit_or_history_cannot_qualify_and_tail_is_retained(self):
        for section in ("submissions", "history"):
            with self.subTest(section=section):
                value = copy.deepcopy(self.base)
                row = value[section][0]
                row["ended_ns"] = row["deadline_ns"] + 1
                self.assertFalse(reader.call(row))
                report = reader.check_phase(value, self.business)
                self.assertFalse(report["service_qualified"])
                self.assertFalse(report["finite_qualification"])
                self.assertEqual(value[section][0]["ended_ns"], row["deadline_ns"] + 1)

    def test_expired_attack_call_tail_is_not_an_extended_live_request(self):
        value = copy.deepcopy(self.base)
        for actor in value["actors"]:
            row = actor["report"]["result"]["calls"][2]
            row.update(started_ns=6_000_000_000, deadline_ns=8_000_000_000, ended_ns=12_000_000_000)
        value["rounds"][1]["overlapping_attack_calls"] = 48
        value["rounds"][2]["overlapping_attack_calls"] = 0
        report = reader.check_phase(value, self.business)
        self.assertTrue(report["service_qualified"])
        self.assertFalse(report["finite_qualification"])
        self.assertEqual(report["rounds"][2]["attack_calls_overlapping"], 0)
        self.assertEqual(report["rounds"][2]["attack_calls_including_physical_tails_overlapping"], 24)
        self.assertEqual(report["attack_calls"], 72)

    def test_actual_late_local_confirmation_stays_visible_but_unqualified(self):
        value = copy.deepcopy(self.base)
        value["rounds"][2].update(ended_ns=reader.WINDOW + 2, confirmed_inside_pressure_window=False)
        value["history"][2]["client_confirmation"]["ended_ns"] = reader.WINDOW + 1
        result = reader.check_phase(value, self.business)
        self.assertFalse(result["finite_qualification"])
        self.assertFalse(result["rounds"][2]["confirmed"])

    def test_known_failure_is_retained_without_qualification(self):
        value = copy.deepcopy(self.base)
        value["rounds"][2]["observation"] = None
        value["rounds"][2]["confirmed_inside_pressure_window"] = False
        result = reader.check_phase(value, self.business)
        self.assertFalse(result["service_qualified"])
        self.assertFalse(result["finite_qualification"])

    def test_hashcash_deadline_extra_credit_and_split_domain_rejected(self):
        controls = [("policy", "ticket_bits", 8), ("policy", "lifetime_ms", 3000),
                    ("policy", "policy_id", "ab" * 32),
                    ("initial_flow", "initial_credit_ns", reader.BURST),
                    ("final_budget", "worker_limit", 3)]
        for section, key, changed in controls:
            with self.subTest(section=section, key=key):
                value = copy.deepcopy(self.base)
                value[section][key] = changed
                with self.assertRaises(ValueError):
                    reader.check_phase(value, self.business)
        value = copy.deepcopy(self.base)
        value["shared_cpu_domain"] = False
        with self.assertRaisesRegex(ValueError, "split CPU"):
            reader.check_phase(value, self.business)

    def test_duplicate_and_nonfinite_json_are_rejected_before_interpretation(self):
        examples = [b'{"schema":"wrong","schema":"pon-pure-pressure-v2"}\n',
                    b'{"policy":{"ticket_bits":8,"ticket_bits":0}}\n',
                    b'{"cpu":NaN}\n', b'{"cpu":Infinity}\n', b'{"cpu":-Infinity}\n',
                    b'{"cpu":1e10000}\n']
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            for raw in examples:
                with self.subTest(raw=raw):
                    path.write_bytes(raw)
                    with self.assertRaisesRegex(ValueError, "duplicate|nonfinite"):
                        reader.load(path)

    def test_bool_and_float_are_not_integer_policy_or_resource_values(self):
        controls = [("policy", "ticket_bits", False), ("policy", "ticket_bits", 0.0),
                    ("policy", "lifetime_ms", 2000.0), ("policy", "call_deadline_ns", 2_000_000_000.0),
                    ("initial_budget", "stored_credit_ns", False),
                    ("initial_budget", "in_flight", False), ("final_budget", "worker_limit", 2.0),
                    ("initial_flow", "initial_credit_ns", False),
                    ("initial_admission", "fifo_capacity", 4.0),
                    ("initial_admission", "arithmetic_slots", 64.0),
                    ("initial_admission", "registered", False)]
        for section, key, changed in controls:
            with self.subTest(section=section, key=key, changed=changed):
                value = copy.deepcopy(self.base)
                value[section][key] = changed
                with self.assertRaises(ValueError):
                    reader.check_phase(value, self.business)
        value = copy.deepcopy(self.base)
        value["submissions"][0]["metrics"]["solution_trials"] = False
        with self.assertRaisesRegex(ValueError, "noninteger"):
            reader.check_phase(value, self.business)
        value = copy.deepcopy(self.base)
        value["services"][0]["Ok"]["mutation_cpu_clock_failures"] = False
        with self.assertRaisesRegex(ValueError, "counter type"):
            reader.check_phase(value, self.business)

    def test_fake_receiver_counter_missing_history_and_extra_authority_rejected(self):
        value = copy.deepcopy(self.base)
        value["rounds"][0]["hostile_after"]["rejections"][0]["connection_id"] = 999999
        with self.assertRaisesRegex(ValueError, "invented receiver"):
            reader.check_phase(value, self.business)
        value = copy.deepcopy(self.base)
        value["history"] = []
        with self.assertRaisesRegex(ValueError, "independent History"):
            reader.check_phase(value, self.business)
        value = copy.deepcopy(self.base)
        value["installation_authorized"] = True
        with self.assertRaisesRegex(ValueError, "unearned"):
            reader.check_phase(value, self.business)

    def test_work_observation_cannot_be_relabelled_as_another_operation(self):
        value = copy.deepcopy(self.base)
        value["observations"][0]["snapshot"]["records"][0]["operation"] = 2
        with self.assertRaisesRegex(ValueError, "different operation"):
            reader.check_phase(value, self.business)

    def test_another_native_confirmation_cannot_be_relabelled_as_this_business(self):
        value = copy.deepcopy(self.base)
        value["rounds"][0]["observation"] = value["rounds"][1]["observation"].copy()
        with self.assertRaisesRegex(ValueError, "native observation identity/context"):
            reader.check_phase(value, self.business)
        for key, changed in (("transaction", "ff" * 32), ("included_block", "ff" * 32),
                             ("observed_tip", "ff" * 32), ("network", "ff" * 32),
                             ("parameters", "ff" * 32), ("included_height", 6),
                             ("observed_height", 12), ("included_height", 5.0),
                             ("observed_height", 11.0), ("reorged", True)):
            with self.subTest(key=key, changed=changed):
                value = copy.deepcopy(self.base)
                value["rounds"][0]["observation"][key] = changed
                with self.assertRaisesRegex(ValueError, "native observation|native confirmation/reorg"):
                    reader.check_phase(value, self.business)

    def test_changed_complete_packet_and_unpaid_hash_trials_rejected(self):
        value = copy.deepcopy(self.base)
        value["actors"][0]["report"]["result"]["calls"][0]["packet_sha256"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "whole-packet"):
            reader.check_phase(value, self.business)
        value = copy.deepcopy(self.base)
        value["actors"][0]["report"]["result"]["calls"][0]["metrics"]["solution_trials"] = 1
        with self.assertRaisesRegex(ValueError, "Hashcash"):
            reader.check_phase(value, self.business)


if __name__ == "__main__":
    unittest.main()
