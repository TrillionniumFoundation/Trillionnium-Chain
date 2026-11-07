"""Independent-reader tests; synthetic event fixtures are not native executions."""
from copy import deepcopy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import w1_native_responsive as reader


def logical_trace(responsive=False):
    """Hand-scheduled trace with prevalidated abstract metadata, not W1 packets.

    The event scheduler below is a literal test history, not the reader's event
    loop. Actual packet legality is covered separately by full native replay.
    """
    identity = lambda number: f"{number:064x}"
    genesis, base, public = map(identity, (1, 2, 3))
    blocks = {
        genesis: {"block_id": genesis, "parent_id": None, "height": 0, "timestamp": 100, "chainwork": 0},
        base: {"block_id": base, "parent_id": genesis, "height": 1, "timestamp": 101, "chainwork": 1},
        public: {"block_id": public, "parent_id": base, "height": 2, "timestamp": 102, "chainwork": 2}}
    histories = {genesis: [blocks[genesis]], base: [blocks[base], blocks[genesis]],
                 public: [blocks[public], blocks[base], blocks[genesis]]}
    fixture = {"public_tip": blocks[public], "prefix": {"tip_id": base,
               "parent_first_headers": [blocks[base], blocks[genesis]]},
               "clock_origin_timestamp": 120, "genesis_timestamp": 100, "contexts": []}
    plan = {"horizon_ticks": 16, "honest_attempt_ticks": 3, "honest_delivery_ticks": 1,
            "honest_tip_notification_ticks": 1, "max_honest_attempts": 6, "max_private_attempts": 2}
    clock = {"candidate_check_ticks": 1 if responsive else 40, "winner_proof_ticks": 1,
             "per_block_propagation_ticks": 1}
    config = {"run_id": "synthetic-reader-trace", "policy": reader.FIXED_POLICY, "seed": 9,
              "private_clock": clock, "execution_kind": "classical-uniform-q0" if responsive else "constructed-quantum",
              "iterations": 0 if responsive else 1}
    events, attempts, active = [], {}, {}

    def event(tick, kind, **fields):
        events.append({"event_index": len(events), "tick": tick, "kind": kind, **fields})

    def start(owner, index, tick, parent, duration, winner=False, opaque=False):
        identifier = owner + "-" + str(index)
        packet = None
        row = {"attempt_id": identifier, "owner": owner, "observer_candidate_generated": not opaque,
               **dict.fromkeys(reader.STAGE_CLOCKS, 0 if opaque else 1)}
        if opaque:
            row["reason"] = "candidate check cannot complete within the declared horizon"
        else:
            height = blocks[parent]["height"] + 1
            block_id = identity(10 + index if owner == "honest" else 30 + index)
            timestamp = (100 + height if owner == "private" else max(blocks[parent]["timestamp"] + 1, 121 + tick // 4))
            packet = {"block_id": block_id, "parent_id": parent, "height": height, "timestamp": timestamp,
                      "nonce": reader.seeded_nonce(9, index, parent, owner), "native_winner": winner}
            row.update(packet=packet, outcome_hidden_until_candidate_due=True, observer_advice=False)
            if winner:
                block = {**packet, "chainwork": blocks[parent]["chainwork"] + 1}
                blocks[block_id], histories[block_id] = block, [block] + histories[parent]
        attempts[identifier] = row
        active[identifier] = {"owner": owner, "parent": parent, "start": tick, "due": tick + duration}
        event(tick, owner + "-start", attempt_id=identifier, owner=owner, parent_id=parent,
              nonce=None if opaque else packet["nonce"], start_tick=tick, due_tick=tick + duration,
              observer_candidate_generated=not opaque)
        return packet

    def complete(identifier, tick, kind):
        row = attempts[identifier]
        event(tick, kind, attempt_id=identifier, owner=row["owner"], packet=row["packet"],
              native_winner=row["packet"]["native_winner"], proof_elapsed_ns=1,
              verification_elapsed_ns=1, actual_cost_reference=identifier,
              actual_cost_counted_once_in_attempt_inventory=True)

    def proof_start(index, tick):
        event(tick, "private-proof-start", owner="private", attempt_id="private-" + str(index),
              start_tick=tick, due_tick=tick + 1, model_phase_only=True)

    def producer(packet, tick):
        event(tick, "private-producer-admit", owner="private", block_id=packet["block_id"],
              admit_activate_elapsed_ns=1, admit_activate_cpu_ns=1)

    def queued(packet, owner, tick, due, index=None):
        fields = {"owner": owner, "block_id": packet["block_id"], "due_tick": due}
        if owner == "private":
            fields["publication_policy"] = "after-two-attempts-parent-first"
        else:
            fields["attempt_id"] = "honest-" + str(index)
        event(tick, "delivery-queued", **fields)

    def delivered(packet, owner, tick, before, after, replacement=False):
        event(tick, "receiver-admit", owner=owner, packet=packet, selected_before=before,
              selected_after=after, selected_work_before_hex=f"{blocks[before]['chainwork']:0128x}",
              selected_work_after_hex=f"{blocks[after]['chainwork']:0128x}", private_replacement=replacement,
              logical_observed_now=121 + tick // 4, admit_activate_elapsed_ns=1, admit_activate_cpu_ns=1)

    def notification(tick, generation, selected, count):
        event(tick, "honest-notification-queued", generation=generation, selected_tip=selected,
              due_tick=tick + 1, visible_packet_count=count)

    def notify(tick, generation, old, new, packets):
        event(tick, "honest-notify", generation=generation, selected_tip=new, old_view_tip=old,
              new_view_tip=new, delivered_packet_ids=[packet["block_id"] for packet in packets],
              admit_activate_elapsed_ns=1, admit_activate_cpu_ns=1)

    def cancel(index, tick, parent):
        identifier = "honest-" + str(index)
        current = active[identifier]
        event(tick, "honest-cancel", attempt_id=identifier, owner="honest", old_parent_id=current["parent"],
              new_parent_id=parent, start_tick=current["start"], cancel_tick=tick, due_tick=current["due"],
              charged_elapsed_ticks=tick - current["start"], reserved_ticks=3, packet=attempts[identifier]["packet"],
              proof_elapsed_ns=1, verification_elapsed_ns=1, actual_cost_reference=identifier,
              actual_eager_cost_charged_in_full=True)

    if responsive:
        p0 = start("private", 0, 0, base, 1, True)
        start("honest", 0, 0, public, 3)
        complete("private-0", 1, "private-check"); proof_start(0, 1)
        complete("private-0", 2, "private-complete"); producer(p0, 2)
        p1 = start("private", 1, 2, p0["block_id"], 1, True)
        complete("honest-0", 3, "honest-complete")
        complete("private-1", 3, "private-check"); proof_start(1, 3)
        h1 = start("honest", 1, 3, public, 3, True)
        complete("private-1", 4, "private-complete"); producer(p1, 4)
        queued(p0, "private", 4, 5); queued(p1, "private", 4, 6)
        delivered(p0, "private", 5, public, public)
        complete("honest-1", 6, "honest-complete"); queued(h1, "honest", 6, 7, 1)
        delivered(p1, "private", 6, public, p1["block_id"], True)
        notification(6, 1, p1["block_id"], 2)
        start("honest", 2, 6, public, 3)
        delivered(h1, "honest", 7, p1["block_id"], p1["block_id"])
        notify(7, 1, public, p1["block_id"], [p0, p1]); cancel(2, 7, p1["block_id"])
        h3 = start("honest", 3, 7, p1["block_id"], 3, True)
        complete("honest-3", 10, "honest-complete"); queued(h3, "honest", 10, 11, 3)
        start("honest", 4, 10, p1["block_id"], 3)
        delivered(h3, "honest", 11, p1["block_id"], h3["block_id"])
        notification(11, 2, h3["block_id"], 4)
        notify(12, 2, p1["block_id"], h3["block_id"], [h1, h3]); cancel(4, 12, h3["block_id"])
        start("honest", 5, 12, h3["block_id"], 3)
        complete("honest-5", 15, "honest-complete")
        final = h3["block_id"]
        private_ids = sorted((p0["block_id"], p1["block_id"]))
        metrics = {"ever_private_replacement": True, "private_tip_at_horizon": False,
                   "private_ancestor_at_horizon": True, "initial_public_block_orphaned_at_horizon": True,
                   "ancestor_includes_tip": True}
    else:
        start("private", 0, 0, base, 40, opaque=True)
        start("honest", 0, 0, public, 3)
        for index in range(5):
            tick = (index + 1) * 3
            complete("honest-" + str(index), tick, "honest-complete")
            start("honest", index + 1, tick, public, 3)
        for identifier in ("honest-5", "private-0"):
            current = active[identifier]
            event(16, "attempt-censored", owner=current["owner"], attempt_id=identifier,
                  start_tick=current["start"], due_tick=current["due"], phase="candidate",
                  charged_elapsed_ticks=16-current["start"], packet=attempts[identifier].get("packet"),
                  actual_cost_reference=identifier, all_observed_cpu_costs_retained=True)
        final, private_ids = public, []
        metrics = {"ever_private_replacement": False, "private_tip_at_horizon": False,
                   "private_ancestor_at_horizon": False, "initial_public_block_orphaned_at_horizon": False,
                   "ancestor_includes_tip": True}
    ancestry, tip = [], final
    while tip is not None:
        ancestry.append(tip)
        tip = blocks[tip]["parent_id"]
    run = {"run_id": config["run_id"], "policy": config["policy"], "seed": 9, "configuration": config,
           "initial_tip": public, "initial_public_block_id": public, "events": events,
           "attempt_inventory": list(attempts.values()), "honest_attempts_started": 6,
           "private_attempts_started": 2 if responsive else 1, "pending_deliveries": [],
           "pending_notifications": [], "final_tip": final, "reopened_tip": final,
           "final_chainwork_hex": f"{blocks[final]['chainwork']:0128x}", "metrics": metrics,
           "private_winning_block_ids": private_ids, "final_ancestry_ids": ancestry,
           "reopened_ancestry_ids": ancestry, "history_replay": dict.fromkeys(
               ("receiver_elapsed_ns", "honest_elapsed_ns", "private_elapsed_ns"), 0),
           "cpu_receipt": {"process_cpu_ns": 100, "wall_ns": 200, "scope": "synthetic unit-test costs only",
                           "eager_observer_work_is_literal_interrupted_miner": False,
                           "exclusive_machine_calibration": False}}
    return fixture, plan, run, config, attempts, blocks, histories


class ResponsiveNativeReaderTests(unittest.TestCase):
    def test_phase_rounding_preserves_original_deadline(self):
        self.assertEqual(reader.ceil_ticks(Fraction(1, 100)), 1)
        self.assertEqual(reader.ceil_ticks(Fraction(4)), 16)
        self.assertEqual(reader.ceil_ticks(Fraction(401, 100)), 17)
        with self.assertRaisesRegex(ValueError, "CLOCK_RANGE"):
            reader.ceil_ticks(Fraction(-1))

    def test_nonce_domain_has_stable_cross_language_vectors(self):
        parent = "07" * 32
        self.assertEqual(reader.seeded_nonce(9, 0, parent, "honest"), 4)
        self.assertEqual(reader.seeded_nonce(9, 0, parent, "private"), 1)
        with self.assertRaises(ValueError):
            reader.seeded_nonce(9, 0, "AB" * 32, "honest")

    def test_quantum_candidate_censor_retains_honest_and_private_costs(self):
        trace = logical_trace()
        result = reader.replay_run_events(*trace)
        self.assertEqual(result["started_attempts"], 7)
        self.assertEqual(result["completed_attempts"], 5)
        self.assertEqual(result["censored_attempts"], 2)
        self.assertEqual(result["modeled_mining_elapsed_ticks"], {"honest": 16, "private": 16})
        self.assertEqual(result["actual_attempt_cpu_ns"], 18)

    def test_live_rebind_stale_arrival_and_honest_descendant(self):
        result = reader.replay_run_events(*logical_trace(True))
        self.assertEqual(result["cancelled_attempts"], 2)
        self.assertEqual(result["honest_cancelled_elapsed_ticks"], 3)
        self.assertEqual(result["modeled_mining_elapsed_ticks"], {"honest": 15, "private": 4})
        self.assertEqual(result["actual_attempt_cpu_ns"], 24)
        self.assertTrue(result["metrics"]["private_ancestor_at_horizon"])
        self.assertFalse(result["metrics"]["private_tip_at_horizon"])

    def test_omitted_event_and_fabricated_extra_event_are_rejected(self):
        for mutate in (lambda events: events.pop(2), lambda events: events.append(deepcopy(events[-1]))):
            trace = logical_trace()
            mutate(trace[2]["events"])
            with self.subTest(length=len(trace[2]["events"])), self.assertRaisesRegex(ValueError, "EVENT"):
                reader.replay_run_events(*trace)

    def test_full_started_inventory_cannot_drop_cancelled_or_censored_cpu_work(self):
        trace = logical_trace(True)
        del trace[4]["honest-2"]
        with self.assertRaisesRegex(ValueError, "MISSING_STARTED_ATTEMPT"):
            reader.replay_run_events(*trace)
        trace = logical_trace()
        trace[2]["cpu_receipt"]["process_cpu_ns"] = 17
        with self.assertRaisesRegex(ValueError, "CPU_COST_SUM"):
            reader.replay_run_events(*trace)

    def test_false_ancestry_metric_and_reopened_chain_are_rejected(self):
        trace = logical_trace(True)
        trace[2]["metrics"]["private_ancestor_at_horizon"] = False
        with self.assertRaisesRegex(ValueError, "FINAL_METRICS"):
            reader.replay_run_events(*trace)
        trace = logical_trace(True)
        trace[2]["reopened_ancestry_ids"] = trace[2]["reopened_ancestry_ids"][1:]
        with self.assertRaisesRegex(ValueError, "REOPEN_OR_TIP"):
            reader.replay_run_events(*trace)

    def test_changed_clock_or_nonce_breaks_causal_event_replay(self):
        trace = logical_trace()
        trace[3]["private_clock"]["candidate_check_ticks"] = 39
        with self.assertRaisesRegex(ValueError, "EVENT_MISMATCH:private-start"):
            reader.replay_run_events(*trace)
        trace = logical_trace(True)
        trace[4]["honest-0"]["packet"]["nonce"] ^= 1
        with self.assertRaisesRegex(ValueError, "CAUSAL_NONCE_OR_PARENT"):
            reader.replay_run_events(*trace)

    def test_wrong_equal_tick_order_and_rebound_parent_are_rejected(self):
        trace = logical_trace(True)
        events = trace[2]["events"]
        at_six = next(i for i, event in enumerate(events) if event["kind"] == "honest-complete" and event["tick"] == 6)
        events[at_six], events[at_six + 2] = events[at_six + 2], events[at_six]
        with self.assertRaisesRegex(ValueError, "EVENT_MISMATCH:honest-complete"):
            reader.replay_run_events(*trace)
        trace = logical_trace(True)
        trace[4]["honest-3"]["packet"]["parent_id"] = trace[0]["public_tip"]["block_id"]
        with self.assertRaisesRegex(ValueError, "CAUSAL_NONCE_OR_PARENT"):
            reader.replay_run_events(*trace)

    def test_duplicate_or_extra_started_attempt_is_rejected(self):
        trace = logical_trace()
        trace[4]["honest-6"] = deepcopy(trace[4]["honest-5"])
        with self.assertRaisesRegex(ValueError, "COMPLETE_ATTEMPT_DENOMINATOR"):
            reader.replay_run_events(*trace)

    def test_timely_quantum_candidate_cannot_be_substituted_with_uniform_cpu_sample(self):
        trace = logical_trace()
        trace[3]["private_clock"]["candidate_check_ticks"] = 1
        with self.assertRaisesRegex(ValueError, "QUANTUM_SAMPLER_UNIMPLEMENTED"):
            reader.replay_run_events(*trace)

    def test_opaque_inventory_has_no_fabricated_proof_or_nonzero_stage_cost(self):
        trace = logical_trace()
        fixture, _, run, config, attempts, blocks, histories = trace
        run["attempt_inventory"] = [attempts["private-0"]]
        with patch.object(reader, "_initial_history", return_value=(blocks, histories)):
            checked = reader.validate_attempt_inventory(Path("unused"), fixture, run, config, {})
            self.assertEqual(list(checked[0]), ["private-0"])
            run["attempt_inventory"][0]["proof_cpu_ns"] = 1
            with self.assertRaisesRegex(ValueError, "OPAQUE_ATTEMPT"):
                reader.validate_attempt_inventory(Path("unused"), fixture, run, config, {})

    def test_cancellation_does_not_give_free_cpu_work_or_fake_physical_timing(self):
        trace = logical_trace(True)
        cancellation = next(row for row in trace[2]["events"] if row["kind"] == "honest-cancel")
        cancellation["actual_eager_cost_charged_in_full"] = False
        with self.assertRaisesRegex(ValueError, "EVENT_MISMATCH:honest-cancel"):
            reader.replay_run_events(*trace)
        trace = logical_trace()
        trace[2]["cpu_receipt"]["exclusive_machine_calibration"] = True
        with self.assertRaisesRegex(ValueError, "CPU_SCOPE"):
            reader.replay_run_events(*trace)

    def test_cached_packet_identity_cannot_be_rebound_to_different_bytes(self):
        row = {"packet_sha256": "a" * 64, "packet_file": "packets/original.pnk"}
        cache = {row["packet_sha256"]: ({}, b"proof", row)}
        corrupt = {**row, "packet_file": "packets/replaced.pnk"}
        with self.assertRaisesRegex(ValueError, "PACKET_RECORD_CHANGED"):
            reader._packet(Path("unused"), corrupt, cache)

    def test_plan_recomputes_clocks_and_keeps_advice_separate(self):
        records = {}
        for architecture in ("classical-host", "serial-lifecycle", "declared-reset-65536-readout-64-v1"):
            for q in ((0,) if architecture == "classical-host" else (0, 1)):
                records[architecture + "-q" + str(q)] = {"record": {
                    "execution_kind": "classical-uniform-q0" if architecture == "classical-host" else "constructed-quantum",
                    "iterations": q, "architecture": architecture}, "projected_clock": {
                    "candidate_check_ticks": 40 if q else 1, "winner_proof_ticks": 4,
                    "per_block_propagation_ticks": 1, "clock_record_sha256": "b" * 64}}
        clocks = {"records": records}
        fixture = {"clock_origin_timestamp": 120}
        with tempfile.TemporaryDirectory() as tmp, patch.object(reader, "sources", return_value={"source": "unit-test"}), \
                patch.object(reader.bridge, "load_fixture", return_value=(fixture, "a" * 64, 0)), \
                patch.object(reader, "clock_records", return_value=clocks):
            directory = Path(tmp)
            raw = reader.json_bytes(clocks)
            (directory / reader.CLOCK_FILE).write_bytes(raw)
            plan = reader.build_plan(fixture, "a" * 64, clocks, hashlib.sha256(raw).hexdigest())
            (directory / reader.PLAN_FILE).write_bytes(reader.json_bytes(plan))
            loaded = reader.load_plan(directory)[1]
            self.assertEqual(len(loaded["runs"]), 12)
            self.assertEqual(sum(row["policy"] == reader.ADVICE_POLICY for row in loaded["runs"]), 4)
            self.assertEqual(loaded["horizon_seconds"], "4")
            self.assertFalse(loaded["claims"]["quantum_hardware_executed"])
            corrupted = deepcopy(plan)
            corrupted["runs"][0]["private_clock"]["candidate_check_ticks"] += 1
            (directory / reader.PLAN_FILE).write_bytes(reader.json_bytes(corrupted))
            with self.assertRaisesRegex(ValueError, "PLAN_CHANGED"):
                reader.load_plan(directory)


if __name__ == "__main__":
    unittest.main()
