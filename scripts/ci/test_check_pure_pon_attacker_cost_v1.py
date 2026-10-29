#!/usr/bin/env python3
"""Synthetic adversarial ledger controls; never measured attack-cost evidence."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest

import check_pure_pon_attacker_cost_v1 as reader
import test_check_pure_pon_pressure_v2 as fixture


def sample(time, cpu):
    return {"started_monotonic_ns": time, "thread_cpu_ns": cpu, "ended_monotonic_ns": time + 1}


def summarize(cost):
    rows = cost["preparations"]
    cpu = reader.cpu_sum([row["preparation_thread_cpu_ns"] for row in rows])
    issued = sum(row["disposition"] == "issued" for row in rows)
    cost["summary"] = {"prepared_attempts": len(rows), "issued_calls": issued,
                       "unissued_preparations": len(rows) - issued,
                       "loop_generation_trials": sum(row["generation_trials"] for row in rows),
                       "known_preparation_thread_cpu_ns": cpu["known_ns"],
                       "unknown_preparation_cpu_count": cpu["unknown_count"],
                       "preparation_thread_cpu_ns": cpu["total_ns"]}


def cost_for(actor, epoch, business, disposition):
    pressure = reader.pressure
    actor["acquisition"]["thread_cpu_ns"] = 30
    actor["diagnostic_thread_cpu_ns"] = 40
    actor["finished_ns"] = pressure.WINDOW + 100
    rows = []
    for sequence, call in enumerate(actor["calls"]):
        call["preparation_thread_cpu_ns"] = 20
        started = epoch + call["started_ns"]
        rows.append({**{k: call[k] for k in ("sequence", "header", "trace", "generation_trials", "packet_sha256")},
                     "iteration_gate_monotonic_ns": started - 40,
                     "begin": sample(started - 30, 1_000 + sequence * 10_000),
                     "end": sample(started - 20, 1_100 + sequence * 10_000),
                     "phase_gate_monotonic_ns": started - 10,
                     "preparation_thread_cpu_ns": 100, "inner_preparation_thread_cpu_ns": 20,
                     "disposition": "issued", "call_entry_monotonic_ns": started,
                     "call_index": sequence, "call_body_digest": call["body_digest"]})
    cutoff, sequence = epoch + pressure.WINDOW, len(rows)
    if disposition != "phase_closed_before_preparation":
        nonce = 10_000_000 + actor["actor"] * 1_000_000
        if actor["mode"] != "from-zero":
            nonce += sequence
        header = business[0]["header"][:310] + struct.pack("<Q", nonce)
        challenge = pressure.wire_hash(b"challenge", header)
        trace = pressure.wire_hash(b"pure-pressure-false-trace-v2", challenge,
                                   struct.pack("<Q", sequence), bytes(8))
        transactions = business[0]["transactions"]
        packet = header + struct.pack("<H", len(transactions)) + b"".join(
            struct.pack("<H", len(tx)) + tx for tx in transactions) + business[0]["proof"][:-32] + trace
        after_preparation = disposition == "phase_closed_after_preparation"
        rows.append({"sequence": sequence, "header": header.hex(), "trace": trace.hex(),
                     "generation_trials": 1, "packet_sha256": hashlib.sha256(packet).hexdigest(),
                     "iteration_gate_monotonic_ns": cutoff - 100,
                     "begin": sample(cutoff - 90, 31_000),
                     "end": sample(cutoff + 5 if after_preparation else cutoff - 20, 31_100),
                     "phase_gate_monotonic_ns": cutoff + 10 if after_preparation else cutoff - 10,
                     "preparation_thread_cpu_ns": 100, "inner_preparation_thread_cpu_ns": 20,
                     "disposition": disposition, "call_index": None, "call_body_digest": None,
                     "call_entry_monotonic_ns": None if after_preparation else cutoff + 10})
    value = {"schema": reader.SCHEMA, "scope": reader.SCOPE,
             "actor": actor["actor"], "pid": actor["pid"], "owner_thread": "ThreadId(2)",
             "mode": actor["mode"], "policy": actor["policy"], "epoch_monotonic_ns": epoch,
             "window_ns": pressure.WINDOW, "actor_call_cap": pressure.CALL_CAP,
             "entry": sample(epoch - 50, 100), "loop_entry": sample(epoch + 10, 200),
             "loop_exit": sample(cutoff + 40, 50_000), "preparations": rows,
             "diagnostic_generation_trials": 1,
             "template_acquisition_search_trials": None, "template_acquisition_search_trials_observed": False,
             "cpu_wall_bracket_tolerance_ns": reader.CPU_WALL_TOLERANCE,
             "physical_cpu_authentication": False,
             "loop_terminal": {"reason": disposition, "sequence": sequence,
                               "observed_monotonic_ns": cutoff + (20 if disposition == "phase_closed_before_preparation" else 10)},
             "public_fairness_qualified": False, "work_hardness_qualified": False,
             "production_qualified": False}
    summarize(value)
    return value


def campaign(disposition="phase_closed_after_preparation"):
    pressure = reader.pressure
    prepared = fixture.prepared()
    business = pressure.preparation(prepared)
    phases = [fixture.phase(name, business) for name in pressure.PHASES]
    manifest = {"schema": pressure.SCHEMA, "window_ns": pressure.WINDOW, "attackers": 24,
                "actor_call_cap": 480, "rounds": 3, "policy": fixture.policy(),
                "phases": [{"phase": name, "file": name + ".json", "all_rounds_confirmed": True}
                           for name in pressure.PHASES], "public_fairness_qualified": False,
                "production_qualified": False, "work_hardness_qualified": False,
                "installation_authorized": False}
    sidecars = {}
    for phase in phases:
        for wrapper in phase["actors"]:
            actor = wrapper["report"]["result"]
            actor["pid"] = wrapper["pid"] = 2000 + actor["actor"]
            sidecars[(phase["phase"], actor["actor"])] = cost_for(
                actor, phase["epoch_monotonic_ns"], business, disposition)
    return manifest, prepared, phases, sidecars


def raw_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parent_capture(args):
    """Synthetic independent parent capture, performed before a tamper control."""
    _, _, phases, sidecars = args
    bindings, captured = {}, {}
    for phase in phases:
        name, rows = phase["phase"], []
        for index, wrapper in enumerate(phase["actors"]):
            key = (name, index)
            if key not in sidecars:
                continue
            cost, actor = sidecars[key], wrapper["report"]["result"]
            raw = {"report.json": raw_bytes(wrapper["report"]), reader.FILE: raw_bytes(cost)}
            captured[key] = raw
            rows.append({"actor": index, "actor_directory": f"actor-{index}", "pid": wrapper["pid"],
                         "exit_success": wrapper["exit_success"], "parent_forced_kill": wrapper["parent_forced_kill"],
                         "files": {name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest(), "error": None}
                                   for name, value in raw.items()},
                         "actor_report_matches_phase": True, "report_issued_calls": len(actor["calls"]),
                         "report_finished_ns": actor["finished_ns"], "sidecar_summary": copy.deepcopy(cost["summary"]),
                         "sidecar_terminal": copy.deepcopy(cost["loop_terminal"]), "capture_complete": True})
        bindings[name] = {"schema": reader.BINDING_SCHEMA, "scope": reader.BINDING_SCOPE,
                          "phase": name, "parent_pid": 90000,
                          "started_monotonic_ns": phase["epoch_monotonic_ns"] + reader.pressure.WINDOW + 200,
                          "ended_monotonic_ns": phase["epoch_monotonic_ns"] + reader.pressure.WINDOW + 300,
                          "read_budget_ns": reader.CAPTURE_BUDGET, "actor_report_limit": reader.REPORT_LIMIT,
                          "actor_cost_limit": reader.COST_LIMIT,
                          "expected_actors": 0 if name == "baseline" else reader.pressure.ATTACKERS,
                          "actors": rows, "capture_complete": True, "physical_authentication": False}
    return bindings, captured


def read(args):
    return reader.check(*args, *parent_capture(args))


def write_capture(directory, args):
    manifest, prepared, phases, _ = args
    bindings, captured = parent_capture(args)
    values = {"campaign.json": manifest, "preparation.json": prepared,
              **{p["phase"] + ".json": p for p in phases},
              **{name + "/" + reader.BINDING_FILE: value for name, value in bindings.items()}}
    files = {name: raw_bytes(value) for name, value in values.items()}
    for (phase, actor), raw in captured.items():
        files.update({f"{phase}/actor-{actor}/{name}": value for name, value in raw.items()})
    for name, value in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(value)


class CostLedgerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = campaign()

    def check_actor(self, change):
        manifest, prepared, phases, sidecars = copy.deepcopy(self.base)
        key = ("correct-product-false-trace", 0)
        change(sidecars[key])
        return read((manifest, prepared, phases, sidecars))

    def test_real_reader_retains_both_unissued_paths_without_extra_calls(self):
        for reason in ("phase_closed_after_preparation", "phase_closed_at_call_entry",
                       "phase_closed_before_preparation"):
            with self.subTest(reason):
                args = campaign(reason)
                before = copy.deepcopy(args[:3])
                result = read(args)
                self.assertTrue(result["preparation_coverage_complete"])
                self.assertTrue(result["cpu_observation_complete"])
                self.assertTrue(result["original_pressure_finite_qualification"])
                self.assertEqual(args[:3], before)
                for phase in result["phases"][1:]:
                    self.assertEqual(phase["issued_calls"], 72)
                    self.assertEqual(phase["unissued_preparations"], 0 if reason == "phase_closed_before_preparation" else 24)
                    self.assertEqual(phase["prepared_attempts"], phase["issued_calls"] + phase["unissued_preparations"])

    def test_unknown_preparation_cpu_stays_null_and_is_not_zero(self):
        def unknown(cost):
            row = cost["preparations"][-1]
            row["end"]["thread_cpu_ns"] = row["preparation_thread_cpu_ns"] = None
            summarize(cost)
        result = self.check_actor(unknown)
        actor = result["phases"][2]["actors"][0]
        self.assertIsNone(actor["preparation_thread_cpu_ns"])
        self.assertEqual(actor["unknown_preparation_cpu_count"], 1)
        self.assertEqual(actor["known_preparation_thread_cpu_ns"], 300)
        self.assertFalse(result["cpu_observation_complete"])
        self.assertTrue(result["original_pressure_finite_qualification"])

    def test_unknown_outer_cpu_does_not_become_an_aggregate_zero(self):
        result = self.check_actor(lambda cost: cost["loop_exit"].update(thread_cpu_ns=None))
        aggregate = result["phases"][2]["actor_entry_through_loop_exit_thread_cpu"]
        self.assertIsNone(aggregate["total_ns"])
        self.assertEqual(aggregate["unknown_count"], 1)

    def test_final_unissued_record_cannot_be_deleted_even_with_recounted_totals(self):
        def remove(cost):
            cost["preparations"].pop()
            summarize(cost)
        with self.assertRaises(ValueError):
            self.check_actor(remove)

    def test_issued_preparation_cannot_be_deleted_or_duplicated(self):
        for duplicate in (False, True):
            def change(cost):
                if duplicate:
                    cost["preparations"][1] = copy.deepcopy(cost["preparations"][0])
                else:
                    cost["preparations"].pop(0)
                summarize(cost)
            with self.subTest(duplicate), self.assertRaises(ValueError):
                self.check_actor(change)

    def test_forged_totals_or_boolean_counts_are_rejected(self):
        for key in ("prepared_attempts", "issued_calls", "unissued_preparations", "loop_generation_trials",
                    "known_preparation_thread_cpu_ns", "unknown_preparation_cpu_count", "preparation_thread_cpu_ns"):
            for value in (True, 999):
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "totals"):
                    self.check_actor(lambda cost: cost["summary"].update({key: value}))

    def test_issued_call_binding_cannot_be_replaced(self):
        for field, value in (("call_index", 1), ("call_body_digest", "00" * 32),
                             ("inner_preparation_thread_cpu_ns", 21), ("header", "00" * 318),
                             ("packet_sha256", "00" * 32)):
            with self.subTest(field), self.assertRaises(ValueError):
                self.check_actor(lambda cost: cost["preparations"][0].update({field: value}))

    def test_discarded_preparation_still_requires_actual_trace_and_trial_witness(self):
        for field, value in (("trace", "00" * 32), ("generation_trials", 2), ("generation_trials", 4097)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.check_actor(lambda cost: cost["preparations"][-1].update({field: value}))

    def test_missing_call_cannot_be_labelled_as_timely_unissued_preparation(self):
        with self.assertRaisesRegex(ValueError, "phase closure"):
            self.check_actor(lambda cost: cost["preparations"][-1].update(
                phase_gate_monotonic_ns=cost["epoch_monotonic_ns"] + reader.pressure.WINDOW - 1,
                end=sample(cost["epoch_monotonic_ns"] + reader.pressure.WINDOW - 20, 31_100)))

    def test_no_added_deadline_or_changed_phase_envelope(self):
        for key, value in (("window_ns", reader.pressure.WINDOW + 1), ("actor_call_cap", 481),
                           ("epoch_monotonic_ns", 999)):
            with self.subTest(key), self.assertRaises(ValueError):
                self.check_actor(lambda cost: cost.update({key: value}))

    def test_counter_regression_and_invented_cpu_fail(self):
        with self.assertRaisesRegex(ValueError, "regressed"):
            self.check_actor(lambda cost: cost["preparations"][0]["end"].update(thread_cpu_ns=999))
        with self.assertRaisesRegex(ValueError, "invented preparation CPU"):
            self.check_actor(lambda cost: cost["preparations"][0].update(preparation_thread_cpu_ns=0))

    def test_nested_measurements_cannot_be_added_as_owner_cpu(self):
        args = copy.deepcopy(self.base)
        args[2][2]["actors"][0]["report"]["result"]["calls"][0]["thread_cpu_ns"] = 50_000
        with self.assertRaisesRegex(ValueError, "double-counted"):
            read(args)

    def test_owner_epoch_and_qualification_authority_cannot_be_relabelled(self):
        for key, value in (("pid", 9000), ("owner_thread", "receiver-process"),
                           ("public_fairness_qualified", True), ("work_hardness_qualified", True),
                           ("production_qualified", True), ("schema", "pon-pure-pressure-v3")):
            with self.subTest(key), self.assertRaises(ValueError):
                self.check_actor(lambda cost: cost.update({key: value}))

    def test_complete_cost_ledger_preserves_original_service_failure(self):
        args = copy.deepcopy(self.base)
        args[2][2]["errors"].append("retained synthetic service failure")
        result = read(args)
        self.assertFalse(result["original_pressure_finite_qualification"])
        self.assertTrue(result["preparation_coverage_complete"])
        for key in ("public_fairness_qualified", "work_hardness_qualified", "production_qualified", "installation_authorized"):
            self.assertFalse(result[key])

    def test_missing_extra_and_dead_actor_cannot_claim_complete_cost_coverage(self):
        for mutation in ("missing", "extra", "dead"):
            args = copy.deepcopy(self.base)
            if mutation == "missing":
                del args[3][("correct-product-false-trace", 0)]
            elif mutation == "extra":
                args[3][("baseline", 0)] = args[3][("correct-product-false-trace", 0)]
            else:
                args[2][2]["actors"][0]["parent_forced_kill"] = True
            with self.subTest(mutation), self.assertRaises(ValueError):
                read(args)

    def test_create_only_raw_files_roundtrip_and_path_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_capture(directory, self.base)
            self.assertTrue(reader.check_directory(directory)["preparation_coverage_complete"])
            wrong = directory / "correct-product-false-trace/actor-00"
            (directory / "correct-product-false-trace/actor-0").rename(wrong)
            with self.assertRaisesRegex(ValueError, "path binding"):
                reader.check_directory(directory)

    def test_removed_final_preparation_and_forged_terminal_fail_parent_raw_binding(self):
        args = copy.deepcopy(self.base)
        bindings, captured = parent_capture(args)
        key = ("correct-product-false-trace", 0)
        cost = args[3][key]
        cost["preparations"].pop()
        summarize(cost)
        cost["loop_terminal"].update(reason="phase_closed_before_preparation", sequence=len(cost["preparations"]))
        # Model an actual edited sidecar file, preserving its original length
        # with valid trailing JSON whitespace so only the raw hash detects it.
        changed = raw_bytes(cost)
        padding = len(captured[key][reader.FILE]) - len(changed)
        self.assertGreater(padding, 0)
        captured[key][reader.FILE] = changed[:-1] + b" " * padding + b"\n"
        with self.assertRaisesRegex(ValueError, "raw SHA256 mismatch"):
            reader.check(*args, bindings, captured)

    def test_parent_bound_raw_file_and_embedded_phase_report_cannot_diverge(self):
        args = copy.deepcopy(self.base)
        bindings, captured = parent_capture(args)
        args[2][2]["actors"][0]["report"]["result"]["diagnostic_thread_cpu_ns"] += 1
        with self.assertRaisesRegex(ValueError, "parsed evidence"):
            reader.check(*args, bindings, captured)
        bindings["from-zero"]["capture_complete"] = False
        with self.assertRaisesRegex(ValueError, "explicitly incomplete"):
            reader.check(*self.base, bindings, captured)

    def test_parent_binding_missing_or_relaxed_capture_limits_fail(self):
        with self.assertRaisesRegex(ValueError, "parent raw binding"):
            reader.check(*self.base)
        for key, value in (("read_budget_ns", reader.CAPTURE_BUDGET + 1),
                           ("actor_cost_limit", reader.COST_LIMIT + 1),
                           ("physical_authentication", True)):
            bindings, captured = parent_capture(self.base)
            bindings["correct-product-false-trace"][key] = value
            with self.subTest(key), self.assertRaises(ValueError):
                reader.check(*self.base, bindings, captured)

    def test_cpu_above_single_thread_acquisition_brackets_is_not_complete(self):
        def impossible(cost):
            row = cost["preparations"][0]
            row["end"]["thread_cpu_ns"] = row["begin"]["thread_cpu_ns"] + reader.CPU_WALL_TOLERANCE + 100
            row["preparation_thread_cpu_ns"] = reader.CPU_WALL_TOLERANCE + 100
            summarize(cost)
        with self.assertRaisesRegex(ValueError, "acquisition brackets"):
            self.check_actor(impossible)

    def test_diagnostic_and_loop_trials_are_separate_and_template_search_remains_unknown(self):
        result = read(self.base)
        phase = result["phases"][2]
        self.assertEqual(phase["loop_generation_trials"], 96)
        self.assertEqual(phase["diagnostic_generation_trials"], 24)
        self.assertEqual(phase["counted_false_trace_generation_trials"], 120)
        self.assertIsNone(result["template_acquisition_search_trials"])
        self.assertFalse(result["all_hash_search_attempts_observed"])
        self.assertFalse(result["physical_cpu_authentication"])
        for key, value in (("diagnostic_generation_trials", 2),
                           ("template_acquisition_search_trials", 0),
                           ("template_acquisition_search_trials_observed", True),
                           ("cpu_wall_bracket_tolerance_ns", reader.CPU_WALL_TOLERANCE + 1)):
            with self.subTest(key), self.assertRaises(ValueError):
                self.check_actor(lambda cost: cost.update({key: value}))

    def test_symlink_actor_directory_and_file_are_never_followed(self):
        for directory_link in (False, True):
            with self.subTest(directory_link), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_capture(root, self.base)
                path = root / "correct-product-false-trace/actor-0"
                if not directory_link:
                    path /= reader.FILE
                retained = path.with_name("retained-evidence")
                path.rename(retained)
                path.symlink_to(retained, target_is_directory=directory_link)
                with self.assertRaises(OSError):
                    reader.check_directory(root)

    def test_regular_file_byte_limit_is_checked_before_capture_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_capture(root, self.base)
            path = root / "correct-product-false-trace/actor-0" / reader.FILE
            with path.open("wb") as stream:
                stream.seek(reader.COST_LIMIT)
                stream.write(b"x")
            with self.assertRaisesRegex(ValueError, "byte limit"):
                reader.check_directory(root)

    def test_expired_observation_read_deadline_never_opens_a_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            held = reader.open_directory(Path(temporary))
            try:
                with self.assertRaisesRegex(ValueError, "read deadline"):
                    reader.safe_read(held, ("not-created.json",), reader.COST_LIMIT, time.monotonic() - 1)
            finally:
                os.close(held)


if __name__ == "__main__":
    unittest.main()
