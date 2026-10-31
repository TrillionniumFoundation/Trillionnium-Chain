#!/usr/bin/env python3
"""Synthetic wait4 association controls, not physical native measurements."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import check_pure_pon_process_cost_v1 as reader
import test_check_pure_pon_attacker_cost_v1 as fixture


def receipt(pid=2000, parent=90000, epoch=100):
    return {"schema": "pon-child-wait4-cost-v1", "scope": reader.WAIT_SCOPE,
            "pid": pid, "parent_pid": parent, "spawn_started_monotonic_ns": epoch - 80,
            "spawn_finished_monotonic_ns": epoch - 70,
            "reap_started_monotonic_ns": epoch + reader.thread_cost.pressure.WINDOW + 110,
            "reap_finished_monotonic_ns": epoch + reader.thread_cost.pressure.WINDOW + 150,
            "wait4_calls": 3, "successful_reaps": 1, "raw_wait_status": 0,
            "exit_success": True, "parent_forced_kill": False, "error": None,
            "physical_authentication": False,
            "rusage": {"user_seconds": 0, "user_microseconds": 10000,
                       "system_seconds": 0, "system_microseconds": 2000,
                       "user_cpu_ns": 10000000, "system_cpu_ns": 2000000, "total_cpu_ns": 12000000,
                       "max_rss_kib": 2000, "minor_faults": 5, "major_faults": 0,
                       "input_blocks": 0, "output_blocks": 20,
                       "voluntary_context_switches": 3, "involuntary_context_switches": 1}}


def binding(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "error": None}


def family(pid, epoch):
    own = copy.deepcopy(receipt()["rusage"])
    own.update(user_microseconds=9000, user_cpu_ns=9000000, total_cpu_ns=11000000)
    children = copy.deepcopy(own)
    children.update(user_microseconds=0, system_microseconds=0, user_cpu_ns=0, system_cpu_ns=0, total_cpu_ns=0)
    return {"schema": "pon-process-family-observation-v1", "scope": reader.FAMILY_SCOPE,
            "pid": pid, "started_monotonic_ns": epoch + reader.thread_cost.pressure.WINDOW + 120,
            "ended_monotonic_ns": epoch + reader.thread_cost.pressure.WINDOW + 130,
            "thread_ids_before": [pid, pid+10000], "thread_ids_after": [pid, pid+10000],
            "thread_children": [{"tid": tid, "children": [], "error": None} for tid in [pid, pid+10000]],
            "observed_child_pids": [], "thread_set_stable": True, "self_rusage": own,
            "waited_children_rusage": children, "child_subreaper": False,
            "capture_complete": True, "no_live_or_unreaped_children_observed": True,
            "errors": [], "physical_authentication": False}


def child_probe(pid, epoch, *, subreaper=False):
    signal = {"disposition": "default", "flags": 0, "no_cld_wait": False, "error": None}
    return {"schema": "pon-child-ownership-probe-v1", "scope": reader.PROBE_SCOPE, "pid": pid,
            "started_monotonic_ns": epoch + reader.thread_cost.pressure.WINDOW + 135,
            "ended_monotonic_ns": epoch + reader.thread_cost.pressure.WINDOW + 140,
            "idtype": 0, "id": 0, "options": reader.PROBE_OPTIONS, "option_names": reader.PROBE_NAMES,
            "sigchld_before": dict(signal), "sigchld_after": dict(signal), "safe_signal_disposition_observed": True,
            "waitid_return": -1, "errno": reader.errno.ECHILD, "event": None,
            "child_subreaper": subreaper, "subreaper_error": None, "waitid_echild_observed": True,
            "no_eligible_children_at_probe": True, "successful_reaps": 0, "physical_authentication": False}


def write_probe_binding(location, kind, phase, parent_pid, pids, epoch):
    parent_file = "attacker-process-cost-v1.json" if kind == "actor" else "receiver-owner-binding-v1.json"
    parent = json.loads((location / parent_file).read_text())
    rows = []
    for index, pid in enumerate(pids):
        directory = f"actor-{index}" if kind == "actor" else None
        target = location / directory if directory else location
        file = kind + "-child-ownership-v1.json"
        (target / file).write_text(json.dumps(child_probe(pid, epoch, subreaper=kind == "receiver")) + "\n")
        rows.append({"index": index, "pid": pid, "directory": directory, "file": file,
                     "capture_complete": True, "binding": binding((target / file).read_bytes())})
    value = {"schema": "pon-child-ownership-binding-v1", "scope": reader.PROBE_BINDING_SCOPE,
             "kind": kind, "phase": phase, "parent_pid": parent_pid, "parent_cost_file": parent_file,
             "parent_cost_binding": binding((location / parent_file).read_bytes()),
             "started_monotonic_ns": parent["ended_monotonic_ns"] + 1,
             "ended_monotonic_ns": parent["ended_monotonic_ns"] + 2,
             "read_budget_ns": reader.thread_cost.CAPTURE_BUDGET, "probe_limit": reader.LOG_LIMIT,
             "expected_children": len(pids), "children": rows, "capture_complete": True, "physical_authentication": False}
    (location / (("attacker" if kind == "actor" else "receiver") + "-child-ownership-binding-v1.json")).write_text(json.dumps(value) + "\n")


def write_processes(directory, args):
    fixture.write_capture(directory, args)
    _, _, phases, _ = args
    for phase in phases:
        name, epoch = phase["phase"], phase["epoch_monotonic_ns"]
        location = directory / name
        old_binding = (location / reader.thread_cost.BINDING_FILE).read_bytes()
        rows = []
        for index, wrapper in enumerate(phase["actors"]):
            actor = location / f"actor-{index}"
            (actor / "actor.log").write_bytes(b"synthetic original child terminal\n")
            (actor / reader.FAMILY_FILE).write_text(json.dumps(family(wrapper["pid"], epoch)) + "\n")
            rows.append({"actor": index, "actor_directory": f"actor-{index}", "pid": wrapper["pid"],
                         "cost": receipt(wrapper["pid"], epoch=epoch), "capture_complete": True,
                         "files": {name: binding((actor / name).read_bytes())
                                   for name in ("report.json", reader.thread_cost.FILE, "actor.log", reader.FAMILY_FILE)}})
        value = {"schema": reader.SCHEMA, "scope": reader.SCOPE, "phase": name,
                 "epoch_monotonic_ns": epoch, "parent_pid": 90000,
                 "expected_actors": len(rows), "actors": rows, "capture_complete": True,
                 "physical_authentication": False,
                 "started_monotonic_ns": epoch + reader.thread_cost.pressure.WINDOW + 500,
                 "ended_monotonic_ns": epoch + reader.thread_cost.pressure.WINDOW + 600,
                 "read_budget_ns": reader.thread_cost.CAPTURE_BUDGET,
                 "actor_report_limit": reader.thread_cost.REPORT_LIMIT,
                 "actor_cost_limit": reader.thread_cost.COST_LIMIT,
                 "actor_log_limit": reader.LOG_LIMIT, "thread_cost_parent_binding": binding(old_binding)}
        (location / reader.FILE).write_text(json.dumps(value) + "\n")
        write_probe_binding(location, "actor", name, 90000, [a["pid"] for a in phase["actors"]], epoch)


class WaitControls(unittest.TestCase):
    def check(self, value):
        return reader.check_wait4(value, 2000, 90000, 40_000_000_000)

    def test_independent_kernel_timeval_derivation(self):
        row = self.check(receipt())
        self.assertEqual(row["total_cpu_ns"], 12000000)

    def test_unknown_timeval_cannot_become_zero(self):
        value = receipt()
        value["rusage"].update(user_seconds=-1, user_cpu_ns=None, total_cpu_ns=None)
        self.assertFalse(self.check(value)["cpu_observed"])
        value["rusage"]["total_cpu_ns"] = 0
        with self.assertRaisesRegex(ValueError, "unknown propagation"):
            self.check(value)

    def test_wrong_pid_parent_reap_count_and_authority_reject(self):
        for field, bad in (("pid", 2001), ("parent_pid", 90001), ("successful_reaps", 2),
                           ("successful_reaps", True), ("wait4_calls", 0),
                           ("physical_authentication", True), ("error", "ECHILD")):
            value = receipt()
            value[field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                self.check(value)

    def test_normal_failure_and_signal_costs_do_not_become_success(self):
        for status, forced in ((7 << 8, False), (9, True)):
            value = receipt()
            value.update(raw_wait_status=status, exit_success=False, parent_forced_kill=forced)
            self.assertFalse(self.check(value)["exit_success"])
            value["exit_success"] = True
            with self.assertRaisesRegex(ValueError, "status"):
                self.check(value)

    def test_reversed_clocks_and_boolean_cpu_reject(self):
        value = receipt()
        value["reap_finished_monotonic_ns"] = 10
        with self.assertRaises(ValueError):
            self.check(value)
        value = receipt()
        value["rusage"]["user_seconds"] = True
        with self.assertRaises(ValueError):
            self.check(value)

    def test_nested_thread_cpu_cannot_exceed_enclosing_kernel_sample(self):
        nested = {"entry": fixture.sample(100, 0), "loop_exit": fixture.sample(20_000_000_000, 20_000_000)}
        with self.assertRaisesRegex(ValueError, "exceeds whole child"):
            reader.check_wait4(receipt(), 2000, 90000, 40_000_000_000, nested)

    def test_live_or_unreaped_descendant_stays_unqualified(self):
        value = family(2000, 100)
        value["observed_child_pids"] = [3000]
        value["thread_children"][0]["children"] = [3000]
        value["no_live_or_unreaped_children_observed"] = False
        self.assertFalse(reader.check_family(value, receipt())["descendants_quiescent_observed"])
        value["no_live_or_unreaped_children_observed"] = True
        with self.assertRaisesRegex(ValueError, "association"):
            reader.check_family(value, receipt())

    def test_receiver_needs_real_subreaper_and_unknown_census_is_not_empty(self):
        value = family(2000, 100)
        self.assertFalse(reader.check_family(value, receipt(), require_subreaper=True)["descendants_quiescent_observed"])
        value["child_subreaper"] = True
        self.assertTrue(reader.check_family(value, receipt(), require_subreaper=True)["descendants_quiescent_observed"])
        value.update(capture_complete=False, errors=["proc unavailable"], no_live_or_unreaped_children_observed=False)
        self.assertFalse(reader.check_family(value, receipt())["family_observation_complete"])


class ChildProbeControls(unittest.TestCase):
    def check(self, value, census=None):
        return reader.check_child_probe(value, receipt(), family(2000, 100) if census is None else census)

    def test_procfs_unavailable_is_preserved_with_independent_kernel_basis(self):
        census = family(2000, 100)
        census.update(capture_complete=False, errors=["ENOENT"], no_live_or_unreaped_children_observed=False)
        value = self.check(child_probe(2000, 100), census)
        self.assertFalse(value["procfs_capture_complete"])
        self.assertTrue(value["no_eligible_children_at_probe"])
        self.assertEqual(value["quiescence_basis"], "waitid-echild-with-sig-dfl-no-nocldwait")

    def test_live_zero_event_and_zombie_event_are_not_absence(self):
        for pid in (0, 3000):
            value = child_probe(2000, 100)
            value.update(waitid_return=0, errno=None, event={"signo": 0 if pid == 0 else 17,
                         "code": 0 if pid == 0 else 1, "errno": 0, "pid": pid, "uid": 1000, "status": 7},
                         waitid_echild_observed=False, no_eligible_children_at_probe=False)
            self.assertFalse(self.check(value)["descendants_quiescent_observed"])
            value["no_eligible_children_at_probe"] = True
            with self.assertRaisesRegex(ValueError, "cannot mean"):
                self.check(value)

    def test_eintr_eperm_and_auto_reap_cannot_promote(self):
        for code in (reader.errno.EINTR, reader.errno.EPERM):
            value = child_probe(2000, 100)
            value.update(errno=code, waitid_echild_observed=False, no_eligible_children_at_probe=False)
            self.assertFalse(self.check(value)["descendants_quiescent_observed"])
        for disposition, flags in (("ignored", 0), ("default", 2), ("handler", 0)):
            value = child_probe(2000, 100)
            for key in ("sigchld_before", "sigchld_after"):
                value[key].update(disposition=disposition, flags=flags, no_cld_wait=bool(flags & 2))
            value.update(safe_signal_disposition_observed=False, no_eligible_children_at_probe=False)
            self.assertFalse(self.check(value)["descendants_quiescent_observed"])
            value["no_eligible_children_at_probe"] = True
            with self.assertRaises(ValueError):
                self.check(value)

    def test_wrong_waitid_options_reaping_and_signal_changes_reject(self):
        for field, bad in (("options", reader.PROBE_OPTIONS | 0x20000000), ("options", reader.PROBE_OPTIONS & ~0x01000000),
                           ("successful_reaps", 1), ("idtype", 1), ("id", 2000), ("physical_authentication", True)):
            value = child_probe(2000, 100)
            value[field] = bad
            with self.assertRaises(ValueError):
                self.check(value)
        value = child_probe(2000, 100)
        value["sigchld_after"].update(disposition="ignored")
        with self.assertRaisesRegex(ValueError, "signal guard"):
            self.check(value)

    def test_actual_proc_children_cannot_be_ignored_even_if_probe_claims_echild(self):
        census = family(2000, 100)
        census["observed_child_pids"] = [3000]
        census["thread_children"][0]["children"] = [3000]
        with self.assertRaisesRegex(ValueError, "contradict"):
            self.check(child_probe(2000, 100), census)


class PartialCensusControls(unittest.TestCase):
    def census(self):
        value = family(2000, 100)
        value["thread_children"][0]["children"] = [3000]
        value["thread_children"][1].update(children=None, error="No such file or directory (os error 2)")
        value.update(capture_complete=False, errors=["No such file or directory (os error 2)"],
                     no_live_or_unreaped_children_observed=False, observed_child_pids=[3000])
        return value

    def test_failed_sibling_read_cannot_hide_successful_child_row(self):
        # Actual B counterexample shape: one successful positive row, one ENOENT,
        # but a false empty aggregate. Both public predicate entry points reject.
        value = self.census()
        value["observed_child_pids"] = []
        with self.assertRaisesRegex(ValueError, "census association"):
            reader.check_family(value, receipt())
        with self.assertRaisesRegex(ValueError, "census association"):
            reader.check_child_probe(child_probe(2000, 100), receipt(), value)

    def test_partial_known_children_remain_positive_and_cpu_stays_unknown(self):
        value = self.census()
        result = reader.check_family(value, receipt())
        self.assertFalse(result["family_observation_complete"])
        self.assertFalse(result["descendants_quiescent_observed"])
        self.assertIsNone(result["self_cpu_before_publication_ns"])
        self.assertIsNone(result["waited_children_cpu_ns"])
        with self.assertRaisesRegex(ValueError, "contradict"):
            reader.check_child_probe(child_probe(2000, 100), receipt(), value)
        probe = child_probe(2000, 100)
        probe.update(waitid_return=0, errno=None,
                     event={"signo": 0, "code": 0, "errno": 0, "pid": 0, "uid": 0, "status": 0},
                     waitid_echild_observed=False, no_eligible_children_at_probe=False)
        result = reader.check_child_probe(probe, receipt(), value)
        self.assertEqual(result["procfs_children_observed"], [3000])
        self.assertFalse(result["descendants_quiescent_observed"])

    def test_partial_census_covers_before_rows_even_when_after_set_changes(self):
        for after in ([2000], None, []):
            value = self.census()
            value["thread_children"][0]["children"] = []
            value.update(observed_child_pids=[], thread_ids_after=after, thread_set_stable=False)
            with self.subTest(after=after):
                self.assertFalse(reader.check_family(value, receipt())["family_observation_complete"])
                result = reader.check_child_probe(child_probe(2000, 100), receipt(), value)
                self.assertFalse(result["procfs_capture_complete"])
                self.assertTrue(result["descendants_quiescent_observed"])
                self.assertEqual(result["quiescence_basis"], "waitid-echild-with-sig-dfl-no-nocldwait")

    def test_missing_before_census_is_unknown_without_invented_rows(self):
        for after in (None, [2000]):
            value = self.census()
            value.update(thread_ids_before=None, thread_ids_after=after, thread_set_stable=False,
                         thread_children=[], observed_child_pids=[])
            with self.subTest(after=after):
                self.assertFalse(reader.check_family(value, receipt())["family_observation_complete"])
                self.assertTrue(reader.check_child_probe(child_probe(2000, 100), receipt(), value)
                                ["descendants_quiescent_observed"])
                value["thread_children"] = [{"tid": 2000, "children": [], "error": None}]
                with self.assertRaisesRegex(ValueError, "row coverage"):
                    reader.check_family(value, receipt())

    def test_partial_row_omission_and_boolean_pid_are_rejected(self):
        value = self.census()
        value["thread_children"].pop(0)
        value["observed_child_pids"] = []
        with self.assertRaisesRegex(ValueError, "row coverage"):
            reader.check_family(value, receipt())
        for target in ("before", "row", "child", "aggregate"):
            value = self.census()
            if target == "before":
                value["thread_ids_before"][0] = True
            elif target == "row":
                value["thread_children"][0]["tid"] = True
            elif target == "child":
                value["thread_children"][0]["children"] = [True]
            else:
                value["observed_child_pids"] = [True]
            with self.subTest(target=target), self.assertRaises(ValueError):
                reader.check_family(value, receipt())


class DirectoryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.args = fixture.campaign()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        write_processes(self.path, self.args)
        self.cost = self.path / "correct-product-false-trace" / reader.FILE

    def mutate(self, function):
        value = json.loads(self.cost.read_text())
        function(value)
        self.cost.write_text(json.dumps(value) + "\n")
        path = self.cost.parent / "attacker-child-ownership-binding-v1.json"
        probe = json.loads(path.read_text())
        probe["parent_cost_binding"] = binding(self.cost.read_bytes())
        path.write_text(json.dumps(probe) + "\n")

    def test_full_capture_keeps_original_finite_verdict_separate(self):
        value = reader.check_directory(self.path)
        self.assertTrue(value["process_coverage_complete"])
        self.assertTrue(value["cpu_observation_complete"])
        self.assertFalse(value["receiver_owner_observed"])
        self.assertFalse(value["public_fairness_qualified"])
        self.assertEqual(value["phases"][1]["whole_actor_process_cpu"]["total_ns"], 24 * 12000000)

    def test_missing_process_row_cannot_shrink_population(self):
        self.mutate(lambda value: value["actors"].pop())
        with self.assertRaisesRegex(ValueError, "coverage"):
            reader.check_directory(self.path)

    def test_actor_log_same_length_mutation_rejects(self):
        path = self.path / "correct-product-false-trace/actor-0/actor.log"
        raw = path.read_bytes()
        path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            reader.check_directory(self.path)

    def test_substituted_pid_and_reused_parent_binding_reject(self):
        self.mutate(lambda value: value["actors"][0]["cost"].update(pid=2001))
        with self.assertRaisesRegex(ValueError, "PID"):
            reader.check_directory(self.path)

    def test_unknown_kernel_cpu_remains_unknown(self):
        self.mutate(lambda value: value["actors"][0]["cost"]["rusage"].update(
            user_seconds=-1, user_cpu_ns=None, total_cpu_ns=None))
        value = reader.check_directory(self.path)
        self.assertTrue(value["input_consistent"])
        self.assertFalse(value["cpu_observation_complete"])
        self.assertIsNone(value["phases"][2]["whole_actor_process_cpu"]["total_ns"])
        self.assertEqual(value["phases"][2]["whole_actor_process_cpu"]["unknown_count"], 1)

    def test_resealed_parent_bindings_do_not_hide_partial_positive_census(self):
        path = self.cost.parent / "actor-0" / reader.FAMILY_FILE
        value = json.loads(path.read_text())
        value["thread_children"][0]["children"] = [3000]
        value["thread_children"][1].update(children=None, error="ENOENT")
        value.update(capture_complete=False, errors=["ENOENT"],
                     no_live_or_unreaped_children_observed=False, observed_child_pids=[])
        path.write_text(json.dumps(value) + "\n")
        self.mutate(lambda process: process["actors"][0]["files"].update(
            {reader.FAMILY_FILE: binding(path.read_bytes())}))
        with self.assertRaisesRegex(ValueError, "census association"):
            reader.check_directory(self.path)


if __name__ == "__main__":
    unittest.main()
