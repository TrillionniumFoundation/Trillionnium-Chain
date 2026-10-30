#!/usr/bin/env python3
"""Synthetic parser negatives, not a fixed-Host native execution claim."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import read_native_history_verifier as owner
import read_pure_fixed_host_client_v1 as reader
import test_native_history_verifier as original
import test_check_pure_pon_pressure_v2 as pressure_fixture
import test_check_pure_pon_process_cost_v1 as process_fixture


def put(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def fixture(root, experiment="pure-pressure"):
    report, ipc = original.graph_fixture(root, owner.STRICT_PROFILE)
    prepared = pressure_fixture.prepared()
    if experiment == "fresh-caller-pressure":
        prepared["schema"] = reader.fresh.SCHEMA
    seed_tip = reader.pressure.packet(reader.pressure.raw_hex(prepared["seed"][-1]))["id"]
    phases = report["phases"]
    for phase, data, name in zip(phases, ipc, reader.pressure.PHASES):
        old = data["directory"].parent
        if old.name != name:
            old.rename(root / name)
            data["directory"] = root / name / "independent-client"
        phase["phase"] = name
        if experiment == "fresh-caller-pressure":
            phase["schema"] = reader.fresh.SCHEMA
        phase["client_execution_profile"] = owner.PURE_CLIENT_PROFILE
        phase["epoch_monotonic_ns"] = 1
        phase["addresses"] = ["127.0.0.1:5001", "127.0.0.1:5002"]
        phase["client_tip"] = phase.pop("final_client_tip")
        phase["client_height"], phase["client_generation"] = 10, 4
        phase["rounds"] = phase.pop("confirmations")
        del phase["receiver_client_state_equal"]
        phase["history"][0]["listener"] = 0
        value = phase["history_verifier_process"]
        ready, entry = value["ready"], value["report"]["result"]
        value["schema"] = owner.PURE_CLIENT_SCHEMA
        entry["schema"] = owner.PURE_CLIENT_ENTRY_SCHEMA
        ready["initial_tip"] = list(bytes.fromhex(seed_tip))
        for item in (value, data["job"], ready, entry):
            item["client_execution_profile"] = owner.PURE_CLIENT_PROFILE
        data["job"]["seed"] = copy.deepcopy(prepared["seed"])
        data["responses"][2]["value"]["active_height"] = phase["client_height"]
        original.rehash(phase, data, 2)
        launcher_pid = ready["pid"] + 10_000
        wait4 = process_fixture.receipt(launcher_pid, data["job"]["controller_observation"]["pid"])
        wait4.update(role="sudo-systemd-run-launcher-only", native_actor_is_direct_child=False,
                     native_actor_cpu_included=False, observed_before_original_finish_deadline=True)
        value["launcher_wait4"] = wait4
        value["launcher_observed_monotonic_ns"] = wait4["reap_finished_monotonic_ns"] + 1
        data["launch"] = {
            "schema": "native-history-verifier-launch-v1", "unit": value["unit"],
            "native_selector": "history_verifier::owned_actor_entry",
            "controller_pid": data["job"]["controller_observation"]["pid"],
            "launcher_pid": launcher_pid, "binary_sha256": original.BINARY,
            "parent": owner.PARENT, "original_outer_cgroup": original.OUTER,
            "parent_before_spawn": copy.deepcopy(value["parent_before_spawn"]),
            "controller_capability_prequeued": True, "owner_death_control": None,
            "history_resource_profile": owner.STRICT_PROFILE, "collect_on_exit": True,
        }
    schemas = {"pure-pressure": reader.pressure.SCHEMA,
               "fresh-caller-pressure": reader.fresh.SCHEMA,
               "receiver-owner-supplement": "pon-pure-receiver-owner-campaign-v1"}
    manifest = {"schema": schemas[experiment],
                "phases": [{"phase": name, "file": name + ".json"}
                           for name in reader.pressure.PHASES]}
    composition = {"schema": reader.COMPOSITION_SCHEMA,
                   "client_execution_profile": owner.PURE_CLIENT_PROFILE,
                   "experiment": experiment, "native_selector": reader.EXPERIMENTS[experiment],
                   "receiver_outer_budget_changed": False, "attacker_outer_budget_changed": False,
                   "window_ns": reader.pressure.WINDOW, "history_call_cap": 64,
                   "phases": [{"phase": name, "file": name + ".json"}
                              for name in reader.pressure.PHASES],
                   "public_fairness_qualified": False, "production_qualified": False,
                   "work_hardness_qualified": False, "installation_authorized": False}
    result = dict(report=report, ipc=ipc, manifest=manifest, composition=composition, prepared=prepared)
    flush(root, result)
    return result


def flush(root, data):
    original.flush(data["report"], data["ipc"])
    for phase, ipc, binding in zip(data["report"]["phases"], data["ipc"], data["composition"]["phases"]):
        ipc["launch"]["job_sha256"] = hashlib.sha256((ipc["directory"] / "job.json").read_bytes()).hexdigest()
        put(ipc["directory"] / "launch.json", ipc["launch"])
        binding["sha256"] = put(root / binding["file"], phase)
    put(root / "preparation.json", data["prepared"])
    data["composition"]["campaign_sha256"] = put(root / "campaign.json", data["manifest"])
    put(root / "client-composition.json", data["composition"])


class PureFixedHostClientControls(unittest.TestCase):
    def test_explicit_compositions_keep_scope_separate(self):
        for experiment in reader.EXPERIMENTS:
            with self.subTest(experiment=experiment), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture(root, experiment)
                result = reader.check_directory(root, original.BINARY, original.OUTER, experiment)
                self.assertTrue(result["client_boundary_complete"])
                self.assertFalse(result["native_actor_wait4_claimed"])
                self.assertFalse(result["full_receiver_state_equality_claimed"])
                self.assertTrue(result["original_service_predicates_still_required"])
                self.assertEqual(len(result["phases"]), 3)

    def test_fresh_caller_composition_cannot_relabel_legacy_raw_inputs(self):
        for kind in ("manifest", "prepared", "phase"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                data = fixture(root, "fresh-caller-pressure")
                value = data["report"]["phases"][0] if kind == "phase" else data[kind]
                value["schema"] = reader.pressure.SCHEMA
                flush(root, data)
                with self.assertRaisesRegex(ValueError, "namespace"):
                    reader.check_directory(root, original.BINARY, original.OUTER, "fresh-caller-pressure")

    def test_new_composition_does_not_relabel_original_owner_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = fixture(root)
            phase = data["report"]["phases"][0]
            with self.assertRaises(ValueError):
                owner.validate_phase(phase, data["ipc"][0]["directory"], original.BINARY, original.OUTER)
            phase["history_verifier_process"]["schema"] = owner.SCHEMA
            flush(root, data)
            with self.assertRaisesRegex(ValueError, "original History owner schema cannot relabel"):
                owner.validate_phase(phase, data["ipc"][0]["directory"], original.BINARY, original.OUTER)
            with self.assertRaises(ValueError):
                reader.check_directory(root, original.BINARY, original.OUTER, "pure-pressure")

    def test_rehashed_profile_placement_and_launcher_mutations_rejected(self):
        names = ("profile", "job_profile", "ready_profile", "entry_profile", "graph_profile",
                 "backend", "whole_campaign_moved", "parent_limit", "parent_replaced", "remaining_task",
                 "native_wait4_claim", "native_cpu_claim", "launcher_role", "launcher_pid", "launcher_parent",
                 "same_native_launcher", "double_reap", "wait4_error", "forced_cleanup", "late_reap", "status_lie",
                 "cpu_conversion_lie", "unknown_cpu",
                 "lost_lifeline", "not_prequeued", "job_source", "source_listener", "listener_index",
                 "snapshot_height", "snapshot_generation", "epoch", "seed", "initial_tip")
        for name in names:
            with self.subTest(vector=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                data = fixture(root)
                phase, ipc = data["report"]["phases"][0], data["ipc"][0]
                value = phase["history_verifier_process"]
                ready, entry, wait4 = value["ready"], value["report"]["result"], value["launcher_wait4"]
                if name == "profile": phase["client_execution_profile"] = "old"
                elif name == "job_profile": ipc["job"]["client_execution_profile"] = "old"
                elif name == "ready_profile": ready["client_execution_profile"] = "old"
                elif name == "entry_profile": entry["client_execution_profile"] = "old"
                elif name == "graph_profile": phase["history_resource_profile"] = owner.GRAPH_PROFILE
                elif name == "backend": phase["state_backend"] = ipc["job"]["backend"] = "legacy-v2"
                elif name == "whole_campaign_moved": value["original_outer_cgroup"] = ready["cgroup"]
                elif name == "parent_limit": ready["parent"]["cpu.max"] = "400000 100000"
                elif name == "parent_replaced": ready["parent"]["inode"] += 1
                elif name == "remaining_task": value["parent_after_reap"]["pids.current"] = 1
                elif name == "native_wait4_claim": wait4["native_actor_is_direct_child"] = True
                elif name == "native_cpu_claim": wait4["native_actor_cpu_included"] = True
                elif name == "launcher_role": wait4["role"] = "native"
                elif name == "launcher_pid": wait4["pid"] = ready["pid"]
                elif name == "launcher_parent": wait4["parent_pid"] += 1
                elif name == "same_native_launcher": wait4["pid"] = ipc["launch"]["launcher_pid"] = ready["pid"]
                elif name == "double_reap": wait4["successful_reaps"] = 2
                elif name == "wait4_error": wait4["error"] = "ECHILD"
                elif name == "forced_cleanup": wait4["parent_forced_kill"] = True
                elif name == "late_reap": wait4["observed_before_original_finish_deadline"] = False
                elif name == "status_lie": wait4["raw_wait_status"] = 256
                elif name == "cpu_conversion_lie": wait4["rusage"]["total_cpu_ns"] = None
                elif name == "unknown_cpu":
                    wait4["rusage"].update(user_seconds=-1, user_cpu_ns=None, total_cpu_ns=None)
                elif name == "lost_lifeline": ready["controller_lifeline"]["watch_until_process_exit"] = False
                elif name == "not_prequeued": ipc["launch"]["controller_capability_prequeued"] = False
                elif name == "job_source": ipc["launch"]["binary_sha256"] = "cd" * 32
                elif name == "source_listener": ipc["requests"][0]["source"] = phase["addresses"][1]
                elif name == "listener_index": phase["history"][0]["listener"] = 2
                elif name == "snapshot_height": ipc["responses"][2]["value"]["active_height"] += 1
                elif name == "snapshot_generation": ipc["responses"][2]["value"]["active"][1] += 1
                elif name == "epoch": ipc["requests"][0]["epoch"] += 1
                elif name == "seed": ipc["job"]["seed"][0] = "00"
                elif name == "initial_tip": ready["initial_tip"] = [9] * 32
                else: self.fail(name)
                for sequence in range(len(ipc["requests"])):
                    original.rehash(phase, ipc, sequence)
                flush(root, data)
                with self.assertRaises((ValueError, KeyError, TypeError, IndexError)):
                    reader.check_directory(root, original.BINARY, original.OUTER, "pure-pressure")

    def test_missing_or_relabelled_composition_never_falls_back(self):
        mutations = ("missing", "old_selector", "wrong_experiment", "window", "cap", "receiver_moved", "attacker_moved",
                     "missing_phase", "bytes", "duplicate_key")
        for mutation in mutations:
            with self.subTest(vector=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                data = fixture(root)
                composition = data["composition"]
                if mutation == "missing": (root / "client-composition.json").unlink()
                elif mutation == "duplicate_key":
                    raw = (root / "client-composition.json").read_text()
                    (root / "client-composition.json").write_text('{"schema":"forged",' + raw[1:])
                elif mutation == "bytes":
                    (root / "baseline.json").write_text((root / "baseline.json").read_text() + " ")
                else:
                    if mutation == "old_selector": composition["native_selector"] = "pure_pon_cold_shared_domain_pressure_v2"
                    elif mutation == "wrong_experiment": composition["experiment"] = "receiver-owner-supplement"
                    elif mutation == "window": composition["window_ns"] += 1
                    elif mutation == "cap": composition["history_call_cap"] += 1
                    elif mutation == "receiver_moved": composition["receiver_outer_budget_changed"] = True
                    elif mutation == "attacker_moved": composition["attacker_outer_budget_changed"] = True
                    elif mutation == "missing_phase": composition["phases"].pop()
                    else: self.fail(mutation)
                    put(root / "client-composition.json", composition)
                with self.assertRaises((OSError, ValueError, KeyError, TypeError, IndexError)):
                    reader.check_directory(root, original.BINARY, original.OUTER, "pure-pressure")


if __name__ == "__main__":
    unittest.main()
