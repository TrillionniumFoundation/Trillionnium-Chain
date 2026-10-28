#!/usr/bin/env python3
"""Synthetic strict-reader controls; these do not stand in for native execution."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import read_native_history_verifier as reader


BINARY = "ab" * 32
OUTER = "/system.slice/trnm-native-campaign-test.service"
MODES = ("baseline", "from-zero", "late-product")
BOUNDARY_VECTOR_COUNT = 38
BINDING_VECTOR_COUNT = 19


def put(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def parent(counter, tasks):
    return {
        "path": reader.PARENT, "device": 1, "inode": 77, "uid": 0,
        "mode": 0o40755, "boot_id": "12345678-1234-1234-1234-123456789abc",
        **reader.LIMITS, "pids.current": tasks, "memory.current": 4096,
        "cpu.stat": {key: counter for key in reader.COUNTERS},
    }


def fixture(root):
    phases, ipc = [], []
    for index, mode in enumerate(MODES):
        directory = root / mode / "independent-client"
        directory.mkdir(parents=True)
        pid = 120 + index
        unit = f"trnm-campaign-verifier-101-{1000 + index}.service"
        cgroup = "/trnmponpublic.slice/" + unit
        tip, after, transaction, included = ([byte] * 32 for byte in (1, 2, 3, 4))
        observation = {"confirmations": 6, "final": True}
        page = {"packets": [], "test_fixture": "reader shape, not a native Page execution"}
        requests = [
            {"operation": "import", "source": "127.0.0.1:5001", "page": page,
             "tip": tip, "after": after, "clock": 1, "epoch": 1},
            {"operation": "confirmation", "transaction": transaction,
             "included": included, "clock": 1, "epoch": 1},
            {"operation": "snapshot"},
            {"operation": "finish"},
        ]
        values = [tip, observation,
                  {"active": [tip, 4, {}], "native_history_arithmetic": {}},
                  {"closing_original_node": True}]
        responses, calls = [], []
        for sequence, (request, value) in enumerate(zip(requests, values)):
            request["sequence"] = sequence
            measurement = {
                "process_id": pid, "sequence": sequence,
                "thread_cpu_observation_available": True, "thread_cpu_ns": 10,
                "process_cpu_ns": 30, "process_wall_ns": 50,
            }
            request_sha = put(directory / f"request-{sequence:03}.json", request)
            response = {
                "sequence": sequence, "request_sha256": request_sha,
                "binary_sha256": BINARY, "value": value, "error": None,
                "measurement": copy.deepcopy(measurement),
            }
            response_sha = put(directory / f"response-{sequence:03}.json", response)
            responses.append(response)
            calls.append({
                "sequence": sequence, "operation": request["operation"],
                "request_sha256": request_sha, "response_sha256": response_sha,
                "succeeded": True, "measurement": copy.deepcopy(measurement),
            })
        controller = {"pid": 101, "uid": 1001, "gid": 1001}
        lifeline = {"schema": "native-history-controller-lifeline-v1",
                    "capability": "anonymous-unix-stream+prequeued-self-pidfd",
                    "controller": controller,
                    "armed_before_node_open": True,
                    "watch_until_process_exit": True}
        ready = {
            "pid": pid, "cgroup": cgroup, "calling_thread_cgroup": "0::" + cgroup,
            "binary_sha256": BINARY, "public_host_kernel_checked": True,
            "wrong_parent_refused": True, "parent": parent(3, 2),
            "setup_process_cpu_ns": 100,
            "controller_lifeline": copy.deepcopy(lifeline),
        }
        entry = {
            "schema": "native-public-history-verifier-entry-v2",
            "pid": pid, "cgroup": cgroup, "binary_sha256": BINARY,
            "clean_node_close": True, "parent_before": parent(2, 1),
            "controller_lifeline": copy.deepcopy(lifeline),
            "parent_after_node_close": parent(4, 1),
            "whole_verifier_process_cpu_ns": 1000,
            "process_cpu_since_start_ns": 2000, "calls": calls,
        }
        report = {"kind": "history-verifier", "error": None, "result": entry,
                  "whole_entry_cpu_ns": 1200}
        job = {"kind": "history-verifier", "parent": reader.PARENT,
               "binary_sha256": BINARY, "backend": "authenticated-v1",
               "seed": ["00"] * 4, "controller_observation": copy.deepcopy(controller),
               "owner_death_control": None}
        phase = {
            "mode": mode, "state_backend": "authenticated-v1",
            "address": "127.0.0.1:5001", "final_client_tip": bytes(tip).hex(),
            "receiver_client_state_equal": True,
            "confirmations": [
                {"transaction": bytes(transaction).hex(), "included_block": bytes(included).hex(),
                 "observation": observation},
                {"transaction": "05" * 32, "included_block": "06" * 32, "observation": None},
                {"transaction": "07" * 32, "included_block": "08" * 32, "observation": None},
            ],
            "history": [{
                "request": {"op": "history", "tip": bytes(tip).hex(), "after": bytes(after).hex()},
                "response": {"value": page},
                "client_import": {**copy.deepcopy(calls[0]["measurement"]), "succeeded": True},
                "client_confirmation": {**copy.deepcopy(calls[1]["measurement"]), "succeeded": True},
            }],
            "history_verifier_process": {
                "schema": reader.SCHEMA, "completed_successfully": True,
                "exit_success": True, "parent_forced_kill": False,
                "outer_process_cpu_excludes_verifier": True,
                "original_outer_cgroup": OUTER, "unit": unit,
                "ready": ready, "report": report, "binary_sha256": BINARY,
                "parent_before_spawn": parent(1, 0), "parent_after_reap": parent(5, 0),
                "request_count": len(calls),
            },
        }
        phases.append(phase)
        ipc.append({"directory": directory, "job": job, "requests": requests,
                    "responses": responses})
    result = {"phases": phases}
    flush(result, ipc)
    return result, ipc


def flush(report, ipc):
    for phase, data in zip(report["phases"], ipc):
        observed = phase["history_verifier_process"]
        put(data["directory"] / "ready.json", observed["ready"])
        put(data["directory"] / "report.json", observed["report"])
        put(data["directory"] / "job.json", data["job"])


def rehash(phase, data, sequence):
    """A semantic substitution must survive all transport digest recomputation."""
    request = data["requests"][sequence]
    response = data["responses"][sequence]
    call = phase["history_verifier_process"]["report"]["result"]["calls"][sequence]
    request_sha = put(data["directory"] / f"request-{sequence:03}.json", request)
    response["request_sha256"] = request_sha
    call["request_sha256"] = request_sha
    call["response_sha256"] = put(
        data["directory"] / f"response-{sequence:03}.json", response)


def boundary_change(name, phase, data):
    value = phase["history_verifier_process"]
    entry = value["report"]["result"]
    ready = value["ready"]
    if name == "incomplete": value["completed_successfully"] = False
    elif name == "exit_failure": value["exit_success"] = False
    elif name == "forced_kill": value["parent_forced_kill"] = True
    elif name == "cpu_relabel": value["outer_process_cpu_excludes_verifier"] = False
    elif name == "outer_group": value["original_outer_cgroup"] = "/different.service"
    elif name == "unit": value["unit"] = "unbound.service"
    elif name == "backend": data["job"]["backend"] = "legacy-v2"
    elif name == "seed_count": data["job"]["seed"].pop()
    elif name == "entry_pid": entry["pid"] += 1
    elif name == "ready_cgroup": ready["cgroup"] = "/different"
    elif name == "thread_cgroup": ready["calling_thread_cgroup"] = "0::/different"
    elif name == "original_checker": ready["public_host_kernel_checked"] = False
    elif name == "wrong_parent_control": ready["wrong_parent_refused"] = False
    elif name == "entry_error": value["report"]["error"] = "actual failure"
    elif name == "node_close": entry["clean_node_close"] = False
    elif name == "binary": value["binary_sha256"] = "cd" * 32
    elif name == "fixed_limit": ready["parent"]["cpu.max"] = "400000 100000"
    elif name == "fixed_identity": ready["parent"]["inode"] += 1
    elif name == "counter_rewind": ready["parent"]["cpu.stat"]["usage_usec"] = 0
    elif name == "before_tasks": value["parent_before_spawn"]["pids.current"] = 1
    elif name == "after_tasks": value["parent_after_reap"]["pids.current"] = 1
    elif name == "request_digest": entry["calls"][0]["request_sha256"] = "00" * 32
    elif name == "response_digest": entry["calls"][0]["response_sha256"] = "00" * 32
    elif name == "measurement_pid":
        entry["calls"][0]["measurement"]["process_id"] += 1
        data["responses"][0]["measurement"]["process_id"] += 1
        rehash(phase, data, 0)
    elif name.startswith("lifeline_"):
        if name == "lifeline_missing_ready": del ready["controller_lifeline"]
        elif name == "lifeline_missing_entry": del entry["controller_lifeline"]
        elif name == "lifeline_missing_controller": del data["job"]["controller_observation"]
        elif name == "lifeline_old_schema": value["schema"] = "native-public-history-verifier-process-v1"
        elif name == "lifeline_cut_in_campaign": data["job"]["owner_death_control"] = "after-node-close-before-report"
        elif name == "lifeline_unit_owner":
            value["unit"] = value["unit"].replace("verifier-101-", "verifier-102-")
            cgroup = "/trnmponpublic.slice/" + value["unit"]
            ready["cgroup"] = entry["cgroup"] = cgroup
            ready["calling_thread_cgroup"] = "0::" + cgroup
        else:
            line = ready["controller_lifeline"]
            if name == "lifeline_schema": line["schema"] = "unbound"
            elif name == "lifeline_mechanism": line["capability"] = "numeric-pid-listener"
            elif name == "lifeline_not_armed": line["armed_before_node_open"] = False
            elif name == "lifeline_early_disarm": line["watch_until_process_exit"] = False
            elif name == "lifeline_pid": line["controller"]["pid"] += 1
            elif name == "lifeline_uid": line["controller"]["uid"] += 1
            elif name == "lifeline_gid": line["controller"]["gid"] += 1
            elif name == "lifeline_bool_pid":
                line["controller"]["pid"] = True
                data["job"]["controller_observation"]["pid"] = True
            else: raise AssertionError(name)
            entry["controller_lifeline"] = copy.deepcopy(line)
    else: raise AssertionError(name)


def binding_change(name, phase, data):
    requests, responses = data["requests"], data["responses"]
    row = phase["history"][0]
    rounds = phase["confirmations"]
    if name == "import_tip": requests[0]["tip"] = [9] * 32
    elif name == "import_cursor": requests[0]["after"] = [9] * 32
    elif name == "import_bool_hash": requests[0]["tip"][0] = True
    elif name == "import_short_hash": requests[0]["tip"].pop()
    elif name == "original_tip": row["request"]["tip"] = "09" * 32
    elif name == "original_cursor": row["request"]["after"] = "09" * 32
    elif name == "original_operation": row["request"]["op"] = "different"
    elif name == "confirmation_transaction": requests[1]["transaction"] = [9] * 32
    elif name == "confirmation_block": requests[1]["included"] = [9] * 32
    elif name == "round_transaction": rounds[0]["transaction"] = "09" * 32
    elif name == "round_block": rounds[0]["included_block"] = "09" * 32
    elif name == "duplicate_round": rounds.append(copy.deepcopy(rounds[0]))
    elif name == "confirmation_value": responses[1]["value"] = {"different": True}
    elif name == "confirmation_failure_label": row["client_confirmation"]["succeeded"] = False
    elif name == "confirmation_integer_label": row["client_confirmation"]["succeeded"] = 1
    elif name == "hidden_observed_round": rounds[1]["observation"] = {"confirmations": 6}
    elif name == "snapshot_tip": responses[2]["value"]["active"][0] = [9] * 32
    elif name == "snapshot_failure":
        responses[2]["error"] = "actual failure"
        phase["history_verifier_process"]["report"]["result"]["calls"][2]["succeeded"] = False
    elif name == "snapshot_shape": responses[2]["value"]["active"] = [[1] * 32]
    else: raise AssertionError(name)
    for sequence in range(len(requests)):
        rehash(phase, data, sequence)


class NativeHistoryVerifierReader(unittest.TestCase):
    def test_complete_original_three_phase_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, _ = fixture(root)
            result = reader.validate_report(report, root, BINARY, OUTER)
            self.assertTrue(result["complete"])
            self.assertEqual(len(result["phases"]), 3)
            self.assertTrue(all(row["all_ipc_bytes_read_back"] for row in result["phases"]))
            self.assertTrue(all(row["cost_scopes_are_nested_not_additive"]
                                for row in result["phases"]))
            self.assertTrue(all(not row["production_qualification"] for row in result["phases"]))

    def test_boundary_mutations_are_rejected(self):
        names = (
            "incomplete", "exit_failure", "forced_kill", "cpu_relabel", "outer_group",
            "unit", "backend", "seed_count", "entry_pid", "ready_cgroup",
            "thread_cgroup", "original_checker", "wrong_parent_control", "entry_error",
            "node_close", "binary", "fixed_limit", "fixed_identity", "counter_rewind",
            "before_tasks", "after_tasks", "request_digest", "response_digest",
            "measurement_pid",
            "lifeline_missing_ready", "lifeline_missing_entry", "lifeline_missing_controller",
            "lifeline_old_schema", "lifeline_cut_in_campaign", "lifeline_unit_owner", "lifeline_schema",
            "lifeline_mechanism", "lifeline_not_armed", "lifeline_early_disarm",
            "lifeline_pid", "lifeline_uid", "lifeline_gid", "lifeline_bool_pid",
        )
        self.assertEqual(len(names), BOUNDARY_VECTOR_COUNT)
        self.check_mutations(names, boundary_change)

    def test_rehashed_semantic_substitutions_are_rejected(self):
        names = (
            "import_tip", "import_cursor", "import_bool_hash", "import_short_hash",
            "original_tip", "original_cursor", "original_operation",
            "confirmation_transaction", "confirmation_block", "round_transaction",
            "round_block", "duplicate_round", "confirmation_value",
            "confirmation_failure_label", "confirmation_integer_label",
            "hidden_observed_round", "snapshot_tip", "snapshot_failure", "snapshot_shape",
        )
        self.assertEqual(len(names), BINDING_VECTOR_COUNT)
        self.check_mutations(names, binding_change)

    def check_mutations(self, names, change):
        for name in names:
            with self.subTest(vector=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                report, ipc = fixture(root)
                self.assertTrue(reader.validate_report(report, root, BINARY, OUTER)["complete"])
                change(name, report["phases"][0], ipc[0])
                flush(report, ipc)
                with self.assertRaises((ValueError, KeyError, TypeError, IndexError)):
                    reader.validate_report(report, root, BINARY, OUTER)


if __name__ == "__main__":
    unittest.main(verbosity=2)
