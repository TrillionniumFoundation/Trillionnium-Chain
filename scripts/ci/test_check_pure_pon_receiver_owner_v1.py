#!/usr/bin/env python3
"""Synthetic association/negative controls; these are never native CPU evidence."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import check_pure_pon_receiver_owner_v1 as reader
import test_check_pure_pon_process_cost_v1 as fixture


def write(path, value):
    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
    path.write_bytes(raw)
    return fixture.binding(raw)


def raw_frame(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def write_supplement(directory, args):
    fixture.write_processes(directory, args)
    manifest, prepared, phases, _ = copy.deepcopy(args)
    manifest.update(schema=reader.CAMPAIGN_SCHEMA, scope=reader.OWNER_SCOPE,
                    original_campaign_qualification=False, fixed_parent_provisioned=False,
                    physical_authentication=False)
    write(directory / "campaign.json", manifest)
    for index, phase in enumerate(phases):
        name, epoch, pid = phase["phase"], phase["epoch_monotonic_ns"], 50000 + index
        path = directory / name
        phase.update(schema=reader.PHASE_SCHEMA, scope=reader.OWNER_SCOPE,
                     experiment="receiver-owner-supplement", parent_pid=90000, receiver_pid=pid,
                     receiver_exit_success=True, receiver_parent_forced_kill=False,
                     original_campaign_qualification=False, physical_authentication=False)
        fields = ("phase", "scope", "experiment", "policy", "window_ns", "epoch_monotonic_ns", "listeners",
                  "shared_cpu_domain", "initial_budget", "initial_flow", "initial_admission", "final_budget",
                  "final_flow", "final_admission", "services", "observations", "receiver_tip", "receiver_height",
                  "receiver_generation", "physical_authentication", "public_fairness_qualified", "production_qualified")
        node = {k: copy.deepcopy(phase[k]) for k in fields}
        node.update(schema=reader.NODE_SCHEMA, pid=pid, received_stop=True, control_error=None,
                    owned_reactors_joined=2, node_owner_dropped=True, control_receipts=[], hostile_snapshots=[],
                    kernel_parent={"path": reader.FIXED_PARENT, "created_or_modified": False,
                                   "scope": reader.KERNEL_SCOPE, "open_error": "parent absent",
                                   "before": None, "after": None, "delta": None})
        write(path / "receiver-ready.json", {"schema": "pon-receiver-ready-v1", "pid": pid,
              "experiment": "receiver-owner-supplement", "subreaper_enabled": True,
              "addresses": ["127.0.0.1:10001", "127.0.0.1:10002"], "initial_height": 4, "initial_generation": 4,
              "initial_tip": reader.pressure.packet(bytes.fromhex(prepared["seed"][-1]))["id"]})
        write(path / "receiver-job.json", {"schema": "pon-receiver-job-v1", "phase": name,
              "experiment": "receiver-owner-supplement", "control_socket": "/synthetic/private/ipc",
              "seed_packets": prepared["seed"],
              "honest_body_digests": sorted(p["body"] for p in reader.pressure.preparation(prepared))})
        events = [(epoch - 1, epoch + 1, "arm", {"epoch_monotonic_ns": epoch})]
        for sample in phase["samples"]:
            events.append((epoch + sample["started_ns"] - 1, epoch + sample["ended_ns"] + 1, "sample", sample))
        for round in phase["rounds"]:
            for key in ("hostile_before", "hostile_after"):
                snapshot = round[key]
                events.append((epoch + snapshot["started_ns"] - 1, epoch + snapshot["ended_ns"] + 1, "hostile", snapshot))
        events.sort(key=lambda row: row[0])
        events.append((epoch + reader.pressure.WINDOW + 50, epoch + reader.pressure.WINDOW + 145, "stop", None))
        rows, size = [], 0
        for sequence, (start, end, operation, value) in enumerate(events):
            if operation == "hostile":
                filename = f"hostile-{sequence}.json"
                bound = write(path / filename, value)
                value = {"file": filename, "binding": bound}
                node["hostile_snapshots"].append(value)
            request = raw_frame({"schema": "pon-receiver-control-request-v1", "sequence": sequence, "operation": operation})
            request_sha = hashlib.sha256(request).hexdigest()
            if operation == "stop":
                node["control_receipts"].append({"sequence": sequence, "operation": operation,
                                                "request_sha256": request_sha, "response_sha256": None})
                value = {"report": write(path / "receiver-report.json", node)}
            response = raw_frame({"schema": "pon-receiver-control-response-v1", "sequence": sequence,
                                  "operation": operation, "pid": pid, "value": value})
            response_sha = hashlib.sha256(response).hexdigest()
            if operation != "stop":
                node["control_receipts"].append({"sequence": sequence, "operation": operation,
                                                "request_sha256": request_sha, "response_sha256": response_sha})
            rows.append({"sequence": sequence, "operation": operation, "started_monotonic_ns": start,
                         "ended_monotonic_ns": end, "request_hex": request.hex(), "response_hex": response.hex(),
                         "request_sha256": request_sha, "response_sha256": response_sha,
                         "sent_frame_bytes": len(request) + 4,
                         "response_prefix_hex": len(response).to_bytes(4, "big").hex(),
                         "response_payload_hex": response.hex(), "error": None})
            size += len(request) + len(response)
        write(path / "receiver-control-trace.json", {"schema": "pon-receiver-control-trace-v2", "scope": reader.IPC_SCOPE,
              "parent_pid": 90000, "receiver_pid": pid, "frame_limit": reader.FRAME_LIMIT,
              "trace_payload_limit": reader.TRACE_LIMIT, "payload_bytes": size, "exchanges": rows,
              "physical_authentication": False})
        cost = fixture.receipt(pid, epoch=epoch)
        family = fixture.family(pid, epoch)
        family["child_subreaper"] = True
        write(path / "receiver-wait4.json", cost)
        write(path / "receiver-family-observation-v1.json", family)
        (path / "receiver.log").write_bytes(b"synthetic receiver terminal\n")
        bind = {"schema": "pon-pure-receiver-owner-binding-v1", "scope": reader.OWNER_SCOPE,
                "parent_pid": 90000, "receiver_pid": pid, "cost": cost,
                "started_monotonic_ns": epoch + reader.pressure.WINDOW + 300,
                "ended_monotonic_ns": epoch + reader.pressure.WINDOW + 400,
                "read_budget_ns": reader.actor.CAPTURE_BUDGET, "capture_complete": True,
                "files": {file: fixture.binding((path / file).read_bytes()) for file in reader.FILES},
                "physical_authentication": False, "public_fairness_qualified": False, "production_qualified": False}
        write(path / "receiver-owner-binding-v1.json", bind)
        fixture.write_probe_binding(path, "receiver", name, 90000, [pid], epoch)
        phase.update({key: value for key, value in node.items() if key != "schema"})
        write(directory / f"{name}.json", phase)


class ReceiverControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.args = fixture.fixture.campaign()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        write_supplement(self.root, self.args)
        self.phase = self.root / "correct-product-false-trace.json"
        self.location = self.root / "correct-product-false-trace"

    def mutate(self, path, function, rebind=False):
        value = json.loads(path.read_text())
        function(value)
        write(path, value)
        if rebind:
            binding = self.location / "receiver-owner-binding-v1.json"
            value = json.loads(binding.read_text())
            if path.name != "receiver-child-ownership-v1.json":
                value["files"][path.name] = fixture.binding(path.read_bytes())
                if path.name == "receiver-wait4.json":
                    value["cost"] = json.loads(path.read_text())
                write(binding, value)
            ownership = self.location / "receiver-child-ownership-binding-v1.json"
            outer = json.loads(ownership.read_text())
            outer["parent_cost_binding"] = fixture.binding(binding.read_bytes())
            if path.name == "receiver-child-ownership-v1.json":
                outer["children"][0]["binding"] = fixture.binding(path.read_bytes())
            write(ownership, outer)

    def test_full_synthetic_capture_is_separate_and_unknown_parent_is_not_zero(self):
        result = reader.check_directory(self.root)
        self.assertTrue(result["input_consistent"])
        self.assertTrue(result["receiver_lifetime_cost_observed"])
        self.assertTrue(result["receiver_descendants_quiescent_observed"])
        self.assertTrue(result["supplemental_finite_qualification"])
        self.assertFalse(result["original_campaign_qualification"])
        self.assertFalse(result["public_fairness_qualified"])
        self.assertFalse(result["exclusive_receiver_cgroup_observed"])
        self.assertIsNone(result["receiver_processes"][0]["fixed_parent_cpu_delta"])

    def test_original_reader_cannot_consume_new_campaign_namespace(self):
        with self.assertRaisesRegex(ValueError, "campaign envelope"):
            reader.actor.check_directory(self.root)

    def test_legacy_campaign_cannot_claim_receiver_ownership(self):
        self.mutate(self.root / "campaign.json", lambda value: value.update(schema=reader.pressure.SCHEMA))
        with self.assertRaisesRegex(ValueError, "supplemental campaign"):
            reader.check_directory(self.root)

    def test_wrong_receiver_pid_cannot_use_mixed_parent_cpu(self):
        self.mutate(self.phase, lambda value: value.update(receiver_pid=value["parent_pid"]))
        with self.assertRaisesRegex(ValueError, "mixed receiver"):
            reader.check_directory(self.root)

    def test_same_length_receiver_log_tamper_rejects(self):
        path = self.location / "receiver.log"
        raw = path.read_bytes()
        path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            reader.check_directory(self.root)

    def test_parent_phase_cannot_change_bound_receiver_sample(self):
        self.mutate(self.phase, lambda value: value["final_flow"].update(paid_cpu_debit_ns=1))
        with self.assertRaisesRegex(ValueError, "changed receiver"):
            reader.check_directory(self.root)

    def test_deleted_final_ipc_row_cannot_hide_stop(self):
        self.mutate(self.location / "receiver-control-trace.json", lambda value: value["exchanges"].pop(), rebind=True)
        with self.assertRaisesRegex(ValueError, "complete request coverage"):
            reader.check_directory(self.root)

    def test_ipc_lost_receive_stays_failure_even_with_parent_rebinding(self):
        self.mutate(self.location / "receiver-control-trace.json",
                    lambda value: value["exchanges"][2].update(response_hex=None, error="timed out"), rebind=True)
        with self.assertRaisesRegex(ValueError, "incomplete receive"):
            reader.check_directory(self.root)

    def test_sampling_row_cannot_be_omitted_from_phase(self):
        self.mutate(self.phase, lambda value: value["samples"].pop())
        with self.assertRaisesRegex(ValueError, "sample omitted"):
            reader.check_directory(self.root)

    def test_unknown_receiver_cpu_is_not_replaced_with_zero(self):
        self.mutate(self.location / "receiver-wait4.json",
                    lambda value: value["rusage"].update(user_seconds=-1, user_cpu_ns=None, total_cpu_ns=None), rebind=True)
        result = reader.check_directory(self.root)
        self.assertFalse(result["receiver_lifetime_cost_observed"])
        self.assertIsNone(result["receiver_processes"][2]["total_cpu_ns"])

    def test_nonempty_descendant_census_does_not_obtain_quiescence(self):
        def dirty(value):
            value["thread_children"][0]["children"] = [60000]
            value.update(observed_child_pids=[60000], no_live_or_unreaped_children_observed=False)
        self.mutate(self.location / "receiver-family-observation-v1.json", dirty, rebind=True)
        with self.assertRaisesRegex(ValueError, "contradict"):
            reader.check_directory(self.root)

    def test_missing_subreaper_is_not_process_family_coverage(self):
        self.mutate(self.location / "receiver-family-observation-v1.json",
                    lambda value: value.update(child_subreaper=False), rebind=True)
        self.assertFalse(reader.check_directory(self.root)["receiver_descendants_quiescent_observed"])

    def test_nested_authority_promotion_rejects(self):
        self.mutate(self.root / "campaign.json", lambda value: value.update(nested={"physical_authentication": True}))
        with self.assertRaisesRegex(ValueError, "authority"):
            reader.check_directory(self.root)

    def test_duplicate_keys_and_symlink_raw_capture_reject(self):
        path = self.location / "receiver-wait4.json"
        raw = path.read_bytes()
        path.write_bytes(b'{"schema":"ignored",' + raw[1:])
        with self.assertRaises(ValueError):
            reader.check_directory(self.root)
        path.unlink()
        target = self.root / "linked-receipt"
        target.write_bytes(raw)
        path.symlink_to(target)
        with self.assertRaises(OSError):
            reader.check_directory(self.root)

    def test_arm_epoch_must_be_inside_actual_request_response_bracket(self):
        epoch = json.loads(self.phase.read_text())["epoch_monotonic_ns"]
        self.mutate(self.location / "receiver-control-trace.json", lambda value:
                    value["exchanges"][0].update(started_monotonic_ns=epoch + 1, ended_monotonic_ns=epoch + 2), rebind=True)
        with self.assertRaisesRegex(ValueError, "clock bracket"):
            reader.check_directory(self.root)

    def test_stop_cannot_gain_second_timeout_after_prefix(self):
        epoch = json.loads(self.phase.read_text())["epoch_monotonic_ns"]
        self.mutate(self.location / "receiver-control-trace.json", lambda value:
                    value["exchanges"][-1].update(started_monotonic_ns=epoch + 31_000_000_000,
                                                  ended_monotonic_ns=epoch + 36_000_000_000), rebind=True)
        with self.assertRaisesRegex(ValueError, "absolute cleanup"):
            reader.check_directory(self.root)

    def test_partial_prefix_and_payload_cannot_be_relabelled_complete(self):
        self.mutate(self.location / "receiver-control-trace.json", lambda value:
                    value["exchanges"][-1].update(response_payload_hex="7b"), rebind=True)
        with self.assertRaisesRegex(ValueError, "partial frame"):
            reader.check_directory(self.root)

    def test_receiver_probe_has_independent_exact_parent_binding(self):
        path = self.location / "receiver-child-ownership-v1.json"
        self.mutate(path, lambda value: value.update(no_eligible_children_at_probe=False))
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            reader.check_directory(self.root)

    def test_missing_proc_files_are_preserved_with_explicit_kernel_basis(self):
        self.mutate(self.location / "receiver-family-observation-v1.json", lambda value:
                    value.update(capture_complete=False, errors=["ENOENT"], no_live_or_unreaped_children_observed=False), rebind=True)
        result = reader.check_directory(self.root)
        observed = result["receiver_processes"][2]
        self.assertFalse(observed["procfs_capture_complete"])
        self.assertTrue(observed["no_eligible_children_at_probe"])
        self.assertEqual(observed["quiescence_basis"], "waitid-echild-with-sig-dfl-no-nocldwait")
        self.assertFalse(result["physical_authentication"])

    def test_kernel_probe_zero_event_does_not_silently_replace_proc_unknown(self):
        self.mutate(self.location / "receiver-family-observation-v1.json", lambda value:
                    value.update(capture_complete=False, errors=["ENOENT"], no_live_or_unreaped_children_observed=False), rebind=True)
        self.mutate(self.location / "receiver-child-ownership-v1.json", lambda value:
                    value.update(waitid_return=0, errno=None, event={"signo": 0, "code": 0, "errno": 0,
                                 "pid": 0, "uid": 0, "status": 0}, waitid_echild_observed=False,
                                 no_eligible_children_at_probe=False), rebind=True)
        result = reader.check_directory(self.root)
        self.assertFalse(result["receiver_descendants_quiescent_observed"])
        self.assertFalse(result["receiver_processes"][2]["procfs_capture_complete"])


class KernelControls(unittest.TestCase):
    def sample(self, cpu):
        return {"schema": "public-host-kernel-bound-resource-sample-v1",
                "binding": {"schema": "public-host-kernel-binding-v1", "parent": reader.FIXED_PARENT,
                            "boot_id": "synthetic", "device": 1, "inode": 2, "cpu_quota_usec": 25000,
                            "cpu_period_usec": 100000, "cpu_burst_usec": 0, "memory_max_bytes": 2 * 1024 ** 3,
                            "memory_swap_max_bytes": 0, "pids_max": 256},
                "resources": {"cpu_usage_usec": cpu, "cpu_nr_periods": 2, "cpu_nr_throttled": 0,
                              "cpu_throttled_usec": 0, "memory_current_bytes": 1000, "pids_current": 5}}

    def value(self):
        return {"path": reader.FIXED_PARENT, "scope": reader.KERNEL_SCOPE, "created_or_modified": False,
                "open_error": None, "before": {"Ok": self.sample(100)}, "after": {"Ok": self.sample(200)},
                "delta": {"Ok": {"usage_usec": 100, "nr_periods": 0, "nr_throttled": 0, "throttled_usec": 0}}}

    def test_bound_parent_counters_stay_aggregate(self):
        self.assertTrue(reader.kernel_observation(self.value())["fixed_parent_interval_observed"])

    def test_changed_parent_or_rewind_or_invented_delta_rejects(self):
        for mutation in (lambda v: v["after"]["Ok"]["binding"].update(inode=3),
                         lambda v: v["after"]["Ok"]["resources"].update(cpu_usage_usec=99),
                         lambda v: v["delta"]["Ok"].update(usage_usec=101),
                         lambda v: v["after"]["Ok"]["binding"].update(cpu_quota_usec=True)):
            value = self.value()
            mutation(value)
            with self.assertRaises(ValueError):
                reader.kernel_observation(value)

    def test_unknown_endpoint_is_not_zero_delta(self):
        value = self.value()
        value.update(after={"Err": "counter unavailable"}, delta=None)
        self.assertIsNone(reader.kernel_observation(value)["fixed_parent_cpu_delta"])
        value["delta"] = {"Ok": {"usage_usec": 0}}
        with self.assertRaises(ValueError):
            reader.kernel_observation(value)


if __name__ == "__main__":
    unittest.main()
