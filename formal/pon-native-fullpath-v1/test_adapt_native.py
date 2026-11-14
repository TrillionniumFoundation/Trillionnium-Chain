"""Synthetic raw collector records test accounting, never native computation."""
import copy
from pathlib import Path
import tempfile
import unittest

import adapt_native as adapter
import fullpath_gate as gate
from test_fullpath_gate import Campaign, progress


class OriginalCollector:
    def __init__(self, root):
        self.root = Path(root)
        self.c = Campaign(root)
        self.c.put("candidate.pnp2", self.c.raw)
        altered = bytearray(self.c.raw); altered[-36] = 1
        self.bad = gate.parse_packet(bytes(altered))
        self.c.put("late-product.pnp2", bytes(altered))
        self.native_context = dict(schema=gate.PROCESS_SCHEMA, event="context", development=True,
            network_hex="01" * 32, parameters_hex="02" * 32, genesis_hex="03" * 32,
            parent_hex="03" * 32, task_hex="09" * 32, packet_limit=gate.PACKET_LIMIT)
        self.c.put_json("context.stdout.json", self.native_context)
        self.context = dict(schema=adapter.CONTEXT_SCHEMA, scope="same-host-development-component-observation",
            source_commit="ab" * 20, source_tree="cd" * 20, binary_sha256="11" * 32,
            collector_sha256="22" * 32, native_context=self.native_context,
            workload="synthetic adapter test; no actual native work", resource_enforcement="unqualified host",
            original_business_contract=dict(deadline_ns=4_000_000_000, required_depth=6,
                cpu_cores="0.25", memory_bytes=2147483648, swap_bytes=0, pids=256, hostile_workers=16))
        context_ref = self.c.put_json("context.json", self.context)
        self.plan = dict(schema=adapter.PLAN_SCHEMA, context_sha256=context_ref["sha256"], required_depth=6,
            observation_end_ns=4_000_000_000, all_scheduled_starts_retained=True, production_activation=False,
            schedule=[dict(id=identity, cohort=cohort, mode="native", requires_new_search=identity == "valid",
                           scheduled_ns=0, deadline_ns=4_000_000_000,
                           parent_hex="03" * 32, task_hex="09" * 32)
                      for identity, (cohort, _, _) in adapter.ATTEMPTS.items()])
        self.plan_ref = self.c.put_json("preregistration.json", self.plan)
        self.processes = []
        search = self.c.native_event("search_complete"); search["nonce_attempts"] = 1
        prepared = self.c.native_event("produce_complete")
        self.add("produce", [search, prepared])
        self.add("receive", self.receive_events())
        observed = self.c.native_event("observe_complete"); observed["native_observation"] = self.c.observation()
        self.add("observe", [observed])
        self.add("duplicate", self.receive_events(duplicate=True))
        self.add("duplicate-observe", [observed])
        error = self.identity_event("error", self.bad)
        error.update(stage="verification", error="WORK:Product", cancelled=False,
                     admission_call_ns=10, work_progress=progress((1, 512, 1, 0)))
        self.add("late-product", [self.identity_event("packet_received", self.bad)], error=error)
        bad_observed = self.identity_event("observe_complete", self.bad)
        bad_observed["native_observation"] = self.absent()
        self.add("late-product-observe", [bad_observed])
        cancelled = self.c.native_event("error")
        cancelled.update(stage="verification", error="PUBLIC_REQUEST_CANCELLED", cancelled=True,
                         admission_call_ns=10, work_progress=progress())
        self.add("cancelled", [self.c.native_event("packet_received")], error=cancelled)
        absent = self.c.native_event("observe_complete"); absent["native_observation"] = self.absent()
        self.add("cancelled-observe", [absent])
        self.report = dict(schema=adapter.SOURCE_SCHEMA, manifest_sha256=self.plan_ref["sha256"],
            context_sha256=context_ref["sha256"], observed_through_ns=1000,
            source_and_binary_unchanged=True, cpu_ns=100, peak_rss_upper_bound_bytes=200,
            owner_unresolved=False, unresolved_owner=None, resource_accounting_complete=True,
            collection_errors=[],
            stdin_bytes_written=sum(row["stdin_bytes_written"] for row in self.processes),
            attempts=[dict(id=identity, status="observed", processes=names, planned_processes=names)
                      for identity, (_, names, _) in adapter.ATTEMPTS.items()], processes=self.processes)
        self.save()

    def identity_event(self, name, packet):
        value = self.c.native_event(name)
        for field in ("claim", "block_hex", "parent_hex", "task_hex", "challenge_hex", "packet_bytes"):
            value[field] = packet[field]
        return value

    def receive_events(self, duplicate=False):
        admission = self.c.native_event("admission_complete")
        admission.update(admitted_block_hex=self.c.packet["block_hex"], admission_reused_existing=duplicate,
                         admission_call_ns=10, work_progress=progress((0, 0, 0, 0) if duplicate else (1, 512, 1, 1)))
        return [self.c.native_event("packet_received"), admission, self.c.native_event("receive_complete")]

    def absent(self):
        value = self.c.observation(member=False, stored=False)
        value.update(active_tip="03" * 32, active_tip_height=0, active_tip_chainwork_hex="00" * 64)
        return value

    def add(self, identity, events, error=None):
        start = 10 + 100 * len(self.processes)
        raw = b"".join(gate.canonical(event) + b"\n" for event in events)
        stdout = self.stream(identity + ".stdout.ndjson", raw)
        stderr = self.stream(identity + ".stderr.txt", gate.canonical(error) + b"\n" if error else b"")
        row = dict(id=identity, argv=["development-fixture", identity], pid=100 + len(self.processes),
            start_ns=start, end_ns=start + 90, exit_code=2 if error else 0, timed_out=False,
            process_started=True, process_reaped=True, pipes_resolved=True, process_group_resolved=True,
            owner_unresolved=False, dispatch_blocked_by=None, cleanup_attempted=False,
            stderr_error_event=error is not None,
            process_errors=[], cleanup_errors=[], cleanup_notes=[], output_errors=[],
            resource_accounting_complete=True,
            events=[dict(at_ns=start + 10 * (i + 1), value=value) for i, value in enumerate(events)],
            reader_errors=[], feeder_errors=[],
            stdin_bytes_written=len(self.c.raw) if identity in {"receive", "duplicate", "late-product", "cancelled"} else 0,
            cpu_ns=10, peak_rss_upper_bound_bytes=200, stdout=stdout, stderr=stderr)
        self.processes.append(row)

    def stream(self, path, raw):
        return dict(self.c.put(path, raw), complete=True)

    def save(self):
        for row in self.processes:
            self.c.put_json(row["id"] + ".process.json", row)
        self.c.put_json("process-observations.json", self.report)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.original = OriginalCollector(self.tmp.name)

    def read(self):
        return adapter.adapt(self.tmp.name, self.original.plan_ref["sha256"])

    def test_four_original_starts_and_failures_survive_normalization(self):
        original = self.original
        before = (original.root / "preregistration.json").read_bytes()
        result = self.read()
        self.assertEqual(result["scheduled"], 4)
        self.assertEqual(result["recorded"], 4)
        self.assertEqual([row["status"] for row in result["attempts"]],
                         ["accepted", "duplicate", "rejected", "cancelled"])
        self.assertEqual(result["recorded_unique_new_native_blocks"], 1)
        self.assertEqual(result["timely_accepted_progress"], 0)
        self.assertFalse(result["observation_window_covered"])
        self.assertTrue(result["attempts"][2]["late_product_rejection_observed"])
        self.assertFalse(result["attempts"][3]["full_native_replay_observed"])
        self.assertEqual(result["performance_gate"], "COMPONENT_OBSERVATION_ONLY")
        self.assertEqual((original.root / "preregistration.json").read_bytes(), before)
        self.assertEqual(self.read(), result)  # Same originals, deterministic idempotent readback.
        normalized = gate.decode((original.root / "gate-observations.json").read_bytes())
        self.assertEqual([stage["phase"] for stage in normalized["attempts"][1]["stages"]],
                         ["propagation", "verification", "acceptance"])
        self.assertEqual([stage["phase"] for stage in normalized["attempts"][2]["stages"]],
                         ["propagation", "verification"])

    def test_original_digest_and_fixed_business_thresholds_cannot_be_relaxed(self):
        with self.assertRaisesRegex(ValueError, "ORIGINAL_PREREGISTRATION_DIGEST"):
            adapter.adapt(self.tmp.name, "ff" * 32)
        original = self.original
        original.plan["required_depth"] = 0
        original.plan_ref = original.c.put_json("preregistration.json", original.plan)
        original.report["manifest_sha256"] = original.plan_ref["sha256"]
        original.save()
        with self.assertRaisesRegex(ValueError, "ORIGINAL_BUSINESS_THRESHOLDS"):
            self.read()

    def test_raw_stdout_cannot_be_replaced_by_aggregate_success_fields(self):
        original = self.original
        original.processes[1]["events"][1]["value"]["work_progress"]["BeforeVerifiedWork"]["count"] = 0
        original.save()
        with self.assertRaisesRegex(ValueError, "NATIVE_STDOUT_EVENT_MISMATCH"):
            self.read()

    def test_preregistered_parent_and_task_must_match_original_native_context(self):
        original = self.original
        for field in ("parent_hex", "task_hex"):
            before = original.plan["schedule"][0][field]
            original.plan["schedule"][0][field] = "ff" * 32
            original.plan_ref = original.c.put_json("preregistration.json", original.plan)
            original.report["manifest_sha256"] = original.plan_ref["sha256"]
            original.save()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "ORIGINAL_START_CHANGED"):
                self.read()
            original.plan["schedule"][0][field] = before

    def test_zero_progress_duplicate_cannot_be_called_new_acceptance(self):
        original = self.original
        row = original.processes[3]
        row["events"][1]["value"]["admission_reused_existing"] = False
        row["stdout"] = original.stream(row["stdout"]["path"], b"".join(gate.canonical(value["value"]) + b"\n" for value in row["events"]))
        original.save()
        with self.assertRaisesRegex(ValueError, "REUSED_WORK_IS_NOT_NEW"):
            self.read()

    def test_same_callback_counts_with_local_error_are_not_product_rejection(self):
        original = self.original
        row = original.processes[5]
        error = gate.decode(gate.Evidence(original.root).artifact(adapter.retained_reference(row["stderr"])))
        error["error"] = "PUBLIC_CPU_BUDGET"
        row["stderr"] = original.stream(row["stderr"]["path"], gate.canonical(error) + b"\n")
        original.save()
        result = self.read()
        self.assertEqual(result["attempts"][2]["status"], "error")
        self.assertFalse(result["attempts"][2]["late_product_rejection_observed"])

    def test_launch_failure_with_null_pid_and_exit_keeps_all_four_starts(self):
        original = self.original
        row = original.processes[0]
        row.update(pid=None, exit_code=None, process_errors=["PROCESS:PermissionError:launch failed"],
                   process_started=False, process_reaped=False,
                   events=[], stdin_bytes_written=0)
        row["stdout"] = original.stream(row["stdout"]["path"], b"")
        row["stderr"] = original.stream(row["stderr"]["path"], b"launch failed\n")
        original.processes[:] = [row]
        original.report["attempts"] = [dict(id=identity, status="error", reason="NO_COMPLETE_SOURCE_PACKET",
                                            planned_processes=names, processes=["produce"] if identity == "valid" else [])
                                        for identity, (_, names, _) in adapter.ATTEMPTS.items()]
        original.report["stdin_bytes_written"] = 0
        (original.root / "candidate.pnp2").unlink()
        (original.root / "late-product.pnp2").unlink()
        original.save()
        result = self.read()
        self.assertEqual(result["scheduled"], 4)
        self.assertEqual([row["status"] for row in result["attempts"]], ["error"] * 4)
        self.assertEqual(result["recorded_unique_new_native_blocks"], 0)

    def test_unresolved_process_owner_cannot_be_success(self):
        original = self.original
        row = original.processes[1]
        row.update(exit_code=None, process_reaped=False, owner_unresolved=True)
        original.save()
        result = self.read()
        self.assertEqual(result["attempts"][0]["status"], "error")
        self.assertEqual(result["recorded_unique_new_native_blocks"], 0)
        self.assertEqual(result["overall_gate"], "HOLD")

    def test_unstable_stream_and_unavailable_resource_counters_preserve_failure(self):
        original = self.original
        row = original.processes[1]
        row.update(exit_code=None, process_reaped=False, pipes_resolved=False,
                   process_group_resolved=False, owner_unresolved=True, resource_accounting_complete=False)
        for field in ("stdout", "stderr"):
            row[field].update(sha256=None, complete=False)
        original.report.update(owner_unresolved=True, unresolved_owner="receive",
                               resource_accounting_complete=False, source_and_binary_unchanged=False,
                               collection_errors=["FINAL_SOURCE_AUDIT_SKIPPED_UNRESOLVED_OWNER"])
        original.save()
        result = self.read()
        self.assertEqual(result["scheduled"], 4)
        self.assertEqual(result["attempts"][0]["status"], "error")
        self.assertIsNone(result["resources"]["cpu_ns"])
        self.assertFalse(result["recorded_resource_thresholds_met"])

    def test_timeout_exit_zero_and_cleanup_do_not_become_success(self):
        original = self.original
        original.processes[1]["timed_out"] = True
        original.processes[1]["cleanup_attempted"] = True
        original.save()
        result = self.read()
        self.assertEqual(result["attempts"][0]["status"], "timeout")
        self.assertEqual(result["recorded_unique_new_native_blocks"], 0)

    def test_success_stdout_and_zero_exit_cannot_hide_error_in_original_stderr(self):
        original = self.original
        row = original.processes[1]
        error = original.c.native_event("error")
        error.update(stage="acceptance", error="LOCAL_IO_ERROR", cancelled=False)
        row["stderr"] = original.stream(row["stderr"]["path"], gate.canonical(error) + b"\n")
        row["stderr_error_event"] = False  # Untrusted aggregate must not hide the retained original.
        original.save()
        result = self.read()
        self.assertEqual(result["attempts"][0]["status"], "error")
        self.assertEqual(result["recorded_unique_new_native_blocks"], 0)


if __name__ == "__main__":
    unittest.main()
