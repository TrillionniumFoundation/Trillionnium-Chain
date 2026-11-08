"""Bounded owner-cancel contract controls. No proof/funding/cgroup kill is run."""
import json
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import w1_owner_cancellation_v1 as cancel
import w1_owned_generation_runtime_v2 as runtime
import w1_generation_target_v2 as target
import test_w1_generation_target_v2 as target_controls


def request_fixture(root):
    """Synthetic funded-intent record only; no Node, M12 or cgroup execution."""
    request = target_controls.add_339_real_file_pins(target_controls.short_process_request(root), root)
    group = root / "synthetic-cgroup-readback"
    group.mkdir()
    (group / "cgroup.controllers").write_text("cpu memory\n")
    request.update(containment="cgroup-v2", cgroup_parent=str(group))
    c = {"provider_operation": request["operation"], "target_instance": request["target_instance"],
         "original_deadline_ns": request["deadline_monotonic_ns"], "out": str(root),
         "target": {"path": str(Path(target.__file__).resolve()), "sha256": target.file_sha(target.__file__)}}
    config_path = root / "config.json"
    config_path.write_bytes(runtime.canonical(c))
    c["_config_path"] = str(config_path)
    request["execution_source_commitment"] = runtime.sha(config_path)
    normalized = {key: value for key, value in request.items() if key != "statement"}
    funded = {"schema": "TRNM-W1-FUNDED-DISPATCH2", "provider_operation": request["operation"],
              "statement": request["statement"], "original_deadline_ns": request["deadline_monotonic_ns"],
              "winner_monotonic_ns": request["winner_monotonic_ns"],
              "target_request_sha256": target.sha(target.canonical(request)),
              "normalized_request_digest": target.sha(target.canonical(normalized))}
    (root / "native-funded-intent.json").write_bytes(runtime.canonical(funded))
    path = root / "request.json"
    path.write_text(json.dumps(request, indent=2), encoding="utf-8")
    return c, request, funded, path


class OwnerCancellationTests(unittest.TestCase):
    def test_only_explicit_complete_owner_plan_grants_a_request(self):
        c = {"owner_cancellation": {"schema": cancel.PLAN, "authority": "development-owner-0",
             "trigger": "live-first-prove-r0vm", "reason_sha256": "01" * 32,
             "native_task_action": "retain-reserved"}}
        self.assertEqual(cancel.plan(c)["native_task_action"], "retain-reserved")
        for changed in ({"provider_error": "failed"}, {**c, "provider": {"kind": "kaggle-cli"}},
                        {"owner_cancellation": {**c["owner_cancellation"], "unexpected": True}},
                        {"owner_cancellation": {**c["owner_cancellation"], "reason_sha256": "0" * 64}}):
            with self.assertRaises(ValueError):
                cancel.plan(changed)


    def test_timeout_domain_and_original_deadline_cannot_be_substituted_by_cancel(self):
        c = {"original_deadline_ns": 1000, "owner_cancellation": {
            "schema": cancel.TIMEOUT_PLAN, "authority": "development-owner-0",
            "trigger": "original-deadline-after-live-first-prove-r0vm",
            "reason_sha256": "02" * 32, "native_task_action": "cancel-reserved"}}
        request = {"operation": "03" * 32, "clock_domain": "04" * 32, "deadline_monotonic_ns": 1000}
        job = {"job_id": "original"}
        retained = {"original_job": job, "target_request_sha256": "05" * 32}
        result = {"operation": request["operation"], "provider_job": job,
            "request_sha256": retained["target_request_sha256"], "clock_domain": request["clock_domain"],
            "original_deadline_monotonic_ns": 1000, "exit_code": -9, "command_success": False,
            "all_owned_processes_terminal": True, "direct_child_reaped": True,
            "resources": {"gpu_ns": None}, "sticky_cancel": False,
            "cause": "original-deadline", "finished_monotonic_ns": 1001}
        row = {"cancel": False, "result": result}
        self.assertEqual(cancel.runtime_schema(c), cancel.TIMEOUT_SCHEMA)
        self.assertEqual(cancel.terminal_observation(c, request, retained, row),
                         {"cancellation_observed": False, "original_deadline_timeout_observed": True})
        for key, value in (("cause", "cancelled"), ("sticky_cancel", True),
                           ("finished_monotonic_ns", 999), ("original_deadline_monotonic_ns", 1001),
                           ("provider_job", {"job_id": "replacement"}),
                           ("clock_domain", "06" * 32), ("command_success", True),
                           ("resources", {"gpu_ns": 0}), ("direct_child_reaped", False)):
            changed = copy.deepcopy(row)
            changed["result"][key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                cancel.terminal_observation(c, request, retained, changed)
        changed = copy.deepcopy(row)
        changed["cancel"] = True
        with self.assertRaises(ValueError):
            cancel.terminal_observation(c, request, retained, changed)
        for key, value in (("schema", cancel.PLAN), ("trigger", "live-first-prove-r0vm"),
                           ("native_task_action", "retain-reserved")):
            changed = copy.deepcopy(c)
            changed["owner_cancellation"][key] = value
            with self.subTest(plan_field=key), self.assertRaises(ValueError):
                cancel.plan(changed)

    def test_duplicate_and_nonfinite_configuration_rejected(self):
        for raw in ('{"authority":1,"authority":2}', '{"deadline":NaN}'):
            with self.assertRaises(ValueError):
                cancel.strict_json(raw)

    def test_actual_coordinator_whole_argv_requires_fixed_r0vm_and_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            c = {"out": str(root), "expected_commit": "a" * 40, "image_id": [1] * 8,
                 "runner": {"path": "/fixed/runner", "sha256": "b" * 64},
                 "r0vm": {"path": "/fixed/r0vm", "sha256": "c" * 64},
                 "guest": {"sha256": "d" * 64}}
            cp = root / "proof/checkpoint"
            cp.mkdir(parents=True)
            manifest = {"schema": "TRNM-W1-STAGED-PROOF2", "source_commit": c["expected_commit"],
                        "input_sha256": "e" * 64, "runner_sha256": "b" * 64,
                        "r0vm_sha256": "c" * 64, "guest_sha256": "d" * 64, "image_id": [1] * 8}
            (cp / "manifest.json").write_text(json.dumps(manifest))
            (root / "native-winner").mkdir()
            (root / "native-winner/result.json").write_text(json.dumps({"input_sha256": "e" * 64}))
            rt = SimpleNamespace(obj=lambda p, *unused: json.loads(Path(p).read_text()))
            target = SimpleNamespace(cgroup_observation=lambda *unused: {"members": []})
            for workers in (1, 2):
                stage = root / "proof/controller" / ("prove-0000" if workers == 1 else "prove-batch-0000")
                stage.mkdir(parents=True)
                args = ["/fixed/runner", "--r0vm", "/fixed/r0vm"] + (
                    ["prove", str(cp), "1"] if workers == 1 else ["prove-parallel", str(cp), "2", "2"])
                declaration = stage / "declaration.json"
                declaration.write_text(json.dumps({"command": args}))
                request = {"proof_plan": {"segment_workers": workers}}
                # Exact argv alone never claims that a live prover was observed.
                self.assertIsNone(cancel.live_first_prover(rt, target, c, request, root, {}))
                for wrong in ([args[0], *args[3:]], [*args[:-1], "8"]):
                    declaration.write_text(json.dumps({"command": wrong}))
                    with self.assertRaisesRegex(ValueError, "exact original"):
                        cancel.live_first_prover(rt, target, c, request, root, {})

    def test_unknown_terminal_retains_last_real_readback_not_only_error_text(self):
        request = {"operation": "01" * 32}
        job = {"identity": {"pid": 7, "start_ticks": 9, "boot_id": "boot"}}
        retained = {"schema": cancel.SCHEMA, "phase": "start", "config_sha256": "h",
                    "operation": request["operation"], "target_request_raw_sha256": "h",
                    "target_request_sha256": "canonical", "original_job": job,
                    "trigger": {"child_cgroup": {"path": "/original", "identity": {"inode": 1}}}}
        row = {"worker": job, "request_sha256": "canonical", "result": None}
        db = SimpleNamespace(close=lambda: None)
        rt = SimpleNamespace(obj=lambda p: retained, sha=lambda p: "h")
        target = SimpleNamespace(open_db=lambda *a: (db, None), read_operation=lambda *a: row,
                                 public_readback=lambda *a: {"sticky_cancel": True, "result": None},
                                 cgroup_observation=lambda *a: {"recursive_empty": False, "members": [7]})
        scope = SimpleNamespace(observe=lambda: {"scope_empty_except_live_caller_ancestors": False, "remaining_noncaller_members": [7]})
        c = {"_config_path": "/fixed", "target_root": "/root", "target_instance": "original",
             "owner_cancellation": {"schema": cancel.PLAN, "authority": "development-owner-0",
                 "trigger": "live-first-prove-r0vm", "reason_sha256": "01" * 32,
                 "native_task_action": "retain-reserved"}}
        with patch.object(cancel, "original_request", return_value=request), \
             patch.object(cancel, "ContinuingScope", return_value=scope), \
             patch.object(cancel, "process_state", return_value={"execution_terminal": False}), \
             patch.object(cancel.time, "monotonic_ns", side_effect=[0, 1, 2, 2_000_000_000]):
            with self.assertRaisesRegex(ValueError, "UNKNOWN") as caught:
                cancel.reconcile(rt, target, c, "/request", "/start", 1)
        snapshot = caught.exception.owner_cancel_observation
        self.assertEqual(snapshot["original_job"], job)
        self.assertEqual(snapshot["child_cgroup"]["members"], [7])
        self.assertIsNone(snapshot["target"]["result"])

    def test_worker_exit_observation_does_not_claim_wait_reaped(self):
        selected = {"boot_id": "original", "pid": 123, "start_ticks": 1}
        target = SimpleNamespace(boot_id=lambda: "new")
        self.assertEqual(cancel.process_state(target, selected)["state"], "UNKNOWN")
        target.boot_id = lambda: "original"
        target.process_identity = lambda pid: selected
        with patch.object(Path, "read_text", return_value="123 (fixture) Z 1 1"):
            state = cancel.process_state(target, selected)
        self.assertTrue(state["execution_terminal"])
        self.assertFalse(state["wait_reaped"])
        with patch.object(Path, "read_text", side_effect=FileNotFoundError()):
            self.assertIsNone(cancel.process_state(target, selected)["wait_reaped"])

    def test_original_large_request_uses_common_loader_and_keeps_exact_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            c, request, funded, path = request_fixture(root)
            self.assertGreater(path.stat().st_size, 65536)
            self.assertGreater(len(target.canonical(request)), 65536)
            with patch.object(target, "load_request", wraps=target.load_request) as loader:
                actual = cancel.original_request(runtime, target, c, path, check_clock=True)
                self.assertEqual(actual, request)
                loader.assert_called_once_with(path, c["target_instance"], check_clock=True)
            for key, replacement in (("schema", "v3"), ("operation", "fe" * 32),
                                     ("target_instance", "replacement-target"), ("statement", "fa" * 32),
                                     ("deadline_monotonic_ns", c["original_deadline_ns"] + 1),
                                     ("target_backend_sha256", "fb" * 32),
                                     ("execution_source_commitment", "fc" * 32)):
                changed = copy.deepcopy(request)
                changed[key] = replacement
                path.write_bytes(target.canonical(changed))
                with self.subTest(field=key), self.assertRaises(ValueError):
                    cancel.original_request(runtime, target, c, path)
            path.write_bytes(target.canonical(request))
            for key in ("statement", "normalized_request_digest", "target_request_sha256", "provider_operation"):
                changed = copy.deepcopy(funded)
                changed[key] = "ff" * 32
                (root / "native-funded-intent.json").write_bytes(runtime.canonical(changed))
                with self.subTest(intent_field=key), self.assertRaisesRegex(ValueError, "funded statement/request"):
                    cancel.original_request(runtime, target, c, path)
            (root / "native-funded-intent.json").write_bytes(runtime.canonical(funded))
            with Path(c["_config_path"]).open("ab") as stream:
                stream.write(b" ")
            with self.assertRaisesRegex(ValueError, "original config changed"):
                cancel.original_request(runtime, target, c, path)
            self.assertFalse((root / "invocations").exists())

    def test_request_loader_refuses_ambiguity_but_reconcile_keeps_original_expired_clock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            c, request, _, path = request_fixture(root)
            with patch.object(target.time, "monotonic_ns", return_value=c["original_deadline_ns"] + 1):
                self.assertEqual(cancel.original_request(runtime, target, c, path), request)
                with self.assertRaisesRegex(ValueError, "original deadline expired"):
                    cancel.original_request(runtime, target, c, path, check_clock=True)
            # Only the input-reader boundary is exercised, never a cold owner
            # operation or a claim that a fabricated cgroup has been reclaimed.
            for raw in (b' ' * (target.MAX_REQUEST + 1), b'{"nested":{"k":1,"k":2}}',
                        b'{"nested":[1e999]}', b'[]', b'null'):
                path.write_bytes(raw)
                with self.subTest(raw_prefix=raw[:40]), \
                     patch.object(target, "load_request", wraps=target.load_request) as loader, \
                     patch.object(target, "open_db") as opened, patch.object(target, "dispatch") as dispatched:
                    with self.assertRaises(ValueError):
                        cancel.original_request(runtime, target, c, path)
                    loader.assert_called_once_with(path, c["target_instance"], check_clock=False)
                    opened.assert_not_called()
                    dispatched.assert_not_called()
            self.assertFalse((root / "invocations").exists())


if __name__ == "__main__":
    unittest.main()
