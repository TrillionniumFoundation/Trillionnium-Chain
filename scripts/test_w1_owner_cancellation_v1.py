"""Bounded owner-cancel contract controls. No proof/funding/cgroup kill is run."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import w1_owner_cancellation_v1 as cancel


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
        c = {"_config_path": "/fixed", "target_root": "/root", "target_instance": "original"}
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


if __name__ == "__main__":
    unittest.main()
