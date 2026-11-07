"""Synthetic raw-record/parser controls, never a generated or verified W1 proof."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from w1_owned_generation_runtime_v2 import complete_controller, complete_worker_archive, archive_object, canonical
import w1_owned_generation_runtime_v2 as runtime
import w1_generation_target_v2 as target
import test_w1_generation_target_v2 as target_controls


def synthetic_controller():
    labels = ["prepare-full-execution", "reverify-existing-prefix", "prove-batch-0000",
              "complete-recursive-compression", "fresh-process-strict-verification"]
    stage = {"schema": "TRNM-W1-STAGE-MEASUREMENT3", "returncode": 0, "stage_process_complete": True,
             "error": None, "termination_reasons": [], "canceled_signal": None, "cancellation_event": None,
             "completion_observed_before_deadline": True, "timed_out": False, "deadline_exhausted_at_snapshot": False,
             "owned_session_observation_complete": True, "final_owned_session_members": [],
             "final_known_group_probes": [{"state": "ABSENT"}], "process_group_remaining_after_child_exit": False}
    return {"schema": "TRNM-W1-COMPLETE-STAGED-RUN3", "complete_proof_claim": True, "error": None,
            "stage_dispatch_attempts": labels, "unretained_stage_labels": [],
            "controller_canceled_signal": None, "controller_cancellation_event": None,
            "deadline_exhausted_at_snapshot": False,
            "stages": [{"stage": label, "result": copy.deepcopy(stage)} for label in labels]}


class OwnerRuntimeTests(unittest.TestCase):
    def test_verified_controller_does_not_substitute_for_complete_worker_archive(self):
        controller = synthetic_controller()
        complete_controller(controller)
        good = {"outcome": "verified", "raw_archive_name": "w1-raw-logs.tar.gz", "raw_archive": {"complete": True},
                "controller_result": controller}
        self.assertEqual(complete_worker_archive(good), "w1-raw-logs.tar.gz")
        for incomplete in (False, None, 1, "true"):
            record = copy.deepcopy(good)
            record["raw_archive"]["complete"] = incomplete
            with self.assertRaisesRegex(ValueError, "closure is not complete"):
                complete_worker_archive(record)
        missing = copy.deepcopy(good)
        del missing["raw_archive"]
        with self.assertRaisesRegex(ValueError, "closure is not complete"):
            complete_worker_archive(missing)

    def test_complete_fact_never_overrides_actual_cancellation_or_missing_stage(self):
        valid = synthetic_controller()
        complete_controller(valid)
        for key, changed in (("controller_canceled_signal", 15), ("controller_cancellation_event", {"signal": 15}),
                             ("unretained_stage_labels", ["prove-batch-0000"]),
                             ("deadline_exhausted_at_snapshot", True), ("stage_dispatch_attempts", [])):
            record = copy.deepcopy(valid)
            record[key] = changed
            with self.assertRaises(ValueError):
                complete_controller(record)

    def test_receipt_fact_does_not_hide_nonzero_or_unreconciled_owned_processes(self):
        valid = synthetic_controller()
        for key, changed in (("returncode", 7), ("final_owned_session_members", [{"pid": 100}]),
                             ("final_known_group_probes", [{"state": "UNKNOWN"}]),
                             ("cancellation_event", {"after_ack": True}), ("owned_session_observation_complete", False)):
            record = copy.deepcopy(valid)
            record["stages"][-1]["result"][key] = changed
            with self.assertRaises(ValueError):
                complete_controller(record)
        record = copy.deepcopy(valid)
        record["stages"][0]["stage"] = "reuse-old-execution"
        record["stage_dispatch_attempts"][0] = "reuse-old-execution"
        with self.assertRaises(ValueError):
            complete_controller(record)

    def test_archive_reads_exact_regular_member_and_rejects_duplicate_or_link(self):
        raw = canonical({"fixture": "not a proof"})
        digest = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for mode in ("regular", "duplicate", "link"):
                path = root / (mode + ".tar.gz")
                with tarfile.open(path, "w:gz") as tar:
                    info = tarfile.TarInfo("controller/result.json")
                    if mode == "link":
                        info.type = tarfile.SYMTYPE
                        info.linkname = "/outside/forbidden"
                        tar.addfile(info)
                    else:
                        info.size = len(raw)
                        tar.addfile(info, io.BytesIO(raw))
                        if mode == "duplicate":
                            tar.addfile(info, io.BytesIO(raw))
                if mode == "regular":
                    self.assertEqual(archive_object(path, "controller/result.json", digest), {"fixture": "not a proof"})
                else:
                    with self.assertRaises(ValueError):
                        archive_object(path, "controller/result.json", digest)

    def test_archive_ambiguous_json_and_path_escape_never_enter_owner_observation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "raw.tar.gz"
            raw = b'{"complete":true,"complete":false}'
            with tarfile.open(path, "w:gz") as tar:
                info = tarfile.TarInfo("controller.json")
                info.size = len(raw)
                tar.addfile(info, io.BytesIO(raw))
            with self.assertRaisesRegex(ValueError, "duplicate JSON"):
                archive_object(path, "controller.json", hashlib.sha256(raw).hexdigest())
            with self.assertRaisesRegex(ValueError, "member path"):
                archive_object(path, "../controller.json", hashlib.sha256(raw).hexdigest())

    def test_local_generate_rejects_via_shared_loader_before_target_open_or_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = root / "request.json"
            config = {"target_instance": "actual-short-process-test"}
            for raw in (b' ' * (target.MAX_REQUEST + 1), b'{"nested":{"k":1,"k":2}}',
                        b'{"nested":[1e999]}', b'[]', b'null'):
                request.write_bytes(raw)
                with self.subTest(raw_prefix=raw[:40]), \
                     patch.object(runtime, "load_target", return_value=target), \
                     patch.object(target, "load_request", wraps=target.load_request) as loader, \
                     patch.object(target, "open_db") as opened, patch.object(target, "dispatch") as dispatched:
                    with self.assertRaises(ValueError):
                        runtime.generate(config, SimpleNamespace(path=root), request)
                    loader.assert_called_once_with(request, config["target_instance"])
                    opened.assert_not_called()
                    dispatched.assert_not_called()

    def test_local_generate_parses_large_real_pins_but_keeps_containment_gate(self):
        # Real pinned files and the real parser; the finite-process request is
        # intentionally not an owned cgroup and must never enter generation.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = target_controls.add_339_real_file_pins(target_controls.short_process_request(root), root)
            value["cgroup_parent"] = str(root)
            request = root / "request.json"
            request.write_text(json.dumps(value, indent=2), encoding="utf-8")
            self.assertGreater(request.stat().st_size, 65536)
            self.assertGreater(len(target.canonical(value)), 65536)
            with patch.object(runtime, "load_target", return_value=target), \
                 patch.object(target, "load_request", wraps=target.load_request) as loader, \
                 patch.object(target, "open_db") as opened, patch.object(target, "dispatch") as dispatched:
                with self.assertRaisesRegex(ValueError, "actual owned sub-cgroup"):
                    runtime.generate({"target_instance": value["target_instance"]}, SimpleNamespace(path=root), request)
                loader.assert_called_once_with(request, value["target_instance"])
                opened.assert_not_called()
                dispatched.assert_not_called()
            self.assertFalse((root / "invocations").exists())


if __name__ == "__main__":
    unittest.main()
