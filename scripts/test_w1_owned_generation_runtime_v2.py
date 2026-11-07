"""Synthetic raw-record/parser controls, never a generated or verified W1 proof."""
import copy
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from w1_owned_generation_runtime_v2 import complete_controller, complete_worker_archive, archive_object, canonical


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


if __name__ == "__main__":
    unittest.main()
