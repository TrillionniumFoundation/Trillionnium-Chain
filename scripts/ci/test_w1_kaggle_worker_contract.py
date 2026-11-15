#!/usr/bin/env python3
"""CPU-only data contracts. These tests never generate or simulate a valid proof."""

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "scripts/w1_kaggle_worker_template.py"
SPEC = importlib.util.spec_from_file_location("w1_kaggle_worker_contract_target", PATH)
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)


def data_config():
    # Encoding fixtures only: these zero bytes are never accepted as W1 work.
    values = {"input": bytes(49506), "header": bytes(318), "expected_artifacts": bytes(64)}
    result = {"schema": WORKER.CONFIG_SCHEMA, "request_id": "data-contract-01", "repo_url": WORKER.REPO_URL,
              "source_commit": "1" * 40, "source_tree": "2" * 40, "template_sha256": "3" * 64,
              "guest_sha256": WORKER.GUEST_SHA, "image_id": list(WORKER.IMAGE_ID),
              "r0vm_bundle_url": WORKER.BUNDLE_URL, "r0vm_bundle_sha256": WORKER.BUNDLE_SHA,
              "r0vm_sha256": WORKER.R0VM_SHA, "segment_workers": 2, "compression_mode": "balanced",
              "compression_workers": 2, "rayon_threads": 2, "worker_wall_seconds": 60,
              "prover_profile": "cpu-fixed-v3.0.3", "cuda_required": False,
              "owner_deadline_provenance": {"original_deadline_monotonic_ns": 700,
                    "original_deadline_boot_id": "11111111-1111-1111-1111-111111111111",
                    "native_winner_monotonic_ns": 100, "winner_saved_monotonic_ns": 200}}
    for name, raw in values.items():
        result[name + "_b64"] = base64.b64encode(raw).decode()
        result[name + "_sha256"] = hashlib.sha256(raw).hexdigest()
    return result


class WorkerDataContracts(unittest.TestCase):
    def test_cpu_config_preserves_opaque_owner_clock_without_translation(self):
        config = data_config(); before = copy.deepcopy(config)
        decoded = WORKER.validate_config(config)
        self.assertEqual({name: len(raw) for name, raw in decoded.items()},
                         {"input": 49506, "header": 318, "expected_artifacts": 64})
        self.assertEqual(config, before)

    def test_expected64_length_and_hash_cannot_drift(self):
        for raw in (bytes(63), bytes(65)):
            config = data_config(); config["expected_artifacts_b64"] = base64.b64encode(raw).decode()
            config["expected_artifacts_sha256"] = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):
                WORKER.validate_config(config)
        config = data_config(); config["input_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            WORKER.validate_config(config)

    def test_input_header_binding_is_independent_of_their_own_hashes(self):
        config = data_config(); raw = b"x" + bytes(317)
        config["header_b64"] = base64.b64encode(raw).decode()
        config["header_sha256"] = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError, "header"):
            WORKER.validate_config(config)

    def test_cuda_unknown_profile_and_changed_old_pin_are_rejected(self):
        for key, value in (("cuda_required", True), ("prover_profile", "cuda-candidate"),
                           ("r0vm_sha256", "0" * 64), ("r0vm_bundle_url", "https://example.invalid/a")):
            config = data_config(); config[key] = value
            with self.assertRaises(ValueError):
                WORKER.validate_config(config)

    def test_worker_resource_and_integer_boundaries_are_exact(self):
        for key, value in (("rayon_threads", 3), ("segment_workers", True), ("worker_wall_seconds", 60.0),
                           ("worker_wall_seconds", 7201), ("compression_mode", "sequential")):
            config = data_config(); config[key] = value
            with self.assertRaises(ValueError):
                WORKER.validate_config(config)
        config = data_config(); config["owner_deadline_provenance"]["original_deadline_monotonic_ns"] = 700.0
        with self.assertRaises(ValueError):
            WORKER.validate_config(config)

    def test_unknown_config_fields_and_duplicate_nonfinite_json_are_rejected(self):
        config = data_config(); config["receipt_override"] = "old.bin"
        with self.assertRaises(ValueError):
            WORKER.validate_config(config)
        for value in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":1e999}'):
            with self.assertRaises(ValueError):
                WORKER.strict_json(value)

    def test_proof_fact_cannot_override_cancelled_operation(self):
        # Negative data only. No stage rows or successful proof are manufactured.
        row = {"schema": "TRNM-W1-COMPLETE-STAGED-RUN3", "complete_proof_claim": True,
               "end_to_end_observation_complete": True, "error": None, "controller_canceled_signal": 15,
               "controller_cancellation_event": {"signal": 15}, "deadline_exhausted_at_snapshot": False}
        before = copy.deepcopy(row)
        with self.assertRaisesRegex(ValueError, "veto"):
            WORKER.validate_controller(row)
        self.assertEqual(row, before)

    def test_incomplete_fresh_history_cannot_become_complete(self):
        row = {"schema": "TRNM-W1-COMPLETE-STAGED-RUN3", "complete_proof_claim": True,
               "end_to_end_observation_complete": True, "error": None, "controller_canceled_signal": None,
               "controller_cancellation_event": None, "deadline_exhausted_at_snapshot": False,
               "fresh_preparation_included": False, "prior_runs": [{"old": True}], "prior_bounded_wall_seconds": 5,
               "unretained_stage_labels": []}
        with self.assertRaisesRegex(ValueError, "fresh"):
            WORKER.validate_controller(row)

    def test_archive_is_deterministic_and_binds_exact_regular_members(self):
        with tempfile.TemporaryDirectory(prefix="w1-worker-data-") as temporary:
            root = Path(temporary); raw = root / "raw"; raw.mkdir()
            (raw / "result.json").write_bytes(b'{"raw":1.0000000000000002}\n')
            left, right = root / "a.tar.gz", root / "b.tar.gz"
            first = WORKER.archive_raw([("controller", raw)], left)
            second = WORKER.archive_raw([("controller", raw)], right)
            self.assertEqual(first, second); self.assertEqual(left.read_bytes(), right.read_bytes())
            with tarfile.open(left, "r:gz") as archive:
                self.assertEqual(archive.extractfile("controller/result.json").read(), (raw / "result.json").read_bytes())
                self.assertEqual(json.loads(archive.extractfile("member-index.json").read()), first)
                self.assertTrue(all(member.isfile() and member.uid == 0 and member.gid == 0 and member.mtime == 0
                                    for member in archive.getmembers()))

    def test_archive_rejects_links_output_inside_input_and_overwrite(self):
        with tempfile.TemporaryDirectory(prefix="w1-worker-data-") as temporary:
            root = Path(temporary); raw = root / "raw"; raw.mkdir()
            (raw / "ordinary").write_bytes(b"x"); (raw / "link").symlink_to(raw / "ordinary")
            with self.assertRaises(ValueError):
                WORKER.archive_raw([("data", raw)], root / "a.tar.gz")
            (raw / "link").unlink()
            with self.assertRaises(ValueError):
                WORKER.archive_raw([("data", raw)], raw / "inside.tar.gz")
            archive = root / "done.tar.gz"; WORKER.archive_raw([("data", raw)], archive); original = archive.read_bytes()
            with self.assertRaises(ValueError):
                WORKER.archive_raw([("data", raw)], archive)
            self.assertEqual(archive.read_bytes(), original)

    def test_file_read_and_new_write_refuse_links_and_existing_bytes(self):
        with tempfile.TemporaryDirectory(prefix="w1-worker-data-") as temporary:
            root = Path(temporary); path = root / "raw"; WORKER.write_new(path, b"original")
            with self.assertRaises(FileExistsError):
                WORKER.write_new(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"original")
            link = root / "link"; link.symlink_to(path)
            with self.assertRaises(ValueError):
                WORKER.file_info(link)

    def test_template_does_not_automatically_dispatch(self):
        self.assertNotIn('if __name__ == "__main__"', PATH.read_text())
        self.assertTrue(callable(WORKER.main))


if __name__ == "__main__":
    unittest.main()
