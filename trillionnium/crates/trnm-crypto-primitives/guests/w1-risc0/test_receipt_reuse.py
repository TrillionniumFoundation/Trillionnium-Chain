#!/usr/bin/env python3
"""Metadata/binding negatives. Synthetic bytes here are never proof evidence."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import receipt_reuse as reuse


class ReuseBoundary(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.here = Path(self.temporary.name) / "source"
        self.out = Path(self.temporary.name) / "output"
        self.prior = self.out / "prior-proof"
        self.here.mkdir()
        self.prior.mkdir(parents=True)
        self.addCleanup(patch.stopall)
        patch.object(reuse, "HERE", self.here).start()
        self.commit = "a" * 40
        self.files = {name: b"metadata fixture\n" for name in reuse.REQUIRED_FILES}
        self.files["receipt.bin"] = b"deliberately NOT a RISC Zero proof"
        for name in ["source-before.json", "source-after.json"]:
            self.files[name] = json.dumps({"tested_commit": self.commit}).encode()
        for name in ["prove", "verify", "audit"]:
            self.files[f"{name}.process.json"] = json.dumps({"returncode": 0,
                "timed_out": False, "source_sha": self.commit}).encode()
        # An untrusted historical report can CLAIM success. prepare() must still
        # report that current cryptographic verification has NOT happened.
        self.files["checked-observation.json"] = b'{"real_proof_verified":true}'
        for name, raw in self.files.items():
            (self.prior / name).write_bytes(raw)
        for name in ["backend-manifest.json", "input.bin", "guest.raw.elf", "guest.bin"]:
            (self.out / name).write_bytes(self.files[name])
        (self.here / "backend-manifest.json").write_bytes(self.files["backend-manifest.json"])
        self.value = {"schema": "pon-w1-exact-image-receipt-reuse-v1",
            "repository": reuse.REPOSITORY, "source_commit": self.commit,
            "workflow_run_id": 1, "workflow_run_attempt": 1, "artifact_id": 2,
            "artifact_name": f"complete-w1-real-proof-{self.commit}-1",
            "github_artifact_digest": "sha256:" + "b" * 64,
            "files": {}, "new_proof_generated": False, "required_acceptance_waived": False}

    def write_policy(self):
        self.value["files"] = {name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                               for name, raw in self.files.items()}
        (self.here / "receipt-reuse.json").write_text(json.dumps(self.value))

    def test_absent_policy_only_selects_original_generation(self):
        self.assertIsNone(reuse.policy())

    def test_metadata_preparation_never_authenticates_synthetic_proof(self):
        self.write_policy()
        result = reuse.prepare(self.out)
        self.assertFalse(result["current_cryptographic_verification_completed"])
        self.assertFalse(result["proof_generated_in_current_run"])
        self.assertFalse(result["required_acceptance_waived"])
        self.assertFalse(result["consensus_authority"])
        self.assertEqual((self.out / "receipt.bin").read_bytes(), self.files["receipt.bin"])

    def test_changed_new_image_or_input_is_not_a_reuse(self):
        self.write_policy()
        for name in ["guest.raw.elf", "guest.bin", "input.bin"]:
            with self.subTest(name=name):
                (self.out / name).write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "newly rebuilt"):
                    reuse.prepare(self.out)
                (self.out / name).write_bytes(self.files[name])
                self.assertFalse((self.out / "receipt.bin").exists())

    def test_missing_or_changed_prior_receipt_fails_without_fallback(self):
        self.write_policy()
        (self.prior / "receipt.bin").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "prior artifact differs"):
            reuse.prepare(self.out)
        (self.prior / "receipt.bin").unlink()
        with self.assertRaises(FileNotFoundError):
            reuse.prepare(self.out)
        self.assertFalse((self.out / "receipt.bin").exists())

    def test_original_timeout_cannot_be_reclassified_as_success(self):
        self.files["prove.process.json"] = json.dumps({"returncode": 124,
            "timed_out": True, "source_sha": self.commit}).encode()
        (self.prior / "prove.process.json").write_bytes(self.files["prove.process.json"])
        self.write_policy()
        with self.assertRaisesRegex(ValueError, "original prove did not complete"):
            reuse.prepare(self.out)

    def test_source_change_refuses_and_declaration_never_waives_acceptance(self):
        self.write_policy()
        (self.here / "backend-manifest.json").write_bytes(b"another backend")
        with self.assertRaisesRegex(ValueError, "backend profile differs"):
            reuse.policy()
        (self.here / "backend-manifest.json").write_bytes(self.files["backend-manifest.json"])
        self.value["required_acceptance_waived"] = True
        self.write_policy()
        with self.assertRaisesRegex(ValueError, "neither proof generation nor acceptance waiver"):
            reuse.policy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
