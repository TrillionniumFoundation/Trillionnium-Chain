#!/usr/bin/env python3
"""Storage-identity reader controls only; no native or zkVM execution/verification.

The synthetic files exercise exact record binding. Their boolean fields are
reader fixtures, never proof of native execution, funding, or a verified receipt.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import run_w1_postwin_proof as postwin


class WinnerIdentityReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.boot = "synthetic-reader-boot"
        self.now = 3_000
        self.header = b"reader-only-header".ljust(318, b"\0")
        self.inputs = {"header.bin": self.header,
                       "input.bin": self.header + bytes(49506 - 318),
                       "expected-artifacts.bin": b"reader-only-external-commitment".ljust(64, b"\0")}
        for name, raw in self.inputs.items():
            (self.root / name).write_bytes(raw)
        self.winner = {
            "schema": "TRNM-W1-NATIVE-WINNER2",
            "fixture_scope": "synthetic storage reader only; no native execution or proof",
            "winner_observed": True, "native_replay_verified": True,
            "native_ticket_before_deadline": True, "winner_saved_before_deadline": True,
            "node_admission": False, "native_winner_monotonic_ns": 1_000,
            "winner_saved_monotonic_ns": 2_000, "original_deadline_monotonic_ns": 9_000,
            "original_deadline_boot_id": self.boot,
            **{name.removesuffix(".bin").replace("-", "_") + "_sha256":
               hashlib.sha256(raw).hexdigest() for name, raw in self.inputs.items()},
        }
        self.intent = {"schema": self.winner["schema"],
                       "fixture_scope": self.winner["fixture_scope"],
                       "original_deadline_monotonic_ns": self.winner["original_deadline_monotonic_ns"],
                       "original_deadline_boot_id": self.boot,
                       "expected_artifacts_sha256": self.winner["expected_artifacts_sha256"]}
        (self.root / "result.json").write_text(json.dumps(self.winner) + "\n")
        (self.root / "intent.json").write_text(json.dumps(self.intent) + "\n")
        self.initial, self.records = postwin.capture_winner_identity(self.root, self.now, self.boot)

    def test_unchanged_record_identity_reads_without_claiming_execution(self):
        self.assertEqual(postwin.require_unchanged_winner(
            self.root, self.initial, self.records, self.now, self.boot), self.winner)
        self.assertEqual(set(self.records), {"result.json", "intent.json"})
        for name, digest in self.records.items():
            self.assertEqual(digest, hashlib.sha256((self.root / name).read_bytes()).hexdigest())

    def test_another_self_consistent_winner_record_is_rejected(self):
        replacement = {**self.winner, "native_winner_monotonic_ns": 1_001}
        (self.root / "result.json").write_text(json.dumps(replacement) + "\n")
        self.assertEqual(postwin.winner_identity(self.root, self.now, self.boot), replacement)
        with self.assertRaisesRegex(ValueError, "original native winner"):
            postwin.require_unchanged_winner(
                self.root, self.initial, self.records, self.now, self.boot)

    def test_pre_search_intent_change_is_rejected_even_with_same_deadline(self):
        replacement = {**self.intent, "fixture_label": "changed pre-search selection record"}
        (self.root / "intent.json").write_text(json.dumps(replacement) + "\n")
        self.assertEqual(postwin.winner_identity(self.root, self.now, self.boot), self.winner)
        with self.assertRaisesRegex(ValueError, "pre-search intent"):
            postwin.require_unchanged_winner(
                self.root, self.initial, self.records, self.now, self.boot)

    def test_semantically_identical_json_rewrite_cannot_reuse_original_bytes(self):
        for name in ("result.json", "intent.json"):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b" \n")
                    self.assertEqual(postwin.winner_identity(self.root, self.now, self.boot), self.winner)
                    with self.assertRaisesRegex(ValueError, "original native winner"):
                        postwin.require_unchanged_winner(
                            self.root, self.initial, self.records, self.now, self.boot)
                finally:
                    path.write_bytes(original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
