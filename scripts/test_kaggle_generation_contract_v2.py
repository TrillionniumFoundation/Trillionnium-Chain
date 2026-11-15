"""Unexecuted contract tests. All provider receipts are explicitly SYNTHETIC.
No fixture below is signed by Kaggle or evidence of a live GPU/proof/payment.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from kaggle_generation_contract_v2 import (
    NAMESPACE, KaggleGenerationTargetV2, AccountGuardedCliAdapter, canonical, digest, receipt_identity, check_download,
)


def binding():
    intent = {"source_sha256": hashlib.sha256(b"print('synthetic fixture')\n").hexdigest(),
              "timeout_seconds": 300, "accelerator": "cpu", "internet": False,
              "kernel_type": "script", "language": "python", "is_private": True,
              "dataset_sources": [], "kernel_sources": [], "model_sources": [], "competition_sources": []}
    return {"schema": NAMESPACE, "request_id": "SYNTHETIC-W1-TEST-01", "task_scope": "01" * 32,
            "statement": "02" * 32, "journal_identity": "03" * 32, "operation": "04" * 32,
            "provider_namespace": "05" * 32, "account_username": "synthetic_owner",
            "intent": intent, "input_digest": digest(intent),
            "original_controller_deadline": {"clock_domain": "06" * 32, "winner_ns": 100, "deadline_ns": 1000}}


def receipt(b, state="QUEUED"):
    return {"schema": "hepta-kaggle-job-v1", "request_id": b["request_id"],
            "input_digest": b["input_digest"], "intent": copy.deepcopy(b["intent"]),
            "account": {"username": "synthetic_owner"}, "submission_state": "ACCEPTED",
            "remote_submission_state": "ACKNOWLEDGED", "remote_effect_unknown": False,
            "remote_state": state, "notebook_ref": "synthetic_owner/hepta-synthetic-test",
            "notebook_version": 1, "kernel_id": 200, "kernel_session_id": None,
            "identity_verified": False}


class SyntheticTransport:
    def account(self):
        return {"username": "synthetic_owner"}


class SyntheticAdapter:
    def __init__(self, b, unknown=False):
        self.transport = SyntheticTransport()
        self.b = b
        self.calls = {"submit": 0, "resume": 0, "cancel": 0}
        self.result = receipt(b)
        self.unknown = unknown

    def submit(self, **kw):
        self.calls["submit"] += 1
        assert kw["request_id"] == self.b["request_id"]
        assert hashlib.sha256(Path(kw["source"]).read_bytes()).hexdigest() == self.b["intent"]["source_sha256"]
        if self.unknown:
            self.result.update(submission_state="UNKNOWN", remote_submission_state="MAY_HAVE_BEEN_SENT",
                               remote_effect_unknown=True, notebook_version=None, kernel_id=None)
            raise RuntimeError("SYNTHETIC post-dispatch transport loss")
        return copy.deepcopy(self.result)

    def resume(self, request_id):
        self.calls["resume"] += 1
        assert request_id == self.b["request_id"]
        return copy.deepcopy(self.result)

    def cancel(self, request_id, wait_seconds):
        self.calls["cancel"] += 1
        assert request_id == self.b["request_id"]
        raise RuntimeError("SESSION_IDENTITY_UNPROVEN")


class ContractTests(unittest.TestCase):
    def test_provider_replayed_submission_flag_is_never_erased(self):
        b = binding()
        for flag in (True, None, 1, "false"):
            r = receipt(b)
            r["remote_submission_replayed"] = flag
            with self.assertRaisesRegex(ValueError, "replayed or unproven"):
                receipt_identity(b, r)

    def test_live_schema_change_refuses_reconcile_without_provider_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.py"
            source.write_bytes(b"print('synthetic fixture')\n")
            b = binding()
            adapter = SyntheticAdapter(b)
            target = KaggleGenerationTargetV2(adapter, root / "target.sqlite",
                lambda: {"clock_domain": "06" * 32, "now_ns": 200})
            target.dispatch(b, source, m12_new_intent=True)
            target.db.execute("PRAGMA user_version=3")
            with self.assertRaisesRegex(ValueError, "live namespace"):
                target.reconcile(b["operation"])
            self.assertEqual(adapter.calls, {"submit": 1, "resume": 0, "cancel": 0})

    def test_real_subprocess_cli_contract_retains_failed_transport_and_normal_prefix(self):
        # This executes a real LOCAL fixture process, not Kaggle or a GPU job.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            b = binding()
            r = receipt(b)
            r.update(remote_state="UNKNOWN", remote_effect_unknown=True,
                     submission_state="UNKNOWN", remote_submission_state="MAY_HAVE_BEEN_SENT",
                     notebook_version=None, kernel_id=None)
            wrapper = root / "synthetic-account-wrapper"
            wrapper.write_text("#!/usr/bin/env python3\nimport json,sys\n"
                               "assert sys.argv[1:3] == ['qiqian','batch']\n"
                               "assert sys.argv[3:] == ['resume','--request-id','SYNTHETIC-W1-TEST-01']\n"
                               f"print({json.dumps(json.dumps(r))})\nraise SystemExit(7)\n")
            wrapper.chmod(0o700)
            adapter = AccountGuardedCliAdapter([str(wrapper), "qiqian", "batch"],
                hashlib.sha256(wrapper.read_bytes()).hexdigest(), "qiqian", "synthetic_owner",
                root / "evidence", time.monotonic_ns() + 5_000_000_000,
                Path("/proc/sys/kernel/random/boot_id").read_text().strip())
            observed = adapter.resume(b["request_id"])
            self.assertTrue(receipt_identity(b, observed)["remote_effect_unknown"])
            retained = list((root / "evidence").glob("*.result.json"))
            self.assertEqual(len(retained), 1)
            self.assertEqual(json.loads(retained[0].read_bytes())["returncode"], 7)
            wrapper.write_text("#!/bin/false\n")
            with self.assertRaisesRegex(ValueError, "wrapper changed"):
                adapter.resume(b["request_id"])

    def test_ack_queued_has_no_gpu_proof_payment_or_release_authority(self):
        b = binding()
        observed = receipt_identity(b, receipt(b))
        self.assertTrue(observed["acknowledged"])
        self.assertFalse(observed["artifact_candidate"])
        self.assertFalse(observed["remote_terminal_observed"])
        self.assertFalse(observed["may_release_resources"])
        self.assertFalse(observed["can_authorize_payment"])
        self.assertEqual(observed["cancel_blocker"], "SESSION_IDENTITY_UNPROVEN")

    def test_exact_terminal_set_and_identity_required(self):
        b = binding()
        for state in ["QUEUED", "RUNNING", "CANCEL_REQUESTED", "NEW_SCRIPT", "UNKNOWN", "COMPLETE", "ERROR", "CANCEL_ACKNOWLEDGED"]:
            r = receipt(b, state)
            r["identity_verified"] = True
            o = receipt_identity(b, r)
            self.assertEqual(o["remote_terminal_observed"], state in {"COMPLETE", "ERROR", "CANCEL_ACKNOWLEDGED"})
            self.assertEqual(o["artifact_candidate"], state == "COMPLETE")
            self.assertFalse(o["may_release_resources"])
        r["remote_effect_unknown"] = True
        self.assertFalse(receipt_identity(b, r)["remote_terminal_observed"])

    def test_version_kernel_ref_and_intent_are_not_rebound(self):
        b = binding()
        first = receipt(b)
        pinned = receipt_identity(b, first)["identity"]
        for name, value in [("notebook_version", 2), ("kernel_id", 201), ("notebook_ref", "synthetic_owner/other")]:
            changed = copy.deepcopy(first)
            changed[name] = value
            with self.assertRaises(ValueError):
                receipt_identity(b, changed, pinned)
        changed = copy.deepcopy(first)
        changed["intent"]["timeout_seconds"] += 1
        with self.assertRaises(ValueError):
            receipt_identity(b, changed, pinned)
        changed = copy.deepcopy(first)
        changed["notebook_version"] = True
        with self.assertRaises(ValueError):
            receipt_identity(b, changed)

    def test_session_never_falls_back_to_version_or_notebook_id(self):
        b = binding()
        r = receipt(b)
        r["kernel_session_id"] = r["notebook_version"]
        self.assertFalse(receipt_identity(b, r)["cancel_session_proven"])
        r["session_binding"] = {"notebook_ref": r["notebook_ref"], "notebook_version": 2,
                                "response_sha256": "07" * 32}
        self.assertFalse(receipt_identity(b, r)["cancel_session_proven"])
        r["session_binding"]["notebook_version"] = 1
        self.assertTrue(receipt_identity(b, r)["cancel_session_proven"])
        # The value is accepted only as an explicitly bound session assertion;
        # this fixture does not establish that Kaggle issued session 1.

    def test_cold_replay_and_different_journal_never_dispatch_twice(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.py"
            source.write_bytes(b"print('synthetic fixture')\n")
            b = binding()
            adapter = SyntheticAdapter(b)
            clock = lambda: {"clock_domain": "06" * 32, "now_ns": 200}
            target = KaggleGenerationTargetV2(adapter, root / "target.sqlite", clock)
            target.dispatch(b, source, m12_new_intent=True)
            target.db.close()
            target = KaggleGenerationTargetV2(adapter, root / "target.sqlite", clock)
            replay = target.dispatch(b, source, m12_new_intent=True)
            self.assertEqual(adapter.calls, {"submit": 1, "resume": 1, "cancel": 0})
            self.assertFalse(replay["may_dispatch_again"])
            changed = copy.deepcopy(b)
            changed["journal_identity"] = "08" * 32
            with self.assertRaises(ValueError):
                target.dispatch(changed, source, m12_new_intent=True)
            changed["operation"] = "09" * 32
            changed["request_id"] = "SYNTHETIC-DIFFERENT-REQUEST"
            with self.assertRaises(Exception):
                target.dispatch(changed, source, m12_new_intent=True)
            self.assertEqual(adapter.calls["submit"], 1)
            target.reconcile(b["operation"])

    def test_unknown_submission_and_cancel_refusal_keep_original_identity_and_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.py"
            source.write_bytes(b"print('synthetic fixture')\n")
            b = binding()
            adapter = SyntheticAdapter(b, unknown=True)
            now = {"clock_domain": "06" * 32, "now_ns": 200}
            target = KaggleGenerationTargetV2(adapter, root / "target.sqlite", lambda: now)
            with self.assertRaises(RuntimeError):
                target.dispatch(b, source, m12_new_intent=True)
            now["now_ns"] = 2000
            replay = target.dispatch(b, source, m12_new_intent=True)
            self.assertTrue(replay["remote_effect_unknown"])
            self.assertFalse(replay["may_release_resources"])
            self.assertEqual(adapter.calls["submit"], 1)
            with self.assertRaisesRegex(RuntimeError, "SESSION_IDENTITY_UNPROVEN"):
                target.cancel(b["operation"])
            self.assertTrue(target._row(b["operation"])["cancel"])
            self.assertTrue(target.reconcile(b["operation"])["sticky_cancel"])
            self.assertEqual(target._row(b["operation"])["binding"], b)

    def test_clock_change_prevents_initial_submission_and_does_not_renew_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.py"
            source.write_bytes(b"print('synthetic fixture')\n")
            b = binding()
            adapter = SyntheticAdapter(b)
            target = KaggleGenerationTargetV2(adapter, root / "target.sqlite",
                lambda: {"clock_domain": "ff" * 32, "now_ns": 200})
            with self.assertRaisesRegex(ValueError, "continuity UNKNOWN"):
                target.dispatch(b, source, m12_new_intent=True)
            self.assertEqual(adapter.calls["submit"], 0)

    def test_complete_download_is_only_input_to_full_verifier(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            b = binding()
            r = receipt(b, "COMPLETE")
            r["identity_verified"] = True
            proof = b"SYNTHETIC-NOT-A-CRYPTOGRAPHIC-RECEIPT"
            (root / "receipt.bin").write_bytes(proof)
            entry = {"path": "receipt.bin", "bytes": len(proof), "sha256": hashlib.sha256(proof).hexdigest()}
            manifest = {"schema": "hepta-artifact-manifest-v1", "request_id": b["request_id"], "files": [entry]}
            raw_manifest = canonical(manifest)
            (root / "manifest.json").write_bytes(raw_manifest)
            items = [entry, {"path": "manifest.json", "bytes": len(raw_manifest), "sha256": hashlib.sha256(raw_manifest).hexdigest()}]
            items = [{**x, "http_content_length": x["bytes"], "http_content_length_verified": True} for x in items]
            download = {"schema": "hepta-kaggle-download-v1", "request_id": b["request_id"],
                "input_digest": b["input_digest"], "notebook_ref": r["notebook_ref"], "notebook_version": 1,
                "directory": str(root), "files": items, "files_manifest_sha256": digest(items),
                "total_bytes": sum(x["bytes"] for x in items), "remote_manifest_verified": True,
                "remote_manifest_name": "manifest.json", "verification_policy": "manifest-and-http-v1"}
            observed = check_download(b, r, download, root, "manifest.json")
            self.assertEqual(observed["next_gate"], "INDEPENDENT_FULL_W1_V2_VERIFIER")
            self.assertFalse(observed["can_authorize_payment"])
            self.assertFalse(observed["may_release_resources"])
            changed = copy.deepcopy(download)
            changed["files"][0]["http_content_length"] += 1
            changed["files_manifest_sha256"] = digest(changed["files"])
            with self.assertRaises(ValueError):
                check_download(b, r, changed, root, "manifest.json")
            (root / "receipt.bin").write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                check_download(b, r, download, root, "manifest.json")


if __name__ == "__main__":
    unittest.main()
