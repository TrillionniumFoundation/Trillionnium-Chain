"""Shared synthetic-key fixture for external evidence authentication tests."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import authenticate_external_evidence_v1 as auth
from test_external_evidence_intake_v1 import SCOPES, SOURCE_COMMIT, SOURCE_TREE, submission

NOW = "2026-09-05T00:00:00Z"
PKCS8 = bytes.fromhex("302e020100300506032b657004220420")

def encode(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()

def openssl(*args: str) -> bytes:
    result = subprocess.run(["openssl", *args], capture_output=True, timeout=5, check=True)
    return result.stdout

class AuthenticationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("openssl") is None:
            raise RuntimeError("OpenSSL is required: authentication tests cannot be skipped")
        cls.key_material = []
        with tempfile.TemporaryDirectory(prefix="trnm-test-key-material-") as directory:
            for index in range(2):
                seed = hashlib.sha256(f"SYNTHETIC-NOT-ENROLLED-evidence-key-{index}".encode()).digest()
                private = PKCS8 + seed
                path = pathlib.Path(directory) / "private.der"
                path.write_bytes(private)
                public = openssl("pkey", "-inform", "DER", "-in", str(path), "-pubout", "-outform", "DER")
                if public[:12] != auth.ED25519_SPKI or len(public) != 44:
                    raise RuntimeError("unexpected Ed25519 public encoding")
                cls.key_material.append((private, public[12:]))

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="trnm-authentication-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.raw_artifact = b"SYNTHETIC trace, not a physical experiment\x00\xff"
        self.digest = hashlib.sha256(self.raw_artifact).hexdigest()
        self.file = self.artifacts / self.digest
        self.file.write_bytes(self.raw_artifact)
        self.policy = {
            "schema": "trnm-external-evidence-trust-v1",
            "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-12-31T23:59:59Z",
            "keys": [
                {"signer": signer, "public_key_hex": self.key_material[index][1].hex(),
                 "role": role, "independence_domain": "fixture-domain-" + str(index),
                 "blocker_ids": sorted(SCOPES), "valid_from": "2026-01-01T00:00:00Z",
                 "valid_until": "2026-12-31T23:59:59Z", "revoked": False}
                for index, (signer, role) in enumerate(
                    [("fixture-producer", "producer"), ("fixture-reviewer", "reviewer")])
            ],
        }
        self.row = submission()
        self.row["artifacts"] = [{"name": "synthetic-trace", "sha256": self.digest,
                                   "immutable_uri": "urn:sha256:" + self.digest}]
        self.sign()

    def sign(self) -> None:
        self.policy_raw = encode(self.policy)
        self.pin = hashlib.sha256(self.policy_raw).hexdigest()
        digest = auth.body_digest(self.row)
        signatures = []
        for index, key in enumerate(self.policy["keys"][:2]):
            private = self.root / "fixture-private.der"
            message = self.root / "fixture-message"
            private.write_bytes(self.key_material[index][0])
            message.write_bytes(auth.signature_message(digest, self.pin, key["signer"], key["role"]))
            signature = openssl("pkeyutl", "-sign", "-keyform", "DER", "-inkey", str(private),
                                "-rawin", "-in", str(message))
            signatures.append({"signer": key["signer"], "algorithm": auth.PROFILE,
                               "signature": signature.hex(), "signed_digest": digest})
        self.row["signatures"] = signatures

    def verify(self, **changes: object) -> dict:
        args = dict(row=self.row, policy_raw=self.policy_raw, policy_sha256=self.pin,
                    artifact_directory=self.artifacts, source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE, as_of=NOW)
        args.update(changes)
        return auth.authenticate(**args)

    def reject(self, **changes: object) -> None:
        with self.assertRaises((auth.AuthenticationError, OSError)):
            self.verify(**changes)

    def cli(self, row_raw: bytes | None = None, policy_raw: bytes | None = None) -> subprocess.CompletedProcess[str]:
        row_path, policy_path = self.root / "submission.json", self.root / "policy.json"
        row_path.write_bytes(encode(self.row) if row_raw is None else row_raw)
        policy_path.write_bytes(self.policy_raw if policy_raw is None else policy_raw)
        return subprocess.run(
            [sys.executable, str(pathlib.Path(auth.__file__).resolve()), "--submission", str(row_path),
             "--trust-policy", str(policy_path), "--trust-policy-sha256", self.pin,
             "--artifact-directory", str(self.artifacts), "--source-commit", SOURCE_COMMIT,
             "--source-tree", SOURCE_TREE, "--as-of", NOW],
            capture_output=True, text=True, check=False, timeout=15,
        )
