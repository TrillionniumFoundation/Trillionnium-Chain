#!/usr/bin/env python3
"""Positive and negative controls for the external-evidence contract.

The positive envelope is synthetic and lives only in a temporary directory;
it exercises the cryptographic/source checks without creating a submission or
changing any release truth.  No fixture produced here is evidence of a real
external blocker.
"""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import check_external_evidence_v1 as checker


ROOT = checker.ROOT
ALLOWED = {
    "EXT-REVIEW-001",
    "EXT-G1-CAMPAIGN-001",
    "EXT-ANCHOR-HSM-001",
    "EXT-POWERLOSS-001",
    "EXT-AUDIT-001",
    "EXT-SOAK-ACTIVATION-001",
}


def openssl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["openssl", *arguments], check=check, capture_output=True)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for signature controls")
class ExternalEvidenceContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="trnm-external-evidence-test-")
        self.root = pathlib.Path(self.temp.name)
        self.secrets: list[pathlib.Path] = []
        self.registry: dict[str, dict[str, object]] = {}
        for index, (signer, key_id, role) in enumerate(
            (("operator-a", "test-producer", "producer"),
             ("reviewer-b", "test-reviewer", "independent_reviewer"))
        ):
            secret = self.root / f"key-{index}.der"
            public = self.root / f"public-{index}.der"
            openssl("genpkey", "-algorithm", "ED25519", "-outform", "DER", "-out", str(secret))
            openssl(
                "pkey", "-inform", "DER", "-in", str(secret), "-pubout",
                "-outform", "DER", "-out", str(public),
            )
            public_bytes = public.read_bytes()
            self.assertEqual(public_bytes[: len(checker.ED25519_SPKI_PREFIX)], checker.ED25519_SPKI_PREFIX)
            self.secrets.append(secret)
            self.registry[key_id] = {
                "signer": signer,
                "key_id": key_id,
                "algorithm": "ed25519-sha256-v1",
                "public_key": public_bytes[len(checker.ED25519_SPKI_PREFIX):].hex(),
                "roles": [role],
                "active": True,
            }
        registry_document = {
            "schema": checker.REGISTRY_SCHEMA,
            "version": 1,
            "signers": list(self.registry.values()),
        }
        self.registry_digest = hashlib.sha256(
            b"trnm.external-evidence.signer-registry.v1\0"
            + checker.canonical_json(registry_document, "test signer registry")
        ).hexdigest()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def sign(self, secret: pathlib.Path, message: bytes) -> str:
        source = self.root / f"message-{len(message)}.bin"
        output = self.root / f"signature-{len(message)}.bin"
        source.write_bytes(message)
        openssl(
            "pkeyutl", "-sign", "-rawin", "-keyform", "DER",
            "-inkey", str(secret), "-in", str(source), "-out", str(output),
        )
        return output.read_bytes().hex()

    def base_row(self) -> dict[str, object]:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
        ).stdout.strip()
        tree = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, check=True, capture_output=True, text=True
        ).stdout.strip()
        artifact_bytes = (ROOT / "PROJECT_ID").read_bytes()
        row: dict[str, object] = {
            "schema": "trnm-external-evidence-v1",
            "evidence_id": "synthetic-review-001",
            "blocker_id": "EXT-REVIEW-001",
            "source_commit": commit,
            "source_tree": tree,
            "producer": "operator-a",
            "independent_reviewer": "reviewer-b",
            "independence_declaration": True,
            "scope": "review",
            "result": "rejected",
            "started_at": "2026-08-30T00:00:00Z",
            "ended_at": "2026-08-30T00:00:00Z",
            "wall_clock_seconds": 0,
            "artifacts": [{
                "name": "project-id",
                "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                "immutable_uri": (
                    "urn:trnm:artifact:sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
                ),
                "local_path": "PROJECT_ID",
                "bytes": len(artifact_bytes),
            }],
            "signatures": [],
            "claims": {
                "package_digest": "11" * 32,
                "interface_digest": "22" * 32,
                "replayed_p0_mutants": 1,
                "downstream_invalidation": [],
            },
            "evidence_digest": "",
            "signer_registry_sha256": self.registry_digest,
        }
        row["evidence_digest"] = checker.envelope_digest(row)
        message = checker.SIGNATURE_DOMAIN + bytes.fromhex(str(row["evidence_digest"]))
        row["signatures"] = [
            {
                "signer": "operator-a",
                "key_id": "test-producer",
                "algorithm": "ed25519-sha256-v1",
                "signature": self.sign(self.secrets[0], message),
                "signed_digest": row["evidence_digest"],
            },
            {
                "signer": "reviewer-b",
                "key_id": "test-reviewer",
                "algorithm": "ed25519-sha256-v1",
                "signature": self.sign(self.secrets[1], message),
                "signed_digest": row["evidence_digest"],
            },
        ]
        return row

    def test_valid_synthetic_envelope_is_cryptographically_checked(self) -> None:
        row = self.base_row()
        checker.validate_common(
            ROOT / "synthetic-external.json",
            row,
            ALLOWED,
            signer_registry=self.registry,
            signer_registry_digest=self.registry_digest,
        )
        checker.validate_specific(ROOT / "synthetic-external.json", row)

    def test_source_tree_substitution_is_rejected(self) -> None:
        row = self.base_row()
        row["source_tree"] = "0" * 40
        with self.assertRaises(checker.EvidenceError):
            checker.validate_source_binding(ROOT / "synthetic-external.json", row)

    def test_uri_digest_substitution_is_rejected(self) -> None:
        with self.assertRaises(checker.EvidenceError):
            checker.parse_uri_digest("https://example.invalid/report", "synthetic artifact")
        row = self.base_row()
        row["artifacts"][0]["immutable_uri"] = "urn:trnm:artifact:sha256:" + "0" * 64
        with self.assertRaises(checker.EvidenceError):
            checker.validate_common(
                ROOT / "synthetic-external.json",
                row,
                ALLOWED,
                signer_registry=self.registry,
                signer_registry_digest=self.registry_digest,
            )

    def test_signature_mutation_is_rejected(self) -> None:
        row = self.base_row()
        mutated = copy.deepcopy(row)
        signature = str(mutated["signatures"][0]["signature"])
        mutated["signatures"][0]["signature"] = ("0" if signature[0] != "0" else "1") + signature[1:]
        with self.assertRaises(checker.EvidenceError):
            checker.validate_common(
                ROOT / "synthetic-external.json",
                mutated,
                ALLOWED,
                signer_registry=self.registry,
                signer_registry_digest=self.registry_digest,
            )

    def test_duplicate_json_names_are_rejected(self) -> None:
        path = self.root / "duplicate.json"
        path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
        with self.assertRaises(checker.EvidenceError):
            checker.read_json(path)

    def test_empty_repository_submission_set_stays_open(self) -> None:
        result = subprocess.run(
            ["python3", str(ROOT / "scripts/ci/check_external_evidence_v1.py")],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(result.stdout)
        self.assertEqual(report["submission_count"], 0)
        self.assertEqual(set(report["open_blockers"]), ALLOWED)
        self.assertFalse(report["all_external_blockers_closed"])
        self.assertFalse(report["production_candidate"])
        self.assertFalse(report["production_consensus_activation"])


if __name__ == "__main__":
    unittest.main()
