#!/usr/bin/env python3
"""Real filesystem negatives for byte materialization, never deployment evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import pon_decentralization_audit as D
import pon_decentralization_evidence as E

# Exact historical source-only input, retained as a fixture rather than a current observation.
CURRENT = ROOT / "scripts/ci/fixtures/pon_decentralization_source_only_20261106.json"
HISTORICAL_SOURCE_ONLY_SHA256 = "dfa8436a646626def5468f391d2fcfabe79b167fb5b150f61d8992fb3190f473"
SCRIPT = ROOT / "scripts/pon_decentralization_evidence.py"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Materialization(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.cas = self.root / "cas"
        self.cas.mkdir()
        self.input = self.root / "input.json"
        self.value = json.loads(CURRENT.read_bytes())
        # Synthetic declarations are explicitly separated from the retained
        # source-only input. No tests appoint controllers or install credentials.
        for part in (self.value["audit"], self.value["registry"]):
            part["context"] = {"chain_source_sha256": "1" * 64, "profile_sha256": "2" * 64}
        self.value["audit"]["window"] = {"start_unix_ms": 10, "end_unix_ms": 20}
        self.value["registry"].update(valid_from_unix_ms=10, valid_until_unix_ms=20)

    def add(self, raw=b"synthetic material", *, status="current", start=10, end=20, present=True):
        digest = sha(raw)
        self.value["registry"]["evidence"].append({"sha256": digest, "status": status,
            "valid_from_unix_ms": start, "valid_until_unix_ms": end})
        if present:
            (self.cas / digest).write_bytes(raw)
        return digest

    def seal(self):
        registry = self.value["registry"]
        registry["subjects_sha256"] = D.canonical_sha256(registry["subjects"])
        self.value["audit"]["control_registry_sha256"] = D.canonical_sha256(registry)
        raw = json.dumps(self.value, indent=2, sort_keys=True).encode() + b"\n"
        self.input.write_bytes(raw)
        return sha(raw)

    def run_reader(self):
        return E.materialize(self.input, self.seal(), self.cas)

    def cli(self, digest, *args, script=SCRIPT):
        return subprocess.run([sys.executable, str(script), "--input", str(self.input),
            "--expected-input-sha256", digest, "--artifact-dir", str(self.cas), *map(str, args)],
            capture_output=True, timeout=10)

    def assert_unaccepted(self, report):
        self.assertEqual(report["status"], "HOLD")
        for key in ("evidence_references_authenticated", "signatures_verified", "claim_contents_verified",
                    "context_contents_verified", "deployment_evidence_verified", "independent_administration_verified",
                    "permissionless_utility_accepted", "public_network_ready", "production_activation"):
            self.assertIs(report[key], False, key)

    def test_actual_source_only_input_is_empty_with_all_findings_retained(self):
        raw = CURRENT.read_bytes()
        self.assertEqual(sha(raw), HISTORICAL_SOURCE_ONLY_SHA256)
        # Repository checkout material may be hardlinked by workspace isolation.
        # Use a distinct regular file with identical externally pinned bytes;
        # do not relax the reader's hardlink refusal for the retained original.
        self.input.write_bytes(raw)
        report = E.materialize(self.input, sha(raw), self.cas)
        self.assertEqual(report["schema"], "trnm-decentralization-evidence-materialization-v1")
        self.assertEqual(report["materialization_status"], "empty")
        self.assertFalse(report["all_declared_material_bytes_matched"])
        self.assertIn("DEPLOYMENT_EVIDENCE_MISSING", report["materialization_findings"])
        original = json.loads(raw)
        self.assertEqual(report["accounting_findings"], D.evaluate(original["audit"], original["registry"])["findings"])
        self.assertEqual(report["total_artifact_bytes_read"], 0)
        self.assert_unaccepted(report)

    def test_matched_bytes_and_repeated_uses_are_deterministic_without_mutation(self):
        digest = self.add()
        registry, audit = self.value["registry"], self.value["audit"]
        registry["controllers"] = [{"id": "fixture-owner", "parents": [], "evidence_sha256": digest}]
        registry["subjects"] = [{"id": "fixture-subject", "controller": "fixture-owner",
                                  "key_sha256": None, "evidence_sha256": digest}]
        audit["work_production"]["inventory_evidence_sha256"] = digest
        audit["resources"]["funding"]["unit_definition_sha256"] = digest
        expected = self.seal()
        before = self.input.read_bytes(), (self.cas / digest).read_bytes()
        report = E.materialize(self.input, expected, self.cas)
        self.assertEqual(report, E.materialize(self.input, expected, self.cas))
        self.assertEqual(before, (self.input.read_bytes(), (self.cas / digest).read_bytes()))
        self.assertEqual(report["materialization_status"], "bytes_complete")
        self.assertEqual(report["matched_artifact_count"], 1)
        self.assertEqual(report["total_artifact_bytes_read"], len(before[1]))
        self.assertEqual(report["materials"][0]["uses"], [
            "/audit/resources/funding/unit_definition_sha256", "/audit/work_production/inventory_evidence_sha256",
            "/registry/controllers/0/evidence_sha256", "/registry/subjects/0/evidence_sha256"])
        self.assert_unaccepted(report)

    def test_missing_and_mismatched_files_keep_original_references(self):
        missing = self.add(b"missing", present=False)
        corrupt = self.add(b"expected")
        (self.cas / corrupt).write_bytes(b"corrupt")
        report = self.run_reader()
        self.assertEqual(report["materialization_status"], "incomplete")
        self.assertEqual(report["material_gaps"]["missing"], [missing])
        self.assertEqual(report["material_gaps"]["hash_mismatch"], [corrupt])
        row = next(row for row in report["materials"] if row["sha256"] == corrupt)
        self.assertEqual(row["observed_sha256"], sha(b"corrupt"))
        self.assertEqual(report["total_artifact_bytes_read"], 7)
        self.assert_unaccepted(report)

    def test_matching_bytes_do_not_clear_revoked_unknown_or_declared_time_gaps(self):
        revoked = self.add(b"revoked", status="revoked")
        unknown = self.add(b"unknown", status="unknown")
        expired = self.add(b"expired", end=19)
        future = self.add(b"future", start=11)
        current = self.add(b"current")
        report = self.run_reader()
        self.assertTrue(report["all_declared_material_bytes_matched"])
        for field, value in (("revoked", revoked), ("unknown", unknown),
                             ("expired_for_audit_window", expired), ("not_yet_valid_for_audit_window", future)):
            self.assertEqual(report["material_gaps"][field], [value])
        self.assertEqual([row["sha256"] for row in report["materials"] if row["declared_reference_current"]], [current])
        self.value["registry"]["valid_until_unix_ms"] = 19
        self.assertFalse(any(row["declared_reference_current"] for row in self.run_reader()["materials"]))
        self.assert_unaccepted(report)

    def test_unused_material_is_not_a_deployment_inventory(self):
        self.add()
        report = self.run_reader()
        self.assertEqual(report["materials"][0]["uses"], [])
        self.assertTrue(report["absent_reference_uses"])
        self.assert_unaccepted(report)

    def test_expected_digest_binds_raw_input_bytes_before_artifact_access(self):
        expected = self.seal()
        self.input.write_bytes(self.input.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "INPUT_SHA256_MISMATCH"):
            E.materialize(self.input, expected, self.root / "absent-directory")

    def test_duplicate_json_and_duplicate_evidence_are_rejected(self):
        raw = b'{"audit":{},"audit":{},"registry":{}}'
        self.input.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
            E.materialize(self.input, sha(raw), self.cas)
        self.add()
        self.value["registry"]["evidence"].append(copy.deepcopy(self.value["registry"]["evidence"][0]))
        with self.assertRaisesRegex(ValueError, "DUPLICATE_EVIDENCE"):
            self.run_reader()

    def test_invalid_digest_paths_unknown_references_and_extra_fields_reject(self):
        for change, code in ((lambda: self.value.update(extra=True), "INPUT_FIELDS"),
                (lambda: self.value["audit"]["work_production"].update(inventory_evidence_sha256="f" * 64), "UNKNOWN_EVIDENCE_REFERENCE"),
                (lambda: self.value["registry"]["evidence"].append(dict(sha256="../outside", status="current",
                    valid_from_unix_ms=10, valid_until_unix_ms=20)), "EVIDENCE")):
            with self.subTest(code=code):
                saved = copy.deepcopy(self.value)
                change()
                with self.assertRaisesRegex(ValueError, code):
                    self.run_reader()
                self.value = saved

    def test_file_symlinks_hardlinks_directories_and_fifos_never_read(self):
        digest = self.add(present=False)
        outside = self.root / "outside"
        outside.write_bytes(b"synthetic material")
        for kind in ("symlink", "hardlink", "directory", "fifo"):
            with self.subTest(kind=kind):
                path = self.cas / digest
                if kind == "symlink":
                    path.symlink_to(outside)
                elif kind == "hardlink":
                    os.link(outside, path)
                elif kind == "directory":
                    path.mkdir()
                else:
                    os.mkfifo(path)
                with self.assertRaisesRegex(ValueError, "NONREGULAR_OR_SYMLINK_FILE|HARDLINK_FILE"):
                    self.run_reader()
                path.rmdir() if kind == "directory" else path.unlink()
        self.assertEqual(outside.read_bytes(), b"synthetic material")

    def test_root_and_ancestor_symlinks_and_traversal_are_refused(self):
        expected = self.seal()
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for input_path, cas_path in ((self.input, alias / "cas"), (alias / "input.json", self.cas),
                                      (self.input, str(self.cas) + "/../cas")):
            with self.subTest(input=input_path, cas=cas_path), self.assertRaises((ValueError, OSError)):
                E.materialize(input_path, expected, cas_path)

    def test_input_symlink_hardlink_or_nonregular_is_refused(self):
        expected = self.seal()
        alias = self.root / "input-alias"
        for kind in ("symlink", "hardlink", "directory", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    alias.symlink_to(self.input)
                elif kind == "hardlink":
                    os.link(self.input, alias)
                elif kind == "directory":
                    alias.mkdir()
                else:
                    os.mkfifo(alias)
                with self.assertRaisesRegex(ValueError, "NONREGULAR_OR_SYMLINK_FILE|HARDLINK_FILE"):
                    E.materialize(alias, expected, self.cas)
                alias.rmdir() if kind == "directory" else alias.unlink()

    def test_per_file_input_and_total_caps_are_enforced_before_large_reads(self):
        digest = self.add()
        with (self.cas / digest).open("wb") as handle:
            handle.truncate(E.MAX_ARTIFACT_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "FILE_BYTE_BOUND"):
            self.run_reader()
        (self.cas / digest).unlink()
        self.value["registry"]["evidence"] = []
        self.add(b"aaaaaa")
        self.add(b"bbbbbb")
        with mock.patch.object(E, "MAX_TOTAL_BYTES", 10), self.assertRaisesRegex(ValueError, "FILE_BYTE_BOUND"):
            self.run_reader()
        with self.input.open("wb") as handle:
            handle.truncate(D.MAX_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "FILE_BYTE_BOUND"):
            E.materialize(self.input, "1" * 64, self.cas)

    def read_with_mutation(self, watched_path, action, expected):
        watched_inode = watched_path.stat().st_ino
        original_read, changed = os.read, False
        def mutate(fd, length):
            nonlocal changed
            block = original_read(fd, length)
            if block and not changed and os.fstat(fd).st_ino == watched_inode:
                changed = True
                action()
            return block
        with mock.patch.object(E.os, "read", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, expected):
                self.run_reader()
        self.assertTrue(changed)

    def test_same_size_mutation_and_replacement_during_read_reject(self):
        digest = self.add(b"initial")
        path = self.cas / digest
        self.read_with_mutation(path, lambda: path.write_bytes(b"changed"), "FILE_CHANGED_DURING_READ")
        path.write_bytes(b"initial")
        replacement = self.root / "replacement"
        replacement.write_bytes(b"initial")
        self.read_with_mutation(path, lambda: os.replace(replacement, path), "FILE_CHANGED_DURING_READ")

    def test_growth_during_read_is_bounded(self):
        digest = self.add(b"tiny")
        path = self.cas / digest
        with mock.patch.object(E, "MAX_ARTIFACT_BYTES", 4):
            self.read_with_mutation(path, lambda: path.write_bytes(b"larger"), "FILE_BYTE_BOUND")

    def test_changes_to_previously_read_material_or_input_are_rejected(self):
        first, second = sorted([self.add(b"first"), self.add(b"second")])
        self.read_with_mutation(self.cas / second, lambda: (self.cas / first).write_bytes(b"mutated"),
                                "ARTIFACT_CHANGED_DURING_SCAN")
        self.read_with_mutation(self.cas / second, lambda: self.input.write_bytes(b"changed input"),
                                "INPUT_CHANGED_DURING_SCAN")

    def test_initially_missing_material_cannot_appear_after_its_check(self):
        first, second = sorted([self.add(b"first"), self.add(b"second")])
        raw = (self.cas / first).read_bytes()
        (self.cas / first).unlink()
        self.read_with_mutation(self.cas / second, lambda: (self.cas / first).write_bytes(raw),
                                "ARTIFACT_CHANGED_DURING_SCAN")

    def test_artifact_directory_replacement_is_detected(self):
        digest = self.add()
        def replace():
            self.cas.rename(self.root / "old-cas")
            self.cas.mkdir()
        self.read_with_mutation(self.cas / digest, replace, "ARTIFACT_DIRECTORY_CHANGED|DIRECTORY_LINEAGE_CHANGED")

    def test_cli_is_create_only_and_does_not_write_input_or_artifact_directory(self):
        self.add()
        expected = self.seal()
        output = self.root / "report.json"
        result = self.cli(expected, "--output", output)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assert_unaccepted(json.loads(output.read_bytes()))
        original = output.read_bytes()
        self.assertEqual(self.cli(expected, "--output", output).returncode, 2)
        self.assertEqual(output.read_bytes(), original)
        self.assertEqual(self.cli(expected, "--output", self.input).returncode, 2)
        self.assertEqual(self.cli(expected, "--output", self.cas / "report.json").returncode, 2)
        self.assertEqual(sha(self.input.read_bytes()), expected)
        self.assertFalse((self.cas / "report.json").exists())

    def test_cli_fatal_input_error_leaves_no_report(self):
        self.seal()
        output = self.root / "report.json"
        result = self.cli("f" * 64, "--output", output)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"INPUT_SHA256_MISMATCH", result.stderr)
        self.assertFalse(output.exists())

    def test_cli_rejects_drifted_installed_policy_without_report(self):
        # Run the real entry point in an isolated minimal installation. Never
        # mutate the shared checkout's policy to exercise refusal behavior.
        isolated = self.root / "isolated"
        scripts, config = isolated / "scripts", isolated / "config/pon"
        scripts.mkdir(parents=True)
        config.mkdir(parents=True)
        script = scripts / SCRIPT.name
        shutil.copyfile(SCRIPT, script)
        shutil.copyfile(ROOT / "scripts/pon_decentralization_audit.py",
                        scripts / "pon_decentralization_audit.py")
        policy_path = config / "decentralization-audit-v1.json"
        policy_path.write_text(json.dumps(D.POLICY))
        expected = self.seal()
        accepted = self.cli(expected, script=script)
        self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
        self.assert_unaccepted(json.loads(accepted.stdout))
        for case, updates in (("extra-field", {"unexpected": True}),
                              ("schema-version", {"schema": "trnm-decentralization-policy-v2"}),
                              ("changed-limit", {"max_input_bytes": D.MAX_BYTES + 1})):
            policy = copy.deepcopy(D.POLICY)
            policy.update(updates)
            policy_path.write_text(json.dumps(policy))
            output = self.root / (case + "-report.json")
            with self.subTest(case=case):
                rejected = self.cli(expected, "--output", output, script=script)
                self.assertEqual(rejected.returncode, 2)
                self.assertIn(b"INSTALLED_POLICY_BINDING", rejected.stderr)
                self.assertEqual(rejected.stdout, b"")
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
