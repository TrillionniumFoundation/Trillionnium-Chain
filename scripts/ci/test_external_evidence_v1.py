#!/usr/bin/env python3
"""Isolated CLI regressions: submission declarations are not authenticated evidence.

These fixtures never enter the repository submission directory. The tests run a
byte-for-byte copy of the real checker, not a replacement acceptance algorithm.
"""
from __future__ import annotations

import copy
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE_COMMIT = "3" * 40
SOURCE_TREE = "4" * 40
SCOPES = {
    "EXT-REVIEW-001": "review",
    "EXT-G1-CAMPAIGN-001": "network",
    "EXT-ANCHOR-HSM-001": "custody",
    "EXT-POWERLOSS-001": "host",
    "EXT-AUDIT-001": "audit",
    "EXT-SOAK-ACTIVATION-001": "production",
}
CLAIMS = {
    "EXT-REVIEW-001": {
        "package_digest": "1" * 64, "interface_digest": "2" * 64,
        "replayed_p0_mutants": 1, "downstream_invalidation": [],
    },
    "EXT-G1-CAMPAIGN-001": {
        "node_counts": [4, 7, 31, 100], "physical_hosts": 3, "operators": 2,
        "custody_domains": 2, "real_processes": True, "signed_raw_traces": True,
        "partition_heal": True, "restart_recovery": True, "state_sync": True,
        "epoch_key_rotation": True, "conflicting_finality_count": 0,
        "double_sign_count": 0,
    },
    "EXT-ANCHOR-HSM-001": {
        "device_backed": True, "private_key_non_exportable": True,
        "external_monotonic_anchor": True, "quorum_custody": True,
        "rotation_rehearsed": True, "revocation_rehearsed": True,
        "rollback_mutants_rejected": 1, "cloned_namespace_mutants_rejected": 1,
        "device_attestation_sha256": "3" * 64,
    },
    "EXT-POWERLOSS-001": {
        "physical_power_interruption": True, "host_reboot": True,
        "controller_cache_loss": True, "independent_recovery_process": True,
        "exact_root_readback": True, "sigkill_only": False,
    },
    "EXT-AUDIT-001": {
        "consensus_audit": True, "cryptography_audit": True,
        "economic_audit": True, "red_team": True, "open_critical": 0,
        "open_high": 0, "all_findings_source_bound": True,
    },
    "EXT-SOAK-ACTIVATION-001": {
        "chaos_72h_seconds": 259200, "public_testnet_7d_seconds": 604800,
        "production_candidate_30d_seconds": 2592000, "simulated_time": False,
        "incident_drill": True, "restore_drill": True,
        "key_rotation_drill": True, "state_sync_drill": True,
        "authorized_governance_record": True,
    },
}


def submission(blocker: str = "EXT-REVIEW-001") -> dict:
    return {
        "schema": "trnm-external-evidence-v1",
        "evidence_id": "synthetic-" + blocker,
        "blocker_id": blocker,
        "source_commit": SOURCE_COMMIT,
        "source_tree": SOURCE_TREE,
        "producer": "fixture-producer",
        "independent_reviewer": "fixture-reviewer",
        "independence_declaration": True,
        "scope": SCOPES[blocker],
        "result": "accepted",
        "started_at": "2026-01-01T00:00:00Z",
        "ended_at": "2026-02-01T00:00:00Z",
        "wall_clock_seconds": 31 * 86400,
        "artifacts": [{"name": "nonexistent-fixture", "sha256": "5" * 64,
                       "immutable_uri": "urn:fixture:nonexistent"}],
        "signatures": [
            {"signer": identity, "algorithm": "not-a-signature-scheme",
             "signature": "this-is-not-a-signature", "signed_digest": "6" * 64}
            for identity in ("fixture-producer", "fixture-reviewer")
        ],
        "claims": copy.deepcopy(CLAIMS[blocker]),
    }


class ExternalEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="trnm-evidence-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.script = self.root / "scripts/ci/check_external_evidence_v1.py"
        self.script.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/ci/check_external_evidence_v1.py", self.script)
        self.directory = self.root / "docs/evidence/external/submissions"
        self.directory.mkdir(parents=True)
        self.policy = self.root / "config/repository-policy-v1.json"
        self.policy.parent.mkdir()
        shutil.copyfile(ROOT / "config/repository-policy-v1.json", self.policy)

    def write(self, row: dict, name: str = "evidence.json") -> pathlib.Path:
        path = self.directory / name
        path.write_text(json.dumps(row), encoding="utf-8")
        return path

    def run_checker(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(self.script), *args], cwd=self.root,
            capture_output=True, text=True, check=False, timeout=10,
        )

    def release(self) -> subprocess.CompletedProcess[str]:
        return self.run_checker("--require-all", "--source-commit", SOURCE_COMMIT,
                                "--source-tree", SOURCE_TREE)

    def report(self, run: subprocess.CompletedProcess[str], code: int = 0) -> dict:
        self.assertEqual(run.returncode, code, run.stdout + run.stderr)
        return json.loads(run.stdout)

    def assert_unaccepted(self, report: dict) -> None:
        self.assertEqual(report["accepted"], {})
        self.assertEqual(report["open_blockers"], sorted(SCOPES))
        self.assertIs(report["all_external_blockers_closed"], False)
        self.assertIs(report["production_candidate"], False)
        self.assertIs(report["production_consensus_activation"], False)
        self.assertEqual(report["verification_scope"], "structural-declarations-only")
        self.assertIs(report["authenticity_verified"], False)
        self.assertEqual(report["independent_acceptance"], "not-assessed")

    def assert_invalid(self, run: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        self.assertNotIn("Traceback", run.stderr)
        self.assertEqual(run.stdout, "")

    def test_no_submissions_is_not_completion(self) -> None:
        report = self.report(self.run_checker())
        self.assert_unaccepted(report)
        self.assertEqual(report["submission_count"], 0)

    def test_empty_release_stays_closed(self) -> None:
        self.assert_unaccepted(self.report(self.release(), 2))

    def test_all_six_fabricated_declarations_never_close_release(self) -> None:
        for blocker in SCOPES:
            self.write(submission(blocker), blocker + ".json")
        result = self.release()
        report = self.report(result, 2)
        self.assert_unaccepted(report)
        self.assertEqual(set(report["declared_accepted"]), set(SCOPES))
        self.assertIn("external evidence gate remains open", result.stderr)

    def test_each_declaration_remains_unverified(self) -> None:
        for blocker in SCOPES:
            with self.subTest(blocker=blocker):
                self.write(submission(blocker))
                report = self.report(self.run_checker())
                self.assert_unaccepted(report)
                self.assertEqual(report["declared_accepted"],
                                 {blocker: "synthetic-" + blocker})

    def test_signature_shape_does_not_become_verification(self) -> None:
        row = submission()
        for signature in row["signatures"]:
            signature["algorithm"] = "ed25519"
            signature["signature"] = "ab" * 64
        self.write(row)
        self.assert_unaccepted(self.report(self.release(), 2))

    def test_changed_claims_and_artifact_hash_cannot_be_accepted(self) -> None:
        row = submission()
        row["claims"]["replayed_p0_mutants"] = 1000000
        row["artifacts"][0]["sha256"] = "b" * 64
        self.write(row)
        self.assert_unaccepted(self.report(self.run_checker()))

    def test_mutable_artifact_uri_is_only_a_declaration(self) -> None:
        row = submission()
        row["artifacts"][0]["immutable_uri"] = "https://example.invalid/latest"
        self.write(row)
        self.assert_unaccepted(self.report(self.run_checker()))

    def test_policy_flags_cannot_grant_this_checker_authority(self) -> None:
        policy = json.loads(self.policy.read_text())
        for key in policy["release_truth"]:
            policy["release_truth"][key] = True
        self.policy.write_text(json.dumps(policy))
        for blocker in SCOPES:
            self.write(submission(blocker), blocker + ".json")
        self.assert_unaccepted(self.report(self.release(), 2))

    def test_output_file_has_the_same_unaccepted_semantics(self) -> None:
        self.write(submission())
        output = self.root / "report.json"
        result = self.run_checker("--output", str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assert_unaccepted(json.loads(output.read_text()))

    def test_require_all_arguments_checked_even_when_empty(self) -> None:
        self.assert_invalid(self.run_checker("--require-all"))

    def test_invalid_source_arguments_are_rejected(self) -> None:
        for args in (("--source-commit", "bad", "--source-tree", SOURCE_TREE),
                     ("--source-commit", SOURCE_COMMIT, "--source-tree", "bad"),
                     ("--source-commit", SOURCE_COMMIT)):
            with self.subTest(args=args):
                self.assert_invalid(self.run_checker("--require-all", *args))

    def test_stale_commit_rejected(self) -> None:
        row = submission()
        row["source_commit"] = "7" * 40
        self.write(row)
        self.assert_invalid(self.release())

    def test_stale_tree_rejected(self) -> None:
        row = submission()
        row["source_tree"] = "7" * 40
        self.write(row)
        self.assert_invalid(self.release())

    def test_duplicate_evidence_id_rejected(self) -> None:
        self.write(submission(), "a.json")
        self.write(submission(), "b.json")
        self.assert_invalid(self.run_checker())

    def test_multiple_declared_acceptances_rejected(self) -> None:
        row = submission()
        self.write(row, "a.json")
        row["evidence_id"] += "-another"
        self.write(row, "b.json")
        self.assert_invalid(self.run_checker())

    def test_same_producer_and_reviewer_rejected(self) -> None:
        row = submission()
        row["independent_reviewer"] = row["producer"]
        self.write(row)
        self.assert_invalid(self.run_checker())

    def test_signature_digest_disagreement_rejected(self) -> None:
        row = submission()
        row["signatures"][1]["signed_digest"] = "7" * 64
        self.write(row)
        self.assert_invalid(self.run_checker())

    def test_wall_clock_boolean_is_not_an_integer(self) -> None:
        row = submission()
        row["ended_at"] = row["started_at"]
        row["wall_clock_seconds"] = False
        self.write(row)
        self.assert_invalid(self.run_checker())

    def test_duplicate_top_level_json_member_rejected(self) -> None:
        encoded = json.dumps(submission())
        (self.directory / "evidence.json").write_text(
            encoded[:-1] + ', "result": "accepted"}')
        self.assert_invalid(self.run_checker())

    def test_duplicate_nested_json_member_rejected(self) -> None:
        encoded = json.dumps(submission()).replace(
            '"replayed_p0_mutants": 1',
            '"replayed_p0_mutants": 0, "replayed_p0_mutants": 1')
        (self.directory / "evidence.json").write_text(encoded)
        self.assert_invalid(self.run_checker())

    def test_non_finite_json_number_rejected(self) -> None:
        encoded = json.dumps(submission())
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token):
                (self.directory / "evidence.json").write_text(
                    encoded[:-1] + ', "notes": ' + token + '}')
                self.assert_invalid(self.run_checker())

    def test_invalid_utf8_is_a_controlled_error(self) -> None:
        (self.directory / "evidence.json").write_bytes(b"\xff")
        self.assert_invalid(self.run_checker())

    def test_rejected_failure_is_retained_without_success_thresholds(self) -> None:
        row = submission("EXT-AUDIT-001")
        row["result"] = "rejected"
        row["claims"]["open_critical"] = 1
        row["claims"]["open_high"] = 2
        self.write(row)
        report = self.report(self.run_checker())
        self.assert_unaccepted(report)
        self.assertEqual(report["rejected_latest"]["EXT-AUDIT-001"], row["evidence_id"])

    def test_claimed_success_still_rejects_open_findings(self) -> None:
        row = submission("EXT-AUDIT-001")
        row["claims"]["open_critical"] = 1
        self.write(row)
        self.assert_invalid(self.run_checker())

    def test_rejected_record_cannot_override_an_acceptance(self) -> None:
        first = submission()
        self.write(first, "a.json")
        second = submission()
        second["evidence_id"] += "-rejected"
        second["result"] = "rejected"
        self.write(second, "z.json")
        self.assert_unaccepted(self.report(self.release(), 2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
