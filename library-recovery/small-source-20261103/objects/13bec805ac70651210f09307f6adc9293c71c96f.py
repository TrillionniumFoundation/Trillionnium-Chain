import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pq_readiness import GATES, SURFACES, EXPECTED_PATHS, audit, safe_existing_file


class PqReadinessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.repo = self.base / "checkout"
        self.repo.mkdir()
        self.policy_file = self.base / "policy.json"
        self.policy = json.loads((Path(__file__).resolve().parents[1] / "pq_evidence.template.json").read_text())
        for rel in EXPECTED_PATHS.values():
            file = self.repo / rel
            file.parent.mkdir(parents=True, exist_ok=True)
            if file.suffix == ".json":
                file.write_text(json.dumps({"risc0_version": "4.1.0",
                                            "pq_128_security_qualified": False,
                                            "production_consensus_activation": False}), encoding="utf8")
            else:
                file.write_text("// Ed25519 reference: triage only\n", encoding="utf8")
        (self.repo / "evidence").mkdir()
        for gate in GATES:
            artifact = self.repo / "evidence" / f"{gate}.txt"
            artifact.write_text("Independent evidence placeholder for tests", encoding="utf8")
            self.policy["evidence"][gate] = {
                "verdict": "pass",
                "author": "implementation-owner",
                "reviewer": "independent-reviewer",
                "independent_reproduction": True,
                "artifact": f"evidence/{gate}.txt",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        for surface in SURFACES:
            self.policy["authority_surfaces"][surface] = {"verification": "pq_only"}
        self.policy["downgrade_policy"].update({
            "pre_quantum_ownership_committed": True, "domain_separated": True,
            "chain_and_nonce_bound": True, "reorg_replay_tested": True})
        self.policy["proof_policy"].update({
            "independently_reviewed_quantum_bits": 128,
            "complete_w1_relation_verified": True,
            "fiat_shamir_quantum_model_reviewed": True})
        for key in self.policy["quantum_work_policy"]:
            self.policy["quantum_work_policy"][key] = True
        for key in self.policy["resource_policy"]:
            self.policy["resource_policy"][key] = True
        for key in self.policy["rollback_policy"]:
            self.policy["rollback_policy"][key] = True
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=PQ-test", "-c", "user.email=pq@example.invalid",
                 "commit", "-qm", "fixture")
        self.policy["expected_head_sha"] = self.git("rev-parse", "HEAD").strip()
        self.write_policy()

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args],
                              text=True, capture_output=True, check=True).stdout

    def write_policy(self):
        self.policy_file.write_text(json.dumps(self.policy), encoding="utf8")

    def codes(self):
        return {i["code"] for i in audit(self.repo, self.policy_file)["issues"]}

    def test_evidence_precheck_cannot_certify(self):
        report = audit(self.repo, self.policy_file)
        self.assertEqual(report["status"], "EVIDENCE_PRECHECK_PASSED_NOT_CERTIFIED")
        self.assertFalse(report["pq128_certified"])
        self.assertFalse(report["production_approved"])
        self.assertFalse(report["issues"])
        self.assertGreater(report["classical_and_pq_references"]["counts"]["ed25519"], 0)

    def test_default_template_fails_closed(self):
        default = json.loads((Path(__file__).resolve().parents[1] / "pq_evidence.template.json").read_text())
        self.policy = default
        self.write_policy()
        report = audit(self.repo, self.policy_file)
        self.assertEqual(report["status"], "NOT_QUALIFIED")
        self.assertIn("source_baseline_unverified", self.codes())
        self.assertIn("pq128_not_reviewed", self.codes())

    def test_hybrid_or_is_downgrade(self):
        self.policy["downgrade_policy"]["hybrid_acceptance"] = "either"
        self.write_policy()
        self.assertIn("hybrid_or_downgrade", self.codes())

    def test_proof_groth16_not_accepted(self):
        self.policy["proof_policy"]["allow_groth16"] = True
        self.write_policy()
        self.assertIn("unsafe_allow_groth16", self.codes())

    def test_pq_128_self_flagged_is_not_certified(self):
        p = self.repo / EXPECTED_PATHS["w1_backend_manifest"]
        obj = json.loads(p.read_text())
        obj["pq_128_security_qualified"] = True
        p.write_text(json.dumps(obj))
        report = audit(self.repo, self.policy_file)
        self.assertFalse(report["pq128_certified"])
        self.assertIn("pq128_qualification_claim_detected", self.codes())

    def test_consensus_activated_requires_external_review(self):
        p = self.repo / EXPECTED_PATHS["w1_backend_manifest"]
        obj = json.loads(p.read_text())
        obj["production_consensus_activation"] = True
        p.write_text(json.dumps(obj))
        self.assertIn("production_activation_detected", self.codes())

    def test_backend_version_3_0_6_does_not_support_pq128_claim(self):
        p = self.repo / EXPECTED_PATHS["w1_backend_manifest"]
        obj = json.loads(p.read_text())
        obj["risc0_version"] = "3.0.6"
        p.write_text(json.dumps(obj))
        self.assertIn("risc0_3_0_6_insufficient", self.codes())

    def test_evidence_tampering_detected(self):
        artifact = self.repo / "evidence" / "quantum_work.txt"
        artifact.write_text("tampered")
        self.assertIn("artifact_digest_mismatch", self.codes())

    def test_no_artifact_path_traversal(self):
        self.policy["evidence"]["quantum_work"]["artifact"] = "../policy.json"
        self.write_policy()
        self.assertIn("artifact_unavailable", self.codes())
        self.assertIsNone(safe_existing_file(self.repo, "../policy.json"))

    def test_symlink_not_accepted_as_evidence(self):
        (self.repo / "evidence" / "quantum_work.txt").unlink()
        (self.repo / "evidence" / "quantum_work.txt").symlink_to(self.policy_file)
        self.assertIn("artifact_unavailable", self.codes())

    def test_symlink_parent_not_accepted(self):
        (self.repo / "linked").symlink_to(self.repo / "evidence", target_is_directory=True)
        self.assertIsNone(safe_existing_file(self.repo, "linked/quantum_work.txt"))

    def test_unknown_authority_surface_blocks(self):
        self.policy["authority_surfaces"]["governance"] = None
        self.write_policy()
        self.assertIn("unmapped_governance", self.codes())

    def test_rollback_anchor_not_optional(self):
        self.policy["rollback_policy"]["external_monotonic_anchor"] = False
        self.write_policy()
        self.assertIn("missing_external_monotonic_anchor", self.codes())

    def test_activation_requested_still_cannot_certify(self):
        self.policy["activation_requested"] = True
        self.write_policy()
        self.assertIn("activation_requested", self.codes())

    def test_malformed_backend_manifest_fails(self):
        p = self.repo / EXPECTED_PATHS["w1_backend_manifest"]
        p.write_text("{ bad json")
        self.assertIn("invalid_backend_manifest", self.codes())

    def test_wrong_repository_sha_fails(self):
        self.policy["expected_head_sha"] = "a" * 40
        self.write_policy()
        self.assertIn("source_baseline_unverified", self.codes())

    def test_nonboolean_flag_rejected(self):
        p = self.repo / EXPECTED_PATHS["w1_backend_manifest"]
        obj = json.loads(p.read_text())
        obj["pq_128_security_qualified"] = "false"
        p.write_text(json.dumps(obj))
        self.assertIn("nonboolean_pq_128_security_qualified", self.codes())

    def test_missing_file_marked_not_qualified(self):
        (self.repo / EXPECTED_PATHS["ingress"]).unlink()
        self.assertIn("missing_ingress", self.codes())


if __name__ == "__main__":
    unittest.main()
