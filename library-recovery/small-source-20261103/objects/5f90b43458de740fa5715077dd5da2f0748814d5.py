"""Synthetic fixture tests for local preflight behavior. NO real PQ proofs here."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pq_preflight import (  # noqa: E402
    GATES,
    MIGRATION_CONTROLS,
    MINING_CASES,
    OPERATIONS_CONTROLS,
    PERF_CASES,
    W1_CONTROLS,
    evaluate,
    template,
)


class PQPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data = template()
        self.data["baseline"] = {
            "main_sha": "a" * 40,
            "target_network": "synthetic-regtest",
            "evaluated_at": "2000-01-01T00:00:00Z",
        }
        self.next_id = 0

    def receipt(self, claim: str, *, independent: bool = False) -> str:
        self.next_id += 1
        key = f"e{self.next_id:04d}"
        path = f"receipt_{key}.txt"
        contents = ("SYNTHETIC ONLY: " + claim + "\n").encode()
        (self.root / path).write_bytes(contents)
        self.data["evidence"].append({
            "id": key,
            "path": path,
            "sha256": hashlib.sha256(contents).hexdigest(),
            "commit_sha": self.data["baseline"]["main_sha"],
            "status": "passed",
            "independent": independent,
            "reviewer_id": "test-reviewer" if independent else None,
            "claims": [claim],
        })
        return key

    def fully_attested_synthetic(self) -> dict:
        for surface in self.data["authority_surfaces"]:
            surface.update({
                "source_path": "SYNTHETIC/no-real-source.rs",
                "reachability": "reachable", "authority_effect": "yes",
                "policy": "hybrid_and", "owner_binding": "precommitted_pq",
                "context_bound": True, "replay_bound": True,
                "downgrade_rejected": True,
                "reachability_evidence": self.receipt(surface["id"] + " reachability"),
                "authorization_evidence": self.receipt(surface["id"] + " authorization"),
            })
        for name in MIGRATION_CONTROLS:
            self.data["migration"][name] = {"verified": True, "evidence": self.receipt(name)}
        p = self.data["w1_proof"]
        p.update({
            "backend": "transparent_stark_composite",
            "pq_128_security_qualified": True, "soundness_bits_quantum": 128,
            "groth16_enabled": False, "fake_or_remote_receipts_enabled": False,
            "independent_review_evidence": self.receipt("W1 independent proof review", independent=True),
        })
        manifest = {"pq_128_security_qualified": True,
                    "production_consensus_activation": True}
        raw = (json.dumps(manifest) + "\n").encode()
        (self.root / "backend-manifest.json").write_bytes(raw)
        self.next_id += 1
        key = f"e{self.next_id:04d}"
        self.data["evidence"].append({
            "id": key,
            "path": "backend-manifest.json",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "commit_sha": self.data["baseline"]["main_sha"],
            "status": "passed", "independent": False,
            "claims": ["W1 backend manifest exact"],
        })
        p["backend_manifest_evidence"] = key
        for name in W1_CONTROLS:
            p["controls"][name] = {"verified": True, "evidence": self.receipt(name)}
        q = self.data["quantum_consensus"]
        q.update({
            "cheapest_legal_solver_benchmark": True,
            "quantum_attack_lower_bound_justified": True,
            "difficulty_attack_safety_verified": True,
            "independent_review_evidence": self.receipt("independent mining review", independent=True),
        })
        for name in MINING_CASES:
            q["cases"][name] = {"verified": True, "evidence": self.receipt(name)}
        for name in PERF_CASES:
            self.data["capacity_dos"]["cases"][name] = {"budget_met": True, "evidence": self.receipt(name)}
        o = self.data["recovery_activations"]
        o["independent_review_evidence"] = self.receipt("independent recovery review", independent=True)
        for name in OPERATIONS_CONTROLS:
            o["controls"][name] = {"verified": True, "evidence": self.receipt(name)}
        return self.data

    def blocked(self, gate: str, token: str = "") -> None:
        result = evaluate(self.data, self.root)
        self.assertTrue(result[gate], f"gate unexpectedly clear: {gate}")
        if token:
            self.assertIn(token, "\n".join(result[gate]))

    def test_empty_template_is_no_go_all_six(self) -> None:
        result = evaluate(self.data, self.root)
        self.assertTrue(all(result[g] for g in GATES))

    def test_synthetic_complete_claims_are_only_precheck_consistent(self) -> None:
        self.fully_attested_synthetic()
        result = evaluate(self.data, self.root)
        self.assertEqual(result, {gate: [] for gate in GATES})

    def test_classic_only_authority_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["authority_surfaces"][0]["policy"] = "classic_only"
        self.blocked(GATES[0], "classic-only")

    def test_hybrid_or_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["authority_surfaces"][0]["policy"] = "hybrid_or"
        self.blocked(GATES[0], "OR")

    def test_unknown_reachability_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["authority_surfaces"][1]["reachability"] = "unknown"
        self.blocked(GATES[0], "remain unknown")

    def test_inactive_classic_path_with_proved_guard_not_active_authority(self) -> None:
        self.fully_attested_synthetic()
        self.data["authority_surfaces"][0].update({
            "reachability": "unreachable", "policy": "classic_only",
            "inaccessible_activation_guard": True,
        })
        self.assertFalse(evaluate(self.data, self.root)[GATES[0]])

    def test_unproved_inactive_guard_is_blocked(self) -> None:
        self.fully_attested_synthetic()
        self.data["authority_surfaces"][0].update({
            "reachability": "unreachable", "policy": "classic_only",
            "inaccessible_activation_guard": False,
        })
        self.blocked(GATES[0], "not proven fail-closed")

    def test_missing_surface_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["authority_surfaces"].pop()
        self.blocked(GATES[0], "exactly one authority surface")

    def test_reused_receipt_without_claim_scope_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["authority_surfaces"][0]["authorization_evidence"] = self.data["authority_surfaces"][0]["reachability_evidence"]
        self.blocked(GATES[0], "does not identify this exact claim")

    def test_digest_tampering_rejected(self) -> None:
        self.fully_attested_synthetic()
        (self.root / "receipt_e0001.txt").write_text("TAMPERED", encoding="utf-8")
        self.blocked(GATES[0], "digest mismatch")

    def test_outside_evidence_root_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["evidence"][0]["path"] = "../../etc/hosts"
        self.blocked(GATES[0], "path escaped")

    def test_wrong_commit_evidence_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["evidence"][0]["commit_sha"] = "b" * 40
        self.blocked(GATES[0], "commit does not equal")

    def test_missing_reviewer_rejected(self) -> None:
        self.fully_attested_synthetic()
        ref = self.data["w1_proof"]["independent_review_evidence"]
        for item in self.data["evidence"]:
            if item["id"] == ref:
                item["reviewer_id"] = None
        self.blocked(GATES[2], "named independent reviewer")

    def test_false_w1_pq128_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["w1_proof"]["pq_128_security_qualified"] = False
        self.blocked(GATES[2], "explicit PQ-128")

    def test_backend_manifest_false_blocks_even_if_claim_says_true(self) -> None:
        self.fully_attested_synthetic()
        raw = json.dumps({"pq_128_security_qualified": False,
                          "production_consensus_activation": True}).encode()
        (self.root / "backend-manifest.json").write_bytes(raw)
        ref = self.data["w1_proof"]["backend_manifest_evidence"]
        for e in self.data["evidence"]:
            if e["id"] == ref:
                e["sha256"] = hashlib.sha256(raw).hexdigest()
        self.blocked(GATES[2], "pq_128_security_qualified")

    def test_production_activation_false_rejected(self) -> None:
        self.fully_attested_synthetic()
        raw = json.dumps({"pq_128_security_qualified": True,
                          "production_consensus_activation": False}).encode()
        (self.root / "backend-manifest.json").write_bytes(raw)
        ref = self.data["w1_proof"]["backend_manifest_evidence"]
        for e in self.data["evidence"]:
            if e["id"] == ref:
                e["sha256"] = hashlib.sha256(raw).hexdigest()
        self.blocked(GATES[2], "production_consensus_activation")

    def test_groth16_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["w1_proof"]["groth16_enabled"] = True
        self.blocked(GATES[2], "Groth16")

    def test_cheap_solver_without_lower_bound_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["quantum_consensus"]["quantum_attack_lower_bound_justified"] = False
        self.blocked(GATES[3], "lower_bound")

    def test_historic_db_rollback_not_anchored_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["recovery_activations"]["controls"]["external_monotonic_anchor"]["verified"] = False
        self.blocked(GATES[5], "external_monotonic_anchor")

    def test_invalid_signature_cost_unbounded_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["capacity_dos"]["cases"]["invalid_signature_worst_case"]["budget_met"] = False
        self.blocked(GATES[4], "invalid_signature")

    def test_unsafe_downgrade_rejected(self) -> None:
        self.fully_attested_synthetic()
        self.data["migration"]["signature_algorithm_no_downgrade"]["verified"] = False
        self.blocked(GATES[1], "no_downgrade")


if __name__ == "__main__":
    unittest.main()
