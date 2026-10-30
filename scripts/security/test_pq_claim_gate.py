"""Negative controls for the conservative PQ readiness claim gate."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("pq_claim_gate.py")
spec = importlib.util.spec_from_file_location("pq_claim_gate", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ClaimGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for key, rel in module.PATHS.items():
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if key in module.CLASSICAL_MARKERS:
                target.write_text(" ".join(module.CLASSICAL_MARKERS[key]), encoding="utf-8")
            elif key == "w1_backend":
                target.write_text(json.dumps({"pq_128_security_qualified": False}), encoding="utf-8")
            else:
                target.write_text(json.dumps({f: False for f in module.PRODUCTION_FLAGS}), encoding="utf-8")

    def kinds(self):
        return {row["kind"] for row in module.inspect(self.root)["known_open_findings"]}

    def test_current_classical_authority_and_proof_remain_open(self):
        self.assertIn("classical_authority", self.kinds())
        self.assertIn("unqualified_proof", self.kinds())
        self.assertFalse(module.inspect(self.root)["pq_chain_qualified"])

    def test_classical_markers_disappearing_does_not_grant_pq(self):
        for key in module.CLASSICAL_MARKERS:
            (self.root / module.PATHS[key]).write_text("replaced", encoding="utf-8")
        (self.root / module.PATHS["w1_backend"]).write_text(
            json.dumps({"pq_128_security_qualified": True}), encoding="utf-8")
        report = module.inspect(self.root)
        self.assertFalse(report["pq_chain_qualified"])
        self.assertFalse(report["complete_authority_inventory_reviewed"])

    def test_unsafe_production_claim_is_reported(self):
        path = self.root / module.PATHS["consensus"]
        profile = json.loads(path.read_text())
        profile["release_ready"] = True
        path.write_text(json.dumps(profile), encoding="utf-8")
        self.assertIn("production_claim_requires_independent_pq_review", self.kinds())

    def test_deleted_or_malformed_inputs_fail_closed(self):
        (self.root / module.PATHS["hepta_handoff"]).unlink()
        (self.root / module.PATHS["w1_backend"]).write_text("{oops", encoding="utf-8")
        self.assertIn("missing_source", self.kinds())
        self.assertIn("unreadable_proof_profile", self.kinds())

if __name__ == "__main__":
    unittest.main()
