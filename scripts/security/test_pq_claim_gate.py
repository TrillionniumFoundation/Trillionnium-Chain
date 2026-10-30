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
                profile = {"pq_128_security_qualified": False,
                           "proof_receipt_kind": module.RESEARCH_PROOF_RECEIPT_KIND}
                profile.update({flag: False for flag in module.PROOF_RESEARCH_ONLY_FALSE_FLAGS})
                target.write_text(json.dumps(profile), encoding="utf-8")
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

    def test_unreviewed_pq128_flag_does_not_bypass_claim_gate(self):
        import subprocess
        import sys
        path = self.root / module.PATHS["w1_backend"]
        profile = json.loads(path.read_text(encoding="utf-8"))
        profile["pq_128_security_qualified"] = True
        path.write_text(json.dumps(profile), encoding="utf-8")
        self.assertIn("unreviewed_pq128_proof_claim", self.kinds())
        self.assertFalse(module.inspect(self.root)["pq_chain_qualified"])
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), "--assert-unqualified"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(
            {item["kind"] for item in json.loads(result.stdout)["known_open_findings"]},
            {"classical_authority", "unreviewed_pq128_proof_claim"},
        )

    def test_unreadable_classic_authority_is_fail_closed(self):
        import subprocess
        import sys
        (self.root / module.PATHS["hepta_handoff"]).write_bytes(b"\xff")
        self.assertIn("unreadable_source", self.kinds())
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), "--assert-unqualified"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)

    def test_unqualified_baseline_remains_reported_without_false_failure(self):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), "--assert-unqualified"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unqualified_proof", result.stdout)

    def test_malformed_proof_types_and_non_object_profile_are_refused(self):
        import subprocess
        import sys

        proof = self.root / module.PATHS["w1_backend"]
        baseline = json.loads(proof.read_text(encoding="utf-8"))

        def assert_cli_refuses(expected):
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(self.root), "--assert-unqualified"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            report = json.loads(result.stdout)
            expected_kinds = {"classical_authority", expected}
            self.assertEqual(
                {item["kind"] for item in report["known_open_findings"]},
                expected_kinds,
            )
            self.assertFalse(report["pq_chain_qualified"])

        for bad_value in (1, "true", None):
            with self.subTest(bad_value=bad_value):
                proof.write_text(
                    json.dumps({**baseline, "pq_128_security_qualified": bad_value}),
                    encoding="utf-8",
                )
                self.assertIn("invalid_proof_qualification_flag_type", self.kinds())
                assert_cli_refuses("invalid_proof_qualification_flag_type")
        proof.write_text("[]", encoding="utf-8")
        self.assertIn("invalid_proof_profile_shape", self.kinds())
        assert_cli_refuses("invalid_proof_profile_shape")
        proof.write_text(json.dumps(baseline), encoding="utf-8")

    def test_all_production_flags_refuse_in_isolation_with_valid_proof(self):
        import subprocess
        import sys

        consensus = self.root / module.PATHS["consensus"]
        baseline = json.loads(consensus.read_text(encoding="utf-8"))
        # Keep setUp's complete Composite/exact-false W1 fixture unchanged.
        # An unrelated proof failure must not mask a broken consensus CLI gate.
        proof = self.root / module.PATHS["w1_backend"]
        original_proof = proof.read_bytes()

        def assert_cli(expected=None):
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(self.root), "--assert-unqualified"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0 if expected is None else 2, result.stdout)
            report = json.loads(result.stdout)
            expected_kinds = {"classical_authority", "unqualified_proof"}
            if expected is not None:
                expected_kinds.add(expected)
            self.assertEqual(
                {item["kind"] for item in report["known_open_findings"]},
                expected_kinds,
            )
            self.assertFalse(report["pq_chain_qualified"])
            self.assertEqual(proof.read_bytes(), original_proof)

        assert_cli()
        for flag in module.PRODUCTION_FLAGS:
            cases = [(True, "production_claim_requires_independent_pq_review")]
            cases.extend(
                (value, "invalid_production_flag_type")
                for value in (None, 0, 1, "false", "true", [], {})
            )
            for value, expected in cases:
                with self.subTest(flag=flag, value=value):
                    consensus.write_text(json.dumps({**baseline, flag: value}), encoding="utf-8")
                    self.assertIn(expected, self.kinds())
                    assert_cli(expected)
            with self.subTest(flag=flag, missing=True):
                missing = dict(baseline)
                del missing[flag]
                consensus.write_text(json.dumps(missing), encoding="utf-8")
                self.assertIn("invalid_production_flag_type", self.kinds())
                assert_cli("invalid_production_flag_type")
            consensus.write_text(json.dumps(baseline), encoding="utf-8")
            assert_cli()

        for value in ([], None, 0, "invalid", True):
            with self.subTest(non_object=value):
                consensus.write_text(json.dumps(value), encoding="utf-8")
                self.assertIn("invalid_consensus_profile_shape", self.kinds())
                assert_cli("invalid_consensus_profile_shape")
        consensus.write_text(json.dumps(baseline), encoding="utf-8")
        assert_cli()

    def test_proof_receipt_and_all_fallback_switches_fail_closed(self):
        import subprocess
        import sys
        proof = self.root / module.PATHS["w1_backend"]
        baseline = json.loads(proof.read_text(encoding="utf-8"))

        def refuses(expected):
            self.assertIn(expected, self.kinds())
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(self.root), "--assert-unqualified"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout)

        # Even with pq_128_security_qualified=false, a Groth16 or Fake
        # receipt must not silently enter this Composite-only profile.
        for receipt in ("Groth16", "Fake", "", None):
            with self.subTest(receipt=receipt):
                proof.write_text(json.dumps({**baseline, "proof_receipt_kind": receipt}),
                                 encoding="utf-8")
                refuses("unsupported_proof_receipt_kind")
        proof.write_text(json.dumps(baseline), encoding="utf-8")

        for flag in module.PROOF_RESEARCH_ONLY_FALSE_FLAGS:
            with self.subTest(flag=flag, value=True):
                proof.write_text(json.dumps({**baseline, flag: True}), encoding="utf-8")
                refuses("unsafe_proof_policy_enabled")
                self.assertTrue(any(
                    item.get("field") == flag and item["kind"] == "unsafe_proof_policy_enabled"
                    for item in module.inspect(self.root)["known_open_findings"]
                ))
            for bad_value in (1, "false", None):
                with self.subTest(flag=flag, bad_value=bad_value):
                    proof.write_text(json.dumps({**baseline, flag: bad_value}),
                                     encoding="utf-8")
                    refuses("invalid_proof_policy_flag_type")
            with self.subTest(flag=flag, missing=True):
                missing = dict(baseline)
                del missing[flag]
                proof.write_text(json.dumps(missing), encoding="utf-8")
                refuses("invalid_proof_policy_flag_type")
        proof.write_text(json.dumps(baseline), encoding="utf-8")
        baseline_result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), "--assert-unqualified"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(baseline_result.returncode, 0, baseline_result.stdout)
        self.assertIn("unqualified_proof", baseline_result.stdout)

    def test_duplicate_json_members_cannot_hide_unsafe_pq_or_consensus_flags(self):
        import subprocess
        import sys

        proof = self.root / module.PATHS["w1_backend"]
        consensus = self.root / module.PATHS["consensus"]
        baseline_proof = proof.read_text(encoding="utf-8")
        baseline_consensus = consensus.read_text(encoding="utf-8")

        def refuses(kind, member):
            matches = [finding for finding in
                       module.inspect(self.root)["known_open_findings"]
                       if finding["kind"] == kind]
            self.assertEqual([finding["member"] for finding in matches], [member])
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(self.root),
                 "--assert-unqualified"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn(kind, result.stdout)

        # A first-wins consumer sees unsafe true; Python's default
        # last-wins parser previously let the false duplicate bypass this gate.
        proof.write_text('{"pq_128_security_qualified": true,' +
                         baseline_proof[1:], encoding="utf-8")
        refuses("duplicate_proof_json_member", "pq_128_security_qualified")
        proof.write_text(baseline_proof, encoding="utf-8")

        consensus.write_text('{"release_ready": true,' +
                             baseline_consensus[1:], encoding="utf-8")
        refuses("duplicate_consensus_json_member", "release_ready")
        consensus.write_text(baseline_consensus, encoding="utf-8")

        # No ambiguity is allowed even inside a nested future policy object.
        proof.write_text('{"future_policy":{"algorithm":"Groth16",'
                         '"algorithm":"Composite"},' + baseline_proof[1:],
                         encoding="utf-8")
        refuses("duplicate_proof_json_member", "algorithm")
        proof.write_text(baseline_proof, encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root),
             "--assert-unqualified"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("unqualified_proof", result.stdout)

if __name__ == "__main__":
    unittest.main()
