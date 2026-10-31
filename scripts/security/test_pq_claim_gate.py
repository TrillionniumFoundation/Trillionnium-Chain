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
                profile.update(module.PINNED_W1_RESEARCH_PARAMETERS)
                profile.update({flag: False for flag in module.PROOF_RESEARCH_ONLY_FALSE_FLAGS})
                target.write_text(json.dumps(profile), encoding="utf-8")
            elif key == "consensus":
                profile = dict(module.PINNED_CONSENSUS_UNQUALIFIED_PARAMETERS)
                profile["native_application_scope"] = "unit-test-research-only"
                profile.update({f: False for f in module.PRODUCTION_FLAGS})
                target.write_text(json.dumps(profile), encoding="utf-8")
            else:
                target.write_text(json.dumps({f: False for f in module.PRODUCTION_FLAGS}), encoding="utf-8")

        # Original source-bound fixture: no synthetic preimage can pass the
        # SHA-256 manifest gate. Copy the unchanged, real pinned guest bytes.
        for source_rel in module.PINNED_W1_RESEARCH_PARAMETERS["guest_source_sha256"]:
            relative = Path(module.PATHS["w1_backend"]).parent / source_rel
            original = (SCRIPT.parents[2] / relative).resolve()
            destination = (self.root / relative).resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(original.read_bytes())

    def kinds(self):
        return {row["kind"] for row in module.inspect(self.root)["known_open_findings"]}


    def test_redirected_checkout_source_refused_even_with_identical_valid_bytes(self):
        import subprocess
        import sys

        def assert_refused(key):
            findings = module.inspect(self.root)["known_open_findings"]
            self.assertTrue(any(
                item["kind"] == "untrusted_checkout_source_path"
                and item["path"] == module.PATHS[key]
                for item in findings
            ), findings)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(self.root),
                 "--assert-unqualified"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("untrusted_checkout_source_path", result.stdout)

        # Each policy/authority source must be a real checkout file, not a
        # symlink redirect to byte-identical content in the same repository.
        # The old gate accepted these redirects with exit code zero.
        for key in module.PATHS:
            with self.subTest(redirected_file=key):
                source = self.root / module.PATHS[key]
                copied = source.with_name(source.name + ".shadow")
                original_bytes = source.read_bytes()
                copied.write_bytes(original_bytes)
                source.unlink()
                source.symlink_to(copied.name)
                try:
                    assert_refused(key)
                finally:
                    source.unlink()
                    source.write_bytes(original_bytes)
                    copied.unlink()

        # A symlinked parent directory is also a redirect even when the
        # final config/consensus-mainline.json is a regular byte-identical file.
        real_config = self.root / "config"
        alternate_config = self.root / "config-checked-out"
        real_config.rename(alternate_config)
        real_config.symlink_to(alternate_config.name, target_is_directory=True)
        try:
            assert_refused("consensus")
        finally:
            real_config.unlink()
            alternate_config.rename(real_config)

        # Original unqualified inputs are intentionally still an exit-zero
        # audit baseline; this fix does not promote them to PQ qualification.
        restored = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root),
             "--assert-unqualified"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(restored.returncode, 0, restored.stdout)
        self.assertIn("unqualified_proof", restored.stdout)

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
        path.write_text(json.dumps({"pq_128_security_qualified": True}), encoding="utf-8")
        self.assertIn("unreviewed_pq128_proof_claim", self.kinds())
        self.assertFalse(module.inspect(self.root)["pq_chain_qualified"])
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), "--assert-unqualified"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unreviewed_pq128_proof_claim", result.stdout)

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

    def test_malformed_flag_types_and_non_object_profiles_are_refused(self):
        import subprocess
        import sys

        def assert_cli_refuses():
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(self.root), "--assert-unqualified"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout)

        proof = self.root / module.PATHS["w1_backend"]
        consensus = self.root / module.PATHS["consensus"]
        original_consensus = json.loads(consensus.read_text(encoding="utf-8"))

        for bad_value in (1, "true", None):
            proof.write_text(
                json.dumps({"pq_128_security_qualified": bad_value}), encoding="utf-8"
            )
            self.assertIn("invalid_proof_qualification_flag_type", self.kinds())
            assert_cli_refuses()
        proof.write_text(json.dumps({"pq_128_security_qualified": False}), encoding="utf-8")

        for bad_value in (1, "false", None):
            wrong = dict(original_consensus)
            wrong["production_candidate"] = bad_value
            consensus.write_text(json.dumps(wrong), encoding="utf-8")
            self.assertIn("invalid_production_flag_type", self.kinds())
            assert_cli_refuses()

        consensus.write_text(json.dumps(original_consensus), encoding="utf-8")
        proof.write_text("[]", encoding="utf-8")
        self.assertIn("invalid_proof_profile_shape", self.kinds())
        assert_cli_refuses()
        proof.write_text(json.dumps({"pq_128_security_qualified": False}), encoding="utf-8")
        consensus.write_text("[]", encoding="utf-8")
        self.assertIn("invalid_consensus_profile_shape", self.kinds())
        assert_cli_refuses()

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

    def test_w1_research_security_parameter_changes_require_review(self):
        import subprocess
        import sys

        proof = self.root / module.PATHS["w1_backend"]
        baseline = json.loads(proof.read_text(encoding="utf-8"))

        def refuse(field, changed):
            modified = dict(baseline)
            if changed is None:
                modified.pop(field)
            else:
                modified[field] = changed
            proof.write_text(json.dumps(modified), encoding="utf-8")
            findings = [
                f for f in module.inspect(self.root)["known_open_findings"]
                if f["kind"] == "unreviewed_w1_research_parameter_change"
            ]
            self.assertTrue(any(f["field"] == field for f in findings), findings)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(self.root),
                 "--assert-unqualified"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout)

        # A false PQ128 flag does not make silently weakened FRI, swapped
        # transcript/commitment hash, different backend or guest executable safe.
        changed = {
            "proof_fri_queries": 1,
            "proof_fri_inverse_rate": 2,
            "work_transcript_hash": "SHA-1",
            "proof_commitment_hash": "SHA-256",
            "backend_version": "3.0.7",
            "backend_source_commit": "0" * 40,
            "guest_image_id": "0" * 64,
            "guest_program_sha256": "0" * 64,
            "work_n": 32,
            "backend_claimed_conjectured_security_bits": 128,
        }
        for field, value in changed.items():
            with self.subTest(field=field, value=value):
                refuse(field, value)
        # Python considers True == 1; strict source types must not.
        with self.subTest(field="work_r", value=True):
            refuse("work_r", True)
        with self.subTest(field="proof_fri_queries", missing=True):
            refuse("proof_fri_queries", None)
        # Missing and explicit null were previously indistinguishable to
        # profile.get(): omitting provenance must never pass a frozen profile.
        with self.subTest(field="guest_relation_source_commit", missing=True):
            refuse("guest_relation_source_commit", None)

        proof.write_text(json.dumps(baseline), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root),
             "--assert-unqualified"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("unqualified_proof", result.stdout)


    def test_consensus_unknown_fields_and_research_status_changes_are_refused(self):
        import subprocess
        import sys

        consensus = self.root / module.PATHS["consensus"]
        baseline = json.loads(consensus.read_text(encoding="utf-8"))
        self.assertEqual(set(baseline), module.ALLOWED_CONSENSUS_FIELDS)

        def refuses(profile, kind, field=None):
            consensus.write_text(json.dumps(profile), encoding="utf-8")
            findings = module.inspect(self.root)["known_open_findings"]
            self.assertTrue(any(
                item["kind"] == kind and (field is None or item.get("field") == field)
                for item in findings
            ), findings)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(self.root),
                 "--assert-unqualified"], capture_output=True,
                text=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn(kind, result.stdout)

        # Alias claims are not permitted just because all four known
        # release/production switches are still explicit Boolean false.
        for field, value in (
            ("pq_chain_qualified", True),
            ("pq_128_security_qualified", True),
            ("alternate_consensus_activation", {"enabled": True}),
        ):
            with self.subTest(unreviewed=field):
                refuses({**baseline, field: value},
                        "unreviewed_consensus_profile_field", field)

        for field, value in (
            ("runtime_implemented", True),
            ("work_profile_qualified", 1),
            ("active_consensus_implementation", "pon-production"),
            ("schema", "trnm-consensus-mainline-truth-v3"),
        ):
            with self.subTest(changed=field):
                refuses({**baseline, field: value},
                        "unreviewed_consensus_unqualified_parameter_change", field)

        # A null-valued *required* authority declaration cannot disappear:
        # dict.get() would otherwise conflate the absence with explicit null.
        missing = dict(baseline)
        del missing["active_consensus_implementation"]
        refuses(missing, "unreviewed_consensus_unqualified_parameter_change",
                "active_consensus_implementation")
        missing = dict(baseline)
        del missing["native_application_scope"]
        refuses(missing, "invalid_consensus_scope")

        consensus.write_text(json.dumps(baseline), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root),
             "--assert-unqualified"], capture_output=True,
            text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("unqualified_proof", result.stdout)

    def test_extra_w1_policy_fields_require_review_even_when_pq128_is_false(self):
        import subprocess
        import sys

        proof = self.root / module.PATHS["w1_backend"]
        baseline = proof.read_text(encoding="utf-8")
        declared = json.loads(baseline)
        self.assertEqual(set(declared), module.ALLOWED_W1_RESEARCH_FIELDS)

        # None of these names is currently approved in the research schema.
        # A future prover could interpret one as an active override.
        for field, value in (
            ("proof_fri_queries_override", 1),
            ("receipt_verification_mode", "Groth16"),
            ("external_pq_attestation", True),
        ):
            with self.subTest(field=field):
                changed = dict(declared)
                changed[field] = value
                proof.write_text(json.dumps(changed), encoding="utf-8")
                self.assertTrue(any(
                    finding["kind"] == "unreviewed_w1_research_field"
                    and finding.get("field") == field
                    for finding in module.inspect(self.root)["known_open_findings"]
                ))
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "--root", str(self.root),
                     "--assert-unqualified"],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn("unreviewed_w1_research_field", result.stdout)

        proof.write_text(baseline, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root),
             "--assert-unqualified"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("unqualified_proof", result.stdout)

    def test_actual_w1_guest_bytes_not_only_declared_manifest_are_pinned(self):
        import subprocess
        import sys

        original_relative = "guest/src/main.rs"
        relative = Path(module.PATHS["w1_backend"]).parent / original_relative
        source = self.root / relative
        baseline = source.read_bytes()

        def assert_cli_rejects(kind):
            self.assertIn(kind, self.kinds())
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(self.root),
                 "--assert-unqualified"], capture_output=True,
                text=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout)

        # Changing the actual relation bytes with an untouched, truthfully
        # unqualified W1 manifest must still fail before any PQ status claim.
        source.write_bytes(baseline + b"\\n")
        assert_cli_rejects("w1_guest_source_digest_mismatch")
        source.write_bytes(baseline)

        # A missing file is not permitted to inherit a prior digest.
        source.unlink()
        assert_cli_rejects("unreadable_w1_guest_source")
        source.write_bytes(baseline)

        # A path redirected outside the reviewed tree is not an identity.
        source.unlink()
        source.symlink_to("/etc/hosts")
        assert_cli_rejects("escaped_w1_guest_source")
        source.unlink()
        source.write_bytes(baseline)

        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root),
             "--assert-unqualified"], capture_output=True,
            text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("unqualified_proof", result.stdout)

    def test_w1_guest_source_and_toolchain_provenance_change_refused(self):
        import subprocess
        import sys

        proof = self.root / module.PATHS["w1_backend"]
        baseline_text = proof.read_text(encoding="utf-8")
        baseline = json.loads(baseline_text)
        cases = {
            "official_linux_tools_sha256": "0" * 64,
            "guest_compiler_release": "r0.1.97.1",
            "official_linux_guest_compiler_archive_sha256": "0" * 64,
            "sha256_guest_accelerator_commit": "0" * 40,
            "compatibility_kernel_crate": "risc0-zkos-v1compat = 0.0.0",
            "guest_relation_source_commit": "0" * 40,
            "guest_source_sha256": {
                **baseline["guest_source_sha256"], "Cargo.lock": "0" * 64
            },
            "guest_native_differential_source": "src/changed.rs",
            "proof_grinding_review_scope": "independently-audited",
        }
        for field, altered in cases.items():
            with self.subTest(field=field):
                changed = dict(baseline)
                changed[field] = altered
                proof.write_text(json.dumps(changed), encoding="utf-8")
                findings = module.inspect(self.root)["known_open_findings"]
                self.assertTrue(any(
                    item["kind"] == "unreviewed_w1_research_parameter_change"
                    and item.get("field") == field for item in findings
                ), findings)
                run = subprocess.run(
                    [sys.executable, str(SCRIPT), "--root", str(self.root),
                     "--assert-unqualified"],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(run.returncode, 2, run.stdout)
        proof.write_text(baseline_text, encoding="utf-8")
        run = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root),
             "--assert-unqualified"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertIn("unqualified_proof", run.stdout)

    def test_nonstandard_json_nan_infinity_refused_even_in_future_fields(self):
        import subprocess
        import sys

        for label, expected_kind in (
            ("w1_backend", "unreadable_proof_profile"),
            ("consensus", "unreadable_consensus_profile"),
        ):
            path = self.root / module.PATHS[label]
            original = path.read_text(encoding="utf-8")
            self.assertTrue(original.rstrip().endswith("}"))
            for token in ("NaN", "Infinity", "-Infinity"):
                with self.subTest(label=label, token=token):
                    # The candidate still has truthful PQ=false flags, but
                    # default json.loads historically accepted these non-JSON
                    # numbers. Such bytes cannot cross a policy trust boundary.
                    altered = original.rstrip()[:-1] + (
                        ',"unreviewed_future_policy":' + token + "}"
                    )
                    path.write_text(altered, encoding="utf-8")
                    self.assertIn(expected_kind, self.kinds())
                    run = subprocess.run(
                        [sys.executable, str(SCRIPT), "--root", str(self.root),
                         "--assert-unqualified"],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(run.returncode, 2, run.stdout)
            path.write_text(original, encoding="utf-8")


    def test_native_differential_source_bytes_are_covered(self):
        import subprocess
        import sys

        source_rel = "../../src/pon_work/full_relation_tests.rs"
        expected = "3c85efae06acc62d5fdbce3d8b1e0f8a65e59675da0a6e741885952ccaad513b"
        self.assertEqual(
            module.PINNED_W1_RESEARCH_PARAMETERS["guest_source_sha256"][source_rel],
            expected,
        )
        source = self.root / Path(module.PATHS["w1_backend"]).parent / source_rel
        baseline = source.read_bytes()
        source.write_bytes(baseline + b"\n// unreviewed differential drift\n")
        self.assertIn("w1_guest_source_digest_mismatch", self.kinds())
        rejected = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root),
             "--assert-unqualified"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(rejected.returncode, 2, rejected.stdout)
        source.write_bytes(baseline)
        original = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root),
             "--assert-unqualified"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(original.returncode, 0, original.stdout)
        self.assertIn("unqualified_proof", original.stdout)

    def test_actual_w1_source_changes_trigger_the_claim_workflow(self):
        workflow = (SCRIPT.parents[2] / ".github/workflows/pq-production-claim-gate.yml")
        definition = workflow.read_text(encoding="utf-8")
        self.assertIn("  pull_request:\n", definition)
        self.assertIn(
            "trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/**",
            definition,
        )
        self.assertIn(
            "trillionnium/crates/trnm-crypto-primitives/src/pon_work/full_relation.rs",
            definition,
        )
        self.assertIn(
            "trillionnium/crates/trnm-crypto-primitives/src/pon_work/full_relation_tests.rs",
            definition,
        )
        self.assertIn(
            "ref: ${{ github.event.pull_request.head.sha || github.sha }}",
            definition,
        )

if __name__ == "__main__":
    unittest.main()
