"""Independent scalar/full-predicate and actual-gate subset controls."""
from collections import Counter
import copy
from fractions import Fraction
import hashlib
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_w1_quantum_oracle import fixture, reference
from w1_quantum_oracle import FixedTemplate, OracleProgram, Shape, canonical, h_bytes
from w1_quantum_restricted_oracle import (
    PrefixRestrictedProgram, SCHEMA, conditional_prefix_retention,
)


def prefix_flags(template, nonce):
    challenge = hashlib.sha256(h_bytes(template.challenge_tag, template.header_for(nonce))).digest()
    result = []
    required = template.shape.n * template.shape.r
    for label in range(4):
        words = []
        for counter in range((required + 7) // 8):
            digest = hashlib.sha256(h_bytes(b"noise", challenge, bytes([label]),
                                          struct.pack("<I", counter))).digest()
            words.extend(raw & ((1 << template.shape.field_bits) - 1)
                         for (raw,) in struct.iter_unpack("<I", digest))
        result.append(all(word < template.shape.q for word in words[:required]))
    return result


class RestrictedOracleControls(unittest.TestCase):
    def test_subset_matches_independent_full_relation_and_retains_lost_winners(self):
        lost = retained = 0
        for profile in ("PNH1", "PGH2"):
            for shape in (Shape(1, 1, 4, 1), Shape(2, 1, 4, 2), Shape(2, 2, 4, 2)):
                template = fixture(shape, profile, 6)
                program = PrefixRestrictedProgram(template)
                for nonce in range(16):
                    with self.subTest(profile=profile, shape=shape, nonce=nonce):
                        expected = reference(template, nonce)
                        flags = prefix_flags(template, nonce)
                        actual = program.execute(nonce)
                        self.assertEqual(actual["noise_complete"], flags)
                        self.assertEqual(actual["winner"], expected["winner"] and all(flags))
                        self.assertTrue(actual["clean_ancillas"])
                        self.assertTrue(actual["nonce_preserved"])
                        if all(flags):
                            retained += expected["winner"]
                            for name in ("challenge", "trace", "ticket"):
                                self.assertEqual(actual[name], expected[name])
                        else:
                            lost += expected["winner"]
        self.assertGreater(lost, 0)
        self.assertGreater(retained, 0)

    def test_actual_gates_restore_success_and_rejected_noncanonical_raw_factors(self):
        template = fixture(nonce_bits=8)
        program = PrefixRestrictedProgram(template)
        nonces = {}
        for nonce in range(256):
            nonces.setdefault(all(prefix_flags(template, nonce)), nonce)
            if len(nonces) == 2:
                break
        self.assertEqual(set(nonces), {False, True})
        for valid, nonce in nonces.items():
            with self.subTest(valid=valid, nonce=nonce):
                actual = program.execute(nonce, mode="gates")
                expected = program.execute(nonce)
                for name in ("challenge", "trace", "ticket", "winner", "noise_complete", "phase"):
                    self.assertEqual(actual[name], expected[name])
                self.assertEqual(actual["winner"], valid)
                self.assertTrue(actual["clean_ancillas"])
                self.assertTrue(actual["nonce_preserved"])
                self.assertEqual(actual["leaf_gates_executed"] + actual["outer_X_Z_gates_executed"],
                                 program.resources()["phase_oracle_gate_count"])

    def test_reduced_surplus_words_are_not_extra_restrictions(self):
        template = fixture(nonce_bits=6)
        program = PrefixRestrictedProgram(template)
        self.assertEqual(program.required, 1)
        self.assertEqual(program.prefix_counters, 1)
        self.assertEqual([len(group) for group in program.raw], [1] * 4)
        for nonce in range(16):
            self.assertEqual(program.execute(nonce)["prefix_all_accepted"],
                             all(prefix_flags(template, nonce)))

    def test_every_reduced_operation_is_counted_and_reversed(self):
        program = PrefixRestrictedProgram(fixture(Shape(2, 1, 4, 2)))
        for stage, counts in program.stage_counts().items():
            forward = list(program.stage_operations(stage))
            self.assertEqual(Counter(operation.leaf for operation in forward), Counter(counts))
            self.assertEqual(list(program.stage_operations(stage, True)), list(reversed(forward)))

    def test_native_census_uses_half_noise_hashes_and_no_compaction(self):
        for profile in ("PNH1", "PGH2"):
            template = fixture(Shape(), profile, 64)
            full = OracleProgram(template).resources()
            restricted = PrefixRestrictedProgram(template).resources()
            with self.subTest(profile=profile):
                self.assertEqual(restricted["schema"], SCHEMA)
                self.assertEqual(restricted["hash_framing"]["noise_hashes_prefix_only"], 256)
                self.assertEqual(restricted["stages"]["noise_hashes"]["calls"]["sha:32:11"], 512)
                self.assertNotIn("noise_compaction", restricted["stages"])
                self.assertFalse(any(name.startswith("select:") for name in restricted["leaves"]))
                self.assertLess(restricted["forward_gate_count"], full["forward_gate_count"])
                self.assertLess(restricted["logical_qubits"], full["logical_qubits"])
                self.assertEqual(restricted["stages"]["transcript_arithmetic"], full["stages"]["transcript_arithmetic"])
                self.assertEqual(restricted["hash_framing"]["trace_bytes"], 131120)
                self.assertFalse(restricted["full_legal_winner_predicate_equivalence"])
                self.assertFalse(restricted["winning_probability_inferred_from_retention"])
                self.assertFalse(restricted["quantum_mining_security_qualified"])

    def test_distinct_source_identity_and_immutable_report_copy(self):
        template = fixture()
        program = PrefixRestrictedProgram(template)
        actual = program.resources()
        self.assertNotEqual(actual["construction_sha256"], OracleProgram(template).resources()["construction_sha256"])
        self.assertIn("formal/pon-nakamoto-v1/w1_quantum_restricted_oracle.py", actual["source_sha256"])
        original = actual["construction_sha256"]
        actual["construction_sha256"] = "0" * 64
        actual["stages"].clear()
        self.assertEqual(program.resources()["construction_sha256"], original)
        self.assertTrue(program.resources()["stages"])

    def test_changed_target_rebuilds_challenge_and_construction_identity(self):
        template = fixture()
        raw = bytearray(template.header)
        raw[118:150] = (1).to_bytes(32, "big")
        changed = FixedTemplate.from_header(bytes(raw), template.a, template.b,
                                           template.nonce_bits, template.shape)
        first, second = PrefixRestrictedProgram(template), PrefixRestrictedProgram(changed)
        self.assertNotEqual(first.resources()["construction_sha256"], second.resources()["construction_sha256"])
        self.assertNotEqual(first.execute(0)["challenge"], second.execute(0)["challenge"])
        for nonce in range(4):
            self.assertFalse(second.execute(nonce)["winner"])

    def test_retention_is_exact_conditional_raw_word_algebra_only(self):
        self.assertEqual(conditional_prefix_retention(Shape(1, 1, 4, 1)), Fraction(11, 16) ** 4)
        native = conditional_prefix_retention(Shape())
        self.assertEqual(native, Fraction((1 << 32) - 5, 1 << 32) ** 2048)
        self.assertLess(native, 1)
        self.assertGreater(native, Fraction(999997, 1000000))

    def test_gate_limit_and_missing_inverse_are_explicit(self):
        program = PrefixRestrictedProgram(fixture())
        with self.assertRaisesRegex(ValueError, "EXPLICIT_GATE_EXECUTION_BUDGET"):
            program.execute(0, mode="gates", gate_limit=1)
        self.assertFalse(program.execute(0, inverse=False)["clean_ancillas"])


class RestrictedCampaignControls(unittest.TestCase):
    def test_parser_preserves_inclusive_256_bit_denominator_and_rejects_aliases(self):
        from experiments import w1_restricted_oracle_campaign as campaign
        self.assertEqual(campaign.strict_load(canonical({"d": 1 << 256})), {"d": 1 << 256})
        for raw in (b'{"x":NaN}', b'{"x":1e999}', b'{"x":1,"x":2}',
                    canonical({"x": (1 << 256) + 1})):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                campaign.strict_load(raw)

    def test_literal_replay_refuses_rehashed_free_domain_filtering(self):
        from experiments import w1_restricted_oracle_campaign as campaign
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "campaign"
            with patch.object(campaign, "definitions", return_value=(("bounded", fixture(nonce_bits=1)),)):
                campaign.run(out)
                self.assertEqual(campaign.verify(out)["result"], "RESTRICTED_W1_DIFFERENTIAL_REPLAY_PASS")
                report = campaign.strict_load((out / "report.json").read_bytes())
                report["records"]["cases"][0]["Grover_domain_size"] = 1
                self._replace_report(out, report, campaign)
                with self.assertRaisesRegex(ValueError, "RESTRICTED_CAMPAIGN_REPLAY_MISMATCH"):
                    campaign.verify(out)

    def test_rehashed_source_and_security_claim_mutations_are_refused(self):
        from experiments import w1_restricted_oracle_campaign as campaign
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "campaign"
            with patch.object(campaign, "definitions", return_value=(("bounded", fixture(nonce_bits=1)),)):
                campaign.run(out)
                original = campaign.strict_load((out / "report.json").read_bytes())
                mutated = copy.deepcopy(original)
                mutated["assertions"]["production_activation"] = True
                self._replace_report(out, mutated, campaign)
                with self.assertRaisesRegex(ValueError, "CLAIMS_SUBSTITUTION"):
                    campaign.verify(out)
                mutated = copy.deepcopy(original)
                mutated["source"]["all_sources_committed_at_head"] = not mutated["source"]["all_sources_committed_at_head"]
                self._replace_report(out, mutated, campaign)
                with self.assertRaisesRegex(ValueError, "SOURCE_COMMITMENT_CLAIM"):
                    campaign.verify(out)

    @staticmethod
    def _replace_report(out, report, campaign):
        raw = canonical(report) + b"\n"
        (out / "report.json").write_bytes(raw)
        (out / "manifest.json").write_bytes(canonical({"schema": campaign.SCHEMA + "-manifest",
            "report_sha256": hashlib.sha256(raw).hexdigest()}))


if __name__ == "__main__":
    unittest.main()
