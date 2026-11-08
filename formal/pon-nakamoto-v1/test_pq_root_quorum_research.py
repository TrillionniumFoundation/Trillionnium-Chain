#!/usr/bin/env python3
"""Codec/policy tests with explicit test doubles, never native crypto evidence."""
from dataclasses import replace
import itertools
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import pq_root_quorum_research as r


class RecordingDouble:
    """Opaque token registry: no cryptography and no emulated security claim."""
    def __init__(self):
        self.tokens = {}
        self.calls = []

    def sign(self, key, message, *, context=b""):
        token = len(self.tokens).to_bytes(4, "big") + b"\xa5" * (key.suite.signature_bytes - 4)
        self.tokens[token] = key.key_id, message, context
        return token

    def verify(self, key, message, signature):
        self.calls.append(key.key_id)
        return self.tokens.get(signature) == (key.key_id, message, b"")


def config():
    rosters = []
    for suite in r.SUITES:
        keys = [r.PublicKey(suite, bytes([suite.code * 16 + i]) * suite.spki_bytes) for i in range(3)]
        rosters.append(tuple(sorted(keys, key=lambda key: key.key_id)))
    return r.ResearchConfig(*rosters)


class RootQuorumResearchTests(unittest.TestCase):
    def setUp(self):
        self.config = config()
        self.expected = r.fixture_expected(self.config, 0)
        self.backend = RecordingDouble()
        self.message, self.records = r.sign_records(self.config, self.expected, self.backend)
        self.wire = r.encode_frame(r.FULL_MAGIC, self.message, self.records)

    def refuse(self, wire=None, code=None, *, expected=None, configuration=None):
        self.backend.calls.clear()
        with self.assertRaises(r.Rejected) as caught:
            r.verify_root_candidate(configuration or self.config, expected or self.expected,
                                    self.wire if wire is None else wire, self.backend)
        if code:
            self.assertEqual(caught.exception.code, code)
        return self.backend.calls

    def test_all_nine_independent_two_of_three_combinations(self):
        combos = tuple(itertools.combinations(range(3), 2))
        for index, pairs in enumerate(itertools.product(combos, repeat=2)):
            expected = r.fixture_expected(self.config, index, pairs=pairs)
            message, records = r.sign_records(self.config, expected, self.backend)
            result = r.verify_root_candidate(self.config, expected,
                                            r.encode_frame(r.FULL_MAGIC, message, records), self.backend)
            self.assertTrue(result["hybrid_policy_satisfied"])
            self.assertEqual(result["verified_signatures"], 4)
            self.assertFalse(result["root_effect_executed"])
            self.assertFalse(result["activation_performed"])

    def test_component_same_proposal_never_satisfies_and_and_cannot_be_relabelled(self):
        component = r.encode_frame(r.COMPONENT_MAGIC, self.message, self.records[:2])
        result = r.verify_ml_component_observation(self.config, self.expected, component, self.backend)
        self.assertFalse(result["hybrid_policy_satisfied"])
        self.assertTrue(result["component_only"])
        self.assertEqual(result["verified_signatures"], 2)
        self.assertEqual(self.refuse(component, "scope"), [])
        self.assertEqual(self.refuse(r.FULL_MAGIC + component[4:], "quorum"), [])

    def test_missing_either_family_and_threshold_input_refuse_before_backend(self):
        for records in (self.records[:2], self.records[2:], self.records[:3], ()):
            self.assertEqual(self.refuse(r.encode_frame(r.FULL_MAGIC, self.message, records), "quorum"), [])
        at = self.message.index(b"AND\x02\x02")
        weakened = self.message[:at] + b"AND\x01\x01" + self.message[at + 5:]
        self.assertEqual(self.refuse(r.encode_frame(r.FULL_MAGIC, weakened, self.records), "proposal"), [])

    def test_duplicate_unknown_cross_family_and_reordered_signers_refuse(self):
        cases = [(self.records[0], self.records[0], *self.records[2:]),
                 (replace(self.records[0], signer=b"\xff" * 64), *self.records[1:]),
                 (replace(self.records[0], family=2), *self.records[1:]),
                 (self.records[1], self.records[0], *self.records[2:])]
        for records in cases:
            self.assertEqual(self.refuse(r.encode_frame(r.FULL_MAGIC, self.message, records), "signer"), [])

    def test_exact_trusted_public_key_required(self):
        changed = replace(self.records[0], spki=b"\0" * len(self.records[0].spki))
        self.assertEqual(self.refuse(r.encode_frame(r.FULL_MAGIC, self.message, (changed, *self.records[1:])), "signer"), [])

    def test_wrong_context_and_late_invalid_reach_four_verify_calls(self):
        key = next(k for k in self.config.slh_roster if k.key_id == self.records[-1].signer)
        wrong = self.backend.sign(key, self.message, context=b"another-domain")
        broken = self.records[-1].signature[:-1] + b"\x5a"
        for signature in (wrong, broken):
            records = (*self.records[:-1], replace(self.records[-1], signature=signature))
            calls = self.refuse(r.encode_frame(r.FULL_MAGIC, self.message, records), "signature")
            self.assertEqual(len(calls), 4)

    def test_fully_signed_other_state_and_split_proposals_refuse(self):
        other = replace(self.expected, previous_state=b"\xee" * 64)
        other_message, other_records = r.sign_records(self.config, other, self.backend)
        self.assertEqual(self.refuse(r.encode_frame(r.FULL_MAGIC, other_message, other_records), "proposal"), [])
        split = self.records[:2] + other_records[2:]
        self.assertEqual(len(self.refuse(r.encode_frame(r.FULL_MAGIC, self.message, split), "signature")), 3)

    def test_expected_state_network_genesis_and_roster_are_not_input_selected(self):
        for field, value in (("owner_generation", 8), ("key_epoch", 4), ("sequence", 1001),
                             ("operation_id", b"\x66" * 32), ("payload", b"other payload"),
                             ("valid_from", 101), ("valid_until", 199)):
            self.assertEqual(self.refuse(code="proposal", expected=replace(self.expected, **{field: value})), [])
        for field in ("network", "genesis"):
            self.assertEqual(self.refuse(code="proposal", configuration=replace(self.config, **{field: b"\x77" * 32})), [])
        self.assertEqual(self.refuse(code="expired", expected=replace(self.expected, now_height=201)), [])

    def test_duplicate_trusted_roster_and_boolean_state_rejected(self):
        bad = replace(self.config, ml_roster=(self.config.ml_roster[0],) * 3)
        self.assertEqual(self.refuse(code="trusted-roster", configuration=bad), [])
        self.assertEqual(self.refuse(code="trusted-state", expected=replace(self.expected, sequence=True)), [])

    def test_full_parser_checks_entire_frame_before_any_crypto(self):
        for wire in (self.wire + b"\0", self.wire[:-1], self.wire[:9], b"\0" * (r.MAX_WIRE + 1)):
            self.assertEqual(self.refuse(wire), [])
        wrong_length = self.wire[:4] + struct.pack(">I", r.MAX_MESSAGE + 1) + self.wire[8:]
        self.assertEqual(self.refuse(wrong_length, "size"), [])

    def test_message_ceiling_and_signature_lengths(self):
        with self.assertRaisesRegex(r.Rejected, "size"):
            r.proposal(self.config, replace(self.expected, payload=b"\0" * r.MAX_MESSAGE))
        bad = replace(self.records[-1], signature=self.records[-1].signature[:-1])
        self.assertEqual(self.refuse(r.encode_frame(r.FULL_MAGIC, self.message, (*self.records[:-1], bad)), "size"), [])

    def test_each_measured_expected_operation_sequence_and_message_is_fresh(self):
        expected = [r.fixture_expected(self.config, i) for i in range(r.SAMPLES)]
        self.assertEqual(len({x.operation_id for x in expected}), 64)
        self.assertEqual(len({x.sequence for x in expected}), 64)
        self.assertEqual(len({r.proposal(self.config, x) for x in expected}), 64)

    def test_observers_keep_same_message_separate_stage_times_and_distinct_scope(self):
        ml = r.observe_ml_component(self.config, self.expected, self.backend)
        both = r.observe_and_candidate(self.config, self.expected, self.backend)
        self.assertEqual(ml[0], both[0])
        self.assertFalse(ml[2]["hybrid_policy_satisfied"])
        self.assertTrue(both[2]["hybrid_policy_satisfied"])
        for observed in (ml, both):
            self.assertEqual(set(observed[3]), {"sign_and_encode_ns", "verify_frame_ns"})
            self.assertTrue(all(type(ns) is int and ns >= 0 for ns in observed[3].values()))

    def test_backend_failure_is_not_signature_rejection(self):
        with mock.patch.object(self.backend, "verify", side_effect=r.BackendFailure("tool unavailable")):
            with self.assertRaises(r.BackendFailure):
                r.verify_root_candidate(self.config, self.expected, self.wire, self.backend)

    def test_cli_errors_are_not_counted_as_negative_signature_results(self):
        backend = r.OpenSSL.__new__(r.OpenSSL)
        backend.verifications = 0
        with tempfile.TemporaryDirectory() as temporary:
            backend.temporary = Path(temporary)
            key = self.config.ml_roster[0]
            signature = b"\0" * r.ML.signature_bytes
            for return_value in ((1, b""), (2, b"Signature Verification Failure\n"),
                                 (0, b"unexpected output")):
                with mock.patch.object(backend, "_run", return_value=return_value):
                    with self.assertRaises(r.BackendFailure):
                        backend.verify(key, self.message, signature)
            with mock.patch.object(backend, "_run", return_value=(1, b"Signature Verification Failure\n")):
                self.assertIs(backend.verify(key, self.message, signature), False)

    def test_backend_digest_mismatch_precedes_every_executable_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            executable = directory / "openssl"
            executable.write_bytes(b"never execute this test fixture")
            executable.chmod(0o700)
            journal = r.Journal(directory / "commands.jsonl")
            try:
                with mock.patch.object(r.subprocess, "run") as invoke:
                    with self.assertRaisesRegex(r.BackendFailure, "digest mismatch"):
                        r.OpenSSL(executable, "00" * 32, directory, journal)
                    invoke.assert_not_called()
            finally:
                journal.close()

    def test_no_activation_from_any_returned_observation(self):
        result = r.verify_root_candidate(self.config, self.expected, self.wire, self.backend)
        for field in r.NO_EFFECT:
            self.assertIs(result[field], False)

    def test_bad_backend_run_persists_failure_and_cannot_emit_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "failed-run"
            with mock.patch.object(r, "OpenSSL", side_effect=r.BackendFailure("bad pinned backend")):
                self.assertEqual(r.run(Path("/nonexistent/openssl"), "00" * 32, output), 1)
            import json
            rows = [json.loads(line) for line in (output / "observations.jsonl").read_text().splitlines()]
            self.assertEqual([row["kind"] for row in rows], ["start", "failure"])
            self.assertFalse(rows[-1]["production_qualified"])
            with self.assertRaises(FileExistsError):
                r.run(Path("/nonexistent/openssl"), "00" * 32, output)


if __name__ == "__main__":
    unittest.main()
