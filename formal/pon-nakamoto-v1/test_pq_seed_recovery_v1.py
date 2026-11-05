"""Public-binding rejection tests, with deliberately invalid proof/key fixtures.

These are parser/context tests, never seed knowledge, PQ signature or recovery
success evidence. No real seed, prover, verifier or migration owner is used.
"""
from dataclasses import fields, replace
import hashlib
import json
import unittest

import pq_seed_recovery_v1 as recovery


def fixture_statement():
    return recovery.SeedRecoveryStatement(
        version=1,
        purpose=recovery.PURPOSE,
        message_hash_profile=recovery.MESSAGE_HASH_PROFILE,
        proof_profile=recovery.PROOF_PROFILE,
        derivation_profile=recovery.DERIVATION_PROFILE,
        pq_algorithm=recovery.PQ_ALGORITHM,
        source_commit=recovery.SOURCE_COMMIT,
        network=b"n" * 32,
        genesis=b"g" * 32,
        crypto_profile_id=b"p" * 32,
        account_id=b"a" * 32,
        old_public_key=b"e" * 32,
        source_snapshot_root=b"s" * 32,
        migration_root=b"m" * 32,
        new_pq_public_key=b"k" * recovery.ML_DSA_65_PUBLIC_KEY_BYTES,
        circuit_source_sha256=recovery.CIRCUIT_SOURCE_SHA256,
        verifier_source_sha256=recovery.VERIFIER_SOURCE_SHA256,
        parameter_source_sha256=recovery.PARAMETER_SOURCE_SHA256,
        parameter_profile_sha256=recovery.PARAMETER_PROFILE_SHA256,
        circuit_artifact_sha256=b"c" * 32,
        verifier_artifact_sha256=b"v" * 32,
        account_generation=7,
        operation_nonce=11,
        not_before=100,
        expires_at=200,
        recovery_state="restricted",
    )


def fixture_context(statement):
    return recovery.ResearchContext(**{
        item.name: getattr(statement, item.name) for item in fields(recovery.ResearchContext)
    })


def fixture_request(statement, proof=b"not a ZK proof"):
    inputs = recovery.prepare_public_inputs(
        statement, expected=fixture_context(statement), now=150,
    )
    return {
        "version": 1,
        "statement": statement.to_mapping(),
        "public_message": inputs.message.hex(),
        "hx": (b"h" * 64).hex(),
        "new_pq_signature": (b"q" * recovery.ML_DSA_65_SIGNATURE_BYTES).hex(),
        "proof_length": len(proof),
        "proof_sha256": hashlib.sha256(proof).hexdigest(),
    }


def header(request):
    return json.dumps(request, separators=(",", ":")).encode("ascii")


class SeedRecoveryPublicInputsTests(unittest.TestCase):
    def setUp(self):
        self.statement = fixture_statement()
        self.expected = fixture_context(self.statement)
        self.proof = b"not a ZK proof"
        self.request = fixture_request(self.statement, self.proof)

    def inspect(self, request=None, proof=None, expected=None, now=150):
        return recovery.inspect_research_request(
            header(self.request if request is None else request),
            self.proof if proof is None else proof,
            expected=self.expected if expected is None else expected,
            now=now,
        )

    def test_public_statement_roundtrip_and_fixed_message_vector(self):
        restored = recovery.statement_from_mapping(self.statement.to_mapping())
        self.assertEqual(restored, self.statement)
        inputs = recovery.prepare_public_inputs(restored, expected=self.expected, now=150)
        self.assertEqual(len(inputs.message), 32)
        self.assertEqual(inputs.message.hex(),
                         "cc1d711888809ecc157b4e20f398b98c1dbaf71d4860627c3b5a551e01657cdf")
        self.assertEqual(recovery.PARAMETER_PROFILE_SHA256.hex(),
                         "29796925cbe04b7dd7d50227eb6b0fb250da451d91a58e508f8cdaed1053ac04")
        # Fixed by an independently spelled-out wire vector in this test below.
        texts = (
            b"legacy-eddsa-seed-recovery-v1", b"trnm-seed-recovery-sha256-v1",
            b"pqchain-ligetron-1.1.0-unqualified-v1", b"rfc8032-ed25519-seed32-v1",
            b"ml-dsa-65-fips204-pure-v1", b"598cdff516c3086487a173d7d9f9af2830e04a32",
        )
        wire = b"TRNM/PoN/SeedRecoveryStatement/v1\x00\x00\x01"
        wire += b"".join(len(text).to_bytes(2, "big") + text for text in texts)
        wire += b"n" * 32 + b"g" * 32 + b"p" * 32 + b"a" * 32 + b"e" * 32
        wire += b"s" * 32 + b"m" * 32 + b"k" * 1952
        wire += bytes.fromhex("ad7914a99a3e3f8bcf647f116da602a65e5e14d1b379ad59a6075523caeb9272")
        wire += bytes.fromhex("714bcac596b193173d67d86cedd97204ed7c88d856e35c03c2913c8c43c50b97")
        wire += bytes.fromhex("99b1aecc916de8fb63e16c0cdb021633be5cc53df05bce1807654baf35c12db3")
        wire += recovery.PARAMETER_PROFILE_SHA256 + b"c" * 32 + b"v" * 32
        wire += b"".join(number.to_bytes(8, "big") for number in (7, 11, 100, 200))
        wire += b"\x01"
        self.assertEqual(inputs.statement, wire)
        self.assertEqual(inputs.message, hashlib.sha256(
            b"TRNM/PoN/SeedRecoveryPublicMessage/v1\x00" + wire).digest())

    def test_all_mutable_statement_fields_change_the_public_message(self):
        baseline = bytes.fromhex(self.request["public_message"])
        changes = {
            "network": b"N" * 32, "genesis": b"G" * 32,
            "crypto_profile_id": b"P" * 32, "account_id": b"A" * 32,
            "old_public_key": b"E" * 32, "source_snapshot_root": b"S" * 32,
            "migration_root": b"M" * 32, "new_pq_public_key": b"K" * 1952,
            "circuit_artifact_sha256": b"C" * 32,
            "verifier_artifact_sha256": b"V" * 32,
            "account_generation": 8, "operation_nonce": 12,
            "not_before": 101, "expires_at": 201, "recovery_state": "frozen",
        }
        for name, value in changes.items():
            with self.subTest(field=name):
                changed = replace(self.statement, **{name: value})
                inputs = recovery.prepare_public_inputs(
                    changed, expected=fixture_context(changed), now=150,
                )
                self.assertNotEqual(inputs.message, baseline)
                request = dict(self.request, statement=changed.to_mapping())
                with self.assertRaisesRegex(recovery.Reject, "public_message binding"):
                    self.inspect(request, expected=fixture_context(changed))

    def test_cross_network_reorg_account_key_nonce_generation_and_artifact_context_refuse(self):
        for item in fields(self.expected):
            original = getattr(self.expected, item.name)
            if type(original) is bytes:
                other = bytes([original[0] ^ 1]) + original[1:]
            elif type(original) is int:
                other = original + 1
            else:
                other = "frozen"
            with self.subTest(field=item.name), self.assertRaisesRegex(
                recovery.Reject, "context mismatch: " + item.name,
            ):
                self.inspect(expected=replace(self.expected, **{item.name: other}))

    def test_context_does_not_coerce_boolean_nonce_or_mutable_byte_arrays(self):
        for name, value in (("operation_nonce", True), ("account_generation", 7.0),
                            ("network", bytearray(self.expected.network))):
            with self.subTest(field=name), self.assertRaises(recovery.Reject):
                self.inspect(expected=replace(self.expected, **{name: value}))

    def test_unknown_source_circuit_verifier_parameters_algorithm_and_profile_refuse(self):
        text_fields = ("purpose", "message_hash_profile", "proof_profile", "derivation_profile",
                       "pq_algorithm", "source_commit")
        byte_fields = ("circuit_source_sha256", "verifier_source_sha256",
                       "parameter_source_sha256", "parameter_profile_sha256")
        for name in text_fields + byte_fields:
            value = b"x" * 32 if name in byte_fields else "unreviewed-profile"
            with self.subTest(field=name), self.assertRaises(recovery.Reject):
                replace(self.statement, **{name: value}).encode()
        for version in (0, 2, True, 1.0, "1"):
            with self.subTest(version=version), self.assertRaises(recovery.Reject):
                replace(self.statement, version=version).encode()

    def test_every_identity_and_key_is_exact_nonzero_immutable_bytes(self):
        for item in fields(self.statement):
            value = getattr(self.statement, item.name)
            if type(value) is not bytes:
                continue
            for invalid in (b"", value[:-1], value + b"\x01", bytes(len(value)),
                            bytearray(value), memoryview(value), value.hex()):
                with self.subTest(field=item.name, invalid_type=type(invalid).__name__), \
                        self.assertRaises(recovery.Reject):
                    replace(self.statement, **{item.name: invalid}).encode()

    def test_positive_u64_identity_and_times_reject_bool_float_overflow(self):
        for name in ("account_generation", "operation_nonce", "not_before", "expires_at"):
            invalid = (-1, True, 1.0, "1", 1 << 64, None)
            if name != "account_generation":
                invalid += (0,)
            for value in invalid:
                with self.subTest(field=name, value=value), self.assertRaises(recovery.Reject):
                    replace(self.statement, **{name: value}).encode()

    def test_zero_generation_restricted_import_is_only_a_current_state_observation(self):
        imported = replace(self.statement, account_generation=0)
        expected = fixture_context(imported)
        result = self.inspect(fixture_request(imported), expected=expected)
        self.assertEqual(result.status, recovery.RESEARCH_STATUS)
        self.assertNotEqual(result.public_inputs.message, bytes.fromhex(self.request["public_message"]))
        with self.assertRaisesRegex(recovery.Reject, "account_generation"):
            self.inspect(fixture_request(imported))
        with self.assertRaisesRegex(recovery.Reject, "account_generation"):
            self.inspect(fixture_request(imported), expected=replace(expected, account_generation=False))
        for value in (False, True, 0.0, -1, 1 << 64):
            with self.subTest(value=value), self.assertRaises(recovery.Reject):
                replace(imported, account_generation=value).encode()

    def test_validity_window_is_bounded_and_expiry_is_exclusive(self):
        self.assertEqual(self.inspect(now=100).status, recovery.RESEARCH_STATUS)
        self.assertEqual(self.inspect(now=199).status, recovery.RESEARCH_STATUS)
        for now in (99, 200, 201, True, 0, -1, 1 << 64, 150.0):
            with self.subTest(now=now), self.assertRaises(recovery.Reject):
                self.inspect(now=now)
        for until in (99, 100, 101 + recovery.MAX_VALIDITY_SECONDS):
            with self.subTest(until=until), self.assertRaises(recovery.Reject):
                replace(self.statement, expires_at=until).encode()
        replace(self.statement, expires_at=100 + recovery.MAX_VALIDITY_SECONDS).encode()

    def test_noncanonical_hex_rejected_without_whitespace_or_case_normalization(self):
        for bad in (self.request["public_message"].upper(),
                    "0x" + self.request["public_message"], "11 " * 32, "z" * 64,
                    "0" * 64, "1" * 63):
            with self.subTest(value=bad), self.assertRaises(recovery.Reject):
                self.inspect(dict(self.request, public_message=bad))
        for name in ("network", "old_public_key", "new_pq_public_key"):
            changed = self.statement.to_mapping()
            changed[name] = " " + changed[name]
            with self.subTest(field=name), self.assertRaises(recovery.Reject):
                recovery.statement_from_mapping(changed)

    def test_missing_extra_nested_or_duplicate_fields_are_not_ignored(self):
        for name in self.request:
            request = dict(self.request)
            del request[name]
            with self.subTest(missing=name), self.assertRaises(recovery.Reject):
                self.inspect(request)
        for name in self.statement.to_mapping():
            value = self.statement.to_mapping()
            del value[name]
            with self.subTest(missing_statement=name), self.assertRaises(recovery.Reject):
                self.inspect(dict(self.request, statement=value))
        for extra in ({"approved": True}, {"verify": True}, {"metadata": {}},
                      {"verifier_url": "https://example.invalid"}):
            with self.subTest(extra=extra), self.assertRaises(recovery.Reject):
                self.inspect(dict(self.request, **extra))
        for raw in (b'{"version":1,' + header(self.request)[1:],
                    header(self.request).replace(b'"network":', b'"network":"11","network":', 1)):
            with self.subTest(duplicate=True), self.assertRaisesRegex(recovery.Reject, "duplicate"):
                recovery.inspect_research_request(raw, self.proof, expected=self.expected, now=150)

    def test_secret_named_fields_are_refused_at_every_object_depth(self):
        for name in ("seed", "private_key", "privateKey", "seed_bytes", "Seed", "mnemonic", "witness"):
            for request in (dict(self.request, **{name: "must-never-be-logged"}),
                            dict(self.request, statement=dict(self.request["statement"],
                                                              **{name: "must-never-be-logged"})),
                            dict(self.request, extra={"nested": {name: "must-never-be-logged"}})):
                with self.subTest(field=name):
                    with self.assertRaises(recovery.Reject) as raised:
                        self.inspect(request)
                    self.assertNotIn("must-never-be-logged", str(raised.exception))
        raw = header(dict(self.request, seed="must-never-be-logged")).replace(b'"seed"', b'"se\\u0065d"')
        with self.assertRaisesRegex(recovery.Reject, "secret input"):
            recovery.inspect_research_request(raw, self.proof, expected=self.expected, now=150)

    def test_malformed_json_nonfinite_and_wrong_envelope_types_refuse(self):
        malformed = (b"", b"{", b"\xff", b"[]", b"null", b"true", b"42",
                     header(self.request) + b"trailing", b"[" * 2000 + b"]" * 2000)
        for raw in malformed:
            with self.subTest(raw_prefix=raw[:15]), self.assertRaises(recovery.Reject):
                recovery.inspect_research_request(raw, self.proof, expected=self.expected, now=150)
        for token in (b"NaN", b"Infinity", b"-Infinity"):
            raw = header(self.request).replace(b'"operation_nonce":11', b'"operation_nonce":' + token)
            with self.subTest(token=token), self.assertRaises(recovery.Reject):
                recovery.inspect_research_request(raw, self.proof, expected=self.expected, now=150)
        for value in (None, [], True, "statement"):
            with self.subTest(value=value), self.assertRaises(recovery.Reject):
                self.inspect(dict(self.request, statement=value))

    def test_header_and_proof_caps_apply_before_decoding_or_hashing(self):
        for raw in (b" " * (recovery.MAX_HEADER_BYTES + 1), bytearray(header(self.request)), "{}"):
            with self.subTest(header_type=type(raw).__name__), \
                    self.assertRaisesRegex(recovery.Reject, "header size/type"):
                recovery.inspect_research_request(raw, self.proof, expected=self.expected, now=150)
        for proof in (b"", b"x" * (recovery.MAX_PROOF_BYTES + 1), bytearray(self.proof), "proof"):
            with self.subTest(proof_type=type(proof).__name__), \
                    self.assertRaisesRegex(recovery.Reject, "proof size/type"):
                recovery.inspect_research_request(b"{", proof, expected=self.expected, now=150)
        bounded = b"x" * recovery.MAX_PROOF_BYTES
        result = self.inspect(fixture_request(self.statement, bounded), proof=bounded)
        self.assertEqual(result.proof_length, recovery.MAX_PROOF_BYTES)
        self.assertEqual(result.status, recovery.RESEARCH_STATUS)

    def test_truncated_replaced_proof_and_false_lengths_refuse(self):
        for proof in (self.proof[:-1], self.proof + b"x", b"x" * len(self.proof)):
            with self.subTest(proof=proof), self.assertRaises(recovery.Reject):
                self.inspect(proof=proof)
        for length in (0, -1, True, float(len(self.proof)), len(self.proof) + 1, 1 << 64):
            with self.subTest(length=length), self.assertRaises(recovery.Reject):
                self.inspect(dict(self.request, proof_length=length))
        with self.assertRaises(recovery.Reject):
            self.inspect(dict(self.request, proof_sha256="11" * 32))

    def test_signature_and_hx_have_strict_public_framing_but_no_crypto_verdict(self):
        for name, length in (("new_pq_signature", recovery.ML_DSA_65_SIGNATURE_BYTES), ("hx", 64)):
            for bad in ("00" * length, "11" * (length - 1), "11" * (length + 1), None):
                with self.subTest(field=name, length=length), self.assertRaises(recovery.Reject):
                    self.inspect(dict(self.request, **{name: bad}))
            changed = self.inspect(dict(self.request, **{name: "ab" * length}))
            self.assertEqual(changed.status, recovery.RESEARCH_STATUS)
            self.assertNotEqual(changed.request_sha256, self.inspect().request_sha256)

    def test_duplicate_observation_is_not_nonce_consumption_or_one_use_recovery(self):
        first, retry = self.inspect(), self.inspect()
        self.assertEqual(first, retry)
        self.assertEqual(first.status, recovery.RESEARCH_STATUS)
        with self.assertRaisesRegex(recovery.Reject, "operation_nonce"):
            self.inspect(expected=replace(self.expected, operation_nonce=12))
        with self.assertRaisesRegex(recovery.Reject, "migration_root"):
            self.inspect(expected=replace(self.expected, migration_root=b"r" * 32))

    def test_fabricated_proof_is_only_an_unverified_diagnostic_never_authority(self):
        result = self.inspect()
        self.assertEqual(result.status, "RESEARCH_ONLY_NO_PROOF_OR_SIGNATURE_VERIFICATION")
        with self.assertRaisesRegex(TypeError, "not an authorization verdict"):
            bool(result)
        with self.assertRaises(TypeError):
            recovery.ResearchDiagnostic(result.public_inputs, result.hx, result.proof_length,
                                        result.proof_sha256, result.request_sha256, status="verified")
        self.assertFalse(hasattr(result, "authorized"))
        self.assertFalse(hasattr(result, "verified"))

    def test_request_version_is_exact_and_research_only(self):
        for value in (0, 2, True, 1.0, "1", None):
            with self.subTest(version=value), self.assertRaises(recovery.Reject):
                self.inspect(dict(self.request, version=value))


if __name__ == "__main__":
    unittest.main()
