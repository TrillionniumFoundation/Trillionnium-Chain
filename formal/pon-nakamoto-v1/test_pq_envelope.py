"""Real OpenSSL 3.5+ ML-DSA-65 negative/positive tests; no mock signatures."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from pq_openssl_backend import run as run_pinned_openssl

from pq_envelope import (
    MAX_PAYLOAD_BYTES, ML_DSA_65_SIGNATURE_BYTES, Reject, SIGNED_BYTES,
    UNSIGNED_BYTES, attach_signature, make_unsigned, parse_signed,
    parse_unsigned, public_key_id, sign_reference, verify_reference,
)


class PureMLDSA65WireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="trnm-pq-vectors-")
        cls.addClassCleanup(cls.temp.cleanup)
        d = Path(cls.temp.name)
        cls.secret, cls.public = d / "secret.pem", d / "public.pem"
        run_pinned_openssl(["genpkey", "-algorithm", "ML-DSA-65", "-out", str(cls.secret)])
        run_pinned_openssl(["pkey", "-in", str(cls.secret), "-pubout", "-out", str(cls.public)])
        cls.pem = cls.public.read_bytes()
        cls.network = bytes(range(32))
        cls.context = bytes(range(32, 64))
        cls.payload = b"public Cell release manifest hash and consent"  # non-private fixture
        cls.purpose = 4
        cls.generation = 7
        cls.sequence = 19
        cls.expiry = 4000
        cls.u = make_unsigned(purpose=cls.purpose, network=cls.network, context=cls.context,
                              signer_key_id=public_key_id(cls.pem), owner_generation=cls.generation,
                              operation_sequence=cls.sequence, expires_at=cls.expiry, payload=cls.payload)
        cls.frame = sign_reference(cls.u, private_key_path=cls.secret)

    def arguments(self, **updates):
        result = dict(frame=self.frame, payload=self.payload, public_pem=self.pem,
                      expected_network=self.network, expected_context=self.context,
                      expected_purpose=self.purpose, expected_generation=self.generation,
                      expected_sequence=self.sequence, now=3900)
        result.update(updates)
        return result

    def test_stable_cross_language_unsigned_vector(self):
        # Independent of randomized ML-DSA signature/key generation.
        vector = make_unsigned(purpose=4, network=bytes(range(32)),
                               context=bytes(range(32, 64)),
                               signer_key_id=bytes([0x33] * 32),
                               owner_generation=7, operation_sequence=19,
                               expires_at=4000,
                               payload=b"public Cell release manifest hash and consent")
        self.assertEqual(
            hashlib.sha256(vector.encode()).hexdigest(),
            "e7ab1d942db272e5ac779abdfb0ed9fa5fc2318e059d439a33ca3e09773deae0",
        )
        self.assertEqual(parse_unsigned(vector.encode()), vector)

    def test_actual_mldsa65_sign_and_verify_exact_size(self):
        self.assertEqual(len(self.u.encode()), UNSIGNED_BYTES)
        self.assertEqual(len(self.frame), SIGNED_BYTES)
        self.assertEqual(SIGNED_BYTES, 3487)
        parsed, sig = parse_signed(self.frame)
        self.assertEqual(len(sig), ML_DSA_65_SIGNATURE_BYTES)
        self.assertEqual(parsed, self.u)
        self.assertEqual(verify_reference(**self.arguments()), self.u)
        self.assertGreater(len(self.frame), 2048)  # existing tx cap, cannot enable on old wire

    def test_context_purpose_generation_sequence_payload_expiration_fail_closed(self):
        for changed in (
            {"expected_network": bytes(32)},
            {"expected_context": bytes(32)},
            {"expected_purpose": 3},
            {"expected_generation": 8},
            {"expected_sequence": 20},
            {"payload": self.payload + b"!"},
            {"now": 4001},
        ):
            with self.subTest(changed=changed), self.assertRaises(Reject):
                verify_reference(**self.arguments(**changed))
        self.assertEqual(verify_reference(**self.arguments(now=4000)), self.u)

    def test_each_signed_header_field_mutation_fails_without_legacy_fallback(self):
        # Mutation of every byte in the full 176-byte statement except known impossible
        # encodings must either reject parsing or fail real ML-DSA verification.
        for i in range(UNSIGNED_BYTES):
            mutated = bytearray(self.frame)
            mutated[i] ^= 1
            with self.subTest(i=i), self.assertRaises(Reject):
                verify_reference(**self.arguments(frame=bytes(mutated)))

    def test_bad_signature_rejects_even_if_statement_is_exact(self):
        last = bytearray(self.frame)
        last[-1] ^= 1
        with self.assertRaises(Reject):
            verify_reference(**self.arguments(frame=bytes(last)))

    def test_wrong_key_rejects_signature(self):
        with tempfile.TemporaryDirectory(prefix="trnm-other-") as root:
            secret, public = Path(root) / "key", Path(root) / "pub"
            run_pinned_openssl(["genpkey", "-algorithm", "ML-DSA-65", "-out", str(secret)])
            run_pinned_openssl(["pkey", "-in", str(secret), "-pubout", "-out", str(public)])
            with self.assertRaises(Reject):
                verify_reference(**self.arguments(public_pem=public.read_bytes()))

    def test_algorithm_downgrade_and_wrong_public_key_type_reject(self):
        wrong = bytearray(self.frame)
        wrong[5] = 0  # simulated unknown/legacy algorithm id
        with self.assertRaises(Reject):
            parse_signed(bytes(wrong))
        with tempfile.TemporaryDirectory(prefix="trnm-ed-") as root:
            k, p = Path(root) / "key", Path(root) / "pub"
            run_pinned_openssl(["genpkey", "-algorithm", "Ed25519", "-out", str(k)])
            run_pinned_openssl(["pkey", "-in", str(k), "-pubout", "-out", str(p)])
            with self.assertRaises(Reject):
                public_key_id(p.read_bytes())

    def test_canonical_signed_length_reserved_and_zero_lifetime_reject(self):
        for frame in (self.frame[:-1], self.frame + b"x", self.frame[:UNSIGNED_BYTES]
                      + b"\x00\x00" + self.frame[UNSIGNED_BYTES + 2:]):
            with self.assertRaises(Reject):
                parse_signed(frame)
        wrong = bytearray(self.frame)
        wrong[7] = 1  # reserved != 0
        with self.assertRaises(Reject):
            parse_signed(bytes(wrong))
        with self.assertRaises(Reject):
            make_unsigned(purpose=1, network=self.network, context=self.context,
                          signer_key_id=public_key_id(self.pem), owner_generation=0,
                          operation_sequence=1, expires_at=1, payload=b"")

    def test_strict_python_integer_size_and_purpose(self):
        for generation in (True, -1, 1 << 64, 1.0):
            with self.subTest(generation=generation), self.assertRaises(Reject):
                make_unsigned(purpose=1, network=self.network, context=self.context,
                              signer_key_id=public_key_id(self.pem), owner_generation=generation,
                              operation_sequence=1, expires_at=1, payload=b"")
        with self.assertRaises(Reject):
            make_unsigned(purpose=255, network=self.network, context=self.context,
                          signer_key_id=public_key_id(self.pem), owner_generation=1,
                          operation_sequence=1, expires_at=1, payload=b"")
        with self.assertRaises(Reject):
            make_unsigned(purpose=1, network=self.network, context=self.context,
                          signer_key_id=public_key_id(self.pem), owner_generation=1,
                          operation_sequence=1, expires_at=1, payload=b"x" * (MAX_PAYLOAD_BYTES + 1))


if __name__ == "__main__":
    unittest.main()
