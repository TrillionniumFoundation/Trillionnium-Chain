"""PQL8: independently check the native TPQ1 SPKI byte/identity contract.

Offline test only. This validates DER layout and key-ID derivation against OpenSSL
real ML-DSA-65 keys, NOT Rust execution, possession, signature acceptance, consensus,
or any production quantum-resistance claim.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

KEY_DOMAIN = b"TRNM/PoN/PQKey/v1\x00"
# DER SubjectPublicKeyInfo: SEQUENCE(1970) + SEQUENCE(OID ML-DSA-65) + BITSTRING(1953).
SPKI_PREFIX = bytes.fromhex("308207b2300b0609608648016503040312038207a100")
PUBLIC_KEY_BYTES = 1952
SPKI_BYTES = len(SPKI_PREFIX) + PUBLIC_KEY_BYTES


def spki_key_id(pinned_spki: bytes) -> bytes:
    """Read-only independent Python byte oracle for the unverified Rust preflight."""
    if type(pinned_spki) is not bytes or len(pinned_spki) != SPKI_BYTES:
        raise ValueError("wrong SPKI byte length")
    if not pinned_spki.startswith(SPKI_PREFIX):
        raise ValueError("noncanonical/wrong algorithm SPKI")
    return hashlib.sha256(KEY_DOMAIN + pinned_spki).digest()


class Pql8NativeSpkiContractTests(unittest.TestCase):
    def test_frozen_deterministic_identity_and_der_structure(self):
        self.assertEqual(SPKI_BYTES, 1974)
        fixture = SPKI_PREFIX + bytes([0x42]) * PUBLIC_KEY_BYTES
        self.assertEqual(spki_key_id(fixture).hex(),
                         "afc295d8a2307875be792894d57b195f2f9513ede37ac98162232d2a09ca0989")
        # Fixture checks framing only. No claim this is a valid ML-DSA public key.

    def test_strict_bad_algorithm_lengths_and_suffixes(self):
        good = SPKI_PREFIX + bytes([0x42]) * PUBLIC_KEY_BYTES
        variants = [good[:-1], good + b"\x00", good + b"\x30\x00",
                    b"\x00" + good[1:], good[:3] + b"\xb1" + good[4:],
                    good[:15] + bytes([good[15] ^ 1]) + good[16:],
                    good[:20] + b"\xa0" + good[21:],
                    good[:21] + b"\x01" + good[22:]]
        for altered in variants:
            with self.subTest(length=len(altered), header=altered[:24].hex()):
                with self.assertRaises(ValueError):
                    spki_key_id(altered)

    def test_real_openssl_mldsa_key_and_ed25519_downgrade(self):
        with tempfile.TemporaryDirectory(prefix="trnm-pql8-spki-") as root:
            base = Path(root)
            for algorithm in ("ML-DSA-65", "ED25519"):
                private = base / f"{algorithm}.pem"
                public = base / f"{algorithm}.der"
                subprocess.run(["openssl", "genpkey", "-algorithm", algorithm,
                                "-out", str(private)], check=True,
                               capture_output=True, timeout=15)
                subprocess.run(["openssl", "pkey", "-in", str(private),
                                "-pubout", "-outform", "DER", "-out", str(public)],
                               check=True, capture_output=True, timeout=15)
                der = public.read_bytes()
                if algorithm == "ML-DSA-65":
                    self.assertEqual(len(der), SPKI_BYTES)
                    self.assertTrue(der.startswith(SPKI_PREFIX))
                    self.assertEqual(spki_key_id(der), hashlib.sha256(KEY_DOMAIN + der).digest())
                else:
                    with self.assertRaises(ValueError):
                        spki_key_id(der)


if __name__ == "__main__":
    unittest.main()
