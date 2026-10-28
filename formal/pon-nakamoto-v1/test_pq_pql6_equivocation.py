"""True ML-DSA-65 PQL5 double-sign evidence, adversarial non-authorization tests."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from pq_openssl_backend import run as run_pinned_openssl
from pq_pql6_equivocation import (
    Reject, PQL5_PREFIX, PQL5_UNSIGNED, PQL6_LEN,
    _public_key, build_evidence, verify_evidence,
)


def run(*argv):
    if not argv or argv[0] != "openssl":
        raise AssertionError("fixture must use the declared OpenSSL backend")
    return run_pinned_openssl([str(arg) for arg in argv[1:]])


class PQL6EquivocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="pql6-real-ml-dsa-")
        cls.addClassCleanup(cls.temp.cleanup)
        p = Path(cls.temp.name)
        cls.secret = p / "witness.key"
        cls.pubpath = p / "witness.pem"
        cls.foreign = p / "foreign.key"
        cls.foreign_pub = p / "foreign.pem"
        cls.ed_pub = p / "classical.pem"
        run("openssl", "genpkey", "-algorithm", "ML-DSA-65", "-out", cls.secret)
        run("openssl", "pkey", "-in", cls.secret, "-pubout", "-out", cls.pubpath)
        run("openssl", "genpkey", "-algorithm", "ML-DSA-65", "-out", cls.foreign)
        run("openssl", "pkey", "-in", cls.foreign, "-pubout", "-out", cls.foreign_pub)
        classical = p / "classical.key"
        run("openssl", "genpkey", "-algorithm", "ED25519", "-out", classical)
        run("openssl", "pkey", "-in", classical, "-pubout", "-out", cls.ed_pub)
        cls.pem = cls.pubpath.read_bytes()
        cls.kid, _ = _public_key(cls.pem)
        cls.network = bytes(range(1, 33))
        cls.root = bytes([0xA1]) * 48
        cls.genesis = bytes([0xB2]) * 48
        cls.a = bytes([0xC3]) * 48
        cls.b = bytes([0xD4]) * 48

    def sign(self, *, frontier=None, seq=23, challenge=None, key=None, kid=None,
             network=None, root=None, genesis=None, observed=1000, expiry=None):
        header = (b"PQL5\x01" + (self.kid if kid is None else kid)
                  + (self.network if network is None else network)
                  + (self.root if root is None else root)
                  + (self.genesis if genesis is None else genesis)
                  + seq.to_bytes(8, "big") + (self.a if frontier is None else frontier)
                  + (bytes([0x44]) * 32 if challenge is None else challenge)
                  + observed.to_bytes(8, "big")
                  + (observed + 30 if expiry is None else expiry).to_bytes(8, "big"))
        self.assertEqual(len(header), PQL5_UNSIGNED)
        with tempfile.TemporaryDirectory(prefix="pql6-sign-") as d:
            m, s = Path(d) / "msg", Path(d) / "sig"
            m.write_bytes(PQL5_PREFIX + header)
            run("openssl", "pkeyutl", "-sign", "-inkey", self.secret if key is None else key,
                "-rawin", "-in", m, "-out", s)
            signature = s.read_bytes()
            self.assertEqual(len(signature), 3309)
            return header + (3309).to_bytes(2, "big") + signature

    def kw(self):
        return dict(public_pem=self.pem, expected_signer_key_id=self.kid,
                    network=self.network, import_root=self.root, genesis=self.genesis)

    def pair(self):
        return (self.sign(frontier=self.a, challenge=b"a" * 32),
                self.sign(frontier=self.b, challenge=b"b" * 32))

    def test_real_pq_double_sign_yields_non_authoritative_evidence(self):
        a, b = self.pair()
        e = build_evidence(a, b, **self.kw())
        self.assertEqual(len(e), PQL6_LEN)
        o = verify_evidence(e, **self.kw())
        self.assertEqual(o.sequence, 23)
        self.assertEqual(set((o.first_frontier, o.second_frontier)), {self.a, self.b})
        self.assertEqual(o.evidence_id, e[-48:])
        self.assertFalse(hasattr(o, "authority"))
        self.assertFalse(hasattr(o, "rollback_prevented"))
        self.assertEqual(build_evidence(b, a, **self.kw()), e)

    def test_same_head_different_challenge_is_not_equivocation(self):
        a = self.sign(frontier=self.a, challenge=b"1" * 32)
        b = self.sign(frontier=self.a, challenge=b"2" * 32)
        with self.assertRaises(Reject):
            build_evidence(a, b, **self.kw())

    def test_different_sequences_are_not_equivocation(self):
        a = self.sign(seq=23, frontier=self.a)
        b = self.sign(seq=24, frontier=self.b)
        with self.assertRaises(Reject):
            build_evidence(a, b, **self.kw())

    def test_cross_chain_import_genesis_mismatch_reject(self):
        a = self.sign(frontier=self.a)
        for change in ({"network": b"x" * 32}, {"root": b"y" * 48},
                       {"genesis": b"z" * 48}):
            with self.subTest(change=change), self.assertRaises(Reject):
                build_evidence(a, self.sign(frontier=self.b, **change), **self.kw())

    def test_foreign_key_and_classical_ed25519_downgrade_reject(self):
        a, b = self.pair()
        foreign_id, _ = _public_key(self.foreign_pub.read_bytes())
        for change in (dict(public_pem=self.foreign_pub.read_bytes()),
                       dict(expected_signer_key_id=foreign_id),
                       dict(public_pem=self.ed_pub.read_bytes()),
                       dict(public_pem=self.pem + b"junk")):
            with self.subTest(change=list(change)), self.assertRaises(Reject):
                build_evidence(a, b, **(self.kw() | change))
        with self.assertRaises(Reject):
            build_evidence(a, self.sign(frontier=self.b, key=self.foreign), **self.kw())

    def test_every_269_byte_header_mutation_refused(self):
        a, b = self.pair()
        for i in range(PQL5_UNSIGNED):
            changed = bytearray(b)
            changed[i] ^= 1
            with self.subTest(byte=i), self.assertRaises(Reject):
                build_evidence(a, bytes(changed), **self.kw())

    def test_invalid_time_and_empty_frontier_not_signed_evidence(self):
        a = self.sign(frontier=self.a)
        for b in (self.sign(frontier=self.b, expiry=1090),
                  self.sign(frontier=bytes(48)),
                  self.sign(frontier=self.b, seq=0),
                  self.sign(frontier=self.b, challenge=bytes(32))):
            with self.subTest(case=b[:20]), self.assertRaises(Reject):
                build_evidence(a, b, **self.kw())

    def test_exact_envelope_truncation_reorder_and_tamper(self):
        a, b = self.pair()
        e = build_evidence(a, b, **self.kw())
        for bad in (e[:-1], e + b"x", b"PQL7\x01" + e[5:],
                    e[:-1] + bytes([e[-1] ^ 1]),
                    e[:37] + e[37 + 3580:37 + 7160] + e[37:37 + 3580] + e[-48:],
                    e[:37 + 3580] + bytes([e[37 + 3580] ^ 1]) + e[38 + 3580:]):
            with self.subTest(len=len(bad)), self.assertRaises(Reject):
                verify_evidence(bad, **self.kw())

    def test_wrong_external_anchor_must_fail(self):
        e = build_evidence(*self.pair(), **self.kw())
        for change in (dict(network=b"x" * 32), dict(import_root=b"z" * 48),
                       dict(genesis=b"m" * 48), dict(expected_signer_key_id=b"n" * 32)):
            with self.subTest(k=list(change)), self.assertRaises(Reject):
                verify_evidence(e, **(self.kw() | change))

    def test_two_witnesses_signing_same_older_head_is_not_double_sign_evidence(self):
        # Important bound: a colluding majority can return the same old head without
        # any cryptographically contradictory PQL5 statements. PQL6 does NOT stop it.
        old = self.sign(frontier=self.a, seq=10)
        newer = self.sign(frontier=self.a, seq=10, challenge=b"c" * 32)
        with self.assertRaises(Reject):
            build_evidence(old, newer, **self.kw())


if __name__ == "__main__":
    unittest.main()
