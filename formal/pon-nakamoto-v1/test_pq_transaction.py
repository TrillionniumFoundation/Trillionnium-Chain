"""Actual OpenSSL ML-DSA-65 QTX1 conformance and adversarial preflight tests.

All signatures use fresh real keys. No fake signature acceptance; no native-chain
or independent post-quantum security acceptance is inferred from these tests.
"""
from dataclasses import replace
from pathlib import Path
import hashlib
import subprocess
import tempfile
import unittest

from pq_envelope import Reject, SIGNED_BYTES, make_unsigned, public_key_id, sign_reference
from pq_transaction import (
    AccountView, HEADER_BYTES, INSTALLED_MAX_TX_BYTES, RESEARCH_MAX_TX_BYTES,
    Transfer, decode_transfer, parse_signed_transfer, preflight_transfer,
    sign_transfer, _context,
)


class PQTransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="trnm-qtx1-")
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        cls.secret, cls.public_path = root / "secret.pem", root / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ML-DSA-65",
                        "-out", str(cls.secret)], check=True, capture_output=True, timeout=15)
        subprocess.run(["openssl", "pkey", "-in", str(cls.secret), "-pubout",
                        "-out", str(cls.public_path)], check=True, capture_output=True, timeout=15)
        cls.pem = cls.public_path.read_bytes()
        cls.network = bytes(range(32))
        cls.sender = bytes(range(32, 64))
        cls.recipient = bytes(range(64, 96))
        cls.transfer = Transfer(cls.network, cls.sender, cls.recipient,
                                2, 7, 5000, 1200, 10000, b"cell settlement")
        cls.raw = sign_transfer(cls.transfer, public_pem=cls.pem, private_key_path=cls.secret)
        cls.account = AccountView(cls.network, cls.sender, public_key_id(cls.pem),
                                  2, 7, 20000, True)

    def check(self, raw=None, **params):
        opts = dict(public_pem=self.pem, account=self.account, now=4000,
                    base_fee=100, byte_fee=1)
        opts.update(params)
        return preflight_transfer(self.raw if raw is None else raw, **opts)

    def test_real_signature_and_transfer_preflight(self):
        v = self.check()
        self.assertEqual(v.encoded_bytes, len(self.raw))
        self.assertEqual(v.required_fee, 100 + len(self.raw))
        self.assertEqual(v.remaining_units, 20000 - 1200 - v.required_fee)
        self.assertEqual(len(v.identity), 48)
        self.assertEqual(parse_signed_transfer(self.raw)[0], self.transfer)

    def test_signed_identity_does_not_use_signature_randomness(self):
        again = sign_transfer(self.transfer, public_pem=self.pem, private_key_path=self.secret)
        self.assertEqual(self.check().identity, self.check(again).identity)
        self.assertEqual(self.check(again).encoded_bytes, len(again))

    def test_real_pq_size_cannot_fit_unmodified_legacy_wire(self):
        self.assertEqual(HEADER_BYTES, 144)
        self.assertEqual(len(self.raw), HEADER_BYTES + len(self.transfer.memo) + SIGNED_BYTES)
        self.assertGreater(len(self.raw), INSTALLED_MAX_TX_BYTES)
        self.assertLessEqual(len(self.raw), RESEARCH_MAX_TX_BYTES)

    def test_change_any_canonical_body_byte_fails(self):
        for i in range(HEADER_BYTES + len(self.transfer.memo)):
            bad = bytearray(self.raw)
            bad[i] ^= 1
            with self.subTest(i=i), self.assertRaises(Reject):
                self.check(bytes(bad))

    def test_replay_account_generation_and_nonce_reject(self):
        for view in (replace(self.account, generation=3),
                     replace(self.account, next_nonce=8),
                     replace(self.account, active=False),
                     replace(self.account, signer_key_id=bytes(32)),
                     replace(self.account, account=bytes(32)),
                     replace(self.account, network=bytes(32))):
            with self.subTest(view=view), self.assertRaises(Reject):
                self.check(account=view)

    def test_true_bool_float_and_out_of_range_rejected(self):
        for changed in ({"generation": True}, {"nonce": 0},
                        {"nonce": 1 << 64}, {"amount": -1},
                        {"amount": 1.2}, {"max_fee": True},
                        {"expires_at": 0}, {"sender": bytes(32)},
                        {"recipient": self.sender}, {"memo": "not bytes"},
                        {"memo": bytes(513)}):
            with self.subTest(changed=changed), self.assertRaises(Reject):
                replace(self.transfer, **changed).encode()
        with self.assertRaises(Reject):
            self.check(base_fee=True)
        with self.assertRaises(Reject):
            self.check(now=-1)
        with self.assertRaises(Reject):
            self.check(account=replace(self.account, available_units=1.5))

    def test_public_key_and_full_signature_are_mandatory(self):
        bad = bytearray(self.raw)
        bad[-1] ^= 1
        with self.assertRaises(Reject):
            self.check(bytes(bad))
        with tempfile.TemporaryDirectory(prefix="qtx1-wrong-pq-") as path:
            private, public = Path(path) / "k", Path(path) / "p"
            subprocess.run(["openssl", "genpkey", "-algorithm", "ML-DSA-65",
                            "-out", str(private)], check=True, capture_output=True, timeout=15)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout",
                            "-out", str(public)], check=True, capture_output=True, timeout=15)
            with self.assertRaises(Reject):
                self.check(public_pem=public.read_bytes())

    def test_cross_purpose_signed_payload_cannot_be_used_for_transactions(self):
        body = self.transfer.encode()
        cross = make_unsigned(purpose=4, network=self.network,
                              context=_context(self.network, self.sender),
                              signer_key_id=public_key_id(self.pem),
                              owner_generation=2, operation_sequence=7,
                              expires_at=5000, payload=body)
        valid_release_signature = sign_reference(cross, private_key_path=self.secret)
        with self.assertRaises(Reject):
            self.check(body + valid_release_signature)

    def test_fee_balance_expiry_and_no_integer_wrap(self):
        for change in (
            {"now": 5001}, {"base_fee": 10001},
            {"base_fee": 1 << 64}, {"byte_fee": 1 << 64},
            {"account": replace(self.account, available_units=1000)},
            {"account": replace(self.account, available_units=(1 << 64) - 1),
             "base_fee": (1 << 64) - 1}
        ):
            with self.subTest(change=change), self.assertRaises(Reject):
                self.check(**change)
        self.assertEqual(self.check(now=5000).encoded_bytes, len(self.raw))

    def test_reject_unexpected_frames_and_memo_size(self):
        for raw in (self.raw[:20], self.raw[:-1], self.raw + b"x",
                    b"ETX1" + self.raw[4:],
                    self.raw[:4] + b"\x02" + self.raw[5:],
                    self.raw[:5] + b"\x02" + self.raw[6:],
                    self.raw[:142] + b"\xff\xff" + self.raw[144:],
                    self.raw[:144] + b"X" + self.raw[144:]):
            with self.subTest(size=len(raw)), self.assertRaises(Reject):
                self.check(raw)

    def test_noncanonical_or_missing_key_binding_reject(self):
        with self.assertRaises(Reject):
            self.check(account=replace(self.account, signer_key_id=b"bad"))
        with self.assertRaises(Reject):
            self.check(account=replace(self.account, active=1))
        with self.assertRaises(Reject):
            self.check(account="fake owner")

    def test_memo_512_bytes_roundtrip_without_signature(self):
        t = replace(self.transfer, memo=bytes(range(256)) * 2)
        self.assertEqual(decode_transfer(t.encode()), t)
        self.assertLessEqual(len(t.encode()) + SIGNED_BYTES, RESEARCH_MAX_TX_BYTES)
        self.assertEqual(hashlib.sha384(t.encode()).digest(),
                         hashlib.sha384(decode_transfer(t.encode()).encode()).digest())


if __name__ == "__main__":
    unittest.main()
