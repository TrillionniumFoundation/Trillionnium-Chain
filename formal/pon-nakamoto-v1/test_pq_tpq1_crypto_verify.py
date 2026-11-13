"""Real OpenSSL ML-DSA-65 vs standalone C11 TPQ1 research verifier; no grants."""
import ctypes
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
K = b"TRNM/PoN/PQKey/v1\0"
D = b"TRNM/PoN/PQAuth/ML-DSA-65/v1\0"
PREFIX = bytes.fromhex("308207b2300b0609608648016503040312038207a100")

class Expect(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ubyte * 32) for n in ("network", "context", "signer_key_id")]
    _fields_ += [("purpose", ctypes.c_ubyte)] + [(n, ctypes.c_uint64) for n in
                ("generation", "sequence", "expires_at", "now")]
    _fields_ += [("payload", ctypes.c_void_p), ("payload_len", ctypes.c_size_t)]

def cli(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=20)

class CryptoCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="pql9-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared"]
        if os.environ.get("PQL9_SANITIZE") == "1":
            flags += ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        elif os.environ.get("PQL9_UBSAN") == "1":
            flags += ["-O1", "-g", "-fsanitize=undefined", "-fno-omit-frame-pointer"]
        else:
            flags += ["-O2"]
        cls.dll = cls.root / "verifier.so"
        cli("cc", *flags, str(HERE / "pq_tpq1_crypto_verify.c"), "-o", str(cls.dll), "-lcrypto")
        cls.fun = ctypes.CDLL(str(cls.dll)).trnm_tpq1_crypto_verify_research_v1
        cls.fun.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                            ctypes.c_size_t, ctypes.POINTER(Expect)]
        cls.fun.restype = ctypes.c_int
        cls.keys = []
        for i, alg in enumerate(("ML-DSA-65", "ML-DSA-65", "ED25519")):
            key = cls.root / f"key{i}.pem"; der = cls.root / f"pub{i}.der"
            cli("openssl", "genpkey", "-algorithm", alg, "-out", str(key))
            cli("openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER", "-out", str(der))
            cls.keys.append((key, der.read_bytes()))
        for _, der in cls.keys[:2]:
            assert len(der) == 1974 and der.startswith(PREFIX)

    def fixture(self, signer=0, purpose=4, generation=7, sequence=19, expiry=4000):
        key, der = self.keys[signer]
        payload = b"Base plus all Cell content commitments"
        network, context = bytes(range(1, 33)), bytes(range(33, 65))
        kid = hashlib.sha256(K + der).digest()
        digest = hashlib.sha384(D + b"payload\0" + len(payload).to_bytes(8, "big") + payload).digest()
        statement = (b"TPQ1" + bytes((1, 0x65, purpose, 0)) + network + context + kid
                     + generation.to_bytes(8, "big") + sequence.to_bytes(8, "big")
                     + expiry.to_bytes(8, "big") + digest)
        assert len(statement) == 176
        message = self.root / "statement"; signature = self.root / "signature"
        message.write_bytes(statement)
        cli("openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin",
            "-in", str(message), "-out", str(signature))
        sig = signature.read_bytes(); assert len(sig) == 3309
        return statement + b"\x0c\xed" + sig, der, dict(
            network=network, context=context, kid=kid, purpose=purpose,
            generation=generation, sequence=sequence, expiry=expiry,
            now=3999, payload=payload)

    def verify(self, frame, der, opts=None, **edits):
        o = dict(opts or self.fixture()[2]); o.update(edits)
        payload = o.get("payload")
        b = ctypes.create_string_buffer(payload or b"\0") if payload is not None else None
        e = Expect((ctypes.c_ubyte * 32).from_buffer_copy(o["network"]),
                   (ctypes.c_ubyte * 32).from_buffer_copy(o["context"]),
                   (ctypes.c_ubyte * 32).from_buffer_copy(o["kid"]),
                   o["purpose"], o["generation"], o["sequence"], o["expiry"], o["now"],
                   ctypes.cast(b, ctypes.c_void_p) if b is not None else None,
                   len(payload) if payload is not None else 0)
        f = ctypes.create_string_buffer(frame) if frame is not None else None
        k = ctypes.create_string_buffer(der) if der is not None else None
        return self.fun(f, len(frame) if frame is not None else 0,
                        k, len(der) if der is not None else 0, ctypes.byref(e))

    def test_six_real_signed_purpose_domains(self):
        for p in range(1, 7):
            frame, der, exp = self.fixture(purpose=p)
            self.assertEqual(self.verify(frame, der, exp), 1, p)

    def test_all_176_signed_statement_byte_flips_rejected(self):
        frame, der, exp = self.fixture()
        for i in range(176):
            changed = bytearray(frame); changed[i] ^= 1
            self.assertEqual(self.verify(bytes(changed), der, exp), 0, i)

    def test_all_3309_real_signature_byte_flips_rejected(self):
        frame, der, exp = self.fixture()
        for i in range(178, len(frame)):
            changed = bytearray(frame); changed[i] ^= 1
            self.assertEqual(self.verify(bytes(changed), der, exp), 0, i)

    def test_malformed_lengths_zero_fake_signature_and_ed25519_refused(self):
        frame, der, exp = self.fixture()
        for bad in (b"", frame[:-1], frame + b"X", frame[:178] + bytes(3309),
                    frame[:176] + b"\0\0" + frame[178:]):
            self.assertEqual(self.verify(bad, der, exp), 0)
        self.assertEqual(self.verify(frame, self.keys[2][1], exp), 0)
        self.assertEqual(self.verify(None, der, exp), 0)
        self.assertEqual(self.verify(frame, None, exp), 0)

    def test_spki_der_header_and_key_substitution_refused(self):
        frame, der, exp = self.fixture()
        for i in range(22):
            bad = bytearray(der); bad[i] ^= 1
            self.assertEqual(self.verify(frame, bytes(bad), exp), 0, i)
        for bad in (der[:-1], der + b"\0", self.keys[1][1]):
            self.assertEqual(self.verify(frame, bad, exp), 0)
        other_id = hashlib.sha256(K + self.keys[1][1]).digest()
        edited = bytearray(frame); edited[72:104] = other_id
        self.assertEqual(self.verify(bytes(edited), self.keys[1][1], exp, kid=other_id), 0)

    def test_caller_context_and_cross_domain_replay_refused(self):
        frame, der, exp = self.fixture()
        for field, wrong in (("network", bytes(32)), ("context", bytes(32)),
                             ("kid", bytes(32)), ("purpose", 1), ("payload", b"wrong")):
            self.assertEqual(self.verify(frame, der, exp, **{field: wrong}), 0)

    def test_generation_nonce_expiry_floor_and_boundary(self):
        frame, der, exp = self.fixture()
        self.assertEqual(self.verify(frame, der, exp, now=4000), 1)
        self.assertEqual(self.verify(frame, der, exp, now=4001), 0)
        for field in ("generation", "sequence", "expiry"):
            self.assertEqual(self.verify(frame, der, exp, **{field: 0}), 0)
            self.assertEqual(self.verify(frame, der, exp, **{field: exp[field]+1}), 0)
        maximum = 2**64 - 1
        high, key, o = self.fixture(generation=maximum, sequence=maximum, expiry=maximum)
        self.assertEqual(self.verify(high, key, o, now=maximum), 1)

    def test_buffer_memory_ceiling_without_giant_allocation(self):
        frame, der, _ = self.fixture()
        e = Expect(); e.purpose = 4; e.generation = 7; e.sequence = 19
        e.expires_at = 4000; e.now = 3999
        f = ctypes.create_string_buffer(frame); k = ctypes.create_string_buffer(der)
        e.payload_len = 64*1024*1024+1; e.payload = 1
        self.assertEqual(self.fun(f, len(frame), k, len(der), ctypes.byref(e)), 0)
        e.payload_len = 1; e.payload = None
        self.assertEqual(self.fun(f, len(frame), k, len(der), ctypes.byref(e)), 0)

    def test_independent_openssl_reference_accepts_same_signature(self):
        frame, der, o = self.fixture()
        msg, sig, pub = (self.root/x for x in ("ref-msg", "ref-sig", "ref-pub.pem"))
        msg.write_bytes(frame[:176]); sig.write_bytes(frame[178:])
        cli("openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(self.root/"pub0.der"),
            "-out", str(pub))
        cli("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub),
            "-rawin", "-in", str(msg), "-sigfile", str(sig))
        self.assertEqual(self.verify(frame, der, o), 1)

    def test_attacker_self_pinned_key_is_crypto_valid_but_not_ownership(self):
        frame, attacker_der, attacker_self_chosen = self.fixture(signer=1)
        # Deliberate trust-boundary counterexample: an attacker can sign its OWN
        # frame, so crypto success MUST NOT become release/consensus permission.
        self.assertEqual(self.verify(frame, attacker_der, attacker_self_chosen), 1)
        self.assertEqual(self.verify(frame, self.keys[0][1], attacker_self_chosen), 0)

if __name__ == "__main__":
    unittest.main()
