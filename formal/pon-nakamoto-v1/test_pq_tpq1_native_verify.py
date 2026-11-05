"""PQL9 real native OpenSSL/ML-DSA-65 TPQ1 signature and pinning negatives.

HOLD_NO_GO. These are independent byte fixtures built without pq_envelope.py;
cryptographic verification never grants PoN consensus or Hepta authority.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'pq_tpq1_native_verify.c'
NET = bytes(range(32))
CONTEXT = bytes(range(32, 64))
KEY_DOMAIN = b'TRNM/PoN/PQKey/v1\x00'
AUTH_DOMAIN = b'TRNM/PoN/PQAuth/ML-DSA-65/v1\x00'
SPKI_PREFIX = bytes.fromhex('308207b2300b0609608648016503040312038207a100')


def run(*args: str, input: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), input=input, capture_output=True, timeout=20, check=False)


def statement(purpose: int, keyid: bytes, payload: bytes, *, net=NET,
              context=CONTEXT, generation=7, sequence=19, expiry=4000) -> bytes:
    digest = hashlib.sha384(AUTH_DOMAIN + b'payload\x00' + len(payload).to_bytes(8, 'big') + payload).digest()
    return (b'TPQ1' + bytes((1, 0x65, purpose, 0)) + net + context + keyid
            + generation.to_bytes(8, 'big') + sequence.to_bytes(8, 'big')
            + expiry.to_bytes(8, 'big') + digest)


class Pql9NativeCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='trnm-pql9-real-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.binary = cls.root / 'pql9-verify'
        cmd = ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
               os.fspath(SOURCE), '-lcrypto', '-o', os.fspath(cls.binary)]
        result = run(*cmd)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace'))
        cls.priv = cls.root / 'private.pem'
        cls.pub = cls.root / 'public.pem'
        cls.payload_path = cls.root / 'payload.bin'
        cls.frame_path = cls.root / 'frame.tpq'
        for cmd in (["openssl", "genpkey", "-algorithm", "ML-DSA-65", "-out", str(cls.priv)],
                    ["openssl", "pkey", "-in", str(cls.priv), "-pubout", "-out", str(cls.pub)]):
            result = run(*cmd)
            if result.returncode:
                raise RuntimeError(result.stderr.decode(errors='replace'))
        der = run('openssl', 'pkey', '-pubin', '-in', str(cls.pub), '-outform', 'DER').stdout
        assert len(der) == 1974 and der.startswith(SPKI_PREFIX)
        cls.kid = hashlib.sha256(KEY_DOMAIN + der).digest()
        cls.payload = b'public Cell release manifest hash and consent'
        cls.write(cls.payload, cls.sign(4, cls.payload))

    @classmethod
    def sign(cls, purpose: int, payload: bytes, *, keyid=None,
             net=NET, context=CONTEXT, generation=7, sequence=19, expiry=4000) -> bytes:
        msg = statement(purpose, cls.kid if keyid is None else keyid, payload, net=net,
                        context=context, generation=generation, sequence=sequence, expiry=expiry)
        assert len(msg) == 176
        path = cls.root / 'unsigned.bin'
        sig = cls.root / 'signature.bin'
        path.write_bytes(msg)
        result = run('openssl', 'pkeyutl', '-sign', '-inkey', str(cls.priv), '-rawin',
                     '-in', str(path), '-out', str(sig))
        assert result.returncode == 0, result.stderr
        data = sig.read_bytes()
        assert len(data) == 3309
        return msg + len(data).to_bytes(2, 'big') + data

    @classmethod
    def write(cls, payload: bytes, frame: bytes) -> None:
        cls.payload_path.write_bytes(payload)
        cls.frame_path.write_bytes(frame)

    def probe(self, *, frame=None, payload=None, pub=None, net=NET, context=CONTEXT,
              kid=None, purpose=4, generation=7, sequence=19, expiry=4000, now=3999,
              frame_path=None, payload_path=None):
        if frame is not None or payload is not None:
            self.write(self.payload if payload is None else payload,
                       self.sign(4,self.payload) if frame is None else frame)
        argv = [str(self.binary), str(self.pub if pub is None else pub),
                str(self.frame_path if frame_path is None else frame_path),
                str(self.payload_path if payload_path is None else payload_path),
                net.hex() if isinstance(net, bytes) else str(net),
                context.hex() if isinstance(context, bytes) else str(context),
                (self.kid if kid is None else kid).hex() if not isinstance(kid, str) else kid,
                str(purpose), str(generation), str(sequence), str(expiry), str(now)]
        return run(*argv)

    def reject(self, **kwargs):
        result = self.probe(**kwargs)
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertIn(b'PQL9_REJECT', result.stderr)
        self.assertNotIn(b'CRYPTO_VALID', result.stdout)

    def test_real_all_six_purposes_and_cross_language_digest(self):
        for purpose in range(1,7):
            with self.subTest(purpose=purpose):
                frame = self.sign(purpose, self.payload)
                self.write(self.payload, frame)
                result = self.probe(purpose=purpose)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(),b'PQL9_RESEARCH_ONLY_CRYPTO_VALID_NO_AUTHORITY')
                self.reject(purpose=(purpose%6)+1)
        # Published independent Python stable digest, not an authority proof.
        self.assertEqual(hashlib.sha384(AUTH_DOMAIN+b'payload\x00'+
                                        len(self.payload).to_bytes(8,'big')+self.payload).hexdigest(),
                         '2ceb9c0f29a40392386f5644c998adedaf5ae91f46b2faff977a66ad8153cbfe2bc62af16fd4125e7f516fc09a1382e4')

    def test_every_signed_statement_byte_and_fake_signature_rejects(self):
        good = self.sign(4, self.payload)
        for offset in range(176):
            fake=bytearray(good);fake[offset]^=1
            with self.subTest(byte=offset):
                self.reject(frame=bytes(fake),payload=self.payload)
        fake=bytearray(good);fake[178]^=1
        self.reject(frame=bytes(fake))
        self.reject(frame=good[:178]+bytes(3309))
        self.reject(frame=good[:-1])
        self.reject(frame=good+b'X')
        fake=bytearray(good);fake[176]^=1
        self.reject(frame=bytes(fake))
        # same detached bytes without the original signed payload must fail.
        self.reject(frame=good,payload=self.payload+b'changed')

    def test_caller_pin_replay_time_and_downgrade_reject(self):
        good = self.sign(4,self.payload)
        self.write(self.payload,good)
        self.reject(net=bytes(32))
        self.reject(context=bytes(32))
        self.reject(kid=bytes(32))
        self.reject(generation=8)
        self.reject(sequence=20)
        self.reject(expiry=3999)
        self.reject(now=4001)
        self.reject(now='04000')
        self.reject(now='-1')
        self.reject(sequence='18446744073709551616')
        self.reject(purpose=0)
        self.reject(purpose=7)
        self.reject(kid='AA'*32)
        bad = bytearray(good);bad[5] = 0x19
        self.reject(frame=bytes(bad))
        self.write(self.payload,good)
        self.assertEqual(self.probe().returncode,0)

    def test_real_other_signer_and_classical_key_reject(self):
        good=self.sign(4,self.payload)
        self.write(self.payload,good)
        second_priv=self.root/'other-sec.pem'
        second_pub=self.root/'other-pub.pem'
        ed_priv=self.root/'ed-sec.pem'
        ed_pub=self.root/'ed-pub.pem'
        for algo,secret,public in [('ML-DSA-65',second_priv,second_pub),('ED25519',ed_priv,ed_pub)]:
            for cmd in (["openssl","genpkey","-algorithm",algo,"-out",str(secret)],
                        ["openssl","pkey","-in",str(secret),"-pubout","-out",str(public)]):
                result=run(*cmd)
                self.assertEqual(result.returncode,0,result.stderr)
            self.reject(pub=public)
        trailing=self.root/'public-extra.pem'
        trailing.write_bytes(self.pub.read_bytes()+b'\nMALICIOUS EXTRA KEY\n')
        self.reject(pub=trailing)

    def test_bounded_regular_file_no_symlink_and_empty_payload(self):
        empty=self.sign(4,b'')
        self.write(b'',empty)
        self.assertEqual(self.probe().returncode,0)
        self.write(self.payload,self.sign(4,self.payload))
        link=self.root/'frame-link.tpq'
        link.symlink_to(self.frame_path)
        self.reject(frame_path=link)
        bad=self.root/'bad-frame.bin'
        bad.write_bytes(bytes(3488))
        self.reject(frame_path=bad)
        emptyfile=self.root/'missing-payload.bin'
        emptyfile.write_bytes(b'')
        self.reject(payload_path=self.root/'non-existent-payload')


if __name__=='__main__':
    unittest.main()
