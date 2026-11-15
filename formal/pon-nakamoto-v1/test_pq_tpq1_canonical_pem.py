"""PQL10 independent PQL9 PEM source-identity regression, real ML-DSA-65.

Requires an exact pinned source pq_tpq1_native_verify.c.  Not production
cryptographic acceptance; result only means the offline oracle checked bytes.
"""
from __future__ import annotations
import base64
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SRC = HERE / 'pq_tpq1_native_verify.c'
NET = bytes(range(32))
CONTEXT = bytes(range(32,64))
KEY_DOMAIN = b'TRNM/PoN/PQKey/v1\x00'
AUTH_DOMAIN = b'TRNM/PoN/PQAuth/ML-DSA-65/v1\x00'
SPKI_PREFIX = bytes.fromhex('308207b2300b0609608648016503040312038207a100')


def command(*parts):
    return subprocess.run([os.fspath(p) for p in parts], capture_output=True,
                          timeout=20, check=False)


class CanonicalPemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='pql10-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name)
        cls.exe = cls.root/'verify'
        sanitize = os.environ.get('PQL10_SANITIZE') == '1'
        options=['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer'] if sanitize else ['-O2']
        cp = command('cc','-std=c11','-Wall','-Wextra','-Werror','-Wpedantic',
                     *options,SRC,'-lcrypto','-o',cls.exe)
        if cp.returncode:
            raise RuntimeError(cp.stderr.decode(errors='replace'))
        cls.secret = cls.root/'secret.pem'
        cls.pem = cls.root/'pub.pem'
        for args in [('openssl','genpkey','-algorithm','ML-DSA-65','-out',cls.secret),
                     ('openssl','pkey','-in',cls.secret,'-pubout','-out',cls.pem)]:
            cp=command(*args)
            if cp.returncode:
                raise RuntimeError(cp.stderr.decode(errors='replace'))
        cp=command('openssl','pkey','-pubin','-in',cls.pem,'-outform','DER')
        if cp.returncode:
            raise RuntimeError(cp.stderr.decode(errors='replace'))
        cls.der=cp.stdout
        assert len(cls.der)==1974 and cls.der.startswith(SPKI_PREFIX)
        cls.keyid=hashlib.sha256(KEY_DOMAIN+cls.der).digest()
        cls.payload=b'PQL10 strict signer-source identity'
        cls.payloadfile=cls.root/'payload.bin'
        cls.payloadfile.write_bytes(cls.payload)
        digest=hashlib.sha384(AUTH_DOMAIN+b'payload\x00'+len(cls.payload).to_bytes(8,'big')+cls.payload).digest()
        cls.msg=b'TPQ1'+bytes((1,0x65,4,0))+NET+CONTEXT+cls.keyid+(7).to_bytes(8,'big')+(19).to_bytes(8,'big')+(4000).to_bytes(8,'big')+digest
        assert len(cls.msg)==176
        msgfile=cls.root/'unsigned.bin';msgfile.write_bytes(cls.msg)
        sigfile=cls.root/'sig.bin'
        cp=command('openssl','pkeyutl','-sign','-inkey',cls.secret,'-rawin',
                   '-in',msgfile,'-out',sigfile)
        if cp.returncode:
            raise RuntimeError(cp.stderr.decode(errors='replace'))
        sig=sigfile.read_bytes();assert len(sig)==3309
        cls.framefile=cls.root/'frame.bin';cls.framefile.write_bytes(cls.msg+len(sig).to_bytes(2,'big')+sig)

    def probe(self,pem=None,purpose=4):
        return command(self.exe,self.pem if pem is None else pem,
                       self.framefile,self.payloadfile,NET.hex(),CONTEXT.hex(),
                       self.keyid.hex(),str(purpose),'7','19','4000','3999')

    def bad_pem(self,name,data):
        path=self.root/name
        path.write_bytes(data)
        r=self.probe(path)
        self.assertEqual(r.returncode,2,(name,r.stdout,r.stderr))
        self.assertIn(b'PQL9_REJECT',r.stderr)
        self.assertNotIn(b'CRYPTO_VALID',r.stdout)

    def test_canonical_genuine_signature_accepts(self):
        cp=self.probe()
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertEqual(cp.stdout.strip(),b'PQL9_RESEARCH_ONLY_CRYPTO_VALID_NO_AUTHORITY')

    def test_preamble_before_pem_rejected(self):
        self.bad_pem('prefix.pem',b'UNSIGNED HEADER CLAIMS ANOTHER KEY\n'+self.pem.read_bytes())

    def test_der_trailing_bytes_inside_pem_rejected(self):
        encoded=base64.encodebytes(self.der+b'UNSIGNED-TRAILER-DER')
        raw=b'-----BEGIN PUBLIC KEY-----\n'+encoded+b'-----END PUBLIC KEY-----\n'
        self.bad_pem('trailing-der.pem',raw)

    def test_pem_suffix_space_is_not_single_canonical_file(self):
        self.bad_pem('trailing-spaces.pem',self.pem.read_bytes()+b'  \n')

    def test_caller_signed_purpose_still_bound(self):
        cp=self.probe(purpose=5)
        self.assertEqual(cp.returncode,2,cp.stdout)

    def test_extra_key_block_rejected(self):
        self.bad_pem('two-keyblocks.pem',self.pem.read_bytes()+self.pem.read_bytes())

    def test_ed25519_downgrade_rejected(self):
        sec=self.root/'ed-secret.pem';pub=self.root/'ed-public.pem'
        self.assertEqual(command('openssl','genpkey','-algorithm','ED25519','-out',sec).returncode,0)
        self.assertEqual(command('openssl','pkey','-in',sec,'-pubout','-out',pub).returncode,0)
        self.assertEqual(self.probe(pub).returncode,2)


if __name__=='__main__':
    unittest.main(verbosity=2)
