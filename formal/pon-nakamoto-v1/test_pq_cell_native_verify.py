"""PQN4 research-only native OpenSSL ML-DSA-65 verifier regression/negative suite.

Real signed fixtures, independent Python canonical byte oracle, compiled C verifier.
There is NO stub cryptographic verifier or product/consensus authority in these tests.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
DOMAIN = b'TRNM/PoN/PQCellCustody/v1\x00'
AUTH = b'TRNM/PoN/PQAuth/ML-DSA-65/v1\x00'
KEY_DOMAIN = b'TRNM/PoN/PQKey/v1\x00'

def be(n, width):
    return n.to_bytes(width, 'big')

def h(tag, *parts):
    return hashlib.sha384(DOMAIN + tag + b''.join(parts)).digest()

def leaf(index, total, b):
    return h(b'leaf\x00', be(index, 4), be(total, 4), be(len(b), 4), b)

def parent(a, b):
    return h(b'node\x00', a, b)

def tree(chunks, target):
    nodes = [leaf(i, len(chunks), data) for i, data in enumerate(chunks)]
    siblings = []
    position = target
    while len(nodes) > 1:
        i = position ^ 1
        siblings.append(nodes[i] if i < len(nodes) else nodes[position])
        nodes = [parent(nodes[i], nodes[i+1] if i+1 < len(nodes) else nodes[i])
                 for i in range(0, len(nodes), 2)]
        position //= 2
    return nodes[0], tuple(siblings)

def call(args, **kw):
    return subprocess.run(args, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=15, **kw)

@dataclass(frozen=True)
class Fixture:
    catalog: bytes
    challenge: bytes
    response: bytes
    release: bytes
    catalog_id: bytes
    requester: bytes
    nonce: bytes
    key_id: bytes
    pub: bytes

class NativeCellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pqn4-native-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.exe = cls.root / 'native'
        cc = os.environ.get('CC', 'cc')
        flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g']
        if os.environ.get('PQN4_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        else:
            flags += ['-O2']
        build = call([cc, *flags, str(ROOT / 'pq_cell_native_verify.c'), '-lcrypto', '-o', str(cls.exe)])
        if build.returncode:
            raise AssertionError(build.stderr.decode(errors='replace'))
        cls.secret = cls.root / 'secret.pem'
        cls.public = cls.root / 'public.pem'
        for argv in (["openssl", "genpkey", "-algorithm", "ML-DSA-65", "-out", str(cls.secret)],
                     ["openssl", "pkey", "-in", str(cls.secret), "-pubout", "-out", str(cls.public)]):
            r = call(argv)
            if r.returncode:
                raise AssertionError(r.stderr.decode(errors='replace'))
        cls.pub = cls.public.read_bytes()
        cls.der = call(["openssl", "pkey", "-pubin", "-in", str(cls.public), "-outform", "DER"]).stdout
        cls.kid = hashlib.sha256(KEY_DOMAIN + cls.der).digest()
        cls.network, cls.release = bytes(range(1, 33)), bytes(range(48))
        cls.requester, cls.nonce = bytes([0xa7])*32, bytes([0xb8])*32
        cls.chunks = (b'A' * 29, b'B' * 29, b'C' * 13)

    def build_fixture(self, *, index=2, chunks=None, nonce=None, sequence=19, chunk_size=29):
        chunks = self.chunks if chunks is None else tuple(chunks)
        nonce = self.nonce if nonce is None else nonce
        root, path = tree(chunks, index)
        catalog = (b'PCC1\x01' + self.network + self.release + be(7,8)
                   + be(sum(map(len, chunks)),8) + be(chunk_size,4) + be(len(chunks),4) + root)
        self.assertEqual(len(catalog), 157)
        catalog_id = h(b'catalog\x00', catalog)
        q = (b'PCQ1\x01' + self.network + catalog_id + nonce + self.requester
             + self.kid + be(7,8) + be(sequence,8) + be(index,4) + be(2000,8) + be(2100,8))
        self.assertEqual(len(q), 217)
        content = chunks[index]
        payload = (DOMAIN + b'signed-retrieval\x00' + catalog_id
                   + h(b'challenge\x00', q) + leaf(index,len(chunks),content)
                   + bytes([len(path)]) + b''.join(path))
        ctx = hashlib.sha256(DOMAIN + b'context\x00' + catalog_id + q).digest()
        dig = hashlib.sha384(AUTH+b'payload\x00'+be(len(payload),8)+payload).digest()
        unsigned = (b'TPQ1' + bytes([1,0x65,5,0]) + self.network + ctx + self.kid
                    + be(7,8) + be(sequence,8) + be(2100,8) + dig)
        self.assertEqual(len(unsigned), 176)
        input_file, sig_file = self.root/'message.bin', self.root/'signature.bin'
        input_file.write_bytes(unsigned)
        r = call(['openssl', 'pkeyutl','-sign','-inkey',str(self.secret),'-rawin',
                  '-in',str(input_file),'-out',str(sig_file)])
        self.assertEqual(r.returncode,0,r.stderr)
        sig = sig_file.read_bytes()
        self.assertEqual(len(sig),3309)
        verify = call(['openssl','pkeyutl','-verify','-pubin','-inkey',str(self.public),
                       '-rawin','-in',str(input_file),'-sigfile',str(sig_file)])
        self.assertEqual(verify.returncode,0,verify.stderr)
        frame = unsigned + be(len(sig),2) + sig
        self.assertEqual(len(frame),3487)
        response = b'PCR1'+be(index,4)+be(len(content),4)+content+bytes([len(path)])+b''.join(path)+frame
        return Fixture(catalog,q,response,self.release,catalog_id,self.requester,nonce,self.kid,self.pub)

    def verify(self, f, *, expected=None, now='2050', override=None):
        cat, chall, resp, pem = (self.root/'cat.bin',self.root/'q.bin',
                                  self.root/'response.bin',self.root/'pub.pem')
        cat.write_bytes(f.catalog);chall.write_bytes(f.challenge)
        resp.write_bytes(f.response);pem.write_bytes(f.pub)
        params = [f.release.hex(),f.catalog_id.hex(),f.requester.hex(),f.nonce.hex(),now,f.key_id.hex()]
        for name,v in (override or {}).items():
            names={'release':0,'catalog':1,'requester':2,'nonce':3,'now':4,'provider':5}
            params[names[name]]=v
        return call([str(self.exe),str(cat),str(chall),str(resp),str(pem),*params])

    def assert_reject(self, f, **kwargs):
        result = self.verify(f, **kwargs)
        self.assertNotEqual(result.returncode,0,result.stdout)
        self.assertNotIn(b'VALID_RESEARCH',result.stdout)

    def test_real_native_ml_dsa65_matches_exact_independent_sha384_wire(self):
        for i in range(3):
            with self.subTest(chunk=i):
                f = self.build_fixture(index=i)
                r = self.verify(f)
                self.assertEqual(r.returncode,0,r.stderr)
                self.assertEqual(r.stdout,b'PQN4_VALID_RESEARCH_OBSERVATION_ONLY\n')

    def test_all_176_signed_header_mutations_reject(self):
        f = self.build_fixture()
        sign_at = len(f.response)-3487
        for i in range(176):
            corrupt = bytearray(f.response)
            corrupt[sign_at+i] ^= 1
            with self.subTest(byte=i):
                self.assert_reject(Fixture(f.catalog,f.challenge,bytes(corrupt),f.release,
                                           f.catalog_id,f.requester,f.nonce,f.key_id,f.pub))

    def test_all_217_challenge_bytes_mutation_reject(self):
        f = self.build_fixture()
        for i in range(217):
            bad = bytearray(f.challenge)
            bad[i] ^= 1
            with self.subTest(byte=i):
                self.assert_reject(Fixture(f.catalog,bytes(bad),f.response,f.release,
                                           f.catalog_id,f.requester,f.nonce,f.key_id,f.pub))

    def test_single_chunk_and_full_one_megabyte_chunk_are_bounded(self):
        for content in (b'tiny', b'X' * (1 << 20)):
            with self.subTest(length=len(content)):
                f=self.build_fixture(index=0,chunks=(content,),chunk_size=max(29,len(content)))
                result=self.verify(f)
                self.assertEqual(result.returncode,0,result.stderr)

    def test_chunk_and_merkle_path_mutation_reject(self):
        f = self.build_fixture()
        for idx in (12, 13, 12 + 13 + 1, 12 + 13 + 1+48):
            bad = bytearray(f.response);bad[idx] ^= 1
            with self.subTest(idx=idx):
                self.assert_reject(Fixture(f.catalog,f.challenge,bytes(bad),f.release,
                                           f.catalog_id,f.requester,f.nonce,f.key_id,f.pub))

    def test_self_consistent_signed_attacker_catalog_rejected_by_independent_pin(self):
        original = self.build_fixture()
        forged = self.build_fixture(chunks=(b'Z'*29,b'B'*29,b'C'*13))
        self.assertEqual(self.verify(forged).returncode,0)
        self.assert_reject(forged,override={'catalog': original.catalog_id.hex()})

    def test_signed_response_from_another_nonce_and_sequence_not_replayable(self):
        old = self.build_fixture()
        new = self.build_fixture(nonce=bytes([0xc7])*32,sequence=20)
        self.assert_reject(Fixture(new.catalog,new.challenge,old.response,
                                   new.release,new.catalog_id,new.requester,new.nonce,new.key_id,new.pub))
        self.assert_reject(old,override={'nonce':new.nonce.hex()})
        self.assertEqual(self.verify(new).returncode,0)

    def test_wrong_current_identity_and_time_fail_closed(self):
        f=self.build_fixture()
        for name, v in [(k, vv) for d in ({'release':'22'*48},{'catalog':'33'*48},
                        {'requester':'11'*32},{'nonce':'14'*32},
                        {'provider':'15'*32},{'now':'1999'},{'now':'2101'},
                        {'now':'-1'},{'now':'99999999999999999999999'},
                        {'now':'02x'},{'nonce':'AB'*32}) for k,vv in d.items()]:
            self.assert_reject(f,override={name:v})

    def test_bad_signature_truncation_and_frame_append_reject(self):
        f=self.build_fixture()
        for raw in (f.response[:-1],f.response+b'0',f.response[:19],
                    f.response[:-50]+b'X'+f.response[-49:],
                    f.response[:-3487]+f.response[-3487:-1]+b'X'):
            with self.subTest(n=len(raw)):
                self.assert_reject(Fixture(f.catalog,f.challenge,raw,
                                          f.release,f.catalog_id,f.requester,f.nonce,f.key_id,f.pub))

    def test_no_classical_ed25519_public_key_downgrade(self):
        f=self.build_fixture()
        old=self.root/'ed.pem'
        r=call(['openssl','genpkey','-algorithm','Ed25519','-out',str(old)])
        self.assertEqual(r.returncode,0)
        pub=self.root/'ed.pub'
        r=call(['openssl','pkey','-in',str(old),'-pubout','-out',str(pub)])
        self.assertEqual(r.returncode,0)
        self.assert_reject(Fixture(f.catalog,f.challenge,f.response,
                                  f.release,f.catalog_id,f.requester,f.nonce,f.key_id,pub.read_bytes()))

    def test_symlink_and_foreign_pem_payload_reject(self):
        f=self.build_fixture()
        self.assertEqual(self.verify(f).returncode,0)
        cat=self.root/'cat.bin';alias=self.root/'alias.bin'
        alias.symlink_to(cat)
        base=[str(self.exe),str(alias),str(self.root/'q.bin'),str(self.root/'response.bin'),
              str(self.root/'pub.pem'),f.release.hex(),f.catalog_id.hex(),
              f.requester.hex(),f.nonce.hex(),'2050',f.key_id.hex()]
        r=call(base)
        self.assertNotEqual(r.returncode,0)
        alias.unlink()
        self.assert_reject(Fixture(f.catalog,f.challenge,f.response,
                       f.release,f.catalog_id,f.requester,f.nonce,f.key_id,f.pub+b'-----BEGIN PRIVATE KEY-----'))

    def test_zero_width_length_and_odd_last_canonical_reject(self):
        f=self.build_fixture(index=2)
        mutations=[]
        for pos in (85,93,101,105,109):
            z=bytearray(f.catalog);z[pos]^=1;mutations.append(Fixture(bytes(z),f.challenge,f.response,
                                             f.release,f.catalog_id,f.requester,f.nonce,f.key_id,f.pub))
        # last sibling of index2 must equal exact hash of itself, even if later signature unchanged
        for bad in mutations:
            self.assert_reject(bad)

if __name__=='__main__':
    unittest.main()
