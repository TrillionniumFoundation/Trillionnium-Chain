"""Differential PQN1 native (C/OpenSSL) vs inherited TPQ1 Python/OpenSSL oracle.

Research ONLY. A reported signature-valid/offline-account-view result is not a
Chain VerifiedTransaction or real account ownership/fork transition.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pq_envelope import make_unsigned, public_key_id, sign_reference, verify_reference, Reject

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "pq_qtx1_verify.c"
NET = bytes(range(32))
SENDER = bytes(range(32, 64))
RECIPIENT = bytes(range(64, 96))
CTX_DOMAIN = b"TRNM/PoN/QTX1Context/v1\x00"
ID_DOMAIN = b"TRNM/PoN/QTX1Identity/v1\x00"


def u64(x: int) -> bytes: return x.to_bytes(8, 'big')


def body(memo: bytes = b"pq cell settlement", *, sender=SENDER, recipient=RECIPIENT,
         net=NET, generation=2, nonce=7, expiry=5000, amount=1200, max_fee=10000) -> bytes:
    return (b'QTX1' + bytes([1, 1]) + net + sender + recipient
            + u64(generation) + u64(nonce) + u64(expiry) + u64(amount) + u64(max_fee)
            + len(memo).to_bytes(2, 'big') + memo)


def signed(data: bytes, pem: bytes, secret: Path, *, purpose=1) -> bytes:
    ctx = hashlib.sha256(CTX_DOMAIN + data[6:38] + data[38:70]).digest()
    obj = make_unsigned(purpose=purpose, network=data[6:38], context=ctx,
                        signer_key_id=public_key_id(pem),
                        owner_generation=int.from_bytes(data[102:110], 'big'),
                        operation_sequence=int.from_bytes(data[110:118], 'big'),
                        expires_at=int.from_bytes(data[118:126], 'big'), payload=data)
    return data + sign_reference(obj, private_key_path=secret)


class NativeQtx1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='trnm-qtx1-native-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name)
        cls.bin = cls.root / 'pq_qtx1_verify'
        sanitizer = os.environ.get('PQN1_SANITIZE') == '1'
        flags = ['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer'] if sanitizer else ['-O2']
        subprocess.run(['cc','-std=c11',*flags,'-Wall','-Wextra','-Werror','-Wpedantic',
                        str(SOURCE), '-lcrypto', '-o', str(cls.bin)],check=True,timeout=30)
        cls.secret = cls.root / 'ml65-private.pem'
        cls.pub = cls.root / 'ml65-public.pem'
        subprocess.run(['openssl','genpkey','-algorithm','ML-DSA-65','-out',str(cls.secret)],
                       check=True,capture_output=True,timeout=15)
        subprocess.run(['openssl','pkey','-in',str(cls.secret),'-pubout','-out',str(cls.pub)],
                       check=True,capture_output=True,timeout=15)
        cls.pem = cls.pub.read_bytes()
        cls.key_id = public_key_id(cls.pem)
        cls.data = body()
        cls.frame = signed(cls.data, cls.pem, cls.secret)
        cls.raw = cls.root / 'signed.qtx'
        cls.raw.write_bytes(cls.frame)

    def probe(self, raw: bytes | None = None, *, pub: Path | None = None, net=NET,
              sender=SENDER, key=None, generation=2, nonce=7, now=4000,
              balance=20000, base_fee=100, byte_fee=1, active=1,
              path: Path | None = None) -> subprocess.CompletedProcess:
        if raw is not None:
            test_path = self.root / 'test-current.qtx'
            test_path.write_bytes(raw)
        else:
            test_path = self.raw
        cmd = [str(self.bin), str(self.pub if pub is None else pub),
               str(test_path if path is None else path), net.hex(),sender.hex(),
               (self.key_id if key is None else key).hex(),str(generation),str(nonce),
               str(now),str(balance),str(base_fee),str(byte_fee),str(active)]
        return subprocess.run(cmd,capture_output=True,text=True,timeout=15)

    def reject(self,*args,**kwargs):
        result=self.probe(*args,**kwargs)
        self.assertEqual(result.returncode,2,(result.stdout,result.stderr))
        self.assertIn('PQN1_REJECT',result.stderr)
        self.assertNotIn('SIGNATURE_VALID',result.stdout)

    def test_real_ml_dsa_signature_matches_python_oracle_and_pinned_id(self):
        checked=verify_reference(self.frame[len(self.data):],payload=self.data,
            public_pem=self.pem, expected_network=NET,
            expected_context=hashlib.sha256(CTX_DOMAIN+NET+SENDER).digest(),
            expected_purpose=1,expected_generation=2,expected_sequence=7,now=4000)
        self.assertEqual(checked.payload_digest,hashlib.sha384(
            b'TRNM/PoN/PQAuth/ML-DSA-65/v1\x00payload\x00' + u64(len(self.data))+self.data).digest())
        result=self.probe()
        self.assertEqual(result.returncode,0,(result.stdout,result.stderr))
        self.assertTrue(result.stdout.startswith('PQN1_RESEARCH_ONLY_SIGNATURE_VALID identity='))
        expected=hashlib.sha384(ID_DOMAIN +len(self.data).to_bytes(4,'big')+self.data+self.key_id).hexdigest()
        self.assertIn(f'identity={expected}',result.stdout)
        self.assertIn(f'fee={100+len(self.frame)}',result.stdout)
        self.assertIn(f'remaining={20000-1200-100-len(self.frame)}',result.stdout)
        self.assertIn(f'bytes={len(self.frame)}',result.stdout)
        self.assertGreater(len(self.frame),2048)

    def test_all_signed_qtx1_body_mutations_reject(self):
        # Re-signing would represent a fresh separately authorized statement;
        # mutating captured bytes must NEVER validate.
        for pos in range(len(self.data)):
            t=bytearray(self.frame);t[pos]^=1
            with self.subTest(offset=pos): self.reject(bytes(t))

    def test_all_tpq1_statement_mutations_reject(self):
        for pos in range(len(self.data),len(self.data)+176):
            t=bytearray(self.frame);t[pos]^=1
            with self.subTest(offset=pos): self.reject(bytes(t))

    def test_bad_signature_key_and_classical_downgrade_reject(self):
        t=bytearray(self.frame);t[-1]^=1;self.reject(bytes(t))
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            sec=p/'other-secret';pub=p/'other-pub'
            subprocess.run(['openssl','genpkey','-algorithm','ML-DSA-65','-out',str(sec)],
                           check=True,capture_output=True,timeout=15)
            subprocess.run(['openssl','pkey','-in',str(sec),'-pubout','-out',str(pub)],
                           check=True,capture_output=True,timeout=15)
            self.reject(pub=pub)
            ed=p/'ed-secret';ep=p/'ed-pub'
            subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(ed)],
                           check=True,capture_output=True,timeout=15)
            subprocess.run(['openssl','pkey','-in',str(ed),'-pubout','-out',str(ep)],
                           check=True,capture_output=True,timeout=15)
            self.reject(pub=ep)
        self.reject(key=bytes(32))

    def test_replay_domain_and_caller_owned_state(self):
        self.reject(net=bytes(32));self.reject(sender=bytes(32))
        self.reject(generation=3);self.reject(nonce=8)
        self.reject(now=5001);self.reject(active=0)
        self.reject(base_fee=10001);self.reject(balance=1000)
        self.reject(byte_fee=2**64-1)
        self.reject(base_fee=2**64-1)
        self.reject(balance=2**64)
        self.reject(base_fee=-1);self.reject(byte_fee='00')
        self.reject(generation='2.0')
        self.reject(key=bytes([255])*32)

    def test_cross_purpose_signature_is_not_transaction(self):
        cross=signed(self.data,self.pem,self.secret,purpose=4)
        self.reject(cross)
        t=bytearray(self.frame);t[len(self.data)+5]=0;self.reject(bytes(t))
        t=bytearray(self.frame);t[len(self.data)+6]=6;self.reject(bytes(t))

    def test_exact_wire_sizes_reject_length_memo_and_spki_confusion(self):
        for raw in (b'',self.frame[:-1],self.frame+b'X',b'PTX1'+self.frame[4:],
                    self.frame[:142]+b'\xff\xff'+self.frame[144:],
                    self.frame[:5]+b'\x02'+self.frame[6:],
                    self.frame[:len(self.data)+176]+b'\x00\x01'+self.frame[len(self.data)+178:],
                    bytes(8193)):
            with self.subTest(length=len(raw)):self.reject(raw)
        self.reject(path=self.root / 'nonexistent')
        link=self.root/'symlink.qtx';link.symlink_to(self.raw)
        self.reject(path=link)

    def test_repeated_signature_has_stable_identity_not_signature_bytes(self):
        second=signed(self.data,self.pem,self.secret)
        first=self.probe().stdout
        follow=self.probe(second)
        self.assertEqual(follow.returncode,0,follow.stderr)
        pattern=r'identity=([0-9a-f]{96})'
        self.assertEqual(re.search(pattern,first).group(1),re.search(pattern,follow.stdout).group(1))

    def test_exact_512_byte_memo_and_large_fee(self):
        b=body(bytes(range(256))*2)
        frame=signed(b,self.pem,self.secret)
        result=self.probe(frame,balance=20000)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(int(re.search(r'bytes=(\d+)',result.stdout).group(1)),len(frame))
        self.assertLess(len(frame),8192)
        self.assertGreater(len(frame),2048)
        # Fee limit encoded in the sender's signed body is fixed 10000.
        self.reject(frame,base_fee=7000)

    def test_structurally_valid_resigned_but_mismatched_owner_reject(self):
        b=body(recipient=bytes([93])*32)
        frame=signed(b,self.pem,self.secret)
        self.assertEqual(self.probe(frame).returncode,0)
        self.reject(frame,sender=bytes(32))
        b=body(sender=bytes([12])*32)
        frame=signed(b,self.pem,self.secret)
        self.reject(frame)
        b=body(generation=3)
        frame=signed(b,self.pem,self.secret)
        self.reject(frame)
        b=body(nonce=8)
        frame=signed(b,self.pem,self.secret)
        self.reject(frame)

if __name__=='__main__':unittest.main()
