"""PQN2 independent local native/Python byte conformance; research only.

Tests the actual OpenSSL ML-DSA-65 and strict Ed25519 proof for a PQG1
snapshot with balances plus liabilities. All assertions are fail-closed.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE=Path(__file__).resolve().parent
SOURCE=b"TRNM/PQ/GenesisSource/v1\x00"
MIGRATION=b"TRNM/PQ/GenesisMigration/v1\x00"
KEY=b"TRNM/PoN/PQKey/v1\x00"


def be(n:int)->bytes:
    return n.to_bytes(8,"big")


def h48(prefix:bytes,value:bytes)->bytes:
    return hashlib.sha384(prefix+be(len(value))+value).digest()


def call(args:list[str], **kw)->bytes:
    cp=subprocess.run(args,capture_output=True,check=True,timeout=20,**kw)
    return cp.stdout


class NativePQGenesisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix="pqg-native-")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root=Path(cls.tmp.name)
        cls.exe=cls.root/"pqn2"
        options=["-fsanitize=address,undefined","-fno-omit-frame-pointer"] if os.environ.get("PQN2_SANITIZE") == "1" else []
        call(["cc","-std=c11","-Wall","-Wextra","-Werror","-O2",*options,
              str(HERE/"pqg_native_verify.c"),"-lcrypto","-o",str(cls.exe)])
        cls.pqpriv=cls.root/"pq-private.pem"
        cls.pqpub=cls.root/"pq-public.pem"
        call(["openssl","genpkey","-algorithm","ML-DSA-65","-out",str(cls.pqpriv)])
        call(["openssl","pkey","-in",str(cls.pqpriv),"-pubout","-out",str(cls.pqpub)])
        der=call(["openssl","pkey","-pubin","-in",str(cls.pqpub),"-outform","DER"])
        assert len(der)==1974 and der[:4]==bytes.fromhex("308207b2")
        cls.pqkid=hashlib.sha256(KEY+der).digest()
        cls.old=(Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate())
        cls.oldpub=sorted(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw) for k in cls.old)
        cls.keys={k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw):k for k in cls.old}
        cls.legacy_network=b"\x11"*32
        cls.new_network=b"\x22"*32
        cls.legacy_head=b"\x33"*32
        cls.withdrawal_head=b"\x44"*32
        cls.profile=b"\x55"*32
        cls.account1=cls.oldpub[0]+be(8000)+be(17)+be(3)
        cls.account2=cls.oldpub[1]+be(7000)+be(9)+be(2)
        cls.liability1=b"\x66"*32+cls.oldpub[0]+be(1000)+be(21)+b"\x01"
        cls.liability2=b"\x77"*32+cls.oldpub[1]+be(2000)+be(37)+b"\x04"
        cls.issued=18000
        cls.snap=(b"PQG1\x01"+cls.legacy_network+cls.new_network+cls.legacy_head+
                  cls.withdrawal_head+cls.profile+be(cls.issued)+bytes.fromhex("00020002")+
                  cls.account1+cls.account2+cls.liability1+cls.liability2)
        cls.source_digest=h48(SOURCE,cls.snap)
        cls.expiry=5000
        cls.statement=(MIGRATION+cls.source_digest+cls.legacy_network+cls.new_network+
                       cls.legacy_head+cls.withdrawal_head+cls.profile+cls.account1+
                       cls.pqkid+be(4)+be(cls.expiry))
        cls.ed_sig=cls.keys[cls.oldpub[0]].sign(cls.statement)
        statement_file=cls.root/"message.bin"
        pqsignature=cls.root/"signature.bin"
        statement_file.write_bytes(cls.statement)
        call(["openssl","pkeyutl","-sign","-inkey",str(cls.pqpriv),
              "-rawin","-in",str(statement_file),"-out",str(pqsignature)])
        cls.pq_sig=pqsignature.read_bytes()
        assert len(cls.pq_sig)==3309
        cls.proof=b"PQM1"+cls.oldpub[0]+cls.pqkid+be(cls.expiry)+cls.ed_sig+cls.pq_sig
        cls.anchor=(b"PQA1"+cls.source_digest+cls.legacy_network+cls.new_network+
                    cls.legacy_head+cls.withdrawal_head+cls.profile+be(cls.issued)+
                    cls.oldpub[0]+cls.pqkid+be(4900))
        assert len(cls.anchor)==292 and len(cls.proof)==3449

    def run_gate(self,*,snapshot=None,anchor=None,proof=None,pem=None,symlink=False):
        with tempfile.TemporaryDirectory(prefix="pqn2-case-") as td:
            root=Path(td)
            a=root/"snapshot.bin";b=root/"anchor.bin";c=root/"claim.bin";d=root/"public.pem"
            a.write_bytes(self.snap if snapshot is None else snapshot)
            b.write_bytes(self.anchor if anchor is None else anchor)
            c.write_bytes(self.proof if proof is None else proof)
            d.write_bytes(self.pqpub.read_bytes() if pem is None else pem)
            if symlink:
                link=root/"alias";link.symlink_to(a);a=link
            return subprocess.run([str(self.exe),str(a),str(b),str(c),str(d)],
                                  capture_output=True,timeout=15)

    def assertReject(self,**kw):
        result=self.run_gate(**kw)
        self.assertNotEqual(result.returncode,0,(result.stdout,result.stderr))
        self.assertNotIn(b"PQN2_VALID",result.stdout)

    def mutate(self,raw:bytes,position:int)->bytes:
        b=bytearray(raw);b[position]^=1;return bytes(b)

    def test_real_dual_possession_with_two_conserved_liabilities(self):
        observed=self.run_gate()
        self.assertEqual(observed.returncode,0,observed.stderr)
        self.assertEqual(observed.stdout.strip(),b"PQN2_VALID_RESEARCH_OBSERVATION_ONLY")
        self.assertEqual(int.from_bytes(self.snap[165:173],"big"),self.issued)

    def test_snapshot_fields_and_liability_tampering_fail(self):
        for p in (0,4,5,37,69,101,133,165,173,175,177,177+56,177+112,177+112+81, len(self.snap)-1):
            with self.subTest(index=p):self.assertReject(snapshot=self.mutate(self.snap,p))

    def test_external_expected_anchor_and_source_hash_are_mandatory(self):
        for p in (0,4,51,52,84,116,148,180,212,220,252):
            with self.subTest(index=p):self.assertReject(anchor=self.mutate(self.anchor,p))

    def test_expired_migration_even_when_both_signatures_cryptographically_valid(self):
        expiry=5001
        anchor=self.anchor[:-8]+be(expiry)
        self.assertReject(anchor=anchor)
        self.assertEqual(self.run_gate(anchor=self.anchor[:-8]+be(5000)).returncode,0)

    def test_old_signature_and_new_signature_are_both_required(self):
        for p in (76,139,140,500,3448):
            with self.subTest(index=p):self.assertReject(proof=self.mutate(self.proof,p))
        self.assertReject(proof=self.proof[:-1])

    def test_any_migration_identity_replacement_rejects(self):
        for p in (0,3,4,35,36,67,68,75):
            with self.subTest(index=p):self.assertReject(proof=self.mutate(self.proof,p))
        self.assertReject(proof=self.proof+b"\x00")

    def test_ed25519_key_is_not_a_pq_signer(self):
        bad=b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----\n"
        self.assertReject(pem=bad)

    def test_public_key_trailing_data_is_not_canonical(self):
        self.assertReject(pem=self.pqpub.read_bytes()+b"\nEXTRA PUBLIC KEY")

    def test_wrong_pq_public_key_cannot_authenticate_original_proof(self):
        secret=self.root/"other-private.pem";pub=self.root/"other-public.pem"
        call(["openssl","genpkey","-algorithm","ML-DSA-65","-out",str(secret)])
        call(["openssl","pkey","-in",str(secret),"-pubout","-out",str(pub)])
        self.assertReject(pem=pub.read_bytes())

    def test_foreign_file_symlink_refused(self):
        self.assertReject(symlink=True)

    def test_truncated_and_appended_source_reject(self):
        self.assertReject(snapshot=self.snap[:-1])
        self.assertReject(snapshot=self.snap+b"x")

    def test_sum_conservation_not_just_snapshot_digest(self):
        data=bytearray(self.snap)
        data[165:173]=be(self.issued+1)
        source=bytes(data)
        new_digest=h48(SOURCE,source)
        new_anchor=self.anchor[:4]+new_digest+self.anchor[52:212]+be(self.issued+1)+self.anchor[220:]
        self.assertReject(snapshot=source,anchor=new_anchor)

    def test_noncanonical_account_roster_rejects_even_if_reanchored(self):
        data=bytearray(self.snap)
        data[177:177+56],data[233:289]=bytes(data[233:289]),bytes(data[177:233])
        source=bytes(data); new_digest=h48(SOURCE,source)
        new_anchor=self.anchor[:4]+new_digest+self.anchor[52:]
        self.assertReject(snapshot=source,anchor=new_anchor)

    def test_missing_owner_or_misassigned_liability_rejects_even_if_reanchored(self):
        data=bytearray(self.snap)
        data[177+112+32:177+112+64]=bytes([0x88])*32
        source=bytes(data);new_digest=h48(SOURCE,source)
        self.assertReject(snapshot=source,anchor=self.anchor[:4]+new_digest+self.anchor[52:])

    def test_strict_ed25519_R_and_S_negative_vectors(self):
        identity=b"\x01"+bytes(31)
        negative_zero=b"\x01"+bytes(30)+b"\x80"
        p=((1<<255)-19).to_bytes(32,"little")
        L=((1<<252)+27742317777372353535851937790883648493).to_bytes(32,"little")
        for off,replacement in ((76,identity),(76,negative_zero),(76,p),(108,L)):
            data=bytearray(self.proof);data[off:off+32]=replacement
            result=self.run_gate(proof=bytes(data))
            with self.subTest(off=off,repr=replacement.hex()[:20]):
                self.assertNotEqual(result.returncode,0)
                self.assertIn(b"strict Ed25519",result.stderr)

    def test_strict_ed25519_legacy_identity_point_rejected_after_reanchor(self):
        identity=b"\x01"+bytes(31)
        data=bytearray(self.snap)
        data[177:209]=identity
        first_liability_owner=177+112+32
        data[first_liability_owner:first_liability_owner+32]=identity
        snapshot=bytes(data)
        a=bytearray(self.anchor)
        a[4:52]=h48(SOURCE,snapshot)
        a[220:252]=identity
        proof=bytearray(self.proof);proof[4:36]=identity
        result=self.run_gate(snapshot=snapshot,anchor=bytes(a),proof=bytes(proof))
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b"strict Ed25519",result.stderr)

    def test_no_implicit_ledger_or_final_use_authority(self):
        cp=self.run_gate()
        self.assertEqual(cp.returncode,0)
        self.assertNotIn(b"FINAL",cp.stdout)
        self.assertNotIn(b"CHAIN",cp.stdout)
        self.assertNotIn(b"IMPORT",cp.stdout)


if __name__ == "__main__":unittest.main()
