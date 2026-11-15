"""PQN5 native whole-roster structural projection / no-authority attack regressions."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
S = b"TRNM/PQ/GenesisSource/v1\x00"
T = b"TRNM/PQ/GenesisState/v1\x00"
G = b"TRNM/PQ/GenesisID/v1\x00"
Q = b"TRNM/PQ/Quarantine/v1\x00"
A = b"TRNM/PQ/Account/v1\x00"
OLD = bytes([11])*32
NEW = bytes([22])*32
HEAD = bytes([33])*32
WITHDRAW = bytes([44])*32
PROFILE = bytes([55])*32
OLD_KEYS = [bytes([64])*32, bytes([96])*32]
PQS_KEYS = [bytes([77])*32, bytes([88])*32]


def uint64(n): return n.to_bytes(8, "big")
def framed(domain, raw): return hashlib.sha384(domain + uint64(len(raw)) + raw).digest()


def make_fixture(*, migrated=(True, False), balances=(700, 200),
                 nonces=(17, 29), generations=(4, 8),
                 liabilities=((bytes([1])*32, 0, 50, 40, 1),
                              (bytes([2])*32, 1, 50, 60, 4)),
                 issued=None, source_old=OLD, source_new=NEW):
    accounts = []
    for i, public in enumerate(OLD_KEYS):
        accounts.append(public + uint64(balances[i]) + uint64(nonces[i]) + uint64(generations[i]))
    liabs = [lid + OLD_KEYS[owner] + uint64(amount) + uint64(due) + bytes([kind])
             for lid, owner, amount, due, kind in liabilities]
    count = sum(balances) + sum(l[2] for l in liabilities)
    if issued is None: issued = count
    source = (b"PQG1\x01" + source_old + source_new + HEAD + WITHDRAW + PROFILE + uint64(issued)
              + len(accounts).to_bytes(2,"big") + len(liabs).to_bytes(2,"big")
              + b"".join(accounts) + b"".join(liabs))
    records = []
    for i, account in enumerate(accounts):
        if migrated[i]:
            pqid = PQS_KEYS[i]
            addr = hashlib.sha256(A + source_new + OLD_KEYS[i] + pqid).digest()
            status = b"\x01"
        else:
            pqid = bytes(32)
            addr = hashlib.sha256(Q + source_new + OLD_KEYS[i]).digest()
            status = b"\x00"
        records.append(status + addr + pqid + account + uint64(generations[i]+1))
    target = (b"PQS1\x01" + source_new + PROFILE + len(records).to_bytes(2,"big")
              + b"".join(records) + len(liabs).to_bytes(2,"big")
              + b"".join(liabs) + uint64(issued))
    return source, target, make_anchor(source, target)


def make_anchor(source, target):
    source_hash = framed(S, source)
    target_hash = framed(T, target)
    genesis = framed(G, source[37:69] + source[133:165] + source_hash + target_hash)
    return (b"PQA3\x01" + source_hash + target_hash + genesis + source[5:37] + source[37:69]
            + source[69:101] + source[101:133] + source[133:165] + source[165:173])


def make_dense_fixture(account_count=128, liability_count=256):
    old_ids=[i.to_bytes(32, "big") for i in range(1,account_count+1)]
    rows=[]; records=[]; locks=[]
    for i, old in enumerate(old_ids):
        account = old + uint64(10) + uint64(100+i) + uint64(1)
        rows.append(account)
        if i % 2:
            status=b"\x00"; kid=bytes(32)
            addr=hashlib.sha256(Q+NEW+old).digest()
        else:
            status=b"\x01"; kid=hashlib.sha256(b"pq-key"+old).digest()
            addr=hashlib.sha256(A+NEW+old+kid).digest()
        records.append(status+addr+kid+account+uint64(2))
    for i in range(1,liability_count+1):
        locks.append(i.to_bytes(32,"big")+old_ids[(i-1)%len(old_ids)]
                     +uint64(1)+uint64(i)+bytes([1+(i-1)%4]))
    issued=10*account_count+liability_count
    source=(b"PQG1\x01"+OLD+NEW+HEAD+WITHDRAW+PROFILE+uint64(issued)
            +account_count.to_bytes(2,"big")+liability_count.to_bytes(2,"big")
            +b"".join(rows)+b"".join(locks))
    target=(b"PQS1\x01"+NEW+PROFILE+account_count.to_bytes(2,"big")
            +b"".join(records)+liability_count.to_bytes(2,"big")
            +b"".join(locks)+uint64(issued))
    return source,target,make_anchor(source,target)


class NativePQN5(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="pqn5-")
        cls.addClassCleanup(cls.work.cleanup)
        cls.binary = Path(cls.work.name)/"pqn5"
        cc = os.environ.get("CC", "cc")
        cmd = [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O1" if os.environ.get("PQN5_SANITIZE") else "-O2"]
        if os.environ.get("PQN5_SANITIZE"):
            cmd += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        cmd += [str(HERE/"pq_import_projection_verify.c"), "-o", str(cls.binary), "-lcrypto"]
        subprocess.run(cmd, check=True, capture_output=True, timeout=30)
        cls.source, cls.target, cls.anchor = make_fixture()
        assert len(cls.anchor)==317
        cls.n=0

    def run_case(self, source=None, target=None, anchor=None, *, good=False):
        s=self.source if source is None else source
        t=self.target if target is None else target
        a=self.anchor if anchor is None else anchor
        with tempfile.TemporaryDirectory(prefix="pqn5-case-", dir=self.work.name) as root:
            paths=[]
            for name, raw in (("source", s), ("target", t), ("anchor", a)):
                p=Path(root)/name; p.write_bytes(raw); paths.append(str(p))
            r=subprocess.run([str(self.binary),*paths],capture_output=True,timeout=10)
            if good:
                self.assertEqual(r.returncode,0, (r.stderr, len(s),len(t),len(a)))
                self.assertEqual(r.stdout,b"PQN5_VALID_STRUCTURAL_PROJECTION_ONLY\n")
            else:
                self.assertEqual(r.returncode,1, (r.stdout,r.stderr))
                self.assertEqual(r.stderr,b"PQN5_REJECTED_NO_AUTHORITY\n")
            self.n+=1

    def test_valid_migrated_and_quarantined_all_four_liability_classes(self):
        self.run_case(good=True)
        for migrated in ((False,False),(True,True),(False,True)):
            s,t,a=make_fixture(migrated=migrated)
            self.run_case(s,t,a,good=True)
        s,t,a=make_fixture(liabilities=tuple((bytes([i])*32, i%2, i*3, i*100, i)
                                          for i in range(1,5)))
        self.run_case(s,t,a,good=True)
        s,t,a=make_fixture(liabilities=())
        self.run_case(s,t,a,good=True)

    def test_every_pinned_anchor_byte_mutation_fails(self):
        for i in range(len(self.anchor)):
            raw=bytearray(self.anchor);raw[i]^=1
            with self.subTest(i=i):self.run_case(anchor=bytes(raw))

    def test_every_source_byte_mutation_fails_against_fixed_pin(self):
        for i in range(len(self.source)):
            raw=bytearray(self.source);raw[i]^=1
            with self.subTest(i=i):self.run_case(source=bytes(raw))

    def test_every_target_byte_mutation_fails_against_fixed_pin(self):
        for i in range(len(self.target)):
            raw=bytearray(self.target);raw[i]^=1
            with self.subTest(i=i):self.run_case(target=bytes(raw))

    def test_truncation_length_and_extensions_fail(self):
        for s,t,a in ((self.source[:-1],self.target,self.anchor),
                      (self.source+b"x",self.target,self.anchor),
                      (self.source,self.target[:-1],self.anchor),
                      (self.source,self.target+b"x",self.anchor),
                      (self.source,self.target,self.anchor[:-1]),
                      (self.source,self.target,self.anchor+b"x"),
                      (self.source[:20],self.target,self.anchor),
                      (self.source,self.target[:69],self.anchor)):
            self.run_case(s,t,a)

    def test_reanchored_migration_cannot_reset_nonce_or_generation(self):
        for offset in (71+65+32+8, 71+65+32+8+8, 71+121):
            target=bytearray(self.target)
            target[offset:offset+8]=uint64(1)
            self.run_case(target=bytes(target),anchor=make_anchor(self.source,bytes(target)))

    def test_reanchored_quarantine_becoming_active_without_correct_account_key_rejects(self):
        target=bytearray(self.target)
        second=71+129
        target[second]=1
        target[second+33:second+65]=PQS_KEYS[1]
        self.run_case(target=bytes(target),anchor=make_anchor(self.source,bytes(target)))

    def test_reanchored_active_key_or_address_swapping_rejects(self):
        for start in (71+1,71+33):
            target=bytearray(self.target);target[start]^=1
            self.run_case(target=bytes(target),anchor=make_anchor(self.source,bytes(target)))

    def test_duplicate_active_identity_rejects_even_reanchored(self):
        source,target,_=make_fixture(migrated=(True,True))
        changed=bytearray(target)
        changed[71+129+33:71+129+65]=PQS_KEYS[0]
        changed[71+129+1:71+129+33]=hashlib.sha256(A+NEW+OLD_KEYS[1]+PQS_KEYS[0]).digest()
        self.run_case(source,bytes(changed),make_anchor(source,bytes(changed)))

    def test_source_and_target_counterfeit_liability_edits_reject_against_fixed_anchor(self):
        ss=bytearray(self.source);tt=bytearray(self.target)
        so=177+56*2+64; to=71+129*2+2+64
        ss[so:so+8]=uint64(1)
        tt[to:to+8]=uint64(1)
        self.run_case(bytes(ss),bytes(tt))
        # Even if attacker forges all three commitments, supply conservation still rejects.
        self.run_case(bytes(ss),bytes(tt),make_anchor(bytes(ss),bytes(tt)))

    def test_reanchored_removed_or_relabelled_liability_rejects(self):
        for offset in (71+129*2,71+129*2+2,71+129*2+2+32,
                       71+129*2+2+80,71+129*2+2+81):
            raw=bytearray(self.target);raw[offset]^=1
            self.run_case(target=bytes(raw),anchor=make_anchor(self.source,bytes(raw)))

    def test_source_fork_or_revocation_context_rejects(self):
        for start in (5,37,69,101,133,165):
            changed=bytearray(self.source);changed[start]^=1
            self.run_case(source=bytes(changed))

    def test_wrong_target_generation_or_source_zero_floor_fails(self):
        for field in (177+40,177+48):
            raw=bytearray(self.source);raw[field:field+8]=uint64(0)
            self.run_case(source=bytes(raw),anchor=make_anchor(bytes(raw),self.target))
        target=bytearray(self.target);target[71+121:71+129]=uint64(999)
        self.run_case(target=bytes(target),anchor=make_anchor(self.source,bytes(target)))

    def test_symlink_source_and_nonfile_input_fail(self):
        with tempfile.TemporaryDirectory(prefix="pqn5-symlink-") as root:
            r=Path(root);src=r/"original";src.write_bytes(self.source)
            link=r/"alias";link.symlink_to(src)
            dest=r/"target";dest.write_bytes(self.target)
            pin=r/"pin";pin.write_bytes(self.anchor)
            cases=((str(link),str(dest),str(pin)),(str(r),str(dest),str(pin)))
            for argv in cases:
                p=subprocess.run([str(self.binary),*argv],capture_output=True,timeout=10)
                self.assertEqual(p.returncode,1)

    def test_no_authority_and_untrusted_self_reanchor_counterexample(self):
        self.run_case(good=True)
        # A colluding source exporter can create a DIFFERENT self-consistent snapshot,
        # matched projection and new anchor. This structural verifier MUST NOT claim
        # independent old-chain authority or enable any new-chain spending.
        s,t,a=make_fixture(balances=(600,300))
        self.assertNotEqual(a,self.anchor)
        self.run_case(s,t,a,good=True)


    def test_full_128_account_256_liability_capacity(self):
        s,t,a=make_dense_fixture()
        self.assertLessEqual(len(s),65536)
        self.assertLessEqual(len(t),65536)
        self.run_case(s,t,a,good=True)

    def test_reanchor_cannot_exceed_account_or_liability_limits(self):
        for ac,li in ((129,0),(128,257)):
            s,t,a=make_dense_fixture(ac,li)
            self.run_case(s,t,a)

    def test_reanchor_cannot_wrap_64_bit_conserved_amount(self):
        source,target,_=make_fixture(balances=((1<<64)-1,(1<<64)-1),issued=(1<<64)-1)
        self.run_case(source,target,make_anchor(source,target))

    def test_unknown_obligation_owner_rejected_even_if_both_views_reanchored(self):
        s=bytearray(self.source);t=bytearray(self.target)
        source_offset=177+56*2+32
        target_offset=71+129*2+2+32
        s[source_offset:source_offset+32]=bytes([0xEE])*32
        t[target_offset:target_offset+32]=bytes([0xEE])*32
        s,t=bytes(s),bytes(t)
        self.run_case(s,t,make_anchor(s,t))

    def test_duplicate_or_unsorted_source_account_rejected_with_reanchoring(self):
        s=bytearray(self.source);t=bytearray(self.target)
        s[177+56:177+88]=s[177:209]
        t[71+129+65:71+129+97]=s[177:209]
        self.run_case(bytes(s),bytes(t),make_anchor(bytes(s),bytes(t)))

    def test_unrecognized_quarantine_identity_rejected_after_reanchor(self):
        t=bytearray(self.target);start=71+129+1
        t[start:start+32]=bytes([0x77])*32
        self.run_case(target=bytes(t),anchor=make_anchor(self.source,bytes(t)))


if __name__ == "__main__":
    unittest.main()
