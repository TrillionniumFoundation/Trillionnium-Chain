"""PQL3 standalone reference tests: no chain admission, signing or activation."""
from __future__ import annotations

from dataclasses import replace
from contextlib import closing
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from pq_pql2_fork_recovery import (Reject, ImportView, ResearchForkStore,
                                  check_import, framed, PQL2_DOMAIN, MAX_U64)

SOURCE = b"TRNM/PQ/GenesisSource/v1\x00"
STATE = b"TRNM/PQ/GenesisState/v1\x00"
GENESIS = b"TRNM/PQ/GenesisID/v1\x00"
OLDNET = bytes([11])*32
NEWNET = bytes([12])*32
HEAD = bytes([13])*32
WITHDRAW = bytes([14])*32
PROFILE = bytes([15])*32
OLDIDS = [bytes([21])*32,bytes([22])*32]
PQKEY = bytes([31])*32
U = lambda n: n.to_bytes(8,"big")


def fixture(*, nonces=(17,29), accounts_balance=(700,200), liabilities=None):
    if liabilities is None:
        liabilities = [(i.to_bytes(32,"big"), OLDIDS[i%2], amount, i*10, i)
                       for i,amount in enumerate((0,50,80,120,250)) if i > 0]
    olds = [k + U(accounts_balance[i]) + U(nonces[i]) + U(4+i) for i,k in enumerate(OLDIDS)]
    locked = b"".join(lid+owner+U(amount)+U(due)+bytes([kind])
                       for lid,owner,amount,due,kind in liabilities)
    issued = sum(accounts_balance)+sum(x[2] for x in liabilities)
    source=(b"PQG1\x01"+OLDNET+NEWNET+HEAD+WITHDRAW+PROFILE+U(issued)
            +len(olds).to_bytes(2,"big")+len(liabilities).to_bytes(2,"big")
            +b"".join(olds)+locked)
    aid0=hashlib.sha256(b"TRNM/PQ/Account/v1\x00"+NEWNET+OLDIDS[0]+PQKEY).digest()
    aid1=hashlib.sha256(b"TRNM/PQ/Quarantine/v1\x00"+NEWNET+OLDIDS[1]).digest()
    rows=[b"\x01"+aid0+PQKEY+olds[0]+U(5),b"\x00"+aid1+bytes(32)+olds[1]+U(6)]
    target=(b"PQS1\x01"+NEWNET+PROFILE+len(rows).to_bytes(2,"big")+b"".join(rows)
            +len(liabilities).to_bytes(2,"big")+locked+U(issued))
    sd=framed(SOURCE,source);sr=framed(STATE,target)
    gid=framed(GENESIS,NEWNET+PROFILE+sd+sr)
    pql2=(b"PQL2\x01"+NEWNET+PROFILE+HEAD+WITHDRAW+sd+gid
          +len(rows).to_bytes(2,"big")+b"".join(rows)
          +len(liabilities).to_bytes(2,"big")+locked+U(issued)
          +U(accounts_balance[1])+U(sum(x[2] for x in liabilities)))
    expected=dict(expected_root=framed(PQL2_DOMAIN,pql2),expected_source_digest=sd,
                  expected_genesis_id=gid,expected_network=NEWNET,
                  expected_profile=PROFILE,expected_old_head=HEAD,
                  expected_withdrawal_head=WITHDRAW,expected_issued=issued)
    return pql2, expected, source, target


class PQL3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pql3-")
        self.addCleanup(self.tmp.cleanup)
        self.dir=Path(self.tmp.name)
        self.path=self.dir/"sim.sqlite"
        self.raw,self.pins,self.source,self.target=fixture()
        self.imp=check_import(self.raw,**self.pins)

    def open(self):
        return ResearchForkStore(self.path,self.imp)

    def test_exact_pql2_identity_account_nonce_and_all_four_liabilities(self):
        self.assertEqual(self.imp.issued,1400)
        self.assertEqual(self.imp.quarantine,200)
        self.assertEqual(self.imp.locked,500)
        self.assertEqual(len(self.imp.liabilities),4)
        self.assertEqual([x[-1] for x in self.imp.liabilities],[1,2,3,4])
        self.assertEqual([a.nonce_floor for a in self.imp.accounts],[17,29])
        self.assertEqual([a.generation for a in self.imp.accounts],[5,6])
        self.assertEqual([a.status for a in self.imp.accounts],[1,0])

    def test_mutate_all_pql2_bytes_under_original_independent_root(self):
        for i in range(len(self.raw)):
            bad=bytearray(self.raw); bad[i]^=1
            with self.subTest(i=i),self.assertRaises(Reject):
                check_import(bytes(bad),**self.pins)

    def test_reanchored_wrong_nonce_balance_gen_and_quarantine_reject(self):
        # Attacker rehashes input to dodge a naive root equality check.
        for i in (231,232,263,264,295,296,303,304,312,352,353,360,367,368):
            bad=bytearray(self.raw);bad[i]^=1
            newp=dict(self.pins,expected_root=framed(PQL2_DOMAIN,bytes(bad)))
            with self.subTest(i=i),self.assertRaises(Reject):
                check_import(bytes(bad),**newp)

    def test_reanchored_dropped_or_overcredited_liability_reject(self):
        # Quarantine/locked summary can't silently recategorize funds.
        for off in (-1,-9,-17,-25):
            bad=bytearray(self.raw);bad[off]^=1
            newp=dict(self.pins,expected_root=framed(PQL2_DOMAIN,bytes(bad)))
            with self.subTest(offset=off),self.assertRaises(Reject):
                check_import(bytes(bad),**newp)

    def test_independent_pin_validation_and_strict_types(self):
        for k,v in self.pins.items():
            if k=="expected_issued": changed=v+1
            else:changed=bytes([v[0]^1])+v[1:]
            with self.subTest(key=k),self.assertRaises(Reject):
                check_import(self.raw,**dict(self.pins,**{k:changed}))
        for v in (None,bytearray(self.raw),b"",self.raw+b"junk"):
            with self.assertRaises(Reject):check_import(v,**self.pins)
        with self.assertRaises(Reject):check_import(self.raw,**dict(self.pins,expected_issued=True))

    def test_two_forks_exact_nonce_reorg_does_not_unlock_liabilities(self):
        with self.open() as store:
            genesis,gen=store.active()
            self.assertEqual(gen,1)
            a=store.simulate_append(genesis,0,bytes([1])*32)
            b=store.simulate_append(a,0,bytes([2])*32)
            c=store.simulate_append(genesis,0,bytes([3])*32)
            self.assertEqual(store.inspect_nonces(b),(19,29))
            self.assertEqual(store.inspect_nonces(c),(18,29))
            self.assertEqual(store.simulate_choose_tip(b,expected_generation=1),2)
            self.assertEqual(store.simulate_choose_tip(c,expected_generation=2),3)
            self.assertEqual(store.inspect_liabilities(),self.imp.liabilities)
            self.assertEqual(store.active(),(c,3))
        with self.open() as store:
            self.assertEqual(store.active(),(c,3))
            self.assertEqual(store.inspect_nonces(b),(19,29))
            self.assertEqual(store.inspect_liabilities(),self.imp.liabilities)

    def test_quarantined_never_advances_even_on_sibling_fork(self):
        with self.open() as store:
            with self.assertRaises(Reject):store.simulate_append(store.genesis,1,bytes([1])*32)
            self.assertEqual(store.inspect_nonces(store.genesis),(17,29))

    def test_cold_retry_same_parent_and_op_idempotent(self):
        with self.open() as store:
            original=store.simulate_append(store.genesis,0,bytes([7])*32)
            self.assertEqual(store.simulate_append(store.genesis,0,bytes([7])*32),original)
        with self.open() as store:
            self.assertEqual(store.simulate_append(store.genesis,0,bytes([7])*32),original)
            self.assertEqual(store.db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],2)

    def test_stale_generation_refuses_cas_and_unknown_tip(self):
        with self.open() as store:
            a=store.simulate_append(store.genesis,0,bytes([7])*32)
            self.assertEqual(store.simulate_choose_tip(a,expected_generation=1),2)
            with self.assertRaises(Reject):store.simulate_choose_tip(store.genesis,expected_generation=1)
            with self.assertRaises(Reject):store.simulate_choose_tip(bytes([91])*48,expected_generation=2)
            self.assertEqual(store.active(),(a,2))

    def test_irreversible_observation_not_rewound_by_branch_switch(self):
        with self.open() as store:
            a=store.simulate_append(store.genesis,0,bytes([1])*32)
            b=store.simulate_append(store.genesis,0,bytes([2])*32)
            store.simulate_choose_tip(a,expected_generation=1)
            self.assertEqual(store.observe_irreversible_effect(bytes([3])*32),"FIRST_OBSERVATION")
            store.simulate_choose_tip(b,expected_generation=2)
            self.assertEqual(store.observe_irreversible_effect(bytes([3])*32),"ALREADY_OBSERVED")
        with self.open() as store:
            self.assertEqual(store.observe_irreversible_effect(bytes([3])*32),"ALREADY_OBSERVED")

    def test_sqlite_foreign_trigger_or_view_refuses_open(self):
        with self.open() as store: pass
        db=sqlite3.connect(self.path)
        db.execute("CREATE TRIGGER poison AFTER INSERT ON nodes BEGIN DELETE FROM effects; END")
        db.commit();db.close()
        with self.assertRaises(Reject):self.open()

    def test_cold_reject_corrupt_nonce_or_active_pointer(self):
        with self.open() as store:
            a=store.simulate_append(store.genesis,0,bytes([1])*32)
            store.simulate_choose_tip(a,expected_generation=1)
        db=sqlite3.connect(self.path)
        db.execute("UPDATE active SET tip=?",(bytes([99])*48,))
        db.commit();db.close()
        with self.assertRaises(Reject):self.open()

    def test_import_pin_is_required_on_reopen(self):
        with self.open() as store:pass
        other=replace(self.imp,root=bytes([88])*48)
        with self.assertRaises(Reject): ResearchForkStore(self.path,other)

    def test_refuse_symlinked_sqlite(self):
        target=self.dir/"real.sqlite"
        with ResearchForkStore(target,self.imp):pass
        self.path.symlink_to(target)
        with self.assertRaises(Reject):self.open()

    def test_real_process_exit_after_committed_append_before_ack(self):
        with self.open() as store:genesis=store.genesis
        child = r'''import os,sys
from pathlib import Path
from pq_pql2_fork_recovery import check_import, ResearchForkStore
from test_pq_pql2_fork_recovery import fixture
raw,pins,_,_=fixture()
with ResearchForkStore(Path(sys.argv[1]),check_import(raw,**pins)) as db:
    db.simulate_append(db.genesis,0,bytes([44])*32)
os._exit(0)
'''
        proc=subprocess.run([sys.executable,"-c",child,str(self.path)],
                            cwd=Path(__file__).parent,timeout=20,capture_output=True)
        self.assertEqual(proc.returncode,0,proc.stderr.decode())
        with self.open() as store:
            self.assertEqual(store.db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],2)
            self.assertEqual(store.active(),(genesis,1))  # no unauthorized auto-tip switch

    def test_real_process_exit_after_commit_of_tip_cas(self):
        with self.open() as store:
            a=store.simulate_append(store.genesis,0,bytes([23])*32)
        child=r'''import os,sys
from pathlib import Path
from pq_pql2_fork_recovery import check_import, ResearchForkStore
from test_pq_pql2_fork_recovery import fixture
raw,pins,_,_=fixture()
with ResearchForkStore(Path(sys.argv[1]),check_import(raw,**pins)) as db:
    db.simulate_choose_tip(bytes.fromhex(sys.argv[2]),expected_generation=1)
os._exit(0)
'''
        proc=subprocess.run([sys.executable,"-c",child,str(self.path),a.hex()],
                            cwd=Path(__file__).parent,timeout=20,capture_output=True)
        self.assertEqual(proc.returncode,0,proc.stderr.decode())
        with self.open() as store:self.assertEqual(store.active(),(a,2))

    def test_concurrent_writers_same_tip_one_generation_advance(self):
        with self.open() as store:
            a=store.simulate_append(store.genesis,0,bytes([15])*32)
        child=r'''import sys
from pathlib import Path
from pq_pql2_fork_recovery import check_import, ResearchForkStore, Reject
from test_pq_pql2_fork_recovery import fixture
raw,pins,_,_=fixture()
with ResearchForkStore(Path(sys.argv[1]),check_import(raw,**pins)) as db:
    try: db.simulate_choose_tip(bytes.fromhex(sys.argv[2]),expected_generation=1);sys.exit(0)
    except Reject:sys.exit(3)
'''
        procs=[subprocess.Popen([sys.executable,"-c",child,str(self.path),a.hex()],
                                cwd=Path(__file__).parent,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
               for _ in range(8)]
        for p in procs: p.communicate(timeout=25)
        codes=[p.returncode for p in procs]
        self.assertEqual(codes.count(0),1,codes)
        self.assertEqual(codes.count(3),7,codes)
        with self.open() as store:self.assertEqual(store.active(),(a,2))

    def test_post_open_foreign_meta_mutation_refuses_new_write(self):
        with self.open() as db:
            with closing(sqlite3.connect(self.path)) as second:
                second.execute("UPDATE meta SET value=? WHERE key='import'",(bytes([3])*48,))
                second.commit()
            with self.assertRaises(Reject):
                db.simulate_append(db.genesis,0,bytes([4])*32)
        with self.assertRaises(Reject):self.open()

    def test_foreign_new_db_refuses_before_enabling_wal(self):
        with closing(sqlite3.connect(self.path)) as second:
            second.execute("CREATE TABLE stranger (a INTEGER)")
            second.commit()
        with self.assertRaises(Reject):self.open()
        with closing(sqlite3.connect(self.path)) as second:
            self.assertEqual(second.execute("PRAGMA journal_mode").fetchone()[0],"delete")

    def test_full_128_accounts_256_liabilities_import_parser(self):
        count=128; lcount=256
        olds=[i.to_bytes(32,"big") for i in range(1,count+1)]
        records=[]; liabilities=[]; totalspend=totalq=0
        for i,old in enumerate(olds):
            balance=10; account=old+U(balance)+U(9+i)+U(1)
            if i%2:
                pq=bytes(32); status=b"\x00"
                aid=hashlib.sha256(b"TRNM/PQ/Quarantine/v1\x00"+NEWNET+old).digest()
                totalq+=balance
            else:
                pq=hashlib.sha256(b"pq"+old).digest();status=b"\x01"
                aid=hashlib.sha256(b"TRNM/PQ/Account/v1\x00"+NEWNET+old+pq).digest()
                totalspend+=balance
            records.append(status+aid+pq+account+U(2))
        for i in range(lcount):
            liabilities.append((i+1).to_bytes(32,"big")+olds[i%count]+U(1)+U(1)+bytes([1+i%4]))
        total=count*10+lcount
        sd=bytes([8])*48; gid=bytes([9])*48
        raw=(b"PQL2\x01"+NEWNET+PROFILE+HEAD+WITHDRAW+sd+gid+
             count.to_bytes(2,"big")+b"".join(records)+lcount.to_bytes(2,"big")+
             b"".join(liabilities)+U(total)+U(totalq)+U(lcount))
        pins=dict(expected_root=framed(PQL2_DOMAIN,raw),expected_source_digest=sd,
                  expected_genesis_id=gid,expected_network=NEWNET,
                  expected_profile=PROFILE,expected_old_head=HEAD,
                  expected_withdrawal_head=WITHDRAW,expected_issued=total)
        view=check_import(raw,**pins)
        self.assertEqual((len(view.accounts),len(view.liabilities),view.issued),(128,256,total))
        self.assertEqual(view.quarantine,totalq)
        bigdb=self.dir/"large.sqlite"
        with ResearchForkStore(bigdb,view) as sim:
            self.assertEqual(sim.inspect_nonces(sim.genesis)[0],9)
            self.assertEqual(sim.inspect_nonces(sim.genesis)[127],136)
            with self.assertRaises(Reject):sim.simulate_append(sim.genesis,1,bytes([4])*32)

    def test_full_snapshot_rollback_still_undetectable_without_external_anchor(self):
        # Deliberate unclosed blocker: physically replace ALL DB+WAL state with an
        # internally valid earlier copy. Local root cannot prove nonrollback.
        with self.open() as store:pass
        backup=self.dir/"backup.sqlite"
        with closing(sqlite3.connect(self.path)) as src,closing(sqlite3.connect(backup)) as dest:
            src.backup(dest)
        with self.open() as store:
            a=store.simulate_append(store.genesis,0,bytes([1])*32)
            store.simulate_choose_tip(a,expected_generation=1)
        for suffix in ("-wal","-shm"):
            p=Path(str(self.path)+suffix)
            if p.exists():p.unlink()
        os.replace(backup,self.path)
        with self.open() as store:self.assertEqual(store.active(),(store.genesis,1))
        # This is an observed REPLAY RISK, not a passing anti-rollback guarantee.


if __name__ == '__main__':
    unittest.main()
