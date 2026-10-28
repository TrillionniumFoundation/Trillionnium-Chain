"""QTX1 / ML-DSA-65 fork-state adversarial regressions (offline research)."""
from dataclasses import replace
import multiprocessing
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from pq_envelope import Reject, public_key_id
from pq_transaction import Transfer, sign_transfer
from pq_branch_execution import (GenesisAccount, ResearchBranchState, _decode_txs,
                                 _encode_txs, MAX_TX_PER_BLOCK, digest)


def race_reopen(path, net, roster, signed, results, position):
    try:
        node=ResearchBranchState(Path(path),network=net,genesis_accounts=roster)
        p=node.genesis
        got=node.admit(p,500,(signed,))
        node.close()
        results[position]=(got.block_id.hex(), got.height)
    except BaseException as exc:
        results[position]=("ERROR",str(exc))


class PQBranchExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keysdir = tempfile.TemporaryDirectory(prefix="pql1-keys-")
        cls.addClassCleanup(cls.keysdir.cleanup)
        cls.keypairs=[]
        cls.net=bytes(range(1,33))
        for index in range(3):
            secret = Path(cls.keysdir.name) / f"k{index}"
            pub = Path(cls.keysdir.name) / f"p{index}"
            subprocess.run(["openssl","genpkey","-algorithm","ML-DSA-65","-out",str(secret)],
                           capture_output=True, check=True,timeout=15)
            subprocess.run(["openssl","pkey","-in",str(secret),"-pubout","-out",str(pub)],
                           capture_output=True,check=True,timeout=15)
            cls.keypairs.append((secret,pub.read_bytes()))
        cls.roster=tuple(GenesisAccount(bytes([10+i])*32, cls.keypairs[i][1],
                                        100000 if i==0 else 10000) for i in range(3))

    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix="pql1-ledger-")
        self.addCleanup(self.work.cleanup)
        self.path=Path(self.work.name)/"node.sqlite"
        self.node=ResearchBranchState(self.path,network=self.net,genesis_accounts=self.roster)
        self.addCleanup(self.node.close)

    def sign(self,sender=0,recipient=1,nonce=1,generation=1,amount=200,expiry=10000,memo=b""):
        t=Transfer(self.net,self.roster[sender].account,self.roster[recipient].account,
                   generation,nonce,expiry,amount,10000,memo)
        secret,pem=self.keypairs[sender]
        return sign_transfer(t,public_pem=pem,private_key_path=secret)

    def test_real_mldsa_transfer_commits_only_on_correct_parent(self):
        tx=self.sign()
        record=self.node.admit(self.node.genesis,100,(tx,))
        self.assertEqual(record.height,1)
        self.assertEqual(len(record.tx_ids[0]),48)
        self.assertFalse(hasattr(record,"finalized"))
        self.assertFalse(hasattr(record,"authority"))
        balances=self.node.balances(record.block_id)
        fee=100+len(tx)
        self.assertEqual(balances[self.roster[0].account.hex()],100000-200-fee)
        self.assertEqual(balances[self.roster[1].account.hex()],10200)
        self.assertEqual(self.node._state_at(record.block_id)["fees"],fee)
        self.assertEqual(sum(balances.values())+fee,120000)
        self.assertEqual(self.node.active(),(self.node.genesis,1))

    def test_alternative_forks_do_not_share_nonce_or_balance(self):
        genesis=self.node.genesis
        a=self.node.admit(genesis,100,(self.sign(amount=700),))
        b=self.node.admit(genesis,100,(self.sign(amount=900),))
        self.assertNotEqual(a.block_id,b.block_id)
        self.assertEqual(self.node.balances(a.block_id)[self.roster[1].account.hex()],10700)
        self.assertEqual(self.node.balances(b.block_id)[self.roster[1].account.hex()],10900)
        with self.assertRaises(Reject):
            self.node.admit(a.block_id,200,(self.sign(amount=600),))  # same nonce on same ancestry
        child_a=self.node.admit(a.block_id,200,(self.sign(nonce=2,amount=100),))
        self.assertEqual(self.node.observe_selected_tip(child_a.block_id,expected_prior=genesis),2)
        self.assertEqual(self.node.observe_selected_tip(b.block_id,expected_prior=child_a.block_id),3)
        self.assertEqual(self.node.balances(child_a.block_id)[self.roster[1].account.hex()],10800)
        self.assertEqual(self.node.balances(b.block_id)[self.roster[1].account.hex()],10900)
        with self.assertRaises(Reject):
            self.node.observe_selected_tip(child_a.block_id,expected_prior=genesis)
        self.assertEqual(self.node.active(),(b.block_id,3))

    def test_same_body_different_real_signatures_same_block_id(self):
        first=self.sign(memo=b"identical body")
        again=self.sign(memo=b"identical body")
        observed=self.node.admit(self.node.genesis,100,(first,))
        repeat=self.node.admit(self.node.genesis,100,(again,))
        self.assertEqual(repeat.block_id,observed.block_id)
        self.assertEqual(repeat.tx_ids,observed.tx_ids)
        self.assertEqual(self.node.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0],1)
        self.assertEqual(self.node.balances(observed.block_id)[self.roster[0].account.hex()],
                         self.node.balances(repeat.block_id)[self.roster[0].account.hex()])

    def test_second_valid_nonce_in_same_block_and_order_consistency(self):
        tx1=self.sign(amount=3)
        tx2=self.sign(nonce=2,amount=17)
        pair=self.node.admit(self.node.genesis,150,(tx1,tx2))
        self.assertEqual(self.node._state_at(pair.block_id)["accounts"][self.roster[0].account.hex()]["next_nonce"],3)
        with self.assertRaises(Reject):
            self.node.admit(self.node.genesis,150,(tx2,tx1))
        self.assertEqual(self.node.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0],1)

    def test_failed_valid_signed_transaction_does_not_publish_parent(self):
        head=self.node.active()
        cases=[(self.sign(nonce=2),), (self.sign(generation=2),),
               (self.sign(expiry=99),), (self.sign(sender=2,amount=99999),),
               (self.sign(),self.sign())]
        for txs in cases:
            with self.subTest(label=len(txs)),self.assertRaises(Reject):
                self.node.admit(self.node.genesis,100,txs)
            self.assertEqual(self.node.active(),head)
        self.assertEqual(self.node.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0],0)

    def test_mutated_purpose_signature_sender_network_or_unknown_account_reject(self):
        good=self.sign()
        cases=[good[:-1]+bytes([good[-1]^1]),
               good[:38]+bytes(32)+good[70:],
               good[:6]+bytes(32)+good[38:],
               good[:70]+bytes([87])*32+good[102:],
               good[:144]+good[144:-3487]+good[-3487:-1]]
        for bad in cases:
            with self.subTest(length=len(bad)),self.assertRaises(Reject):
                self.node.admit(self.node.genesis,200,(bad,))
        self.assertEqual(self.node.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0],0)

    def test_signed_block_framing_and_caps_fail_before_persistence(self):
        raw=self.sign()
        data=_encode_txs((raw,))
        self.assertEqual(_decode_txs(data),(raw,))
        for bad in (data[:-1],data+b"trailing",bytes([255,255])+data[2:],
                    data[:2]+bytes([255])*4+data[6:]):
            with self.subTest(length=len(bad)),self.assertRaises(Reject):
                _decode_txs(bad)
        with self.assertRaises(Reject):
            self.node.admit(self.node.genesis,200,tuple([raw]*(MAX_TX_PER_BLOCK+1)))

    def test_reopen_audits_entire_multifork_signed_history(self):
        genesis=self.node.genesis
        a=self.node.admit(genesis,100,(self.sign(amount=1),))
        b=self.node.admit(genesis,101,(self.sign(amount=2),))
        a2=self.node.admit(a.block_id,200,(self.sign(nonce=2,amount=3),))
        self.node.observe_selected_tip(a2.block_id,expected_prior=genesis)
        self.node.close()
        self.node=ResearchBranchState(self.path,network=self.net,genesis_accounts=self.roster,
                                      expected_active_tip=a2.block_id)
        self.addCleanup(self.node.close)
        self.node.audit(expected_active_tip=a2.block_id)
        self.assertEqual(self.node.active(),(a2.block_id,2))
        self.assertEqual(self.node.balances(b.block_id)[self.roster[1].account.hex()],10002)
        with self.assertRaises(Reject):
            self.node.audit(expected_active_tip=b.block_id)

    def test_foreign_schema_and_rehashed_corruption_fail_cold(self):
        a=self.node.admit(self.node.genesis,100,(self.sign(),))
        self.node.close()
        alien=sqlite3.connect(self.path)
        alien.execute("CREATE TRIGGER subvert AFTER INSERT ON blocks BEGIN DELETE FROM active; END")
        alien.commit();alien.close()
        with self.assertRaisesRegex(Reject,"DDL"):
            ResearchBranchState(self.path,network=self.net,genesis_accounts=self.roster)
        alien=sqlite3.connect(self.path)
        alien.execute("DROP TRIGGER subvert")
        alien.execute("UPDATE blocks SET state_root=? WHERE id=?",(bytes(48),a.block_id))
        alien.commit();alien.close()
        with self.assertRaises(Reject):
            ResearchBranchState(self.path,network=self.net,genesis_accounts=self.roster)

    def test_genesis_roster_change_and_file_symlink_reject(self):
        self.node.close()
        changed=(replace(self.roster[0],balance=123),)+self.roster[1:]
        with self.assertRaises(Reject):
            ResearchBranchState(self.path,network=self.net,genesis_accounts=changed)
        with self.assertRaises(Reject):
            ResearchBranchState(self.path,network=bytes([88])*32,genesis_accounts=self.roster)
        link=Path(self.work.name)/"alias.sqlite"
        link.symlink_to(self.path)
        with self.assertRaises(Reject):
            ResearchBranchState(link,network=self.net,genesis_accounts=self.roster)

    def test_replaying_nonce_after_fork_switch_depends_on_actual_parent(self):
        first=self.sign(amount=50)
        a=self.node.admit(self.node.genesis,100,(first,))
        b=self.node.admit(self.node.genesis,101,(self.sign(amount=200),))
        self.node.observe_selected_tip(a.block_id,expected_prior=self.node.genesis)
        self.node.observe_selected_tip(b.block_id,expected_prior=a.block_id)
        self.assertEqual(self.node._state_at(b.block_id)["accounts"][self.roster[0].account.hex()]["next_nonce"],2)
        with self.assertRaises(Reject):
            self.node.admit(b.block_id,200,(first,))
        correct=self.node.admit(b.block_id,200,(self.sign(nonce=2),))
        self.assertEqual(correct.height,2)

    def test_no_work_no_quantum_proof_no_final_use_authority(self):
        a=self.node.admit(self.node.genesis,100,(self.sign(),))
        for key in ("VerifiedWork","chainwork","confirmation","final_use","adoption_authorized","work_proof"):
            self.assertFalse(hasattr(a,key))
        self.assertEqual(a.current_active,False)
        self.assertEqual(self.node.active()[0],self.node.genesis)

    def test_eight_independent_processes_same_scheduled_fork_remain_identical(self):
        # Same encoded signed frame; no duplicate authority even when SQLite readers race.
        tx=self.sign()
        self.node.close()
        ctx=multiprocessing.get_context("spawn")
        with ctx.Manager() as manager:
            records=manager.dict()
            workers=[ctx.Process(target=race_reopen,args=(str(self.path),self.net,self.roster,tx,records,i)) for i in range(8)]
            for p in workers:p.start()
            for p in workers:
                p.join(timeout=25)
                if p.is_alive():p.terminate();p.join();self.fail("child timed out")
                self.assertEqual(p.exitcode,0)
            self.assertEqual(len(records),8)
            self.assertEqual(len(set(tuple(v) for v in records.values())),1,records.copy())
        self.node=ResearchBranchState(self.path,network=self.net,genesis_accounts=self.roster)
        self.addCleanup(self.node.close)
        self.assertEqual(self.node.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0],1)

    def test_crash_after_commit_before_ack_recovers_without_double_effect(self):
        tx=self.sign()
        self.node.close()
        ctx=multiprocessing.get_context("spawn")
        proc=ctx.Process(target=_crash_after_commit,args=(str(self.path),self.net,self.roster,tx))
        proc.start();proc.join(timeout=20)
        self.assertFalse(proc.is_alive())
        self.assertEqual(proc.exitcode,79)
        self.node=ResearchBranchState(self.path,network=self.net,genesis_accounts=self.roster)
        self.addCleanup(self.node.close)
        recovered=self.node.admit(self.node.genesis,300,(tx,))
        self.assertEqual(self.node.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0],1)
        self.assertEqual(self.node.balances(recovered.block_id)[self.roster[1].account.hex()],10200)

    def test_live_foreign_trigger_blocked_before_admit(self):
        tx=self.sign()
        other=sqlite3.connect(self.path)
        other.execute("CREATE TRIGGER malicious AFTER INSERT ON blocks BEGIN DELETE FROM active; END")
        other.commit();other.close()
        with self.assertRaisesRegex(Reject,"DDL"):
            self.node.admit(self.node.genesis,100,(tx,))
        self.assertEqual(self.node.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0],0)

    def test_parent_rehashed_root_alone_is_not_an_authority(self):
        first=self.node.admit(self.node.genesis,100,(self.sign(),))
        # A local attacker mutates both state payload and its state_root without
        # forging the already signed transaction or matching the original block ID.
        # Such an in-process mutation must be rejected on the NEXT admission too.
        other=sqlite3.connect(self.path)
        changed=bytearray(other.execute("SELECT state_data FROM blocks WHERE id=?",(first.block_id,)).fetchone()[0]);
        i=changed.find(b'10000')
        self.assertGreater(i,0)
        changed[i:i+5]=b'99999'
        import hashlib,json
        from pq_branch_execution import state_hash
        forged=json.loads(changed)
        other.execute("UPDATE blocks SET state_data=?,state_root=? WHERE id=?",
                      (bytes(changed),state_hash(forged),first.block_id))
        other.commit();other.close()
        with self.assertRaises(Reject):
            self.node.admit(first.block_id,200,(self.sign(nonce=2),))
        with self.assertRaises(Reject):
            self.node.observe_selected_tip(first.block_id,expected_prior=self.node.genesis)
        self.assertEqual(self.node.active()[0],self.node.genesis)


def _crash_after_commit(path,net,roster,signed):
    """A process dies before its caller receives the already durable ACK."""
    import os
    node=ResearchBranchState(Path(path),network=net,genesis_accounts=roster)
    node.admit(node.genesis,300,(signed,))
    os._exit(79)


if __name__ == "__main__": unittest.main()
