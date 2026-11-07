"""Real ML-DSA-65 PPH1 checks with durable local observation, crash and clone negatives."""
from __future__ import annotations
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
import multiprocessing as mp
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pq_envelope import Reject,public_key_id
from pq_peer_session import PeerHello,sign_hello
from pq_peer_replay import LocalPeerReplayJournal,SCHEMA

NETWORK=bytes(range(32));GENESIS=bytes(range(32,64));PROFILE=bytes(range(64,96))


def consume_process(args):
    db,frame,verify=args
    j=LocalPeerReplayJournal(Path(db))
    try:return j.record(frame,**verify)[0]
    finally:j.close()


def crash_after_commit(args):
    try:
        consume_process(args)
    except Exception:
        os._exit(9)
    os._exit(0) # no observable caller ACK even though SQLite write committed

class PeerReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="pq-peer-replay-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name)
        cls.secret=cls.root/"remote.secret"
        cls.public=cls.root/"remote.public"
        subprocess.run(["openssl","genpkey","-algorithm","ML-DSA-65","-out",str(cls.secret)],check=True,capture_output=True,timeout=15)
        subprocess.run(["openssl","pkey","-in",str(cls.secret),"-pubout","-out",str(cls.public)],check=True,capture_output=True,timeout=15)
        cls.pem=cls.public.read_bytes()
        cls.sender=public_key_id(cls.pem)
        cls.receiver=bytes([0x55])*32
        cls.tag=bytes([0x61])*32 # test fixture: independently trusted TLS exporter supplied by caller
        cls.base=PeerHello(NETWORK,GENESIS,PROFILE,cls.sender,cls.receiver,cls.tag,2,7,1040,bytes([0x51])*32)
        cls.frame=sign_hello(cls.base,private_key_path=cls.secret)
        cls.verify=dict(remote_public_pem=cls.pem,expected_network=NETWORK,
                        expected_genesis=GENESIS,expected_profile=PROFILE,
                        expected_remote_key_id=cls.sender,expected_local_key_id=cls.receiver,
                        independently_verified_tls_channel_tag=cls.tag,
                        expected_generation=2,expected_sequence=7,now=1000)

    def newdb(self):
        return self.root/(next(tempfile._get_candidate_names())+".sqlite")

    def test_local_first_exact_retry_and_cold_reopen(self):
        db=self.newdb();j=LocalPeerReplayJournal(db)
        try:
            a,h=j.record(self.frame,**self.verify)
            self.assertEqual(a,"FIRST_RECORD")
            b,h2=j.record(self.frame,**self.verify)
            self.assertEqual((b,h2),("ALREADY_RECORDED",h))
        finally:j.close()
        j=LocalPeerReplayJournal(db)
        try:self.assertEqual(j.record(self.frame,**self.verify)[0],"ALREADY_RECORDED")
        finally:j.close()

    def test_eight_real_processes_one_first_seven_exact_retries(self):
        db=self.newdb();j=LocalPeerReplayJournal(db);j.close()
        context=mp.get_context("spawn")
        args=(str(db),self.frame,self.verify)
        with ProcessPoolExecutor(max_workers=8,mp_context=context) as pool:
            results=list(pool.map(consume_process,[args]*8))
        self.assertEqual(results.count("FIRST_RECORD"),1)
        self.assertEqual(results.count("ALREADY_RECORDED"),7)

    def test_committed_without_ack_is_not_reissued_after_crash(self):
        db=self.newdb();j=LocalPeerReplayJournal(db);j.close()
        proc=mp.get_context("spawn").Process(target=crash_after_commit,args=((str(db),self.frame,self.verify),))
        proc.start();proc.join(timeout=8)
        if proc.is_alive():proc.kill();proc.join()
        self.assertEqual(proc.exitcode,0)
        j=LocalPeerReplayJournal(db)
        try:self.assertEqual(j.record(self.frame,**self.verify)[0],"ALREADY_RECORDED")
        finally:j.close()

    def test_conflicting_same_sequence_and_stale_generation_reject(self):
        db=self.newdb();j=LocalPeerReplayJournal(db)
        try:
            j.record(self.frame,**self.verify)
            forged=sign_hello(replace(self.base,nonce=bytes([3])*32),private_key_path=self.secret)
            with self.assertRaises(Reject):j.record(forged,**self.verify)
            newer=replace(self.base,sequence=8,nonce=bytes([9])*32)
            f=sign_hello(newer,private_key_path=self.secret)
            self.assertEqual(j.record(f,**(self.verify|dict(expected_sequence=8)))[0],"FIRST_RECORD")
            with self.assertRaises(Reject):j.record(self.frame,**self.verify)
            nextgen=replace(self.base,generation=3,sequence=1,nonce=bytes([10])*32)
            f=sign_hello(nextgen,private_key_path=self.secret)
            self.assertEqual(j.record(f,**(self.verify|dict(expected_generation=3,expected_sequence=1)))[0],"FIRST_RECORD")
            with self.assertRaises(Reject):j.record(self.frame,**self.verify)
        finally:j.close()

    def test_failed_crypto_or_channel_or_expired_cannot_mutate_database(self):
        db=self.newdb();j=LocalPeerReplayJournal(db)
        try:
            broken=bytearray(self.frame);broken[-1]^=1
            for frame,policy in ((bytes(broken),self.verify),
                                 (self.frame,self.verify|dict(independently_verified_tls_channel_tag=bytes([4])*32)),
                                 (self.frame,self.verify|dict(now=1041))):
                with self.assertRaises(Reject):j.record(frame,**policy)
            self.assertEqual(j.db.execute('SELECT count(*) FROM peer_current').fetchone()[0],0)
        finally:j.close()

    def test_foreign_view_trigger_and_weakened_schema_cold_open_rejected(self):
        db=self.newdb();j=LocalPeerReplayJournal(db);j.close()
        c=sqlite3.connect(db)
        c.execute('CREATE VIEW sneaky AS SELECT generation FROM peer_current');c.commit();c.close()
        with self.assertRaises(Reject):LocalPeerReplayJournal(db)
        db=self.newdb();j=LocalPeerReplayJournal(db);j.close()
        c=sqlite3.connect(db)
        c.execute('CREATE TRIGGER hacked AFTER INSERT ON peer_current BEGIN DELETE FROM peer_current; END');c.commit();c.close()
        with self.assertRaises(Reject):LocalPeerReplayJournal(db)
        db=self.newdb();j=LocalPeerReplayJournal(db);j.close()
        c=sqlite3.connect(db)
        c.execute('DROP TABLE peer_current')
        c.execute('CREATE TABLE peer_current(network BLOB, remote_key_id BLOB,generation INTEGER,sequence INTEGER,statement_digest BLOB,channel_tag BLOB)')
        c.commit();c.close()
        with self.assertRaises(Reject):LocalPeerReplayJournal(db)

    def test_symlink_path_rejected_without_opening_target(self):
        db=self.newdb();j=LocalPeerReplayJournal(db);j.close()
        link=self.root/'redirect.sqlite';link.symlink_to(db)
        with self.assertRaises(Reject):LocalPeerReplayJournal(link)

    def test_single_host_journal_cannot_defeat_clone_double_first_counterexample(self):
        a=self.newdb();b=self.newdb()
        j=LocalPeerReplayJournal(a);j.close()
        # Clone only after sealed initialization. This intentionally proves the missing
        # global anti-rollback/unique-spend owner, not a passing production guarantee.
        shutil.copy2(a,b)
        ja=LocalPeerReplayJournal(a);jb=LocalPeerReplayJournal(b)
        try:
            self.assertEqual(ja.record(self.frame,**self.verify)[0],"FIRST_RECORD")
            self.assertEqual(jb.record(self.frame,**self.verify)[0],"FIRST_RECORD")
        finally:ja.close();jb.close()

if __name__=="__main__":unittest.main()
