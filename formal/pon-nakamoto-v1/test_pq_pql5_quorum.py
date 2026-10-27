"""PQL5 real ML-DSA-65 signatures, owned SQLite state, and quorum rollback negatives."""
from __future__ import annotations

from contextlib import closing
import multiprocessing as mp
from pathlib import Path
import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from pq_pql5_quorum import (LocalWitness, Reject, PQL4_SIGN, PQL4_ID, PQL4_SIGNED,
    PQL4_UNSIGNED, RESP_SIGNED, ZERO48, key_id, parse_pql4,
    sign_fixture, verify_fresh_response, verify_quorum)


def witness_job(path, net, root, genesis, obs_pub, wit_pub, frame, output):
    try:
        store=LocalWitness(Path(path), network=net, import_root=root, genesis=genesis,
                           observer_pub=obs_pub, witness_pub=wit_pub)
        outcome=store.append(frame, now=1500)
        store.close()
        output.put(outcome)
    except BaseException as e:
        output.put("ERR:"+str(e))


class PQL5ActualTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_context=tempfile.TemporaryDirectory(prefix="pql5-realkeys-")
        cls.addClassCleanup(cls.key_context.cleanup)
        root=Path(cls.key_context.name)
        cls.keys={}
        for name in ("observer","w0","w1","w2","attacker","ed25519"):
            secret=root/(name+".private.pem")
            public=root/(name+".public.pem")
            kind="ED25519" if name=="ed25519" else "ML-DSA-65"
            subprocess.run(["openssl","genpkey","-algorithm",kind,"-out",str(secret)],
                           check=True,capture_output=True,timeout=15)
            subprocess.run(["openssl","pkey","-in",str(secret),"-pubout","-out",str(public)],
                           check=True,capture_output=True,timeout=15)
            cls.keys[name]=(secret,public.read_bytes())
        cls.network=bytes(range(1,33))
        cls.root=bytes([0x22])*48
        cls.genesis=bytes([0x33])*48
        cls.tip1=bytes([0x44])*48
        cls.tip2=bytes([0x45])*48
        cls.state1=bytes([0x55])*48
        cls.state2=bytes([0x56])*48
        cls.observer_pub=cls.keys["observer"][1]
        cls.observer_id=key_id(cls.observer_pub)
        cls.roster={key_id(cls.keys[f"w{i}"][1]):cls.keys[f"w{i}"][1] for i in range(3)}

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="pql5-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.paths=[Path(self.tmp.name)/f"w{i}.sqlite" for i in range(3)]
        self.stores=[self.open_store(i) for i in range(3)]
        self.addCleanup(self.close_stores)
        self.frame1,self.fid1=self.make_frame(1,ZERO48,self.tip1,self.state1,1)
        self.frame2,self.fid2=self.make_frame(2,self.fid1,self.tip2,self.state2,2)

    def close_stores(self):
        for w in self.stores:
            if w is not None:
                w.close()
        self.stores=[None]*3

    def open_store(self,i):
        return LocalWitness(self.paths[i],network=self.network,import_root=self.root,
                            genesis=self.genesis,observer_pub=self.observer_pub,
                            witness_pub=self.keys[f"w{i}"][1])

    def make_frame(self,seq,previous,tip,digest,generation,expiry=3000):
        raw=(b"PQL4\x01\x65\x00\x00"+self.network+self.root+self.genesis+tip
             +generation.to_bytes(8,"big")+seq.to_bytes(8,"big")
             +previous+digest+expiry.to_bytes(8,"big")+self.observer_id)
        self.assertEqual(len(raw),PQL4_UNSIGNED)
        sig=sign_fixture(self.keys["observer"][0],PQL4_SIGN+raw)
        frame=raw+len(sig).to_bytes(2,"big")+sig
        self.assertEqual(len(frame),PQL4_SIGNED)
        fid=__import__("hashlib").sha384(PQL4_ID+raw).digest()
        self.assertEqual(parse_pql4(frame,self.observer_pub,now=1500).frontier_id,fid)
        return frame,fid

    def append(self,frame,which=(0,1,2)):
        return [self.stores[i].append(frame,now=1500) for i in which]

    def response(self,i,challenge,now=1500):
        return (key_id(self.keys[f"w{i}"][1]),
                self.stores[i].observe(challenge=challenge,now=now,
                    witness_pub=self.keys[f"w{i}"][1], witness_secret=self.keys[f"w{i}"][0]))

    def check(self, replies, *, sequence=1, frontier=None, challenge=None, now=1500, roster=None):
        return verify_quorum(replies,roster=self.roster if roster is None else roster,
            network=self.network,root=self.root,genesis=self.genesis,
            challenge=bytes([0x66])*32 if challenge is None else challenge,now=now,
            expected_sequence=sequence,
            expected_frontier_id=self.fid1 if frontier is None else frontier)

    def test_real_pql4_and_fresh_quorum_2_of_3(self):
        self.assertEqual(self.append(self.frame1),["FIRST_RECORD"]*3)
        c=bytes([0x66])*32
        replies=[self.response(i,c) for i in (0,1)]
        v=self.check(replies)
        self.assertEqual(v.head.sequence,1)
        self.assertEqual(v.head.frontier_id,self.fid1)
        self.assertEqual(len(v.responding),2)
        self.assertFalse(hasattr(v,"final_use"))
        self.assertFalse(hasattr(v,"chainwork"))
        self.assertEqual(len(replies[0][1]),RESP_SIGNED)

    def test_live_old_state_rejected_against_two_fresh_witnesses(self):
        self.append(self.frame1)
        self.append(self.frame2)
        c=bytes([0x66])*32
        replies=[self.response(i,c) for i in range(3)]
        self.assertEqual(self.check(replies,sequence=2,frontier=self.fid2).head.sequence,2)
        # Roll back PQL3 bytes AND local trusted pointer: independently live signers do not.
        with self.assertRaises(Reject):
            self.check(replies,sequence=1,frontier=self.fid1)

    def test_one_witness_offline_two_live_continue(self):
        self.append(self.frame1)
        self.append(self.frame2,which=(0,1))
        c=bytes([0x66])*32
        reply=[self.response(i,c) for i in (0,1)]
        self.assertEqual(self.check(reply,sequence=2,frontier=self.fid2).head.sequence,2)
        with self.assertRaises(Reject):
            self.check([self.response(i,c) for i in (1,2)],sequence=1)

    def test_one_witness_rolled_back_fresh_signed_majority_recovers(self):
        self.append(self.frame1)
        backup=Path(self.tmp.name)/"old-w2.sqlite"
        with closing(sqlite3.connect(backup)) as dst:
            self.stores[2].db.backup(dst)
        self.append(self.frame2)
        self.close_stores()
        for suffix in ("-wal","-shm"):
            Path(str(self.paths[2])+suffix).unlink(missing_ok=True)
        shutil.copyfile(backup,self.paths[2])
        self.stores=[self.open_store(i) for i in range(3)]
        c=bytes([0x66])*32
        latest=[self.response(i,c) for i in range(3)]
        self.assertEqual(self.check(latest,sequence=2,frontier=self.fid2).head.sequence,2)

    def test_two_witness_clones_remain_a_real_unclosed_attack(self):
        self.append(self.frame1)
        snapshots=[]
        for i in (0,1):
            dest=Path(self.tmp.name)/f"snapshot-{i}.sqlite"
            with closing(sqlite3.connect(dest)) as dst:self.stores[i].db.backup(dst)
            snapshots.append(dest)
        self.append(self.frame2)
        self.close_stores()
        for i in (0,1):
            for suffix in ("-wal","-shm"):
                Path(str(self.paths[i])+suffix).unlink(missing_ok=True)
            shutil.copyfile(snapshots[i],self.paths[i])
        self.stores=[self.open_store(i) for i in range(3)]
        c=bytes([0x66])*32
        replies=[self.response(i,c) for i in range(3)]
        with self.assertRaises(Reject):
            self.check(replies,sequence=2,frontier=self.fid2)
        # The unmodified witness can be unreachable/censored, leaving two cloned stores.
        # NEGATIVE scientific result: if 2 distinct operator storage/keys are rewound,
        # a stale head can obtain 2 fresh signatures. Not an antirollback theorem.
        self.assertEqual(self.check(replies[:2],sequence=1,frontier=self.fid1).head.sequence,1)

    def test_wrong_challenge_expiry_duplicate_and_bad_signature(self):
        self.append(self.frame1)
        c=bytes([0x66])*32
        a,b=self.response(0,c),self.response(1,c)
        for bad in (a[1][:-1]+bytes([a[1][-1]^1]),
                    a[1][:10]+bytes([a[1][10]^1])+a[1][11:],
                    a[1]+b"x",a[1][:-1],b"BAD"):
            with self.subTest(size=len(bad)),self.assertRaises(Reject):
                self.check([(a[0],bad),b])
        with self.assertRaises(Reject):self.check([a,b],challenge=bytes([7])*32)
        with self.assertRaises(Reject):self.check([a,b],now=1531)
        with self.assertRaises(Reject):self.check([a,a])
        with self.assertRaises(Reject):self.check([a])

    def test_classical_key_roster_and_operator_substitution_reject(self):
        self.append(self.frame1)
        c=bytes([0x66])*32
        two=[self.response(i,c) for i in (0,1)]
        with self.assertRaises(Reject):
            self.check(two,roster={**self.roster, bytes([9])*32:b"bad"})
        key=key_id(self.keys["attacker"][1])
        forged=dict(self.roster)
        forged.pop(next(iter(forged)))
        forged[key]=self.keys["attacker"][1]
        with self.assertRaises(Reject):self.check(two,roster=forged)
        with self.assertRaises(Reject):
            key_id(self.keys["ed25519"][1])
        with self.assertRaises(Reject):
            self.stores[0].observe(challenge=c,now=1500,
                  witness_pub=self.keys["attacker"][1],witness_secret=self.keys["attacker"][0])

    def test_pql4_false_signature_context_and_gap_refuse(self):
        self.append(self.frame1)
        fake=self.frame1[:-1]+bytes([self.frame1[-1]^1])
        with self.assertRaises(Reject):self.stores[0].append(fake,now=1500)
        wrong,_=self.make_frame(2,self.fid1,bytes([4])*48,self.state2,2)
        with self.assertRaises(Reject):
            self.stores[1].append(self.make_frame(3,self.fid1,self.tip2,self.state2,2)[0],now=1500)
        with self.assertRaises(Reject):self.stores[0].append(self.frame2,now=4000)
        changed_network=self.frame2[:9]+bytes([self.frame2[9]^1])+self.frame2[10:]
        with self.assertRaises(Reject):self.stores[0].append(changed_network,now=1500)
        self.assertEqual(self.stores[0].append(self.frame1,now=1500),"ALREADY_RECORDED")
        self.assertEqual(self.stores[0].append(self.frame2,now=1500),"FIRST_RECORD")
        with self.assertRaises(Reject):self.stores[0].append(wrong,now=1500)

    def test_connection_temp_trigger_never_erases_acknowledged_witness(self):
        store=self.stores[0]
        store.db.execute("CREATE TEMP TRIGGER erase AFTER INSERT ON events "
                         "BEGIN DELETE FROM events; END")
        with self.assertRaisesRegex(Reject, "temporary witness"):
            store.append(self.frame1,now=1500)
        self.assertEqual(store.db.execute("SELECT count(*) FROM main.events").fetchone()[0],0)

    def test_connection_temp_table_cannot_shadow_witness_history(self):
        store=self.stores[0]
        store.db.execute("CREATE TEMP TABLE events(seq INTEGER PRIMARY KEY, "
                         "fid BLOB NOT NULL, signed_frame BLOB NOT NULL)")
        with self.assertRaisesRegex(Reject, "temporary witness"):
            store.append(self.frame1,now=1500)
        with self.assertRaisesRegex(Reject, "temporary witness"):
            store.observe(challenge=bytes([0x66])*32,now=1500,
                          witness_pub=self.keys["w0"][1],
                          witness_secret=self.keys["w0"][0])
        self.assertEqual(store.db.execute("SELECT count(*) FROM main.events").fetchone()[0],0)

    def test_file_moved_inside_transaction_never_acks_signed_frontier(self):
        store=self.stores[0]
        before=store._audit
        moved=Path(self.tmp.name)/"detached-w0.sqlite"
        relocated=False

        def move_after_audit():
            nonlocal relocated
            result=before()
            if not relocated:
                os.rename(self.paths[0],moved)
                relocated=True
            return result

        with patch.object(store,"_audit",side_effect=move_after_audit):
            with self.assertRaisesRegex(Reject, "disappeared"):
                store.append(self.frame1,now=1500)
        self.assertTrue(moved.exists())

    def test_cold_readback_and_foreign_ddl_refuse(self):
        self.append(self.frame1)
        self.close_stores()
        self.stores=[self.open_store(i) for i in range(3)]
        with closing(sqlite3.connect(self.paths[0])) as db:
            db.execute("CREATE TRIGGER hostile AFTER INSERT ON events BEGIN DELETE FROM pins; END")
        with self.assertRaises(Reject):self.stores[0].append(self.frame2,now=1500)
        with self.assertRaises(Reject):self.open_store(0)

    def test_symlink_and_empty_owned_db_refuse(self):
        link=Path(self.tmp.name)/"linked.sqlite"
        link.symlink_to(self.paths[0])
        with self.assertRaises(Reject):LocalWitness(link,network=self.network,
             import_root=self.root,genesis=self.genesis,observer_pub=self.observer_pub,
             witness_pub=self.keys["w0"][1])
        foreign=Path(self.tmp.name)/"foreign.sqlite"
        foreign.touch()
        with self.assertRaises((Reject,sqlite3.Error)):
            LocalWitness(foreign,network=self.network,import_root=self.root,
                         genesis=self.genesis,observer_pub=self.observer_pub,
                         witness_pub=self.keys["w0"][1])

    def test_concurrent_eight_real_processes_one_append(self):
        self.append(self.frame1,which=(0,))
        self.stores[0].close();self.stores[0]=None
        ctx=mp.get_context("spawn");q=ctx.Queue()
        jobs=[ctx.Process(target=witness_job,args=(str(self.paths[0]),self.network,self.root,
            self.genesis,self.observer_pub,self.keys["w0"][1],self.frame2,q)) for _ in range(8)]
        for p in jobs:p.start()
        for p in jobs:p.join(20);self.assertEqual(p.exitcode,0)
        outcomes=[q.get(timeout=5) for _ in jobs]
        self.assertEqual(outcomes.count("FIRST_RECORD"),1,outcomes)
        self.assertEqual(outcomes.count("ALREADY_RECORDED"),7,outcomes)
        self.stores[0]=self.open_store(0)

    def test_pql5_every_unsigned_byte_mutation_and_wrong_purpose(self):
        self.append(self.frame1)
        c=bytes([0x66])*32
        a,b=self.response(0,c),self.response(1,c)
        for i in range(269):
            raw=bytearray(a[1]);raw[i]^=1
            with self.subTest(i=i),self.assertRaises(Reject):
                self.check([(a[0],bytes(raw)),b])
        with self.assertRaises(Reject):
            self.check([(a[0],a[1][:269]+b"\x00\x00"+a[1][271:]),b])

    def test_pql4_competing_signed_same_sequence_is_not_accepted_twice(self):
        self.append(self.frame1)
        alt,alt_id=self.make_frame(2,self.fid1,bytes([9])*48,self.state2,2)
        self.append(self.frame2,which=(0,1))
        self.append(alt,which=(2,))
        c=bytes([0x66])*32
        r=[self.response(i,c) for i in range(3)]
        self.assertEqual(self.check(r,sequence=2,frontier=self.fid2).head.frontier_id,self.fid2)
        with self.assertRaises(Reject):
            self.check(r[1:],sequence=2,frontier=alt_id)
        with self.assertRaises(Reject):
            self.stores[2].append(self.frame2,now=1500)

    def test_empty_witnesses_do_not_grant_a_genesis_checkpoint(self):
        c=bytes([0x66])*32
        with self.assertRaises(Reject):
            self.check([self.response(i,c) for i in (0,1)],sequence=0,frontier=ZERO48)

    def test_no_trusted_prod_authority_from_local_quorum(self):
        self.append(self.frame1)
        got=self.check([self.response(i,bytes([0x66])*32) for i in (0,1)])
        for field in ("accept_block","mint","final_use","rollback_authorized",
                      "production_activated","independent_operators","chainwork"):
            self.assertFalse(hasattr(got,field))


if __name__=="__main__":unittest.main()
