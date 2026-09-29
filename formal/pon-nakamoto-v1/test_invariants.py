"""Operation-level counterexamples. Real files/processes; no live service or keys."""
from __future__ import annotations
import copy,concurrent.futures,json,os,sqlite3,subprocess,sys,tempfile,threading,time,unittest
from pathlib import Path
from ledger import *

class CapacityTests(unittest.TestCase):
    def test_zero_score_history_does_not_consume_pending_capacity(self):
        state=genesis_state();author=public(key(0));nonce=[0,0,0];height=1
        pending=[]
        for i in range(257):
            artifact=H('failed-candidate',u64(i));cid=contribution_id(author,FAMILY,ZERO,artifact,ZERO)
            nonce[0]+=1;pending.append(sign(key(0),nonce[0],'contribute',dict(contribution=cid,family=FAMILY,parent_release=ZERO,artifact=artifact,size=1,components_root=ZERO,submission_round=0)))
            for evaluator in [1,2]:
                nonce[evaluator]+=1;pending.append(sign(key(evaluator),nonce[evaluator],'evaluate',dict(contribution=cid,plan=PLAN,evidence=H('failed-eval',u64(i)),score=0)))
            if len(pending)>=252 or i==256:
                state,_=execute(state,pending,height,author,H('capacity-parent',u64(height)));pending=[];height+=1
        self.assertEqual(sum(k.startswith('contribution:')for k in state),257)
        self.assertEqual(sum(candidate_active(v,state['model:current'],height)for k,v in state.items()if k.startswith('contribution:')),0)
        first=H('failed-candidate',u64(0));cid=contribution_id(author,FAMILY,ZERO,first,ZERO)
        with self.assertRaisesRegex(ValueError,'DUPLICATE'):
            execute(state,[sign(key(0),nonce[0]+1,'contribute',dict(contribution=cid,family=FAMILY,parent_release=ZERO,artifact=first,size=1,components_root=ZERO,submission_round=0))],height+1,author,H("capacity-parent",u64(height+1)))

    def test_generation_retirement_keeps_claim_authority_in_release_root(self):
        state={'model:current':'11'*32,'contribution:a':{'parent':'00'*32,'status':'adopted','owner':'22'*32},'artifact:'+('00'*32)+':0:x':'a','release:kept':{'root':'33'*32,'claims':{},'remaining':1}}
        retire_candidates(state,2)
        self.assertNotIn('contribution:a',state);self.assertIn('release:kept',state)

    def test_expiry_releases_capacity_without_dropping_current_parent_nullifier(self):
        state={'model:current':'00'*32,'contribution:a':{'parent':'00'*32,'status':'submitted','score':0,'votes':{},'submitted_height':1},'artifact:'+('00'*32)+':0:x':'a'}
        retire_candidates(state,66)
        self.assertEqual(state['contribution:a']['status'],'expired')
        self.assertIn('artifact:'+('00'*32)+':0:x',state)

class CandidateWindowTests(unittest.TestCase):
    def make_candidate(self, height, artifact, round_id=None, nonce=1):
        owner=public(key(0));round_id=submission_round(height)if round_id is None else round_id
        cid=contribution_id(owner,FAMILY,ZERO,artifact,ZERO,round_id)
        return sign(key(0),nonce,'contribute',dict(contribution=cid,family=FAMILY,parent_release=ZERO,artifact=artifact,size=1,components_root=ZERO,submission_round=round_id),expiry=100000)

    def test_full_history_window_reopens_without_old_signed_replay(self):
        # Root-checked application fixture, not a claim of 512 independently trained experts.
        state=genesis_state();owner=public(key(0)).hex()
        for index in range(PARAMS['max_candidate_history_per_round']):
            art=H('zero-history-window',u64(index)).hex()
            state['contribution:'+art]={'owner':owner,'artifact':art,'components_root':ZERO.hex(),'family':FAMILY.hex(),'parent':ZERO.hex(),'votes':{},'score':0,'status':'evaluated','submitted_height':1,'submission_round':0}
            state['artifact:'+ZERO.hex()+':0:'+art]=art
        before=copy.deepcopy(state);fresh=H('new-window-candidate')
        with self.assertRaisesRegex(ValueError,'CANDIDATE_WINDOW_FULL'):
            execute_reference(state,[self.make_candidate(2,fresh)],2,public(key(0)),GENESIS)
        self.assertEqual(state,before)
        height=PARAMS['candidate_round_blocks']
        with self.assertRaisesRegex(ValueError,'SUBMISSION_ROUND'):
            execute_reference(state,[self.make_candidate(2,fresh)],height,public(key(0)),GENESIS)
        after,_=execute_reference(state,[self.make_candidate(height,fresh)],height,public(key(0)),GENESIS)
        self.assertEqual(sum(k.startswith('contribution:')for k in after),1)
        self.assertEqual(sum(k.startswith('artifact:')for k in after),1)
        self.assertEqual(total_funds(after),after['meta:issued'])

    def test_round_is_part_of_contribution_and_signature_identity(self):
        art=H('same-artifact')
        a=self.make_candidate(2,art);b=self.make_candidate(PARAMS['candidate_round_blocks'],art)
        self.assertNotEqual(tx_decode(a)['fields']['contribution'],tx_decode(b)['fields']['contribution'])
        self.assertNotEqual(tx_decode(a)['signature'],tx_decode(b)['signature'])

    def test_positive_evaluation_expires_and_cannot_be_adopted_late(self):
        state={'model:current':ZERO.hex(),'contribution:a':{'owner':public(key(0)).hex(),'parent':ZERO.hex(),'status':'evaluated','score':100,'votes':{},'submitted_height':1,'submission_round':0}}
        retire_candidates(state,66)
        self.assertEqual(state['contribution:a']['status'],'expired')
        self.assertEqual(state['contribution:a']['score'],0)
        self.assertFalse(candidate_active(state['contribution:a'],ZERO.hex(),66))

class InitializationTests(unittest.TestCase):
    def test_every_initialization_cut_recovers_only_our_exact_intent(self):
        for cut in ['init-intent','init-schema','init-before-commit','init-committed']:
            with self.subTest(cut=cut),tempfile.TemporaryDirectory()as path:
                code="from ledger import Ledger;import os,sys;Ledger(sys.argv[1],lambda c:os._exit(86)if c==sys.argv[2]else None)"
                p=subprocess.run([sys.executable,'-c',code,path,cut],cwd=Path(__file__).parent)
                self.assertEqual(p.returncode,86)
                ledger=Ledger(path)
                try:self.assertEqual(ledger.read_active()[0],GENESIS)
                finally:ledger.close()
                ledger=Ledger(path);ledger.close();self.assertFalse((Path(path)/'initializing.json').exists())

    def test_unmarked_empty_database_is_not_reinitialized(self):
        with tempfile.TemporaryDirectory()as path:
            sqlite3.connect(Path(path)/'ledger.sqlite').close()
            with self.assertRaisesRegex(ValueError,'INITIALIZATION_INTENT_REQUIRED'):Ledger(path)

    def test_injected_trigger_rejects_before_writable_open(self):
        import hashlib
        with tempfile.TemporaryDirectory()as path:
            ledger=Ledger(path);ledger.close();db=Path(path)/'ledger.sqlite'
            c=sqlite3.connect(db);c.execute("CREATE TRIGGER unexpected AFTER INSERT ON events BEGIN DELETE FROM events; END");c.commit();c.close()
            before=hashlib.sha256(db.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError,'SCHEMA'):Ledger(path)
            self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(),before)

    def test_wrong_initialization_context_is_rejected(self):
        with tempfile.TemporaryDirectory()as path:
            (Path(path)/'initializing.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'INITIALIZATION_CONTEXT'):Ledger(path)

class EffectLinearizationTests(unittest.TestCase):
    def test_revoke_committed_first_prevents_entry(self):
        with tempfile.TemporaryDirectory()as path:
            a=EffectJournal(Path(path)/'effects');b=EffectJournal(Path(path)/'effects');op=H('revoked-first')
            try:
                b.revoke(op)
                with self.assertRaisesRegex(ValueError,'REVOKED'):a.enter(op,H('payload'),1)
                self.assertEqual(a.db.execute('SELECT count(*) FROM effects').fetchone()[0],0)
            finally:a.db.close();b.db.close()

    def test_revoker_cannot_commit_inside_entry_transaction(self):
        with tempfile.TemporaryDirectory()as path:
            db=Path(path)/'effects';journal=EffectJournal(db);op=H('entry-first');started=threading.Event();committed=threading.Event();future=None;observations=[]
            def revoker():
                other=EffectJournal(db)
                try:started.set();other.revoke(op);committed.set()
                finally:other.db.close()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1)as pool:
                def interleave(sql):
                    nonlocal future
                    if sql.startswith('INSERT INTO effects'):
                        future=pool.submit(revoker);observations.append(('started',started.wait(3)))
                        observations.append(('committed_inside',committed.wait(.05)))
                journal.db.set_trace_callback(interleave);journal.enter(op,H('payload'),1)
                journal.db.set_trace_callback(None);future.result(timeout=5)
            self.assertEqual(observations,[('started',True),('committed_inside',False)])
            self.assertTrue(committed.is_set())
            with self.assertRaisesRegex(ValueError,'REVOKED'):journal.enter(op,H('payload'),1)
            self.assertEqual(journal.db.execute('SELECT count(*) FROM effects').fetchone()[0],1);journal.db.close()

    def test_crash_after_entry_commit_rejects_replay(self):
        with tempfile.TemporaryDirectory()as path:
            db=Path(path)/'effects';op=H('crash-effect')
            code="from ledger import *;import os,sys;j=EffectJournal(sys.argv[1]);j.enter(bytes.fromhex(sys.argv[2]),H('payload'),1);os._exit(86)"
            p=subprocess.run([sys.executable,'-c',code,str(db),op.hex()],cwd=Path(__file__).parent);self.assertEqual(p.returncode,86)
            journal=EffectJournal(db)
            with self.assertRaisesRegex(ValueError,'OPERATION_ALREADY_ENTERED'):journal.enter(op,H('payload'),1)
            journal.db.close()

class RestartForkTests(unittest.TestCase):
    def test_admitted_before_activation_is_selected_on_restart(self):
        with tempfile.TemporaryDirectory()as path:
            ledger=Ledger(path);h,txs,p=ledger.make(GENESIS,[]);bid=ledger.admit(h,txs,p,PARAMS['genesis_timestamp']+10000);ledger.close()
            ledger=Ledger(path)
            try:
                self.assertEqual(ledger.active()[0],GENESIS);self.assertEqual(ledger.recover(),bid)
                generation=ledger.active()[1];self.assertEqual(ledger.recover(),bid);self.assertEqual(ledger.active()[1],generation)
            finally:ledger.close()

    def test_append_retains_one_physical_state_slot(self):
        with tempfile.TemporaryDirectory()as path:
            ledger=Ledger(path);tip=GENESIS
            try:
                for _ in range(6):
                    h,t,p=ledger.make(tip,[]);tip=ledger.admit(h,t,p,PARAMS['genesis_timestamp']+10000);ledger.activate(tip)
                self.assertEqual(ledger.active()[1],6)
                self.assertEqual(ledger.db.execute('SELECT count(DISTINCT generation) FROM kv').fetchone()[0],1)
                self.assertEqual(ledger.db.execute('SELECT count(*) FROM kv').fetchone()[0],len(ledger.read_active()[2]))
            finally:ledger.close()

    def test_storage_replay_beyond_4096_does_not_invent_finality(self):
        # Storage-only verified-history premise: not 4100 mined/admitted work proofs.
        with tempfile.TemporaryDirectory()as path:
            ledger=Ledger(path);state=genesis_state();root=state_root(state);parent=GENESIS
            try:
                ledger.db.execute('BEGIN IMMEDIATE')
                for height in range(1,4102):
                    bid=H('storage-fixture-block',u64(height))
                    ledger.db.execute('INSERT INTO blocks VALUES(?,?,?,?,?,?,?,?)',(bid,parent,height,(height*2).to_bytes(64,'big'),None,None,None,root));parent=bid
                    if height%128==0:ledger.db.execute('INSERT INTO snapshots VALUES(?,?)',(bid,canonical(state)))
                ledger.db.execute('COMMIT')
                self.assertEqual(state_root(ledger.state_at(parent)),root)
                # No checkpoint is trusted without its exact stored block root.
                latest=H('storage-fixture-block',u64(4096));ledger.db.execute('UPDATE snapshots SET state=? WHERE block=?',(canonical({'bad':1}),latest))
                with self.assertRaisesRegex(ValueError,'ROOT'):ledger.state_at(parent)
            finally:ledger.close()

class CheapAdmissionTests(unittest.TestCase):
    def test_transaction_count_rejects_before_root_or_work_replay(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory()as path:
            ledger=Ledger(path)
            try:
                with patch('ledger.work.verify',side_effect=AssertionError('expensive work reached')):
                    with self.assertRaisesRegex(ValueError,'LIMIT'):
                        ledger.admit(bytes(318),[b'']*257,bytes(49188),1800000000)
                self.assertEqual(ledger.db.execute('SELECT count(*) FROM blocks').fetchone()[0],1)
            finally:ledger.close()
    def test_short_envelope_rejects_before_proof(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory()as path:
            ledger=Ledger(path)
            try:
                with patch('ledger.work.verify',side_effect=AssertionError('expensive work reached')):
                    with self.assertRaisesRegex(ValueError,'LIMIT'):
                        ledger.admit(bytes(318),[bytes(158)],bytes(49188),1800000000)
            finally:ledger.close()

class DuplicateAdmissionTests(unittest.TestCase):
    def test_exact_verified_duplicate_does_not_repeat_expensive_work(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory()as path:
            ledger=Ledger(path)
            try:
                header,body,proof=ledger.make(GENESIS,[])
                bid=ledger.admit(header,body,proof,1800010000)
                with patch('ledger.work.verify',side_effect=AssertionError('duplicate replayed expensive work')):
                    self.assertEqual(ledger.admit(header,body,proof,1800010000),bid)
                self.assertEqual(ledger.db.execute('SELECT count(*) FROM blocks').fetchone()[0],2)
            finally:ledger.close()
    def test_same_block_id_with_changed_certificate_never_uses_valid_cache(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory()as path:
            ledger=Ledger(path)
            try:
                header,body,proof=ledger.make(GENESIS,[])
                ledger.admit(header,body,proof,1800010000)
                changed=proof[:20]+bytes([proof[20]^1])+proof[21:]
                with patch('ledger.work.verify',side_effect=AssertionError('changed duplicate reached heavy work')):
                    with self.assertRaisesRegex(ValueError,'DUPLICATE_CONTENT'):ledger.admit(header,body,changed,1800010000)
                self.assertEqual(ledger.db.execute('SELECT proof FROM blocks WHERE proof IS NOT NULL').fetchone()[0],proof)
            finally:ledger.close()

class StreamingReplayTests(unittest.TestCase):
    def test_missing_checkpoints_spill_and_cancel_without_height_veto(self):
        from unittest.mock import patch
        import tempfile as actual_tempfile
        factory=actual_tempfile.SpooledTemporaryFile;spools=[]
        def track(*args,**kwargs):
            spool=factory(*args,**kwargs);spools.append(spool);return spool
        with tempfile.TemporaryDirectory()as path:
            ledger=Ledger(path);state=genesis_state();root=state_root(state);tip=GENESIS
            try:
                ledger.db.execute('BEGIN IMMEDIATE')
                for height in range(1,4103):
                    bid=H('streaming-storage-premise',u64(height))
                    ledger.db.execute('INSERT INTO blocks VALUES(?,?,?,?,?,?,?,?)',(bid,tip,height,(height*2).to_bytes(64,'big'),None,None,None,root));tip=bid
                ledger.db.execute('COMMIT')
                # These are storage-authenticated premises, not generated mining proof evidence.
                def cancel(kind,count):
                    if kind=='ancestry'and count==512:raise ValueError('TEST_CANCEL')
                with patch('ledger.tempfile.SpooledTemporaryFile',side_effect=track):
                    with self.assertRaisesRegex(ValueError,'TEST_CANCEL'):ledger.state_at(tip,cancel)
                    self.assertTrue(spools[-1].closed)
                    result=ledger.state_at(tip)
                self.assertEqual(result,state);self.assertTrue(spools[-1].closed)
                self.assertTrue(spools[-1]._rolled)
                self.assertEqual(ledger.active()[0],GENESIS)
            finally:ledger.close()

if __name__=='__main__':unittest.main(verbosity=2)
