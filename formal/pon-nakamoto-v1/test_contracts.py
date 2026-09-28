from __future__ import annotations
import copy,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from contract_wire import *
from ledger import *

class CodecTests(unittest.TestCase):
    def test_fixed_vectors_without_native_dependency(self):
        d=Path(__file__).parent/'vectors';v=json.loads((d/'expected.json').read_text())
        self.assertEqual(H('challenge',(d/'header.bin').read_bytes()).hex(),v['header']['challenge'])
        for x in v['transactions']:
            b=(d/x['file']).read_bytes();self.assertEqual(H('tx-id',b).hex(),x['id']);self.assertEqual(tx_decode(b)['tag'],x['tag'])
        for x in v['negative']:
            with self.subTest(case=x['file']),self.assertRaises(ValueError):(header_decode if x['kind']=='header'else tx_decode)((d/x['file']).read_bytes())
    def test_header_mutations_bind_all_fields(self):
        h=header_decode((Path(__file__).parent/'vectors/header.bin').read_bytes());base=H('challenge',header_encode(h))
        for field in SCHEMA['header']:
            d=dict(h);name=field['name'];d[name]=(d[name]+1)if field['type']=='u64'else bytes([d[name][0]^1])+d[name][1:]
            self.assertNotEqual(base,H('challenge',header_encode(d)))
    def test_json_float_and_duplicate_rejected(self):
        with self.assertRaises(ValueError):canonical({'score':float('nan')})
        with self.assertRaises(ValueError):json.loads('{"x":1,"x":2}',object_pairs_hook=unique)
    def test_allocation_proof_root_and_payee_are_bound(self):
        rows=[(H('c',bytes([i])),public(key(i)),100+i)for i in range(3)];root,proofs=allocation_root_and_proofs(rows)
        for cid,payee,score in rows:
            self.assertTrue(allocation_check(allocation_leaf(cid,payee,score),proofs[cid],root))
            self.assertFalse(allocation_check(allocation_leaf(cid,payee,score+1),proofs[cid],root))
    def test_sparse_root_absence_empty_and_order(self):
        a={b'a':b'1',b'b':b'2'};b={b'b':b'2',b'a':b'1'};self.assertEqual(state_root(a),state_root(b));self.assertNotEqual(state_root({}),state_root({b'a':b''}))

class ExecutionTests(unittest.TestCase):
    def setUp(self):self.s=genesis_state();self.m=public(key(0))
    def apply(self,s,txs,h=1):return execute(s,txs,h,self.m,GENESIS)[0]
    def test_signature_nonce_and_no_write_on_reject(self):
        tx=sign(key(0),1,'transfer',{'recipient':public(key(1)),'amount':100});s=copy.deepcopy(self.s)
        for bad in [tx[:-1]+bytes([tx[-1]^1]),sign(key(0),2,'transfer',{'recipient':public(key(1)),'amount':100})]:
            with self.assertRaises(ValueError):self.apply(self.s,[bad])
            self.assertEqual(self.s,s)
    def test_expiry_fee_balance_rejections(self):
        for tx in [sign(key(0),1,'transfer',{'recipient':public(key(1)),'amount':100},expiry=0),sign(key(0),1,'transfer',{'recipient':public(key(1)),'amount':100},fee_limit=0),sign(key(0),1,'transfer',{'recipient':public(key(1)),'amount':10**12})]:
            with self.assertRaises(ValueError):self.apply(self.s,[tx])
    def test_task_receipt_does_not_self_settle(self):
        task=H('task-example');out=H('actual-result')
        s=self.apply(self.s,[sign(key(0),1,'reserve_task',{'task':task,'provider':public(key(1)),'budget':10000,'deadline':10})])
        s=self.apply(s,[sign(key(1),1,'record_receipt',{'task':task,'output':out})],2)
        self.assertEqual(s['task:'+task.hex()]['remaining'],10000)
        with self.assertRaises(ValueError):self.apply(s,[sign(key(1),2,'accept_task',{'task':task,'output':out})],3)
        s=self.apply(s,[sign(key(0),2,'accept_task',{'task':task,'output':out})],3)
        self.assertEqual(s['task:'+task.hex()]['remaining'],0);self.assertEqual(total_funds(s),s['meta:issued'])
    def test_cancel_and_late_receipt_are_monotonic(self):
        task=H('cancel');s=self.apply(self.s,[sign(key(0),1,'reserve_task',{'task':task,'provider':public(key(1)),'budget':1000,'deadline':10}),sign(key(0),2,'cancel_task',{'task':task})])
        with self.assertRaises(ValueError):self.apply(s,[sign(key(1),1,'record_receipt',{'task':task,'output':H('out')})],2)
    def test_mandatory_expiry_returns_reserved_funds(self):
        task=H('expiry');s=self.apply(self.s,[sign(key(0),1,'reserve_task',{'task':task,'provider':public(key(1)),'budget':1000,'deadline':2})]);s=self.apply(s,[],2)
        self.assertEqual(s['task:'+task.hex()]['status'],'expired');self.assertEqual(total_funds(s),s['meta:issued'])
    def test_free_consumer_is_not_charged_or_implicitly_authorized(self):
        q=H('free');consumer=key(4);provider=key(1)
        s=self.apply(self.s,[sign(key(0),1,'reserve_quota',{'quota':q,'consumer':public(consumer),'provider':public(provider),'units':2,'deadline':10})])
        fields={'quota':q,'units':1,'result':H('served'),'consumer_signature':consumer.sign(H('use',q,public(provider),u64(1),u64(1),H('served')))}
        bad=dict(fields,consumer_signature=bytes(64))
        with self.assertRaises(ValueError):self.apply(s,[sign(provider,1,'consume_quota',bad)],2)
        s=self.apply(s,[sign(provider,1,'consume_quota',fields)],2)
        self.assertNotIn('account:'+public(consumer).hex(),s);self.assertEqual(s['quota:'+q.hex()]['units'],1);self.assertEqual(total_funds(s),s['meta:issued'])
    def test_contribution_cannot_swap_parent_family_or_claim_self_eval(self):
        artifact=H('model');sender=public(key(0));cid=contribution_id(sender,FAMILY,ZERO,artifact,ZERO)
        fields={'contribution':cid,'family':FAMILY,'parent_release':ZERO,'artifact':artifact,'size':32,'components_root':ZERO}
        s=self.apply(self.s,[sign(key(0),1,'contribute',fields)])
        with self.assertRaises(ValueError):self.apply(s,[sign(key(0),2,'evaluate',{'contribution':cid,'plan':PLAN,'evidence':H('evidence'),'score':10})],2)
        with self.assertRaises(ValueError):self.apply(s,[sign(key(0),2,'contribute',fields)],2)
        wrong=dict(fields,family=H('other-family'))
        with self.assertRaises(ValueError):self.apply(self.s,[sign(key(0),1,'contribute',wrong)])

class DiskReorgTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pon-crash-fixture-');cls.root=Path(cls.temp.name);l=Ledger(cls.root)
        tx=sign(key(0),1,'transfer',{'recipient':public(key(1)),'amount':1000});h,t,p=l.make(GENESIS,[tx]);a=l.admit(h,t,p,PARAMS['genesis_timestamp']+10000);l.activate(a)
        h,t,p=l.make(a,[]);a2=l.admit(h,t,p,PARAMS['genesis_timestamp']+10000);l.activate(a2);cls.old=a2
        b=GENESIS
        for i in range(3):
            txs=[sign(key(0),1,'transfer',{'recipient':public(key(2)),'amount':500})]if i==0 else[]
            h,t,p=l.make(b,txs,public(key(1)));b=l.admit(h,t,p,PARAMS['genesis_timestamp']+10000)
        cls.target=b;cls.targetroot=l.block(b)[6];l.close()
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def test_two_writer_admission_is_rejected(self):
        with tempfile.TemporaryDirectory()as d:
            a=Ledger(d)
            try:
                with self.assertRaisesRegex(ValueError,'WRITER_BUSY'):Ledger(d)
            finally:a.close()
    def test_foreign_database_rejected_without_schema_writes(self):
        import sqlite3
        with tempfile.TemporaryDirectory()as d:
            db=Path(d)/'ledger.sqlite';conn=sqlite3.connect(db);conn.execute('CREATE TABLE unrelated(value TEXT)');conn.commit();conn.close();before=db.read_bytes()
            with self.assertRaisesRegex(ValueError,'SCHEMA'):Ledger(d)
            self.assertEqual(before,db.read_bytes())
    def test_false_parameter_context_rejects_and_releases_owner(self):
        with tempfile.TemporaryDirectory()as d:
            l=Ledger(d);l.db.execute("UPDATE metadata SET value=? WHERE key='parameters'",(b'bad',));l.close()
            with self.assertRaisesRegex(ValueError,'NETWORK'):Ledger(d)
            # Rejected open must not retain a writer lock. A direct known fixture repair is explicit.
            import sqlite3
            conn=sqlite3.connect(Path(d)/'ledger.sqlite');conn.execute("UPDATE metadata SET value=? WHERE key='parameters'",(PARAMETER_HASH,));conn.commit();conn.close()
            l=Ledger(d);l.close()
    def test_every_reorg_process_crash_cut_recovers_exactly(self):
        cuts=['intent','detach:0','detach:1','attach:2','attach:3','attach:4','before-publish','published']
        for cut in cuts:
            with self.subTest(cut=cut),tempfile.TemporaryDirectory(prefix='pon-crash-case-')as d:
                shutil.copytree(self.root,Path(d)/'chain');chain=Path(d)/'chain';ej=EffectJournal(Path(d)/'effects.sqlite');op=H('real-operation');ej.enter(op,H('payload'),1);ej.revoke(H('revoked'));ej.db.close()
                code="from ledger import Ledger;import os,sys;l=Ledger(sys.argv[1]);l.activate(bytes.fromhex(sys.argv[2]),lambda phase: os._exit(86) if phase==sys.argv[3] else None)"
                p=subprocess.run([sys.executable,'-c',code,str(chain),self.target.hex(),cut],cwd=Path(__file__).parent)
                self.assertEqual(p.returncode,86)
                l=Ledger(chain)
                before=l.read_active()[0];self.assertIn(before,[self.old,self.target])
                l.recover();tip,g,s=l.read_active();self.assertEqual(tip,self.target);self.assertEqual(state_root(s),self.targetroot)
                count=l.db.execute('SELECT count(*) FROM events WHERE generation=?',(g,)).fetchone()[0];self.assertEqual(count,5);l.recover();self.assertEqual(l.active(),(tip,g));l.close()
                ej=EffectJournal(Path(d)/'effects.sqlite')
                with self.assertRaisesRegex(ValueError,'OPERATION_ALREADY_ENTERED'):ej.enter(op,H('payload'),g)
                self.assertEqual(ej.db.execute('SELECT count(*) FROM revoked').fetchone()[0],1);ej.db.close()
    def test_root_substitution_rejects_before_persistence(self):
        with tempfile.TemporaryDirectory()as d:
            l=Ledger(d);hb,txs,proof=l.make(GENESIS,[]);h=header_decode(hb);h['state']=H('forged')
            with self.assertRaises(ValueError):l.admit(header_encode(h),txs,proof,PARAMS['genesis_timestamp']+10000)
            self.assertEqual(l.db.execute('SELECT count(*) FROM blocks').fetchone()[0],1);l.close()
    def test_same_work_keeps_existing_tip(self):
        with tempfile.TemporaryDirectory()as d:
            l=Ledger(d);tips=[]
            for i in range(2):
                h,t,p=l.make(GENESIS,[],public(key(i)));tips.append(l.admit(h,t,p,PARAMS['genesis_timestamp']+10000))
            l.activate(tips[0]);self.assertEqual(l.activate(tips[1]),tips[0]);l.close()

if __name__=='__main__':unittest.main(verbosity=2)
