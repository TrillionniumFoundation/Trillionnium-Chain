"""Real signed transactions under explicit revision4, compared with the Rust owner."""
import copy, itertools, json, os, subprocess, sys, unittest
from pathlib import Path
PROFILE = 'closed-round-all-eligible-min-v1'
if __name__ == '__main__' and os.environ.get('TRNM_PON_EVALUATION_POLICY') != PROFILE:
    env = dict(os.environ, TRNM_PON_EVALUATION_POLICY=PROFILE)
    raise SystemExit(subprocess.call([sys.executable, __file__], env=env))
from ledger import (H, ZERO, FAMILY, PLAN, PARAMS, NETWORK, PARAMETER_HASH, ROOT,
                    key, public, sign, contribution_id, genesis_state, execute_reference,
                    EVALUATORS, state_root, allocation_root_and_proofs, release_id)
from evaluation_round import complete_score

class ClosedRoundTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(PARAMS['evaluation_profile'], PROFILE)
        self.binary = Path(os.environ.get('CARGO_TARGET_DIR', ROOT/'trillionnium/target'))/'release/examples/pon_execute'
        self.assertTrue(self.binary.is_file(), 'build the exact native examples first')
        self.parent = H('evaluation-round-test-parent')
        self.miner = public(key(0))
    def native(self, state, txs, height=1, workers=1, policy=PROFILE, error=None):
        request = {'state':state,'transactions':[t.hex() for t in txs], 'height':height,
                   'miner':self.miner.hex(),'parent':self.parent.hex(),'workers':workers,
                   'network':NETWORK.hex(),'parameters':PARAMETER_HASH.hex()}
        args = [str(self.binary), '--evaluation-policy', policy]
        result = subprocess.run(args, input=json.dumps(request).encode(), capture_output=True, timeout=30)
        if error:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(error, result.stderr.decode())
            return
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return json.loads(result.stdout)
    def check_both(self, state, txs, height=1, workers=1):
        before = copy.deepcopy(state)
        expected, receipts = execute_reference(state,txs,height,self.miner,self.parent)
        actual = self.native(state,txs,height,workers)
        self.assertEqual(state,before)
        self.assertEqual(actual['state'], expected)
        self.assertEqual(actual['receipts'], [x.hex() for x in receipts])
        self.assertEqual(actual['root'], state_root(expected).hex())
        return expected, actual
    def contribution(self, author=3):
        artifact = H('closed-round-artifact', bytes([author]))
        cid = contribution_id(public(key(author)),FAMILY,ZERO,artifact,ZERO,0)
        tx = sign(key(author),1,'contribute',dict(contribution=cid,family=FAMILY,
            parent_release=ZERO,artifact=artifact,size=100,components_root=ZERO,submission_round=0))
        return cid,tx
    def evaluation(self,cid,signer,score,nonce=1,plan=PLAN):
        return sign(key(signer),nonce,'evaluate',dict(contribution=cid,plan=plan,
            evidence=H('evaluation-record',bytes([signer])),score=score))
    def test_all_six_arrival_orders_close_to_the_same_state_with_all_workers(self):
        cid,submitted=self.contribution(); roots=set()
        for order in itertools.permutations(range(3)):
            txs=[submitted]+[self.evaluation(cid,i,[10,100,100][i]) for i in order]
            for workers in [1,2,4,8]:
                state,actual=self.check_both(genesis_state(),txs,workers=workers)
                self.assertEqual(state['contribution:'+cid.hex()]['score'],10)
                self.assertEqual(state['contribution:'+cid.hex()]['status'],'evaluated')
                roots.add(actual['root'])
        self.assertEqual(len(roots),1)
    def test_two_fast_high_scores_do_not_unlock_and_missing_vote_expires(self):
        cid,submitted=self.contribution()
        state,_=self.check_both(genesis_state(),[submitted,self.evaluation(cid,1,100),self.evaluation(cid,2,100)])
        self.assertEqual(state['contribution:'+cid.hex()]['status'],'submitted')
        expired,_=self.check_both(state,[],height=66)
        self.assertEqual(expired['contribution:'+cid.hex()]['status'],'expired')
        self.assertFalse(any(k.startswith('release:') for k in expired))
        with self.assertRaisesRegex(ValueError,'STATE'):
            execute_reference(expired,[self.evaluation(cid,0,10)],67,self.miner,self.parent)
        self.native(expired,[self.evaluation(cid,0,10)],height=67,error='STATE')
    def test_zero_full_round_has_no_adoption_or_reward(self):
        cid,submitted=self.contribution()
        txs=[submitted]+[self.evaluation(cid,i,[0,100,100][i]) for i in [2,1,0]]
        state,_=self.check_both(genesis_state(),txs)
        self.assertEqual(state['contribution:'+cid.hex()]['score'],0)
        self.assertEqual(state['model:current'],ZERO.hex())
        self.assertFalse(any(k.startswith('release:') for k in state))
    def test_author_in_roster_is_excluded_not_permitted_to_evaluate_self(self):
        cid,submitted=self.contribution(author=0)
        txs=[submitted,self.evaluation(cid,2,100),self.evaluation(cid,1,10)]
        state,_=self.check_both(genesis_state(),txs)
        self.assertEqual(state['contribution:'+cid.hex()]['score'],10)
        txs=[submitted,self.evaluation(cid,0,100,nonce=2)]
        with self.assertRaisesRegex(ValueError,'AUTHORITY'):
            execute_reference(genesis_state(),txs,1,self.miner,self.parent)
        self.native(genesis_state(),txs,error='AUTHORITY')
    def test_duplicate_replacement_wrong_plan_and_score_overflow_reject(self):
        cid,submitted=self.contribution()
        bad=[([submitted,self.evaluation(cid,0,10),self.evaluation(cid,0,100,nonce=2)],'DUPLICATE'),
             ([submitted,self.evaluation(cid,0,10,plan=H('wrong-plan'))],'EVIDENCE'),
             ([submitted,self.evaluation(cid,0,PARAMS['max_evidence_score']+1)],'EVIDENCE')]
        for txs,error in bad:
            state=genesis_state();before=copy.deepcopy(state)
            with self.assertRaisesRegex(ValueError,error):
                execute_reference(state,txs,1,self.miner,self.parent)
            self.native(state,txs,error=error)
            self.assertEqual(state,before)
    def test_legacy_and_unknown_native_policy_cannot_accept_new_context(self):
        self.native(genesis_state(),[],policy='legacy-first-two-v3',error='CONTEXT')
        self.native(genesis_state(),[],policy='made-up',error='EVALUATION_POLICY')
        old=(ROOT/'formal/pon-nakamoto-v1/vectors/accepted-block/transaction.bin').read_bytes()
        with self.assertRaisesRegex(ValueError,'NETWORK'):
            execute_reference(genesis_state(),[old],1,self.miner,self.parent)
        self.native(genesis_state(),[old],error='NETWORK')
    def test_complete_round_can_publish_mature_and_claim_exactly_once(self):
        owner=public(key(0)); score=10; artifact=H('positive-expert')
        cid=contribution_id(owner,FAMILY,ZERO,artifact,ZERO,0)
        allocation,proofs=allocation_root_and_proofs([(cid,owner,score)])
        bundle_art=H('positive-bundle')
        bundle=contribution_id(public(key(3)),FAMILY,ZERO,bundle_art,allocation,0)
        txs=[sign(key(who),1,'contribute',dict(contribution=c,family=FAMILY,parent_release=ZERO,
              artifact=a,size=100,components_root=component,submission_round=0))
              for who,c,a,component in [(0,cid,artifact,ZERO),(3,bundle,bundle_art,allocation)]]
        txs += [self.evaluation(cid,1,10),self.evaluation(cid,2,100),
                self.evaluation(bundle,0,100,nonce=2),self.evaluation(bundle,1,10,nonce=2),
                self.evaluation(bundle,2,100,nonce=2)]
        state,_=self.check_both(genesis_state(),txs,workers=8)
        budget=100000; rid=release_id(ZERO,bundle,budget,allocation,score)
        publish=sign(key(0),3,'publish_release',dict(release=rid,parent_release=ZERO,bundle=bundle,
            budget=budget,allocation_root=allocation,total_score=score,allocations=[(cid,score)]))
        state,_=self.check_both(state,[publish],height=2)
        state,_=self.check_both(state,[],height=22)
        claim=lambda nonce: sign(key(0),nonce,'claim_reward',dict(release=rid,
            contribution=cid,score=score,siblings=proofs[cid]))
        state,_=self.check_both(state,[claim(4)],height=23)
        self.assertEqual(state['release:'+rid.hex()]['remaining'],0)
        with self.assertRaisesRegex(ValueError,'DUPLICATE'):
            execute_reference(state,[claim(5)],24,self.miner,self.parent)
        self.native(state,[claim(5)],height=24,error='DUPLICATE')
    def test_ordinary_native_cli_uses_successor_and_reopens_only_its_namespace(self):
        import tempfile
        binary=self.binary.parent.parent/'trnm-pon-node'
        self.assertTrue(binary.is_file(), 'build the exact native node before qualification')
        cid,contribution=self.contribution()
        txs=[contribution]+[self.evaluation(cid,i,[10,100,100][i]) for i in [2,1,0]]
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); store=directory/'node'
            common=['--development','--store',str(store),'--evaluation-policy',PROFILE,
                    '--logical-now','1800010000']
            def command(action,*args):
                result=subprocess.run([str(binary),action,*common,*args],capture_output=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stderr.decode())
                return json.loads(result.stdout)['result']
            initial=command('status'); parent=bytes.fromhex(initial['tip'])
            txfile=directory/'transactions.json';txfile.write_text(json.dumps([tx.hex() for tx in txs]))
            packet=directory/'block.bin'
            mined=command('mine','--transactions',str(txfile),'--timestamp','1800000010','--output',str(packet))
            expected,_=execute_reference(genesis_state(),txs,1,self.miner,parent)
            self.assertEqual(mined['state']['state_root'],state_root(expected).hex())
            self.assertEqual(command('recover')['state_root'],state_root(expected).hex())
            # A real heavier fork removes the evaluated candidate. Replaying the
            # original signed operations on the surviving branch recomputes it.
            branch_state=genesis_state(); branch_tip=initial['tip']
            for height in [1,2]:
                result=command('mine','--parent',branch_tip,'--timestamp',str(1800000001+10*height),
                    '--output',str(directory/f'fork-{height}.bin'))
                branch_state,_=execute_reference(branch_state,[],height,self.miner,bytes.fromhex(branch_tip))
                branch_tip=result['block']
            self.assertEqual(command('recover')['state_root'],state_root(branch_state).hex())
            replayed=command('mine','--transactions',str(txfile),'--timestamp','1800000031',
                '--output',str(directory/'replayed.bin'))
            expected,_=execute_reference(branch_state,txs,3,self.miner,bytes.fromhex(branch_tip))
            self.assertEqual(replayed['state']['state_root'],state_root(expected).hex())
            old=subprocess.run([str(binary),'status','--development','--store',str(store)],capture_output=True,timeout=30)
            self.assertNotEqual(old.returncode,0)
            self.assertIn('STORAGE_CONTEXT',old.stderr.decode())
            self.assertEqual(command('status')['state_root'],state_root(expected).hex())
            foreign=directory/'legacy'
            result=subprocess.run([str(binary),'submit','--development','--store',str(foreign),
                '--packet',str(packet),'--logical-now','1800010000'],capture_output=True,timeout=30)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual('NETWORK',result.stderr.decode().strip())

    def test_scalar_rule_rejects_boolean_and_unregistered_attestor(self):
        roster={'a','b','c'}
        with self.assertRaisesRegex(ValueError,'EVIDENCE'):
            complete_score(roster,'author',{'a':{'score':True}},100)
        with self.assertRaisesRegex(ValueError,'AUTHORITY'):
            complete_score(roster,'author',{'stranger':{'score':10}},100)

if __name__=='__main__':unittest.main(verbosity=2)
