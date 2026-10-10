"""All twelve native transitions against the independent Python reference.

These are signed application transitions, not unverified success flags. Three-round
release tests use explicitly controlled dev attestations, not measured future ML gain.
"""
from __future__ import annotations
import copy,json,os,unittest,subprocess
from pathlib import Path
from ledger import *
from native_execution import execute_native
BINARY=Path(os.environ.get('TRNM_NATIVE_EXECUTOR',str(Path(os.environ.get('CARGO_TARGET_DIR',str(ROOT/'trillionnium/target')))/os.environ.get('TRNM_NATIVE_MODE','release')/'examples/pon_execute')))

class NativeExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file():raise RuntimeError('Build native pon_execute; absence is not a skipped pass')

    def setUp(self):self.state=genesis_state();self.height=0;self.nonces={};self.tags=set();self.last_metrics={}
    def tx(self,who,name,fields):
        self.nonces[who]=self.nonces.get(who,account(self.state,public(key(who)).hex())['nonce'])+1
        return sign(key(who),self.nonces[who],name,fields,expiry=100000)
    def run_block(self,txs,advance=1):
        self.height+=advance;parent=H('transition-parent',u64(self.height));before=copy.deepcopy(self.state)
        expected,receipts=execute_reference(self.state,txs,self.height,public(key(0)),parent)
        for raw in txs:self.tags.add(tx_decode(raw)['tag'])
        for workers in [1,2,4,8]:
            with self.subTest(height=self.height,workers=workers):
                actual,observed,metrics=execute_native(self.state,txs,self.height,public(key(0)),parent,workers,BINARY)
                self.assertEqual(actual,expected);self.assertEqual(observed,receipts)
                self.assertEqual(state_root(actual),state_root(expected));self.assertLessEqual(metrics['reexecuted'],len(txs))
                self.last_metrics[workers]=metrics
        self.assertEqual(self.state,before);self.state=expected

    def contribute_and_publish(self,index):
        parent=bytes.fromhex(self.state['model:current']);art=H('controlled-expert',u64(index));bundle_art=H('controlled-bundle',u64(index));owner=public(key(0))
        round_id=submission_round(self.height+1);cid=contribution_id(owner,FAMILY,parent,art,ZERO,round_id);score=100
        allocation,proofs=allocation_root_and_proofs([(cid,owner,score)])
        bundle=contribution_id(public(key(3)),FAMILY,parent,bundle_art,allocation,round_id)
        self.run_block([self.tx(0,'contribute',dict(contribution=cid,family=FAMILY,parent_release=parent,artifact=art,size=100,components_root=ZERO,submission_round=round_id)),self.tx(3,'contribute',dict(contribution=bundle,family=FAMILY,parent_release=parent,artifact=bundle_art,size=100,components_root=allocation,submission_round=round_id))])
        txs=[]
        for contribution,operators in [(cid,[1,2]),(bundle,[0,1])]:
            for operator in operators:txs.append(self.tx(operator,'evaluate',dict(contribution=contribution,plan=PLAN,evidence=H('controlled-attestation',u64(index),u64(operator),contribution),score=score)))
        self.run_block(txs)
        budget=100000;release=release_id(parent,bundle,budget,allocation,score)
        self.run_block([self.tx(0,'publish_release',dict(release=release,parent_release=parent,bundle=bundle,budget=budget,allocation_root=allocation,total_score=score,allocations=[(cid,score)]))])
        self.run_block([],advance=PARAMS['reward_maturity_blocks'])
        self.assertNotIn('contribution:'+cid.hex(),self.state)
        self.assertEqual(self.state['release:'+release.hex()]['artifact'],bundle_art.hex())
        self.assertEqual(self.state['release:'+release.hex()]['family'],FAMILY.hex())
        self.run_block([self.tx(0,'claim_reward',dict(release=release,contribution=cid,score=score,siblings=proofs[cid]))])
        return release,cid,score,proofs[cid]

    def test_all_twelve_tags_match_for_1_2_4_8_workers(self):
        self.run_block([self.tx(0,'transfer',dict(recipient=public(key(1)),amount=10))])
        tasks=[task_identity(public(key(0)),2+i,public(key(1)),10000,200)for i in range(2)];output=H('actual-recorded-output')
        self.run_block([self.tx(0,'reserve_task',dict(task=t,provider=public(key(1)),budget=10000,deadline=200))for t in tasks]+[self.tx(2,'register_work',dict(task_commitment=H('work-registration')))])
        self.run_block([self.tx(1,'record_receipt',dict(task=tasks[0],output=output)),self.tx(0,'cancel_task',dict(task=tasks[1]))])
        self.run_block([self.tx(0,'accept_task',dict(task=tasks[0],output=output))])
        self.contribute_and_publish(0)
        consumer=key(30);provider=public(key(1));quota=quota_identity(public(key(0)),self.nonces[0]+1,public(consumer),provider,2,self.height+100)
        self.run_block([self.tx(0,'reserve_quota',dict(quota=quota,consumer=public(consumer),provider=provider,units=2,deadline=self.height+100))])
        nonce=self.nonces.get(1,0)+1;result=H('service-result')
        signature=consumer.sign(H('use',NETWORK,PARAMETER_HASH,quota,provider,u64(nonce),u64(1),result))
        self.run_block([self.tx(1,'consume_quota',dict(quota=quota,units=1,result=result,consumer_signature=signature))])
        self.assertEqual(self.tags,set(range(1,13)));self.assertNotIn('account:'+public(consumer).hex(),self.state)

    def test_revision3_first_pair_is_order_sensitive_and_late_third_rejects(self):
        # A retained counterexample, not a claimed fix or a new consensus profile.
        from itertools import permutations
        author=public(key(3));artifact=H('ordering-counterexample')
        cid=contribution_id(author,FAMILY,ZERO,artifact,ZERO,0)
        self.run_block([self.tx(3,'contribute',dict(contribution=cid,family=FAMILY,
            parent_release=ZERO,artifact=artifact,size=100,components_root=ZERO,submission_round=0))])
        before=copy.deepcopy(self.state);scores={0:10,1:100,2:100};outcomes=set()
        signed={i:sign(key(i),1,'evaluate',dict(contribution=cid,plan=PLAN,
            evidence=H('ordering-evidence',u64(i)),score=scores[i]),expiry=100000) for i in scores}
        for order in permutations(scores):
            txs=[signed[i] for i in order[:2]];parent=H('ordering-parent')
            expected,receipts=execute_reference(before,txs,2,public(key(0)),parent)
            score=expected['contribution:'+cid.hex()]['score'];outcomes.add(score)
            self.assertEqual(score,min(scores[i] for i in order[:2]))
            for workers in [1,2,4,8]:
                actual,observed,_=execute_native(before,txs,2,public(key(0)),parent,workers,BINARY)
                self.assertEqual(actual,expected);self.assertEqual(observed,receipts)
                with self.assertRaisesRegex(ValueError,'STATE'):
                    execute_native(actual,[signed[order[2]]],3,public(key(0)),H('late-evidence'),workers,BINARY)
        self.assertEqual(outcomes,{10,100});self.assertEqual(self.state,before)

    def test_exact_artifact_copy_across_authors_does_not_gain_second_intake(self):
        artifact=H('same-parameter-bytes');parent=ZERO
        txs=[]
        for author in [0,3]:
            cid=contribution_id(public(key(author)),FAMILY,parent,artifact,ZERO,0)
            txs.append(sign(key(author),1,'contribute',dict(contribution=cid,family=FAMILY,
                parent_release=parent,artifact=artifact,size=100,components_root=ZERO,submission_round=0)))
        before=copy.deepcopy(self.state)
        for workers in [1,2,4,8]:
            with self.assertRaisesRegex(ValueError,'DUPLICATE'):
                execute_native(before,txs,1,public(key(0)),GENESIS,workers,BINARY)
        self.assertEqual(self.state,before)

    def test_independent_senders_commit_without_false_conflicts(self):
        self.run_block([self.tx(0,'transfer',dict(recipient=public(key(i)),amount=10000))for i in range(4,20)])
        self.run_block([self.tx(i,'transfer',dict(recipient=H('isolated-recipient',u64(i)),amount=1))for i in range(4,20)])
        for workers in [2,4,8]:self.assertEqual(self.last_metrics[workers]['reexecuted'],0)
        self.assertEqual(self.last_metrics[8]['peak_inflight'],8)

    def test_hot_sender_degrades_to_serial_without_speculation(self):
        self.run_block([self.tx(0,'transfer',dict(recipient=public(key(1)),amount=1))for _ in range(16)])
        self.assertEqual(self.last_metrics[8]['reexecuted'],0)
        self.assertEqual(self.last_metrics[8]['peak_inflight'],1)
        self.assertEqual(self.last_metrics[8]['serial_conflict_batches'],1)

    def test_hot_recipient_conflict_reexecutes_once_in_canonical_order(self):
        self.run_block([self.tx(0,'transfer',dict(recipient=public(key(i)),amount=10000))for i in range(4,20)])
        self.run_block([self.tx(i,'transfer',dict(recipient=public(key(1)),amount=1))for i in range(4,20)])
        self.assertEqual(self.last_metrics[8]['reexecuted'],15)
        self.assertEqual(self.last_metrics[8]['peak_inflight'],8)
        self.assertEqual(self.last_metrics[8]['serial_conflict_batches'],0)

    def test_block_scoped_workers_and_no_duplicate_main_signature_on_conflict(self):
        self.run_block([self.tx(0,'transfer',dict(recipient=public(key(i)),amount=10000))for i in range(4,36)])
        self.run_block([self.tx(i,'transfer',dict(recipient=public(key(1)),amount=1))for i in range(4,36)])
        for workers in [1,2,4,8]:
            metrics=self.last_metrics[workers]
            self.assertEqual(metrics['signature_verifications'],32)
            self.assertLessEqual(metrics['workers_spawned'],workers)
            self.assertEqual(metrics['workers_spawned'],0 if workers==1 else workers)
        self.assertEqual(self.last_metrics[8]['reexecuted'],31)

    def test_later_invalid_signature_does_not_change_canonical_error(self):
        first=sign(key(0),2,'transfer',dict(recipient=public(key(1)),amount=1))
        second=sign(key(1),1,'transfer',dict(recipient=public(key(2)),amount=1))
        second=second[:-1]+bytes([second[-1]^1]);before=copy.deepcopy(self.state)
        for workers in [1,2,4,8]:
            with self.assertRaisesRegex(ValueError,'NONCE'):
                execute_native(self.state,[first,second],1,public(key(0)),GENESIS,workers,BINARY)
        self.assertEqual(self.state,before)

    def test_funding_dependency_replays_state_not_main_signature(self):
        self.run_block([self.tx(0,'transfer',dict(recipient=public(key(4)),amount=10000)),
                        self.tx(4,'transfer',dict(recipient=public(key(5)),amount=1000))])
        for workers in [2,4,8]:
            self.assertEqual(self.last_metrics[workers]['reexecuted'],1)
            self.assertEqual(self.last_metrics[workers]['signature_verifications'],2)

    def test_capacity_prefix_commands_do_not_speculate_unbounded_snapshots(self):
        self.run_block([self.tx(0,'transfer',dict(recipient=public(key(i)),amount=10000))for i in range(4,20)])
        deadline=self.height+20;transactions=[]
        for i in range(4,20):
            task=task_identity(public(key(i)),1,public(key(1)),1000,deadline)
            transactions.append(self.tx(i,'reserve_task',dict(task=task,provider=public(key(1)),budget=1000,deadline=deadline)))
        self.run_block(transactions)
        for workers in [1,2,4,8]:
            self.assertEqual(self.last_metrics[workers]['speculative'],0)
            self.assertEqual(self.last_metrics[workers]['signature_verifications'],16)
        task=task_identity(public(key(0)),self.nonces[0]+1,public(key(1)),1000,deadline)
        overflow=self.tx(0,'reserve_task',dict(task=task,provider=public(key(1)),budget=1000,deadline=deadline))
        before=copy.deepcopy(self.state)
        for workers in [1,2,4,8]:
            with self.assertRaisesRegex(ValueError,'LIMIT'):
                execute_native(self.state,[overflow],self.height+1,public(key(0)),GENESIS,workers,BINARY)
        self.assertEqual(self.state,before)

    def test_single_signature_context_cannot_be_reused_for_another_payload(self):
        raw=bytearray(sign(key(0),1,'transfer',dict(recipient=public(key(1)),amount=1)))
        raw[127]^=1;before=copy.deepcopy(self.state)
        for workers in [1,2,4,8]:
            with self.assertRaisesRegex(ValueError,'SIGNATURE'):
                execute_native(self.state,[bytes(raw)],1,public(key(0)),GENESIS,workers,BINARY)
        self.assertEqual(self.state,before)

    def test_three_signed_release_generations_preserve_payout_and_retirement(self):
        for i in range(3):
            release,cid,score,siblings=self.contribute_and_publish(i)
            self.assertEqual(self.state['model:current'],release.hex())
            self.assertLessEqual(sum(k.startswith('contribution:')for k in self.state),2)
            bad=self.tx(0,'claim_reward',dict(release=release,contribution=cid,score=score,siblings=siblings))
            with self.assertRaisesRegex(ValueError,'DUPLICATE'):
                execute_native(self.state,[bad],self.height+1,public(key(0)),H('bad-parent'),8,BINARY)
            self.nonces[0]-=1

    def test_unclaimed_release_budget_refunds_at_reserved_deadline(self):
        # Seed a validated application-state fixture; this tests refund/retirement,
        # not the provenance of this synthetic prior release.
        who=public(key(0)).hex();budget=1000;rid=H('unclaimed-release').hex()
        self.state['account:'+who]['balance']-=budget
        self.state['release:'+rid]={'owner':who,'remaining':budget,'budget':budget,'total':1,'root':H('allocation').hex(),'maturity':1,'bundle':H('bundle').hex(),'leaf_count':1,'claims':{},'deadline':2,'status':'open'}
        before=self.state['account:'+who]['balance'];self.run_block([],advance=2)
        self.assertEqual(self.state['account:'+who]['balance'],before+budget)
        self.assertEqual(self.state['release:'+rid]['remaining'],0)
        self.run_block([]);self.assertNotIn('release:'+rid,self.state)

    def test_native_round_boundary_retires_history_and_rejects_old_signature(self):
        owner=public(key(0));artifact=H('boundary-artifact')
        old=contribution_id(owner,FAMILY,ZERO,artifact,ZERO,0)
        raw=sign(key(0),1,'contribute',dict(contribution=old,family=FAMILY,parent_release=ZERO,artifact=artifact,size=1,components_root=ZERO,submission_round=0),expiry=100000)
        before=copy.deepcopy(self.state)
        for workers in [1,2,4,8]:
            with self.assertRaisesRegex(ValueError,'SUBMISSION_ROUND'):
                execute_native(self.state,[raw],PARAMS['candidate_round_blocks'],owner,GENESIS,workers,BINARY)
        self.assertEqual(self.state,before)
        self.height=PARAMS['candidate_round_blocks']-1
        self.contribute_and_publish(91)
        self.assertNotEqual(self.state['model:current'],ZERO.hex())

    def test_bad_signature_rejects_entire_block_without_parent_mutation(self):
        tx=self.tx(0,'transfer',dict(recipient=public(key(1)),amount=1));bad=tx[:-1]+bytes([tx[-1]^1]);before=copy.deepcopy(self.state)
        for workers in [1,2,4,8]:
            with self.assertRaisesRegex(ValueError,'SIGNATURE'):execute_native(self.state,[bad],1,public(key(0)),GENESIS,workers,BINARY)
        self.assertEqual(before,self.state)

    def test_terminal_task_retirement_cannot_reopen_same_resource_id(self):
        owner=public(key(0));provider=public(key(1));task=task_identity(owner,1,provider,1000,3)
        self.run_block([self.tx(0,'reserve_task',dict(task=task,provider=provider,budget=1000,deadline=3)),self.tx(0,'cancel_task',dict(task=task))])
        self.run_block([],advance=3);self.assertNotIn('task:'+task.hex(),self.state)
        malicious=sign(key(0),3,'reserve_task',dict(task=task,provider=provider,budget=1000,deadline=8),expiry=1000)
        for workers in [1,2,4,8]:
            with self.assertRaisesRegex(ValueError,'RESOURCE_ID'):
                execute_native(self.state,[malicious],5,owner,GENESIS,workers,BINARY)
        fresh=task_identity(owner,3,provider,1000,8)
        self.run_block([self.tx(0,'reserve_task',dict(task=fresh,provider=provider,budget=1000,deadline=8))])
        self.assertIn('task:'+fresh.hex(),self.state)

    def test_spent_quota_retirement_preserves_consent_identity(self):
        owner=public(key(0));provider=public(key(1));consumer=key(4)
        quota=quota_identity(owner,1,public(consumer),provider,1,3)
        self.run_block([self.tx(0,'reserve_quota',dict(quota=quota,consumer=public(consumer),provider=provider,units=1,deadline=3))])
        result=H('once-served');signature=consumer.sign(H('use',NETWORK,PARAMETER_HASH,quota,provider,u64(1),u64(1),result))
        self.run_block([self.tx(1,'consume_quota',dict(quota=quota,units=1,result=result,consumer_signature=signature))])
        self.run_block([],advance=2);self.assertNotIn('quota:'+quota.hex(),self.state)
        malicious=sign(key(0),2,'reserve_quota',dict(quota=quota,consumer=public(consumer),provider=provider,units=1,deadline=8),expiry=1000)
        for workers in [1,2,4,8]:
            with self.assertRaisesRegex(ValueError,'RESOURCE_ID'):
                execute_native(self.state,[malicious],5,owner,GENESIS,workers,BINARY)
        fresh=quota_identity(owner,2,public(consumer),provider,1,8)
        self.run_block([self.tx(0,'reserve_quota',dict(quota=fresh,consumer=public(consumer),provider=provider,units=1,deadline=8))])
        reuse=sign(key(1),2,'consume_quota',dict(quota=fresh,units=1,result=result,consumer_signature=signature),expiry=1000)
        with self.assertRaisesRegex(ValueError,'SIGNATURE'):
            execute_native(self.state,[reuse],6,owner,GENESIS,8,BINARY)

    def test_wrong_native_context_rejects_even_an_empty_block(self):
        data={'network':NETWORK.hex(),'parameters':H('wrong-context').hex(),'state':self.state,'transactions':[],'height':1,'miner':public(key(0)).hex(),'parent':GENESIS.hex(),'workers':8}
        result=subprocess.run([str(BINARY)],input=canonical(data),capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0);self.assertIn(b'CONTEXT',result.stderr)

    def test_missing_native_binary_is_not_reference_fallback(self):
        with self.assertRaisesRegex(ValueError,'NATIVE_EXECUTOR_UNAVAILABLE'):execute_native(self.state,[],1,public(key(0)),GENESIS,1,Path('/nonexistent/native-owner'))

if __name__=='__main__':unittest.main(verbosity=2)
