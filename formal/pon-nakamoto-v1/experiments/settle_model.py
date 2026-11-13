"""Bind observed model artifacts to actual signed transactions, work and disk settlement.
Experimental 2-of-3 attested evaluators and all accounts are controlled by this harness.
No external token, independent operators or ordinary Hepta entry is claimed.
"""
from pathlib import Path
from dataclasses import dataclass
import argparse,hashlib,json,sys,subprocess,time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ledger import *
from inference_receipt import receipt as encode_receipt,verify as verify_receipt
from evaluation_bundle import (verify_bundle, verify_partition_set, evaluate_bundle,
    predict_rows, read_bounded, write_new, MAX_BUNDLE_BYTES, MAX_TASK_BYTES)

WORK_BYTES = 4 + 12 * work.CELLS + 32
WORK_SCOPE = ('first 64 feature coordinates of fixed expert zero on up to 64 real '
              'consumer tasks; not a whole-model training proof')


@dataclass(frozen=True)
class ObservationInputs:
    """Owned immutable bytes for this local replay, not an authority token."""
    files: tuple[tuple[str, bytes], ...]

    def raw(self, name):
        for filename, raw in self.files:
            if filename == name:
                return raw
        raise ValueError('SETTLEMENT_INPUT')

    def parsed(self, name):
        return json.loads(self.raw(name), object_pairs_hook=unique)


def _read_observation(directory, expected_bundle):
    """Validate all committed partitions and retain the exact evaluated bytes.

    The directory may change after this function. Later settlement must use this
    snapshot instead of reopening mutable source paths. Disjoint committed rows
    do not prove that a trainer used only those rows or that the data was lawful.
    """
    directory = Path(directory)
    files = {}

    def read(name, maximum):
        raw = read_bounded(directory / name, maximum)
        files[name] = raw
        return raw

    raw = read('evaluation-bundle.json', MAX_BUNDLE_BYTES)
    bundle = verify_bundle(raw, expected_bundle)
    # This harness creates an initial ledger with submission round zero. Its
    # evaluation round is one-based; later rounds and nonzero parent releases
    # require their actual ledger/owner instead of being relabelled as genesis.
    require(bundle['parent_release'] == ZERO.hex() and bundle['round'] == 1,
            'SETTLEMENT_CONTEXT')
    model_bytes = read('model.json', 65536)
    require(H('artifact',model_bytes).hex()==bundle['candidate_artifact'],'MODEL_IDENTITY')
    observed = json.loads(read('report.json', MAX_TASK_BYTES), object_pairs_hook=unique)
    require(observed['evaluation_bundle']==expected_bundle and observed['source']==bundle['source_commit'],'OBSERVATION_BINDING')
    require(observed['models']['artifact_hash']==bundle['candidate_artifact'] and observed['models']['bytes']==len(model_bytes),'MODEL_IDENTITY')
    partitions = {}
    for name in sorted(bundle['partitions']):
        try:
            partition_raw = read(name + '.json', MAX_TASK_BYTES)
        except FileNotFoundError as error:
            raise ValueError('PARTITION_SET') from error
        partitions[name] = json.loads(partition_raw, object_pairs_hook=unique)
    verify_partition_set(bundle, partitions)
    require({'evaluation_a', 'evaluation_b'} <= set(partitions), 'SETTLEMENT_PARTITIONS')
    # Controlled attestors replay the named evaluation instead of signing mutable report scores.
    for partition in ['evaluation_a','evaluation_b']:
        result=evaluate_bundle(raw,expected_bundle,partitions[partition],partition,
                               calibration_rows=partitions['calibration'])
        record=json.loads(read(partition+'-result.json',MAX_TASK_BYTES),object_pairs_hook=unique)
        exact={'evaluation_bundle':expected_bundle,'evaluation_partition':partition,
               'model_artifact':bundle['candidate_artifact'],'predictions':result['predictions'],
               'value_claim':result['value_claim'],
               'whole_gain':dict(result['primary'],score=result['primary']['exploratory_score']),
               'marginal':[dict(r,score=r['exploratory_score'])for r in result['marginal']],
               'strong_reference':bundle['selected'],'strong_reference_artifact':result['reference_artifact']}
        for key,value in exact.items():
            require(canonical(record.get(key))==canonical(value) and canonical(observed['results'][partition].get(key))==canonical(value),'OBSERVED_EVALUATION_MISMATCH')
    return ObservationInputs(tuple(sorted(files.items())))

def verify_observation(directory,expected_bundle):
    inputs = _read_observation(directory, expected_bundle)
    return inputs.parsed('report.json'), inputs.parsed('evaluation-bundle.json')['candidate']


def _verify_model_work(inputs, proof):
    """Replay the producer's existing partial contraction before opening a ledger.

    This checks exact mathematical/model binding only. It neither proves fresh
    training nor promotes this partial operator to a complete model computation.
    """
    bundle = inputs.parsed('evaluation-bundle.json')
    require('consumer' in bundle['partitions'], 'MODEL_WORK_CONSUMER')
    model = bundle['candidate']
    consumer = inputs.parsed('consumer.json')
    require(type(proof) is bytes and len(proof) == WORK_BYTES, 'MODEL_WORK_LENGTH')
    a, b = [0] * work.CELLS, [0] * work.CELLS
    for row, item in enumerate(consumer[:work.N]):
        for column, value in enumerate(item['x'][:work.N]):
            a[row * work.N + column] = value % work.Q
    for row in range(work.N):
        for column in range(3):
            value = model['base'][column][row] + model['deltas'][0][column][row]
            require(abs(value) <= 32767, 'MODEL_BOUND')
            b[row * work.N + column] = value % work.Q
    material = struct.pack('<' + 'I' * (2 * work.CELLS), *a, *b)
    require(proof[:4] == b'PNW1' and proof[4:4 + len(material)] == material,
            'MODEL_WORK_MATERIAL')
    challenge = H('real-model-work', H('artifact', inputs.raw('model.json')),
                  H('tasks', canonical(consumer)))
    _, product = work.verify(challenge, work.task_id(a, b), bytes([255]) * 32, proof)
    # Independently check the signed bridge and the explicit zero padding.
    for row in range(work.N):
        for column in range(work.N):
            expected = 0
            if row < min(len(consumer), work.N) and column < 3:
                expected = sum(consumer[row]['x'][k] *
                    (model['base'][column][k] + model['deltas'][0][column][k])
                    for k in range(work.N))
            value = product[row * work.N + column]
            signed = value - work.Q if value > work.Q // 2 else value
            require(abs(expected) < work.Q // 2 and signed == expected, 'NUMERIC_BRIDGE')
    return a, b


def _persist_inputs(inputs, out):
    directory = out / 'verified-inputs'
    directory.mkdir(mode=0o700)
    hashes = {}
    for name, raw in inputs.files:
        write_new(directory / name, raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    manifest = {'schema': 'pon-settlement-verified-inputs-v1', 'files_sha256': hashes,
                'scope': 'local-replay-inputs-not-training-provenance-or-authority'}
    raw = canonical(manifest)
    write_new(directory / 'manifest.json', raw)
    return H('settlement-verified-inputs-v1', raw).hex()

def run(directory,out,expected_bundle):
    directory=Path(directory);out=Path(out);out.mkdir(parents=True,exist_ok=False)
    inputs = _read_observation(directory, expected_bundle)
    observed = inputs.parsed('report.json')
    model = inputs.parsed('evaluation-bundle.json')['candidate']
    report={'schema':'pon-observed-artifact-settlement-v2','source_model':observed['models']['artifact_hash'],'evaluation_bundle':expected_bundle,'observed_evaluation_recomputed':True,'committed_partitions_rechecked':True,'ordinary_hepta_entry':False,'independent_evaluators':False,'future_window_accepted':False,'asset':'test-unit-no-market-value','chain_clock':'fixed logical timestamps; no live-clock acceptance','production_activation':False}
    eligible=[i for i in range(3)if min(observed['results'][p]['marginal'][i]['score']for p in ['evaluation_a','evaluation_b'])>0]
    whole=min(observed['results'][p]['whole_gain']['score']for p in ['evaluation_a','evaluation_b'])
    if not eligible or not whole:
        report['verified_input_snapshot'] = _persist_inputs(inputs, out)
        report.update(outcome='not_adopted',model_reward=0,reason='preregistered statistical gate not met');(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True);return
    proof = read_bounded(directory / 'model-work.bin', WORK_BYTES)
    wa, wb = _verify_model_work(inputs, proof)
    inputs = ObservationInputs(inputs.files + (('model-work.bin', proof),))
    report['verified_input_snapshot'] = _persist_inputs(inputs, out)
    report['model_work_binding_replayed'] = True
    report['model_work_scope'] = WORK_SCOPE
    l=Ledger(out/'chain');tip=GENESIS;nonces={i:0 for i in range(5)};blocks=[];timings=[]
    task=work.task_id(wa,wb)
    def tx(i,name,fields):nonces[i]+=1;return sign(key(i),nonces[i],name,fields)
    def block(txs):
        nonlocal tip
        start=time.perf_counter();inputs=None if tip==GENESIS else(wa,wb)
        hb,ts,p=l.make(tip,txs,work_inputs=inputs);tip=l.admit(hb,ts,p,PARAMS['genesis_timestamp']+100000);l.activate(tip)
        timings.append(time.perf_counter()-start);blocks.append({'id':tip.hex(),'height':l.block(tip)[1],'transactions':len(txs),'work_task':header_decode(hb)['work_task'].hex()});return tip
    contributions=[];initial=[tx(3,'register_work',{'task_commitment':task})]
    for i in range(3):
        value={'schema':'hepta-source-owner-delta-v1','family':FAMILY.hex(),'base':H('base',canonical(model['base'])).hex(),'delta':model['deltas'][i],'feature':model['feature']}
        b=canonical(value);(out/f'expert-{i}.json').write_bytes(b);artifact=H('artifact',b);cid=contribution_id(public(key(i)),FAMILY,ZERO,artifact,ZERO);contributions.append(cid)
        initial.append(tx(i,'contribute',dict(contribution=cid,family=FAMILY,parent_release=ZERO,artifact=artifact,size=len(b),components_root=ZERO,submission_round=0)))
    block(initial)
    votes=[]
    for i,cid in enumerate(contributions):
        evaluators=[j for j in range(3)if j!=i]
        for j,partition in zip(evaluators,['evaluation_a','evaluation_b']):
            obs=observed['results'][partition];score=obs['marginal'][i]['score'];evidence=H('observed-evaluation',cid,inputs.raw(partition+'-result.json'))
            votes.append(tx(j,'evaluate',dict(contribution=cid,plan=PLAN,evidence=evidence,score=score)))
    block(votes)
    allocations=[(contributions[i],public(key(i)),min(observed['results'][p]['marginal'][i]['score']for p in ['evaluation_a','evaluation_b']))for i in eligible]
    root,proofs=allocation_root_and_proofs(allocations);model_bytes=inputs.raw('model.json');model_hash=H('artifact',model_bytes)
    bundle=contribution_id(public(key(3)),FAMILY,ZERO,model_hash,root)
    block([tx(3,'contribute',dict(contribution=bundle,family=FAMILY,parent_release=ZERO,artifact=model_hash,size=len(model_bytes),components_root=root,submission_round=0))])
    block([tx(i,'evaluate',dict(contribution=bundle,plan=PLAN,evidence=H('whole-evaluation',bundle,inputs.raw(partition+'-result.json')),score=observed['results'][partition]['whole_gain']['score']))for i,partition in enumerate(['evaluation_a','evaluation_b'])])
    budget=100000;total=sum(s for _,_,s in allocations);rid=release_id(ZERO,bundle,budget,root,total)
    block([tx(3,'publish_release',dict(release=rid,parent_release=ZERO,bundle=bundle,budget=budget,allocation_root=root,total_score=total,allocations=sorted((cid,s)for cid,_,s in allocations)))])
    release_height=l.block(tip)[1]
    while l.block(tip)[1]<release_height+PARAMS['reward_maturity_blocks']:block([])
    claims=[]
    for i in eligible:
        cid=contributions[i];score=next(s for c,_,s in allocations if c==cid);claims.append(tx(i,'claim_reward',dict(release=rid,contribution=cid,score=score,siblings=proofs[cid])))
    block(claims);_,generation,state=l.read_active();allocated=sum(state['release:'+rid.hex()]['claims'].values());require(allocated<=budget,'BUDGET')
    before=state_root(state);i=eligible[0];cid=contributions[i];score=next(s for c,_,s in allocations if c==cid)
    duplicate=sign(key(i),nonces[i]+1,'claim_reward',dict(release=rid,contribution=cid,score=score,siblings=proofs[cid]))
    rejected=False
    try:l.make(tip,[duplicate],work_inputs=(wa,wb))
    except ValueError as e:rejected=str(e)=='DUPLICATE'
    require(rejected and state_root(l.read_active()[2])==before,'DUPLICATE_REWARD')
    # Two actual replicas are read without consulting the original author artifact.
    for name in ['custodian-a','custodian-b']:
        p=out/name;p.mkdir();(p/'model.json').write_bytes(model_bytes);require(H('artifact',(p/'model.json').read_bytes())==model_hash,'DA')
    quota=quota_identity(public(key(3)),nonces.get(3,0)+1,public(key(4)),public(key(0)),2,l.block(tip)[1]+100);block([tx(3,'reserve_quota',dict(quota=quota,consumer=public(key(4)),provider=public(key(0)),units=2,deadline=l.block(tip)[1]+100))])
    # Withdraw only our frozen author copy. Original evidence paths are never
    # renamed or reopened; the consumer reads one retained replica and inputs.
    original=out/'verified-inputs/model.json';offline=out/'verified-inputs/model.author-offline';original.rename(offline)
    effect=EffectJournal(out/'effects.sqlite');op=H('public-consumer-request',rid,quota);effect.enter(op,model_hash,generation)
    try:
        subprocess.run([sys.executable,str(Path(__file__).with_name('model_loop.py')),'--mode','infer','--tasks',str(out/'verified-inputs/consumer.json'),'--model',str(out/'custodian-a/model.json'),'--out',str(out/'consumer-service.json')],check=True)
    finally:offline.rename(original)
    service_bytes = read_bounded(out/'consumer-service.json', MAX_TASK_BYTES)
    service = json.loads(service_bytes, object_pairs_hook=unique)
    consumer = inputs.parsed('consumer.json')
    require(service['schema'] == 'controlled-source-inference-v2' and
            service['model_artifact'] == model_hash.hex() and
            service['task_commitment'] == H('tasks', canonical(consumer)).hex() and
            canonical(service['predictions']) == canonical(predict_rows(model, consumer)) and
            service['training_consent'] is False, 'CONSUMER_SNAPSHOT_BINDING')
    for name, raw in inputs.files:
        require(read_bounded(out/'verified-inputs'/name, len(raw)) == raw, 'SETTLEMENT_SNAPSHOT_CHANGED')
    nextnonce=nonces[0]+1
    fields={'network':NETWORK.hex(),'parameters':PARAMETER_HASH.hex(),'model':model_hash.hex(),'request':op.hex(),'input':H('request-input',inputs.raw('consumer.json')).hex(),'output':H('served-output',service_bytes).hex(),'provider':public(key(0)).hex(),'quota':quota.hex(),'units':1,'provider_nonce':nextnonce}
    exact_receipt=encode_receipt(fields);(out/'inference-receipt.json').write_bytes(exact_receipt)
    result=verify_receipt(exact_receipt,fields)
    acknowledgement=key(4).sign(H('use',NETWORK,PARAMETER_HASH,quota,public(key(0)),u64(nextnonce),u64(1),result))
    block([tx(0,'consume_quota',dict(quota=quota,units=1,result=result,consumer_signature=acknowledgement))])
    _,_,state=l.read_active();require('account:'+public(key(4)).hex()not in state,'FREE_CONSUMER_CHARGED');require(total_funds(state)==state['meta:issued'],'CONSERVATION')
    effect.db.close();l.close()
    report.update(outcome='experimental_release_claim_and_free_service_completed',release=rid.hex(),adopted_model=model_hash.hex(),rewarded_experts=eligible,model_reward=allocated,budget=budget,duplicate_claim_rejected=rejected,author_source_withdrawal_test=True,author_withdrawal_scope='frozen-local-author-copy',replicas=2,consumer_paid=0,consumer_result=result.hex(),block_count=len(blocks),blocks=blocks,block_seconds=timings,actual_model_work_used_after_first_block=True,consensus_security_accepted=False)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k not in {'blocks','block_seconds'}}),flush=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--out',required=True);p.add_argument('--bundle-hash',required=True);a=p.parse_args();run(a.input,a.out,a.bundle_hash)
