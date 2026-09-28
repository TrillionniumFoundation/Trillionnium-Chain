"""Bind observed model artifacts to actual signed transactions, work and disk settlement.
Experimental 2-of-3 attested evaluators and all accounts are controlled by this harness.
No external token, independent operators or ordinary Hepta entry is claimed.
"""
from pathlib import Path
import argparse,json,sys,subprocess,shutil,time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ledger import *

def run(directory,out):
    directory=Path(directory);out=Path(out);out.mkdir(parents=True,exist_ok=True)
    observed=json.loads((directory/'report.json').read_text());model=json.loads((directory/'model.json').read_text())
    report={'schema':'pon-observed-artifact-settlement-v1','source_model':observed['models']['artifact_hash'],'ordinary_hepta_entry':False,'independent_evaluators':False,'future_window_accepted':False,'asset':'test-unit-no-market-value','chain_clock':'fixed logical timestamps; no live-clock acceptance','production_activation':False}
    eligible=[i for i in range(3)if min(observed['results'][p]['marginal'][i]['score']for p in ['evaluation_a','evaluation_b'])>0]
    whole=min(observed['results'][p]['whole_gain']['score']for p in ['evaluation_a','evaluation_b'])
    if not eligible or not whole:
        report.update(outcome='not_adopted',model_reward=0,reason='preregistered statistical gate not met');(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');return
    l=Ledger(out/'chain');tip=GENESIS;nonces={i:0 for i in range(5)};blocks=[];timings=[]
    data=(directory/'model-work.bin').read_bytes();values=list(struct.unpack('<'+'I'*(2*work.CELLS),data[4:4+8*work.CELLS]));wa,wb=values[:work.CELLS],values[work.CELLS:];task=work.task_id(wa,wb)
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
        initial.append(tx(i,'contribute',dict(contribution=cid,family=FAMILY,parent_release=ZERO,artifact=artifact,size=len(b),components_root=ZERO)))
    block(initial)
    votes=[]
    for i,cid in enumerate(contributions):
        evaluators=[j for j in range(3)if j!=i]
        for j,partition in zip(evaluators,['evaluation_a','evaluation_b']):
            obs=observed['results'][partition];score=obs['marginal'][i]['score'];evidence=H('observed-evaluation',cid,(directory/(partition+'-result.json')).read_bytes())
            votes.append(tx(j,'evaluate',dict(contribution=cid,plan=PLAN,evidence=evidence,score=score)))
    block(votes)
    allocations=[(contributions[i],public(key(i)),min(observed['results'][p]['marginal'][i]['score']for p in ['evaluation_a','evaluation_b']))for i in eligible]
    root,proofs=allocation_root_and_proofs(allocations);model_bytes=(directory/'model.json').read_bytes();model_hash=H('artifact',model_bytes)
    bundle=contribution_id(public(key(3)),FAMILY,ZERO,model_hash,root)
    block([tx(3,'contribute',dict(contribution=bundle,family=FAMILY,parent_release=ZERO,artifact=model_hash,size=len(model_bytes),components_root=root))])
    block([tx(i,'evaluate',dict(contribution=bundle,plan=PLAN,evidence=H('whole-evaluation',bundle,(directory/(partition+'-result.json')).read_bytes()),score=observed['results'][partition]['whole_gain']['score']))for i,partition in enumerate(['evaluation_a','evaluation_b'])])
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
    quota=H('public-consumer-quota',rid);block([tx(3,'reserve_quota',dict(quota=quota,consumer=public(key(4)),provider=public(key(0)),units=2,deadline=l.block(tip)[1]+100))])
    original=directory/'model.json';offline=directory/'model.author-offline';original.rename(offline)
    effect=EffectJournal(out/'effects.sqlite');op=H('public-consumer-request',rid,quota);effect.enter(op,model_hash,generation)
    try:
        subprocess.run([sys.executable,str(Path(__file__).with_name('model_loop.py')),'--mode','evaluate','--tasks',str(directory/'consumer.json'),'--model',str(out/'custodian-a/model.json'),'--out',str(out/'consumer-service.json')],check=True)
    finally:offline.rename(original)
    result=H('served-output',(out/'consumer-service.json').read_bytes());nextnonce=nonces[0]+1
    acknowledgement=key(4).sign(H('use',quota,public(key(0)),u64(nextnonce),u64(1),result))
    block([tx(0,'consume_quota',dict(quota=quota,units=1,result=result,consumer_signature=acknowledgement))])
    _,_,state=l.read_active();require('account:'+public(key(4)).hex()not in state,'FREE_CONSUMER_CHARGED');require(total_funds(state)==state['meta:issued'],'CONSERVATION')
    effect.db.close();l.close()
    report.update(outcome='experimental_release_claim_and_free_service_completed',release=rid.hex(),adopted_model=model_hash.hex(),rewarded_experts=eligible,model_reward=allocated,budget=budget,duplicate_claim_rejected=rejected,author_source_withdrawal_test=True,replicas=2,consumer_paid=0,consumer_result=result.hex(),block_count=len(blocks),blocks=blocks,block_seconds=timings,actual_model_work_used_after_first_block=True,consensus_security_accepted=False)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k not in {'blocks','block_seconds'}}),flush=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--out',required=True);a=p.parse_args();run(a.input,a.out)
