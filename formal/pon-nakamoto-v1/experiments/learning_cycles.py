"""Three controlled real-learning attempts, allowing unchanged public parameters.

The source corpus is retrospective public code, not unseen future user experience.
Successful training never manufactures public reward eligibility or Hepta owner receipts.
"""
from __future__ import annotations
import argparse,copy,json,time
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from experiments.model_loop import corpus,train,quantize,predict,artifact,np,DIM,SCALE,CLASSES
from evaluation_bundle import control_models,freeze_bundle,evaluate_bundle,verify_bundle,write_new
from ledger import FAMILY
from contract_wire import canonical,H

def run(source,out):
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    tasks=corpus(source);groups={}
    for row in tasks:groups.setdefault(row['file'],[]).append(row)
    ordered=sorted(groups,key=lambda name:H('cycle-source-group',name.encode()))
    bootstrap_files=set()
    for label in range(3):
        bootstrap_files.update([name for name in ordered if groups[name][0]['label']==label][:3])
    pools=[[]for _ in range(3)]
    for index,name in enumerate(name for name in ordered if name not in bootstrap_files):pools[index%3].append(name)
    # Bootstrap-only source groups are never put into later evaluation partitions.
    seed=[]
    for label in range(3):
        seed.extend([row for name in ordered if name in bootstrap_files for row in groups[name] if row['label']==label][:20])
    base=quantize(train([r['x']for r in seed],[r['label']for r in seed],8))
    current={'schema':'hepta-source-owner-linear-256-v1','family':FAMILY.hex(),'scale':SCALE,'source':source,
             'base':base.tolist(),'router':np.zeros((3,DIM),dtype=np.int64).tolist(),
             'deltas':np.zeros((3,3,DIM),dtype=np.int64).tolist(),'feature':'signed-token-hash-256-clipped8-plus-bias-v1','classes':CLASSES}
    initial=artifact(current,out/'bootstrap.json').hex();rows=[]
    for cycle,files in enumerate(pools,1):
        directory=out/f'cycle-{cycle}';directory.mkdir()
        partitions={'train':[],'calibration':[],'evaluation':[]}
        for index,name in enumerate(files):
            split='evaluation'if index%4==0 else 'calibration'if index%4==1 else 'train'
            partitions[split].extend(groups[name])
        for name,data in partitions.items():(directory/(name+'.json')).write_bytes(canonical(data))
        before=H('artifact',canonical(current)).hex();started=time.perf_counter_ns();candidate=copy.deepcopy(current)
        base=np.asarray(current['base'],dtype=np.int64);deltas=[];training=partitions['train']
        for i in range(3):
            shard=[r for r in training if r['label']==i or int(r['id'][:8],16)%3==i]
            start_weights=(base+np.asarray(current['deltas'][i],dtype=np.int64))/SCALE
            weights=train([r['x']for r in shard],[r['label']for r in shard],120,start_weights)
            deltas.append((quantize(weights)-base).clip(-32767,32767))
        candidate['deltas']=np.asarray(deltas,dtype=np.int64).tolist()
        calibration=partitions['calibration'];xc=np.array([r['x']for r in calibration],dtype=np.int64);yc=np.array([r['label']for r in calibration])
        # Select expert targets on calibration only; this is not a held-out quality claim.
        candidates=[]
        for delta in deltas:
            logits=xc@(base+delta).T/(8*SCALE);logits-=logits.max(axis=1,keepdims=True)
            probs=np.exp(logits);probs/=probs.sum(axis=1,keepdims=True);candidates.append(probs[np.arange(len(yc)),yc])
        candidate['router']=quantize(train(xc,np.argmax(np.array(candidates).T,axis=1),120,np.asarray(current['router'])/SCALE)).tolist()
        digest=artifact(candidate,directory/'candidate.json').hex()
        pooled=quantize(train([r['x']for r in training],[r['label']for r in training],120,base/SCALE))
        controls=control_models(current,candidate,calibration,pooled.tolist())
        bundle_raw,bundle_hash=freeze_bundle(source_commit=source,round_number=cycle,parent_release='00'*32,
            current=current,candidate=candidate,controls=controls,partitions=partitions)
        write_new(directory/'evaluation-bundle.json',bundle_raw)
        bundle=verify_bundle(bundle_raw,bundle_hash,expected_parent=before)
        selected=bundle['selected'];evaluation=partitions['evaluation']
        observed=evaluate_bundle(bundle_raw,bundle_hash,evaluation,'evaluation',calibration_rows=calibration,expected_parent=before)
        write_new(directory/'bound-evaluation.json',(json.dumps(observed,sort_keys=True,separators=(',',':'))+'\n').encode())
        result=observed['primary']
        # Without independent source/time and owner admission, even an exploratory win
        # cannot change the public pointer. No-update is the valid terminal outcome.
        assert result['public_reward_eligible']is False
        row={'cycle':cycle,'parent_actually_admitted_artifact':before,'candidate':digest,'selected_reference':selected,'evaluation_bundle':bundle_hash,'bound_evaluation':'bound-evaluation.json',
             'training_rows':len(training),'calibration_rows':len(calibration),'evaluation_rows':len(evaluation),
             'source_groups':{k:len({r['file']for r in v})for k,v in partitions.items()},'evaluation':result,
             'outcome':'no_public_update','reward':0,'public_artifact_after':before,'duration_ns':time.perf_counter_ns()-started}
        (directory/'result.json').write_text(json.dumps(row,indent=2)+'\n');rows.append(row)
    report={'schema':'pon-real-training-controlled-cycles-v4','source':source,'bootstrap':initial,'bootstrap_source_groups':sorted(bootstrap_files),'cycles':rows,
            'real_optimization':True,'independent_tasks_across_cycles':False,'file_groups_disjoint_across_cycles':True,
            'new_future_window':False,'ordinary_hepta_entry':False,'independent_evaluators':False,
            'three_improving_public_generations':False,'public_pointer_unchanged':True,'total_model_reward':0,'production_activation':False}
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--out',required=True);a=p.parse_args();run(a.source,a.out)
