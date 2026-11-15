"""Controlled real-parameter learning on public repository routing tasks.
No private user data or provider API is used. This is NOT an ordinary Hepta product run,
independently administered evaluation, or a future-time-window acceptance.
"""
from __future__ import annotations
import os
os.environ.setdefault('OPENBLAS_NUM_THREADS','1');os.environ.setdefault('OMP_NUM_THREADS','1')
import argparse,hashlib,json,re,subprocess,sys,time,tempfile,math
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import numpy as np
from contract_wire import *
from ledger import *
from evaluation import assess,select_reference,freeze_plan
from evaluation_bundle import (control_models, freeze_bundle, verify_bundle, evaluate_bundle,
    write_new, read_bounded, partition_manifest, MAX_TASK_BYTES, MAX_BUNDLE_BYTES)
DIM=257;CLASSES=['M00','M04','M10'];SCALE=1024

def features(text):
    tokens=re.findall(r'[a-zA-Z_][a-zA-Z_0-9]*',text.lower())
    tokens=[t for t in tokens if not t.startswith('trnm')and t not in {'m00','m04','m10'}]
    counts=[0]*256
    for t in tokens[:1024]:
        digest=hashlib.sha256(t.encode()).digest();counts[int.from_bytes(digest[:2],'little')%256]+=1 if digest[2]&1 else -1
    return [max(-8,min(8,v))for v in counts]+[8]

def corpus(source):
    raw=subprocess.check_output(['git','show',source+':config/portability-inventory-v1.json'],cwd=ROOT)
    inv=json.loads(raw);files=subprocess.check_output(['git','ls-tree','-r','--name-only',source],cwd=ROOT,text=True).splitlines()
    grouped={m:[]for m in CLASSES}
    for row in inv['packages']:
        if row['module']not in grouped:continue
        for f in files:
            if f.startswith(row['path']+'/src/')and f.endswith('.rs')and '/tests/'not in f and not f.endswith('/tests.rs'):
                grouped[row['module']].append(f)
    tasks=[];seen=set();splits={0:'consumer',1:'evaluation_a',2:'evaluation_b',3:'calibration'}
    for module,paths in grouped.items():
        ordered=sorted(paths,key=lambda p:hashlib.sha256(p.encode()).digest())
        for index,path in enumerate(ordered):
            text=subprocess.check_output(['git','show',source+':'+path],cwd=ROOT,text=True)
            # Public function snippets; strip comments and explicit crate/module labels.
            text=re.sub(r'(?m)^\s*//.*$','',text)
            starts=[m.start()for m in re.finditer(r'(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[A-Za-z_]\w*',text)]
            if not starts:starts=[0]
            for j,start in enumerate(starts):
                snippet=text[start:starts[j+1]if j+1<len(starts)else len(text)][:4096]
                if len(snippet)<80:continue
                normalized=re.sub(r'\s+',' ',snippet).strip();digest=hashlib.sha256(normalized.encode()).hexdigest()
                if digest in seen:continue
                seen.add(digest);tasks.append({'id':H('source-task',source.encode(),path.encode(),u64(start)).hex(),'file':path,'source_content_sha256':digest,'split':splits.get(index%10,'train'),'label':CLASSES.index(module),'x':features(normalized)})
    return tasks

def train(x,y,steps,initial=None,weight=None):
    w=np.zeros((3,DIM),dtype=np.float64)if initial is None else initial.astype(np.float64).copy()
    x=np.asarray(x,dtype=np.float64)/8;y=np.asarray(y,dtype=np.int64)
    frequencies=np.bincount(y,minlength=3);weights=1.0/frequencies[y]
    if weight is not None:weights*=np.asarray(weight)
    weights/=weights.sum()
    for _ in range(steps):
        logits=x@w.T;logits-=logits.max(axis=1,keepdims=True);probs=np.exp(logits);probs/=probs.sum(axis=1,keepdims=True)
        probs[np.arange(len(y)),y]-=1
        gradient=(probs*weights[:,None]).T@x+.0005*w
        w-=0.3*gradient
    return w

def quantize(w):return np.clip(np.rint(w*SCALE),-32767,32767).astype(np.int64)
def artifact(value,path):
    b=canonical(value);Path(path).write_bytes(b);return H('artifact',b)
from model_contract import load_model

def predict(m,x,removed=None,mode='composed',expert=0):
    x=np.asarray(x,dtype=np.int64);base=np.asarray(m['base'],dtype=np.int64);deltas=np.asarray(m['deltas'],dtype=np.int64)
    if mode=='base':return np.argmax(x@base.T,axis=1)
    if mode=='expert':return np.argmax(x@(base+deltas[expert]).T,axis=1)
    if mode=='merge':return np.argmax(x@(base+np.rint(deltas.mean(axis=0)).astype(np.int64)).T,axis=1)
    route=np.argmax(x@np.asarray(m['router'],dtype=np.int64).T,axis=1)
    logits=x@base.T
    for i in range(3):
        if i!=removed:
            selected=route==i;logits[selected]+=x[selected]@deltas[i].T
    return np.argmax(logits,axis=1)

def gain(correct,reference):
    wins=int(np.sum(correct&~reference));losses=int(np.sum(reference&~correct));n=len(correct);m=wins+losses
    significant=False
    if m and wins>losses and n>=20:
        numerator=sum(math.comb(m,k)for k in range(wins,m+1));significant=20*numerator<=(1<<m)
    return {'samples':n,'wins':wins,'losses':losses,'paired_sign_test_p_le_0_05':significant,'score':max(0,(wins-losses)*1000000//n)if significant else 0}

def worker(args):
    start=time.perf_counter();tasks=json.loads(read_bounded(args.tasks,MAX_TASK_BYTES),object_pairs_hook=unique);partition_manifest(tasks);x=np.array([r['x']for r in tasks],dtype=np.int64);y=np.array([r['label']for r in tasks])
    if args.mode=='train':
        base=np.array(json.loads(Path(args.base).read_text()),dtype=np.float64)/SCALE;i=args.node
        # Non-IID shard: own class plus a disjoint share of other classes, fixed before outcomes.
        mask=np.array([r['label']==i or int(r['id'][:8],16)%3==i for r in tasks])
        w=train(x[mask],y[mask],120,base);delta=(quantize(w)-quantize(base)).clip(-32767,32767)
        value={'node':i,'rows':int(mask.sum()),'file_count':len({r['file']for r,ok in zip(tasks,mask)if ok}),'delta':delta.tolist(),'duration_seconds':time.perf_counter()-start}
    elif args.mode=='infer':
        m=load_model(args.model);pred=predict(m,x)
        value={'schema':'controlled-source-inference-v2','task_commitment':H('tasks',canonical(tasks)).hex(),'model_artifact':H('artifact',Path(args.model).read_bytes()).hex(),'predictions':pred.tolist(),'duration_seconds':time.perf_counter()-start,'training_consent':False}
    else:
        require(args.evaluation_bundle and args.bundle_hash and args.partition and args.calibration, 'FROZEN_BUNDLE_REQUIRED')
        bundle_raw=read_bounded(args.evaluation_bundle,MAX_BUNDLE_BYTES)
        bundle=verify_bundle(bundle_raw,args.bundle_hash)
        # The requested candidate file must be the exact bytes sealed before evaluation.
        candidate_raw=read_bounded(args.model,65536)
        require(H('artifact',candidate_raw).hex()==bundle['candidate_artifact'],'REFERENCE_MODEL')
        calibration=json.loads(read_bounded(args.calibration,MAX_TASK_BYTES),object_pairs_hook=unique)
        result=evaluate_bundle(bundle_raw,args.bundle_hash,tasks,args.partition,calibration_rows=calibration)
        m=bundle['candidate'];pred=np.asarray(result['predictions']);base=predict(m,x,mode='base');correct=pred==y
        whole=dict(result['primary'],score=result['primary']['exploratory_score'])
        marginal=[dict(value,score=value['exploratory_score'])for value in result['marginal']]
        value={'schema':'controlled-source-evaluation-v3','task_commitment':H('tasks',canonical(tasks)).hex(),
          'model_artifact':bundle['candidate_artifact'],'evaluation_bundle':args.bundle_hash,
          'evaluation_partition':args.partition,'value_claim':result['value_claim'],'samples':len(y),'composed_correct':int(correct.sum()),
          'base_correct':int((base==y).sum()),'whole_gain':whole,
          'weak_base_gain_for_comparison_only':gain(correct,base==y),'strong_reference':bundle['selected'],
          'strong_reference_artifact':result['reference_artifact'],
          'strong_reference_correct':result['control_correct'][bundle['selected']],
          'control_correct':result['control_correct'],
          'expert_correct':[int((predict(m,x,mode='expert',expert=i)==y).sum())for i in range(3)],
          'simple_merge_correct':int((predict(m,x,mode='merge')==y).sum()),'marginal':marginal,
          'predictions':pred.tolist(),'duration_seconds':time.perf_counter()-start,
          'independent_administration':False,'public_reward_eligible':False}
    Path(args.out).write_text(json.dumps(value,indent=2)+'\n')

def run(source,out):
    out=Path(out);out.mkdir(parents=True,exist_ok=False);start=time.perf_counter();tasks=corpus(source)
    groups={s:[t for t in tasks if t['split']==s]for s in ['train','calibration','evaluation_a','evaluation_b','consumer']}
    for s,t in groups.items():
        require(len(t)>=20,'INSUFFICIENT_'+s);(out/(s+'.json')).write_text(json.dumps(t)+'\n')
    # Bound class imbalance in the shared seed training. This plan is fixed before held-out evaluation.
    common=[]
    for label in range(3):common.extend([r for r in groups['train']if r['label']==label][:20])
    base=quantize(train([r['x']for r in common],[r['label']for r in common],8));(out/'base.json').write_text(json.dumps(base.tolist())+'\n')
    for i in range(3):
        subprocess.run([sys.executable,__file__,'--mode','train','--tasks',str(out/'train.json'),'--base',str(out/'base.json'),'--node',str(i),'--out',str(out/f'node-{i}.json')],check=True)
    deltas=np.array([json.loads((out/f'node-{i}.json').read_text())['delta']for i in range(3)],dtype=np.int64)
    xc=np.array([r['x']for r in groups['calibration']],dtype=np.int64);yc=np.array([r['label']for r in groups['calibration']])
    scores=[]
    for d in deltas:
        z=xc@(base+d).T/(8*SCALE);z-=z.max(axis=1,keepdims=True);p=np.exp(z);p/=p.sum(axis=1,keepdims=True);scores.append(p[np.arange(len(yc)),yc])
    route_y=np.argmax(np.array(scores).T,axis=1);router=quantize(train(xc,route_y,120))
    model={'schema':'hepta-source-owner-linear-256-v1','family':FAMILY.hex(),'scale':SCALE,'source':source,'base':base.tolist(),'router':router.tolist(),'deltas':deltas.tolist(),'feature':'signed-token-hash-256-clipped8-plus-bias-v1','classes':CLASSES}
    artifact(model,out/'model.json')
    train_rows=groups['train'];pooled=quantize(train([r['x']for r in train_rows],[r['label']for r in train_rows],120,base/SCALE))
    current=dict(model,router=np.zeros((3,DIM),dtype=np.int64).tolist(),deltas=np.zeros((3,3,DIM),dtype=np.int64).tolist())
    controls=control_models(current,model,groups['calibration'],pooled.tolist())
    bundle_raw,bundle_hash=freeze_bundle(source_commit=source,round_number=1,parent_release=ZERO.hex(),
        current=current,candidate=model,controls=controls,partitions=groups)
    write_new(out/'evaluation-bundle.json',bundle_raw)
    reference=verify_bundle(bundle_raw,bundle_hash)
    for split in ['evaluation_a','evaluation_b','consumer']:
        subprocess.run([sys.executable,__file__,'--mode','evaluate','--tasks',str(out/(split+'.json')),
            '--model',str(out/'model.json'),'--evaluation-bundle',str(out/'evaluation-bundle.json'),
            '--bundle-hash',bundle_hash,'--partition',split,'--calibration',str(out/'calibration.json'),'--out',str(out/(split+'-result.json'))],check=True)
    results={s:json.loads((out/(s+'-result.json')).read_text())for s in ['evaluation_a','evaluation_b','consumer']}
    # Equal-order pooled control makes the extra-data/compute advantage visible, not a claimed MoE theorem.
    train_rows=groups['train'];pooled=quantize(train([r['x']for r in train_rows],[r['label']for r in train_rows],120,base/SCALE))
    for split in results:
        x=np.array([r['x']for r in groups[split]],dtype=np.int64);y=np.array([r['label']for r in groups[split]])
        results[split]['pooled_120_epoch_control_correct']=int((np.argmax(x@pooled.T,axis=1)==y).sum())
    # Compute a real model contraction with signed bounds allowing exact finite-field decoding.
    selected=np.array([r['x']for r in groups['consumer'][:64]],dtype=np.int64)
    aa=np.zeros((64,64),dtype=np.int64);aa[:len(selected),:]=selected[:,:64]
    bb=np.zeros((64,64),dtype=np.int64);bb[:,:3]=(base+deltas[0])[:,:64].T
    require(np.max(np.abs(aa))<=128 and np.max(np.abs(bb))<=32767,'MODEL_BOUND')
    context=H('real-model-work',H('artifact',(out/'model.json').read_bytes()),H('tasks',canonical(groups['consumer'])))
    av=(aa%work.Q).ravel().tolist();bv=(bb%work.Q).ravel().tolist();proof=work.prove(context,av,bv)
    _,product=work.verify(context,work.task_id(av,bv),bytes([255])*32,proof)
    signed=np.array([v-work.Q if v>work.Q//2 else v for v in product],dtype=np.int64).reshape(64,64)
    require(np.array_equal(signed,aa@bb),'NUMERIC_BRIDGE');(out/'model-work.bin').write_bytes(proof)
    report={'schema':'controlled-model-loop-report-v1','source':source,'strong_reference':reference['selected'],'evaluation_bundle':bundle_hash,'task':'route public Rust function changes to their actual owning module','private_data_used':False,'ordinary_hepta_product_entry':False,'future_time_window_observed':False,'evaluation_partitions_previously_observed_in_exploration':True,'independent_operators':False,'training_is_real_parameter_optimization':True,
      'plan':{'feature_dimensions':257,'classes':CLASSES,'base_steps':8,'local_steps':120,'router_steps':120,'split':'whole-file-stratified deterministic, exact-content deduplicated','feature_scaling':'signed count clipping to [-8,8], bias=8, no frequency-erasing integer division','class_weighting':'inverse within-training-shard frequency','statistical_rule':'source-file cluster sign test with four-comparison correction against strongest calibration-locked deployable control; local exploratory only','seed_tasks':len(common)},
      'task_counts':{s:len(v)for s,v in groups.items()},'file_counts':{s:len({x['file']for x in v})for s,v in groups.items()},'models':{'artifact_hash':H('artifact',(out/'model.json').read_bytes()).hex(),'bytes':(out/'model.json').stat().st_size,'base_parameters':int(base.size),'delta_parameters':int(deltas.size),'router_parameters':int(router.size)},'results':results,
      'useful_work':{'proof_file':'model-work.bin','task_commitment':work.task_id(av,bv).hex(),'challenge':context.hex(),'proof_bytes':len(proof),'exact_integer_contraction':True,'scope':'first 64 feature coordinates of one selected expert on up to 64 real consumer tasks; not a whole-model training proof'},
      'end_to_end_seconds':time.perf_counter()-start,'production_activation':False}
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'evaluation_bundle':bundle_hash,'task_counts':report['task_counts'],'results':{s:{k:v for k,v in d.items()if k not in {'predictions'}}for s,d in results.items()},'artifact':report['models'],'elapsed':report['end_to_end_seconds']}),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=['run','train','evaluate','infer'],default='run');p.add_argument('--source');p.add_argument('--out',required=True);p.add_argument('--tasks');p.add_argument('--base');p.add_argument('--model');p.add_argument('--reference');p.add_argument('--evaluation-bundle');p.add_argument('--bundle-hash');p.add_argument('--partition');p.add_argument('--calibration');p.add_argument('--node',type=int,default=0);a=p.parse_args()
    if a.mode=='run':run(a.source,a.out)
    else:worker(a)
