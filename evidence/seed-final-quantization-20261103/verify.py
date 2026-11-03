"""Replay stored 2x2 weights and all OOF accounting, without refitting."""
import collections,gzip,hashlib,json,sys
from pathlib import Path
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
from experiments.model_loop import np,quantize,SCALE
from evaluation import macro_accuracy

def read(name):
 p=P/name
 return p.read_bytes()if p.exists()else gzip.decompress((P/(name+'.gz')).read_bytes())
r=json.loads(read('report.json'));weights=json.loads(read('weights.json'));plan_raw=(P/'PLAN.json').read_bytes();plan=json.loads(plan_raw)
assert hashlib.sha256(plan_raw).hexdigest()==r['plan_sha256']
raw=(ROOT/plan['input']).read_bytes();assert hashlib.sha256(raw).hexdigest()==r['input_sha256']==plan['input_sha256']
rows=json.loads(raw);assert all(x['split']=='train'for x in rows)
old_raw=(ROOT/plan['fold_reference']).read_bytes();assert hashlib.sha256(old_raw).hexdigest()==r['old_control_report_sha256']
old={x['id']:x for x in json.loads(old_raw)['out_of_fold']};oof=r['out_of_fold'];assert len(oof)==len(rows)==len({x['id']for x in oof})==1005
arms=('FF','FQ','QF','QQ');folds={}
for row,out in zip(rows,oof):
 assert row['id']==out['id']and row['label']==out['true'];assert old[row['id']]['fold']==out['fold']
 folds.setdefault(row['file'],out['fold']);assert folds[row['file']]==out['fold']
assert len(folds)==150
for w in weights:
 fold=w['fold'];ii=[i for i,x in enumerate(oof)if x['fold']==fold];test=[rows[i]for i in ii];fit=[x for x in rows if folds[x['file']]!=fold]
 seed_ids=[x['id']for label in range(3)for x in [z for z in fit if z['label']==label][:20]];assert seed_ids==r['folds'][fold]['seed_row_ids']
 assert {x['file']for x in fit}.isdisjoint(x['file']for x in test)
 sf=np.asarray(w['seed_float']);si=np.asarray(w['seed_quantized_integer']);wf=np.asarray(w['pooled_float_seed']);wq=np.asarray(w['pooled_quantized_seed']);qf=np.asarray(w['final_float_seed_integer']);qq=np.asarray(w['final_quantized_seed_integer'])
 assert np.array_equal(quantize(sf),si)and np.array_equal(quantize(wf),qf)and np.array_equal(quantize(wq),qq)
 x=np.asarray([row['x']for row in test],dtype=np.int64);scores={'FF':x@wf.T,'FQ':x@qf.T,'QF':x@wq.T,'QQ':x@qq.T}
 for arm,score in scores.items():
  pred=np.argmax(score,axis=1);unit=score.astype(np.float64)/(SCALE if arm in ('FQ','QQ')else 1);ordered=np.sort(unit,axis=1);margin=ordered[:,-1]-ordered[:,-2]
  for j,i in enumerate(ii):
   assert int(pred[j])==oof[i]['predictions'][arm]
   assert np.array_equal(unit[j],oof[i]['logits_common_units'][arm])
   assert float(margin[j])==oof[i]['top_margins_common_units'][arm]
   if arm in ('QF','QQ'):assert int(pred[j])==old[rows[i]['id']]['float'if arm=='QF'else 'integer']
for arm in arms:
 pred=[x['predictions'][arm]for x in oof];m=[[0]*3 for _ in range(3)]
 for row,p in zip(rows,pred):m[row['label']][p]+=1
 assert m==r['metrics'][arm]['confusion']
 assert sum(m[i][i]for i in range(3))==r['metrics'][arm]['correct']
 assert float(macro_accuracy(rows,pred))==r['metrics'][arm]['file_macro']
for key,a,b in [('seed_before_final','FF','QF'),('seed_after_final','FQ','QQ'),('final_from_float_seed','FF','FQ'),('final_from_quantized_seed','QF','QQ')]:
 assert sum(x['predictions'][a]!=x['predictions'][b]for x in oof)==r['disagreements'][key]
assert r['primary_seed_before_final_prediction_disagreements']==r['disagreements']['seed_before_final']==1
print(json.dumps({'result':'PASS','rows':1005,'whole_file_groups':150,'folds':5,'arms':4,'stored_weight_logits_margins_and_predictions_exact':True,'old_float_and_integer_controls_exact':True,'all_metrics_recomputed':True,'disagreements':r['disagreements'],'model_adopted':False},indent=2))
