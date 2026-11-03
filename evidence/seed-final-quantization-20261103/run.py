"""Fixed 2x2 seed/final quantization diagnostic; only original TRAIN data."""
import collections,hashlib,json,platform,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
from experiments.model_loop import np,train,quantize,SCALE
from evaluation import macro_accuracy
ARMS=('FF','FQ','QF','QQ')
def cm(rows,p):
    m=[[0]*3 for _ in range(3)]
    for r,x in zip(rows,p):m[r['label']][int(x)]+=1
    return m
def difference(a,b):
    d=np.asarray(a,dtype=np.float64)-np.asarray(b,dtype=np.float64)
    return {'max_abs':float(np.max(np.abs(d))),'l2':float(np.linalg.norm(d)),'nonzero_entries':int(np.count_nonzero(d))}
def run():
    plan_raw=(HERE/'PLAN.json').read_bytes();plan=json.loads(plan_raw)
    raw=(ROOT/plan['input']).read_bytes();assert hashlib.sha256(raw).hexdigest()==plan['input_sha256']
    rows=json.loads(raw);assert len(rows)==1005 and all(r['split']=='train'for r in rows)
    old_raw=(ROOT/plan['fold_reference']).read_bytes();old=json.loads(old_raw);refs={r['id']:r for r in old['out_of_fold']}
    assert len(refs)==len(rows)and set(refs)=={r['id']for r in rows}
    files=collections.defaultdict(list)
    for r in rows:files[r['file']].append(r)
    folds={}
    for label in range(3):
        group=[f for f,rs in files.items()if rs[0]['label']==label]
        for f in group:assert {r['label']for r in files[f]}=={label}
        for i,f in enumerate(sorted(group,key=lambda f:hashlib.sha256(f.encode()).digest())):folds[f]=i%5
    for r in rows:assert refs[r['id']]['fold']==folds[r['file']] and refs[r['id']]['true']==r['label']
    all_preds={a:[None]*len(rows)for a in ARMS};observations=[None]*len(rows);fold_reports=[];weights=[]
    for fold in range(5):
        fit=[r for r in rows if folds[r['file']]!=fold];ii=[i for i,r in enumerate(rows)if folds[r['file']]==fold];test=[rows[i]for i in ii]
        assert {r['file']for r in fit}.isdisjoint(r['file']for r in test)
        seed_rows=[r for label in range(3)for r in [r for r in fit if r['label']==label][:20]]
        seed_float=train([r['x']for r in seed_rows],[r['label']for r in seed_rows],8)
        seed_int=quantize(seed_float);seed_quantized=seed_int.astype(np.float64)/SCALE
        xfit=[r['x']for r in fit];yfit=[r['label']for r in fit]
        wf=train(xfit,yfit,120,seed_float);wq=train(xfit,yfit,120,seed_quantized)
        qf=quantize(wf);qq=quantize(wq);x=np.asarray([r['x']for r in test],dtype=np.int64)
        score={'FF':x@wf.T,'FQ':x@qf.T,'QF':x@wq.T,'QQ':x@qq.T}
        pred={a:np.argmax(score[a],axis=1).tolist()for a in ARMS}
        assert pred['QF']==[refs[r['id']]['float']for r in test],'OLD_FLOAT_CONTROL_DRIFT'
        assert pred['QQ']==[refs[r['id']]['integer']for r in test],'OLD_INTEGER_CONTROL_DRIFT'
        unit_score={a:score[a].astype(np.float64)/(SCALE if a in ('FQ','QQ')else 1)for a in ARMS}
        margins={a:(np.sort(unit_score[a],axis=1)[:,-1]-np.sort(unit_score[a],axis=1)[:,-2]).tolist()for a in ARMS}
        comparisons={name:sum(pred[a][i]!=pred[b][i]for i in range(len(test)))for name,a,b in [('seed_before_final','FF','QF'),('seed_after_final','FQ','QQ'),('final_from_float_seed','FF','FQ'),('final_from_quantized_seed','QF','QQ')]}
        interaction=(unit_score['QQ']-unit_score['QF'])-(unit_score['FQ']-unit_score['FF'])
        fold_reports.append({'fold':fold,'fit_rows':len(fit),'test_rows':len(test),'fit_files':len({r['file']for r in fit}),'test_files':len({r['file']for r in test}),'seed_row_ids':[r['id']for r in seed_rows],'prediction_disagreements':comparisons,'seed_weight_change':difference(seed_float,seed_quantized),'pooled_weight_change':difference(wf,wq),'seed_logit_shift_before_final':difference(unit_score['FF'],unit_score['QF']),'seed_logit_shift_after_final':difference(unit_score['FQ'],unit_score['QQ']),'logit_interaction_max_abs':float(np.max(np.abs(interaction))),'clipped_weights':{'seed':int(np.sum(np.abs(np.rint(seed_float*SCALE))>32767)),'float_seed_final':int(np.sum(np.abs(np.rint(wf*SCALE))>32767)),'quantized_seed_final':int(np.sum(np.abs(np.rint(wq*SCALE))>32767))},'margins':{a:{'minimum':min(margins[a]),'exact_top_ties':sum(v==0 for v in margins[a])}for a in ARMS},'both_old_controls_exact_match':True})
        weights.append({'fold':fold,'seed_float':seed_float.tolist(),'seed_quantized_integer':seed_int.tolist(),'pooled_float_seed':wf.tolist(),'pooled_quantized_seed':wq.tolist(),'final_float_seed_integer':qf.tolist(),'final_quantized_seed_integer':qq.tolist()})
        for j,i in enumerate(ii):
            for a in ARMS:all_preds[a][i]=pred[a][j]
            observations[i]={'id':rows[i]['id'],'fold':fold,'true':rows[i]['label'],'predictions':{a:pred[a][j]for a in ARMS},'logits_common_units':{a:unit_score[a][j].tolist()for a in ARMS},'top_margins_common_units':{a:margins[a][j]for a in ARMS}}
    result={'schema':'chain-seed-final-quantization-2x2-result-v1','plan_sha256':hashlib.sha256(plan_raw).hexdigest(),'input_sha256':hashlib.sha256(raw).hexdigest(),'old_control_report_sha256':hashlib.sha256(old_raw).hexdigest(),'environment':{'python':platform.python_version(),'numpy':np.__version__},'rows':len(rows),'files':len(files),'primary_seed_before_final_prediction_disagreements':sum(f['prediction_disagreements']['seed_before_final']for f in fold_reports),'disagreements':{k:sum(f['prediction_disagreements'][k]for f in fold_reports)for k in fold_reports[0]['prediction_disagreements']},'metrics':{a:{'correct':sum(p==r['label']for p,r in zip(pred,rows)),'file_macro':float(macro_accuracy(rows,pred)),'confusion':cm(rows,pred)}for a,pred in all_preds.items()},'folds':fold_reports,'out_of_fold':observations,'all_original_rows_scored':True,'controls_exact_match':True,'new_independent_data':False,'model_adopted':False,'public_reward':0}
    (HERE/'weights.json').write_text(json.dumps(weights,indent=2)+'\n')
    print(json.dumps(result,indent=2))
if __name__=='__main__':run()
