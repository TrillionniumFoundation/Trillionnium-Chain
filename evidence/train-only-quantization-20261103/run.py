"""Fixed train-only quantization diagnostic. Does not load held-out historical data."""
import collections,hashlib,json,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
from experiments.model_loop import np,train,quantize,SCALE
from evaluation import macro_accuracy

def confusion(rows,pred):
    out=[[0]*3 for _ in range(3)]
    for r,p in zip(rows,pred):out[r['label']][int(p)]+=1
    return out

def run():
    plan=json.loads((HERE/'PLAN.json').read_text());data=(ROOT/plan['input']).read_bytes()
    assert hashlib.sha256(data).hexdigest()==plan['input_sha256'],'INPUT_CHANGED'
    rows=json.loads(data);assert all(r['split']=='train' for r in rows)
    files=collections.defaultdict(list)
    for i,r in enumerate(rows):files[r['file']].append(i)
    folds={}
    for label in range(3):
        group=[f for f,ii in files.items() if rows[ii[0]]['label']==label]
        for f in group:assert {rows[i]['label'] for i in files[f]}=={label}
        for j,f in enumerate(sorted(group,key=lambda f:hashlib.sha256(f.encode()).digest())):folds[f]=j%5
    predictions={name:[None]*len(rows) for name in ('float','integer')};details=[]
    for fold in range(5):
        fit=[r for r in rows if folds[r['file']]!=fold];indices=[i for i,r in enumerate(rows) if folds[r['file']]==fold];test=[rows[i] for i in indices]
        assert {r['file'] for r in fit}.isdisjoint(r['file'] for r in test)
        seed=[r for label in range(3) for r in [r for r in fit if r['label']==label][:20]]
        base=quantize(train([r['x'] for r in seed],[r['label'] for r in seed],8))
        w=train([r['x'] for r in fit],[r['label'] for r in fit],120,base/SCALE)
        x=np.asarray([r['x'] for r in test],dtype=np.int64)
        fp=np.argmax(x@w.T,axis=1).tolist();ip=np.argmax(x@quantize(w).T,axis=1).tolist()
        for name,pred in (('float',fp),('integer',ip)):
            for i,p in zip(indices,pred):predictions[name][i]=p
        details.append({'fold':fold,'fit_rows':len(fit),'test_rows':len(test),'test_files':len({r['file'] for r in test}),'float_correct':sum(p==r['label'] for p,r in zip(fp,test)),'integer_correct':sum(p==r['label'] for p,r in zip(ip,test)),'float_file_macro':float(macro_accuracy(test,fp)),'integer_file_macro':float(macro_accuracy(test,ip)),'disagreements':sum(a!=b for a,b in zip(fp,ip)),'quantized_clipped_weights':int(np.sum(np.abs(np.rint(w*SCALE))>32767))})
    buckets=collections.defaultdict(list)
    for i,r in enumerate(rows):buckets[tuple(r['x'])].append(i)
    ambiguous=[ii for ii in buckets.values() if len({rows[i]['label'] for i in ii})>1]
    report={'schema':'train-only-quantization-report-v1','plan_sha256':hashlib.sha256((HERE/'PLAN.json').read_bytes()).hexdigest(),'input_sha256':plan['input_sha256'],'rows':len(rows),'files':len(files),'file_size_min':min(map(len,files.values())),'file_size_max':max(map(len,files.values())),'folds':details,'summary':{name:{'correct':sum(p==r['label'] for p,r in zip(pred,rows)),'file_macro':float(macro_accuracy(rows,pred)),'confusion_true_rows_predicted_columns':confusion(rows,pred)} for name,pred in predictions.items()},'identical_feature_cross_label_groups':len(ambiguous),'identical_feature_cross_label_rows':sum(map(len,ambiguous)),'unavoidable_errors_for_any_deterministic_classifier_on_these_features':sum(len(ii)-max(collections.Counter(rows[i]['label'] for i in ii).values()) for ii in ambiguous),'per_file':[{'file':f,'fold':folds[f],'rows':len(ii),'integer_errors':sum(predictions['integer'][i]!=rows[i]['label'] for i in ii)}for f,ii in sorted(files.items())],'out_of_fold':[{'id':r['id'],'fold':folds[r['file']],'true':r['label'],'float':predictions['float'][i],'integer':predictions['integer'][i]}for i,r in enumerate(rows)],'historical_train_only':True,'new_unseen_external_data':False,'model_changed':False,'public_reward':0,'independent_acceptance':False}
    print(json.dumps(report,indent=2))
if __name__=='__main__':run()
