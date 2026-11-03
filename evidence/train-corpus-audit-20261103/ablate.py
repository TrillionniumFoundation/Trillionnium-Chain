"""One fixed direct-test training ablation; unchanged out-of-fold score population."""
import hashlib,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
from experiments.model_loop import np,train,quantize,SCALE
from evaluation import macro_accuracy,assess

def fit(rows,test):
    assert {r['label'] for r in rows}=={0,1,2}
    common=[r for label in range(3) for r in [r for r in rows if r['label']==label][:20]]
    base=quantize(train([r['x'] for r in common],[r['label'] for r in common],8))
    w=quantize(train([r['x'] for r in rows],[r['label'] for r in rows],120,base/SCALE))
    return np.argmax(np.asarray([r['x'] for r in test],dtype=np.int64)@w.T,axis=1).tolist()
def metrics(rows,pred):
    matrix=[[0]*3 for _ in range(3)]
    for r,p in zip(rows,pred):matrix[r['label']][p]+=1
    return {'rows':len(rows),'correct':sum(r['label']==p for r,p in zip(rows,pred)),'file_macro':float(macro_accuracy(rows,pred)),'confusion':matrix}
def run():
    raw=(ROOT/'evidence/pon-evaluation-bundle-v1/model/train.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest()=='bde4f99f3d1adc49ed06ee170a204f33057d93d0ddfce598148cc535c47b48fe'
    rows=json.loads(raw);audit=json.loads((HERE/'report.json').read_text());meta={r['id']:r for r in audit['rows']}
    old=json.loads((ROOT/'evidence/train-only-quantization-20261103/report.json').read_text());reference={r['id']:r['integer'] for r in old['out_of_fold']}
    predictions=[None]*len(rows);details=[]
    for fold in range(5):
        train_rows=[r for r in rows if meta[r['id']]['fold']!=fold];ii=[i for i,r in enumerate(rows) if meta[r['id']]['fold']==fold];test=[rows[i] for i in ii]
        assert {r['file'] for r in train_rows}.isdisjoint(r['file'] for r in test)
        baseline=fit(train_rows,test);assert baseline==[reference[r['id']] for r in test]
        clean=[r for r in train_rows if not meta[r['id']]['direct_test_attribute']]
        candidate=fit(clean,test)
        for i,p in zip(ii,candidate):predictions[i]=p
        details.append({'fold':fold,'baseline_fit_rows':len(train_rows),'ablation_fit_rows':len(clean),'baseline':metrics(test,baseline),'ablation':metrics(test,candidate)})
    baseline=[reference[r['id']] for r in rows]
    groups={}
    for name,flag in [('direct_test',True),('other',False)]:
        ii=[i for i,r in enumerate(rows) if meta[r['id']]['direct_test_attribute']==flag]
        groups[name]={'baseline':metrics([rows[i] for i in ii],[baseline[i] for i in ii]),'ablation':metrics([rows[i] for i in ii],[predictions[i] for i in ii])}
    report={'schema':'chain-direct-test-ablation-result-v1','plan_sha256':hashlib.sha256((HERE/'ABLATION_PLAN.json').read_bytes()).hexdigest(),'baseline':metrics(rows,baseline),'ablation':metrics(rows,predictions),'folds':details,'groups':groups,'exploratory_cluster_assessment_only':assess(rows,predictions,baseline),'out_of_fold':[{'id':r['id'],'fold':meta[r['id']]['fold'],'baseline':baseline[i],'ablation':predictions[i]}for i,r in enumerate(rows)],'baseline_recomputed_exact_match':True,'all_original_rows_scored':True,'independent_efficacy_claim':False,'public_reward':0,'model_changed':False}
    print(json.dumps(report,indent=2))
if __name__=='__main__':run()
