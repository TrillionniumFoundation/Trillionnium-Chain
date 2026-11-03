"""Read train-listed historical source files only; verify before diagnosing."""
import collections,hashlib,json,re,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
from experiments.model_loop import features
from contract_wire import H,u64
SOURCE='6cdbf9551aae1754e489773bac29bc0598e20a9b'
def show(path):return subprocess.check_output(['git','show',SOURCE+':'+path],cwd=ROOT)
def run():
    raw=(ROOT/'evidence/pon-evaluation-bundle-v1/model/train.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest()=='bde4f99f3d1adc49ed06ee170a204f33057d93d0ddfce598148cc535c47b48fe'
    rows=json.loads(raw);assert all(r['split']=='train' for r in rows)
    oof=json.loads((ROOT/'evidence/train-only-quantization-20261103/report.json').read_text())
    predictions={r['id']:r for r in oof['out_of_fold']}
    inv=json.loads(show('config/portability-inventory-v1.json'));classes=['M00','M04','M10']
    sources={};found={}
    for path in sorted({r['file'] for r in rows}):
        data=show(path);sources[path]=hashlib.sha256(data).hexdigest()
        text=re.sub(r'(?m)^\s*//.*$','',data.decode())
        matches=list(re.finditer(r'(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)',text))
        starts=[m.start() for m in matches] or [0]
        owners=[x['module'] for x in inv['packages'] if path.startswith(x['path']+'/src/')];assert len(owners)==1
        for j,start in enumerate(starts):
            end=starts[j+1] if j+1<len(starts) else len(text)
            snippet=text[start:end][:4096]
            if len(snippet)<80:continue
            normalized=re.sub(r'\s+',' ',snippet).strip()
            identity=H('source-task',SOURCE.encode(),path.encode(),u64(start)).hex()
            # Direct attribute only: does not claim a full Rust cfg/module parser.
            attribute=bool(re.search(r'#\[(?:test|tokio::test(?:\([^\]]*\))?)\]\s*$',text[max(0,start-200):start]))
            found[identity]={'file':path,'source_content_sha256':hashlib.sha256(normalized.encode()).hexdigest(),'x':features(normalized),'label':classes.index(owners[0]),'name':matches[j].group(1) if matches else None,'direct_test_attribute':attribute,'snippet_truncated_4096':end-start>4096,'span_characters_before_truncation':end-start}
    details=[]
    for row in rows:
        d=found[row['id']]
        for k in ('file','source_content_sha256','x','label'):assert row[k]==d[k],(row['id'],k)
        o=predictions[row['id']];assert o['true']==row['label']
        details.append({k:v for k,v in d.items() if k not in ('x','source_content_sha256')}|{'id':row['id'],'prediction':o['integer'],'correct':o['integer']==row['label'],'fold':o['fold']})
    groups={}
    for label,name in enumerate(classes):
        for test in (False,True):
            group=[r for r in details if r['label']==label and r['direct_test_attribute']==test]
            groups[name+('_direct_test' if test else '_other')]={'rows':len(group),'correct':sum(r['correct'] for r in group),'predicted_M10':sum(r['prediction']==2 for r in group),'truncated':sum(r['snippet_truncated_4096'] for r in group)}
    bad=[r for r in details if r['label']==0 and r['prediction']==2]
    report={'schema':'chain-train-corpus-audit-v1','source_commit':SOURCE,'train_sha256':hashlib.sha256(raw).hexdigest(),'verified_exact_train_rows':len(details),'verified_owner_labels':True,'historical_sources_sha256':sources,'class_and_direct_test_groups':groups,'M00_to_M10_errors':len(bad),'M00_to_M10_direct_test_errors':sum(r['direct_test_attribute'] for r in bad),'M00_to_M10_truncated_errors':sum(r['snippet_truncated_4096'] for r in bad),'rows':details,'limitations':['Direct test attribute heuristic is not a Rust AST parser; cfg(test) helpers may be missed.','Source feature reconstruction matches original training rows; label ownership is not semantic separability.','No historical calibration/evaluation/consumer task files loaded.','Association of test markers with errors is not causal proof.'],'model_changed':False,'independent_efficacy_claim':False}
    print(json.dumps(report,indent=2))
if __name__=='__main__':run()
