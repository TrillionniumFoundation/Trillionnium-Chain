
import hashlib,json,platform,resource,sys,time
from pathlib import Path
root=Path(__file__).resolve().parent
manifest=json.loads((root/'manifest.json').read_text())
for name,digest in manifest['files'].items():
    if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:raise ValueError('SOURCE_HASH')
sys.path.insert(0,str(root/'formal/pon-nakamoto-v1'))
from evaluation_bundle import evaluate_bundle,read_bounded,MAX_BUNDLE_BYTES,MAX_TASK_BYTES
bundle=read_bounded(root/'inputs/evaluation-bundle.json',MAX_BUNDLE_BYTES)
calibration=json.loads(read_bounded(root/'inputs/calibration.json',MAX_TASK_BYTES))
expected=json.loads((root/'inputs/expected.json').read_text());samples=[]
for partition in ['evaluation_a','evaluation_b','consumer']:
    rows=json.loads(read_bounded(root/('inputs/'+partition+'.json'),MAX_TASK_BYTES))
    started=time.perf_counter_ns()
    result=evaluate_bundle(bundle,manifest['bundle_hash'],rows,partition,calibration_rows=calibration)
    elapsed=time.perf_counter_ns()-started
    encoded=json.dumps(result,sort_keys=True,separators=(',',':')).encode()
    digest=hashlib.sha256(encoded).hexdigest()
    if digest!=expected[partition]:raise ValueError('EVALUATION_PARITY')
    samples.append({'partition':partition,'rows':len(rows),'result_sha256':digest,'elapsed_ns':elapsed,
                    'exploratory_score':result['primary']['exploratory_score'],
                    'public_reward_eligible':result['public_reward_eligible']})
print(json.dumps({'source_manifest':manifest,'platform':platform.platform(),'machine':platform.machine(),
 'completed_utc_ns':time.time_ns(),'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
 'samples':samples,'parity_passed':True,'independent_operator':False,'ordinary_hepta_entry':False,
 'native_consensus_host':False,'production_activation':False}))
