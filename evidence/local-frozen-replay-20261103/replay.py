"""Replay original sealed inputs; no retraining, tuning, or efficacy claim."""
import hashlib,json,platform,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
from evaluation_bundle import evaluate_bundle
inputs=ROOT/'evidence/pon-evaluation-bundle-v1/model'
report=json.loads((inputs/'report.json').read_text())
raw=(inputs/'evaluation-bundle.json').read_bytes()
calibration=json.loads((inputs/'calibration.json').read_text())
results=[]
for partition in ('evaluation_a','evaluation_b','consumer'):
    rows=json.loads((inputs/(partition+'.json')).read_text())
    result=evaluate_bundle(raw,report['evaluation_bundle'],rows,partition,calibration_rows=calibration)
    original=json.loads((inputs/(partition+'-result.json')).read_text())
    assert result['predictions']==original['predictions']
    assert dict(result['primary'],score=result['primary']['exploratory_score'])==original['whole_gain']
    results.append({'partition':partition,'samples':len(rows),'candidate_correct':sum(p==r['label'] for p,r in zip(result['predictions'],rows)), 'locked_control':result['selected_reference'],'locked_control_correct':result['control_correct'][result['selected_reference']], 'gate':result['primary']['cluster_gate'],'original_predictions_and_gate_exact_match':True,'public_reward_eligible':False})
print(json.dumps({'schema':'local-frozen-replay-v1','source_base':'cca911b47731c9c6f6b61e39758ca3ad17a33555','python':platform.python_version(),'bundle_hash':report['evaluation_bundle'],'input_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(inputs.glob('*.json'))},'results':results,'new_training':False,'new_future_window':False,'independent_acceptance':False,'production_activation':False},indent=2))
