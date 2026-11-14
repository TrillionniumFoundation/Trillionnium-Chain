"""Execute the existing actual local model producers; do not manufacture future owners."""
from pathlib import Path
import hashlib,json,os,platform,subprocess,time,sys
R=Path(sys.argv[1]).resolve()
OUT=Path(sys.argv[2]).resolve()
SOURCE=sys.argv[3]
def git(*args): return subprocess.check_output(['git',*args],cwd=R,text=True).strip()
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
assert not git('status','--porcelain')
head=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}')
OUT.mkdir(exist_ok=False); (OUT/'driver.py').write_bytes(Path(__file__).read_bytes())
env=os.environ.copy();env.update(PYTHONDONTWRITEBYTECODE='1',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1')
for k in list(env):
    if k.startswith('TRNM_'):env.pop(k)
report={'schema':'pon-current-model-producer-execution-v1','source_commit':head,'source_tree':tree,
        'input_source_commit':SOURCE,'source_clean':True,
        'platform':platform.platform(),'results':[], 'all_passed':False,
        'ordinary_hepta_entry':False,'independent_operators':False,'future_window_accepted':False,
        'funded_public_serving':False,'production_activation':False,'paid_provider_calls':0}
def run(name,args):
    command=['python3',*args];started=time.monotonic_ns()
    with (OUT/(name+'.log')).open('w') as log:
        child=subprocess.run(command,cwd=R,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=600)
    report['results'].append({'name':name,'command':command,'returncode':child.returncode,'elapsed_ns':time.monotonic_ns()-started})
    if child.returncode: raise RuntimeError(name)
    assert git('rev-parse','HEAD')==head and not git('status','--porcelain')
try:
    run('model-learning',['formal/pon-nakamoto-v1/experiments/model_loop.py','--source',report['input_source_commit'],'--out',str(OUT/'model')])
    observed=json.loads((OUT/'model/report.json').read_text())
    bundle=observed['evaluation_bundle'];report['evaluation_bundle']=bundle
    run('model-settlement',['formal/pon-nakamoto-v1/experiments/settle_model.py','--input',str(OUT/'model'),'--out',str(OUT/'settlement'),'--bundle-hash',bundle])
    run('learning-cycles',['formal/pon-nakamoto-v1/experiments/learning_cycles.py','--source',report['input_source_commit'],'--out',str(OUT/'cycles')])
    report['model_outcome']=json.loads((OUT/'settlement/report.json').read_text())
    report['value_claims']={k:observed['results'][k]['value_claim'] for k in ['evaluation_a','evaluation_b']}
    report['all_passed']=True
finally:
    report['source_clean_after']=git('rev-parse','HEAD')==head and not git('status','--porcelain')
    (OUT/'execution.json').write_text(json.dumps(report,indent=2)+'\n')
    manifest={'schema':'pon-current-model-supplement-manifest-v1','source_commit':head,'source_tree':tree,
              'files':{str(p.relative_to(OUT)):sha(p) for p in sorted(OUT.rglob('*')) if p.is_file()}}
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ['source_commit','all_passed','model_outcome','value_claims']},indent=2))
