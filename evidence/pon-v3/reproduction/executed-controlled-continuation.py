from pathlib import Path
import hashlib,json,os,subprocess,sys,time
R=Path('/home/qian-qi/Documents/chain-pon-invariants-verify-242906');O=Path('/tmp/pon-bound-campaign-20260929')
old=json.loads((O/'execution.json').read_text())
assert old['source_commit']==subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()
assert not subprocess.check_output(['git','status','--porcelain'],cwd=R,text=True).strip()
assert old['results'][0]['returncode']==0 and old['results'][0]['name']=='long-history'
(O/'execution.json').rename(O/'execution-initial-invocation-failure.json')
(O/'parallel.log').rename(O/'parallel-invocation-failure.log')
env=os.environ.copy();env.update(CARGO_HOME='/home/qian-qi/.cache/pon-invariant-cargo',CARGO_TARGET_DIR='/home/qian-qi/.cache/pon-invariant-target',PYTHONDONTWRITEBYTECODE='1',RUST_TEST_THREADS='1',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1')
binary=env['CARGO_TARGET_DIR']+'/release/examples/pon_execute'
commands=[('parallel',[sys.executable,'formal/pon-nakamoto-v1/experiments/parallel_cost.py','--out',str(O/'parallel'),'--native',binary]),('learning',[sys.executable,'formal/pon-nakamoto-v1/experiments/learning_cycles.py','--source','e7b36311fe5306bf63b7f88985801307e9e47d8c','--out',str(O/'learning')])]
results=[old['results'][0]]
for name,cmd in commands:
 start=time.time_ns()
 with (O/(name+'.log')).open('w')as log:r=subprocess.run(cmd,cwd=R,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=180)
 row={'name':name,'command':cmd,'returncode':r.returncode,'started_utc_ns':start,'finished_utc_ns':time.time_ns()};results.append(row);print(json.dumps(row),flush=True)
 if r.returncode:break
old['results']=results;old['prior_failed_invocations']=[{'name':'parallel','returncode':2,'reason':'missing required --native argument in external campaign driver','log':'parallel-invocation-failure.log','preserved_report':'execution-initial-invocation-failure.json'}]
old['all_commands_passed']=len(results)==3 and all(r['returncode']==0 for r in results)
old['source_unchanged_at_end']=not subprocess.check_output(['git','status','--porcelain'],cwd=R,text=True).strip()
(O/'execution.json').write_text(json.dumps(old,indent=2)+'\n')
print('FINAL_BOUND_CAMPAIGN',old['all_commands_passed'],flush=True)
raise SystemExit(0 if old['all_commands_passed']else 2)
