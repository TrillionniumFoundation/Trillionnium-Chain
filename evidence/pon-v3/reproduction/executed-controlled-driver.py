from pathlib import Path
import hashlib,json,os,platform,subprocess,sys,tempfile,time
root=Path('/home/qian-qi/Documents/chain-pon-invariants-verify-242906')
out=Path('/tmp/pon-bound-campaign-20260929');out.mkdir(exist_ok=False)
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
assert head=='242906bae4f281c738c60adbd2c053d2ded1eae5'
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip()
env=os.environ.copy();env.update(CARGO_HOME='/home/qian-qi/.cache/pon-invariant-cargo',CARGO_TARGET_DIR='/home/qian-qi/.cache/pon-invariant-target',CARGO_BUILD_JOBS='2',TRNM_NATIVE_MODE='release',PYTHONDONTWRITEBYTECODE='1',RUST_TEST_THREADS='1',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1',CARGO_NET_OFFLINE='true')
env.update(TRNM_NATIVE_EXECUTOR=env['CARGO_TARGET_DIR']+'/release/examples/pon_execute',TRNM_NATIVE_WORK=env['CARGO_TARGET_DIR']+'/release/examples/pon_work_io',TRNM_EXECUTION_WORKERS='8')
paths=subprocess.check_output(['git','ls-files','formal/pon-nakamoto-v1','config/pon','trillionnium'],cwd=root,text=True).splitlines()
source={p:hashlib.sha256((root/p).read_bytes()).hexdigest()for p in paths}
fixture=tempfile.TemporaryDirectory(prefix='pon-proof-history-',dir='/dev/shm')
commands=[('long-history',[sys.executable,'formal/pon-nakamoto-v1/experiments/long_history.py','--out',fixture.name+'/history','--height','4106']),('parallel',[sys.executable,'formal/pon-nakamoto-v1/experiments/parallel_cost.py','--out',str(out/'parallel')]),('learning',[sys.executable,'formal/pon-nakamoto-v1/experiments/learning_cycles.py','--source','e7b36311fe5306bf63b7f88985801307e9e47d8c','--out',str(out/'learning')])]
results=[]
try:
 for name,command in commands:
  began=time.time_ns()
  with (out/(name+'.log')).open('w')as log:run=subprocess.run(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=1500)
  row={'name':name,'command':command,'returncode':run.returncode,'started_utc_ns':began,'finished_utc_ns':time.time_ns()};results.append(row);print(json.dumps(row),flush=True)
  if run.returncode:break
  if name=='long-history':
   (out/'long-history').mkdir();(out/'long-history/report.json').write_bytes(Path(fixture.name+'/history/report.json').read_bytes())
   row['database_sha256']=hashlib.sha256(Path(fixture.name+'/history/chain/ledger.sqlite').read_bytes()).hexdigest()
  assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip()
finally:
 report={'schema':'pon-bound-campaign-invocation-v3','source_commit':head,'source_files_sha256':source,'results':results,'long_history_filesystem':'tmpfs /dev/shm','python':sys.version,'platform':platform.platform(),'native_binaries_sha256':{key:hashlib.sha256(Path(env[key]).read_bytes()).hexdigest()for key in ['TRNM_NATIVE_EXECUTOR','TRNM_NATIVE_WORK']},'physical_power_loss':False,'independent_accepted':False,'all_commands_passed':len(results)==len(commands)and all(r['returncode']==0 for r in results),'production_activation':False}
 (out/'execution.json').write_text(json.dumps(report,indent=2)+'\n');fixture.cleanup()
print('BOUND_CAMPAIGN',out,report['all_commands_passed'],flush=True)
sys.exit(0 if report['all_commands_passed']else 2)
