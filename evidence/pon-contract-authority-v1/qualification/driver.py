from pathlib import Path
import datetime,hashlib,json,os,platform,signal,subprocess,time
root=Path('/home/qian-qi/Documents/chain-pon-contract-authority-20260929')
base=Path('/tmp/pon-contract-authority-20260929')
out=base/'qualification';out.mkdir(mode=0o700,exist_ok=False);(out/'logs').mkdir();(base/'tmp').mkdir(exist_ok=True)
def git(*a):return subprocess.check_output(['git',*a],cwd=root,text=True).strip()
assert not git('status','--porcelain')
head=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}')
inputs={p:hashlib.sha256((root/p).read_bytes()).hexdigest()for p in git('ls-files').splitlines()if not p.startswith('evidence/')}
overrides={'CARGO_HOME':str(base/'cargo-home'),'CARGO_TARGET_DIR':str(base/'target'),'CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'2','RUST_TEST_THREADS':'1','TMPDIR':str(base/'tmp'),'PATH':str(base/'venv/bin')+':'+os.environ['PATH']}
env=os.environ.copy();env.update(overrides)
commands=[
 ('preflight',['bash','scripts/project-preflight.sh','--audit']),
 ('rust-baseline',['bash','scripts/ci/ci_job.sh','rust-baseline']),
 ('native-ignored-helper',['cargo','test','--offline','--locked','--manifest-path','trillionnium/Cargo.toml','-p','trnm-research-protocol','--all-targets','--all-features','--','--ignored']),
 ('repository-truth',['bash','scripts/ci/ci_job.sh','repository-truth']),
 ('protocol-contract',['bash','scripts/ci/ci_job.sh','protocol-contract']),
 ('fuzz-smoke',['bash','scripts/ci/ci_job.sh','fuzz-smoke']),
 ('external-evidence-contract',['bash','scripts/ci/ci_job.sh','external-evidence-contract']),
 ('work-cost',['python3','scripts/pon_work_cost_report.py','--run','--out',str(base/'cost')]),
 ('work-cost-verification',['python3','scripts/pon_work_cost_report.py','--verify',str(base/'cost')]),
 ('responsibility-json',['python3','scripts/ci/report_module_evidence.py']),
 ('whitespace',['git','diff','--check'])]
report={'schema':'pon-contract-authority-local-qualification-v1','source_commit':head,'source_tree':tree,'source_clean_before':True,'source_files_sha256':inputs,'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'environment':{'platform':platform.platform(),'overrides':overrides,'temporary_filesystem':subprocess.check_output(['stat','-f','-c','%T',str(base/'tmp')],text=True).strip(),'public_cargo_cache_copy':'isolated copy; reused build artifacts validated by Cargo','physical_power_loss':False},'results':[],'independent_accepted':False,'native_full_node_accepted':False,'future_window_accepted':False,'public_network_tested':False,'production_activation':False}
def save():
 (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
save()
for name,cmd in commands:
 print('START',name,flush=True);start=time.monotonic_ns();timed=False
 log=out/'logs'/f'{name}.log'
 with log.open('wb')as f:
  child=subprocess.Popen(cmd,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
  try:rc=child.wait(timeout=1200)
  except subprocess.TimeoutExpired:
   timed=True;os.killpg(child.pid,signal.SIGKILL);rc=child.wait()
 report['results'].append({'name':name,'command':cmd,'returncode':rc,'timed_out':timed,'elapsed_ns':time.monotonic_ns()-start,'log':'logs/'+log.name,'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()})
 print('END',name,rc,flush=True);save()
 if git('rev-parse','HEAD')!=head or git('status','--porcelain'):
  print('SOURCE_CHANGED_STOP',flush=True);break
report['source_clean_after']=not bool(git('status','--porcelain'))
report['source_unchanged']=head==git('rev-parse','HEAD')and all(hashlib.sha256((root/p).read_bytes()).hexdigest()==h for p,h in inputs.items())
report['all_commands_passed']=len(report['results'])==len(commands)and all(r['returncode']==0 and not r['timed_out']for r in report['results'])
report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
save();print('COMPLETE',report['all_commands_passed'],out,flush=True)
