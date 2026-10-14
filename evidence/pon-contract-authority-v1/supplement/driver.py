from pathlib import Path
import json,os,subprocess,time,hashlib,datetime,signal
base=Path('/tmp/pon-contract-authority-20260929');root=Path('/home/qian-qi/Documents/chain-pon-contract-authority-20260929')
# Keep source and original failed receipt immutable. Run after the first matrix so
# neither qualification nor work-cost measurements contend with this repeat.
while True:
 data=json.loads((base/'qualification/report.json').read_text())
 if 'finished_utc' in data:break
 time.sleep(2)
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
assert head==data['source_commit'] and not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip()
assert (base/'tmp').stat().st_mode & 0o777 == 0o700
out=base/'supplement';out.mkdir(mode=0o700,exist_ok=False)
env=os.environ.copy();env.update(data['environment']['overrides'])
command=['bash','scripts/ci/ci_job.sh','rust-baseline'];start=time.monotonic_ns()
with (out/'rust-baseline.log').open('wb')as log:
 child=subprocess.Popen(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 try:code=child.wait(timeout=1200);timed=False
 except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);code=child.wait();timed=True
report={'schema':'pon-contract-authority-supplement-v1','source_commit':head,'source_tree':data['source_tree'],'reason':'same exact source; correct only the owned test TMPDIR permission from0775 to0700; original failure remains','command':command,'returncode':code,'timed_out':timed,'elapsed_ns':time.monotonic_ns()-start,'log':'rust-baseline.log','log_sha256':hashlib.sha256((out/'rust-baseline.log').read_bytes()).hexdigest(),'temporary_directory_mode':oct((base/'tmp').stat().st_mode&0o777),'product_source_modified':False,'product_guard_relaxed':False,'source_clean_after':not bool(subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip()),'original_report_sha256':hashlib.sha256((base/'qualification/report.json').read_bytes()).hexdigest(),'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'production_activation':False,'independent_accepted':False,'physical_power_loss':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('SUPPLEMENT',code,json.dumps(report),flush=True)
