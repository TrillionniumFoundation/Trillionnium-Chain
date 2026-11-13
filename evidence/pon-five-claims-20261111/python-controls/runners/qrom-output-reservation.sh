python3 - <<'PY'
from pathlib import Path
import subprocess,json,os,time,hashlib,re
T='297bb40798ca1b4e4a987ef00582067282cda4e9'
OUT=Path('.git/pon-five-claims-bindings-d6cb-'+T[:12])
env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',GIT_NO_LAZY_FETCH='1')
def git(*args):return subprocess.check_output(['git',*args],text=True,env=env).strip()
assert git('rev-parse','HEAD')==T and not git('status','--porcelain=v1')
assert json.loads((OUT/'results.json').read_text())['source_remained_clean']
roster='ee2b11492a362bd4be2f2df4e7ad691f4dd8a78cd9df884979cb3409e117745f'
(OUT/'qrom-closure').mkdir(exist_ok=False)
results=[]
for action in ('run','check'):
 name='qrom-closure-'+action+'-recovery'
 args=['python3','scripts/ci/w1_qrom_closure_controls.py',action,'--roster-sha256',roster,'--output',str(OUT/'qrom-closure')]
 print(json.dumps({'started':name,'command':args}),flush=True)
 start=time.time()
 with (OUT/(name+'.stdout.log')).open('wb') as stdout,(OUT/(name+'.stderr.log')).open('wb') as stderr:
  p=subprocess.run(args,env=env,stdout=stdout,stderr=stderr)
 stdout=(OUT/(name+'.stdout.log')).read_bytes();stderr=(OUT/(name+'.stderr.log')).read_bytes()
 record={'name':name,'command':args,'exit':p.returncode,'seconds':time.time()-start,'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'stderr_sha256':hashlib.sha256(stderr).hexdigest(),'stdout_bytes':len(stdout),'stderr_bytes':len(stderr),'reported_test_counts':[int(x) for x in re.findall(r'Ran ([0-9]+) tests? in ',(stdout+stderr).decode(errors='replace'))]}
 if p.returncode:record['failure_tail']=(stdout+stderr).decode(errors='replace')[-6000:]
 results.append(record);print(json.dumps(record),flush=True)
final={'source':T,'setup_correction':'Reserved the output directory as required by the existing workflow; no source, test roster, test case, input, parameter, or acceptance rule changed.','prior_failed_attempts_preserved':True,'results':results,'source_after':{'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain=v1')}}
(OUT/'qrom-output-reservation-recovery.json').write_text(json.dumps(final,indent=2,sort_keys=True)+'\n')
print(json.dumps({'result':'QROM_RECOVERY_COMPLETE',**final}),flush=True)
PY
