from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os,subprocess,sys,time
ROOT=Path('/workspace/scratch/8e76272d9258/chain-joint-tail');OUT=ROOT.parent/'validation'
SOURCE=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip();TREE=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip()
ENV=os.environ.copy()
def run(label,argv,expected=0,timeout=600):
 started=datetime.now(timezone.utc).isoformat();t=time.monotonic();error=None
 out=OUT/(label+'.stdout.log');err=OUT/(label+'.stderr.log')
 with out.open('xb') as a,err.open('xb') as b:
  try:code=subprocess.run(argv,cwd=ROOT,stdout=a,stderr=b,timeout=timeout,env=ENV).returncode
  except (OSError,subprocess.TimeoutExpired) as e:code=None;error=str(e);b.write((str(e)+'\n').encode())
 row={'label':label,'argv':argv,'cwd':str(ROOT),'source_commit':SOURCE,'source_tree':TREE,'started_at_utc':started,'elapsed_seconds':time.monotonic()-t,'exit_code':code,'expected_exit_code':expected,'passed':code==expected,'error':error,'stdout':out.name,'stderr':err.name,'stdout_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256(err.read_bytes()).hexdigest(),'native_probability_qualified':False,'production_activation':False}
 (OUT/(label+'.json')).write_text(json.dumps(row,indent=2,sort_keys=True)+'\n');print(json.dumps({k:row[k] for k in ['label','exit_code','passed','elapsed_seconds']}),flush=True)
 return code==expected
mode=sys.argv[1]
if mode in ['source-before','source-final']:
 run(mode,['python3','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',SOURCE,'--output',str(OUT/(mode+'.report.json'))])
elif mode=='python':
 for label,argv,expected in [
 ('new-tail',['python3','formal/pon-nakamoto-v1/test_joint_production_tail_v1.py','-v'],0),
 ('dynamic',['python3','formal/pon-nakamoto-v1/test_dynamic_participation_v1.py','-v'],0),
 ('qualification-tests',['python3','formal/pon-nakamoto-v1/test_joint_consensus_qualification.py','-v'],0),
 ('ci-contract-tests',['python3','scripts/ci/test_ci_contract.py'],0),
 ('source-integrity-tests',['python3','scripts/ci/test_ci_source_integrity.py'],0),
 ('ci-contract',['python3','scripts/ci/check_ci_contract.py'],0),
 ('qualification-check',['python3','formal/pon-nakamoto-v1/joint_consensus_qualification.py','--check'],0),
 ('qualification-refusal',['python3','formal/pon-nakamoto-v1/joint_consensus_qualification.py','--require-qualified'],3),
 ('repository',['python3','scripts/ci/check_repository.py'],0),
 ]:run(label,argv,expected)
else:raise SystemExit('mode')
