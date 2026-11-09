import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path('/workspace/scratch/6050776ac4f9/chain-src')
OUT=Path('/workspace/scratch/6050776ac4f9/evidence-validation/source-ci')
HEAD='187b880048e30196407960f48b10c379859d1396'
ENV=os.environ.copy()
ENV.update(PYTHONDONTWRITEBYTECODE='1', TMPDIR='/workspace/scratch/6050776ac4f9/validation-tmp')

def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def git(*args):
    return subprocess.check_output(['git',*args],cwd=ROOT,text=True).strip()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

sources=sorted([p for p in (ROOT/'scripts/ci').rglob('*.py') if p.is_file()] + [ROOT/'scripts/project-preflight.sh',ROOT/'scripts/refresh_distributed_source_inventory.py',ROOT/'PROJECT_BOUNDARY.json',ROOT/'PROJECT_ID',ROOT/'config/portability-inventory-v1.json'])
before={str(p.relative_to(ROOT)):sha(p) for p in sources}
assert git('rev-parse','HEAD')==HEAD
assert git('status','--porcelain')==''
manifest=dict(schema='pon-exact-source-ci-validation-v1',head=HEAD,tree=git('rev-parse','HEAD^{tree}'),started_at=stamp(),python=sys.version,max_parallel_gate_processes=2,environment_overrides={k:ENV[k] for k in ['PYTHONDONTWRITEBYTECODE','TMPDIR']},source_sha256=before,scope='Original source/CI component gates; no native consensus or production acceptance')
(OUT/'run-start.json').write_text(json.dumps(manifest,indent=2)+'\n')

commands=[
 ('project-boundary-tests',[sys.executable,'scripts/ci/test_project_boundary.py','-v']),
 ('source-integrity-tests',[sys.executable,'scripts/ci/test_ci_source_integrity.py','-v']),
 ('ci-execution-tests',[sys.executable,'scripts/ci/test_ci_execution.py','-v']),
 ('ci-contract-tests',[sys.executable,'scripts/ci/test_ci_contract.py','-v']),
 ('pq-integration-tests',[sys.executable,'scripts/ci/test_pq_research_integration.py','-v']),
 ('repository-check',[sys.executable,'scripts/ci/check_repository.py']),
 ('ci-contract-check',[sys.executable,'scripts/ci/check_ci_contract.py']),
 ('pq-integration-check',[sys.executable,'scripts/ci/check_pq_research_integration.py']),
 ('distributed-inventory-check',[sys.executable,'scripts/refresh_distributed_source_inventory.py','--check']),
]

def run(item):
    name,argv=item
    record=dict(name=name,argv=argv,cwd=str(ROOT),head_before=git('rev-parse','HEAD'),started_at=stamp(),source_sha256={a:sha(ROOT/a) for a in argv[1:] if a.endswith('.py') or a.endswith('.sh')})
    assert record['head_before']==HEAD
    started=time.monotonic()
    with (OUT/(name+'.stdout')).open('xb') as stdout, (OUT/(name+'.stderr')).open('xb') as stderr:
        p=subprocess.Popen(argv,cwd=ROOT,env=ENV,stdout=stdout,stderr=stderr)
        record['pid']=p.pid
        (OUT/(name+'.running.json')).write_text(json.dumps(record,indent=2)+'\n')
        record['exit_code']=p.wait()
    record.update(finished_at=stamp(),wall_seconds=time.monotonic()-started,head_after=git('rev-parse','HEAD'))
    record['source_after_sha256']={a:sha(ROOT/a) for a in record['source_sha256']}
    for stream in ['stdout','stderr']:
        path=OUT/(name+'.'+stream)
        record[stream]=dict(path=path.name,bytes=path.stat().st_size,sha256=sha(path))
    text=(OUT/(name+'.stderr')).read_text(errors='replace')
    counts=re.findall(r'^Ran (\d+) tests? in ',text,re.MULTILINE)
    record['reported_test_count']=int(counts[-1]) if counts else None
    record['source_unchanged']=record['source_after_sha256']==record['source_sha256'] and record['head_after']==HEAD
    record['passed']=record['exit_code']==0 and record['source_unchanged']
    (OUT/(name+'.json')).write_text(json.dumps(record,indent=2)+'\n')
    (OUT/(name+'.running.json')).unlink()
    print(json.dumps({k:record[k] for k in ['name','exit_code','wall_seconds','reported_test_count','passed']}),flush=True)
    if not record['passed']:
        print((OUT/(name+'.stderr')).read_text(errors='replace')[-6000:],flush=True)
    return record

preflight=run(('preflight',['bash','scripts/project-preflight.sh']))
if not preflight['passed']:
    raise SystemExit(2)
results=[preflight]
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    futures=[executor.submit(run,item) for item in commands]
    for f in concurrent.futures.as_completed(futures):
        results.append(f.result())
after={str(p.relative_to(ROOT)):sha(p) for p in sources}
summary=dict(schema='pon-exact-source-ci-validation-summary-v1',head=HEAD,finished_at=stamp(),commands=results,checked_source_roster_unchanged=before==after,head_after=git('rev-parse','HEAD'),worktree_status=git('status','--porcelain'),all_passed=all(r['passed'] for r in results) and before==after and git('rev-parse','HEAD')==HEAD and git('status','--porcelain')=='',scope=manifest['scope'],test_counts_are_per_suite_and_overlap=True)
(OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({k:summary[k] for k in ['head','finished_at','checked_source_roster_unchanged','head_after','worktree_status','all_passed']}),flush=True)
raise SystemExit(0 if summary['all_passed'] else 1)
