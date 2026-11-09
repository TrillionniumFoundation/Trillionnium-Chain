"""Record existing formal suites on one fixed committed source; keep every exit."""
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time


root = Path('/workspace/scratch/6050776ac4f9/chain-src')
out = Path(__file__).resolve().parent
expected = '187b880048e30196407960f48b10c379859d1396'
patterns = [
    'test_grouped_fresh_deployment_cost_v0.py',
    'test_grouped_fanout_reanalysis_v1.py',
    'test_service_work_settlement_v1.py',
    'test_reward_budget_oracle.py',
    'test_fixed_probability_contract.py',
    'test_credit_feasibility.py',
    'test_credit_envelope_contract.py',
    'test_normalized_search_cost.py',
    'test_amortized_cost_potential.py',
    'test_amortized_cost_potential_independent.py',
    'test_lifecycle_cost_v1.py',
]
assert json.loads((out / 'preflight.receipt.json').read_bytes())['exit_code'] == 0
assert all((root / 'formal/pon-nakamoto-v1' / p).is_file() for p in patterns)


def digest(path):
    raw = Path(path).read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def head():
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()


assert head() == expected
env = os.environ.copy()
env['PYTHONDONTWRITEBYTECODE'] = '1'
versions = {}
for package in ('numpy', 'cryptography'):
    try:
        versions[package] = importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        versions[package] = None
identity = dict(executable=sys.executable, executable_realpath=str(Path(sys.executable).resolve()),
    executable_digest=digest(Path(sys.executable).resolve()), version=sys.version,
    implementation=sys.implementation.name, platform=platform.platform(), uname=list(platform.uname()),
    uid=os.getuid(), package_versions=versions,
    effective_selected_env={name:env.get(name) for name in
        ('PYTHONDONTWRITEBYTECODE','PYTHONHASHSEED','PYTHONPATH','TRNM_PON_EVALUATION_POLICY')})
plan = dict(schema='pon-existing-formal-campaign-v1', expected_commit=expected,
    cwd=str(root), python=identity, patterns=patterns,
    test_sources={p:digest(root/'formal/pon-nakamoto-v1'/p) for p in patterns},
    runners={name:digest(out/name) for name in ('run_campaign.py','run_one_suite.py')},
    process_timeout_seconds=300, scope='existing named Python formal suites; no native campaign or dependency substitution')
with (out/'plan.json').open('x') as handle:
    json.dump(plan,handle,sort_keys=True,indent=2); handle.write('\n')
receipts=[]
for pattern in patterns:
    assert head()==expected
    name=pattern.removesuffix('.py')
    argv=[sys.executable,'-u',str(out/'run_one_suite.py'),str(root),pattern,str(out/(name+'.tests.json'))]
    receipt=dict(schema='pon-formal-command-receipt-v1',name=name,argv=argv,cwd=str(root),head=expected,
        started_utc=datetime.now(timezone.utc).isoformat(),python=identity,
        runner_digest=digest(out/'run_one_suite.py'), process_timeout_seconds=300)
    timer=time.monotonic_ns()
    with (out/(name+'.stdout')).open('xb') as stdout,(out/(name+'.stderr')).open('xb') as stderr:
        process=subprocess.Popen(argv,cwd=root,env=env,stdout=stdout,stderr=stderr)
        receipt['pid']=process.pid
        try:
            receipt['exit_code']=process.wait(timeout=300)
            receipt['timed_out']=False
        except subprocess.TimeoutExpired:
            process.kill(); receipt['exit_code']=process.wait(); receipt['timed_out']=True
    receipt.update(finished_utc=datetime.now(timezone.utc).isoformat(),duration_ns=time.monotonic_ns()-timer)
    for stream in ('stdout','stderr'):
        path=out/(name+'.'+stream)
        receipt[stream]=dict(path=path.name,**digest(path))
    observation_path=out/(name+'.tests.json')
    observation=json.loads(observation_path.read_bytes()) if observation_path.is_file() else None
    receipt['test_observation_file']=None if observation is None else dict(path=observation_path.name,**digest(observation_path))
    receipt['counts']=None if observation is None else {key:observation[key] for key in
        ('tests_run','passed','failures','errors','skipped','expected_failures','unexpected_successes')}
    receipt['module_bytes_unchanged']=None if observation is None else observation['prior_module_bytes_unchanged']
    with (out/(name+'.receipt.json')).open('x') as handle:
        json.dump(receipt,handle,sort_keys=True,indent=2); handle.write('\n')
    receipts.append(receipt)
    print(json.dumps({'suite':pattern,'exit_code':receipt['exit_code'],'timed_out':receipt['timed_out'],'counts':receipt['counts']}),flush=True)

count_keys=('tests_run','passed','failures','errors','skipped','expected_failures','unexpected_successes')
totals={key:sum(r['counts'][key] for r in receipts if r['counts'] is not None) for key in count_keys}
success=all(r['exit_code']==0 and not r['timed_out'] and r['module_bytes_unchanged'] is True and
            r['counts'] is not None and r['counts']['tests_run']>0 for r in receipts)
qualification_complete=success and all(totals[key]==0 for key in
    ('failures','errors','skipped','expected_failures','unexpected_successes'))
summary=dict(schema='pon-existing-formal-campaign-result-v1',expected_commit=expected,final_head=head(),
    scope=plan['scope'],status='PASS' if qualification_complete else 'INCOMPLETE' if success else 'FAIL',
    suite_count=len(patterns),executed_commands=len(receipts),totals=totals,
    missing_observation_suites=[r['name'] for r in receipts if r['counts'] is None],
    empty_suites=[r['name'] for r in receipts if r['counts'] is not None and r['counts']['tests_run']==0],
    suites=[dict(name=r['name'],exit_code=r['exit_code'],timed_out=r['timed_out'],counts=r['counts'],
                 module_bytes_unchanged=r['module_bytes_unchanged']) for r in receipts],
    full_repository_source_check_owned_by_root=True,production_qualification_granted=False)
assert summary['final_head']==expected
with (out/'summary.json').open('x') as handle:
    json.dump(summary,handle,sort_keys=True,indent=2); handle.write('\n')
manifest={p.name:digest(p) for p in sorted(out.iterdir()) if p.is_file() and p.name!='manifest.json'}
with (out/'manifest.json').open('x') as handle:
    json.dump(manifest,handle,sort_keys=True,indent=2); handle.write('\n')
print(json.dumps({'campaign_status':summary['status'],'totals':totals,'manifest_files':len(manifest)}),flush=True)
raise SystemExit(0 if qualification_complete else 1)
