from pathlib import Path
import json, os, subprocess, sys

ROOT=Path(__file__).resolve().parent/'chain-pq'
OUT=ROOT.parent/'repair-exact-validation'
HEAD='8079efb7bbc121688f15c4327b2bc286e26845c3'
OUT.mkdir(exist_ok=False)
commands=[
 ('ci-contract',['python3','scripts/ci/test_ci_contract.py']),
 ('lifetime-tests',['python3','scripts/ci/test_pq_lifetime_budget.py']),
 ('source-controls',['python3','scripts/ci/test_ci_source_integrity.py']),
 ('pq-source-controls',['python3','scripts/ci/test_pq_research_integration.py']),
 ('claim-controls',['python3','scripts/ci/test_pq_chain_claim_guard.py']),
 ('lifetime-inspector',['python3','scripts/ci/pq_lifetime_budget.py']),
 ('pq-corpus',['python3','scripts/ci/check_pq_research_integration.py']),
 ('claim-inspector',['python3','scripts/ci/pq_chain_claim_guard.py']),
 ('inventory',['python3','scripts/refresh_distributed_source_inventory.py','--check']),
 ('repository',['python3','scripts/ci/check_repository.py']),
]
environment=dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
records=[]
for label,command in commands:
 argv=['python3','scripts/ci/record_pq_native_command.py','--kind','head',
       '--candidate',HEAD,'--tested',HEAD,'--label',label,'--output',str(OUT),'--',*command]
 r=subprocess.run(argv,cwd=ROOT,env=environment,capture_output=True)
 (OUT/(label+'.recorder.stdout')).write_bytes(r.stdout)
 (OUT/(label+'.recorder.stderr')).write_bytes(r.stderr)
 row={'label':label,'recorder_exit':r.returncode};records.append(row)
 (OUT/'summary.json').write_text(json.dumps({'source':HEAD,'records':records,'complete':False},indent=2)+'\n')
 print(json.dumps(row),flush=True)
(OUT/'summary.json').write_text(json.dumps({'source':HEAD,'records':records,'complete':True},indent=2)+'\n')
sys.exit(any(row['recorder_exit'] for row in records))
