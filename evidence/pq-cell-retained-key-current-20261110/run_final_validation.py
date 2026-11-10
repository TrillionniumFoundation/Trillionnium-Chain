from pathlib import Path
import json, os, subprocess, sys

ROOT=Path(__file__).resolve().parent/'chain-pq'
OUT=ROOT.parent/'final-exact-validation'
HEAD='a4c594fc9d5f43d0d2b7ae7e0835d0e1514dc667'
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
 ('phase-reader',['python3','scripts/ci/test_pon_public_v3_phase_read.py']),
 ('custody-v2',['python3','scripts/ci/test_pq_root_custody_review_v2.py']),
 ('custody-v2-inspector',['python3','scripts/ci/pq_root_custody_review_v2.py']),
 ('ci-execution',['python3','scripts/ci/test_ci_execution.py']),
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
