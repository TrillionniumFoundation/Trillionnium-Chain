from pathlib import Path
import os,json,subprocess,hashlib
c=Path('/home/qq/work/chain-sqlite-advisory-20261110-checks');out=c/'route-full-corpus-0842';out.mkdir(exist_ok=False);rows=[]
def run(name,args,timeout=900,env=None):
 so=out/(name+'.stdout');se=out/(name+'.stderr')
 with so.open('xb') as f,se.open('xb') as e:
  try:code=subprocess.run(args,stdout=f,stderr=e,timeout=timeout,env=env).returncode
  except subprocess.TimeoutExpired:code='timeout'
 row={'name':name,'argv':args,'exit_code':code,'expected_exit_code':0,'expected_outcome_observed':code==0}
 for label,p in [('stdout',so),('stderr',se)]:row[label+'_bytes']=p.stat().st_size;row[label+'_sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
 rows.append(row);(out/'results.json').write_text(json.dumps(rows,indent=2)+'\n');print(name,code,flush=True)
run('preflight',['bash','scripts/project-preflight.sh'])
run('ci',['python3','scripts/ci/check_ci_contract.py'])
run('repository',['python3','scripts/ci/check_repository.py'])
run('source43',['python3','scripts/ci/test_ci_source_integrity.py'])
run('route28',['python3','scripts/ci/test_w1_stark_route_audit.py'])
run('route-report',['python3','scripts/w1_stark_route_audit.py'])
run('corpus',['python3','scripts/ci/check_pq_research_integration.py'])
run('corpus-controls',['python3','scripts/ci/test_pq_research_integration.py'])
run('ci-controls',['python3','scripts/ci/test_ci_contract.py'])
run('inventory',['python3','scripts/refresh_distributed_source_inventory.py','--check'])
run('workspace-graph',['cargo','metadata','--manifest-path','trillionnium/Cargo.toml','--all-features','--locked','--offline','--format-version','1'])
run('fuzz-graph',['cargo','metadata','--manifest-path','tests/fuzz/Cargo.toml','--all-features','--locked','--offline','--format-version','1'])
run('workspace-check',['cargo','check','--manifest-path','trillionnium/Cargo.toml','--workspace','--all-targets','--all-features','--locked','--offline'])
run('workspace-fmt',['cargo','fmt','--manifest-path','trillionnium/Cargo.toml','--all','--check'])
run('workspace-clippy',['cargo','clippy','--manifest-path','trillionnium/Cargo.toml','--workspace','--all-targets','--all-features','--locked','--offline','--','-D','warnings'])
pe=os.environ.copy();pe.update(CARGO_HOME=str(c/'cargo-policy-home'),TRNM_CI_TOOL_ROOT=str(c/'tools'),TRNM_CI_RECEIPT_DIR=str(out/'original-policy'))
run('original-policy',['python3','scripts/ci/run_supply_chain.py'],env=pe)
raise SystemExit(0 if all(r['expected_outcome_observed'] for r in rows) else 1)
