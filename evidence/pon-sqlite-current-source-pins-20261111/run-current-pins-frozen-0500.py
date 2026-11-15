from pathlib import Path
import os,json,subprocess,hashlib
c=Path('/home/qq/work/chain-sqlite-advisory-20261110-checks');out=c/'current-pins-frozen-0500';out.mkdir(exist_ok=False);rows=[]
def run(name,args,expected=0,timeout=900,env=None):
 so=out/(name+'.stdout');se=out/(name+'.stderr')
 with so.open('xb') as f,se.open('xb') as e:
  try:code=subprocess.run(args,stdout=f,stderr=e,timeout=timeout,env=env).returncode
  except subprocess.TimeoutExpired:code='timeout'
 row={'name':name,'argv':args,'exit_code':code,'expected_exit_code':expected,'expected_outcome_observed':code==expected}
 for label,p in [('stdout',so),('stderr',se)]:row[label+'_bytes']=p.stat().st_size;row[label+'_sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
 rows.append(row);(out/'results.json').write_text(json.dumps(rows,indent=2)+'\n');print(name,code,'expected',expected,flush=True)
run('preflight',['bash','scripts/project-preflight.sh'])
run('ci',['python3','scripts/ci/check_ci_contract.py'])
run('repository',['python3','scripts/ci/check_repository.py'])
run('source43',['python3','scripts/ci/test_ci_source_integrity.py'])
run('corpus',['python3','scripts/ci/check_pq_research_integration.py'])
run('corpus-controls',['python3','scripts/ci/test_pq_research_integration.py'])
run('ci-controls',['python3','scripts/ci/test_ci_contract.py'])
run('inventory',['python3','scripts/refresh_distributed_source_inventory.py','--check'])
impl=out/'impl';impl.mkdir()
run('impl-named',['python3','scripts/ci/w1_qrom_current_ci.py','named','--out',str(impl)])
run('impl-drift',['python3','scripts/ci/w1_qrom_current_ci.py','drift','--out',str(impl)])
run('impl-report',['python3','scripts/w1_qrom_current_implementation_audit.py','--output',str(impl/'implementation.json')])
closure=out/'closure';closure.mkdir()
p=Path('config/pon/w1-qrom-closure-current-required-tests-v2.json');raw=p.read_bytes()
assert raw==subprocess.check_output(['git','show','faf940a53154bc6b4dcbeeb54a868e0922ce863e:'+str(p)])
digest=hashlib.sha256(raw).hexdigest()
for mode in ['run','check']:run('closure-'+mode,['python3','scripts/ci/w1_qrom_closure_current_controls.py',mode,'--roster-sha256',digest,'--output',str(closure)])
run('lifetime-current',['python3','scripts/w1_lifetime_current_observation.py','--input','evidence/pon-w1-lifetime-20261107/project-input.json'])
run('historical-refusal',['python3','scripts/w1_lifetime_ledger.py','--input','evidence/pon-w1-lifetime-20261107/project-input.json'],expected=2)
r=json.loads((out/'historical-refusal.stderr').read_text());assert r['status']=='REFUSED' and r['error']=='source identity mismatch: trillionnium/Cargo.lock'
run('workspace-graph',['cargo','metadata','--manifest-path','trillionnium/Cargo.toml','--all-features','--locked','--offline','--format-version','1'])
run('fuzz-graph',['cargo','metadata','--manifest-path','tests/fuzz/Cargo.toml','--all-features','--locked','--offline','--format-version','1'])
run('workspace-check',['cargo','check','--manifest-path','trillionnium/Cargo.toml','--workspace','--all-targets','--all-features','--locked','--offline'])
run('workspace-fmt',['cargo','fmt','--manifest-path','trillionnium/Cargo.toml','--all','--check'])
run('workspace-clippy',['cargo','clippy','--manifest-path','trillionnium/Cargo.toml','--workspace','--all-targets','--all-features','--locked','--offline','--','-D','warnings'])
pe=os.environ.copy();pe.update(CARGO_HOME=str(c/'cargo-policy-home'),TRNM_CI_TOOL_ROOT=str(c/'tools'),TRNM_CI_RECEIPT_DIR=str(out/'original-policy'))
run('original-policy',['python3','scripts/ci/run_supply_chain.py'],env=pe)
raise SystemExit(0 if all(r['expected_outcome_observed'] for r in rows) else 1)
