"""Exact committed-source V3 validation; raw failed commands remain retained."""
import hashlib,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path('/workspace/scratch/5faaca703596/chain-root')
OUT=Path(sys.argv[1]);OUT.mkdir(parents=True,exist_ok=False)
ENV=os.environ.copy();ENV.update(RUSTUP_HOME='/workspace/scratch/5faaca703596/toolchain/rustup',CARGO_HOME='/workspace/scratch/5faaca703596/toolchain/cargo',CARGO_TARGET_DIR='/workspace/scratch/5faaca703596/cargo-target',CARGO_BUILD_JOBS='2',CARGO_TERM_COLOR='never',RUST_TEST_THREADS='1',OPENSSL_DIR='/usr',OPENSSL_LIB_DIR='/usr/lib/x86_64-linux-gnu',OPENSSL_INCLUDE_DIR='/usr/include',TRNM_PQ_OPENSSL='/usr/bin/openssl',TRNM_PQ_OPENSSL_VERSION='3.5.7')
ENV['PATH']=ENV['CARGO_HOME']+'/bin:'+ENV['PATH']
ENV['TRNM_PQ_OPENSSL_SHA256']=hashlib.sha256(Path(ENV['TRNM_PQ_OPENSSL']).read_bytes()).hexdigest()
ENV.pop('OPENSSL_STATIC',None)
HEAD=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
sys.path.insert(0,str(ROOT/'scripts/ci'))
from verify_ci_source import verify
before=verify('head',HEAD,root=ROOT)
(OUT/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
(OUT/'environment.json').write_text(json.dumps({k:ENV[k] for k in ['RUSTUP_HOME','CARGO_HOME','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','RUST_TEST_THREADS','OPENSSL_DIR','OPENSSL_LIB_DIR','OPENSSL_INCLUDE_DIR','TRNM_PQ_OPENSSL','TRNM_PQ_OPENSSL_VERSION','TRNM_PQ_OPENSSL_SHA256']},indent=2)+'\n')
commands=[('preflight',['bash','scripts/project-preflight.sh','--audit']),('versions-rust',['rustc','--version','--verbose']),('versions-openssl',['/usr/bin/openssl','version','-a'])]
for label,script in [('dependency-controls','test_pq_root_dependency_register.py'),('dependency-register','pq_root_dependency_register.py'),('native-runner-controls','test_run_pq_root_native_v3.py'),('ci-contract-controls','test_ci_contract.py'),('ci-contract','check_ci_contract.py'),('source-integrity-controls','test_ci_source_integrity.py'),('pq-source-controls','test_pq_research_integration.py'),('pq-source-corpus','check_pq_research_integration.py'),('lifetime-controls','test_pq_lifetime_budget.py'),('lifetime-register','pq_lifetime_budget.py'),('claim-controls','test_pq_chain_claim_guard.py'),('claim-guard','pq_chain_claim_guard.py'),('authority-controls','test_pq_authority_effect_register.py'),('authority-register','pq_authority_effect_register.py'),('repository-links','check_repository.py')]:
 commands.append((label,['python3','scripts/ci/'+script]))
commands += [('inventory',['python3','scripts/refresh_distributed_source_inventory.py','--check']),('implementation-summary',['python3','scripts/ci/report_current_implementation.py','--check']),('format',['cargo','fmt','--manifest-path','trillionnium/Cargo.toml','--all','--','--check'])]
for name,manifest,features in [('graph-default','trillionnium/Cargo.toml',[]),('graph-all-features','trillionnium/Cargo.toml',['--all-features']),('graph-fuzz','tests/fuzz/Cargo.toml',[])]:
 commands.append((name,['cargo','metadata','--locked','--manifest-path',manifest,'--format-version','1']+features))
commands += [('v3-native',['python3','scripts/ci/run_pq_root_native_v3.py','--out',str(OUT/'native-v3')])]
for label,filename in [('v2-policy','test_pq_root_recovery_policy_v1.py'),('v2-signature-structure','test_pq_root_recovery_signatures_v2.py'),('v2-provider-structure','test_pq_root_effect_readback_v2.py'),('v2-signature-native','test_pq_root_recovery_signatures_native_v2.py'),('v2-provider-native','test_pq_root_effect_readback_native_v2.py'),('v2-journal-native','test_pq_root_recovery_journal_native_v2.py')]:
 commands.append((label,['python3','formal/pon-nakamoto-v1/'+filename,'-v']))
commands += [('retained-crypto-default',['cargo','test','--locked','--manifest-path','trillionnium/Cargo.toml','-p','trnm-crypto-primitives','--lib','--','--test-threads=1']),('retained-release-default',['cargo','test','--locked','--manifest-path','trillionnium/Cargo.toml','-p','trnm-release-bundle','--lib','--','--test-threads=1']),('workspace-clippy',['cargo','clippy','--locked','--manifest-path','trillionnium/Cargo.toml','--workspace','--all-targets','--all-features','--','-D','warnings']),('diff-check',['git','diff','--check'])]
records=[]
for name,argv in commands:
 log=OUT/(name+'.log'); start=time.monotonic()
 try:
  with log.open('xb') as f:r=subprocess.run(argv,cwd=ROOT,env=ENV,stdout=f,stderr=subprocess.STDOUT,timeout=1800)
  code=r.returncode
 except subprocess.TimeoutExpired:code=124
 except OSError as error:
  code=127
  with log.open('ab') as f:f.write((str(error)+'\n').encode())
 raw=log.read_bytes()
 row={'name':name,'argv':argv,'source':HEAD,'exit_code':code,'elapsed_seconds':time.monotonic()-start,'log':log.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
 records.append(row);(OUT/'commands.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps(row),flush=True)
after=verify('head',HEAD,root=ROOT)
(OUT/'source-after.json').write_text(json.dumps(after,indent=2)+'\n')
result={'schema':'trnm-root-v3-local-campaign','source':HEAD,'source_unchanged':before==after,'commands_passed':sum(r['exit_code']==0 for r in records),'commands_total':len(records),'status':'HOLD','actual_lifetime_failure_bound':None,'whole_chain_pq_qualified':False,'composition_coverage_proved':False,'production_activation':False,'full_protocol_lane_executed':False,'full_workspace_tests_executed':False}
(OUT/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
raise SystemExit(0 if before==after and all(r['exit_code']==0 for r in records) else 1)
