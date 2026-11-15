import datetime, hashlib, json, os, pathlib, re, subprocess, sys, time
ROOT=pathlib.Path('/workspace/scratch/5faaca703596/chain-root')
SHA='aa7ba29a5485a6b04ccb909e34bb3d8ae2528669'
OUT=pathlib.Path('/workspace/scratch/5faaca703596/validation/aa7ba29')
GROUP=sys.argv[1]
OUT.mkdir(parents=True,exist_ok=True)
env=dict(os.environ)
env.update(TRNM_PQ_OPENSSL='/usr/bin/openssl',TRNM_PQ_OPENSSL_SHA256=hashlib.sha256(pathlib.Path('/usr/bin/openssl').read_bytes()).hexdigest(),TRNM_PQ_OPENSSL_VERSION='3.5.7',OPENSSL_DIR='/usr',RUSTUP_HOME='/workspace/scratch/5faaca703596/toolchain/rustup',CARGO_HOME='/workspace/scratch/5faaca703596/toolchain/cargo',CARGO_TARGET_DIR='/workspace/scratch/5faaca703596/cargo-target',CARGO_BUILD_JOBS='2',RUST_TEST_THREADS='1',CARGO_TERM_COLOR='never',PYTHONDONTWRITEBYTECODE='1')
env['PATH']=env['CARGO_HOME']+'/bin:'+env['PATH']
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==SHA
assert not subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)
formal='formal/pon-nakamoto-v1/'
commands={
'native': [
 ['python3',formal+'test_pq_root_recovery_signatures_native_v2.py','-v'],
 ['python3',formal+'test_pq_root_effect_readback_native_v2.py','-v'],
 ['python3',formal+'test_pq_root_recovery_journal_native_v2.py','-v']],
'static': [
 ['bash','scripts/project-preflight.sh','--dev'],
 ['python3','scripts/ci/test_pq_lifetime_budget.py'],
 ['python3','scripts/ci/pq_lifetime_budget.py'],
 ['python3','scripts/ci/test_pq_chain_claim_guard.py'],
 ['python3',formal+'test_pq_root_recovery_policy_v1.py','-v'],
 ['python3',formal+'test_pq_root_recovery_signatures_v2.py','-v'],
 ['python3',formal+'test_pq_root_effect_readback_v2.py','-v'],
 ['python3','scripts/ci/test_pq_authority_effect_register.py'],
 ['python3','scripts/ci/test_pq_authority_surface_scan.py'],
 ['python3','scripts/ci/test_pq_research_integration.py'],
 ['python3','scripts/ci/test_ci_contract.py'],
 ['python3','scripts/ci/test_pq_provider_ci.py'],
 ['python3','scripts/ci/test_ci_source_integrity.py'],
 ['python3','scripts/ci/test_repository.py'],
 ['python3','scripts/ci/check_ci_contract.py'],
 ['python3','scripts/refresh_distributed_source_inventory.py','--check'],
 ['python3','scripts/ci/check_pq_research_integration.py'],
 ['python3','scripts/ci/pq_chain_claim_guard.py'],
 ['python3','scripts/ci/check_repository.py'],
 ['git','diff','--check']],
'rust': [
 ['cargo','metadata','--offline','--locked','--manifest-path','trillionnium/Cargo.toml','--format-version','1'],
 ['cargo','metadata','--offline','--locked','--all-features','--manifest-path','trillionnium/Cargo.toml','--format-version','1'],
 ['cargo','fetch','--locked','--manifest-path','tests/fuzz/Cargo.toml'],
 ['cargo','metadata','--offline','--locked','--manifest-path','tests/fuzz/Cargo.toml','--format-version','1'],
 ['cargo','fmt','--manifest-path','trillionnium/Cargo.toml','--all','--','--check'],
 ['cargo','clippy','--locked','--offline','--workspace','--all-targets','--all-features','--manifest-path','trillionnium/Cargo.toml','--','-D','warnings'],
 ['cargo','test','--locked','--offline','--manifest-path','trillionnium/Cargo.toml','-p','trnm-crypto-primitives','--lib'],
 ['cargo','test','--locked','--offline','--manifest-path','trillionnium/Cargo.toml','-p','trnm-release-bundle','--lib']]
}[GROUP]
rows=[]
for index,argv in enumerate(commands):
 name=f'{GROUP}-{index:02d}.log'; dest=OUT/name
 start=datetime.datetime.now(datetime.timezone.utc).isoformat(); t=time.monotonic()
 try:
  with dest.open('wb') as output:
   completed=subprocess.run(argv,cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT,timeout=1200)
  rc=completed.returncode
 except subprocess.TimeoutExpired:
  rc=124
 raw=dest.read_bytes(); text=raw.decode(errors='replace')
 row={'argv':argv,'cwd':str(ROOT),'source_sha':SHA,'started_utc':start,'elapsed_seconds':time.monotonic()-t,'exit_code':rc,'log':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'python_test_counts':re.findall(r'Ran (\d+) tests?',text),'rust_test_results':re.findall(r'test result: [^\n]+',text)}
 rows.append(row)
 (OUT/(GROUP+'-commands.json')).write_text(json.dumps(rows,indent=2)+'\n')
 print(json.dumps({'group':GROUP,'index':index,'exit_code':rc,'elapsed_seconds':round(row['elapsed_seconds'],3),'test_counts':row['python_test_counts'],'log':name}),flush=True)
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==SHA
assert not subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)
sys.exit(1 if any(row['exit_code'] for row in rows) else 0)
