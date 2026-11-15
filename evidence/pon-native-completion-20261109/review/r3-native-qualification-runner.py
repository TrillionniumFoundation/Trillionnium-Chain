import pathlib,subprocess,json,os,time,hashlib,signal,shutil
base=pathlib.Path('/data/chain-abg-70ae-20261108');root=base/'source';out=base/'evidence/r3-native-and-clippy';out.mkdir(exist_ok=False)
target=base/'target-green';target.mkdir(exist_ok=True);tmp=base/'tmp';tmp.mkdir(exist_ok=True)
prefix=pathlib.Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2/build-runtime/trnm-pq-provider-3.5.9.DYf2qEaX/install')
openssl=prefix/'bin/openssl'
assert hashlib.sha256(openssl.read_bytes()).hexdigest()=='8ff7dd91270fd4a8fc377031f0fd2f2cee1cd17a32ce30e4fd773a25730a120f'
env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','PYTHONUNBUFFERED':'1','GIT_NO_REPLACE_OBJECTS':'1','GIT_NO_LAZY_FETCH':'1','CARGO_TARGET_DIR':str(target),'CARGO_BUILD_JOBS':'2','TMPDIR':str(tmp),'OPENSSL_DIR':str(prefix),'OPENSSL_STATIC':'1','OPENSSL_CONF':'/dev/null','OPENSSL_MODULES':str(prefix/'lib/ossl-modules'),'TRNM_PQ_OPENSSL':str(openssl)}
expected='ef025cbea963e3dee54ec4a17e3db7336c11409b'
def git(*args): return subprocess.check_output(['git',*args],cwd=root,env=env,text=True).strip()
assert git('rev-parse','HEAD')==expected and git('status','--porcelain')==''
rows=[]
def run(name,args,limit):
 assert shutil.disk_usage('/data').free>16*1024**3
 assert git('rev-parse','HEAD')==expected and git('status','--porcelain')==''
 print(json.dumps({'stage':name,'state':'running','argv':args}),flush=True)
 start=time.monotonic();row={'name':name,'argv':args,'cwd':str(root),'source_head':expected,'timeout_seconds':limit}
 with (out/(name+'.stdout')).open('xb') as so,(out/(name+'.stderr')).open('xb') as se:
  p=subprocess.Popen(args,cwd=root,env=env,stdout=so,stderr=se,start_new_session=True)
  try: row['exit_code']=p.wait(timeout=limit)
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=10)
   row.update(exit_code=p.returncode,timed_out=True)
 row.update(elapsed_seconds=time.monotonic()-start)
 for s in ['stdout','stderr']:
  raw=(out/(name+'.'+s)).read_bytes();row[s]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
 rows.append(row);(out/'commands.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps(row),flush=True)
 return row['exit_code']
assert run('preflight',['bash','scripts/project-preflight.sh'],30)==0
assert run('source-before',['python3','-B','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',expected,'--output',str(out/'source-before.json')],180)==0
assert run('fmt',['/home/qian-qi/.cargo/bin/cargo','+1.95.0','fmt','--manifest-path','trillionnium/Cargo.toml','--all','--','--check'],180)==0
cargo=['/home/qian-qi/.cargo/bin/cargo','+1.95.0','test','--locked','--offline','--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node','--lib']
assert run('test-roster',cargo+['--','--list'],1800)==0
roster=(out/'test-roster.stdout').read_text()
names={line[:-6] for line in roster.splitlines() if line.endswith(': test')}
assert any('native_completion_priority_prepared_held_requires_complete_output' in n for n in names)
assert len(names)==1304,len(names)
groups=[
 ('native-completion-six','ingress::public_v3::scalar_cpu::native_completion_tests::',600),
 ('scalar-budget','ingress::public_v3::scalar_cpu::tests::',600),
 ('scalar-completion','ingress::public_v3::scalar_cpu::completion_tests::',600),
 ('metered-facts','ingress::public_v3::scalar_cpu::metered_fact_tests::',600),
 ('metered-network','ingress::public_v3::scalar_cpu::metered_fact_network_tests::',600),
 ('history','ingress::history_import::tests::',900),
 ('detached','store::detached_admission::tests::',900),
 ('signed-profile','paid_envelope_resource_profile_has_fresh_exact_signed_commitment',120),
 ('old-signed-profiles','resource_revision_r18_rejects_signed_old_cookies_and_preserves_control_output_reserve',120)]
results=[]
import re
for name,selector,limit in groups:
 selected=sorted(n for n in names if selector in n);assert selected,(name,selector)
 result=run(name,cargo+[selector,'--','--nocapture','--test-threads=1'],limit)
 raw=(out/(name+'.stdout')).read_text();match=re.search(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',raw)
 counts={'passed':int(match[1]),'failed':int(match[2]),'ignored':int(match[3])} if match else None
 passed=result==0 and counts is not None and counts['failed']==0 and counts['passed']+counts['ignored']==len(selected)
 results.append({'name':name,'selector':selector,'selected_tests':selected,'counts':counts,'pass':passed})
 (out/'retained-results.json').write_text(json.dumps(results,indent=2)+'\n')
 print(json.dumps(results[-1]),flush=True)
rc=run('strict-clippy',['/home/qian-qi/.cargo/bin/cargo','+1.95.0','clippy','--locked','--offline','--manifest-path','trillionnium/Cargo.toml','--workspace','--all-targets','--all-features','--','-D','warnings'],1800)
summary={'actual_distinct_native_passes':len({n for r in results for n in r['selected_tests']})-sum(r['counts']['ignored'] if r['counts'] else 0 for r in results),'schema':'same-committed-source-native-qualification-v1','source_head':expected,'source_tree':git('rev-parse','HEAD^{tree}'),'retained_all_pass':all(r['pass'] for r in results),'strict_clippy_pass':rc==0,'selected_unique_tests':len({n for r in results for n in r['selected_tests']}),'ignored_tests':sum(r['counts']['ignored'] if r['counts'] else 0 for r in results),'fixed_host_contract':False,'production_qualification':'HOLD_NO_GO'}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary),flush=True)
rc=0 if summary['retained_all_pass'] and summary['strict_clippy_pass'] else 1
assert summary['actual_distinct_native_passes']==89 and summary['ignored_tests']==2 and summary['selected_unique_tests']==91
assert run('source-after',['python3','-B','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',expected,'--output',str(out/'source-after.json')],90)==0
(out/'environment.json').write_text(json.dumps({'source_head':expected,'target':str(target),'provider_sha256':hashlib.sha256(openssl.read_bytes()).hexdigest(),'selected_env':{k:env[k] for k in ['CARGO_TARGET_DIR','CARGO_BUILD_JOBS','TMPDIR','OPENSSL_DIR','OPENSSL_STATIC','OPENSSL_CONF','OPENSSL_MODULES','TRNM_PQ_OPENSSL']},'fixed_host_contract':False,'production_qualification':'HOLD_NO_GO'},indent=2)+'\n')
print(json.dumps({'finished':True,'native_exit':rc,'clean':git('status','--porcelain')==''}),flush=True)
print('R3_NATIVE_TERMINAL '+str(rc),flush=True)
raise SystemExit(rc)
