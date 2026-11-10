import hashlib,json,os,pathlib,re,stat,subprocess,time,traceback

root=pathlib.Path('/home/qian-qi/chain-hepta-review-340e')
out=pathlib.Path('/home/qian-qi/chain-hepta-review-340e-validation-05')
out.mkdir(mode=0o700)
env=os.environ.copy();env['TMPDIR']='/home/qian-qi/chain-hepta-review-340e-tmp-05';env['PYTHONDONTWRITEBYTECODE']='1';env['GIT_TERMINAL_PROMPT']='0'
rows=[];summary={'commands':rows,'native_business_campaign_performed':False,'native_tests_performed':False,'native_compile_lint_requested':True,'qualification':'HOLD_NO_GO'}
def run(name,argv):
 start=time.monotonic();p=subprocess.run(argv,cwd=root,env=env,capture_output=True)
 for suffix,raw in [('stdout',p.stdout),('stderr',p.stderr)]: (out/(name+'.'+suffix+'.log')).write_bytes(raw)
 row={'name':name,'argv':argv,'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-start,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()}
 match=re.findall(rb'Ran (\d+) tests? in',p.stdout+p.stderr)
 if match:row['unittest_methods_reported']=[int(n) for n in match]
 rows.append(row);(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(row),flush=True)
 if p.returncode:raise RuntimeError(name+' failed')
 return p.stdout
def guard(name):
 head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
 tree=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=root,text=True).strip()
 assert not subprocess.check_output(['git','status','--porcelain'],cwd=root)
 raw=subprocess.check_output(['git','ls-files','-s','-z'],cwd=root);records=[];total=0
 for row in raw.split(b'\0'):
  if not row:continue
  info,rel=row.split(b'\t',1);mode,oid,stage=info.split();assert stage==b'0';p=root/os.fsdecode(rel);st=p.lstat()
  if mode==b'120000':data=os.fsencode(os.readlink(p))
  else:assert stat.S_ISREG(st.st_mode);data=p.read_bytes()
  assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest().encode()==oid,os.fsdecode(rel)
  total+=len(data);records.append({'path':os.fsdecode(rel),'mode':mode.decode(),'git_blob':oid.decode(),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
 body=json.dumps(records,separators=(',',':'),ensure_ascii=True).encode();import gzip
 (out/(name+'.json.gz')).write_bytes(gzip.compress(body,mtime=0))
 result={'head':head,'tree':tree,'files':len(records),'bytes':total,'source_map_sha256':hashlib.sha256(body).hexdigest()}
 (out/(name+'.summary.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({name:result}),flush=True);return result
try:
 run('preflight-before',['bash','scripts/project-preflight.sh'])
 summary['executed_source']=guard('source-before')
 suites=[('ci-contract','scripts/ci/test_ci_contract.py'),('source-integrity','scripts/ci/test_ci_source_integrity.py'),('scope','scripts/test_cell_learning_scope_join.py'),('proof-profile','scripts/ci/test_pq_proof_profile_binding.py'),('campaign-reader','scripts/ci/test_audit_native_campaign_outcomes.py'),('corpus-controls','scripts/ci/test_pq_research_integration.py'),('custody-v2','scripts/ci/test_pq_root_custody_review_v2.py')]
 for name,path in suites:run(name,['/usr/bin/python3',path,'-v'])
 run('corpus-inspector',['/usr/bin/python3','scripts/ci/check_pq_research_integration.py'])
 run('profile-inspector',['/usr/bin/python3','scripts/ci/pq_proof_profile_binding.py','--expected-profile-descriptor-sha256','5cb35b39dda38d096620e70909bea0cc380464ac2166eddfed83469537deb031'])
 run('inventory-check',['/usr/bin/python3','scripts/refresh_distributed_source_inventory.py','--check'])
 run('repository-check',['/usr/bin/python3','scripts/ci/check_repository.py'])
 run('semantics-check',['/usr/bin/python3','scripts/ci/report_current_implementation.py','--check'])
 env['CARGO_HOME']='/home/qian-qi/chain-hepta-481716-native-check/m14/quality-cargo-home'
 env['CARGO_BUILD_JOBS']='2';env['CARGO_INCREMENTAL']='0'
 target=pathlib.Path('/home/qian-qi/chain-hepta-review-340e-native-target-01');assert not target.exists();target.mkdir(mode=0o700);env['CARGO_TARGET_DIR']=str(target)
 provider=pathlib.Path('/home/qian-qi/chain-hepta-481716-native-check/m5-provider-build-01/trnm-pq-provider-3.5.9.GuZCCvnm/install')
 expected={'bin/openssl':'742a393279b769f7b2bbcaabdcdd152d5565d5108b4b920c69c55a1d42c4e6d7','include/openssl/opensslv.h':'9647fc99758cf83e3bcf11ae310894fd4911ad62bff22d8213a614df89cfedda','include/openssl/configuration.h':'406c26f93511299b264062f9f3faf0760e7a0506e91a61717c491f3c92e1a996','lib/libcrypto.a':'c82db203024d8d53f97a2f81161385f04444365232f5e2e6deaef77a2aff0468','lib/libssl.a':'d7cddef12614789118f792fb4b07748c9a413d241895c1501fe12e3998658d90'}
 def provider_guard(label):
  rows={p:hashlib.sha256((provider/p).read_bytes()).hexdigest() for p in expected};assert rows==expected;(out/(label+'.json')).write_text(json.dumps(rows,indent=2)+'\n')
 provider_guard('provider-before')
 env.update({'OPENSSL_CONF':'/dev/null','OPENSSL_DIR':str(provider),'OPENSSL_MODULES':str(provider/'lib/ossl-modules'),'OPENSSL_STATIC':'1','TRNM_PQ_OPENSSL':str(provider/'bin/openssl'),'TRNM_PQ_OPENSSL_VERSION':'3.5.9','TRNM_PQ_OPENSSL_SHA256':expected['bin/openssl'],'TRNM_EXPECTED_SOURCE_SHA':summary['executed_source']['head']})
 cargo='/home/qian-qi/.cargo/bin/cargo'
 run('cargo-graph-default',[cargo,'+1.95.0','metadata','--manifest-path','trillionnium/Cargo.toml','--locked','--offline','--format-version','1'])
 run('cargo-graph-all-features',[cargo,'+1.95.0','metadata','--manifest-path','trillionnium/Cargo.toml','--locked','--offline','--all-features','--format-version','1'])
 run('cargo-fmt',[cargo,'+1.95.0','fmt','--manifest-path','trillionnium/Cargo.toml','--all','--','--check'])
 run('cargo-clippy',[cargo,'+1.95.0','clippy','--manifest-path','trillionnium/Cargo.toml','--offline','--locked','--workspace','--all-targets','--all-features','--','-D','warnings'])
 provider_guard('provider-after')
 run('preflight-after',['bash','scripts/project-preflight.sh'])
 after=guard('source-after');assert after==summary['executed_source'];summary['source_unchanged']=True;summary['completed']=True
except BaseException as e:summary['error']=str(e);summary['traceback']=traceback.format_exc();raise
finally:(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
