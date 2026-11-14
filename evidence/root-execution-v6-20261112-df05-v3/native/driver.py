import os,sys,json,pathlib,subprocess,hashlib,time,shutil,traceback,re
P=pathlib.Path
RUN_KEY='root-operation-20261112-df05-native-validation-v3'
ROOT=P('/data/chain-root-operation-owned-20261112-df05-v4')
CONTROL=P('/data/chain-root-owner-source-20261112-df05-v4')
OUT=P('/data/chain-root-validation-20261112-df05-v3')
SOURCE='87943f6229d8785c3f431ede5eadba62b634ab8c'
TREE='5d2538f404e32319ea1084a6c79f37c52503546f'
PREVIOUS_SOURCE='92934b64f80ee9b20bcc070a08ca0966b7c5741d'
PREVIOUS_TREE='b1882c2e46827abfd1db5f8744be043d5776df6d'
BASE='8970e2c81abbf48e2a4d3f0802d79624ab20fadd'
BRANCH='fix/chain-root-operation-owned-20261112-df05-v4'
CANONICAL='https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
OUT.mkdir(parents=True,exist_ok=False)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for x in iter(lambda:f.read(1024*1024),b''):h.update(x)
 return h.hexdigest()
def put(path,value):
 text=value if isinstance(value,str) else json.dumps(value,indent=2,sort_keys=True)+'\n'
 q=path.with_name(path.name+'.tmp')
 with q.open('x',encoding='utf-8') as f:f.write(text);f.flush();os.fsync(f.fileno())
 os.replace(q,path)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def git(*args):
 return subprocess.check_output(['git','--no-replace-objects',*args],cwd=ROOT,text=True).strip()
def say(v):print(json.dumps(v,sort_keys=True),flush=True)
stage='await-source'
records=[]
try:
 data=json.loads(sys.stdin.read())
 driver=data['driver_source']
 driver_sha256=hashlib.sha256(driver.encode()).hexdigest()
 put(OUT/'driver.py',driver)
 put(OUT/'invocation.json',{'operation_key':RUN_KEY,'expected_source':SOURCE,'expected_tree':TREE,'source_parent':PREVIOUS_SOURCE,'previous_tested_tree':PREVIOUS_TREE,'base':BASE,'driver_sha256':driver_sha256,'scope':'original complete Root runners and exact-source gates; no external effects; no publication in this process'})
 started=time.monotonic()
 while not (CONTROL/'FROZEN.json').exists():
  if (CONTROL/'FAILED.json').exists():raise RuntimeError('source reconstruction reported failure')
  if time.monotonic()-started>900:raise RuntimeError('no frozen-source receipt within 900 seconds')
  time.sleep(2)
 ready=json.loads((CONTROL/'FROZEN.json').read_text())
 assert re.fullmatch('[0-9a-f]{40}',SOURCE) and re.fullmatch('[0-9a-f]{40}',TREE)
 assert ready['head']==SOURCE and ready['tree']==TREE and ready['same_previous_product_source'] is True
 assert ready['parent']==PREVIOUS_SOURCE and ready['previous_source']==PREVIOUS_SOURCE and ready['previous_tree']==PREVIOUS_TREE and ready['base']==BASE
 assert pathlib.Path(ready['worktree'])==ROOT and ready['branch']==BRANCH
 head=ready['head']
 assert git('rev-parse','HEAD')==head and git('rev-parse','HEAD^{tree}')==TREE
 assert git('show','-s','--format=%P',head)==PREVIOUS_SOURCE
 assert git('show','-s','--format=%P',PREVIOUS_SOURCE)==BASE
 assert git('rev-parse',PREVIOUS_SOURCE+'^{tree}')==PREVIOUS_TREE
 assert set(git('diff','--name-only',PREVIOUS_SOURCE,head).splitlines())=={'scripts/ci/run_pq_root_native_v3.py','scripts/ci/run_pq_root_continuation_v4.py','config/pon/pq-cross-branch-corpus-v1.json','docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'}
 assert git('branch','--show-current')==BRANCH and git('remote','get-url','origin')==CANONICAL
 assert not git('status','--porcelain','--untracked-files=all')
 put(OUT/'source-reconstruction.json',ready)
 stage='environment'
 toolchain=P('/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')
 prefix=P('/home/qian-qi/credit-envelope-f7e62-provider2/runner/trnm-pq-provider-3.5.9.5yXdk2mN/install')
 expected={
 'bin/openssl':'41d5b79f937beed7f94d9623be504db72c5048fcd952965fc0e13305d2802a33',
 'include/openssl/opensslv.h':'9647fc99758cf83e3bcf11ae310894fd4911ad62bff22d8213a614df89cfedda',
 'include/openssl/configuration.h':'406c26f93511299b264062f9f3faf0760e7a0506e91a61717c491f3c92e1a996',
 'lib/libcrypto.a':'005a0f7d9f6a073e6530cc556c90b3c415df7c6bc2475e333d29aa9bfa409bfb',
 'lib/libssl.a':'f355167951857505b5b0305fd2e8ea8f224fa29d780211175d32767b07234727'}
 provider=[]
 for rel,expected_sha in expected.items():
  p=prefix/rel
  assert p.is_file() and not p.is_symlink(),str(p)
  observed=sha(p);assert observed==expected_sha,(rel,observed,expected_sha)
  provider.append({'path':str(p),'bytes':p.stat().st_size,'sha256':observed})
 assert (toolchain/'cargo').is_file() and (toolchain/'rustc').is_file()
 choices=[P('/data'),P('/home/qian-qi/work')]
 available=[p for p in choices if p.is_dir() and os.access(p,os.W_OK) and shutil.disk_usage(p).free>=25*1024**3]
 if not available:raise RuntimeError('no writable isolated target parent with 25 GiB free; no profile downgrade permitted')
 target=available[0]/'chain-root-operation-v6-df05-target-v3';target.mkdir(exist_ok=False)
 tmp=OUT/'tmp';tmp.mkdir()
 cache=OUT/'pycache';cache.mkdir()
 sys.dont_write_bytecode=True;sys.pycache_prefix=str(cache)
 env=dict(os.environ)
 for key in list(env):
  if key.startswith('CARGO_PROFILE_') or key in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER') or key.startswith('GIT_TRACE') or key=='GIT_CURL_VERBOSE':env.pop(key,None)
 selected={
 'PATH':str(toolchain)+':/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin',
 'CARGO_HOME':'/home/qian-qi/.cargo','CARGO_TARGET_DIR':str(target),
 'CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0','CARGO_TERM_COLOR':'never','CARGO_NET_OFFLINE':'true',
 'RUSTUP_TOOLCHAIN':'1.95.0','RUSTC':str(toolchain/'rustc'),'RUSTDOC':str(toolchain/'rustdoc'),
 'OPENSSL_DIR':str(prefix),'OPENSSL_STATIC':'1','OPENSSL_NO_VENDOR':'1',
 'OPENSSL_LIB_DIR':str(prefix/'lib'),'OPENSSL_INCLUDE_DIR':str(prefix/'include'),
 'TRNM_PQ_OPENSSL':str(prefix/'bin/openssl'),'TRNM_PQ_OPENSSL_SHA256':expected['bin/openssl'],'TRNM_PQ_OPENSSL_VERSION':'3.5.9',
 'OPENSSL_CONF':'/dev/null','OPENSSL_MODULES':str(prefix/'lib/ossl-modules'),
 'TMPDIR':str(tmp),'PYTHONDONTWRITEBYTECODE':'1','PYTHONPYCACHEPREFIX':str(cache),'GIT_TERMINAL_PROMPT':'0'
 }
 env.update(selected);os.environ.update(selected)
 put(OUT/'environment.json',{'source':head,'tree':TREE,'host':'desktop','environment':selected,'provider':provider,'optimization_or_debug_profile_overrides':False,'isolated_new_target':True,'before_target_disk':shutil.disk_usage(target)._asdict(),'before_output_disk':shutil.disk_usage(OUT)._asdict(),'minimum_free_bytes_before_command':10*1024**3})
 sys.path.insert(0,str(ROOT/'scripts/ci'))
 from verify_ci_source import verify
 from ci_observation import run
 stage='verify-before'
 before=verify('head',head,root=ROOT);put(OUT/'source-before.json',before)
 cargo=str(toolchain/'cargo')
 metadata=[cargo,'metadata','--locked','--offline','--format-version','1']
 cmds=[
 ('preflight',['bash','scripts/project-preflight.sh'],120),
 ('rustc-version',[str(toolchain/'rustc'),'-Vv'],120),
 ('cargo-version',[cargo,'-V'],120),
 ('openssl-version',[str(prefix/'bin/openssl'),'version','-a'],120),
 ('metadata-default',metadata+['--manifest-path','trillionnium/Cargo.toml'],300),
 ('metadata-all-features',metadata+['--all-features','--manifest-path','trillionnium/Cargo.toml'],300),
 ('metadata-fuzz',metadata+['--manifest-path','tests/fuzz/Cargo.toml'],300),
 ('format',[cargo,'fmt','--manifest-path','trillionnium/Cargo.toml','--all','--','--check'],300),
 ('source-integrity-controls',['/usr/bin/python3','-B','-m','unittest','discover','-s','scripts/ci','-p','test_ci_source_integrity.py','-v'],600),
 ('root-gate-controls',['/usr/bin/python3','-B','-m','unittest','discover','-s','scripts/ci','-p','test_pq_root_dependency_register.py','-v'],600),
 ('root-runner-controls',['/usr/bin/python3','-B','-m','unittest','discover','-s','scripts/ci','-p','test_run_pq_root_witness_v5.py','-v'],600),
 ('repository-links',['/usr/bin/python3','-B','scripts/ci/check_repository.py'],600),
 ('research-corpus',['/usr/bin/python3','-B','scripts/ci/check_pq_research_integration.py'],600),
 ('root-dependency-register',['/usr/bin/python3','-B','scripts/ci/pq_root_dependency_register.py'],600),
 ('source-inventory',['/usr/bin/python3','-B','scripts/refresh_distributed_source_inventory.py','--check'],300),
 ('root-v5-v6',['/usr/bin/python3','-B','scripts/ci/run_pq_root_witness_v5.py','--out',str(OUT/'root-v5-v6')],5400),
 ('root-v4',['/usr/bin/python3','-B','scripts/ci/run_pq_root_continuation_v4.py','--out',str(OUT/'root-v4')],4200),
 ('root-v3',['/usr/bin/python3','-B','scripts/ci/run_pq_root_native_v3.py','--out',str(OUT/'root-v3')],5400),
 ('strict-workspace-clippy',[cargo,'clippy','--locked','--offline','--manifest-path','trillionnium/Cargo.toml','--workspace','--all-targets','--all-features','--','-D','warnings'],3600)
 ]
 put(OUT/'plan.json',{'source':head,'tree':TREE,'commands':[{'name':n,'argv':a,'outer_timeout_seconds':t} for n,a,t in cmds],'outer_owner':'unchanged scripts/ci/ci_observation.py::run with its process-group cleanup','original_inner_runner_limits_unchanged':True})
 for name,argv,timeout in cmds:
  stage=name
  if shutil.disk_usage(target).free<10*1024**3 or shutil.disk_usage(OUT).free<1024**3:raise RuntimeError('minimum retained disk reserve reached before '+name)
  say({'stage':name,'status':'START','source':head})
  row=run(argv,OUT/(name+'.log'),timeout=timeout,env=env,cwd=ROOT,expected_source=head)
  row.update(name=name,source=head,bytes=(OUT/(name+'.log')).stat().st_size,sha256=sha(OUT/(name+'.log')))
  records.append(row);put(OUT/(name+'.receipt.json'),row);put(OUT/'commands.json',records)
  say({'stage':name,'exit_code':row['exit_code'],'timed_out':row['timed_out'],'source_verified':row.get('source_verified')})
  if not row.get('source_verified'):raise RuntimeError('physical source integrity failed at '+name)
 stage='verify-after'
 after=verify('head',head,root=ROOT);assert before==after;put(OUT/'source-after.json',after)
 for row in provider:assert sha(P(row['path']))==row['sha256'],'provider input changed'
 suites={}
 for name in ['root-v5-v6','root-v4','root-v3']:
  p=OUT/name/'summary.json'
  suites[name]=json.loads(p.read_text()) if p.is_file() else {'source':head,'component_execution_passed':False,'summary_missing':True}
 report={'schema':'root-v6-native-validation-v2','operation_key':RUN_KEY,'source':head,'tree':TREE,'source_parent':PREVIOUS_SOURCE,'previous_tested_tree':PREVIOUS_TREE,'source_consistent':True,'provider_unchanged':True,'commands':records,'suites':suites,'all_commands_passed':all(x['exit_code']==0 for x in records),'status':'HOLD','production_activation':False,'whole_chain_pq_qualified':False,'independent_custody_verified':False,'actual_external_effects_verified':False,'native_m15_production_integration_complete':False,'publication_performed':False,'elapsed_seconds':time.monotonic()-started}
 put(OUT/'SUMMARY.json',report)
 artifacts=[]
 for p in sorted(OUT.rglob('*')):
  if p.is_file() and not any(x in ('tmp','pycache') for x in p.relative_to(OUT).parts) and p.name not in ('ARTIFACT_MANIFEST.json','VALIDATION_FINISHED.json'):
   artifacts.append({'path':str(p.relative_to(OUT)),'bytes':p.stat().st_size,'sha256':sha(p)})
 put(OUT/'ARTIFACT_MANIFEST.json',{'source':head,'tree':TREE,'artifacts':artifacts})
 # Files are re-read after the existing process owner has cleaned up each created group.
 for row in artifacts:
  p=OUT/row['path'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256']
 put(OUT/'VALIDATION_FINISHED.json',{'source':head,'tree':TREE,'manifest_sha256':sha(OUT/'ARTIFACT_MANIFEST.json'),'summary_sha256':sha(OUT/'SUMMARY.json'),'all_commands_passed':report['all_commands_passed'],'status':'HOLD','publication_performed':False})
 say({'stage':'VALIDATION_FINISHED','source':head,'all_commands_passed':report['all_commands_passed'],'out':str(OUT)})
except BaseException as e:
 try:put(OUT/'FAILED.json',{'operation_key':RUN_KEY,'stage':stage,'error_type':type(e).__name__,'error':str(e),'records_completed':len(records),'no_success_inferred':True,'traceback':traceback.format_exc()})
 except BaseException:pass
 traceback.print_exc()
 raise
