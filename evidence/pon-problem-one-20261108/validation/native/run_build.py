import os,sys,json,time,hashlib,subprocess,shutil,datetime,pathlib,tempfile,signal
ROOT=pathlib.Path('/workspace/scratch/6050776ac4f9'); REPO=ROOT/'chain-src'; OUT=ROOT/'evidence-validation/native'; EXPECTED='187b880048e30196407960f48b10c379859d1396'
ENV=os.environ.copy(); TARGET=pathlib.Path(tempfile.mkdtemp(prefix='trnm-native-6050776ac4f9-',dir='/tmp'))
OVERRIDES={'CARGO_HOME':str(ROOT/'toolchain/cargo'),'RUSTUP_HOME':str(ROOT/'toolchain/rustup'),'RUSTUP_AUTO_INSTALL':'0','TMPDIR':str(ROOT/'validation-tmp'),'CARGO_TARGET_DIR':str(TARGET),'CARGO_BUILD_JOBS':'1','CARGO_INCREMENTAL':'0','CARGO_PROFILE_DEV_DEBUG':'0','CARGO_PROFILE_TEST_DEBUG':'0','RUST_TEST_THREADS':'1','CARGO_TERM_COLOR':'never','PYTHONDONTWRITEBYTECODE':'1','CI':'true','PATH':str(ROOT/'toolchain/cargo/bin')+os.pathsep+ENV.get('PATH','')}
ENV.update(OVERRIDES)
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=REPO,env=ENV,text=True).strip()
def disk():return {'workspace':shutil.disk_usage(ROOT)._asdict(),'target':shutil.disk_usage(TARGET)._asdict()}
assert git('rev-parse','HEAD')==EXPECTED
assert not git('status','--porcelain')
initial=json.loads((OUT/'initial-summary.json').read_text())
assert initial['all_commands_passed'] and initial['all_requested_initial_commands_completed'] and initial['source_inputs_unchanged']
inputs=['AGENTS.md','rust-toolchain.toml','trillionnium/Cargo.toml','trillionnium/Cargo.lock','tests/fuzz/Cargo.toml','tests/fuzz/Cargo.lock','trillionnium/crates/trnm-crypto-primitives/Cargo.toml','trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs','scripts/project-preflight.sh','scripts/ci/ci_job.sh','.github/workflows/trnm-required-baseline.yml']
source={x:sha(REPO/x) for x in inputs}; toolroot=ROOT/'toolchain/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin'
start={'schema':'native-build-run-v1','started_utc':utc(),'commit':EXPECTED,'tree':git('rev-parse','HEAD^{tree}'),'source_hashes':source,'toolchain_binary_hashes':{x:sha(toolroot/x) for x in ['cargo','rustc','clippy-driver','cargo-clippy','rustfmt']},'env_overrides':OVERRIDES,'selected_inherited_env':{k:ENV.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CC','CXX','CFLAGS','CXXFLAGS','OPENSSL_DIR','OPENSSL_LIB_DIR','OPENSSL_INCLUDE_DIR','OPENSSL_NO_VENDOR','PKG_CONFIG_PATH']},'disk_start':disk(),'runner_sha256':sha(__file__),'profile_note':'Compilation target is an isolated task tmpfs directory; one compiler job limits memory. Dev/test debug info disabled; original opt-level, debug assertions and overflow checks preserved. No features or strict warnings relaxed. Offline after successful locked full metadata dependency acquisition.'}
(OUT/'build-start.json').write_text(json.dumps(start,indent=2)+'\n')
results=[]
def run(name,argv,build=False):
 before=disk(); record={'name':name,'argv':argv,'cwd':str(REPO),'started_utc':utc(),'commit_before':git('rev-parse','HEAD'),'tree':start['tree'],'env_overrides':OVERRIDES,'disk_before':before}
 if build and (before['target']['free']<536870912 or before['workspace']['free']<268435456):
  record.update({'exit_code':None,'not_run_reason':'insufficient disk reserve before build','finished_utc':utc()});results.append(record);(OUT/(name+'.json')).write_text(json.dumps(record,indent=2)+'\n');return False
 (OUT/(name+'.running.json')).write_text(json.dumps(record,indent=2)+'\n'); print(json.dumps({'event':'start','name':name,'argv':argv,'target':str(TARGET),'utc':record['started_utc']}),flush=True)
 tick=time.monotonic(); stop_reason=None
 with open(OUT/(name+'.stdout'),'wb') as out,open(OUT/(name+'.stderr'),'wb') as err,open(OUT/(name+'.resources.jsonl'),'a') as resources:
  process=subprocess.Popen(argv,cwd=REPO,env=ENV,stdout=out,stderr=err,start_new_session=True)
  (OUT/'build-active.json').write_text(json.dumps({'name':name,'pid':process.pid,'argv':argv,'target':str(TARGET),'started_utc':record['started_utc']},indent=2)+'\n')
  while process.poll() is None:
   d=disk(); resources.write(json.dumps({'utc':utc(),'disk':d})+'\n'); resources.flush()
   if d['target']['free']<268435456 or d['workspace']['free']<134217728:
    stop_reason='resource guard: disk reserve below 256 MiB target or 128 MiB evidence';os.killpg(process.pid,signal.SIGTERM)
    try:process.wait(timeout=20)
    except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
    break
   try:process.wait(timeout=10)
   except subprocess.TimeoutExpired:pass
  code=process.wait()
 record.update({'finished_utc':utc(),'duration_seconds':time.monotonic()-tick,'exit_code':code,'stop_reason':stop_reason,'disk_after':disk(),'stdout_sha256':sha(OUT/(name+'.stdout')),'stderr_sha256':sha(OUT/(name+'.stderr')),'commit_after':git('rev-parse','HEAD'),'worktree_status_after':git('status','--porcelain')})
 (OUT/(name+'.json')).write_text(json.dumps(record,indent=2)+'\n'); (OUT/(name+'.running.json')).unlink(); results.append(record)
 print(json.dumps({'event':'finish','name':name,'exit_code':code,'stop_reason':stop_reason,'duration_seconds':record['duration_seconds']}),flush=True)
 return code==0 and not record['worktree_status_after'] and record['commit_after']==EXPECTED
commands=[('preflight-build',['bash','scripts/project-preflight.sh'],False),('rust-clippy',['cargo','+1.95.0','clippy','--offline','--locked','--manifest-path','trillionnium/Cargo.toml','--workspace','--all-targets','--all-features','--','-D','warnings'],True),('pon-work-retained',['cargo','+1.95.0','test','--offline','--locked','--manifest-path','trillionnium/Cargo.toml','-p','trnm-crypto-primitives','--lib','--all-features','pon_work::tests::','--','--test-threads=1'],True)]
for name,argv,build in commands:
 if not run(name,argv,build):break
summary={'schema':'native-build-summary-v1','finished_utc':utc(),'commit':EXPECTED,'all_requested_build_commands_completed':len(results)==len(commands),'all_commands_passed':all(r.get('exit_code')==0 for r in results),'commands':results,'disk_final':disk(),'target_dir':str(TARGET),'source_hashes_after':{name:sha(REPO/name) for name in inputs},'worktree_status_after':git('status','--porcelain')}
summary['source_inputs_unchanged']=summary['source_hashes_after']==source
(OUT/'build-summary.json').write_text(json.dumps(summary,indent=2)+'\n');(OUT/'build-active.json').unlink(missing_ok=True)
print(json.dumps({'event':'build-summary','path':str(OUT/'build-summary.json'),'passed':summary['all_commands_passed'],'completed':summary['all_requested_build_commands_completed']}),flush=True)
