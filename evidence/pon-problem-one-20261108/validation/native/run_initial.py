import os,sys,json,time,hashlib,subprocess,shutil,datetime,pathlib
ROOT=pathlib.Path('/workspace/scratch/6050776ac4f9')
REPO=ROOT/'chain-src'; OUT=ROOT/'evidence-validation/native'
EXPECTED='187b880048e30196407960f48b10c379859d1396'
ENV=os.environ.copy()
OVERRIDES={'CARGO_HOME':str(ROOT/'toolchain/cargo'),'RUSTUP_HOME':str(ROOT/'toolchain/rustup'),'RUSTUP_AUTO_INSTALL':'0','TMPDIR':str(ROOT/'validation-tmp'),'CARGO_TARGET_DIR':str(ROOT/'native-target'),'CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0','CARGO_PROFILE_DEV_DEBUG':'0','CARGO_PROFILE_TEST_DEBUG':'0','RUST_TEST_THREADS':'1','CARGO_TERM_COLOR':'never','PYTHONDONTWRITEBYTECODE':'1','CI':'true','PATH':str(ROOT/'toolchain/cargo/bin')+os.pathsep+ENV.get('PATH','')}
ENV.update(OVERRIDES)
(ROOT/'validation-tmp').mkdir(exist_ok=True)
def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
 return h.hexdigest()
def git(*args): return subprocess.check_output(['git',*args],cwd=REPO,env=ENV,text=True).strip()
head=git('rev-parse','HEAD'); tree=git('rev-parse','HEAD^{tree}')
assert head==EXPECTED,(head,EXPECTED)
assert not git('status','--porcelain'), 'source worktree not clean'
inputs=['AGENTS.md','rust-toolchain.toml','trillionnium/Cargo.toml','trillionnium/Cargo.lock','tests/fuzz/Cargo.toml','tests/fuzz/Cargo.lock','scripts/project-preflight.sh','scripts/ci/ci_job.sh','scripts/ci/run_supply_chain.py','.github/workflows/trnm-required-baseline.yml']
source={name:sha(REPO/name) for name in inputs}
start={'schema':'native-validation-run-v1','started_utc':utc(),'commit':head,'tree':tree,'source_hashes':source,'env_overrides':OVERRIDES,'disk_start':shutil.disk_usage(ROOT)._asdict(),'runner_sha256':sha(__file__),'profile_note':'Only dev/test debug info disabled; original opt-level, debug assertions and overflow checks remain. Two jobs, no incremental compilation. Metadata/fmt are graph/style gates, not full CI/supply-chain campaign.'}
(OUT/'run-start.json').write_text(json.dumps(start,indent=2)+'\n')
results=[]
def run(name,argv,minfree=0):
 before=shutil.disk_usage(ROOT)
 if before.free<minfree:
  result={'name':name,'argv':argv,'started_utc':utc(),'exit_code':None,'not_run_reason':'insufficient disk for bounded build','disk_before':before._asdict(),'minimum_free_bytes':minfree}
  (OUT/(name+'.json')).write_text(json.dumps(result,indent=2)+'\n'); results.append(result); return False
 record={'name':name,'argv':argv,'cwd':str(REPO),'started_utc':utc(),'commit_before':git('rev-parse','HEAD'),'tree':tree,'env_overrides':OVERRIDES,'disk_before':before._asdict()}
 (OUT/(name+'.running.json')).write_text(json.dumps(record,indent=2)+'\n')
 print(json.dumps({'event':'start','name':name,'argv':argv,'utc':record['started_utc']}),flush=True)
 tick=time.monotonic()
 with open(OUT/(name+'.stdout'),'wb') as out,open(OUT/(name+'.stderr'),'wb') as err:
  process=subprocess.Popen(argv,cwd=REPO,env=ENV,stdout=out,stderr=err)
  (OUT/'active.json').write_text(json.dumps({'name':name,'pid':process.pid,'argv':argv,'started_utc':record['started_utc']},indent=2)+'\n')
  code=process.wait()
 record.update({'finished_utc':utc(),'duration_seconds':time.monotonic()-tick,'exit_code':code,'disk_after':shutil.disk_usage(ROOT)._asdict(),'stdout_sha256':sha(OUT/(name+'.stdout')),'stderr_sha256':sha(OUT/(name+'.stderr')),'commit_after':git('rev-parse','HEAD'),'worktree_status_after':git('status','--porcelain')})
 (OUT/(name+'.json')).write_text(json.dumps(record,indent=2)+'\n'); (OUT/(name+'.running.json')).unlink()
 results.append(record)
 print(json.dumps({'event':'finish','name':name,'exit_code':code,'duration_seconds':record['duration_seconds'],'free_bytes':record['disk_after']['free']}),flush=True)
 return code==0 and not record['worktree_status_after'] and record['commit_after']==EXPECTED
commands=[
 ('preflight',['bash','scripts/project-preflight.sh']),
 ('rustc-version',['rustc','-Vv']),
 ('cargo-version',['cargo','-Vv']),
 ('cargo-graph',['cargo','metadata','--locked','--format-version','1','--manifest-path','trillionnium/Cargo.toml']),
 ('cargo-graph-all-features',['cargo','metadata','--locked','--format-version','1','--manifest-path','trillionnium/Cargo.toml','--all-features']),
 ('cargo-graph-fuzz',['cargo','metadata','--locked','--format-version','1','--manifest-path','tests/fuzz/Cargo.toml','--all-features']),
 ('rust-format',['cargo','fmt','--manifest-path','trillionnium/Cargo.toml','--all','--','--check']),
]
for name,argv in commands:
 if not run(name,argv): break
summary={'schema':'native-validation-summary-v1','finished_utc':utc(),'commit':EXPECTED,'all_requested_initial_commands_completed':len(results)==len(commands),'all_commands_passed':all(r.get('exit_code')==0 for r in results),'commands':results,'disk_final':shutil.disk_usage(ROOT)._asdict(),'source_hashes_after':{name:sha(REPO/name) for name in inputs},'worktree_status_after':git('status','--porcelain')}
summary['source_inputs_unchanged']=summary['source_hashes_after']==source
(OUT/'initial-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
(OUT/'active.json').unlink(missing_ok=True)
print(json.dumps({'event':'initial-summary','path':str(OUT/'initial-summary.json'),'passed':summary['all_commands_passed'],'completed':summary['all_requested_initial_commands_completed']}),flush=True)
