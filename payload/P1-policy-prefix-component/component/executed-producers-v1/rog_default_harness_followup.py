import os,sys,pathlib,json,hashlib,subprocess,time,signal,re,traceback
B=pathlib.Path('/home/qian-qi/chain-final-consolidation-20261114-root');S=B/'source';W=B/'policy-prefix-linux-source-v1';O=B/'policy-prefix-linux-default-harness-v1'
P='trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs';H='ed0d35487f2a67239e4d646fd41c2c7acb5cc740';T='1aa9c21812489080980bdc3c1c2bb43611e88354'
OLD='1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70';NEW='0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a'
prior_path=B/'policy-prefix-linux-validation-v1/execution-v1/summary.json';prior_raw=prior_path.read_bytes()
assert hashlib.sha256(prior_raw).hexdigest()=='bf16496bd43d61e935e84748177d8add0ef5cc661be35f77ddb2ec11f94448f4'
prior=json.loads(prior_raw);assert prior['status']=='COMPONENT_VALIDATION_PASSED' and prior['environment']['RUST_TEST_THREADS']=='1'
env=os.environ.copy();removed=sorted(k for k in env if k.startswith('RUST_TEST_'))
for k in removed:del env[k]
env.update(PATH=prior['environment']['PATH'],GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',GIT_ALLOW_PROTOCOL='',PYTHONDONTWRITEBYTECODE='1',PYTHONOPTIMIZE='0',CARGO_TARGET_DIR=str(B/'target'),CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0',CARGO_NET_OFFLINE='true')
assert not any(k.startswith('RUST_TEST_') for k in env)
assert not any(env.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC','RUSTDOC','RUSTDOCFLAGS','CARGO_BUILD_RUSTFLAGS'])
assert not O.exists() and not O.is_symlink();O.mkdir(mode=0o700)
state={'schema':'trnm-policy-prefix-default-harness-followup-v1','status':'RUNNING','prior_serial_summary':{'path':str(prior_path),'bytes':len(prior_raw),'sha256':hashlib.sha256(prior_raw).hexdigest(),'actual_harness':'RUST_TEST_THREADS=1 serial'},'harness':'default; all inherited RUST_TEST_* removed; no harness thread flag','removed_inherited_environment_names':removed,'remaining_rust_test_environment_names':[],'clippy_repeated':False,'compiler_or_source_changed':False,'hosted_qualification':False,'steps':[],'errors':[]}
def put(p,b):
 with p.open('xb')as f:f.write(b)
 return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def info(p):
 b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def run(label,a,timeout=60,cwd=W):
 print(json.dumps({'stage':label,'state':'start'}),flush=True);out=O/(label+'.stdout');err=O/(label+'.stderr')
 row={'label':label,'argv':a,'cwd':str(cwd),'started_unix':time.time(),'timeout_seconds':timeout,'timed_out':False}
 with out.open('xb')as of,err.open('xb')as ef:
  q=subprocess.Popen(a,cwd=cwd,env=env,stdout=of,stderr=ef,start_new_session=True);row['pid']=q.pid
  try:row['returncode']=q.wait(timeout)
  except subprocess.TimeoutExpired:
   row['timed_out']=True;os.killpg(q.pid,signal.SIGTERM)
   try:row['returncode']=q.wait(10)
   except subprocess.TimeoutExpired:os.killpg(q.pid,signal.SIGKILL);row['returncode']=q.wait()
 row.update(ended_unix=time.time(),stdout=info(out),stderr=info(err));state['steps'].append(row)
 print(json.dumps({'stage':label,'returncode':row['returncode'],'timed_out':row['timed_out']}),flush=True)
 assert row['returncode']==0 and not row['timed_out'],label
 return out.read_bytes()
def snap(label,root,sha,dirty):
 h=run(label+'-head',['git','rev-parse','HEAD'],cwd=root).decode().strip();t=run(label+'-tree',['git','rev-parse','HEAD^{tree}'],cwd=root).decode().strip();s=run(label+'-status',['git','status','--porcelain=v1','--untracked-files=all'],cwd=root).decode()
 b=(root/P).read_bytes();assert(h,t)==(H,T) and hashlib.sha256(b).hexdigest()==sha and s==(' M '+P+'\n' if dirty else '')
 return {'head':h,'tree':t,'status':s,'source_path':P,'bytes':len(b),'sha256':sha}
rb=cb=None
try:
 rb=snap('root-before',S,OLD,False);cb=snap('proposal-before',W,NEW,True)
 state.update(root_before=rb,proposal_before=cb)
 run('preflight',['bash','scripts/project-preflight.sh'],120)
 rv=run('rustc-version',['rustc','--version','--verbose']).decode();assert rv.startswith('rustc 1.95.0 ')
 for label,count,names in [
 ('cached-policy-three-controls',3,set(prior['cached_policy_controls']['methods'])),
 ('original-profile-golden',1,{prior['original_golden']['method']})]:
  argv=next(x['argv'] for x in prior['steps'] if x['label']==label)
  assert not any('--test-threads' in a for a in argv)
  out=run(label,argv,1200).decode()
  assert set(re.findall(r'^test (.+?) \.\.\. ok$',out,re.M))==names
  assert re.search(r'test result: ok\. '+str(count)+r' passed; 0 failed; 0 ignored;',out),out[-2000:]
  state[label]={'passed':count,'failed':0,'ignored':0,'methods':sorted(names),'original_argv_unchanged':True}
 state['status']='DEFAULT_HARNESS_COMPONENT_PASSED'
except BaseException as exc:state['status']='HOLD';state['errors'].append({'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()})
finally:
 try:
  ra=snap('root-after',S,OLD,False);ca=snap('proposal-after',W,NEW,True)
  state.update(root_after=ra,proposal_after=ca,root_source_unchanged=ra==rb,proposal_source_unchanged=ca==cb)
  if ra!=rb or ca!=cb:state['status']='HOLD'
 except BaseException as exc:state['status']='HOLD';state['errors'].append({'where':'finally','type':type(exc).__name__,'message':str(exc)})
 state['completed_unix']=time.time();put(O/'summary.json',(json.dumps(state,indent=2)+'\n').encode())
 print(json.dumps({'status':state['status'],'summary':info(O/'summary.json'),'root_source_unchanged':state.get('root_source_unchanged'),'proposal_source_unchanged':state.get('proposal_source_unchanged'),'removed_names':removed,'errors':state['errors']}),flush=True)
sys.exit(0 if state['status']=='DEFAULT_HARNESS_COMPONENT_PASSED' else 1)
