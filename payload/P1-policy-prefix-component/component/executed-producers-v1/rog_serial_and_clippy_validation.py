import os,sys,json,hashlib,pathlib,subprocess,time,signal,re,stat,traceback
B=pathlib.Path('/home/qian-qi/chain-final-consolidation-20261114-root')
S=B/'source'; W=B/'policy-prefix-linux-source-v1'; E=B/'policy-prefix-linux-validation-v1'; O=E/'execution-v1'
H='ed0d35487f2a67239e4d646fd41c2c7acb5cc740'; T='1aa9c21812489080980bdc3c1c2bb43611e88354'
BR='fix/chain-policy-prefix-linux-20261114'
P='trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs'
OLD='1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70'; NEW='0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a'
PATCH=E/'reviewed-policy-prefix.patch'
env=os.environ.copy()
env.update(PATH='/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin:/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin',
GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',GIT_ALLOW_PROTOCOL='',PYTHONDONTWRITEBYTECODE='1',PYTHONOPTIMIZE='0',
CARGO_TARGET_DIR=str(B/'target'),CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0',CARGO_NET_OFFLINE='true',RUST_TEST_THREADS='1')
for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC','RUSTDOC','RUSTDOCFLAGS','CARGO_BUILD_RUSTFLAGS']:
 assert not env.get(k),(k,'unreviewed compiler override')
assert not O.exists() and not O.is_symlink()
assert not W.exists() and not W.is_symlink()
assert E.resolve()==E and E.is_dir()
pb=PATCH.read_bytes();assert len(pb)==16945 and hashlib.sha256(pb).hexdigest()=='519f7b6950743386f53e655edf5e31d3f198de581c7125461a08b28d81211a37'
O.mkdir(mode=0o700)
state={'schema':'trnm-public-policy-prefix-linux-validation-v1','status':'RUNNING','base_head':H,'base_tree':T,'root_source':str(S),'worktree':str(W),'branch':BR,'source_description':'M8 plus exactly one uncommitted reviewed Rust proposal','modified_path':P,'proposal_source_sha256':NEW,'reviewed_patch':{'path':str(PATCH),'bytes':len(pb),'sha256':hashlib.sha256(pb).hexdigest()},'environment':{k:env[k] for k in ['PATH','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','CARGO_INCREMENTAL','CARGO_NET_OFFLINE','RUST_TEST_THREADS']},'steps':[],'errors':[],'hosted_campaign_run':False,'hosted_performance_proved':False,'source_before_after_equal':False,'root_source_unchanged':False}
def put(path,data):
 if isinstance(data,str):data=data.encode()
 with path.open('xb')as f:f.write(data)
 return {'path':str(path),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
def meta(path):
 b=path.read_bytes();return {'path':str(path),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def persist(): 
 q=O/'steps.json'
 tmp=O/'steps.next.json'
 with tmp.open('w')as f:json.dump(state['steps'],f,indent=2);f.write('\n')
 os.replace(tmp,q)
def run(label,argv,timeout=60,cwd=W,allow=False):
 out=O/(label+'.stdout');err=O/(label+'.stderr')
 print(json.dumps({'stage':label,'state':'start','timeout_seconds':timeout}),flush=True)
 row={'label':label,'argv':argv,'cwd':str(cwd),'timeout_seconds':timeout,'started_unix':time.time(),'timed_out':False}
 with out.open('xb')as of,err.open('xb')as ef:
  proc=subprocess.Popen(argv,cwd=cwd,env=env,stdout=of,stderr=ef,start_new_session=True)
  row['pid']=proc.pid
  try:row['returncode']=proc.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   row['timed_out']=True
   os.killpg(proc.pid,signal.SIGTERM)
   try:row['returncode']=proc.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);row['returncode']=proc.wait()
 row.update(ended_unix=time.time(),stdout=meta(out),stderr=meta(err))
 state['steps'].append(row);persist()
 print(json.dumps({'stage':label,'state':'complete','returncode':row['returncode'],'timed_out':row['timed_out'],'elapsed_seconds':row['ended_unix']-row['started_unix']}),flush=True)
 if (row['timed_out'] or row['returncode']!=0)and not allow:raise RuntimeError(label+' failed; original streams retained')
 return out.read_bytes()
def source(label,cwd,expected_sha,dirty):
 hd=run(label+'-head',['git','rev-parse','HEAD'],cwd=cwd).decode().strip()
 tr=run(label+'-tree',['git','rev-parse','HEAD^{tree}'],cwd=cwd).decode().strip()
 st=run(label+'-status',['git','status','--porcelain=v1','--untracked-files=all'],cwd=cwd).decode()
 data=(cwd/P).read_bytes()
 assert (hd,tr)==(H,T),(label,hd,tr)
 assert hashlib.sha256(data).hexdigest()==expected_sha
 assert st==(' M '+P+'\n' if dirty else ''),(label,st)
 return {'head':hd,'tree':tr,'status':st,'source_path':P,'source_bytes':len(data),'source_sha256':hashlib.sha256(data).hexdigest(),'source_git_blob':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()}
root_before=None;candidate_before=None
try:
 root_before=source('root-before',S,OLD,False);state['root_before']=root_before
 run('root-preflight',['bash','scripts/project-preflight.sh'],120,cwd=S)
 refs=run('new-branch-absent',['git','for-each-ref','--format=%(refname)','refs/heads/'+BR],cwd=S)
 assert refs==b'',refs
 run('worktree-add',['git','-c','protocol.allow=never','worktree','add','-b',BR,str(W),H],240,cwd=S)
 source('worktree-original',W,OLD,False)
 run('worktree-preflight',['bash','scripts/project-preflight.sh'],120)
 run('apply-check',['git','apply','--check',str(PATCH)],60)
 run('apply-reviewed',['git','apply',str(PATCH)],60)
 actual=(W/P).read_bytes()
 assert len(actual)==438782 and hashlib.sha256(actual).hexdigest()==NEW
 assert hashlib.sha1(b'blob '+str(len(actual)).encode()+b'\0'+actual).hexdigest()=='b62de39bdba906c9d989498a6299df9a14d900e8'
 candidate_before=source('candidate-before',W,NEW,True);state['candidate_before']=candidate_before
 names=run('candidate-changed-paths',['git','diff','--name-only']).decode().splitlines();assert names==[P],names
 run('candidate-diff',['git','diff','--no-ext-diff','--no-textconv','--',P])
 run('candidate-diff-check',['git','diff','--check'])
 run('candidate-preflight',['bash','scripts/project-preflight.sh'],120)
 rv=run('rustc-version',['rustc','--version','--verbose']).decode();assert rv.startswith('rustc 1.95.0 ')
 run('cargo-version',['cargo','--version'])
 run('locked-offline-graph',['cargo','metadata','--locked','--offline','--format-version','1','--no-deps','--manifest-path','trillionnium/Cargo.toml'],120)
 base=['cargo','test','--locked','--offline','--release','--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node','--lib']
 out=run('cached-policy-three-controls',base+['ingress::public_v3::tests::cached_policy_id_'],1200).decode()
 expected={'ingress::public_v3::tests::cached_policy_id_matches_original_hash_for_public_fields','ingress::public_v3::tests::cached_policy_id_retains_all_six_framed_suffix_parts','ingress::public_v3::tests::cached_policy_id_clones_are_independent_across_callers'}
 actual_names=set(re.findall(r'^test (.+?) \.\.\. ok$',out,re.M));assert actual_names==expected,actual_names
 assert re.search(r'test result: ok\. 3 passed; 0 failed; 0 ignored;',out),out[-2000:]
 state['cached_policy_controls']={'passed':3,'failed':0,'ignored':0,'methods':sorted(expected)}
 golden='ingress::public_v3::tests::paid_envelope_resource_profile_has_fresh_exact_signed_commitment'
 out=run('original-profile-golden',base+[golden,'--','--exact'],1200).decode()
 assert set(re.findall(r'^test (.+?) \.\.\. ok$',out,re.M))=={golden}
 assert re.search(r'test result: ok\. 1 passed; 0 failed; 0 ignored;',out),out[-2000:]
 state['original_golden']={'passed':1,'failed':0,'ignored':0,'method':golden}
 run('strict-all-target-all-feature-clippy',['cargo','clippy','--locked','--offline','--release','--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node','--all-targets','--all-features','--','-D','warnings'],1200)
 state['strict_clippy_passed']=True
 state['status']='COMPONENT_VALIDATION_PASSED'
except BaseException as exc:
 state['status']='HOLD';state['errors'].append({'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()})
finally:
 try:
  ra=source('root-after',S,OLD,False);state['root_after']=ra;state['root_source_unchanged']=ra==root_before
  if candidate_before is not None:
   ca=source('candidate-after',W,NEW,True);state['candidate_after']=ca;state['source_before_after_equal']=ca==candidate_before
  if not state['root_source_unchanged'] or not state['source_before_after_equal']:state['status']='HOLD'
 except BaseException as exc:
  state['status']='HOLD';state['errors'].append({'type':type(exc).__name__,'message':str(exc),'where':'finally-source-readback'})
 state['completed_unix']=time.time();put(O/'summary.json',json.dumps(state,indent=2)+'\n')
 print(json.dumps({'status':state['status'],'summary':meta(O/'summary.json'),'root_source_unchanged':state['root_source_unchanged'],'source_before_after_equal':state['source_before_after_equal'],'errors':state['errors']}),flush=True)
sys.exit(0 if state['status']=='COMPONENT_VALIDATION_PASSED' else 1)
