import os,sys,json,hashlib,subprocess,time,pathlib,shutil,stat
B=pathlib.Path('/home/qian-qi/chain-final-consolidation-20261114-root')
S=B/'source'; E=B/'policy-prefix-linux-validation-v1'; W=B/'policy-prefix-linux-source-v1'
H='ed0d35487f2a67239e4d646fd41c2c7acb5cc740'; T='1aa9c21812489080980bdc3c1c2bb43611e88354'
P='trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs'
assert not E.exists() and not E.is_symlink(), 'evidence must be new'
assert not W.exists() and not W.is_symlink(), 'worktree must be new'
assert B.is_dir() and B.resolve()==B and S.is_dir() and S.resolve()==S
env=os.environ.copy()
env.update({'PATH':'/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin:/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin','GIT_NO_LAZY_FETCH':'1','GIT_NO_REPLACE_OBJECTS':'1','GIT_OPTIONAL_LOCKS':'0','GIT_TERMINAL_PROMPT':'0','PYTHONDONTWRITEBYTECODE':'1'})
steps=[]
def readcmd(a,cwd=S,timeout=60):
 r=subprocess.run(a,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
 assert r.returncode==0,(a,r.returncode,r.stderr.decode(errors='replace')[-1000:])
 return r.stdout
head=readcmd(['git','rev-parse','HEAD']).decode().strip()
tree=readcmd(['git','rev-parse','HEAD^{tree}']).decode().strip()
status=readcmd(['git','status','--porcelain=v1','--untracked-files=all'])
assert (head,tree,status)==(H,T,b''),(head,tree,status.decode())
b=(S/P).read_bytes()
assert len(b)==433736 and hashlib.sha256(b).hexdigest()=='1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70'
assert readcmd(['git','rev-parse',H+':'+P]).decode().strip()=='b9bbe75b8509eaf10a73b50aab7e7892f6796e64'
assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()=='b9bbe75b8509eaf10a73b50aab7e7892f6796e64'
space=shutil.disk_usage(B)
assert space.free>8*1024**3,space
override_names=[k for k in env if k in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC','RUSTDOC','RUSTDOCFLAGS','CARGO_BUILD_RUSTFLAGS') or (k.startswith('CARGO_TARGET_') and (k.endswith('_RUSTFLAGS') or k.endswith('_LINKER')))]
assert not [k for k in override_names if env.get(k)],{'compiler_override_names':[k for k in override_names if env.get(k)]}
E.mkdir(mode=0o700)
def put(n,data):
 if isinstance(data,str): data=data.encode()
 with (E/n).open('xb') as f:f.write(data)
 return {'path':str(E/n),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
def cap(label,a,timeout=60):
 start=time.time()
 r=subprocess.run(a,cwd=S,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
 row={'label':label,'argv':a,'cwd':str(S),'started':start,'ended':time.time(),'returncode':r.returncode,'stdout':put(label+'.stdout',r.stdout),'stderr':put(label+'.stderr',r.stderr)}
 steps.append(row);put('steps-'+str(len(steps))+'.json',json.dumps(row,indent=2)+'\n')
 assert r.returncode==0,(label,r.returncode)
 return r.stdout
rules={}
for q in [S/'AGENTS.md',S/'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md']:
 x=q.read_bytes();rules[str(q.relative_to(S))]={'bytes':len(x),'sha256':hashlib.sha256(x).hexdigest()}
 if q.name=='AGENTS.md':put('AGENTS.original.md',x)
pre=cap('root-preflight',['bash','scripts/project-preflight.sh'],120)
rv=cap('rustc-version',['rustc','--version','--verbose'])
cv=cap('cargo-version',['cargo','--version'])
assert 'rustc 1.95.0' in rv.decode(),rv.decode()
ps=cap('process-comm-snapshot',['ps','-eo','pid,ppid,comm,etime,%cpu'],30)
active=[line for line in ps.decode().splitlines()[1:] if any(z in line.split()[2:3] for z in ('cargo','rustc','clippy-driver'))]
assert not active,{'cargo_processes':active}
info={'schema':'trnm-policy-prefix-linux-preparation-v1','status':'prepared-for-official-patch-copy','base_head':head,'base_tree':tree,'root_source':str(S),'root_clean':True,'worktree':str(W),'evidence':str(E),'source_file':P,'original_bytes':len(b),'original_sha256':hashlib.sha256(b).hexdigest(),'original_blob':'b9bbe75b8509eaf10a73b50aab7e7892f6796e64','free_bytes':space.free,'rules':rules,'target':str(B/'target'),'compiler_override_names_present':override_names,'steps':steps,'proposal_uncommitted':True,'hosted_qualification':False}
put('preparation.json',json.dumps(info,indent=2)+'\n')
print(json.dumps({'status':info['status'],'evidence':str(E),'root_clean':True,'head':head,'tree':tree,'free_bytes':space.free,'preflight_exit':0,'rustc':rv.decode().splitlines()[0],'cargo':cv.decode().strip(),'cargo_active':False,'rules':rules}),flush=True)
