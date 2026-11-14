import pathlib,os,subprocess,json,hashlib,ast,sys,traceback,time
S=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-20261114');E=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1');O=E/'commit-v1';assert not O.exists();O.mkdir()
H='ed0d35487f2a67239e4d646fd41c2c7acb5cc740';BR='fix/chain-public-policy-prefix-cache-20261114'
paths=sorted(['trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs','config/pon/pq128-source-correspondence-current-v2.json','scripts/ci/pq_lifetime_current_v2.py','config/pon/pq128-lifetime-composition-current-v3.json','scripts/ci/pq_lifetime_composition.py','docs/security/PQ128_LIFETIME_BUDGET_V1.md','docs/security/PQ128_LIFETIME_COMPOSITION_V2.md','docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md','docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md','config/pon/pq-cross-branch-corpus-v1.json'])
env=os.environ.copy();env.update(PATH='/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_ALLOW_PROTOCOL='',GIT_TERMINAL_PROMPT='0',PYTHONDONTWRITEBYTECODE='1')
def sha(b):return hashlib.sha256(b).hexdigest()
def oid(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def put(n,b):
 if isinstance(b,str):b=b.encode()
 (O/n).write_bytes(b);return {'path':str(O/n),'bytes':len(b),'sha256':sha(b)}
state={'schema':'trnm-public-policy-prefix-component-commit-v1','status':'HOLD','parent':H,'expected_paths':paths,'steps':[],'errors':[],'hosted_qualification':False}
def run(n,a,timeout=120):
 r=subprocess.run(a,cwd=S,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 state['steps'].append({'label':n,'argv':a,'exit':r.returncode,'stdout':put(n+'.stdout',r.stdout),'stderr':put(n+'.stderr',r.stderr)})
 assert r.returncode==0,(n,r.returncode,r.stderr.decode(errors='replace')[-1000:]);return r.stdout
try:
 gate_raw=(E/'final-contract-validation-v1/summary.json').read_bytes();assert sha(gate_raw)=='66674134ce77d1340ea670b53cd12a93895b6e46b5acc20c997383410a6e8585';gate=json.loads(gate_raw);assert gate['status']=='PASS'
 assert run('parent',['git','rev-parse','HEAD']).decode().strip()==H
 assert run('branch',['git','symbolic-ref','--short','HEAD']).decode().strip()==BR
 assert sorted(run('changed-paths',['git','diff','--name-only']).decode().splitlines())==paths
 assert run('staged-before',['git','diff','--cached','--name-only'])==b''
 status=run('status-before',['git','status','--porcelain=v1','--untracked-files=all']).decode().splitlines();assert len(status)==10 and all(x.startswith(' M ') for x in status)
 run('preflight',['bash','scripts/project-preflight.sh'])
 source=[]
 for p in paths:
  b=(S/p).read_bytes();assert{'bytes':len(b),'sha256':sha(b)}==gate['source_after'][p]
  source.append({'path':p,'bytes':len(b),'sha256':sha(b),'git_blob':oid(b),'mode':'100644'})
 state['source_manifest']=source
 frozen={'config/pon/pq128-lifetime-budget-v1.json':'0315e07ca2988b3b209a6fd2980ca6d9aa22a5bb3aa98b5444a041852b2f0afd','config/pon/pq128-source-lock-v1.json':'094dcae805f3872ee621d6554ab26a7a3a34c498e21be669740949ada424ccb2','config/pon/pq128-lifetime-composition-v2.json':'5b527fbd56885bf7a7cba7516a45f0f911479b0d2867d03ff5361ee3e7a8b052'}
 for p,h in frozen.items():
  b=(S/p).read_bytes();assert sha(b)==h and b==run('frozen-'+pathlib.Path(p).stem,['git','show',H+':'+p])
 state['frozen_files_unchanged']=frozen
 put('source-manifest.json',json.dumps(source,indent=2)+'\n')
 run('precommit-patch',['git','diff','--no-ext-diff','--no-textconv'])
 run('stage-exact',['git','add','--']+paths)
 assert sorted(run('staged-paths',['git','diff','--cached','--name-only']).decode().splitlines())==paths
 stage=run('staged-oids',['git','ls-files','--stage','--']+paths).decode().splitlines()
 expected={r['path']:r for r in source}
 for line in stage:
  front,p=line.split('\t',1);mode,obj,index=front.split();assert mode==expected[p]['mode'] and obj==expected[p]['git_blob'] and index=='0'
 assert len(stage)==10
 run('commit',['git','commit','-m','Reuse immutable PublicPolicy ID hash prefix'])
 head=run('head-after',['git','rev-parse','HEAD']).decode().strip();tree=run('tree-after',['git','rev-parse','HEAD^{tree}']).decode().strip()
 raw=run('commit-object',['git','cat-file','commit',head]);parents=[x[7:].decode()for x in raw.split(b'\n\n',1)[0].splitlines()if x.startswith(b'parent ')]
 assert parents==[H]
 assert sorted(run('commit-paths',['git','diff-tree','--no-commit-id','--name-only','-r',H,head]).decode().splitlines())==paths
 assert run('status-after',['git','status','--porcelain=v1','--untracked-files=all'])==b''
 patch=run('final-patch',['git','diff','--no-ext-diff','--no-textconv',H,head])
 for row in source:assert oid((S/row['path']).read_bytes())==row['git_blob']
 state.update(status='COMMITTED_LOCAL_CLEAN',commit=head,tree=tree,parents=parents,branch=BR,changed_path_count=10,clean=True,final_patch={'path':str(O/'final-patch.stdout'),'bytes':len(patch),'sha256':sha(patch)})
except BaseException as exc:state['errors'].append({'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()})
put('summary.json',json.dumps(state,indent=2)+'\n')
print(json.dumps({'status':state['status'],'commit':state.get('commit'),'tree':state.get('tree'),'clean':state.get('clean'),'paths':state.get('changed_path_count'),'patch':state.get('final_patch'),'summary':str(O/'summary.json'),'summary_sha256':sha((O/'summary.json').read_bytes()),'errors':state['errors']},indent=2),flush=True)
sys.exit(0 if state['status']=='COMMITTED_LOCAL_CLEAN'else 1)
