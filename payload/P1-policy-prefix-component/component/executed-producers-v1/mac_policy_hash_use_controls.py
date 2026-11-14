import os,sys,json,hashlib,pathlib,subprocess,time,re,ast,traceback
S=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-20261114'); E=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1');O=E/'static-and-python-validation-v1'
assert not O.exists();O.mkdir()
P='trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs';expected='0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a'
env=os.environ.copy();env.update(PATH='/Users/qianqi/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_ALLOW_PROTOCOL='',PYTHONDONTWRITEBYTECODE='1',PYTHONOPTIMIZE='0')
state={'schema':'trnm-policy-prefix-static-python-validation-v1','status':'RUNNING','steps':[],'source_sha256':expected,'hosted_campaign_run':False,'hosted_qualification':False,'errors':[]}
def put(n,b):
 if isinstance(b,str):b=b.encode()
 (O/n).write_bytes(b);return {'path':str(O/n),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def run(label,a,timeout=120):
 start=time.time();r=subprocess.run(a,cwd=S,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 row={'label':label,'argv':a,'cwd':str(S),'exit':r.returncode,'elapsed_seconds':time.time()-start,'stdout':put(label+'.stdout',r.stdout),'stderr':put(label+'.stderr',r.stderr)}
 state['steps'].append(row)
 assert r.returncode==0,(label,r.returncode,r.stderr.decode(errors='replace')[-1000:])
 return r
try:
 before=(S/P).read_bytes();assert hashlib.sha256(before).hexdigest()==expected
 run('preflight',['bash','scripts/project-preflight.sh'])
 run('workspace-format-check',['cargo','fmt','--manifest-path','trillionnium/Cargo.toml','--all','--','--check'])
 for label,path in [('original-policy-controls','scripts/ci/test_pon_public_v3_policy_read.py'),('original-hash-use-controls','scripts/ci/test_hash_use_contract.py')]:
  raw=(S/path).read_bytes();tree=ast.parse(raw)
  names=[n.name for n in ast.walk(tree)if isinstance(n,ast.FunctionDef) and n.name.startswith('test_')]
  orig=run(label+'-baseline',['git','show','HEAD:'+path]).stdout;assert orig==raw
  r=run(label,['/opt/homebrew/bin/python3','-B',path,'-v'],180)
  st=r.stderr.decode()
  match=re.search(r'Ran (\d+) tests? in ',st);assert match and int(match.group(1))==len(names),(label,len(names),st[-1000:])
  assert re.search(r'\nOK\s*$',st) and 'skipped='not in st,st[-1000:]
  state[label]={'methods':names,'passed':len(names),'failed':0,'skipped':0,'original_bytes_unchanged':True,'source_sha256':hashlib.sha256(raw).hexdigest()}
 run('actual-hash-use-inspect',['/opt/homebrew/bin/python3','-B','scripts/ci/hash_use_contract.py'])
 result=json.loads((O/'actual-hash-use-inspect.stdout').read_bytes())
 assert result['status']=='HOLD_NO_GO' and result['source_files_checked'] is True and result['declared_use_count']==19 and result['declared_source_count']==31
 assert result['complete_callgraph_coverage_proved'] is False and result['production_activation'] is False
 state['hash_use_scope']={'current_declared_use_count':19,'current_declared_source_count':31,'public_policy_source_not_selected':True,'complete_callgraph_coverage_proved':False,'new_private_helper_classification':'same existing PublicPolicy profile identity operation, established by original framing/oracle; not a new purpose or whole-callgraph coverage claim','manifest_unchanged':True}
 frozen={'config/pon/pq128-lifetime-budget-v1.json':'0315e07ca2988b3b209a6fd2980ca6d9aa22a5bb3aa98b5444a041852b2f0afd','config/pon/pq128-source-lock-v1.json':'094dcae805f3872ee621d6554ab26a7a3a34c498e21be669740949ada424ccb2','config/pon/pq128-lifetime-composition-v2.json':'5b527fbd56885bf7a7cba7516a45f0f911479b0d2867d03ff5361ee3e7a8b052'}
 state['frozen_files']={}
 for path,digest in frozen.items():
  raw=(S/path).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest
  orig=run('frozen-'+pathlib.Path(path).stem,['git','show','HEAD:'+path]).stdout;assert raw==orig
  state['frozen_files'][path]={'bytes':len(raw),'sha256':digest,'same_as_M8':True}
 assert (S/P).read_bytes()==before
 state['source_before_after_equal']=True;state['status']='PASS'
except BaseException as exc:
 state['status']='HOLD';state['errors'].append({'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()})
put('summary.json',json.dumps(state,indent=2)+'\n')
print(json.dumps({'status':state['status'],'summary':str(O/'summary.json'),'sha256':hashlib.sha256((O/'summary.json').read_bytes()).hexdigest(),'tests':{k:v for k,v in state.items() if k in ['original-policy-controls','original-hash-use-controls']},'errors':state['errors']},indent=2),flush=True)
sys.exit(0 if state['status']=='PASS' else 1)
