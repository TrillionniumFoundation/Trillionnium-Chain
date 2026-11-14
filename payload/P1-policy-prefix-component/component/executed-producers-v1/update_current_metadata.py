import pathlib,hashlib,json,subprocess,os,ast,re,traceback,sys
S=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-20261114');E=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1');O=E/'current-metadata-update-v1'
assert not O.exists();O.mkdir()
P='trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs'
H='ed0d35487f2a67239e4d646fd41c2c7acb5cc740'
OLD_SRC='1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70';NEW_SRC='0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a'
OLD_MAP='b1a3e6d9124aa3e15b3f1e46ba361cc3876514f587eeaf4ff7d4530d4b8e2c7a';OLD_SNAPSHOT='69b8f761e92ecd0d43378f44eae7458a0acced35bd9323a171fe59fd843cf5f9'
MAP='config/pon/pq128-source-correspondence-current-v2.json'
CURRENT='scripts/ci/pq_lifetime_current_v2.py';COMP='config/pon/pq128-lifetime-composition-current-v3.json';CREADER='scripts/ci/pq_lifetime_composition.py'
DOCS=['docs/security/PQ128_LIFETIME_BUDGET_V1.md','docs/security/PQ128_LIFETIME_COMPOSITION_V2.md']
env=os.environ.copy();env.update(PATH='/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_ALLOW_PROTOCOL='',PYTHONDONTWRITEBYTECODE='1',PYTHONOPTIMIZE='0')
def sha(b):return hashlib.sha256(b).hexdigest()
def oid(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def put(n,b):
 if isinstance(b,str):b=b.encode()
 (O/n).write_bytes(b);return {'path':str(O/n),'bytes':len(b),'sha256':sha(b),'git_blob':oid(b)}
def run(n,a):
 r=subprocess.run(a,cwd=S,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
 put(n+'.stdout',r.stdout);put(n+'.stderr',r.stderr);assert r.returncode==0,(n,r.returncode)
 return r.stdout
def diffs(a,b,path=()):
 assert type(a) is type(b),(path,type(a),type(b))
 if isinstance(a,dict):
  assert a.keys()==b.keys(),path
  return sum((diffs(a[k],b[k],path+(k,))for k in a),[])
 if isinstance(a,list):
  assert len(a)==len(b),path
  return sum((diffs(x,y,path+(str(i),))for i,(x,y)in enumerate(zip(a,b))),[])
 return [] if a==b else [{'path':'/'+ '/'.join(path),'old':a,'new':b}]
state={'schema':'trnm-public-policy-current-metadata-update-v1','status':'HOLD','base':H,'only_current_identities_change':True,'hosted_performance_proved':False,'changes':[],'errors':[]}
try:
 assert run('head',['git','rev-parse','HEAD']).decode().strip()==H
 assert run('status-before',['git','status','--porcelain=v1','--untracked-files=all']).decode()==' M '+P+'\n'
 assert sha((S/P).read_bytes())==NEW_SRC
 run('preflight',['bash','scripts/project-preflight.sh'])
 paths=[MAP,CURRENT,COMP,CREADER]+DOCS
 old={p:(S/p).read_bytes()for p in paths}
 for p in paths:
  assert old[p]==run('baseline-'+p.replace('/','--'),['git','show',H+':'+p])
  put(p.replace('/','--')+'.before',old[p])
 mapping=json.loads(old[MAP]);assert sha(old[MAP])==OLD_MAP
 inputs=mapping['current_source_files_sha256'];assert len(inputs)==21 and inputs[P]==OLD_SRC
 source_proof=[]
 for p,h in inputs.items():
  raw=(S/p).read_bytes();actual=sha(raw)
  assert actual==(NEW_SRC if p==P else h),p
  source_proof.append({'path':p,'old_sha256':h,'current_sha256':actual,'bytes':len(raw),'git_blob':oid(raw),'changed':p==P})
 new_inputs=dict(inputs);new_inputs[P]=NEW_SRC
 canonical=json.dumps(new_inputs,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
 NEW_SNAPSHOT=sha(canonical)
 assert old[MAP].count(OLD_SRC.encode())==1 and old[MAP].count(OLD_SNAPSHOT.encode())==1
 new_map=old[MAP].replace(OLD_SRC.encode(),NEW_SRC.encode(),1).replace(OLD_SNAPSHOT.encode(),NEW_SNAPSHOT.encode(),1)
 NEW_MAP=sha(new_map)
 changed={MAP:new_map}
 for p in [CURRENT,COMP,CREADER]+DOCS:
  raw=old[p]
  assert raw.count(OLD_MAP.encode())==1,(p,'raw map literal',raw.count(OLD_MAP.encode()))
  assert raw.count(OLD_SNAPSHOT.encode())==1,(p,'snapshot literal',raw.count(OLD_SNAPSHOT.encode()))
  changed[p]=raw.replace(OLD_MAP.encode(),NEW_MAP.encode(),1).replace(OLD_SNAPSHOT.encode(),NEW_SNAPSHOT.encode(),1)
 md=diffs(json.loads(old[MAP]),json.loads(changed[MAP]))
 assert {x['path']for x in md}=={'/current_source_files_sha256/'+P,'/current_source_snapshot_sha256'}
 cd=diffs(json.loads(old[COMP]),json.loads(changed[COMP]))
 assert {x['path']for x in cd}=={'/current_lifetime_correspondence/sha256','/current_lifetime_correspondence/source_snapshot_sha256'}
 state['typed_json_deltas']={MAP:md,COMP:cd};state['reader_ast_checks']={}
 replacements={OLD_MAP:NEW_MAP,OLD_SNAPSHOT:NEW_SNAPSHOT}
 for p in [CURRENT,CREADER]:
  a=ast.parse(old[p]);b=ast.parse(changed[p])
  class Literals(ast.NodeTransformer):
   def visit_Constant(self,node):
    if isinstance(node.value,str)and node.value in replacements:return ast.copy_location(ast.Constant(replacements[node.value]),node)
    return node
  assert ast.dump(Literals().visit(a),include_attributes=False)==ast.dump(b,include_attributes=False),p
  state['reader_ast_checks'][p]={'only_two_reviewed_current_sha256_literals_changed':True,'strict_fields_path_rosters_caps_math_and_flags_unchanged':True}
 frozen={'config/pon/pq128-lifetime-budget-v1.json':'0315e07ca2988b3b209a6fd2980ca6d9aa22a5bb3aa98b5444a041852b2f0afd','config/pon/pq128-source-lock-v1.json':'094dcae805f3872ee621d6554ab26a7a3a34c498e21be669740949ada424ccb2','config/pon/pq128-lifetime-composition-v2.json':'5b527fbd56885bf7a7cba7516a45f0f911479b0d2867d03ff5361ee3e7a8b052'}
 for p,h in frozen.items():assert sha((S/p).read_bytes())==h
 for p,b in changed.items():assert(S/p).read_bytes()==old[p]
 for p,b in changed.items():
  (S/p).write_bytes(b)
  assert(S/p).read_bytes()==b
  state['changes'].append({'path':p,'old_bytes':len(old[p]),'old_sha256':sha(old[p]),'old_blob':oid(old[p]),'new_bytes':len(b),'new_sha256':sha(b),'new_blob':oid(b),'payload':put(p.replace('/','--')+'.after',b)})
 put('current-21-inputs.json',json.dumps(source_proof,indent=2)+'\n')
 state.update(status='CURRENT_METADATA_APPLIED_PENDING_ORIGINAL_CONTROLS',new_map_sha256=NEW_MAP,new_snapshot_sha256=NEW_SNAPSHOT,current_source_count=21,changed_source_count=1,frozen_files_unchanged=frozen)
 patch=run('working-diff',['git','diff','--no-ext-diff','--no-textconv'])
 state['patch']={'bytes':len(patch),'sha256':sha(patch)}
 run('diff-check',['git','diff','--check'])
except BaseException as exc:state['errors'].append({'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()})
put('summary.json',json.dumps(state,indent=2)+'\n')
print(json.dumps({'status':state['status'],'changes':[x['path']for x in state['changes']],'map':state.get('new_map_sha256'),'snapshot':state.get('new_snapshot_sha256'),'summary':str(O/'summary.json'),'sha256':sha((O/'summary.json').read_bytes()),'errors':state['errors']},indent=2),flush=True)
sys.exit(0 if state['status']=='CURRENT_METADATA_APPLIED_PENDING_ORIGINAL_CONTROLS' else 1)
