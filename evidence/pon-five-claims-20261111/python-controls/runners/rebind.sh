python3 - <<'PY'
from pathlib import Path
from copy import deepcopy
import subprocess,json,ast,hashlib,os,re
S='f2375a08f4458f842b96d30215adcd5380270f1d'
BASE='11e242dbaaae14a9d16282fe8deaf36827e98395'
NEW='evidence/pon-w1-lifetime-five-claims-20261111'
ROOT=Path.cwd()
env=dict(os.environ,GIT_NO_LAZY_FETCH='1',PYTHONDONTWRITEBYTECODE='1')
def run(*args):
 p=subprocess.run(args,text=True,capture_output=True,env=env)
 print(json.dumps({'command':list(args),'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}),flush=True)
 if p.returncode:raise SystemExit(p.returncode)
 return p.stdout
def g(*args):return subprocess.check_output(['git','--no-replace-objects',*args],env=env)
assert g('rev-parse','HEAD').decode().strip()==S
assert g('status','--porcelain=v1')==b''
run('bash','scripts/project-preflight.sh')
cache={}
def source(path):
 if path not in cache:cache[path]=g('show',S+':'+path)
 return cache[path]
def sha(data):return hashlib.sha256(data).hexdigest()
def blob_id(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def canonical(data):return (json.dumps(data,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
def value_assignment(text,name):
 tree=ast.parse(text)
 return next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
changed=[]
def write(path,data):
 p=Path(path)
 if isinstance(data,str):data=data.encode()
 if p.exists() and p.read_bytes()==data:return
 p.parent.mkdir(parents=True,exist_ok=True)
 p.write_bytes(data);changed.append(path)
def replace_once(text,old,new):
 assert text.count(old)==1,(old[:150],text.count(old))
 return text.replace(old,new,1)
historical={
 'evidence/pon-w1-lifetime-current-20261109/project-report.json':'8ee20462d669a0e21b0fe964585f85fa2a49e7e58273459ab2501b4a2e39dfc0',
 'evidence/pon-w1-lifetime-account-boundary-20261110/project-report.json':'b050b861ec172305d708ba7c01ca47d547b1646cc3daee1d6aec9877d2cf3390',
 'evidence/pon-w1-lifetime-account-boundary-20261110/project-input.json':'a6e43a5c55e71154592a3489f566995e7961b91611e15d40a18a948a495f9f89'}
for path,digest in historical.items():assert sha(source(path))==digest and Path(path).read_bytes()==source(path)
corpus_path='config/pon/pq-cross-branch-corpus-v1.json'
corpus=json.loads(source(corpus_path))
source_changes=set(g('diff','--name-only',BASE,S).decode().splitlines())
initial_pin_changes={}
for path,pin in corpus['pinned_blobs'].items():
 actual=g('rev-parse',S+':'+path).decode().strip()
 if actual!=pin:initial_pin_changes[path]={'old':pin,'source_S':actual}
assert set(initial_pin_changes)<=source_changes,{'unreviewed_prior_pin_drift':sorted(set(initial_pin_changes)-source_changes)}
print(json.dumps({'source_S':S,'reviewed_composition_pin_drift':initial_pin_changes}),flush=True)
auth_path='config/pon/pq-authority-effects-v1.json'
auth=json.loads(source(auth_path));assert len(auth['routes'])==7 and len(auth['source_files_sha256'])==44
auth_files={path:sha(source(path)) for path in auth['source_files_sha256']}
auth_delta={p for p,v in auth_files.items() if auth['source_files_sha256'][p]!=v}
assert auth_delta=={'trillionnium/crates/trnm-pon-node/src/ingress.rs','trillionnium/crates/trnm-pon-node/src/store.rs'},auth_delta
old_auth_revision=auth['source_revision'];auth['source_revision']=S;auth['source_files_sha256']=auth_files
auth_digest=sha(json.dumps({'source_revision':S,'files':auth_files},sort_keys=True,separators=(',',':')).encode())
write(auth_path,json.dumps(auth,indent=2)+'\n')
path='scripts/ci/pq_authority_effect_register.py';text=source(path).decode()
text,n=re.subn(r"^SOURCE_REVISION = '[0-9a-f]{40}'$", "SOURCE_REVISION = '"+S+"'",text,flags=re.M);assert n==1
text,n=re.subn(r"^REVIEWED_SOURCE_LOCK_SHA256 = '[0-9a-f]{64}'$", "REVIEWED_SOURCE_LOCK_SHA256 = '"+auth_digest+"'",text,flags=re.M);assert n==1
write(path,text)
path='scripts/ci/test_pq_authority_effect_register.py';text=source(path).decode()
assert text.count("'"+old_auth_revision+"'")==1
write(path,text.replace("'"+old_auth_revision+"'","'"+S+"'",1))
path='config/pon/pq128-source-lock-v1.json';pq=json.loads(source(path));assert len(pq['files'])==15
pq_files={p:sha(source(p)) for p in pq['files']}
assert {p for p,v in pq_files.items() if pq['files'][p]!=v}=={'trillionnium/crates/trnm-pon-node/src/store.rs'}
pq['source_revision']=S;pq['files']=pq_files;write(path,canonical(pq))
path='config/pon/pq128-lifetime-budget-v1.json';budget=json.loads(source(path));budget['experiment']['source_revision']=S
write(path,json.dumps(budget,indent=2)+'\n')
path='scripts/w1_lifetime_ledger.py';ledger_text=source(path).decode()
pins=value_assignment(ledger_text,'SOURCE_PINS');assert len(pins)==20
new_pins={p:sha(source(p)) for p in pins}
assert {p for p,v in new_pins.items() if pins[p]!=v}=={'trillionnium/crates/trnm-pon-node/src/store.rs','trillionnium/crates/trnm-pon-node/src/consensus.rs'}
ledger_text,n=re.subn(r'^SOURCE_BASE = "[0-9a-f]{40}"$', 'SOURCE_BASE = "'+S+'"',ledger_text,flags=re.M);assert n==1
for p,v in new_pins.items():
 ledger_text=replace_once(ledger_text,json.dumps(p)+': '+json.dumps(pins[p]),json.dumps(p)+': '+json.dumps(v))
write(path,ledger_text)
metadata={}
anchor_paths={
 'store.rs':{'native_work_verifier':'let work = pon_work::verify(h.challenge(), h.work_task, h.target, &packet.proof)','cumulative_weight':'.checked_add(consensus::required_work(h.target)?)'},
 'consensus.rs':{'required_work_formula':'pub fn required_work(','actual_target_rule':'pub fn retarget('}}
for name,anchors in anchor_paths.items():
 p='trillionnium/crates/trnm-pon-node/src/'+name;data=source(p);text=data.decode()
 metadata[name]={'path':p,'sha256':sha(data),'git_blob':blob_id(data),'bytes':str(len(data)),'anchors':{k:str(text[:text.index(needle)].count('\n')+1) for k,needle in anchors.items()}}
old_report_path='evidence/pon-w1-lifetime-account-boundary-20261110/project-report.json'
expected=json.loads(source(old_report_path));original=deepcopy(expected)
survey=expected['selected_source_survey'];survey['base_commit']=S
fixed_assignments=['        survey["base_commit"] = '+json.dumps(S)]
for name,index in [('store.rs',7),('consensus.rs',8)]:
 item=metadata[name];assert survey['sources'][index]['path']==item['path']
 for key,line in item['anchors'].items():
  assert survey['observations'][key]['path']==item['path']
  survey['observations'][key]['anchor_line']=line
  survey['observations'][key]['sha256']=item['sha256']
  fixed_assignments.append('        survey["observations"]['+json.dumps(key)+']["anchor_line"] = '+json.dumps(line))
  fixed_assignments.append('        survey["observations"]['+json.dumps(key)+']["sha256"] = (\n            '+json.dumps(item['sha256'])+')')
 survey['sources'][index]['bytes']=item['bytes'];survey['sources'][index]['sha256']=item['sha256']
 fixed_assignments.append('        survey["sources"]['+str(index)+']["bytes"] = '+json.dumps(item['bytes']))
 fixed_assignments.append('        survey["sources"]['+str(index)+']["sha256"] = (\n            '+json.dumps(item['sha256'])+')')
assert {k:v for k,v in expected.items() if k!='selected_source_survey'}=={k:v for k,v in original.items() if k!='selected_source_survey'}
write(NEW+'/project-input.json',source('evidence/pon-w1-lifetime-account-boundary-20261110/project-input.json'))
write(NEW+'/project-report.json',canonical(expected))
readme='''# Five-claim composition: selected-source lifetime survey

This successor binds the existing twenty selected source paths to implementation
commit `'''+S+'''`. It records source identity, not execution of a native binary,
cryptographic verification, a lifetime bound, model benefit, or production acceptance.

The 2026-11-09 current report and 2026-11-10 account-boundary report remain
unchanged historical records. This input is byte-identical to the account-boundary
input (SHA-256 `a6e43a5c55e71154592a3489f566995e7961b91611e15d40a18a948a495f9f89`).
All query limits, independent qualification fields, unknown bounds, mathematical
accounting and acceptance refusals retain their prior values.

Only the selected-source base commit and the reviewed store/consensus source
identities, byte counts and anchor locations change. The saved report is formed
from the independently fixed historical report and these exact Git objects.
The retained test separately reconstructs the historical report, then applies
literal reviewed values and compares both this fixture and the actual reader
output in full. Passing that comparison establishes selected-source consistency.

Reproduce from this composed checkout:

```sh
python3 scripts/w1_lifetime_ledger.py --input '''+NEW+'''/project-input.json
python3 scripts/ci/test_w1_lifetime_ledger.py
```

The actual native implementation remains full W1 recomputation. This source
survey does not activate a succinct verifier or close work-cost, independent
model benefit, adoption custody, or ordinary FinalUse obligations.
'''
write(NEW+'/README.md',readme)
path='scripts/ci/test_w1_lifetime_ledger.py';text=source(path).decode()
old='''        self.assertEqual((json.dumps(result, indent=2, sort_keys=True, allow_nan=False)
                          + "\\n").encode(), fixture.read_bytes())
'''
assert old in text
new='''        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(),
                         "b050b861ec172305d708ba7c01ca47d547b1646cc3daee1d6aec9877d2cf3390")
        account_boundary = fixture
        fixture = ROOT / "'''+NEW+'''/project-report.json"
        # These fixed values were reviewed from exact Git objects at the
        # composed implementation commit, independently of the reader output.
'''+ '\n'.join(fixed_assignments)+'''
        self.assertEqual((json.dumps(expected, indent=2, sort_keys=True, allow_nan=False)
                          + "\\n").encode(), fixture.read_bytes())
'''+old+'''        self.assertNotEqual(fixture.read_bytes(), account_boundary.read_bytes())
'''
text=replace_once(text,old,new)
text=replace_once(text,'        reviewed_base = "077ac4f33206de00a178553d9a0c729a20685088"','        reviewed_base = "'+S+'"')
text=replace_once(text,'        reviewed_store = "d4623d65b74a5f7d875037dceeb1a9c3d2a4d957791d4b39514a14eb3a2b90ca"','        reviewed_store = "'+metadata['store.rs']['sha256']+'"')
write(path,text)
path='.github/workflows/pon-w1-qrom-closure.yml';text=source(path).decode()
assert text.count('evidence/pon-w1-lifetime-account-boundary-20261110/')==2
text=text.replace('evidence/pon-w1-lifetime-account-boundary-20261110/',NEW+'/')
text=replace_once(text,'# Bind the reviewed account-boundary source; both older reports stay archived.','# Bind the reviewed composed source; both prior source reports stay archived.')
write(path,text)
path='.github/workflows/pon-recent-batch-acceptance.yml';text=source(path).decode()
old='test "$(git hash-object trillionnium/crates/trnm-pon-node/src/store.rs)" = d162fe28c0abf6bc1f5a2d59dd9dbbfff18f2b7c'
new='test "$(git hash-object trillionnium/crates/trnm-pon-node/src/store.rs)" = '+metadata['store.rs']['git_blob']
write(path,replace_once(text,old,new))
for path in ['config/pon/w1-qrom-implementation-current-v2.json','scripts/w1_qrom_current_implementation_audit.py','scripts/w1_qrom_implementation_audit.py']:
 assert source(path)==g('show',BASE+':'+path)
 assert Path(path).read_bytes()==source(path)
qrom=json.loads(source('config/pon/w1-qrom-implementation-current-v2.json'))
old_pin_keys=set(corpus['pinned_blobs']);old_required=list(corpus['required_paths'])
updated_pins={}
allowed=set(source_changes)|set(changed)
for path,pin in list(corpus['pinned_blobs'].items()):
 actual=blob_id(Path(path).read_bytes())
 if actual!=pin:
  assert path in allowed,('unexpected pin drift',path)
  corpus['pinned_blobs'][path]=actual;updated_pins[path]={'old':pin,'new':actual}
for name in ['README.md','project-input.json','project-report.json']:
 path=NEW+'/'+name
 assert path not in corpus['pinned_blobs']
 corpus['pinned_blobs'][path]=blob_id(Path(path).read_bytes())
 corpus['required_paths'].append(path)
assert old_pin_keys<=set(corpus['pinned_blobs'])
assert all(path in corpus['required_paths'] for path in old_required)
assert all(value is False for value in corpus['assertions'].values())
write(corpus_path,canonical(corpus))
for path,digest in historical.items():assert sha(Path(path).read_bytes())==digest
for path in changed:
 if path.endswith('.json'):json.loads(Path(path).read_bytes())
 if path.endswith('.py'):ast.parse(Path(path).read_text())
run('python3','scripts/refresh_distributed_source_inventory.py','--check')
run('git','diff','--check')
run('git','add',*changed)
run('bash','scripts/project-preflight.sh')
run('git','commit','-m','chore(pon): bind five-claim gates to reviewed implementation source')
T=g('rev-parse','HEAD').decode().strip()
assert g('status','--porcelain=v1')==b''
report={'result':'T_BINDINGS_COMPLETE','implementation_source':S,'binding_commit':T,'binding_tree':g('rev-parse',T+'^{tree}').decode().strip(),'changed_paths':changed,'source_metadata':metadata,'authority_lock_sha256':auth_digest,'authority_paths':44,'pq128_paths':15,'lifetime_paths':20,'corpus_pins':len(corpus['pinned_blobs']),'required_paths':len(corpus['required_paths']),'corpus_updated_pins':updated_pins,'historical_digests_preserved':historical,'qrom_selected_inputs':len(qrom['project_files']),'qrom_local_inputs':len(qrom['local_path_closure']['files']),'qualification_promoted':False}
out=Path('.git/pon-five-claims-bindings-d6cb');out.mkdir(exist_ok=True)
(out/'rebind-review.json').write_bytes(canonical(report))
print(json.dumps(report),flush=True)
PY
