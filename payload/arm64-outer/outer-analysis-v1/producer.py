import os,sys,re,json,hashlib,stat
from pathlib import Path
R=Path('/private/tmp/chain-H5DF-arm64-cross-cost-original-evidence-20261114-v1')
O=R/'outer-analysis-v1';O.mkdir()
paths=[(R/'job-132528769087-original-log.stdout',184757,'b5f690a2a7cb61c16b6b459e1af5a7ca36430557c99ab51f4c66a7db09b32145'),(R/'job-132528769087-metadata.stdout',3914,'77e104cd3509c5ddd79e0fa6f37348df5bb4a6a2ff922110f1bdd135a768ff1d'),(R/'artifact-14124468052-metadata.stdout',809,'d3fdc7640f4c09e5a66b70220f6427b1bc2f1d962d7e354e488b1459d390f2ba')]
def read(p,n,h):
 a=p.lstat()
 if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size!=n:raise ValueError('input shape')
 b=p.read_bytes()
 if p.lstat()!=a or len(b)!=n or hashlib.sha256(b).hexdigest()!=h:raise ValueError('input pin')
 return b
def save(n,b):
 if isinstance(b,str):b=b.encode()
 p=O/n
 with p.open('xb') as f:f.write(b)
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
b,jb,ab=[read(*x) for x in paths];job=json.loads(jb);artifact=json.loads(ab)
rawlines=b.decode().splitlines()
lines=[re.sub(r'^\d{4}-\d{2}-\d{2}T[0-9:.]+Z ?','',l) for l in rawlines]
t='\n'.join(lines);dec=json.JSONDecoder();at=0;objects=[]
while True:
 pos=t.find('{',at)
 if pos<0:break
 try:o,n=dec.raw_decode(t[pos:])
 except json.JSONDecodeError:at=pos+1;continue
 if isinstance(o,dict):objects.append({'start':pos,'schema':o.get('schema'),'object':o})
 at=pos+n
sources=[x for x in objects if x['object'].get('schema')=='trnm-ci-source-v1']
controls=[x for x in objects if any(k in x['object'] for k in ['systemd_run_exit','preparation','final_host_errors'])]
sourcepins=[]
for i,x in enumerate(sources):sourcepins.append(save('source-'+str(i+1).zfill(2)+'.json',json.dumps(x['object'],sort_keys=True,indent=2)+'\n'))
controlpins=[]
for i,x in enumerate(controls):controlpins.append(save('controller-'+str(i+1).zfill(2)+'.json',json.dumps(x['object'],sort_keys=True,indent=2)+'\n'))
hit=re.compile(r'Execute exact native|run_from_zero|systemd_run_exit|final_host_errors|failure|##\[error\]|Artifact name|Artifact ID|Artifact size|SHA256 digest|CONFIRMATION_TARGET|test result|panicked',re.I)
selected=set()
for i,l in enumerate(rawlines):
 if hit.search(l):
  for z in range(max(0,i-2),min(len(rawlines),i+4)):selected.add(z)
context='\n'.join(f'{i+1}: {rawlines[i]}' for i in sorted(selected))+'\n'
if len(context.encode())>65536:raise ValueError('context cap')
cp=save('failure-and-artifact-context.txt',context)
expected={'base':None,'candidate':'5df7ae6f482157c5f7fdcbcd52222117a965053f','kind':'head','prospective_merge':None,'schema':'trnm-ci-source-v1','tested_commit':'5df7ae6f482157c5f7fdcbcd52222117a965053f','tested_tree':'6be4940d38cc88782657f2684cbefe48866f8b9f','tests_executed_by_identity_check':False,'tracked_bytes':3995072357,'tracked_entries':41681,'tracked_worktree_verified':True}
valid=len(sources)==2 and all(x['object'].keys()==expected.keys() and all(type(x['object'][k])is type(v)and x['object'][k]==v for k,v in expected.items())for x in sources)
summary={'schema':'trnm-H5DF-arm64-outer-source-and-failure-v1','status':'OUTER_READ_ORIGINAL_INNER_NOT_YET_ACQUIRED','run_id':43621754143,'run_attempt':1,'job_id':132528769087,'failed_steps':[x for x in job['steps']if x.get('conclusion')=='failure'],'source_objects':sourcepins,'source_before_after_exact_expected_typed':valid,'source_identity':expected if valid else None,'controller_objects':controlpins,'controller_facts':[{k:x['object'].get(k) for k in ('schema','systemd_run_exit','failure','final_host_errors','preparation','native_execution')}for x in controls],'top_level_JSON_schemas':[x['schema']for x in objects],'artifact':{k:artifact.get(k)for k in('id','name','size_in_bytes','digest','expired','workflow_run')},'context':cp,'inner_failure_cause':'UNKNOWN; systemd child exit is not an inner error diagnosis','no_tests_build_probe':True,'source_refs_stage_mutations':False,'inputs':[dict(path=str(p),bytes=n,sha256=h)for p,n,h in paths]}
save('producer.py',sys.argv[1])
sp=save('summary.json',json.dumps(summary,sort_keys=True,indent=2)+'\n')
print(json.dumps(summary));print(json.dumps(sp))
