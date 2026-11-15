import hashlib,json,subprocess,time
from pathlib import Path
repo=Path('/home/qian-qi/work/chain-pon-submit-probe-20261111-d6cb')
root=Path('/home/qian-qi/work/pon-five-claims-w1-artifacts-d6cb')
out=root/'before-subject'
out.mkdir(exist_ok=False)
base='11e242dbaaae14a9d16282fe8deaf36827e98395'
head='e63427560885b65c57db6bdc478df023111b4733'
tree='10a70f10bf5c64fe4b1d8df42c6463ff17aeba88'
branch='refs/heads/fix/chain-pon-five-claims-before-20261111-d6cb'
records=[]
def capture(args):
 return subprocess.run(args,cwd=repo,check=True,capture_output=True,text=True).stdout.strip()
def run(label,args):
 started=time.time()
 with (out/(label+'.stdout.log')).open('wb') as stdout,(out/(label+'.stderr.log')).open('wb') as stderr:
  p=subprocess.run(args,cwd=repo,stdout=stdout,stderr=stderr,timeout=300)
 r={'label':label,'argv':args,'started_unix':started,'finished_unix':time.time(),'exit_code':p.returncode}
 for name in ['stdout','stderr']:
  b=(out/(label+'.'+name+'.log')).read_bytes()
  r[name]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
 records.append(r);(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n')
 print(json.dumps(r),flush=True)
 assert p.returncode==0,label
assert capture(['git','rev-parse','HEAD'])==head
assert capture(['git','rev-parse',branch])==head
assert capture(['git','rev-parse','HEAD^{tree}'])==tree
assert capture(['git','rev-parse',head+'^'])==base
assert capture(['git','status','--porcelain'])==''
bundle=out/'before-subject-e6342756.bundle'
run('bundle-create',['git','bundle','create',str(bundle),branch,'^'+base])
run('bundle-verify',['git','bundle','verify',str(bundle)])
run('bundle-heads',['git','bundle','list-heads',str(bundle)])
run('format-patch',['git','format-patch','-1','--stdout','--full-index','--binary',head])
(out/'before-subject-e6342756.patch').write_bytes((out/'format-patch.stdout.log').read_bytes())
run('commit-raw',['git','cat-file','commit',head])
raw=(out/'commit-raw.stdout.log').read_bytes()
oid=hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
assert oid==head
run('commit-metadata',['git','show','--no-patch','--format=fuller',head])
assert capture(['git','rev-parse','HEAD'])==head
assert capture(['git','status','--porcelain'])==''
receipt={'schema':'trnm-submit-ancestry-before-subject-archive-v1','head':head,'tree':tree,'base_prerequisite':base,'local_branch':branch,'remote_ref_published':False,'bundle_verified':True,'raw_commit_oid_verified':oid,'source_unchanged':True,'subject_is_expected_failure_control':True,'files':[]}
for p in sorted(out.iterdir()):
 if not p.is_file():continue
 b=p.read_bytes()
 receipt['files'].append({'name':p.name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
(out/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2),flush=True)
