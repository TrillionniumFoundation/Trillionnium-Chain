#!/usr/bin/env python3
import pathlib,subprocess,hashlib,json,time,shutil
origin=pathlib.Path('/home/qian-qi/work/chain-w1-c7-attestation-20261108-ec265b')
r=pathlib.Path('/home/qian-qi/work/chain-w1-c8-attestation-20261108-ec265b')
out=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-validation-20261108-ec265b/docs-setup-01');out.mkdir(exist_ok=False)
branch='docs/chain-w1-base9417-qualification-20261108-ec265b'
d5='41d717cc9608153dec0daa26ad68ebf8129ed215';c8='4e007a87ceecbec8d265f6a70cfd71d512a514b5';plan='docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
records=[]
def run(n,argv,cwd=origin,allowed=(0,)):
 p=subprocess.run(argv,cwd=cwd,capture_output=True);(out/(n+'.stdout')).write_bytes(p.stdout);(out/(n+'.stderr')).write_bytes(p.stderr);records.append({'label':n,'argv':argv,'cwd':str(cwd),'exit':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()});(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');assert p.returncode in allowed,(n,p.returncode,p.stderr[-1500:]);return p.stdout
run('00-preflight',['bash','scripts/project-preflight.sh','--dev'])
assert run('01-docs-head',['git','rev-parse','HEAD']).decode().strip()==d5
assert not run('02-docs-clean',['git','status','--porcelain']).strip()
assert not run('03-new-branch-check',['git','for-each-ref','--format=%(refname)','refs/heads/'+branch]).strip()
assert not r.exists()
run('04-new-worktree',['git','worktree','add','-b',branch,str(r),d5])
run('05-merge-c8',['git','merge','--no-ff','--no-commit',c8],r,(0,1))
conflicts=run('06-conflict-list',['git','diff','--name-only','--diff-filter=U'],r).decode().splitlines()
resolution=None
if conflicts:
 assert conflicts==[plan],conflicts
 base=run('07-plan-base',['git','show',':1:'+plan],r)
 ours=run('08-plan-ours',['git','show',':2:'+plan],r)
 theirs=run('09-plan-theirs',['git','show',':3:'+plan],r)
 assert theirs.startswith(base),'C8 sole-plan change is not append-only'
 delta=theirs[len(base):];assert delta and delta not in ours
 merged=ours+delta
 (r/plan).write_bytes(merged)
 run('10-resolve-sole-plan',['git','add',plan],r)
 resolution={'kind':'retain-complete-D5-plan-then-append-exact-C8-delta','base_sha256':hashlib.sha256(base).hexdigest(),'ours_sha256':hashlib.sha256(ours).hexdigest(),'theirs_sha256':hashlib.sha256(theirs).hexdigest(),'appended_sha256':hashlib.sha256(delta).hexdigest(),'result_sha256':hashlib.sha256(merged).hexdigest()}
assert not run('11-no-unmerged',['git','diff','--name-only','--diff-filter=U'],r).strip()
preserved=[]
oldspecs=[('evidence/pon-w1-four-gates-20261108/publication-inventory.json','524bb438ef63bc5fb25ecba3a723e9bb64dc5d7dbf8560797c6788410c282dda',421),('evidence/pon-w1-base62-integration-20261108/publication-inventory.json','1a25fdb927a8ad7b7e980718cd85a1f0bced231b7f37df1ffa817ce142996d95',472),('evidence/pon-w1-base96-integration-20261108/publication-inventory.json','9c0c06ea019853aededd8e24475b34480ec05b45f7cc101a3e54d7a27f0b982a',1242)]
for rel,sha,n in oldspecs:
 p=r/rel;assert hashlib.sha256(p.read_bytes()).hexdigest()==sha
 inv=json.loads(p.read_text());assert len(inv['files'])==n
 for f in inv['files']:
  b=(p.parent/f['path']).read_bytes();assert len(b)==f['bytes'] and hashlib.sha256(b).hexdigest()==f['sha256'],f['path']
 preserved.append({'inventory':rel,'sha256':sha,'members_checked':n})
new=r/'evidence/pon-w1-base9417-integration-20261108';new.mkdir(exist_ok=False)
src=pathlib.Path('/home/qian-qi/work/chain-w1-c8-integration-publication-20261108-ec265b-01')
assert hashlib.sha256((src/'manifest.json').read_bytes()).hexdigest()=='5535e642c8ae2b9b1960be983f1c048d604b18c95e04d0ef2f54c4d6d9238676'
shutil.copytree(src,new/'integration')
changed=run('12-index-vs-c8',['git','diff','--cached','--name-only',c8],r).decode().splitlines()
prefixes=[str(pathlib.Path(rel).parent)+'/' for rel,_,_ in oldspecs]
assert all(p==plan or any(p.startswith(pre) for pre in prefixes) for p in changed),changed
result={'schema':'TRNM-W1-C8-D6-DOCS-SETUP1','worktree':str(r),'branch':branch,'first_parent':d5,'merge_parent':c8,'conflicts':conflicts,'resolution':resolution,'preserved':preserved,'runtime_index_matches_c8':True,'integration_package_copied':True,'commit_created':False,'pushed':False,'observed_monotonic_ns':time.monotonic_ns()}
(out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
