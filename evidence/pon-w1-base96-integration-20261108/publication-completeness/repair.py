#!/usr/bin/env python3
import pathlib,subprocess,hashlib,json,time,shutil,io
r=pathlib.Path('/home/qian-qi/work/chain-w1-c7-attestation-20261108-ec265b')
old=pathlib.Path('/home/qian-qi/work/chain-w1-four-gates-attestation-20261108-ec265b')
v=pathlib.Path('/home/qian-qi/work/chain-w1-c7-root-validation-20261108-ec265b')
out=v/'docs-setup-recovery-01';out.mkdir(exist_ok=False);records=[]
def run(n,argv,allowed=(0,),input=None):
 p=subprocess.run(argv,cwd=r,capture_output=True,input=input);(out/(n+'.stdout')).write_bytes(p.stdout);(out/(n+'.stderr')).write_bytes(p.stderr);records.append({'label':n,'argv':argv,'exit':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()});(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');assert p.returncode in allowed,(n,p.returncode,p.stderr[-1500:]);return p.stdout
run('00-preflight',['bash','scripts/project-preflight.sh','--dev'])
assert run('01-head',['git','rev-parse','HEAD']).decode().strip()=='3daf5d06e84aeb02530e14eecc7ba1f8ec674e24'
assert run('02-merge',['git','rev-parse','MERGE_HEAD']).decode().strip()=='40a3a45d6b8afc5c4706c5235fec47634f4aabbe'
assert not run('03-unmerged',['git','diff','--name-only','--diff-filter=U']).strip()
ap=v/'docs-index-audit-01/audit.json';assert hashlib.sha256(ap.read_bytes()).hexdigest()=='98b4c883716fe1de125f38725b0ccf7a5cb9e52e39f7a09be8a3975acf87c16d'
audit=json.loads(ap.read_text());assert len(audit['missing'])==104
copied=[]
for f in audit['missing']:
 rel=f['repo_path'];assert rel.startswith(('evidence/pon-w1-four-gates-20261108/','evidence/pon-w1-base62-integration-20261108/')) and rel.endswith('.log')
 src=old/rel;b=src.read_bytes();assert len(b)==f['bytes'] and hashlib.sha256(b).hexdigest()==f['sha256']
 dst=r/rel;assert not dst.exists();dst.parent.mkdir(parents=True,exist_ok=True)
 with dst.open('xb') as w:w.write(b)
 copied.append({'path':rel,'bytes':len(b),'sha256':f['sha256']})
run('04-force-add-exact-missing-members',['git','add','-f','--']+[x['path'] for x in copied])
expected=[]
for dirname in ['pon-w1-four-gates-20261108','pon-w1-base62-integration-20261108']:
 prefix='evidence/'+dirname+'/';mp=r/prefix/'publication-inventory.json';m=json.loads(mp.read_text())
 expected.extend([dict(x,path=prefix+x['path']) for x in m['files']])
 expected.append({'path':prefix+'publication-inventory.json','bytes':mp.stat().st_size,'sha256':hashlib.sha256(mp.read_bytes()).hexdigest()})
raw=subprocess.run(['git','cat-file','--batch'],cwd=r,input=''.join(':'+x['path']+'\n' for x in expected).encode(),capture_output=True,check=True).stdout
stream=io.BytesIO(raw)
for x in expected:
 hdr=stream.readline().decode().strip().split();assert len(hdr)==3 and hdr[1]=='blob',(x['path'],hdr)
 b=stream.read(int(hdr[2]));assert stream.read(1)==b'\n';assert len(b)==x['bytes'] and hashlib.sha256(b).hexdigest()==x['sha256'],x['path']
assert not stream.read()
new=r/'evidence/pon-w1-base96-integration-20261108';new.mkdir(exist_ok=False)
ip=pathlib.Path('/home/qian-qi/work/chain-w1-c7-integration-publication-20261108-ec265b-01');assert hashlib.sha256((ip/'manifest.json').read_bytes()).hexdigest()=='667326b7a2736b6b37e9ebf39269bbb298148bde44cbfe68acaaad3f8b0fc04e'
shutil.copytree(ip,new/'integration')
pub=new/'publication-completeness';pub.mkdir()
for p in (v/'docs-index-audit-01').iterdir():
 if p.is_file():shutil.copyfile(p,pub/p.name)
readme='''# Publication completeness correction\n\nThe D3 and D4 local inventories were byte-complete, but earlier publication checks did not verify every inventory member in the Git tree. The repository rule .gitignore:23:*.log excluded 104 retained raw logs. In the immutable D4 commit, the C5 package contained 346 of its 421 inventory members (75 absent, 1,000,778 bytes); the C6 package contained 443 of its 472 inventory members (29 absent, 7,438 bytes). The two inventory JSON files themselves were tracked. This supersedes any interpretation of the earlier local member counts as proof that every member was publicly available in those old commits.\n\nD5 restores those exact 104 pre-existing files, validates their bytes against the unchanged original inventories, and force-adds only the enumerated paths. It does not rewrite the old commits, normalize raw logs, alter inventory hashes, or change runtime source. All 895 C5/C6 paths (893 members plus two inventories) were read from the new Git index through git cat-file --batch and verified for exact byte count and SHA-256. Final commit publication repeats this check against the committed tree.\n\nThe initial D5 setup failure and this discovery are retained. The new publication path verifies indexed and committed bytes instead of treating local existence or a README API readback as sufficient. These corrections add no test pass, full proof, payment, budget or security qualification.\n'''
(pub/'README.md').write_text(readme)
result={'schema':'TRNM-W1-D5-PUBLICATION-COMPLETENESS-REPAIR1','prior_commit':'3daf5d06e84aeb02530e14eecc7ba1f8ec674e24','prior_audit_sha256':hashlib.sha256(ap.read_bytes()).hexdigest(),'missing_members_restored':len(copied),'restored_bytes':sum(x['bytes'] for x in copied),'exact_restored_members':copied,'old_inventory_and_member_git_index_blobs_checked':len(expected),'all_old_manifest_hashes_unchanged':True,'source_tree_changes_due_to_repair':False,'gitignore_modified':False,'integrated_source':'40a3a45d6b8afc5c4706c5235fec47634f4aabbe','integration_package_copied':True,'observed_monotonic_ns':time.monotonic_ns()}
(out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');shutil.copyfile(out/'manifest.json',pub/'repair.json')
print(json.dumps({k:result[k] for k in ('schema','missing_members_restored','restored_bytes','old_inventory_and_member_git_index_blobs_checked','all_old_manifest_hashes_unchanged','gitignore_modified','integration_package_copied')}))
