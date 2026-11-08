#!/usr/bin/env python3
import pathlib,subprocess,json,hashlib,shutil,time,argparse,re
ap=argparse.ArgumentParser();ap.add_argument('--declaration',required=True,type=pathlib.Path);ap.add_argument('--declaration-sha256',required=True);a=ap.parse_args()
db=a.declaration.read_bytes();assert re.fullmatch('[0-9a-f]{64}',a.declaration_sha256) and hashlib.sha256(db).hexdigest()==a.declaration_sha256
d=json.loads(db)
r=pathlib.Path('/home/qian-qi/work/chain-w1-c8-attestation-20261108-ec265b')
v=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-validation-20261108-ec265b')
tool=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-tools-20261108-ec265b')
oldv=pathlib.Path('/home/qian-qi/work/chain-w1-c7-root-validation-20261108-ec265b')
new=r/'evidence/pon-w1-base9417-integration-20261108'
c8='4e007a87ceecbec8d265f6a70cfd71d512a514b5';tree='19a4f1a6e1cec5c27e595fa555b97cddc4717a3c';d5='41d717cc9608153dec0daa26ad68ebf8129ed215'
assert d['tested_source']==c8 and d['tested_tree']==tree and d['old_git_paths']==2138 and d['four_gate_status']==['HOLD']*4
out=v/'docs-validation-01';out.mkdir(exist_ok=False);records=[]
def run(n,args):
 p=subprocess.run(args,cwd=r,capture_output=True);(out/(n+'.stdout')).write_bytes(p.stdout);(out/(n+'.stderr')).write_bytes(p.stderr);records.append({'label':n,'argv':args,'exit':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()});(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');assert p.returncode==0,(n,p.returncode,p.stderr[-2000:]);return p.stdout.decode()
run('00-preflight',['bash','scripts/project-preflight.sh','--dev'])
assert run('01-head',['git','rev-parse','HEAD']).strip()==d5
assert run('02-merge',['git','rev-parse','MERGE_HEAD']).strip()==c8
assert set(d['package_manifest_pins'])=={'integration','qualification','build-preparation','lifecycle-c8','ci-c8','base9417-review'}
review_src=pathlib.Path('/home/qian-qi/work/chain-w1-base9417-cache-review-20261108-ec265b-01')
assert hashlib.sha256((review_src/'manifest.json').read_bytes()).hexdigest()==d['package_manifest_pins']['base9417-review']
shutil.copytree(review_src,new/'base9417-review')
for name,sha in d['package_manifest_pins'].items():
 assert re.fullmatch('[0-9a-f]{64}',sha)
 p=new/name/'manifest.json';assert hashlib.sha256(p.read_bytes()).hexdigest()==sha,name
 assert (new/name/'README.md').is_file(),name
for name in ('README.md','summary.json','sole-plan-append.md'):
 src=pathlib.Path(d['root_files'][name]['path']);b=src.read_bytes()
 assert hashlib.sha256(b).hexdigest()==d['root_files'][name]['sha256']
 if name!='sole-plan-append.md':
  dst=new/name;assert not dst.exists();shutil.copyfile(src,dst)
summary=json.loads((new/'summary.json').read_text())
assert summary['tested_source']==c8 and summary['tested_tree']==tree and summary['four_gate_status']==['HOLD']*4
assert summary['ordinary_test_method_executions']==697 and summary['qualification_command_count_all_attempts']==77 and summary['ordinary_passed']==696 and summary['ordinary_failed']==1 and summary['ignored']==4 and summary['all_first_attempts_passed'] is False
src=tool/'verify_git_publication.py'
assert hashlib.sha256(src.read_bytes()).hexdigest()==d['verify_git_publication_sha256']
shutil.copyfile(src,new/'verify_git_publication.py')
pub=new/'publication';pub.mkdir(exist_ok=False)
for name,path in [('c8-source',v/'source-publication-01'),('c8-preparation',v/'preparation-01'),('c8-docs-setup',v/'docs-setup-01'),('d5-docs-publication',oldv/'docs-publication-01'),('d5-pr-publication',oldv/'pr-d5-publication-01')]:
 shutil.copytree(path,pub/name)
shutil.copytree(tool,pub/'root-tools')
shutil.copyfile(a.declaration,pub/'assembly-declaration.json')
(pub/'README.md').write_text('# Publication and exact-source preparation\n\nThe original C8 source fast-forward records and root qualification plans are retained here, together with D6 setup and the completed D5 publication and PR update. D5 commit-byte and remote tree checks proved all 2138 retained files, including the 104 original logs omitted by the earlier ignore rule. Those older inventory bytes remain fixed.\n\nC8 qualification used exact source 4e007a87ceecbec8d265f6a70cfd71d512a514b5; this evidence merge is not presented as executed source. Root helper files document the declared execution and publication contracts. Final D6 commit/remote-tree verification runs after this inventory is frozen; no circular receipt for this same publication is claimed. Public PR API responses do not capture authentication headers or credential values.\n')
plan=r/'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
addition=pathlib.Path(d['root_files']['sole-plan-append.md']['path']).read_text()
assert d['sole_plan_unique_heading'] in addition and d['sole_plan_unique_heading'] not in plan.read_text()
with plan.open('a') as w:w.write(addition)
files=[];json_count=0
for p in sorted(new.rglob('*')):
 if p.is_dir():continue
 assert p.is_file() and not p.is_symlink() and not p.name.startswith('.hepta-lock'),str(p)
 b=p.read_bytes();assert not b.startswith((b'\x7fELF',b'SQLite format 3\0')),str(p)
 if p.suffix=='.json':json.loads(b);json_count+=1
 files.append({'path':p.relative_to(new).as_posix(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
inv={'schema':'TRNM-W1-C8-D6-PUBLICATION-INVENTORY1','tested_source':c8,'excluded_self':'publication-inventory.json','files':files}
ip=new/'publication-inventory.json';ip.write_text(json.dumps(inv,indent=2)+'\n');ish=hashlib.sha256(ip.read_bytes()).hexdigest()
run('03-stage-exact-evidence',['git','add','-f','--',str(new.relative_to(r)),str(plan.relative_to(r))])
changed=run('04-index-runtime-vs-c8',['git','diff','--cached','--name-only',c8]).splitlines()
allowed=('evidence/pon-w1-four-gates-20261108/','evidence/pon-w1-base62-integration-20261108/','evidence/pon-w1-base96-integration-20261108/','evidence/pon-w1-base9417-integration-20261108/')
assert all(x==str(plan.relative_to(r)) or x.startswith(allowed) for x in changed)
run('05-verify-index-bytes',['python3',str(new/'verify_git_publication.py'),'--rev','INDEX','--expected-new-inventory-sha256',ish,'--output',str(out/'git-index-verification.json')])
iv=json.loads((out/'git-index-verification.json').read_text())
assert iv['file_count']==2138+len(files)+1
run('06-source-inventory',['python3','scripts/refresh_distributed_source_inventory.py','--check'])
run('07-current-implementation',['python3','scripts/ci/report_current_implementation.py','--check'])
run('08-repository-links-and-boundaries',['python3','scripts/ci/check_repository.py'])
authored=[str(plan.relative_to(r)),str((new/'README.md').relative_to(r)),str((new/'summary.json').relative_to(r)),str(ip.relative_to(r)),str((new/'verify_git_publication.py').relative_to(r)),str((pub/'README.md').relative_to(r))]
run('09-authored-whitespace',['git','diff','--cached','--check','--']+authored)
result={'schema':'TRNM-W1-C8-D6-DOCS-VALIDATION2','tested_source':c8,'new_manifest_members':len(files),'new_files_including_inventory':len(files)+1,'new_bytes_excluding_inventory':sum(x['bytes'] for x in files),'new_json_files_validated':json_count,'inventory_sha256':ish,'old_paths_git_index_verified':2138,'all_old_and_new_git_index_blobs_verified':True,'all_git_index_paths_verified':iv['file_count'],'runtime_index_equal_c8':True,'four_gate_status':['HOLD']*4,'qualification_flags_promoted':False,'assembly_declaration_sha256':a.declaration_sha256,'commands':records,'observed_monotonic_ns':time.monotonic_ns()}
(out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='commands'}))
