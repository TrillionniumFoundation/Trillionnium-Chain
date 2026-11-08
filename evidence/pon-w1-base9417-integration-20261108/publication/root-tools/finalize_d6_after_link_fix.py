#!/usr/bin/env python3
import pathlib,subprocess,json,hashlib,shutil,time,argparse,re
ap=argparse.ArgumentParser();ap.add_argument('--declaration',required=True,type=pathlib.Path);ap.add_argument('--declaration-sha256',required=True);a=ap.parse_args()
def sha(b):return hashlib.sha256(b).hexdigest()
db=a.declaration.read_bytes();assert sha(db)==a.declaration_sha256;d=json.loads(db)
r=pathlib.Path('/home/qian-qi/work/chain-w1-c8-attestation-20261108-ec265b')
v=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-validation-20261108-ec265b')
tool=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-tools-20261108-ec265b')
new=r/'evidence/pon-w1-base9417-integration-20261108';pub=new/'publication';ip=new/'publication-inventory.json'
c8='4e007a87ceecbec8d265f6a70cfd71d512a514b5';d5='41d717cc9608153dec0daa26ad68ebf8129ed215'
assert d['tested_source']==c8 and d['old_git_paths']==2138 and d['four_gate_status']==['HOLD']*4
assert sha(pathlib.Path(__file__).read_bytes())==d['helper_sha256']
initial_inventory=ip.read_bytes();assert sha(initial_inventory)==d['initial_inventory_sha256']
first=v/'docs-validation-01';first_commands=json.loads((first/'commands.json').read_bytes())
assert len(first_commands)==9 and all(x['exit']==0 for x in first_commands[:-1])
assert first_commands[-1]['label']=='08-repository-links-and-boundaries' and first_commands[-1]['exit']==2
assert b'publication/root-tools/d6-readme-final.md -> base9417-review/README.md' in (first/'08-repository-links-and-boundaries.stderr').read_bytes()
initial_index=json.loads((first/'git-index-verification.json').read_bytes())
assert initial_index['file_count']==2984 and initial_index['all_inventory_bytes_match_git_blobs'] is True
assert not (first/'manifest.json').exists()
for name,pin in d['package_manifest_pins'].items():
 assert sha((new/name/'manifest.json').read_bytes())==pin,name
for name,entry in d['inputs'].items():
 b=(tool/name).read_bytes();assert sha(b)==entry['sha256'],name
assert sha((new/'README.md').read_bytes())==d['original_root_readme_sha256']
assert sha((new/'summary.json').read_bytes())==d['original_root_summary_sha256']
before=(tool/'publish_d6.py').read_bytes();after=(tool/'publish_d6_v2.py').read_bytes()
old=b"v/'docs-validation-01/manifest.json'";replacement=b"v/'docs-validation-02/manifest.json'"
assert before.count(old)==1 and after==before.replace(old,replacement)
out=v/'docs-validation-02';out.mkdir(exist_ok=False);records=[]
def run(n,args):
 p=subprocess.run(args,cwd=r,capture_output=True);(out/(n+'.stdout')).write_bytes(p.stdout);(out/(n+'.stderr')).write_bytes(p.stderr)
 records.append({'label':n,'argv':args,'exit':p.returncode,'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)})
 (out/'commands.json').write_text(json.dumps(records,indent=2)+'\n')
 assert p.returncode==0,(n,p.returncode,p.stderr[-2000:]);return p.stdout.decode()
run('00-preflight',['bash','scripts/project-preflight.sh','--dev'])
assert run('01-head',['git','rev-parse','HEAD']).strip()==d5
assert run('02-merge',['git','rev-parse','MERGE_HEAD']).strip()==c8
archive=pub/'docs-validation-initial-01';shutil.copytree(first,archive)
(archive/'original-publication-inventory.json').write_bytes(initial_inventory)
shutil.copyfile(pub/'README.md',archive/'publication-readme-original.md.txt')
renamed=[]
for row in d['archived_input_renames']:
 src=pub/'root-tools'/row['old'];dst=pub/'root-tools'/row['new']
 assert src.is_file() and not dst.exists() and sha(src.read_bytes())==row['sha256']
 src.rename(dst);assert sha(dst.read_bytes())==row['sha256'];renamed.append(row)
for name,entry in d['inputs'].items():
 src=tool/name;dst=pub/'root-tools'/entry['archive_name'];assert not dst.exists();shutil.copyfile(src,dst)
 assert sha(dst.read_bytes())==entry['sha256']
shutil.copyfile(pathlib.Path(__file__),pub/'root-tools'/pathlib.Path(__file__).name)
shutil.copyfile(a.declaration,pub/'root-tools'/'d6-publication-link-fix-declaration.json')
derivation={'schema':'TRNM-W1-D6-PUBLISHER-QA-PATH-DERIVATION1','original':'publish_d6.py','original_sha256':sha(before),'derived':'publish_d6_v2.py','derived_sha256':sha(after),'exact_old':old.decode(),'exact_new':replacement.decode(),'other_bytes_changed':False,'original_executed':False}
(pub/'root-tools'/'publish-d6-v2-derivation.json').write_text(json.dumps(derivation,indent=2)+'\n')
shutil.copyfile(tool/'d6-readme-publish-corrected.md',new/'README.md')
shutil.copyfile(tool/'d6-summary-publish-corrected.json',new/'summary.json')
s=json.loads((new/'summary.json').read_bytes())
assert s['tested_source']==c8 and s['four_gate_status']==['HOLD']*4
assert s['ordinary_test_method_executions']==697 and s['qualification_command_count_all_attempts']==77 and s['ordinary_passed']==696 and s['ordinary_failed']==1 and s['ignored']==4
assert s['publication_validation']['initial_job']=='1a1bac67b64-12894-1d21' and s['publication_validation']['initial_exit_code']==1
addition='\n## Initial documentation check and correction\n\nThe first assembly failed the unchanged repository Markdown-link check after all 2984 then-staged file paths passed byte verification. Its original command records, index verification and initial inventory are retained in [docs-validation-initial-01](docs-validation-initial-01/commands.json). The three archived authoring inputs now use .md.txt filenames with identical bytes; the final README and development plan remain normal checked Markdown. The original failed job receipt and the exact old-to-new paths are retained. A separate docs-validation-02 performs the same full checks, and publish_d6_v2.py changes only the QA result path it reads. No source qualification, source guard or business deadline changes are involved.\n'
with (pub/'README.md').open('a') as w:w.write(addition)
fix={'schema':'TRNM-W1-D6-ARCHIVED-MARKDOWN-LINK-FIX1','initial_job':'1a1bac67b64-12894-1d21','initial_failure_retained':True,'initial_inventory_sha256':sha(initial_inventory),'initial_index_paths_verified':2984,'renames':renamed,'same_source':c8,'checker_changed':False,'functional_qualification_rerun':False,'continuation_declaration_sha256':a.declaration_sha256,'publisher_derivation':derivation}
(pub/'link-fix-record.json').write_text(json.dumps(fix,indent=2)+'\n')
files=[];json_count=0
for p in sorted(new.rglob('*')):
 if p.is_dir() or p==ip:continue
 assert p.is_file() and not p.is_symlink() and not p.name.startswith('.hepta-lock'),str(p)
 b=p.read_bytes();assert not b.startswith((b'\x7fELF',b'SQLite format 3\0')),str(p)
 if p.suffix=='.json':json.loads(b);json_count+=1
 files.append({'path':p.relative_to(new).as_posix(),'bytes':len(b),'sha256':sha(b)})
inv={'schema':'TRNM-W1-C8-D6-PUBLICATION-INVENTORY1','tested_source':c8,'excluded_self':'publication-inventory.json','files':files}
ip.write_text(json.dumps(inv,indent=2)+'\n');ish=sha(ip.read_bytes())
plan=r/'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
run('03-stage-exact-evidence',['git','add','-f','--',str(new.relative_to(r)),str(plan.relative_to(r))])
changed=run('04-index-runtime-vs-c8',['git','diff','--cached','--name-only',c8]).splitlines()
allowed=('evidence/pon-w1-four-gates-20261108/','evidence/pon-w1-base62-integration-20261108/','evidence/pon-w1-base96-integration-20261108/','evidence/pon-w1-base9417-integration-20261108/')
assert all(x==str(plan.relative_to(r)) or x.startswith(allowed) for x in changed)
run('05-verify-index-bytes',['python3',str(new/'verify_git_publication.py'),'--rev','INDEX','--expected-new-inventory-sha256',ish,'--output',str(out/'git-index-verification.json')])
iv=json.loads((out/'git-index-verification.json').read_bytes());assert iv['file_count']==2138+len(files)+1
run('06-source-inventory',['python3','scripts/refresh_distributed_source_inventory.py','--check'])
run('07-current-implementation',['python3','scripts/ci/report_current_implementation.py','--check'])
run('08-repository-links-and-boundaries',['python3','scripts/ci/check_repository.py'])
authored=[str(plan.relative_to(r)),str((new/'README.md').relative_to(r)),str((new/'summary.json').relative_to(r)),str(ip.relative_to(r)),str((new/'verify_git_publication.py').relative_to(r)),str((pub/'README.md').relative_to(r))]
run('09-authored-whitespace',['git','diff','--cached','--check','--']+authored)
result={'schema':'TRNM-W1-C8-D6-DOCS-VALIDATION3','tested_source':c8,'new_manifest_members':len(files),'new_files_including_inventory':len(files)+1,'new_bytes_excluding_inventory':sum(x['bytes'] for x in files),'new_json_files_validated':json_count,'inventory_sha256':ish,'old_paths_git_index_verified':2138,'all_old_and_new_git_index_blobs_verified':True,'all_git_index_paths_verified':iv['file_count'],'runtime_index_equal_c8':True,'four_gate_status':['HOLD']*4,'qualification_flags_promoted':False,'assembly_declaration_sha256':a.declaration_sha256,'initial_failed_documentation_attempt_retained':True,'initial_inventory_sha256':sha(initial_inventory),'initial_job':'1a1bac67b64-12894-1d21','commands':records,'observed_monotonic_ns':time.monotonic_ns()}
(out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='commands'}))
