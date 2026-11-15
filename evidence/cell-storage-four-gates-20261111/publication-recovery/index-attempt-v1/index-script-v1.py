from pathlib import Path
import hashlib,json,os,re,subprocess,sys,time,traceback
R=Path('/home/qian-qi/work/chain-cell-storage-four-gates-20261111-2bfb-publish')
A=Path('/home/qian-qi/work/chain-cell-storage-four-gates-20261111-2bfb-publish-setup/final-publication')
E=R/'evidence/cell-storage-four-gates-20261111'
C3='030de92be05bfd4f73e199098c12dfeaedf29b17';NL=chr(10)
s=json.loads((A/'summary.json').read_text());assert s['assembly_completed'] and all(c['exit_code']==0 for c in s['commands'])
def save():
 p=A/'summary.json.tmp';p.write_text(json.dumps(s,indent=2,sort_keys=True)+NL);os.replace(p,A/'summary.json')
def put(p,b):
 p.parent.mkdir(parents=True,exist_ok=True)
 if isinstance(b,str):b=b.encode()
 with p.open('xb') as f:f.write(b)
def sha(b):return hashlib.sha256(b).hexdigest()
def run(name,args,timeout=300):
 st=time.monotonic();timed=False
 try:
  p=subprocess.run(args,cwd=R,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout);code=p.returncode;out=p.stdout;err=p.stderr
 except subprocess.TimeoutExpired as e:code=124;timed=True;out=e.stdout or b'';err=e.stderr or b''
 put(A/(name+'.stdout'),out);put(A/(name+'.stderr'),err)
 item={'name':name,'args':args,'exit_code':code,'timed_out':timed,'elapsed_seconds':time.monotonic()-st,'stdout_sha256':sha(out),'stderr_sha256':sha(err),'stdout_bytes':len(out),'stderr_bytes':len(err)}
 s['commands'].append(item);save();assert code==0 and not timed,(name,code)
 return out,err,item
def git(args):return subprocess.check_output(['git']+args,cwd=R).decode().strip()
try:
 s['status']='finalizing-index';save()
 assert git(['rev-parse','HEAD'])==C3
 run('index-preflight',['bash','scripts/project-preflight.sh','--audit'],60)
 bindings=json.loads((E/'publication-recovery/source-binding-review.json').read_text())
 for row in bindings['changed']:assert git(['hash-object',row['path']])==row['after']
 non_evidence=sorted(p for p in git(['diff','--name-only',C3]).splitlines() if not p.startswith('evidence/cell-storage-four-gates-20261111/'))
 expected=sorted([r['path'] for r in bindings['changed']]+['config/pon/pq-cross-branch-corpus-v1.json'])
 assert non_evidence==expected
 ci_paths=['.github/workflows/codeql-real-exact-source.yml','.github/workflows/pon-next-architecture-security.yml','scripts/ci/test_cell_storage_convergence_ci.py']
 diff=subprocess.check_output(['git','diff',C3,'--']+ci_paths,cwd=R)
 put(A/'ci-changes.diff',diff);put(E/'publication-recovery/ci-changes.diff',diff)
 scope={'runtime_head':C3,'non_evidence_paths':non_evidence,'rust_cargo_examples_and_native_model_runners_unchanged':True,'pin_changes':bindings['changed'],'pinned_blobs':994,'required_paths':902,'other_pins_unchanged':989,'qualification_flags_and_other_corpus_fields_unchanged':True,'ci_diff_sha256':sha(diff)}
 put(A/'scope-precommit.json',json.dumps(scope,indent=2,sort_keys=True)+NL);put(E/'publication-recovery/source-scope.json',json.dumps(scope,indent=2,sort_keys=True)+NL)
 cm=json.loads((E/'current/manifest.json').read_text())
 expected_summaries={'candidate':'98e514c9f632d9919bf8f2615018ebc73a688fea393b848116a65d0adcabc75c','observers':'5f3f100dda83ba4689006367831f35916356eff6024cc002f234ae07388b7e40','model':'f94d2090cd084d69863113c77f1011796574ffc0c8936ca783e324c20385bd3b'}
 original_summaries=[]
 for kind,digest in expected_summaries.items():
  rows=[r for r in cm['files'] if r['sha256']==digest];assert len(rows)==1,(kind,len(rows))
  row=rows[0];p=E/'current'/row['path'];b=p.read_bytes();assert sha(b)==digest;v=json.loads(b)
  original_summaries.append({'kind':kind,'path':str(p.relative_to(E)),'bytes':len(b),'sha256':digest,'original_keys':sorted(v)})
 put(E/'publication-recovery/original-summary-identities.json',json.dumps({'source':C3,'summaries':original_summaries,'all_archive_manifest_and_stream_hashes_verified':True},indent=2,sort_keys=True)+NL)
 readme=E/'README.md';old=readme.read_text();assert '## Evidence index and publication checks' not in old
 block=NL+'## Evidence index and publication checks'+NL+NL
 block+='| Retained material | Entry point |'+NL+'| --- | --- |'+NL
 block+='| Original current C3 records, 206 members; 205 member hashes and 165 streams verified | [Raw archive](raw/remote-current-records.tar.gz), [original manifest](current/manifest.json) |'+NL
 block+='| Original earlier attempts, 177 members; 176 member hashes and 170 streams verified | [Raw archive](raw/remote-prior-records.tar.gz), [original manifest](prior/SNAPSHOT_MANIFEST.json) |'+NL
 block+='| Test-only predecessor with #879 parent and the same test blob as C3 | [Original bundle](raw/cell-four-before-source.bundle), [object verification](publication-recovery/before-source-verification.json) |'+NL
 block+='| Original desktop C3 setup, Draft PR publication and full physical-source audit | [Records and exact rename mapping](desktop-publication/README.md) |'+NL
 block+='| Recovered original native-campaign and CodeQL Actions material, new archive identity | [Archive, member manifest and receipt](hosted-ci/native-codeql/README.md) |'+NL
 block+='| Next/work job logs, retained extraction output and QROM originals, new archive identity | [Archive, member manifest and receipt](hosted-ci/next-work-qrom/README.md) |'+NL
 block+='| Five exact source-binding changes and unchanged 994/902 rosters | [Binding review](publication-recovery/source-binding-review.json) |'+NL
 block+='| Actual workflow/contract patch and C3 byte-preservation scope | [Unified diff](publication-recovery/ci-changes.diff), [scope](publication-recovery/source-scope.json) |'+NL
 block+='| Actual publication 19/5/12 controls, inventory, PQ bindings and whitespace gate | [Raw commands and count guards](publication-recovery/controls/summary.json) |'+NL
 block+='| Preserved failed first assembly attempt and successful parser correction | [Original failed summary](publication-recovery/assembly-attempt-v1/summary.json), [original error](publication-recovery/assembly-attempt-v1/assembly-error.txt) |'+NL
 block+='| Original-package transfer and interrupted review-environment facts | [Transfer receipt](publication-recovery/original-package-recovery.json), [outage record](publication-recovery/interrupted-local-review.json) |'+NL
 for row in original_summaries:block+='| Original '+row['kind']+' summary, SHA256 '+row['sha256']+' | [Raw summary]('+row['path']+') |'+NL
 block+=NL+'The prior C3 precommit-maintenance records remain present. The separately named local-precommit/local-runner-controls packet and the six local archive-download failure receipt files were not recovered from the unavailable scratch environment. Their descriptions are retained observations; they do not claim that all lost raw bytes are included. See the [precise recovery scope](publication-recovery/local-records-recovery-scope.json).'+NL
 block+=NL+'The two Actions recovery archives have their own observed identities. The native/CodeQL package does not claim restoration of the old local 32-review attachment set or the old aggregate archive. The next/work/QROM package retains 65 payloads checked against their prior SHA256, ten complete job logs, four complete extraction stdout/result files and four verified QROM ZIPs with 84 members. The eighteen original fresh-challenge selected members were not all recovered; no complete-restoration claim is made.'+NL
 block+=NL+'The current/prior/desktop raw archives remain byte-identical to their recorded originals. Expanded copies preserve original bytes. Only the known invalid desktop setup JSON is renamed with a recorded mapping. Original Markdown entry points copied from the compressed Actions packages use .md.raw names so their unchanged archived-relative links are not presented as unpacked files.'+NL
 block+=NL+'Publication checks above are Python/source/evidence checks. They are not additional native or model executions. The commit-bound full physical source guard is retained outside the worktree and read back before normal publication; native execution remains attributed to C3.'+NL
 readme.write_text(old+block)
 out,err,item=run('repository-precommit',[sys.executable,'-B','scripts/ci/check_repository.py'],300)
 for suffix in ('.stdout','.stderr'):put(E/'publication-recovery/controls'/('repository-precommit'+suffix),(A/('repository-precommit'+suffix)).read_bytes())
 put(E/'publication-recovery/controls/repository-precommit.json',json.dumps({'scope':'actual complete repository JSON/Markdown-link check before publication commit','command':item,'result':'PASS','native_execution':False},indent=2,sort_keys=True)+NL)
 readme.write_text(readme.read_text()+NL+'The actual precommit repository scan passed: [result and exact command](publication-recovery/controls/repository-precommit.json), [raw stdout](publication-recovery/controls/repository-precommit.stdout), [raw stderr](publication-recovery/controls/repository-precommit.stderr). The final committed tree is rechecked before pushing.'+NL)
 run('final-diff-check',['git','diff','--check'],60)
 s['index_completed']=True;s['status']='ready-to-commit';s['source_scope_path']=str(A/'scope-precommit.json');s['ci_diff_path']=str(A/'ci-changes.diff');save()
 print(json.dumps({'index_completed':True,'status':s['status'],'summary':str(A/'summary.json')}),flush=True)
except Exception as e:
 s['status']='index_failed';s['index_error']=repr(e);save();put(A/'index-error.txt',traceback.format_exc());print(json.dumps({'status':s['status'],'error':repr(e)}),flush=True);raise
