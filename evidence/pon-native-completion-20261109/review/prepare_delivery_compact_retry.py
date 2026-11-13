"""Fixed-scope evidence delivery for the completed R3 campaigns; no new tests."""
import base64,datetime,hashlib,json,os,pathlib,re,subprocess,sys,time
if sys.flags.optimize: raise RuntimeError('Optimized Python is forbidden')
BASE=pathlib.Path('/data/chain-abg-70ae-20261108');ROOT=BASE/'source';EV=BASE/'evidence'
OUT=EV/'delivery-preparation';OUT.mkdir(exist_ok=False)
DEST=ROOT/'evidence/pon-native-completion-20261109'
CODE='ef025cbea963e3dee54ec4a17e3db7336c11409b';TREE='8de2f7b477aa41b75e9818634fc3aaf04f12f4df'
PREFIX='evidence/pon-native-completion-20261109/'
GROUPS='baseline-native baseline-native-corrected-filter candidate-contract-gates candidate-freeze candidate-retained-native def-finite-baseline green-guard-preparation green-native-first green-native-isolated-target green-preparation preparation red-native-first red-native-formatted source-freeze-preparation r2-freeze r2-native-and-clippy r2-contract-gates r2-def-finite r3-freeze r3-native-and-clippy r3-contract-gates r3-def-finite delivery-preparation-first'.split()
ENV={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','GIT_NO_LAZY_FETCH':'1','GIT_NO_REPLACE_OBJECTS':'1'}
INPUT=json.load(sys.stdin);commands=[]
def save(path,data):path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def read(path):return json.loads(path.read_text())
def digest(raw):return hashlib.sha256(raw).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,env=ENV).decode().strip()
def run(label,argv,limit=300,stdin=None):
 start=time.monotonic();p=subprocess.run(argv,cwd=ROOT,env=ENV,input=stdin,capture_output=True,timeout=limit)
 row={'label':label,'argv':argv,'cwd':str(ROOT),'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-start}
 for key,raw in [('stdout',p.stdout),('stderr',p.stderr)]:
  (OUT/(label+'.'+key)).write_bytes(raw);row[key]={'bytes':len(raw),'sha256':digest(raw)}
 if stdin is not None:row['stdin_utf8']=stdin.decode()
 commands.append(row);save(OUT/'commands.json',commands);print(json.dumps(row),flush=True)
 return p
assert git('rev-parse','HEAD')==CODE and git('rev-parse','HEAD^{tree}')==TREE and git('status','--porcelain')==''
expected_ids={'r3-native-and-clippy':'1a1be74a590-5e21-d7','r3-contract-gates':'1a1be75bb4a-5e21-e1','r3-def-finite':'1a1be7923df-5e21-fb'}
assert INPUT['expected_job_ids']==expected_ids
for group,job in expected_ids.items():
 r=INPUT['terminal_receipts'][group]
 assert r['job_id']==job and r['state']=='succeeded' and type(r['exit_code']) is int and r['exit_code']==0
 assert r['output_complete'] is True and r['output_durable'] is True and r['terminal_publication_confirmed'] is True
 assert r['timed_out'] is False and r['cancelled'] is False
 assert all(r['log_synced'][s] is True and r['log_truncated'][s] is False and r['log_errors'][s] is None for s in ['stdout','stderr'])
native=read(EV/'r3-native-and-clippy/summary.json');static=read(EV/'r3-contract-gates/summary.json');finite=read(EV/'r3-def-finite/summary.json')
assert native['source_head']==CODE and native['source_tree']==TREE and native['retained_all_pass'] and native['strict_clippy_pass']
assert native['actual_distinct_native_passes']==89 and native['ignored_tests']==2 and native['selected_unique_tests']==91
native_results=read(EV/'r3-native-and-clippy/retained-results.json')
assert len(native_results)==9 and all(r['pass'] and r['counts']['failed']==0 and r['counts']['passed']>0 for r in native_results)
assert len({n for r in native_results for n in r['selected_tests']})==91
assert sum(r['counts']['passed'] for r in native_results)==89 and sum(r['counts']['ignored'] for r in native_results)==2
for phase in ['source-before','source-after']:
 s=read(EV/'r3-native-and-clippy'/str(phase+'.json'))
 assert s['tested_commit']==CODE and s['tested_tree']==TREE and s['tracked_worktree_verified'] is True
assert static['expected_head']==CODE and static['expected_tree']==TREE and static['all_recorded_gates_pass'] is True
assert len(static['gates'])==13 and all(r['passed'] and r['exit_code']==0 and not r['timed_out'] for r in static['gates'])
for row in static['gates']:
 for phase in ['before','after']:
  assert row[phase]['head']==CODE and row[phase]['tree']==TREE and row[phase]['clean'] is True
bylabel={r['label']:r for r in static['gates']}
for label,count in [('source-integrity-negative-43',43),('pq-research-negative-57',57)]:assert bylabel[label]['tests_run']==count and bylabel[label]['skipped']==0
assert finite['expected_source_commit']==CODE and finite['expected_source_tree']==TREE and finite['all_finite_suites_pass'] is True
assert finite['actual_tests']==255 and finite['actual_modules']==9 and finite['failures']==[] and all(r['pass'] for r in finite['suite_results'])
for phase in ['source_before','source_after']:
 assert finite[phase]['commit']==CODE and finite[phase]['tree']==TREE and finite[phase]['clean'] is True
assert run('preflight',['bash','scripts/project-preflight.sh'],120).returncode==0
components={p:git('rev-parse',CODE+':'+p) for p in ['trillionnium','scripts','config','docs','.github']}
archive=[];planned=[];derived=[]
patterns=[r'gh[pousr]_[A-Za-z0-9]{30,}',r'github_pat_[A-Za-z0-9_]{30,}',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',r'(?i)authorization:\s*(?:bearer|token)\s+[A-Za-z0-9+/_=-]{15,}']
for group in GROUPS:
 source=EV/group;assert source.is_dir() and not source.is_symlink()
 for path in sorted(source.rglob('*')):
  rel=path.relative_to(EV)
  if any(part in ('tmp','cargo-metadata-target','target','target-green') for part in rel.parts):continue
  if path.is_dir():continue
  assert path.is_file() and not path.is_symlink(),str(path)
  assert path.suffix in ('.json','.stdout','.stderr','.txt','.md','.py','.sh','.patch','.log','.raw','.rs') or (group in ('r2-def-finite','r3-def-finite') and path.name in ('stdout','stderr')),str(path)
  raw=path.read_bytes();text=raw.decode('utf-8')
  assert not any(re.search(pattern,text) for pattern in patterns),'credential-pattern match: '+str(rel)
  dest=DEST/'observations'/rel
  if path.suffix=='.json':
   try:json.loads(text)
   except json.JSONDecodeError:
    assert str(rel)=='red-native-formatted/summary.json' and digest(raw)=='6fcd6f6cab3f32236c18f9917de39cd38673ecfd6dc0b812c25d21c4261ab494' and raw.endswith(b'\\n')
    canonical=json.loads(raw[:-2]);dest=dest.with_name('summary.malformed-json.raw')
    derived.append((dest.with_name('summary.derived.json'),{'schema':'derived-red-summary-v1','original_sha256':digest(raw),'derivation':'Only remove the trailing literal backslash-n after JSON; original bytes retained in sibling raw file.','observation':canonical}))
  assert not dest.exists(),str(dest)
  planned.append((dest,raw));archive.append({'original_path':str(path),'repository_path':str(dest.relative_to(ROOT)),'bytes':len(raw),'sha256':digest(raw),'kind':'unchanged original bytes'})
for name,encoded in sorted(INPUT['review_files'].items()):
 rel=pathlib.PurePosixPath(name);assert not rel.is_absolute() and '..' not in rel.parts and (name=='README.md' or name.startswith('review/'))
 raw=base64.b64decode(encoded,validate=True);text=raw.decode('utf-8');assert not any(re.search(p,text) for p in patterns),name
 if name=='README.md':
  assert text.count('@@CODE_HEAD@@')==1 and text.count('@@CODE_TREE@@')==1
  text=text.replace('@@CODE_HEAD@@',CODE).replace('@@CODE_TREE@@',TREE);raw=text.encode();assert '@@' not in text
 dest=DEST/rel
 if dest.exists():assert name=='README.md',name
 planned.append((dest,raw));archive.append({'original_path':'reviewed preparation input: '+name,'repository_path':str(dest.relative_to(ROOT)),'bytes':len(raw),'sha256':digest(raw),'kind':'rendered README' if name=='README.md' else 'unchanged reviewed input'})
assert len({str(p) for p,b in planned})==len(planned)
# The complete selection is reviewed before the first checkout write.
save(OUT/'selection.json',{'files':archive,'credential_pattern_findings':[],'groups':GROUPS})
created=[]
for dest,raw in planned:
 dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
 assert digest(dest.read_bytes())==digest(raw);created.append(dest)
for dest,value in derived:save(dest,value);created.append(dest)
save(DEST/'archive-manifest.json',{'schema':'native-completion-evidence-archive-v1','code_source':CODE,'code_tree':TREE,'files':archive,'file_count':len(archive),'total_bytes':sum(r['bytes'] for r in archive),'derived_files':[str(p.relative_to(ROOT)) for p,d in derived],'excluded':'Temporary directories, Cargo metadata targets, native binaries, databases and private material are outside this fixed selection.','all_original_bytes_preserved':True})
created.append(DEST/'archive-manifest.json')
save(DEST/'terminal-receipts.json',INPUT['terminal_receipts']);created.append(DEST/'terminal-receipts.json')
summary={'schema':'native-completion-exact-code-delivery-v1','code_source':CODE,'code_tree':TREE,'delivery_identity':'The Git evidence-only child containing this file; not a new test execution source.','new_test_execution_claim_on_delivery_head':False,'base':'e798d7125724d4b9f98c24d00cc80031f2eab4a9','native':native,'static_gates':[{k:r.get(k) for k in ['label','exit_code','passed','tests_run','skipped','elapsed_seconds']} for r in static['gates']],'finite_models':{'actual_modules':finite['actual_modules'],'actual_tests':finite['actual_tests'],'all_finite_suites_pass':finite['all_finite_suites_pass'],'summary_sha256':digest((EV/'r3-def-finite/summary.json').read_bytes())},'input_summaries':{name:digest((EV/name/'summary.json').read_bytes()) for name in expected_ids},'archive_manifest_sha256':digest((DEST/'archive-manifest.json').read_bytes()),'same_byte_red_green_test_sha256':'c5f0b9025f5f5b7e69bc766dd5c79403d8b8e4321157c3403d2c68144a92867f','R1':'Native controls passed; strict Clippy and current inline pin failed.','R2':'Native and strict Clippy passed; old applicability selector failed.','invalid_shared_target_observation':'INVALID_CANDIDATE_ARTIFACT_PROVENANCE; not a candidate pass or failure.','actual_distinct_native_passes':89,'ignored_native_tests':2,'production_acceptance':False,'original_fixed_host_contract':False,'ag_joint_acceptance':'HOLD_NO_GO','related_ac':{'pull_request':829,'code_source':'0f71bd817164feef370f75ee2ab881227693573d','evidence_head':'0cdc6ca1878854dd794aad25adfb072bc5fa4422','owner_query_exit':2,'owner_query_status':'NO_UPDATE_NEXT_INPUT_OUTPUT_MISMATCH','independent_source_lineage':True}}
save(DEST/'execution-summary.json',summary);created.append(DEST/'execution-summary.json')
paths=sorted(str(p.relative_to(ROOT)) for p in created)
assert len(paths)==len(set(paths)) and all(p.startswith(PREFIX) for p in paths)
assert git('rev-parse','HEAD')==CODE
assert all(p.startswith(PREFIX) for p in git('diff','--name-only').splitlines())
assert run('stage-evidence',['git','add','-f','--',*paths],120).returncode==0
staged=git('diff','--cached','--name-only').splitlines();assert set(staged)==set(paths)
full=run('raw-and-authored-diff-check',['git','diff','--cached','--check'],120)
raw_whitespace=[]
if full.returncode:
 raw_whitespace=re.findall(r'^(evidence/[^:\n]+):[0-9]+:',full.stdout.decode(),re.M)
 assert raw_whitespace and all(p.startswith(PREFIX+'observations/') for p in raw_whitespace)
 diagnostics=re.findall(r'^evidence/[^:\n]+:[0-9]+: (.*)$',full.stdout.decode(),re.M)
 assert len(diagnostics)==len(raw_whitespace) and all(d in ('trailing whitespace.','new blank line at EOF.') for d in diagnostics)
 assert not full.stderr
# Raw log formatting is preserved byte-for-byte. Authored text has its own gate.
authored=[p for p in paths if not p.startswith(PREFIX+'observations/')]
assert run('authored-diff-check',['git','diff','--cached','--check','--',*authored],120).returncode==0
assert run('repository-before-commit',['python3','-B','scripts/ci/check_repository.py'],600).returncode==0
assert run('inventory',['python3','-B','scripts/refresh_distributed_source_inventory.py','--check'],180).returncode==0
assert run('source-pins',['python3','-B','scripts/ci/check_pq_research_integration.py'],180).returncode==0
assert run('precommit-preflight',['bash','scripts/project-preflight.sh'],120).returncode==0
when=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
ENV.update(GIT_AUTHOR_NAME='ProfHepta',GIT_COMMITTER_NAME='ProfHepta',GIT_AUTHOR_EMAIL='102159240+ProfHepta@users.noreply.github.com',GIT_COMMITTER_EMAIL='102159240+ProfHepta@users.noreply.github.com',GIT_AUTHOR_DATE=when,GIT_COMMITTER_DATE=when)
message=BASE/'inputs/evidence-delivery-commit-message.txt'
message.write_text('docs(pon): retain exact native-completion qualification evidence\n\nPreserve final R3 execution receipts, same-byte red controls, intermediate failures, and the invalid shared-target observation. Keep A-G and production HOLD; this evidence-only child makes no new execution claim.\n')
assert run('commit',['git','commit','-F',str(message)],180).returncode==0
head=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}')
assert git('rev-parse','HEAD^')==CODE and git('status','--porcelain')==''
assert all(p.startswith(PREFIX) for p in git('diff','--name-only',CODE,head).splitlines())
component_rows={}
for path,original in components.items():
 observed=git('rev-parse',head+':'+path);assert observed==original
 component_rows[path]={'code_tree':original,'delivery_tree':observed}
assert run('source-after',['python3','-B','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',head,'--output',str(OUT/'source-after.json')],300).returncode==0
assert run('repository-after-commit',['python3','-B','scripts/ci/check_repository.py'],600).returncode==0
branch=git('branch','--show-current');assert branch=='fix/chain-native-completion-20261108-70ae'
line=('refs/heads/'+branch+' '+head+' refs/heads/'+branch+' '+'0'*40+'\n').encode()
assert run('push-preflight',['bash','scripts/project-preflight.sh','--push','origin','https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'],300,line).returncode==0
assert git('status','--porcelain')=='' and git('rev-parse','HEAD')==head
result={'schema':'native-completion-evidence-delivery-v1','code_source':CODE,'code_tree':TREE,'delivery_head':head,'delivery_tree':tree,'unchanged_component_trees':component_rows,'gates':commands,'push_preflight_passed':True,'new_test_execution_claim_on_delivery_head':False,'production_acceptance':False,'ag_joint_acceptance':'HOLD_NO_GO','archived_file_count':len(archive),'archived_bytes':sum(r['bytes'] for r in archive),'delivery_changed_files':len(paths),'raw_diff_check_exit':full.returncode,'raw_original_artifact_whitespace_paths':sorted(set(raw_whitespace)),'authored_formatting_passed':True}
save(OUT/'delivery.json',result);(OUT/'commit-object.txt').write_bytes(subprocess.check_output(['git','cat-file','commit',head],cwd=ROOT,env=ENV))
print(json.dumps({k:v for k,v in result.items() if k not in ('gates','raw_original_artifact_whitespace_paths')}),flush=True)
