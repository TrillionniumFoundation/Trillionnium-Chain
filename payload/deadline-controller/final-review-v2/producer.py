import ast, datetime, difflib, hashlib, json, os, pathlib, re, stat, sys
E=pathlib.Path('/private/tmp/chain-new-head-5df7-deadline-controller-review-20261114-v1')
F=E/'final-review-v2'
F.mkdir(mode=0o700)
sha=lambda b:hashlib.sha256(b).hexdigest()
def read(p):
 p=pathlib.Path(p);before=p.lstat()
 if p.resolve(strict=True)!=p or not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:raise ValueError('unsafe source')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  first=os.fstat(fd);chunks=[]
  while True:
   q=os.read(fd,65536)
   if not q:break
   chunks.append(q)
  after=os.fstat(fd)
 finally:os.close(fd)
 keys=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 if keys(before)!=keys(first) or keys(first)!=keys(after) or keys(after)!=keys(p.lstat()):raise ValueError('read changed')
 return b''.join(chunks)
def put(rel,data):
 p=F/rel
 with p.open('xb') as f:f.write(data)
 return {'path':str(p),'bytes':len(data),'sha256':sha(data)}
def js(rel,value):return put(rel,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())
put('producer.py',sys.argv[1].encode())
summaryraw=read(E/'input-summary.json')
if sha(summaryraw)!='593207e1148e34a1a11ba2e6bee82b288e1b2c385143a7e609e25201cd1669c3':raise ValueError('input summary SHA')
summary=json.loads(summaryraw)
for row in summary['sources']+summary['derived']:
 raw=read(row['path'])
 if len(raw)!=row['bytes'] or sha(raw)!=row['sha256'] or hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=row['git_oid']:raise ValueError('source byte identity')
old=read(E/'R1/scripts/test_w1_owned_process_collector_v1.py').decode()
new=read(E/'5df-derived/scripts/test_w1_owned_process_collector_v1.py').decode()
oa=ast.parse(old);na=ast.parse(new)
def methods(a):
 return {c.name+'.'+m.name:m for c in a.body if isinstance(c,ast.ClassDef) for m in c.body if isinstance(m,ast.FunctionDef)}
om,nm=methods(oa),methods(na)
if set(om)!=set(nm):raise ValueError('method roster changed')
changed=[n for n in om if ast.dump(om[n],include_attributes=False)!=ast.dump(nm[n],include_attributes=False)]
expected='CollectorControls.test_actual_post_fork_identity_failure_reaps_gated_root_without_exec'
if changed!=[expected]:raise ValueError('unexpected changed methods '+repr(changed))
same=[n for n in om if n!=expected]
if not all(ast.get_source_segment(old,om[n])==ast.get_source_segment(new,nm[n]) for n in same):raise ValueError('unchanged method bytes differ')
for cls in na.body:
 if isinstance(cls,ast.ClassDef):
  cls.body=[om[cls.name+'.'+m.name] if isinstance(m,ast.FunctionDef) and cls.name+'.'+m.name==expected else m for m in cls.body]
if ast.dump(oa,include_attributes=False)!=ast.dump(na,include_attributes=False):raise ValueError('other module AST changed')
tests=[n for n in om if n.split('.')[-1].startswith('test_')]
if len(tests)!=16:raise ValueError('control count')
r_old=read(E/'R1/trillionnium/crates/trnm-pon-node/src/ingress/public_v2.rs')
r_new=read(E/'5df-derived/trillionnium/crates/trnm-pon-node/src/ingress/public_v2.rs')
ol=r_old.splitlines(keepends=True);nl=r_new.splitlines(keepends=True)
ops=difflib.SequenceMatcher(a=ol,b=nl,autojunk=False).get_opcodes()
inserts=[(i,j,a,b) for tag,i,j,a,b in ops if tag!='equal']
if any(tag not in ('equal','insert') for tag,*_ in ops) or [b-a for i,j,a,b in inserts]!=[4,94]:raise ValueError('Rust delta bounds')
rust_segments=[]
for number,(i,j,a,b) in enumerate(inserts,1):
 raw=b''.join(nl[a:b]);pin=put('rust-added-block-'+str(number)+'.rs.original',raw)
 rust_segments.append({'old_line_after':i,'new_first_line':a+1,'new_line_count':b-a,'pin':pin})
rest=b''.join(line for tag,i,j,a,b in ops if tag=='equal' for line in nl[a:b])
if rest!=r_old:raise ValueError('Rust base not exactly retained')
def test_names(raw):
 s=raw.decode()
 return re.findall(r'#\[test\]\s*(?:#\[[^\n]*\]\s*)*fn\s+(\w+)\s*\(',s)
oldnames=test_names(r_old);newnames=test_names(r_new)
added=[n for n in newnames if n not in oldnames]
if added!=['original_v2_client_rejects_expiry_after_signed_response_verification','expired_v2_client_deadline_refuses_before_tcp'] or [n for n in newnames if n in oldnames]!=oldnames:raise ValueError('Rust control roster')
ci=read(E/'R1/scripts/ci/ci_job.sh').decode()
if '("owned-process-collector", 16)' not in ci or 'or not re.search(r"^OK$", text, re.M) or "skipped=" in text' not in ci:raise ValueError('original exact-count gate')
proof={'schema':'trnm-5df-deadline-controller-static-continuity-v1','input_summary':{'path':str(E/'input-summary.json'),'bytes':len(summaryraw),'sha256':sha(summaryraw)},'tests_or_target_helpers_executed':False,
 'python':{'old_tests':len(tests),'new_tests':len(tests),'same_method_names':True,'changed_AST_methods':changed,'unchanged_test_SOURCE_and_AST':15,'remaining_module_AST_equal_after_restoring_one_method':True,'all_test_names':tests,'all_unchanged_method_source_sha256':{n:sha(ast.get_source_segment(old,om[n]).encode()) for n in same}},
 'rust':{'old_test_names':oldnames,'new_test_names':newnames,'added_test_names':added,'all_original_bytes_retained_in_order':True,'only_two_insertions':rust_segments,'all_preexisting_runtime_constants_policy_encoding_server_code_and_tests_byte_unchanged':True},
 'ci':{'same_file_at_new_head_by_complete_12path_compare':True,'exact_required_controls':16,'zero_skip_and_OK_guard_retained':True,'runtime_collector_identical_by_compare':summary['sources'][1]}}
pp=js('static-continuity.json',proof)
review={
 'schema':'trnm-5df-deadline-controller-review-v1','status':'STATIC_REVIEW_NO_BLOCKER','old_head':summary['old'],'new_head':summary['new'],'new_tree':'6be4940d38cc88782657f2684cbefe48866f8b9f','source_basis':summary['new_blob_source'],'input_summary':proof['input_summary'],'static_proof':pp,
 'sources':summary['sources'],'derived_sources':summary['derived'],
 'public_v2':{
  'production_change':'After canonical response context and signature checks, reject when Instant::now() is not less than the same total_deadline constructed at client entry. No phase or nonce budget is rebased.',
  'deadline_context':{'path':'trillionnium/crates/trnm-pon-node/src/ingress/public_v2.rs','entry_lines':[1419,1425],'response_checks_lines':[1528,1542],'new_check_line':1546,'default_overall_ms_unchanged':30000,'nonce_deadline_check_cadence_unchanged':256},
  'unchanged':['Classical-profile rejection before TCP','All signed context/profile/network/genesis/body identities and verification','Policy framing/serialization and server fields','Server reactor and Host verification calls','Existing phase limits and per-caller outer deadline minimum','public_network_ready=false and identity_authority=false'],
  'new_tests':{'count':2,'names':added,'meaning':'One actual signed loopback Head on-time result, then a thread-local test-only delay after successful verification until the same 2s caller deadline; require exact deadline error, the verification hook reached, and two server reads. A second case supplies an already elapsed caller deadline and requires no accepted TCP connection.','not_measured':'Tests were not run in this review; the 2s test is not a hosted 4s performance observation.'},
  'failure_priority':'Malformed-context/signature errors remain before the new deadline rejection. The production check only converts a would-be valid late response into an error.',
  'test_injection':'Both state cells and the helper are cfg(test); thread-local state is consumed with replace(false) and reset by the test, with no cross-thread armed flag.'
 },
 'collector':{
  'runtime_changed':False,'test_method':expected,'test_count':16,'unchanged_other_tests':15,
  'existing_runtime':{'launch':[438,518],'child_gate_eof_exit125':[494,495],'same_deadline_KILL_escalation':[394,414],'waitid_WNOWAIT_wait4_identity_binding':[344,391],'launch_failure_cause':[898,905],'wrapper_and_qualification':[568,622]},
  'legal_raw_outcomes':'A never-released root can consume exec-gate EOF and exit125, or remain unscheduled until the existing KILL escalation reaches min(250ms, grace/2). The new test accepts only these two preserved raw outcomes.',
  'new_causal_requirements':['Exact launch-error cause and injected error text','One actual child and final wait4 ECHILD, same birth identity and collector parent','No truncated records, no root-exec-released event, and no TERM event for this root','wait4 status translates to root returncode and agrees with waitid code/status','For SIGKILL, require same-root sent event from this collector between cleanup-start and actual reap','Wrapper exit125, no marker execution, command_success=false and collector_wait_domain_reaped=false remain required'],
  'limits':'The event ordering is an internal causal consistency proof under the original owned-process test model. It does not establish protection against an external ptracer/signaller, new performance qualification, or actual execution of either branch in this static review.',
  'original_mock_controls':'The two unchanged deterministic controls still require the precise original KILL boundary, TERM deferral only for a confirmed closed/unreleased root, no deadline extension, and normal TERM for released/unconfirmed cases.'
 },
 'qualification':{'native_or_repo_tests_run':False,'new_head_CI_success_asserted':False,'hosted_4s_fixed_asserted':False,'old_R1_failure_reclassified':False,'performance_improvement_claimed':False,'source_or_refs_or_stage_mutated':False,'network_calls':0,'git_read_only_commands':5},
 'remaining':'Any use of this new source as a final candidate requires its own exact-source original gates. The response-boundary correction is stricter acceptance, and the collector change is a test correction for existing cleanup behavior; neither is evidence that the separate W1/PQ deadline failures have been resolved.'
}
rp=js('review.json',review)
md='''# 5df7 deadline and collector review\n\nStatic review found no blocker in the two assigned changes. The new public_v2 completion check uses the original caller deadline after canonical response and signature verification. It adds a refusal for a valid response that completes late; it does not extend a phase, skip verification, change a signed field, or change qualification flags. The original v2 default overall budget is 30 seconds; the new 2-second loopback control is not the separate hosted 4-second confirmation campaign.\n\nThe collector production source is unchanged from R1. Its closed, never-released exec gate exits with 125 on EOF, while the original bounded cleanup can still send SIGKILL if that root has not completed by the unchanged escalation boundary. The amended existing test accepts only those two actual raw outcomes and additionally binds launch error, birth identity, waitid/wait4 status, no exec/no TERM, and the collector's sent KILL event between cleanup and reap. Wrapper 125 and both failure booleans remain required. All 16 method names remain; the other 15 methods and the two deterministic signal-ordering controls are source/AST identical. The original exact 16, OK, and no-skips CI gate is unchanged.\n\nBoth changed files were derived from immutable R1 blobs and the pinned complete GitHub compare patches, with every hunk checked. Their computed Git blob identities exactly match the compare response. They are explicitly derived source copies, not a new server whole-blob download. The production collector and CI shell were read as fixed R1 Git blobs. No target helpers, tests, build, probes, network calls, source/index/ref/stage mutations were performed.\n\nThis review does not claim either new test passed, either collector scheduling branch occurred, or the hosted W1/PQ deadline failures are fixed. Existing failed evidence remains unchanged. Exact identities and source line references are in review.json and static-continuity.json.\n'''
put('README.md',md.encode())
files=[]
for p in sorted(E.rglob('*')):
 if p.is_file():
  raw=read(p);files.append({'path':str(p.relative_to(E)),'bytes':len(raw),'sha256':sha(raw)})
ip=js('EVIDENCE_INDEX.json',{'schema':'trnm-static-source-review-files-v1','root':str(E),'file_count':len(files),'total_bytes':sum(x['bytes'] for x in files),'files':files,'index_excludes_itself':True})
print(json.dumps({'review':rp,'proof':pp,'index':ip,'files_excluding_index':len(files),'bytes_excluding_index':sum(x['bytes'] for x in files),'old_rust_tests':len(oldnames),'new_rust_tests':len(newnames),'python_controls':16,'other15_source_AST_same':True,'tests_executed':False},sort_keys=True))
