import datetime,hashlib,json,os,pathlib,stat,sys
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1")
O=E/"final-review-v1";O.mkdir(mode=0o700)
SHA=lambda b:hashlib.sha256(b).hexdigest()
def put(p,b):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(b)
def jb(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()
def ident(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def stable(p,cap=64*1024*1024):
 if p.resolve(strict=True)!=p:raise ValueError("noncanonical file")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  a=os.fstat(f.fileno())
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>cap:raise ValueError("file boundary")
  b=f.read(cap+1);z=os.fstat(f.fileno())
 if len(b)!=a.st_size or ident(a)!=ident(z) or ident(a)!=ident(p.lstat()):raise ValueError("unstable file")
 return b,{"path":str(p),"bytes":len(b),"sha256":SHA(b)}
def parsed(p):
 b,pin=stable(p);return json.loads(b),pin
def httpjson(p):
 b,pin=stable(p);sep=b"\r\n\r\n" if b"\r\n\r\n" in b else b"\n\n";h,body=b.split(sep,1)
 if not h.splitlines()[0].endswith(b"200 OK"):raise ValueError("HTTP status")
 return json.loads(body),pin
put(O/"seal-review.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
for name,value in json.loads(sys.argv[1]):put(O/"tool-originals"/name,jb(value))
put(O/"local-orchestration-errors.json",jb({"scope":"Two functions.exec JavaScript parse failures before any target invocation","errors":["SyntaxError: Unexpected token '.'","SyntaxError: Unexpected token '.'"],"cause":"unescaped dollar-brace workflow expressions in an outer JavaScript template; no target producer was started by either failed call","target_or_network_or_ci_action":False,"old_raw_evidence_unchanged":True}))
meta,meta_pin=parsed(E/"R1-W1-complete-artifacts-v1/metadata-summary.json")
down,down_pin=parsed(E/"R1-W1-complete-artifacts-v1/download-summary.json")
verified,verified_pin=parsed(E/"R1-W1-inner-originals-v1/summary.json")
if not(meta["all_valid"] and down["all_complete"] and verified["complete"]):raise ValueError("incomplete artifact")
results=[]
for item in verified["results"]:
 aid=item["artifact_id"];D=E/"R1-W1-inner-originals-v1"/str(aid)
 index,index_pin=parsed(E/"R1-W1-inner-originals-v1"/(str(aid)+"-index.json"))
 rows={x["path"]:x for x in index["files"]}
 mf,mf_pin=parsed(D/"fresh-service/manifest.json")
 source_raw,source_pin=stable(D/"source.json");after_raw,after_pin=stable(D/"source-after.json")
 if source_raw!=after_raw:raise ValueError("source beforeafter")
 source=json.loads(source_raw)
 if source["candidate"]!="2a86462a1ab20c68151719ba4635e3c294391e64" or source["tested_tree"]!="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4" or source["kind"]!=item["kind"]:raise ValueError("artifact source")
 if mf["source_before"]!=mf["source_after"] or mf["source_before"]["commit"]!=source["tested_commit"] or mf["source_before"]["tree"]!=source["tested_tree"]:raise ValueError("manifest source")
 if mf["requested_window_ns"]!=4000000000 or mf["attack_workers"]!=16 or not mf["execution_finished"]:raise ValueError("fixture boundary")
 if mf["binary_sha256_before"]!=mf["binary_sha256_after"] or mf["binary_sha256_before"]!=rows["fresh-service/public_v3_from_zero"]["sha256"]:raise ValueError("binary")
 for path,h in mf["files"].items():
  if rows["fresh-service/"+path]["sha256"]!=h:raise ValueError("declared original file mismatch")
 runs=[]
 for run in mf["runs"]:
  rp="fresh-service/"+run["report_path"];lp="fresh-service/"+run["process"]["log"]
  raw,pin=stable(D/lp)
  if SHA(raw)!=run["log_sha256"]:raise ValueError("log pin")
  text=raw.decode()
  runs.append({"selector":run["name"],"process":run["process"],"passed":run["passed"],"failure":run["failure"],"failure_diagnostic":run["failure_diagnostic"],"original_log":pin,"raw_log_text":text,"report_original_zip_member":{k:rows[rp][k] for k in ["path","bytes","sha256","crc32"]}})
 results.append({"artifact_id":aid,"job_id":item["job_id"],"source_kind":item["kind"],"archive":item["zip"],"member_index":index_pin,"all57_crc_sha_verified":index["file_count"]==57 and index["crc_all_verified"] and index["sha256_all_members_verified"],"manifest":mf_pin,"all_declared_manifest_file_hashes_match":True,"source_before":source_pin,"source_after":after_pin,"source":source,"inner_manifest_source":mf["source_before"],"inner_source_kind_note":"The inner verifier identifies its actual checked-out commit as kind head; the outer source record retains head/prospective-merge distinction. Actual tested commit and tree agree.","source_recompiled":mf["source_recompiled"],"binary_sha256":mf["binary_sha256_before"],"requested_window_ns":mf["requested_window_ns"],"attack_workers":mf["attack_workers"],"runs":runs,"flags":{k:mf[k] for k in ["all_named_tests_passed","passed","execution_finished","independent_wan_accepted","work_hardness_accepted","production_activation"]}})
old,old_pin=httpjson(E/"exact-old-run-and-new-failures-v1/N2-run-43588788281-metadata.stdout")
oldjobs,oldjobs_pin=httpjson(E/"dependent-and-controls-v1/N2-required-43588788281-jobs-page-001.stdout")
r1_w,workflow_pin=stable(E/"R1-required-workflow.stdout")
n2_w,n2_workflow_pin=stable(E/"exact-old-run-and-new-failures-v1/N2-required-workflow.stdout")
if r1_w!=n2_w:raise ValueError("same workflow evidence")
group="portable-"+chr(36)+"{{ github.workflow }}-"+chr(36)+"{{ github.ref }}"
if group not in r1_w.decode() or "cancel-in-progress: false" not in r1_w.decode():raise ValueError("concurrency evidence")
ready4,r4pin=parsed(pathlib.Path("/private/tmp/chain-consolidation-20261114-root/R1-required-ci-progress-v1-ready-004/summary.json"))
aftercancel,acpin=parsed(pathlib.Path("/private/tmp/chain-consolidation-20261114-root/R1-old-required-after-cancel-ready-004/summary.json"))
if r4pin["sha256"]!="558bd56aabc31c5174f104c6a174069a53b4a459434170bfcc28fa29aa6a3d96" or acpin["sha256"]!="82f2c8798d1a7b30bfc12330f93700234b664a95547180650c45c0ae7de16444":raise ValueError("followup observation pins")
summary={
"schema":"trnm-R1-required-queue-and-fresh-service-failure-review-v1",
"source":{"head":"2a86462a1ab20c68151719ba4635e3c294391e64","tree":"5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"},
"scope":"Read-only existing source/API/log/artifact evidence; no native/test rerun or source/stage/Git/remote mutation",
"queue":{"required_run":43604217412,"workflow":workflow_pin,"identical_N2_workflow":n2_workflow_pin,"group_expression":group,"cancel_in_progress":False,"old_source_run":43588788281,"old_source_head":old["head_sha"],"old_metadata":old_pin,"old_jobs":oldjobs_pin,"old_jobs_complete":oldjobs["total_count"]==len(oldjobs["jobs"]),"old_nonterminal_ids":[j["id"] for j in oldjobs["jobs"] if j["status"]!="completed"],"interpretation_at_original_snapshot":"Old N2 was the observed active workflow for the same PR group; R1 pending with zero jobs was workflow concurrency waiting, not an optional job dependency.","newer_external_observations":[r4pin,acpin],"newer_reported_facts":"ready004 at14:42:27Z R1 queued with18jobs; old N2 observed14:43:01Z completed/cancelled. These are separately captured observations after root's cancellation, not actions by this review.","latest_status_not_polled":True},
"optional_boundary":{"initial_four":"Historical retained-failure and three historical-subject budget controls; their names alone do not prove expected success or a current runtime regression.","new_two":"Actual R1 fresh-service head/prospective jobs from run43604217632, attempt1; substantive finite-business-target failure retained.","not_promoted_to_required_gate":True,"cannot_replace_required_protocol_five_selectors":True},
"artifact_inputs":{"metadata":meta_pin,"download":down_pin,"verification":verified_pin},
"results":results,
"conclusion":{"original":"Both Rust original selectors exit0 with1pass, but finite_target_met=false and the report validator rejects CONFIRMATION_TARGET.","fresh":"Both explicit fresh selectors exit101 at fresh_challenge.rs:244:5, asserting original four-second/six-depth business target; runner retains FRESH_NATIVE_TEST_FAILED.","last_replay":"All four retained failure diagnostics end with PUBLIC_REQUEST_DEADLINE and replay_accepted=false.","source_or_build_failure":False,"host_controller_cause":"Complete outer logs retain failure=null and final_host_errors=[]; systemd child exit1 follows actual inner failures.","four_second_budget_and_six_depth_not_relaxed":True,"sixteen_workers_not_relaxed":True,"P1_cache_present_not_performance_qualification":True,"rootcause_below_deadline":"Precise scheduling/CPU/verification-cost cause is not established by these manifests alone; architecture independently reviews original report phase data."},
"merge_condition":{"current_M3":"CLEAN required","risk":"Official UNSTABLE means mergeable with nonpassing commit status; CLEAN may be broader than protection-required checks when optional checks fail. No adapter or policy changed; actual required results/state still govern.","official_sources":["https://docs.github.com/en/graphql/reference/pulls#mergestatestatus","https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches"]},
"preserved_observational_failures":["First raw job-log downloads ended network timeout and are preserved separately; subsequent explicit bounded retrieval obtained complete logs.","Hepta temporarily marked the unique ZIP download session lost/target_reboot while boottime seconds and original processes continued; original lost observation and readonly reconciliation retained. Same session later naturally closed exit0; no second ZIP request.","Two local orchestration parse errors occurred before any target invocation and are recorded separately, with no CI effect."],
"no_actions":{"test_or_native_execution":True,"source_or_workflow_change":True,"budget_change":True,"Git_or_stage_write":True,"cancel_dispatch_rerun":True}}
put(O/"review.json",jb(summary))
readme="""# R1 queue and fresh-service failure evidence

The original queue diagnosis is tied to the dated ready002/003 observations. R1 and old N2 use byte-identical required workflows with the same PR concurrency group and cancel-in-progress false. Old N2 still had four Rust shards. The independent ready004 records later show R1 queued with 18 jobs and old N2 cancelled/completed; this review did not perform the cancellation or repoll the queue.

Both current R1 W1 fresh-service artifacts are complete official downloads with API size/digest and original upload-log digest agreement. Every one of the 57 members in each ZIP was read to EOF, CRC and SHA256 verified. Source-before and source-after bytes agree. The prospective commit has the exact R1 tree. The inner verifier's kind=head describes its checked-out commit; the outer source records preserve the prospective-merge relationship.

The two original Rust controls each report one test passed, while their retained business reports say finite_target_met=false and the reader returns CONFIRMATION_TARGET. The two fresh controls fail at fresh_challenge.rs:244:5 with the original four-second/six-depth assertion and native exit101; the runner reports FRESH_NATIVE_TEST_FAILED. All four last-replay diagnostics retain PUBLIC_REQUEST_DEADLINE. The four-second/16-worker parameters and original Host limits are unchanged. Build/source/Host controller checks do not explain away this measured business failure.

These two W1 jobs are separate from the required protocol five-control lane. This record neither adds a new merge-policy requirement nor grants performance/production qualification. It does show a concrete current-source failure deserving diagnosis. The P1 immutable prefix cache is present; no quantified benefit or successful four-second remedy follows from that fact.

Large reports, SQLite files and the compiled binary are retained once inside the two complete ZIPs; no artifact executable was run. Selected bounded logs/JSON are extracted verbatim. Initial log-network failures, temporary PTY lost observation and the same-session natural exit0 are preserved.

No source, workflow, limits, PR, protection, Git refs, or frozen stage were changed.
"""
put(O/"README.md",readme.encode())
entries=[];total=0
for base,dirs,files in os.walk(E,followlinks=False):
 for d in dirs:
  p=pathlib.Path(base)/d
  if p.is_symlink() or not p.is_dir():raise ValueError("evidence directory type")
 for name in sorted(files):
  p=pathlib.Path(base)/name
  raw,pin=stable(p)
  total+=len(raw)
  if total>64*1024*1024:raise ValueError("evidence total cap")
  entries.append({"path":str(p.relative_to(E)),"bytes":len(raw),"sha256":pin["sha256"],"origin":{"host":"mac","path":str(p)}})
entries.sort(key=lambda x:x["path"])
index={"schema":"trnm-closed-readonly-review-evidence-index-v1","root":str(E),"file_count":len(entries),"total_bytes":total,"files":entries,"index_and_seal_excluded":True,"complete_original_ZIP_members":114}
put(O/"EVIDENCE_INDEX.json",jb(index));_,ip=stable(O/"EVIDENCE_INDEX.json");_,rp=stable(O/"review.json")
seal={"schema":"trnm-closed-review-seal-v1","review":rp,"index":ip,"selected_files":len(entries),"selected_bytes":total,"all_selected_source_bytes_hash_verified":True,"stage_written":False,"no_inflight_download":True}
put(O/"seal.json",jb(seal));_,sp=stable(O/"seal.json")
print(json.dumps({"review":rp,"index":ip,"seal":sp,"files":len(entries),"bytes":total,"complete":True},sort_keys=True))
