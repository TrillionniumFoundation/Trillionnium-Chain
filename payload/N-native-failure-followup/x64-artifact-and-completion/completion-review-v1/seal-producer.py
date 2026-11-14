import os,sys,pathlib,stat,json,hashlib,datetime,re
B=pathlib.Path("/private/tmp/chain-prci-N-x64-native-artifact-14109658844-20261114-v1")
O=B/"completion-review-v1";O.mkdir(mode=0o700)
def sig(x):return [x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
def rd(p,limit=24*1024*1024):
 p=pathlib.Path(p);assert p.is_absolute() and ".."not in p.parts
 d=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for q in p.parts[1:-1]:
   nd=os.open(q,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=d);os.close(d);d=nd
  fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=d)
 finally:os.close(d)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=limit
  with os.fdopen(fd,"rb",closefd=False)as f:b=f.read(a.st_size+1)
  assert len(b)==a.st_size and sig(a)==sig(os.fstat(fd))
  return b,sig(a)
 finally:os.close(fd)
def js(x):return(json.dumps(x,indent=2)+"\n").encode()
def save(p,b):
 p=pathlib.Path(p);p.parent.mkdir(parents=True,exist_ok=True);assert p.parent.resolve(strict=True)==p.parent
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 a,_=rd(p);assert a==b
 return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
def pin(p,n,h):
 b,v=rd(p);assert len(b)==n and hashlib.sha256(b).hexdigest()==h,str(p)
 return b,v
inp,iv=pin(B/"completion-seal-inputs-v1.json",333887,"c12c465e4fdf9300efa9e3424cb7afd53146ab67bb20c511e664eab9d2cd7ec7");D=json.loads(inp)
meta=D["artifact"];assert meta["id"]==14109658844 and meta["workflow_run"]["id"]==43582713392 and meta["workflow_run"]["head_sha"]=="5a4b7fe8de1adce803184f262fd9f704ead1930c"
assert meta["size_in_bytes"]==9884207 and meta["digest"]=="sha256:10447497968910ffe69e51bd541f6dfe988293a86a2ab583120f3a25788c40b4" and meta["expired"]is False
created=[save(O/"seal-producer.py",sys.argv[1].encode())]
for op in D["operations"]:
 pages=op["reads"];assert pages and pages[0]["offset"]==0
 joined=b"";at=0
 for p in pages:
  assert p["offset"]==at and p["truncated_before_offset"]is False and p["text_is_lossy"]is False
  raw=bytes.fromhex(p["bytes_hex"]);assert len(raw)==p["next_offset"]-p["offset"] and hashlib.sha256(raw).hexdigest()==p["chunk_sha256"]
  assert raw.decode("utf-8")==p["text"];joined+=raw;at=p["next_offset"]
 last=pages[-1];assert at==last["available_end"] and last["output_complete"]is True and last["status"]["exit_code"]==0
 created.append(save(O/"operation-terminals"/(op["name"]+".json"),js(op)))
 created.append(save(O/"operation-terminals"/(op["name"]+".log"),joined))
zb,zv=pin(B/"N-cost-x64-14109658844.zip",9884207,"10447497968910ffe69e51bd541f6dfe988293a86a2ab583120f3a25788c40b4")
ib,iv2=pin(B/"ZIP_MEMBER_INDEX.json",47816,"989f6ec25dc46aae82ce6a418693a0bca1b69a50b25ccb77d7ddddc3ef3b9199")
zi=json.loads(ib);assert len(zi["files"])==161
mp=B/"selected-read-v1/originals/from-zero-native/manifest.json"
mb,mv=pin(mp,74003,"3362e60289fbf2268b0c9886f97a1b4958cbb095fbdf02c7349a986880ce0bf7");m=json.loads(mb)
src=json.loads(pin(B/"selected-read-v1/originals/source.json",423,"fc1b6e0213fbdd6e1f93ec879c138ec233cc3a4cf6aa08330df81041ef4304b6")[0])
assert m["source_before"]==m["source_after"] and m["source_before"]["tracked_source_identity"]==src
assert src["tested_commit"]=="5a4b7fe8de1adce803184f262fd9f704ead1930c" and src["tested_tree"]=="4bc5ade0813ba3172eeb0ad7425358469a1b1edd" and src["kind"]=="head" and src["prospective_merge"]is None
obs=m["confirmation_observation"];ph=obs["phases"];assert len(ph)==2
assert [(p["mode"],p["workers"],p["window_ns"])for p in ph]==[("attack-free-baseline",0,4000000000),("from-zero-pressure",16,4000000000)]
assert m["failures"]==["CONFIRMATION_TARGET"] and m["all_named_tests_passed"]is True and m["passed"]is False
assert m["terminal"]["native_execution_completed"]is True and m["terminal"]["finalization_completed"]is True and m["terminal"]["acceptance_passed"]is False
assert m["terminal"]["acceptance_stages"]["confirmation_report"]["error"]=="CONFIRMATION_TARGET"
assert obs["original_gate_validated"]is False and obs["original_gate_validation_error"]=="CONFIRMATION_TARGET"
assert obs["sha256"]=="defe805b3d8c7de0c60c89efbe6c70324a5267b03376cb110a799a36fe8566a5"
native=[]
for row in m["terminal"]["native_invocations"]:
 name=row["name"];base=B/"selected-read-v1/originals/from-zero-native"/name
 pb,_=rd(base/"process.json");p=json.loads(pb);out,_=rd(base/"stdout");err,_=rd(base/"stderr")
 assert p["exit_code"]==0 and p["timed_out"]is False and row["status"]=="returned"
 assert hashlib.sha256(out).hexdigest()==p["stdout_sha256"] and hashlib.sha256(err).hexdigest()==p["stderr_sha256"]
 assert re.search(rb"test result: ok\. 1 passed; 0 failed; 0 ignored;",out)
 native.append({"selector":name,"command":p["command"],"exit_code":p["exit_code"],"timed_out":p["timed_out"],"wall_ns":p["wall_ns"],"stdout_sha256":p["stdout_sha256"],"stderr_sha256":p["stderr_sha256"],"test_result":"1 passed; 0 failed; 0 ignored","business_acceptance_is_separate":True})
assert len(native)==5
phase_rows=[]
for i,p in enumerate(ph):
 phase_rows.append({"json_pointer":"/confirmation_observation/phases/"+str(i),"mode":p["mode"],"workers":p["workers"],"window_ns":p["window_ns"],"business":p["business"],"signed_submit_ack":p["signed_submit_ack"],"history_response":p["history_response"],"independent_page_replay":p["independent_page_replay"],"head_response":p["head_response"],"verification_errors":p["verification_errors"],"request_clock":p["request_clock"],"attacker_attempts":{k:p["attacker_attempts"][k]for k in ["scheduled_workers","observed_worker_records","recorded_attempts","submitted_client_calls_recorded","unknown_status_records","calls_with_complete_timing","calls_with_unknown_timing"]}})
assert ph[0]["business"]["reported_independently_confirmed_in_window"]==1 and ph[1]["business"]["reported_independently_confirmed_in_window"]==0
assert ph[0]["independent_page_replay"]["accepted_in_original_window"]==7
assert ph[1]["independent_page_replay"]["attempts"]==2 and ph[1]["independent_page_replay"]["accepted_in_original_window"]==1
old=D["existing_outer_findings"];oldraw,oldv=pin(old["path"],old["bytes"],old["sha256"])
facts={"schema":"trnm-N-x64-original-cost-failure-completion-v1","sealed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"status":"original_business_confirmation_failed","repository":"TrillionniumFoundation/Trillionnium-Chain","run_id":43582713392,"run_attempt":1,"job_id":132415017426,"job_arch":"x64","artifact":meta,"whole_zip_verified":True,"member_count":161,"all_members_crc_sha256_verified_by_completed_transport_receipt":True,"selected_original_member_count":17,"member_code_executed":False,"source":src,"source_before_equals_after":True,"manifest":{"path":str(mp),"bytes":len(mb),"sha256":hashlib.sha256(mb).hexdigest()},"original_failures":m["failures"],"named_native_children":native,"all_named_tests_passed":True,"all_native_children_returned_without_timeout":True,"business_confirmation_passed":False,"acceptance_terminal":m["terminal"],"phase_observations":phase_rows,"sequential_report_acceptance":{"service_report":"passed","sustained_report":"passed","confirmation_report":"failed: CONFIRMATION_TARGET"},"interpretation_scope":{"interpreted":"only original manifest, five native stdout/stderr/process records and source before/after","large_confirmation_report_bytes_hashed_but_not_semantically_read":True,"raw_confirmation_report_sha256":obs["sha256"],"no_claim_about_microarchitectural_cause_or_lock_or_cpu_scheduler":True,"no_extrapolation_to_M8_or_other_architecture_or_prospective_protocol":True,"five_native_test_passes_do_not_imply_business_confirmation_pass":True,"one_fixed_observation_not_general_latency_capacity_qualification":True,"missing_all_worker_cpu_and_physical_network_and_disk_and_request_RSS_remain_unknown":True},"qualification":{"network_capacity_qualified":False,"tail_latency_qualified":False,"production_activation":False,"new_native_execution_performed":False,"hosted_qualification_from_this_review":False},"previous_outer_only_analysis":{"path":old["path"],"sha256":old["sha256"],"preserved_byte_identically":True,"old_unknown_retained_as_original_time_and_scope":True,"superseded_only_for_inner_failure_by_this_new_artifact_overlay":True}}
created.append(save(O/"findings.json",js(facts)))
review="""# N x64 cost failure: completed original-artifact review

## Result

The original x64 job 132415017426 in run 43582713392, attempt 1, failed its **business confirmation acceptance** with CONFIRMATION_TARGET. All five native test child processes returned exit 0 without timeout, and each original stdout reports one passed test. The confirmation test also reports finite_target_met=false; the original runner subsequently rejects its report. Test-method success and business-target success are separate observations.

The exact tested source is head 5a4b7fe8de1adce803184f262fd9f704ead1930c, tree 4bc5ade0813ba3172eeb0ad7425358469a1b1edd. The manifest's complete source-before and source-after records are equal and match the standalone source identity. This is the N head job, not a prospective merge or M8.

## Original conditions and observed boundary

Both original phases retain a 4,000,000,000 ns window and require one signed business transaction. The baseline uses zero attack workers; pressure uses 16, with all 16 worker records present.

| Original observation | Baseline | Pressure |
|---|---:|---:|
| Independently confirmed business transactions | 1 of 1 | 0 of 1 |
| Successful signed-submit ACKs | 7 of 7 | 7 of 7 |
| Successful History responses | 7 of 7 | 2 of 2 |
| Accepted independent replays | 7 of 7 | 1 of 2 |
| Verification errors | none | PUBLIC_REQUEST_DEADLINE |
| Finite business target | true | false |

Baseline business confirmation latency is 3.192652146 seconds. Pressure business begins 90.856880 ms after the original phase starts, leaving 3.909143120 seconds; it did not begin after the original window expired. The accepted pressure replay reports 1.690997151 seconds wall time. The failed or late replay reports 0.600477191 seconds wall time. The manifest does not supply the detailed per-call trace needed to attribute that delay to a lock, repeated computation, CPU scheduling, Host checks, or another micro-level cause.

The original service and sustained-report acceptance stages passed. The confirmation-report stage failed. Its retained bytes match the bytes examined by the original validator. The runner's terminal explicitly distinguishes completed child invocations from successful business acceptance; its legacy execution_finished=false is not evidence of a still-running child.

## Custody and limits

Artifact 14109658844 is exactly 9,884,207 bytes with SHA-256 10447497968910ffe69e51bd541f6dfe988293a86a2ab583120f3a25788c40b4, matching the official artifact metadata and original job upload record. Its 161 members passed the bounded safe-name, duplicate, symlink, size, CRC and SHA checks. The original ZIP is unchanged. Only the approved 17 manifest/source/process/stdout/stderr members were extracted and interpreted. Other members, including the large confirmation report and ELF, were hashed for custody but not executed or semantically analyzed.

The outer-log-only UNKNOWN findings remain byte-identical. This separate completion overlay adds the inner failure now directly evidenced by the approved artifact. No rerun, source edit, deadline change, worker change, dispatch, cancellation, or PR change was made. This N observation establishes no M8 failure, no general throughput/tail-latency qualification, and no production activation.
"""
created.append(save(O/"review.md",review.encode()))
pin(mp,74003,"3362e60289fbf2268b0c9886f97a1b4958cbb095fbdf02c7349a986880ce0bf7");pin(pathlib.Path(old["path"]),old["bytes"],old["sha256"])
allrows=[]
for root,ds,fs in os.walk(B,followlinks=False):
 for name in ds:
  st=(pathlib.Path(root)/name).lstat();assert stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode)
 for name in sorted(fs):
  p=pathlib.Path(root)/name;raw,version=rd(p);allrows.append({"path":str(p.relative_to(B)),"source_path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"version":version})
idx=save(O/"EVIDENCE_INDEX.json",js({"schema":"trnm-N-x64-completed-artifact-review-index-v1","root":str(B),"files":sorted(allrows,key=lambda r:r["path"]),"index_and_seal_self_excluded":True,"all_are_closed_readonly_observations":True}))
seal={"schema":"trnm-N-x64-completion-seal-v1","status":"sealed","sealed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"indexed_files":len(allrows),"indexed_bytes":sum(r["bytes"]for r in allrows),"index":idx,"findings":next(r for r in created if r["path"].endswith("/findings.json")),"review":next(r for r in created if r["path"].endswith("/review.md")),"whole_zip_verified":True,"business_confirmation_passed":False,"no_artifact_code_executed":True,"original_outer_unknown_preserved":True,"stage_changes_by_this_producer":False}
sm=save(O/"seal-summary.json",js(seal))
print(json.dumps({"summary":sm,"index":idx,"findings":seal["findings"],"review":seal["review"],"indexed_files":len(allrows),"indexed_bytes":seal["indexed_bytes"],"status":"sealed","no_stage_writes":True}),flush=True)
