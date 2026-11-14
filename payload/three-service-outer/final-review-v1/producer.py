import os,stat,json,re,hashlib,sys,datetime
from pathlib import Path
D=Path("/private/tmp/chain-prci-H5DF-service-model-original-logs-20261114-v1")
E=D/"final-review-v1"
H="5df7ae6f482157c5f7fdcbcd52222117a965053f"
T="6be4940d38cc88782657f2684cbefe48866f8b9f"
P="a590178fa1ba11fc1419ea60de1f7f5633a70cfd"
B="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
def sha(r):return hashlib.sha256(r).hexdigest()
def fp(s):return(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def stable(pin):
 p=Path(pin["path"]);ls=p.lstat()
 assert stat.S_ISREG(ls.st_mode)and ls.st_nlink==1
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);chunks=[]
  while True:
   r=os.read(fd,1048576)
   if not r:break
   chunks.append(r)
  z=b"".join(chunks);b=os.fstat(fd)
 finally:os.close(fd)
 assert fp(ls)==fp(a)==fp(b)==fp(p.lstat()) and len(z)==pin["bytes"]and sha(z)==pin["sha256"]
 return z
def pin(p):
 r=p.read_bytes();return{"path":str(p),"bytes":len(r),"sha256":sha(r)}
def put(name,raw):
 p=E/name
 with p.open("xb")as f:f.write(raw)
 info=pin(p);assert stable(info)==raw
 return info
def dump(v):return(json.dumps(v,indent=2,sort_keys=True,ensure_ascii=False)+"\n").encode()
assert sys.flags.optimize==0
acqpin={"path":str(D/"acquisition-summary.json"),"bytes":42449,"sha256":"fd73d1a0089e0f132964f23a57b83dd0a89f7d5c1197a165b8117c17520bd262"}
ixpin={"path":str(D/"EVIDENCE_INDEX.json"),"bytes":5222,"sha256":"4107d030713ea4b18e24c451cac31aa71eb78afc6306e58ec12cf2bba6a3e654"}
acq=json.loads(stable(acqpin));oldindex=json.loads(stable(ixpin))
assert acq["status"]=="ACQUIRED"and acq["actual_GETs"]==6 and acq["errors"]==[]
originals={x["path"]:stable(x)for x in oldindex["files"]}
terminal=json.loads(sys.argv[1]);end=terminal["terminal"]
assert terminal["session_id"]==end["session_id"]and end["status"]["state"]=="exited"and end["status"]["exit_code"]==0 and end["output_complete"]is True
off=0;allout=b""
for page in terminal["pages"]:
 z=bytes.fromhex(page["bytes_hex"])
 assert page["offset"]==off and page["next_offset"]==off+len(z)and sha(z)==page["chunk_sha256"]
 assert page["session_id"]==terminal["session_id"]
 allout+=z;off=page["next_offset"]
assert off==end["available_end"]==end["status"]["bytes_seen"]==end["status"]["bytes_stored"]==1781
E.mkdir(mode=0o700)
put("producer.py",Path(__file__).read_bytes())if Path(__file__).parent!=E else None
terminalpin=put("acquisition-actual-terminal.json",dump(terminal))
terminalrawpin=put("acquisition-actual-terminal.log",allout)
rows=[];excerpt=[];derived=[]
for job in acq["jobs"]:
 jid=job["job_id"];meta=job["observed_job"]
 steps=job["steps"]
 assert len(steps)==2 and all(x["complete_transport"]and x["exit"]==0 for x in steps)
 raw=originals[steps[1]["stdout"]["path"]];lines=raw.decode("utf-8").splitlines()
 clean=[re.sub(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z\s?","",x)for x in lines]
 sources=[];controllers=[]
 for i,s in enumerate(clean):
  if s=="{":
   for endline in range(i+1,min(len(clean),i+24)):
    if clean[endline]=="}":
     try:o=json.loads("\n".join(clean[i:endline+1]))
     except ValueError:break
     if o.get("schema")=="trnm-ci-source-v1":sources.append({"first_line":i+1,"last_line":endline+1,"value":o})
     break
  if s.startswith("{")and '"systemd_run_exit"'in s and '"command_argv"'in s:
   o=json.loads(s);controllers.append((i,o))
 assert len(sources)==2 and sources[0]["value"]==sources[1]["value"]
 src=sources[0]["value"]
 assert len(src)==11 and src["candidate"]==H and src["tested_tree"]==T and src["tracked_worktree_verified"]is True
 assert src["tracked_entries"]==41681 and src["tracked_bytes"]==3995072357 and src["tests_executed_by_identity_check"]is False
 prospect=jid==132528768001
 assert src["tested_commit"]==(P if prospect else H)
 assert src["kind"]==("prospective-merge"if prospect else"head")
 assert src["base"]==(B if prospect else None)and src["prospective_merge"]==(P if prospect else None)
 assert len(controllers)==1
 line,ctrl=controllers[0];prep=ctrl["preparation"]
 assert ctrl["schema"]=="trnm-ci-original-public-host-controller-v2"
 assert ctrl["passed"]is False and ctrl["systemd_run_exit"]==1 and ctrl["failure"]is None and ctrl["final_host_errors"]==[]
 assert prep["completed"]is True and prep["failure_type"]is None
 assert prep["process"]["exit_code"]==prep["format_preparation"]["process"]["exit_code"]==0
 pb=prep["source_before"]["tracked_source_identity"];pa=prep["source_after"]["tracked_source_identity"]
 assert pb==pa and pb["tested_commit"]==src["tested_commit"]and pb["tested_tree"]==src["tested_tree"]
 assert pb["kind"]=="head"and pb["candidate"]==src["tested_commit"]and pb["base"]is None and pb["prospective_merge"]is None
 failed=[x for x in meta["steps"]if x["conclusion"]=="failure"]
 assert len(failed)==1 and failed[0]["number"]==7 and failed[0]["name"]=="Execute original release from-zero controls"
 errors=[{"line":i+1,"text":v}for i,v in enumerate(lines)if "##[error]"in v]
 assert len(errors)==1 and "exit code 1."in errors[0]["text"]
 ctrlpin=put("job-"+str(jid)+"-controller-result.json",clean[line].encode()+b"\n")
 derived.append(ctrlpin)
 nrows=[(i,v)for i,v in enumerate(clean)if v.strip().startswith("name: priority-")]
 assert len(nrows)==1
 artifactname=nrows[0][1].split("name: ",1)[1].strip()
 dig=[(i,re.search(r"SHA256 digest of uploaded artifact zip is ([0-9a-f]{64})",v))for i,v in enumerate(clean)if"SHA256 digest of uploaded artifact zip is "in v]
 assert len(dig)==1 and dig[0][1]
 uploads=[(i,re.search(r"Final size is ([0-9]+) bytes\. Artifact ID is ([0-9]+)",v))for i,v in enumerate(clean)if"Final size is "in v]
 assert len(uploads)==1 and uploads[0][1]
 artifact={"name":artifactname,"id":int(uploads[0][1].group(2)),"bytes":int(uploads[0][1].group(1)),"sha256":dig[0][1].group(1),"origin":"original upload-action lines; not fresh artifact API","name_line":nrows[0][0]+1,"digest_line":dig[0][0]+1,"id_size_line":uploads[0][0]+1,"url":"https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43621753847/artifacts/"+uploads[0][1].group(2),"downloaded":False,"whole_zip_sha256_verified":False}
 tokens=["CONFIRMATION_TARGET","PUBLIC_REQUEST_DEADLINE","PQ_WITNESS_DEADLINE","test result: FAILED","error: test failed"]
 matches=[{"line":i+1,"token":t}for i,v in enumerate(clean)for t in tokens if t in v]
 assert matches==[]
 calls=[{"line":i+1,"text":lines[i]}for i,s in enumerate(clean)if"run_from_zero_host.py"in s]
 successful=[{"number":x["number"],"name":x["name"]}for x in meta["steps"]if x["conclusion"]=="success"and 6<=x["number"]<=15]
 paniclines=[i+1 for i,v in enumerate(clean)if"panicked at"in v]
 row={"job_id":jid,"name":meta["name"],"run_id":meta["run_id"],"run_attempt":meta["run_attempt"],"workflow_name":meta["workflow_name"],"metadata_head_sha":meta["head_sha"],"job_url":meta["html_url"],"status":meta["status"],"conclusion":meta["conclusion"],"required14_member":False,"metadata_raw":steps[0]["stdout"],"original_log":steps[1]["stdout"],"total_log_lines":len(lines),"failed_step":failed[0],"top_level_source_before_after":sources,"top_level_source_equal":True,"preparation_source_before_after_equal":True,"preparation_source":pb,"preparation_source_semantics":"kind=head describes the checked-out actual tested commit; top-level job source separately binds candidate/base/prospective","controller_original_json":ctrlpin,"controller_log_line":line+1,"outer_observations":{"systemd_run_exit":ctrl["systemd_run_exit"],"passed":ctrl["passed"],"failure":ctrl["failure"],"final_host_errors":ctrl["final_host_errors"],"cleanup":ctrl["cleanup"],"format_exit":prep["format_preparation"]["process"]["exit_code"],"build_exit":prep["process"]["exit_code"],"preparation_completed":prep["completed"],"preparation_failure_type":prep["failure_type"],"preparation_binary_sha256":prep["binary_sha256"],"binary_bytes_independently_acquired":False,"native_command_argv":ctrl["command_argv"]},"host_command_log_lines":calls,"error_lines":errors,"inner_failure_class":"UNKNOWN","native_manifest_acquired":False,"specific_native_error_tokens_searched":tokens,"specific_native_error_token_matches":matches,"other_successful_steps":successful,"later_panic_lines":paniclines,"later_panic_interpretation":"Panic text appears in later successful control steps and is not the sole failed release step; it is not promoted to a new failure cause","artifact_from_original_upload":artifact}
 rows.append(row)
 use=set()
 for sr in sources:use.update(range(sr["first_line"]-1,sr["last_line"]))
 use.update(x["line"]-1 for x in calls+errors)
 use.update([line,nrows[0][0],dig[0][0],uploads[0][0]])
 excerpt.append({"job_id":jid,"log":steps[1]["stdout"],"lines":[{"line":i+1,"text":lines[i]}for i in sorted(use)]})
facts={"schema":"trnm-H5DF-three-service-model-outer-cause-review-v1","sealed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"scope":"three original PoN priority acceptance service-model jobs, outside required14; metadata and complete outer logs only","status":"OUTER_FAILURE_CONFIRMED_INNER_UNKNOWN","acquisition_summary":acqpin,"acquisition_index":ixpin,"actual_terminal":terminalpin,"actual_terminal_raw":terminalrawpin,"actual_GET_count":6,"all_GET_exit_codes":[x["exit"]for j in acq["jobs"]for x in j["steps"]],"http_status_note":"gh transport completion was recorded; HTTP status headers were not captured and no HTTP 200 claim is inferred","observation_interval":{"started_at":acq["started_at"],"finished_at":acq["finished_at"],"elapsed_seconds":acq["elapsed_seconds"]},"source":{"candidate":H,"tree":T,"base":B,"prospective":P},"jobs":rows,"no_additional_network_for_analysis":True,"source_refs_stage_unchanged":True,"no_native_execution":True,"qualifications":False,"minimal_next_read_plan":{"status":"PROPOSED_NOT_EXECUTED","first_candidate_artifact":rows[0]["artifact_from_original_upload"],"purpose":"Read this job's own native failure manifest, then only evidence named by it if needed; no cause inheritance across jobs","initial_requests":"Fresh metadata, one exact positive tail range, central-directory range only if not wholly in that tail, and the exact local-header+compressed member range for from-zero-native/manifest.json if the actual CD contains it","bounds":{"initial_max_GETs":4,"initial_total_seconds":300,"initial_each_seconds":120,"selected_member_uncompressed_cap_bytes":4194304},"required_checks":"metadata exact run/head/name/size/digest against the original upload; range status 206 and exact Content-Range/length; central-directory safe names/duplicates/symlinks; selected record filename/size/CRC; ignored Range stops without whole-download fallback","not_downloaded":["ELF","SQLite","unrelated artifacts"],"scope_limit":"Selected-member CRC is not whole ZIP digest or all-member validation. Other two jobs stay inner UNKNOWN until their own manifest is acquired."}}
factpin=put("exact-outer-facts.json",dump(facts))
excpin=put("original-line-excerpts.json",dump(excerpt))
artifactpin=put("minimal-artifact-plan.json",dump(facts["minimal_next_read_plan"]))
readme="""# H5DF service-model failures: outer evidence only

The six authorized GET requests all completed in 71.043604 seconds. Each original job has one failed step: #7, Execute original release from-zero controls. The Host controller records successful formatting/build preparation, systemd_run_exit=1 and passed=false, with failure=null and final_host_errors=[].

The native failure cause remains UNKNOWN. These outer logs do not contain the native manifest or the searched confirmation/deadline/test-failure codes. No artifact was requested. Existing H5DF cross-cost or R1 failures are not used as causes for these three jobs. They are outside the fourteen required jobs.

Actual source is taken from each complete log. Both head jobs identify 5df7ae6f482157c5f7fdcbcd52222117a965053f. The ARM prospective job identifies a590178fa1ba11fc1419ea60de1f7f5633a70cfd, with H5DF candidate and dd6e1c3cbeacbdc532b0679297835b3a0aac78f0 base. All before/after records have tree 6be4940d38cc88782657f2684cbefe48866f8b9f, 41681 entries and 3995072357 bytes. Nested preparation records use kind=head for the actual checked-out commit; they are preserved separately from the top-level candidate/base/prospective source record.

Later debug pressure, CLI, service CPU/cancellation and model lifecycle steps succeeded. Panic text from those successful controls is not promoted to the earlier release failure. Exact step names/times, source records, command, original log line numbers and upload artifact identities are in exact-outer-facts.json and original-line-excerpts.json.

The proposed next acquisition is limited to the x64 job's own manifest via verified positive ranges, after fresh artifact metadata. It has NOT been executed. Neither that job nor either ARM job has an established inner failure class from this review.

No Git/source/ref/stage modifications, tests, CI actions or additional network calls were performed in the offline review. Existing acquisition-summary.json is unchanged, including its original pre-analysis actual_tested_source_verified=false value. This review adds evidence from the subsequently parsed original logs without rewriting that receipt.
"""
readmepin=put("README.md",readme.encode())
newpins=[pin(p)for p in sorted(E.iterdir())if p.is_file()]
fullrows=oldindex["files"]+[ixpin]+newpins
for q in fullrows:stable(q)
index=put("EVIDENCE_INDEX.json",dump({"schema":"trnm-H5DF-service-model-closed-review-index-v1","files":fullrows,"self_excluded":True,"bytes":sum(x["bytes"]for x in fullrows),"count":len(fullrows),"scope":"actual acquisition originals plus bounded offline projections; no artifact payload"}))
seal=put("seal-summary.json",dump({"schema":"trnm-H5DF-service-model-closed-review-seal-v1","status":facts["status"],"sealed_at":facts["sealed_at"],"facts":factpin,"excerpts":excpin,"minimal_plan":artifactpin,"index":index,"original_files_unchanged":True,"closed":True,"no_writer_remaining_after_exit":True}))
print(json.dumps({"facts":factpin,"excerpts":excpin,"readme":readmepin,"index":index,"seal":seal,"actual_terminal":terminalpin,"actual_terminal_raw":terminalrawpin,"jobs":[{"job_id":x["job_id"],"tested_commit":x["top_level_source_before_after"][0]["value"]["tested_commit"],"failed_step":x["failed_step"]["name"],"inner":x["inner_failure_class"],"artifact":x["artifact_from_original_upload"]}for x in rows]},sort_keys=True))
