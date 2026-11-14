import datetime,hashlib,json,os,pathlib,re,stat,sys
S=json.loads(sys.argv[1]);BASE=pathlib.Path(S["base"]);OUT=BASE/"outer-review-v1"
HEAD="5df7ae6f482157c5f7fdcbcd52222117a965053f";TREE="6be4940d38cc88782657f2684cbefe48866f8b9f"
def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def ver(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
versions={}
def read(pin):
 p=pathlib.Path(pin["path"]);need(p.resolve(strict=True)==p,"canonical input")
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW),"rb") as f:
  a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_nlink==1,"regular single link")
  b=f.read();z=os.fstat(f.fileno())
 need(ver(a)==ver(z)==ver(p.lstat()),"changed input")
 need(len(b)==pin["bytes"] and sha(b)==pin["sha256"],"pin mismatch")
 versions[str(p)]=ver(a);return b
acq=json.loads(read(S["summary"]));idx=json.loads(read(S["index"]))
for p in idx["files"]:read(p)
need(acq["status"]=="ACQUIRED" and acq["head"]==HEAD and acq["run_id"]==43621754143,"wrong acquisition")
job=acq["jobs"][0];lp=next(r["stdout"] for r in job["steps"] if r["label"].endswith("-original-log"))
raw=read(lp);lines=raw.decode().splitlines()
clean=[re.sub(r"^\d{4}-\d{2}-\d{2}T[0-9:.]+Z ?","",l) for l in lines]
objects=[]
for i,line in enumerate(clean):
 if not line.lstrip().startswith("{"):continue
 try:
  tail="\n".join(clean[i:i+64]);obj,end=json.JSONDecoder().raw_decode(tail.lstrip())
 except (json.JSONDecodeError,ValueError):continue
 if isinstance(obj,dict) and obj.get("schema") in ("trnm-ci-source-v1","trnm-ci-original-public-host-controller-v2"):
  objects.append({"start_line":i+1,"end_line":i+1+tail[:end].count("\n"),"object":obj})
sources=[r for r in objects if r["object"]["schema"]=="trnm-ci-source-v1"]
cs=[r for r in objects if r["object"]["schema"]=="trnm-ci-original-public-host-controller-v2"]
need(len(sources)==2 and len(cs)==1,"exact outer source/controller objects not unique")
controller=cs[0]["object"];before=sources[0]["object"];after=sources[1]["object"]
need(before==after and before["tested_commit"]==HEAD and before["tested_tree"]==TREE and before["tracked_worktree_verified"] is True,"source identity mismatch")
prep=controller["preparation"]
need(prep["source_before"]==prep["source_after"],"preparation source drift")
need(prep["source_before"]["tracked_source_identity"]==before,"nested source differs")
pages=[json.loads(p["content"][0]["text"]) for p in S["pages"]]
cursor=0;chunks=[]
for p in pages:
 b=bytes.fromhex(p["bytes_hex"]);need(sha(b)==p["chunk_sha256"],"terminal chunk sha")
 need(p["next_offset"]==cursor+len(b),"terminal pages not contiguous");cursor=p["next_offset"];chunks.append(b)
term=pages[-1];need(term["status"]["state"]=="exited" and term["status"]["exit_code"]==0 and term["status"]["output_complete"] is True and cursor==term["available_end"]==1867,"incomplete actual terminal")
terminalraw=b"".join(chunks);last=json.loads(terminalraw.decode().splitlines()[-1])
need(last["summary"]==S["summary"] and last["index"]==S["index"],"actual terminal pins mismatch")
os.umask(0o077);OUT.mkdir(mode=0o700,exist_ok=False);pins=[]
def save(name,value):
 b=value if isinstance(value,bytes) else (json.dumps(value,indent=2,sort_keys=True)+"\n").encode();p=OUT/name
 with p.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
 q={"path":str(p),"bytes":len(b),"sha256":sha(b)};read(q);pins.append(q);return q
save("producer.py",sys.argv[2].encode())
save("actual-launch-tool-response.json",S["launch"])
save("actual-pty-read-tool-responses.json",S["pages"])
tp=save("actual-terminal-pages.json",{"schema":"trnm-actual-pty-pages-v1","session_id":S["session_id"],"terminal":term,"pages":pages})
save("actual-terminal.log",terminalraw)
controllerpin=save("controller-parsed-from-log.json",controller)
sourcepin=save("source-identities-parsed-from-log.json",sources)
selected=set()
for r in objects:
 selected.update(range(r["start_line"],r["end_line"]+1))
selected.update(i+1 for i,l in enumerate(lines) if "run_from_zero_host.py -- " in l or "Process completed with exit code 1." in l)
ep=save("exact-numbered-log-excerpts.json",{"original_log":lp,"numbering":"one based original 1437-line log","lines":[{"line":i,"text":lines[i-1]} for i in sorted(selected)]})
artifact=acq["artifact_candidates"]
need(len(artifact)==1 and artifact[0]["id"]==14124189121 and artifact[0]["workflow_run"]["head_sha"]==HEAD,"wrong artifact candidate")
facts={
 "schema":"trnm-H5DF-cross-cost-x64-original-outer-review-v1","status":"CLOSED_OUTER_FAILURE_INNER_UNKNOWN",
 "created_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"acquisition_interval":[acq["started_at"],acq["finished_at"]],
 "run_id":43621754143,"attempt":1,"job_id":132528768933,"job_name":"cross-arch-cost (x64)",
 "job_url":job["observed_job"]["html_url"],"source_head":HEAD,"source_tree":TREE,
 "all_three_GETs_exit_zero":True,"original_log":lp,"original_log_lines":len(lines),
 "source_top_level_before_after_equal":True,"source_objects":sourcepin,
 "preparation_source_before_after_equal":True,"tracked_entries":before["tracked_entries"],"tracked_bytes":before["tracked_bytes"],
 "outer_command_lines":[i+1 for i,l in enumerate(lines) if "run_from_zero_host.py -- " in l],
 "actual_native_runner_argv":controller["command_argv"],"controller_log_line":cs[0]["start_line"],
 "observed_controller_schema":controller["schema"],"observed_systemd_run_exit":controller["systemd_run_exit"],
 "observed_outer_passed":controller["passed"],"observed_outer_failure":controller["failure"],"final_host_errors":controller["final_host_errors"],
 "native_build":{"argv":prep["process"]["command"],"exit_code":prep["process"]["exit_code"],"timed_out":prep["process"]["timed_out"],"timeout_scope":"unchanged original producer build contract"},
 "format_exit_code":prep["format_preparation"]["process"]["exit_code"],
 "recorded_binary_sha256":prep["binary_sha256"],"binary_not_downloaded_or_verified":True,
 "original_final_parent_limits":controller["final_parent_lease"]["parent_identity"]["limits"],
 "preparation_native_tests_executed_flag":prep["native_tests_executed"],
 "preparation_flag_does_not_prove_no_later_native_tests":True,
 "exact_inner_failure":"UNKNOWN","four_second_and_sixteen_worker_actual_inner_run_verified":False,
 "old_R1_cause_inherited":False,"artifact_candidate":artifact[0],"artifact_downloaded":False,
 "smallest_next_diagnostic_scope":"Own artifact metadata plus bounded positive-range ZIP tail/CD and selected native manifest/source/controller/confirmation report and necessary five selector process/stdout; no ELF/SQLite/full-ZIP requirement.",
 "actual_terminal":tp,"original_acquisition":S["summary"],"exact_excerpts":ep,"controller":controllerpin,
 "no_additional_GETs_in_this_review":True,"new_native_tests_or_CI_actions":False,
 "source_refs_stage_changes":False,"qualification":False}
rp=save("review.json",facts)
for p,v in versions.items():need(ver(pathlib.Path(p).lstat())==v,"fenced source changed")
ip=save("EVIDENCE_INDEX.json",{"schema":"trnm-H5DF-cross-cost-outer-review-index-v1","files":list(pins),"original_acquisition_index":S["index"],"self_excluded":True})
sp=save("seal-summary.json",{"status":"CLOSED","review":rp,"index":ip,"actual_acquisition_session":S["session_id"],"originals_unchanged":True,"no_retries":True,"qualification":False})
print(json.dumps({"status":"CLOSED","review":rp,"index":ip,"seal":sp,"controller":controllerpin,"sources":sourcepin,"excerpts":ep},sort_keys=True))
