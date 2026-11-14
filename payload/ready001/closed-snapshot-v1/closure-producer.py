import collections,datetime,hashlib,json,os,pathlib,stat,sys
S=json.loads(sys.argv[1])
BASE=pathlib.Path(S["base"]);OUT=BASE/"closed-snapshot-v1"
HEAD="5df7ae6f482157c5f7fdcbcd52222117a965053f"
TREE="6be4940d38cc88782657f2684cbefe48866f8b9f"
RUN=43621754143
def need(x,m):
    if not x:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def ver(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(pin):
    p=pathlib.Path(pin["path"]);need(p.resolve(strict=True)==p,"noncanonical input")
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW),"rb") as f:
        a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_nlink==1,"not regular single-link")
        b=f.read();z=os.fstat(f.fileno())
    need(ver(a)==ver(z)==ver(p.lstat()),"input version changed")
    need(len(b)==pin["bytes"] and sha(b)==pin["sha256"],"input pin differs")
    return b,ver(a)
original_versions={}
for label in ("summary","index","prior"):
    raw,v=read(S[label]);original_versions[S[label]["path"]]=v
    S[label+"_parsed"]=json.loads(raw)
summary=S["summary_parsed"];index=S["index_parsed"];prior=S["prior_parsed"]
need(summary["status"]=="OBSERVED" and summary["expected_candidate"]==HEAD and summary["expected_candidate_tree"]==TREE,"wrong new-head receipt")
need(prior["status"]=="DRIFT" and prior["expected_candidate"]=="2a86462a1ab20c68151719ba4635e3c294391e64","prior R1 history changed")
need(summary["metadata_pages_complete"] is True and len(summary["steps"])==6,"incomplete six-GET receipt")
need(all(s["exit"]==0 and s["timed_out"] is False and s["spawn_error"] is None for s in summary["steps"]),"GET not closed successfully")
original_pins=[]
for pin in index["files"]:
    need(pathlib.Path(pin["path"]).parent==BASE,"index outside source directory")
    raw,v=read(pin);original_versions[pin["path"]]=v;original_pins.append(pin)
runs=summary["required_runs"]["run_jobs"];need(len(runs)==1 and runs[0]["run_id"]==RUN,"unexpected run")
run=runs[0];need(run["observed_attempt"]==1 and run["metadata"]["head_sha"]==HEAD,"run identity differs")
jobraw,_=read(run["jobs"]);jobs=json.loads(jobraw)
checkraw,_=read(summary["latest_checks"]["normalized"]);checks=json.loads(checkraw)
current=[j for j in jobs if j["matches_observed_run_attempt"] is True]
need(len(current)==18 and all(j["head_sha"]==HEAD and j["run_id"]==RUN and j["run_attempt"]==1 for j in current),"job identity/count differs")
required=[]
for name in S["required_names"]:
    matches=[j for j in current if j["name"]==name];need(len(matches)<=1,"duplicate current named job")
    if not matches:
        required.append({"name":name,"job_id":None,"state":"absent","status":None,"conclusion":None,"source_scope":"prospective" if name.startswith("prospective") else "head"})
        continue
    j=matches[0]
    state="success" if j["status"]=="completed" and j["conclusion"]=="success" else "failure" if j["status"]=="completed" and j["conclusion"]=="failure" else "running" if j["status"]=="in_progress" else j["status"]+"/"+str(j["conclusion"])
    required.append({"name":name,"job_id":j["id"],"state":state,"status":j["status"],"conclusion":j["conclusion"],
      "source_scope":"prospective" if name.startswith("prospective") else "head",
      "started_at":j["started_at"],"completed_at":j["completed_at"],"url":j["html_url"],
      "current_steps":[s for s in j["steps"] if s["status"]=="in_progress"],
      "failed_steps":[s for s in j["steps"] if s["conclusion"]=="failure"],
      "actual_tested_source_verified":False})
failures=[{"job_id":j["id"],"name":j["name"],"url":j["html_url"],"status":j["status"],"conclusion":j["conclusion"],
 "started_at":j["started_at"],"completed_at":j["completed_at"],
 "failed_steps":[s for s in j["steps"] if s["conclusion"]=="failure"],"cause":"UNKNOWN: metadata only; no job log/artifact retrieved"} for j in current if j["conclusion"]=="failure"]
checkfails=[{k:c.get(k) for k in ("id","name","head_sha","status","conclusion","details_url","started_at","completed_at","app")} for c in checks if c["conclusion"]=="failure"]
page=S["actual_page"];term=page["status"]
need(term["state"]=="exited" and term["exit_code"]==0 and term["output_complete"] is True and term.get("capture_error") is None,"not authoritative successful reader terminal")
rawout=bytes.fromhex(page["bytes_hex"])
need(len(rawout)==1142 and page["next_offset"]==page["available_end"]==1142,"actual page incomplete")
need(sha(rawout)==page["chunk_sha256"],"actual terminal SHA differs")
last=json.loads(rawout.decode().splitlines()[-1]);need(last["status"]=="OBSERVED" and last["summary"]==S["summary"] and last["index"]==S["index"],"actual printed terminal pins differ")
os.umask(0o077);OUT.mkdir(mode=0o700,exist_ok=False)
pins=[]
def save(name,value):
    raw=value if isinstance(value,bytes) else (json.dumps(value,indent=2,sort_keys=True)+"\n").encode()
    p=OUT/name
    with p.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
    pin={"path":str(p),"bytes":len(raw),"sha256":sha(raw)}
    read(pin);pins.append(pin);return pin
save("closure-producer.py",sys.argv[2].encode())
save("actual-pty-read-tool-response.json",S["raw_read"])
terminalpin=save("actual-terminal-pages.json",{"schema":"trnm-actual-pty-pages-v1","session_id":S["session_id"],"terminal":page,"pages":[page],
 "launch_tool_response_available_in_this_closure":False,"launch_owner":"root"})
logpin=save("actual-terminal.log",rawout)
facts={
 "schema":"trnm-H5DF-required-ci-progress-closed-snapshot-v1","status":"OBSERVED_METADATA_ONLY",
 "created_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "snapshot_start":summary["started_at"],"snapshot_end":summary["finished_at"],
 "head":HEAD,"expected_tree":TREE,"PR":summary["pr"],"run":run["metadata"],
 "observed_attempt":1,"required_named_count":14,"required_counts":dict(collections.Counter(j["state"] for j in required)),
 "required":required,"all_run_job_counts":run["observed_attempt_job_counts"],
 "all_run_failed_jobs":failures,"latest_checks_counts":summary["latest_checks"]["status_counts"],
 "latest_checks_failed_metadata":checkfails,"all_six_GET_exits":[{"label":s["label"],"exit":s["exit"],"started_at":s["started_at"],"finished_at":s["finished_at"]} for s in summary["steps"]],
 "original_summary":S["summary"],"original_index":S["index"],"normalized_jobs":run["jobs"],
 "normalized_checks":summary["latest_checks"]["normalized"],"actual_terminal":terminalpin,
 "actual_terminal_raw":logpin,
 "scope_transition":{"newhead_first_snapshot":True,"old_R1_scope":S["prior"],
 "old_R1_status":"DRIFT","old_R1_results_inherited":False,"compare_statuses_across_heads_as_test_delta":False},
 "actual_tested_source_verified":False,"PR_prospective_SHA_is_metadata_only":True,
 "running_or_absent_is_not_pass":True,"all_required_success":False,"hosted_qualification_granted":False,
 "merge_permission_granted":False,"observations_non_atomic":True,
 "new_network_GETs_by_closure":0,"new_logs_or_artifacts_acquired":False,
 "source_refs_stage_changes":False,"original_files_modified":False}
factpin=save("progress-delta.json",facts)
save("original-source-pins.json",{"files":original_pins+[S["index"],S["prior"]],"versions_fenced_without_atime":True})
for p,v in original_versions.items():need(ver(pathlib.Path(p).lstat())==v,"original changed during closure")
indexpin=save("EVIDENCE_INDEX.json",{"schema":"trnm-H5DF-closed-progress-index-v1","files":list(pins),"self_excluded":"EVIDENCE_INDEX.json"})
seal=save("seal-summary.json",{"status":"CLOSED","original_reader_exit":0,"original_reader_status":"OBSERVED",
 "actual_session_id":S["session_id"],"original_summary":S["summary"],"facts":factpin,"index":indexpin,
 "original_sources_version_unchanged":True,"new_GETs":0,"no_qualification":True})
print(json.dumps({"status":"CLOSED","facts":factpin,"index":indexpin,"seal":seal,
 "required_counts":facts["required_counts"],"run_id":RUN,"attempt":1,"failed_jobs":failures,
 "required":[{k:j[k] for k in ("name","job_id","state")} for j in required]},sort_keys=True))
