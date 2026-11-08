from pathlib import Path
import collections,datetime,hashlib,json,re,time
ROOT=Path("/home/qian-qi/work/chain-w1-c8-postpush-ci-observation-20261108-ec265b-01")
HEAD="4e007a87ceecbec8d265f6a70cfd71d512a514b5"
def sha(b):return hashlib.sha256(b).hexdigest()
def load(name):
 b=(ROOT/name).read_bytes()
 return json.loads(b),{"path":name,"bytes":len(b),"sha256":sha(b)}
snapshot,sp=load("snapshot.json");checks,cp=load("C8-all-checks.json");runs,rp=load("C8-all-workflow-runs.json")
assert sp["sha256"]=="572738750c14057ed436ef4602085692810bd7c88b0a8c576f09ebb1b16bd5b0"
foreign_checks=[x["id"] for x in checks if x.get("head_sha")!=HEAD]
foreign_runs=[x["id"] for x in runs if x.get("head_sha")!=HEAD]
samples=[];readbacks=[]
for sample in snapshot["job_samples"]:
 jid=sample["job_id"];rid=sample["run_id"]
 meta,pin=load(sample["job_metadata"])
 matches=[]
 for row in checks:
  m=re.search(r"/actions/runs/(\d+)/job/(\d+)",row.get("details_url",""))
  if m and int(m.group(1))==rid and int(m.group(2))==jid:matches.append(row)
 row=matches[0] if len(matches)==1 else None
 check_url=meta.get("check_run_url")
 check_url_id=None
 if isinstance(check_url,str):
  m=re.search(r"/check-runs/(\d+)$",check_url)
  if m:check_url_id=int(m.group(1))
 checks_ok={"unique_snapshot_check":len(matches)==1,"metadata_job_id":meta.get("id")==jid,"metadata_run_id":meta.get("run_id")==rid,"metadata_head_sha":meta.get("head_sha")==HEAD,"snapshot_check_head":row is not None and row.get("head_sha")==HEAD,"check_run_url_id":row is not None and check_url_id==row["id"],"name_matches":row is not None and row.get("name")==meta.get("name")==sample["name"]}
 samples.append({"job_id":jid,"run_id":rid,"check_id":None if row is None else row["id"],"name":sample["name"],"checks":checks_ok,"all_identity_checks_pass":all(checks_ok.values()),"metadata":pin})
 log=ROOT/sample["job_log"];raw=log.read_bytes();lines=raw.decode("utf-8").splitlines()
 def clean(line):
  return re.sub(r"^\d{4}-\d{2}-\d{2}T[0-9:.]+Z\s*","",re.sub(r"\x1b\[[0-9;]*m","",line)).strip()
 errors=[i for i,line in enumerate(lines) if "##[error]" in line]
 relevant=[]
 for i,line in enumerate(lines):
  text=clean(line)
  if re.search(r"Traceback|AssertionError|RuntimeError|error:|FAILED|Error:|CONFIRMATION_TARGET|PUBLIC_REQUEST_DEADLINE|FRESH_NATIVE_PROCESS_REQUIRED|ORIGINAL_THREE_RUN_CAMPAIGN_FAILED|BUDGET|budget.*failed",text):
   if len(text)<3000:relevant.append({"line":i+1,"text":text})
 results=[]
 for i,line in enumerate(lines):
  text=clean(line)
  if not text.startswith("{"):continue
  try:value=json.loads(text)
  except (ValueError,TypeError):continue
  if isinstance(value,dict):
   summary={"line":i+1,"keys":list(value)}
   for k in ("schema","failure","complete_success","expected_head","expected_tree","source_kind","profile","original_inputs","original_campaign_outer_timeout_seconds","expected_resources","public_phase_placement"):
    if k in value:summary[k]=value[k]
   if isinstance(value.get("attempts"),list):
    summary["attempts"]=[{k:a.get(k) for k in ("number","complete_success","original_criteria_met","report_sha256","phase_startup_errors","report_validation_failure")} | {"step":{k:a.get("step",{}).get(k) for k in ("returncode","elapsed_seconds","outer_stage_timeout_seconds","complete_success","stdout_truncated","stderr_truncated")}} for a in value["attempts"]]
   results.append(summary)
 tail=[]
 if errors:
  last=errors[-1]
  tail=[{"line":i+1,"text":clean(lines[i])[:6000]} for i in range(max(0,last-45),min(len(lines),last+3))]
 preconditions=[s for s in meta.get("steps",[]) if re.search(r"source|identity|bind|checkout|host|prepare|limits",s.get("name",""),re.I)]
 readbacks.append({"job_id":jid,"name":sample["name"],"metadata_conclusion":meta.get("conclusion"),"first_failed_step":sample.get("first_failed_step"),"precondition_steps":preconditions,"log":{"path":sample["job_log"],"bytes":len(raw),"sha256":sha(raw)},"event_expected_values":sample.get("event_expected_values"),"error_line_count":len(errors),"relevant_lines":relevant[:30]+([] if len(relevant)<=30 else relevant[-15:]),"valid_json_log_records":results,"tail_before_last_error":tail})
audit={"schema":"TRNM-W1-C8-CI-EXACT-SCOPE-AUDIT1","source_commit":HEAD,"read_only_existing_records":True,"new_API_calls":0,"original_snapshot_modified":False,"snapshot":sp,"check_rows":cp,"workflow_rows":rp,"foreign_check_ids":foreign_checks,"foreign_workflow_run_ids":foreign_runs,"check_ids_unique":len({x["id"] for x in checks})==len(checks),"workflow_ids_unique":len({x["id"] for x in runs})==len(runs),"check_page_totals_match":all(x["declared_total"]==len(checks) for x in snapshot["C8_checks"]["page_counts"]),"workflow_page_totals_match":all(x["declared_total"]==len(runs) for x in snapshot["C8_workflow_runs"]["page_counts"]),"samples":samples}
audit["exact_check_enumeration_complete"]=not foreign_checks and audit["check_ids_unique"] and audit["check_page_totals_match"] and snapshot["C8_checks"]["enumeration_complete"] is True
audit["exact_workflow_enumeration_complete"]=not foreign_runs and audit["workflow_ids_unique"] and audit["workflow_page_totals_match"] and snapshot["C8_workflow_runs"]["enumeration_complete"] is True
audit["all_sample_identities_verified"]=all(x["all_identity_checks_pass"] for x in samples)
for name,data in [("scope-audit.json",audit),("sample-evidence-readback.json",{"schema":"TRNM-W1-C8-CI-RETAINED-SAMPLES1","new_API_calls":0,"samples":readbacks})]:
 with (ROOT/name).open("x") as f:json.dump(data,f,indent=2);f.write("\n")
fails=[{"id":x["id"],"name":x.get("name"),"status":x.get("status"),"conclusion":x.get("conclusion"),"details_url":x.get("details_url")} for x in checks if x.get("conclusion")=="failure"]
with (ROOT/"failure-check-roster.json").open("x") as f:json.dump({"source_commit":HEAD,"snapshot_sha256":sp["sha256"],"count":len(fails),"failure_causes_not_inferred_from_names":True,"checks":fails},f,indent=2);f.write("\n")
def stamp(ns):
 seconds,rem=divmod(ns,10**9)
 return datetime.datetime.fromtimestamp(seconds,datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")+f".{rem:09d} UTC"
print(json.dumps({"start_utc":stamp(snapshot["window_started_unix_ns"]),"finish_utc":stamp(snapshot["window_finished_unix_ns"]),"scope_audit_sha256":sha((ROOT/"scope-audit.json").read_bytes()),"samples_readback_sha256":sha((ROOT/"sample-evidence-readback.json").read_bytes()),"exact_check_enumeration_complete":audit["exact_check_enumeration_complete"],"exact_workflow_enumeration_complete":audit["exact_workflow_enumeration_complete"],"all_sample_identities_verified":audit["all_sample_identities_verified"],"samples":samples,"failure_roster":fails}),flush=True)
for row in readbacks:
 print(json.dumps({"job_id":row["job_id"],"name":row["name"],"first_failed_step":row["first_failed_step"],"precondition_steps":row["precondition_steps"],"relevant_lines":row["relevant_lines"][-10:],"valid_json_log_records":row["valid_json_log_records"],"tail_before_last_error":row["tail_before_last_error"][-20:]}),flush=True)
