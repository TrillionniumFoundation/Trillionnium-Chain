import datetime,hashlib,json,os,pathlib,stat,sys
E=pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-artifacts-20261114-v3")
SESSION="dpty-c6a1971094889ec02e5580480fed230e2c5cf4888ca04f5228e2e1530467842a"
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64";TREE="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"
def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def jb(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def ident(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,cap=134217728):
 need(p.resolve()==p,"canonical")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap,"bounded regular")
  raw=f.read(cap+1);b=os.fstat(f.fileno())
 need(ident(a)==ident(b)==ident(p.lstat()) and len(raw)==a.st_size,"stable file")
 return raw,ident(a)
def pin(p):
 b,v=read(p);return {"path":str(p),"bytes":len(b),"sha256":sha(b)},v
def put(p,b):
 with p.open("xb") as f:f.write(b)
 return pin(p)[0]
inp=json.loads(sys.argv[1]);pages=inp["acquisition_terminal_pages"]
need(isinstance(pages,list) and pages,"actual terminal pages")
off=0;out=b""
for page in pages:
 need(page["session_id"]==SESSION and page["host"]=="mac" and page["offset"]==off and page["truncated_before_offset"] is False,"actual contiguous page identity")
 b=bytes.fromhex(page["bytes_hex"]);need(sha(b)==page["chunk_sha256"] and page["next_offset"]==off+len(b),"actual page digest")
 out+=b;off=page["next_offset"]
last=pages[-1]
need(last["output_complete"] is True and last["status"]["state"]=="exited" and last["status"]["exit_code"]==0 and off==last["available_end"],"actual acquisition collector natural terminal")
acqp=E/"acquisition-summary.json";acqraw,_=read(acqp);acq=json.loads(acqraw)
need(acq["run_id"]==43604217412 and acq["run_attempt"]==1 and acq["head"]==HEAD and acq["automatic_retry"] is False,"actual acquisition identity")
O=E/"final-review-v1";need(not O.exists(),"create only final");O.mkdir(mode=0o700)
put(O/"seal-closed-originals.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
put(O/"actual-acquisition-pty-pages.json",jb({"schema":"trnm-actual-pty-pages-v1","session_id":SESSION,"pages":pages,"terminal":last["status"]}))
put(O/"actual-acquisition-pty-output.bin",out)
for label,rec in inp.get("closed_readonly_processing_terminals",{}).items():
 need(label and label.replace("-","").replace("_","").isalnum(),"safe label")
 put(O/(label+".json"),jb(rec))
artifacts=[]
for a in acq["artifacts"]:
 rid=a["requested"]["id"];row={"artifact_id":rid,"architecture":a["requested"]["arch"],"job_id":a["requested"]["job"],"expected_zip_bytes":a["requested"]["bytes"],"expected_zip_sha256":a["requested"]["sha256"],"metadata_binding":a["binding"],"metadata_step":a["metadata"],"download_step":a["download"],"acquisition_errors":a["errors"],"member_index":a["member_index"]}
 ip=E/"inner-originals-v1"/str(rid)/"summary.json"
 if a["errors"]:
  need(a["member_index"] is None,"failed artifact no false complete index")
  row["inner_diagnosis"]="UNKNOWN: original bounded official GET incomplete or failed; no inference from other architecture"
 else:
  need(ip.exists(),"successful artifact original inspection required")
  ir,_=read(ip);s=json.loads(ir);need(s["filemap"]["exact_prefix_closure"] is True and s["source_before_after_equal"] is True,"actual manifest/source closure")
  row["inner_inspection"]=pin(ip)[0];row["source_before"]=s["source_before"];row["source_after"]=s["source_after"]
  row["native_runs"]=[{"name":q["name"],"passed":q["passed"],"named_execution":q["named_execution"],"process_exit_code":q["process"]["exit_code"],"original_logs":q["originals"]} for q in s["runs"]]
  row["manifest_outcome"]={k:s["manifest_outcome"].get(k) for k in ("source_recompiled","all_named_tests_passed","format_passed","failures","passed","execution_finished","independent_wan_accepted","work_hardness_accepted","production_activation","confirmation_report")}
  cp=ip.parent/"compact-cause-v1"/"summary.json"
  need(cp.exists(),"bounded actual report review")
  cr,_=read(cp);c=json.loads(cr);row["compact_cause"]=pin(cp)[0];row["report_member"]=c["report"]
  row["phases"]=[]
  for ph in c["phase_facts"]:
   p=ph["phase_scalar_values"]
   row["phases"].append({"json_pointer":ph["json_pointer"],"mode":p["mode"],"workers":p["workers"],"requested_window_ns":p["requested_window_ns"],"client_confirmed_transactions":p["client_confirmed_transactions"],"client_confirmation_latency_ns":p["client_confirmation_latency_ns"],"finite_business_target_met":p["finite_business_target_met"],"honest_submissions":len(ph["honest_submissions"]),"honest_history":len(ph["honest_history"]),"replays":[{k:q[k] for k in ("json_pointer","history_call_index","replay_accepted","replay_error","replay_started_ns","replay_ended_ns","replay_wall_ns","replay_thread_cpu_ns","host_checks")} for q in ph["independent_history_page_replay"]],"verification_errors":ph["verification_errors"]})
 artifacts.append(row)
prior=[
 pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-log-review-20261114-v1/closure-v1/summary.json"),
 pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-log-review-20261114-v2/outer-log-review-v1/review.json")
]
priorpins=[pin(p)[0] for p in prior]
summary={"schema":"trnm-R1-required-cross-arch-closed-diagnosis-v1","observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"run_id":43604217412,"run_attempt":1,"head":HEAD,"tree":TREE,"acquisition_status":acq["status"],"acquisition_summary":pin(acqp)[0],"actual_collector_terminal":last["status"],"artifacts":artifacts,"prior_originals_preserved":priorpins,"known_tool_status_boundary":"Intermediate Hepta target_reboot/lost was a boottime-usec mismatch; actual owned PID and growing output were retained, then this same acquisition PTY naturally reached the recorded terminal. No download restart or timeout extension occurred.","no_native_tests_executed":True,"no_source_CI_Git_stage_or_budget_changes":True,"no_automatic_retry":True,"interpretation":"A native invariant selector exit0 does not imply its finite business confirmation target. Host and phase clocks are nested; wall minus calling-thread CPU does not establish scheduler or cgroup causation. Failed/incomplete arm acquisition, if any, remains UNKNOWN and is not assigned the x64 outcome."}
sp=put(O/"review.json",jb(summary))
lines=["# R1 required-workflow cross-architecture original evidence","","This is a read-only acquisition and diagnosis. No native code or tests were executed. The original failed-network v1 and outer-only v2 observations are retained separately and pinned in review.json.","",f"Run: 43604217412, attempt 1. Source: {HEAD}, tree {TREE}.",""]
for a in artifacts:
 lines.append("## "+a["architecture"])
 d=a["download_step"];lines.append(f"- Official artifact {a['artifact_id']}; requested ZIP {a['expected_zip_bytes']} bytes / SHA256 {a['expected_zip_sha256']}.")
 lines.append(f"- Actual GET exit {d['exit_code']}; received {d['stdout']['bytes']} bytes; actual SHA256 {d['stdout']['sha256']}.")
 if a["acquisition_errors"]:lines.append("- Bounded acquisition incomplete/failed. Original partial bytes and error remain; inner cause UNKNOWN.")
 else:
  lines.append("- Complete ZIP and every member CRC/SHA, exact native manifest filemap, source-before/after, and all original selector streams are retained.")
  lines.append("- Actual native failures/validator results: "+json.dumps(a["manifest_outcome"],sort_keys=True)+".")
  for p in a["phases"]:
   lines.append(f"- {p['mode']}: workers={p['workers']}, original window={p['requested_window_ns']} ns, confirmed={p['client_confirmed_transactions']}; History={p['honest_history']}, replay attempts={len(p['replays'])}; errors={p['verification_errors']}.")
 lines.append("")
lines += ["The original report is retained inside its verified ZIP; bounded JSON pointers and original numbered line excerpts link the diagnosis to those bytes. Summed nested/parallel clock intervals are not additive elapsed time. No scheduling, throttle, or performance-fix conclusion is inferred.","","This package is external evidence only; it has not been added to the frozen publication stage."]
put(O/"README.md",("\n".join(lines)+"\n").encode())
files=[];versions={}
for p in sorted(E.rglob("*")):
 need(p.resolve()==p,"canonical scoped tree")
 st=p.lstat()
 if stat.S_ISDIR(st.st_mode):continue
 pp,v=pin(p);versions[str(p)]=v
 files.append({"path":p.relative_to(E).as_posix(),"bytes":pp["bytes"],"sha256":pp["sha256"],"origin":{"host":"mac","path":str(p)}})
index={"schema":"trnm-closed-evidence-index-v1","root":str(E),"files":files,"file_count":len(files),"total_bytes":sum(f["bytes"] for f in files),"index_excludes_itself_and_seal":True,"source_run_id":43604217412,"run_attempt":1,"head":HEAD,"no_artifact_execution":True}
ix=put(O/"EVIDENCE_INDEX.json",jb(index))
for p,v in versions.items():need(ident(pathlib.Path(p).lstat())==v,"closed original changed")
seal=put(O/"seal.json",jb({"review":sp,"index":ix,"indexed_files":len(files),"indexed_bytes":index["total_bytes"],"old_files_stat_identity_preserved":True,"closed":True}))
print(json.dumps({"review":sp,"index":ix,"seal":seal,"indexed_files":len(files),"indexed_bytes":index["total_bytes"],"complete_package_files":len(files)+2,"complete_package_bytes":index["total_bytes"]+ix["bytes"]+seal["bytes"],"acquisition_status":acq["status"]},sort_keys=True))
