import hashlib,json,os,pathlib,stat,sys
B=pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-arm-resume-20261114-v1")
O=B/"final-review-v1";D=B/"offline-corrected-inspection-v1"
def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def jb(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def fid(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,cap=134217728):
 need(p.resolve()==p,"canonical")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap,"bounded regular")
  raw=f.read(cap+1);z=os.fstat(f.fileno())
 need(fid(a)==fid(z)==fid(p.lstat()) and len(raw)==a.st_size,"stable")
 return raw,fid(a)
def pin(p):
 b,v=read(p);return {"path":str(p),"bytes":len(b),"sha256":sha(b)},v
def put(p,b):
 with p.open("xb") as f:f.write(b)
 r,_=read(p);need(r==b,"output readback")
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
arg=json.loads(sys.argv[1]);need(not O.exists(),"create-only final");O.mkdir(mode=0o700)
put(O/"seal-closed-arm-evidence.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
terminals={}
for name,rec in arg.items():
 need(name.replace("-","").replace("_","").isalnum(),"safe terminal label")
 need(rec["output_complete"] is True and rec["status"]["state"]=="exited"
      and rec["offset"]==0 and rec["next_offset"]==rec["available_end"],"complete actual terminal")
 raw=bytes.fromhex(rec["bytes_hex"]);need(sha(raw)==rec["chunk_sha256"] and len(raw)==rec["available_end"],"actual output SHA")
 terminals[name]={"tool":put(O/(name+".json"),jb(rec)),"raw":put(O/(name+".output.bin"),raw),"status":rec["status"]}
transport_raw,_=read(B/"summary.json");need(sha(transport_raw)=="a8bc3bb1da7b0e049185f0846efd4e71da29cb255fa21b00462a739a57679889","original resumed HOLD")
transport=json.loads(transport_raw)
corrected_raw,_=read(D/"summary.json");need(sha(corrected_raw)=="0629ef20cb32329bf3ff25152887de8335397a859bfc0407614844a815938211","corrected inspection pin")
corrected=json.loads(corrected_raw);need(corrected["error"] is None and corrected["frames"]==[],"offline corrected inspection success")
facts_raw,_=read(D/"bounded-confirmation-report-facts.json");need(sha(facts_raw)=="2c95158ab4e84bb7bb87a3713f7b819f1e8711ced3c8e00d868e505c5cf66747","actual report facts")
facts=json.loads(facts_raw);result=corrected["result"]
source_raw,_=read(D/"source-before-after-extracted.json");source=json.loads(source_raw)
need(source["source_before"]==source["source_after"],"exact source before after")
index_raw,_=read(pathlib.Path(result["member_index"]["path"]));need(sha(index_raw)==result["member_index"]["sha256"],"all-member index pin")
member_index=json.loads(index_raw)
native_map=json.loads(read(D/"native-manifest-filemap-verification.json")[0])
need(member_index["all_members_CRC_SHA256_verified"] is True and native_map["exact_prefix_closure"] is True,"full integrity closure")
helper=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/resume_r1_arm64_cost_artifact_v1.py")
helper_raw,_=read(helper);need(sha(helper_raw)=="6aec3684388395ae38f6d871f5d764dce419a41ba1c62d425c81dabcb415b3f9","original helper unchanged")
helper_pin=put(O/"original-resume-helper.py",helper_raw)
launcher=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/R1-arm64-cost-resume-launch-001/launcher.py")
launcher_raw,_=read(launcher);launcher_pin=put(O/"original-root-launcher.py",launcher_raw)
phase_rows=[]
for p in facts["phases"]:
 s=p["phase_scalars"]
 phase_rows.append({"json_pointer":p["json_pointer"],"mode":s["mode"],"workers":s["workers"],"requested_window_ns":s["requested_window_ns"],"client_confirmed_transactions":s["client_confirmed_transactions"],"client_confirmation_latency_ns":s["client_confirmation_latency_ns"],"finite_business_target_met":s["finite_business_target_met"],"honest_submissions":p["honest_submissions_count"],"honest_history":p["honest_history_count"],"verification_errors":p["verification_errors"],"replays":p["replays"]})
summary={"schema":"trnm-r1-arm64-cross-cost-final-readonly-review-v1","run_id":43604217412,"run_attempt":1,"job_id":132481412245,"artifact_id":14119000610,
"status":"COMPLETE_ARTIFACT_AND_NATIVE_FAILURE_OBSERVED","original_full_download_failure":transport["original_failure"],"resumed_transport_original_HOLD":pin(B/"summary.json")[0],
"resumed_transport_facts":{"metadata":transport["steps"][0],"range":transport["steps"][1],"complete_zip":transport["complete_zip"],"tail_body":transport["tail_body"],"original_inputs_before_after_valid":transport["original_inputs_before_after_valid"]},
"checker_error":"Original helper used stat.S_ISREG (a predicate function) in an allowed-kind tuple where stat.S_IFREG (regular-file constant) was required. This checker error rejected an ordinary member; it is not an artifact failure. The original helper, HOLD and false initial inference remain unchanged.",
"single_identifier_correction":corrected["source_correction"],"offline_corrected_inspection":pin(D/"summary.json")[0],"native_manifest":result["manifest"],"member_index":result["member_index"],"native_map":native_map,"source_identity":source,
"native_runs":[{"name":r["name"],"passed":r["passed"],"process_exit_code":r["process"]["exit_code"],"named_execution":r["named_execution"],"original_logs":r["originals"]} for r in result["runs"]],
"manifest_outcome":result["manifest_outcome"],"confirmation_report":facts["report_member"],"phase_facts":phase_rows,"actual_terminals":terminals,
"original_helper":helper_pin,"actual_root_launcher":launcher_pin,"no_additional_GET_after_resume":True,"no_main_capture_network_in_offline_validation":True,"no_inner_native_tests_executed":True,"source_Git_CI_budgets_stage_unchanged":True,
"interval_limit":"Host and native phase intervals are nested. Host CPU includes each actual calling thread, not all worker CPU. Wall minus calling-thread CPU does not establish scheduler/throttle causation."}
sp=put(O/"review.json",jb(summary))
readme="""# R1 arm64 cross-architecture artifact — completed read-only diagnosis

The original full GET timed out at1200s and retained9,142,272 bytes with exit124/process-9. It remains unchanged.

The independent positive Range GET returned206, exact Content-Range bytes9142272-9927037/9927038 and784,766 body bytes, exit0 in105.654s. Concatenating into a new file matched the official9,927,038-byte SHA2568249d027....

The original resume helper then truthfully returned HOLD: its new ZIP regular-kind whitelist mistakenly used the function stat.S_ISREG rather than the integer constant stat.S_IFREG. This was a checker defect, not an illegal archive member. The original script, terminal, HOLD, central metadata and two diagnostic observations remain intact. Root authorized exactly this identifier correction in a separate offline inspector; no main/capture/network was available in that inspector.

The corrected offline pass verified all161 ZIP member CRC/SHA and the exact54/54 native manifest mapping, exact R1 sourcebeforeafter/test identity, unchanged native binary, and all five original selector process/stream bindings. The five Rust selectors actually passed. Native manifest's only failure is CONFIRMATION_TARGET.

Baseline: original4s,0worker,1 confirmation at1.897458176s. Pressure: original4s,16workers,0 confirmations,7Submit records,4History records; first3 replays accepted and fourth returned PUBLIC_REQUEST_DEADLINE at4.094987697s. No result from x64 was substituted. Qualification/activation flags remain the originalfalse values.

The full report remains only in the complete verified ZIP. Bounded facts retain exact JSON pointers and original replay/Host values. Nested intervals are not additive, and wall minus CPU does not establish cgroup/scheduler causation.

This directory is external evidence, not a stage write or source/CI change. No additional GET or native test was run after the one authorized range acquisition.
"""
put(O/"README.md",readme.encode())
files=[];versions={}
for p in sorted(B.rglob("*")):
 need(p.resolve()==p,"canonical evidence tree")
 s=p.lstat()
 if stat.S_ISDIR(s.st_mode):continue
 fp,v=pin(p);versions[str(p)]=v
 files.append({"path":p.relative_to(B).as_posix(),"bytes":fp["bytes"],"sha256":fp["sha256"],"origin":{"host":"mac","path":str(p)}})
ix=put(O/"EVIDENCE_INDEX.json",jb({"schema":"trnm-closed-evidence-index-v1","root":str(B),"file_count":len(files),"total_bytes":sum(x["bytes"] for x in files),"files":files,"excludes_itself_and_seal":True,"GET_count":2,"no_native_execution":True}))
for p,v in versions.items():need(fid(pathlib.Path(p).lstat())==v,"original file identity unchanged")
seal=put(O/"seal.json",jb({"review":sp,"index":ix,"indexed_files":len(files),"indexed_bytes":sum(x["bytes"] for x in files),"original_HOLD_preserved":True,"all_originals_stable":True}))
print(json.dumps({"review":sp,"index":ix,"seal":seal,"total_files":len(files)+2,"total_bytes":sum(x["bytes"] for x in files)+ix["bytes"]+seal["bytes"],"member_count":member_index["member_count"],"native_map":native_map,"manifest_failures":result["manifest_outcome"]["failures"]},sort_keys=True))
