import os,sys,stat,json,hashlib,zlib,re,datetime
from pathlib import Path
assert sys.flags.optimize==0
I=json.loads(sys.argv[1])
BASE=Path("/private/tmp/chain-prci-H5DF-cross-cost-selected-artifact-20261114-v1")
D=BASE/"selected-v1";DD=BASE/"directory-v1";OUT=BASE/"final-review-v1"
HEAD="5df7ae6f482157c5f7fdcbcd52222117a965053f"
TREE="6be4940d38cc88782657f2684cbefe48866f8b9f"
BIN="bb788ecebc740db3e54cdb1a2942db4af9f19f592404f73026dfeb6ad9f26507"
reads={}
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,n=None,h=None):
 p=Path(p);assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<=32*1024*1024 and fp(a)==fp(p.lstat())
  chunks=[]
  while True:
   b=os.read(fd,1048576)
   if not b:break
   chunks.append(b)
  raw=b"".join(chunks);assert fp(a)==fp(os.fstat(fd))==fp(p.lstat())
 finally:os.close(fd)
 pin={"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
 if n is not None:assert len(raw)==n and pin["sha256"]==h
 reads[str(p)]=(pin,fp(a));return raw,pin
def jr(p,n=None,h=None):
 raw,pin=read(p,n,h);return json.loads(raw),pin
def bypin(p):return jr(p["path"],p["bytes"],p["sha256"])
s,sp=jr(D/"summary.json",21253,"20937bc9c0db42441b4a974a9ec70c339146965540e38e141f4dd2ddbbb67f2a")
ds,dsp=bypin(s["directory_stage"])
ai,aip=jr(D/"EVIDENCE_INDEX.json",12118,"e2ff8b5b79ea78a464359939b53606395da5b874e0a010f57441418c30ce59f3")
di,dip=jr(DD/"EVIDENCE_INDEX.json",1474,"6de56f31e5bcb49114cb68152c258930d2118df4530f69b90e95af48ff159541")
ix,ixp=bypin(s["selected_members"])
cd,cdp=jr(DD/"central-directory.json",67501,"25ab09b70c08ff82a8433326ebadd3b24b11035858e7b98ad141cacc864628d6")
assert s["status"]=="SELECTED_ORIGINAL_MEMBERS_VERIFIED"and s["errors"]==[]and s["actual_combined_GETs"]==10 and s["actual_new_GETs"]==8
assert s["whole_artifact_sha256_verified"]is False and s["all_artifact_member_crc_verified"]is False
assert s["combined_elapsed_seconds"]<s["combined_budget_seconds"]==900
assert ix["count"]==25 and cd["entries"]==161
assert len(s["steps"])==8 and all(x["exit"]==0 and x["complete_transport"]is True and x["http_status"]==206 for x in s["steps"])
for row in ai["files"]+di["files"]:read(row["path"],row["bytes"],row["sha256"])
for name in ["directory-producer.py","selected-producer.py","original-to-directory-reader.patch","directory-to-selected-producer.patch","directory-launch.json","selected-launch.json"]:read(BASE/name)
read(BASE/"directory-producer.py",21134,"b5378e5bab78f3c41ecd0379107d7bf9effaeac3de60577ef4bae6a30335e256")
read(BASE/"selected-producer.py",26244,"144a9f3e7af6d3ccf5c1e46c80db9c28e796aeaf22b135d67874a8f3888b3184")
raws={};pins={};origins={}
for row in ix["files"]:
 raw,pin=read(row["original"]["path"],row["bytes"],row["sha256"])
 assert pin==row["original"]and ("%08x"%(zlib.crc32(raw)&0xffffffff))==row["crc32"]and row["crc32_verified"]is True
 assert row["path"]not in raws
 raws[row["path"]]=raw;pins[row["path"]]=pin;origins[pin["path"]]=row["origin"]
m=json.loads(raws["from-zero-native/manifest.json"]);r=json.loads(raws["from-zero-native/confirmation/report.json"])
src=json.loads(raws["source.json"]);c=json.loads(raws["from-zero-native-host/controller-result.json"])
prep=json.loads(raws["from-zero-native-host/prepare-build.json"])
before=json.loads(raws["from-zero-native-host/inside-before.json"]);after=json.loads(raws["from-zero-native-host/inside-after.json"])
assert src["candidate"]==src["tested_commit"]==HEAD and src["base"]is None and src["kind"]=="head"and src["prospective_merge"]is None and src["tested_tree"]==TREE and src["tracked_worktree_verified"]is True
assert src["tracked_entries"]==41681 and src["tracked_bytes"]==3995072357
assert m["source_before"]==m["source_after"]==prep["source_before"]==prep["source_after"]
assert m["source_before"]["commit"]==HEAD and m["source_before"]["tree"]==TREE and m["source_before"]["tracked_source_identity"]==src
assert m["binary_sha256_before"]==m["binary_sha256_after"]==c["preparation"]["binary_sha256"]==prep["binary_sha256"]==BIN
assert m["all_named_tests_passed"]is True and m["failures"]==["CONFIRMATION_TARGET"]and m["passed"]is False
assert m["terminal"]["native_execution_completed"]is True and m["terminal"]["acceptance_passed"]is False and m["terminal"]["finalization_completed"]is True
assert c["systemd_run_exit"]==1 and c["failure"]is None and c["final_host_errors"]==[]and c["passed"]is False
limits={"cpu.max":"25000 100000","cpu.max.burst":"0","memory.max":"2147483648","memory.swap.max":"0","pids.max":"256"}
assert before["limits"]==after["limits"]==limits and before["parent"]==after["parent"]and before["boot_id"]==after["boot_id"]
assert before["read_errors"]==after["read_errors"]=={}
map_names=set(m["files"])
cd_native={x["path"][len("from-zero-native/"):]for x in cd["members"]if not x["directory"]and x["path"].startswith("from-zero-native/")}-{"manifest.json"}
assert map_names==cd_native
mapproof=[]
for name,pin in pins.items():
 if name.startswith("from-zero-native/")and name!="from-zero-native/manifest.json":
  rel=name[len("from-zero-native/"):];assert m["files"][rel]==pin["sha256"];mapproof.append({"manifest_key":rel,"actual":pin})
assert len(mapproof)==16
native=[]
for run in m["runs"]:
 name=run["name"];pfx="from-zero-native/"+name+"/"
 proc=json.loads(raws[pfx+"process.json"]);out=raws[pfx+"stdout"];err=raws[pfx+"stderr"]
 assert proc==run["process"]and proc["exit_code"]==0 and proc["timed_out"]is False
 assert hashlib.sha256(out).hexdigest()==run["stdout_sha256"]==proc["stdout_sha256"]
 assert hashlib.sha256(err).hexdigest()==run["stderr_sha256"]==proc["stderr_sha256"]
 prefix=b"\ntest "+name.encode()+b" ... "
 assert out.count(prefix)==1
 result=re.findall(rb"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s$",out)
 assert len(result)==1
 section=out.split(prefix,1)[1].split(b"\ntest result: ",1)[0].rstrip()
 assert section==b"ok"or section.endswith(b"\nok")
 assert run["named_execution"]["executed_tests"]==1 and run["named_execution"]["result"]=="PASS"and run["passed"]is True
 native.append({"name":name,"exit_code":proc["exit_code"],"timed_out":proc["timed_out"],"named_execution":run["named_execution"],"wall_ns":proc["wall_ns"],"command":proc["command"],"process":pins[pfx+"process.json"],"stdout":pins[pfx+"stdout"],"stderr":pins[pfx+"stderr"]})
assert len(native)==5
b,p=r["phases"]
assert b["workers"]==0 and p["workers"]==16 and b["requested_window_ns"]==p["requested_window_ns"]==4000000000
assert b["client_confirmed_transactions"]==1 and b["independent_client_confirmation"]["depth"]==6 and b["client_confirmed_before_original_window_end"]is True
assert p["client_confirmed_transactions"]==0 and p["finite_business_target_met"]is False
assert len(p["honest_submissions"])==7 and len(p["honest_history"])==len(p["independent_history_page_replay"])==2
assert all(x["status"]=="ok"and x["error"]is None for x in p["honest_submissions"]+p["honest_history"])
rp=p["independent_history_page_replay"]
assert [x["replay_accepted"]for x in rp]==[True,False]and rp[1]["replay_error"]=="PUBLIC_REQUEST_DEADLINE"
assert p["verification_errors"]==["PUBLIC_REQUEST_DEADLINE"]
n=rp[1]["native_import_observation"]
wi=next(i for i,x in enumerate(n["packets"][0]["phases"])if x["phase"]=="work")
work=n["packets"][0]["phases"][wi]
assert work["accepted"]is False and work["error_code"]=="PUBLIC_REQUEST_DEADLINE"
assert all(x["calls_rejected"]==0 and x["last_error_code"]is None for x in n["host_checks"])
def validate_pages(pages,session,size):
 pos=0;chunks=[]
 for pg in pages:
  assert pg["session_id"]==session and pg["offset"]==pos and not pg["truncated_before_offset"]and not pg["text_is_lossy"]
  raw=bytes.fromhex(pg["bytes_hex"]);assert len(raw)==pg["next_offset"]-pos and hashlib.sha256(raw).hexdigest()==pg["chunk_sha256"]
  chunks.append(raw);pos=pg["next_offset"]
 last=pages[-1]
 assert last["status"]["state"]=="exited"and last["status"]["exit_code"]==0 and last["output_complete"]is True and pos==last["available_end"]==size
 return b"".join(chunks),{"schema":"trnm-actual-pty-pages-v1","session_id":session,"archive_path":last["archive_path"],"terminal":last,"pages":pages}
dlog,dterm=validate_pages(I["directory_pages"],"dpty-1f2e75a5d91bc9f54736f22d1333c4376bc94edcc7b37cf4106b1ae437ac3d08",1621)
slog,sterm=validate_pages(I["selected_pages"],"dpty-e25b03eb6cf52bfa22a761d555afb21e3c14b51ca96d99a1f0435986e8f86b25",2856)
OUT.mkdir(exist_ok=False);made=[]
def put(name,raw):
 path=OUT/name
 with path.open("xb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
 pin=read(path,len(raw),hashlib.sha256(raw).hexdigest())[1];made.append(pin);return pin
def js(name,x):return put(name,(json.dumps(x,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+"\n").encode())
put("review-producer.py",sys.argv[2].encode())
js("review-inputs.json",I)
dtp=js("directory-actual-terminal-pages.json",dterm);dlp=put("directory-actual-terminal.log",dlog)
stp=js("selected-actual-terminal-pages.json",sterm);slp=put("selected-actual-terminal.log",slog)
def scalars(x):return{k:v for k,v in x.items()if not isinstance(v,(dict,list))}
def req(q):
 keys=["started_ns","ended_ns","elapsed_wall_ns","status","error","returned_after_window","returned_after_deadline","deadline_ms","client_thread_cpu_ns","metrics"]
 return{k:q[k]for k in keys if k in q}
def rep(q):return{k:v for k,v in q.items()if k!="native_import_observation"}
def phase(q):
 keys=["mode","workers","requested_window_ns","business_started_ns","confirmation_ended_ns","client_confirmation_latency_ns","client_confirmed_transactions","client_confirmed_before_original_window_end","finite_business_target_met","invariant_target_met","accounting_closed","attacker_workers_cpu_ns","attacker_workers_cpu_scope","independent_replay_and_confirmation_cpu_ns","independent_replay_and_confirmation_wall_ns","resource_fairness_qualified","work_profile_qualified","production_activation","public_network_ready"]
 return{**{k:q[k]for k in keys if k in q},"submit_calls":len(q["honest_submissions"]),"successful_submits":sum(x["status"]=="ok"for x in q["honest_submissions"]),"history_calls":len(q["honest_history"]),"successful_history":sum(x["status"]=="ok"for x in q["honest_history"]),"replay_calls":len(q["independent_history_page_replay"]),"replay_accepted":sum(x["replay_accepted"]is True for x in q["independent_history_page_replay"]),"verification_errors":q["verification_errors"]}
def obs(q):
 nn=q["native_import_observation"]
 return{"clock_scope":nn["clock_scope"],"host_checks":nn["host_checks"],"packets":[{"packet_index":pp["packet_index"],"phases":[scalars(x)for x in pp["phases"]]}for pp in nn["packets"]],"measurement_failures":nn["measurement_failures"],"cpu_intervals_are_nested_not_additive":nn["cpu_intervals_are_nested_not_additive"],"host_checks_are_nested_not_additive":nn["host_checks_are_nested_not_additive"]}
facts={"schema":"trnm-H5DF-x64-cost-exact-facts-v1","observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"scope":"Original H5DF cross-arch-cost x64 selected evidence; no tests or report validator rerun","run_id":43621754143,"run_attempt":1,"job_id":132528768933,"artifact_id":14124189121,"source_identity":src,"manifest":pins["from-zero-native/manifest.json"],"report":pins["from-zero-native/confirmation/report.json"],"controller":pins["from-zero-native-host/controller-result.json"],"recorded_native_binary_sha256":BIN,"binary_evidence":{"original_keys":["/binary_sha256_before","/binary_sha256_after"],"both_equal_Host_preparation":True,"binary_bytes_downloaded_or_independently_hashed":False,"acquisition_summary_null_projection":"binary_before/binary_after were absent key projections; original binary_sha256_before/after are present and equal; prior summary unchanged"},"native_original_result":{"selectors":5,"each_named_pass":1,"each_exit_code":0,"each_timed_out":False,"native_execution_completed":m["terminal"]["native_execution_completed"],"legacy_execution_finished":m["execution_finished"],"legacy_execution_finished_scope":m["terminal"]["legacy_execution_finished_scope"],"acceptance_passed":False,"finalization_completed":True,"original_failure_codes":m["failures"],"host_exit":c["systemd_run_exit"],"host_failure":c["failure"],"final_host_errors":c["final_host_errors"]},"baseline":{"pointer":"/phases/0","facts":phase(b),"confirmed_depth":b["independent_client_confirmation"]["depth"]},"pressure":{"pointer":"/phases/1","facts":phase(p),"honest_history":[{"pointer":"/phases/1/honest_history/"+str(i),**req(q)}for i,q in enumerate(p["honest_history"])],"replays":[{"pointer":"/phases/1/independent_history_page_replay/"+str(i),**rep(q)}for i,q in enumerate(rp)],"failed_work":{"pointer":"/phases/1/independent_history_page_replay/1/native_import_observation/packets/0/phases/"+str(wi),"value":work},"second_replay_Host_checks":{"pointer":"/phases/1/independent_history_page_replay/1/native_import_observation/host_checks","value":n["host_checks"]},"native_observation_clock_scope":n["clock_scope"]},"Host":{"original_limits":limits,"inside_before":pins["from-zero-native-host/inside-before.json"],"inside_after":pins["from-zero-native-host/inside-after.json"],"before_after_limits_parent_boot_equal":True,"all_selected_observations_read_errors_empty":True,"counter_scope":"Only whole native lane before/after snapshots; cannot phase-align throttling to this four-second pressure window"},"causal_limits":["Second replay rejects in packet work with PUBLIC_REQUEST_DEADLINE; both History calls succeeded","No inherited explanation from R1 head challenge IO11 or R1 prospective third-replay failure","Wall minus calling-thread CPU does not distinguish runnable wait, cgroup throttling, synchronous blocking, or work on other threads","All Host checks in failed replay accepted; this is not proof of low Host cost or whole process CPU","No sampler, scheduler state/wakeup, phase-aligned cgroup counters, or new execution was obtained"],"coverage":{"selected_members":25,"selected_member_CRC_SHA":True,"native_manifest_name_map_equals_CD":len(map_names),"native_manifest_contents_actually_hashed":16,"CD_members":161,"whole_ZIP_SHA_verified":False,"all_ZIP_member_CRC_verified":False,"binary_independently_hashed":False},"qualification":False}
factpin=js("exact-confirmation-facts.json",facts)
nativepin=js("original-five-native-results.json",native)
obspin=js("pressure-native-observations.json",{"original_report":pins["from-zero-native/confirmation/report.json"],"observations":[{"pointer":"/phases/1/independent_history_page_replay/"+str(i)+"/native_import_observation","bounded_fields":obs(q)}for i,q in enumerate(rp)],"full_raw_original_report_retained":True})
map_pin=js("selected-manifest-bindings.json",{"manifest":pins["from-zero-native/manifest.json"],"CD":cdp,"name_map_exact":True,"name_map_count":len(map_names),"names":sorted(map_names),"actually_hashed_native_count":len(mapproof),"actually_hashed_native":mapproof,"all_other_native_contents_verified":False})
overlay=js("binary-projection-correction-overlay.json",{"scope":"Correct only derived summary field lookup; do not modify original acquisition receipt","original_acquisition":sp,"original_manifest":pins["from-zero-native/manifest.json"],"prior_projection":{"binary_before":s["manifest_source_identity"]["binary_before"],"binary_after":s["manifest_source_identity"]["binary_after"]},"actual_original_keys":{"binary_sha256_before":m["binary_sha256_before"],"binary_sha256_after":m["binary_sha256_after"]},"Host_preparation":prep["binary_sha256"],"binary_bytes_verified":False})
review={"schema":"trnm-H5DF-x64-selected-originals-review-v1","status":"ORIGINAL_FIVE_NATIVE_PASS_BUSINESS_CONFIRMATION_FAILURE","closed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"source":HEAD,"tree":TREE,"run_id":43621754143,"run_attempt":1,"job_id":132528768933,"artifact_id":14124189121,"actual_GETs":10,"acquisition_started_at":ds["started_at"],"acquisition_finished_at":s["finished_at"],"combined_elapsed_seconds":s["combined_elapsed_seconds"],"original_acquisition":sp,"directory_acquisition":dsp,"actual_directory_terminal":dtp,"actual_selected_terminal":stp,"actual_terminal_logs":[dlp,slp],"facts":factpin,"original_five_results":nativepin,"pressure_native_observations":obspin,"manifest_bindings":map_pin,"binary_projection_overlay":overlay,"declared_whole_ZIP_bytes":s["declared_whole_archive_bytes"],"declared_whole_ZIP_SHA256":s["declared_whole_archive_sha256"],"whole_ZIP_SHA_verified":False,"all_ZIP_member_CRC_verified":False,"selected_member_CRC_SHA_verified":True,"outer_review_preserved":"/private/tmp/chain-prci-H5DF-cross-arch-cost-x64-original-log-20261114-v1/outer-review-v1/review.json","conclusion":"The five original native selectors each passed. The attack-free 4-second baseline confirms depth 6; the original 16-worker pressure phase confirms none. Both History requests succeeded; replay 1 accepted and replay 2 failed in packet work with PUBLIC_REQUEST_DEADLINE, ending at 4.096388092 seconds. The report validator rejected CONFIRMATION_TARGET. No microcausal scheduler attribution is claimed.","no_new_GET_test_or_source_ref_stage_mutation_during_review":True,"qualification":False}
reviewpin=js("review.json",review)
original_reads=list(reads.values())
for pin,identity in original_reads:
 read(pin["path"],pin["bytes"],pin["sha256"])
 assert fp(Path(pin["path"]).lstat())==identity
allpins={k:v[0]for k,v in reads.items()}
idx=js("EVIDENCE_INDEX.json",{"schema":"trnm-H5DF-x64-selected-originals-index-v1","count":len(allpins),"bytes":sum(x["bytes"]for x in allpins.values()),"files":[allpins[k]for k in sorted(allpins)],"member_origins":[{"local":pins[row["path"]],"member":row["path"],"origin":row["origin"]}for row in ix["files"]],"self_excluded":True,"original_files_preserved":True})
seal=js("seal-summary.json",{"schema":"trnm-evidence-seal-v1","status":"CLOSED","index":idx,"review":reviewpin,"facts":factpin,"indexed_files":len(allpins),"indexed_bytes":sum(x["bytes"]for x in allpins.values()),"qualification":False,"no_network_or_test_or_source_mutation":True})
print(json.dumps({"status":"CLOSED","review":reviewpin,"facts":factpin,"observations":obspin,"index":idx,"seal":seal},sort_keys=True))
