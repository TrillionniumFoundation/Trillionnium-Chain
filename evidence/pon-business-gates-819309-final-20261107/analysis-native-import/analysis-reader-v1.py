import collections,hashlib,json,os,pathlib,subprocess,sys
ROOT=pathlib.Path("/home/qian-qi/chain-throughput-local-admin-20261107/work-final-business-20261107")
OUT=ROOT.parent/"analysis-native-import-819309-20261107"
ENV=dict(os.environ,GIT_OPTIONAL_LOCKS="0",GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1")
SOURCES=[
"trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs",
"trillionnium/crates/trnm-pon-node/src/ingress/history_import/observation.rs",
"trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs",
"trillionnium/crates/trnm-pon-node/src/ingress.rs",
"trillionnium/crates/trnm-pon-node/src/ingress/execution_observation.rs",
"trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs",
"trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs",
"trillionnium/crates/trnm-pon-node/src/store.rs",
"trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs",
"trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
"trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs",
"trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/fresh_challenge.rs"]
INPUTS=[
("fresh-H-fresh","/home/qian-qi/throughput-final-ci-observation-20261107/20261107T185302Z-819309fd3122-28c8f400/fresh-artifact-read-v1/13586581750/fresh-service/fresh/report.json","242c09c6196980e5e0552be822e93c00797486f17e18d70bedef1b060c7daa80"),
("service-x64-M","/home/qian-qi/throughput-final-ci-observation-20261107/20261107T185919Z-819309fd3122-f4da8b5c/service-artifact-read-v1/13586194181/from-zero-native/confirmation/report.json","44afacbb1d64f50053926a483feee888e49b322be8d9d8dd0dadc3f8c35a2379")]
FLAGS={"cpu_intervals_are_nested_not_additive":True,"host_checks_are_nested_not_additive":True,"phase_cpu_excludes_scoped_workers":True,"host_cpu_includes_each_calling_thread":True,"host_cpu_is_full_worker_cpu":False,"observation_has_consensus_authority":False}
def git(*args):
 return subprocess.run(["git",*args],cwd=ROOT,env=ENV,text=True,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout.strip()
def sha(data):return hashlib.sha256(data).hexdigest()
def source():
 return {"head":git("rev-parse","HEAD"),"tree":git("rev-parse","HEAD^{tree}"),"status":git("status","--porcelain=v1","--untracked-files=all"),"sha256":{p:sha((ROOT/p).read_bytes()) for p in SOURCES}}
def identity(p):
 s=p.stat()
 return {"dev":s.st_dev,"ino":s.st_ino,"size":s.st_size,"mtime_ns":s.st_mtime_ns,"ctime_ns":s.st_ctime_ns}
def phase_map(rows):
 assert len(rows)==len({r["phase"] for r in rows})
 return {r["phase"]:r for r in rows}
def metric(rows,key):
 entered=[r for r in rows if r["started"]]
 missing=sum(r[key] is None for r in entered)
 known=sum(r[key] for r in entered if r[key] is not None)
 return {"known_sum_ns":known,"unknown_entered_rows":missing,"total_ns":None if missing or not entered else known}
def aggregate_phases(groups):
 buckets=collections.defaultdict(list)
 for rows in groups:
  for name,r in phase_map(rows).items():buckets[name].append(r)
 result={}
 inactive=[]
 for name,rows in buckets.items():
  entered=[r for r in rows if r["started"]]
  if not entered:
   inactive.append(name);continue
  parents={r["parent_phase"] for r in entered};assert len(parents)==1
  result[name]={"parent_phase":next(iter(parents)),"started":len(entered),"not_entered":len(rows)-len(entered),"completed":sum(r["completed"] for r in entered),"accepted":sum(r["accepted"] is True for r in entered),"rejected":sum(r["accepted"] is False for r in entered),"error_codes":dict(collections.Counter(r["error_code"] for r in entered if r["error_code"] is not None)),"cpu":metric(rows,"thread_cpu_ns"),"wall":metric(rows,"wall_ns")}
 return {"entered":result,"never_entered":inactive}
def aggregate_host(observations):
 result={}
 for name in ["resolve","initial","checkpoint","final"]:
  rows=[next(h for h in n["host_checks"] if h["phase"]==name) for n in observations]
  numeric=["calls_started","calls_completed","calls_accepted","calls_rejected","calls_unfinished","cpu_clock_unknown_calls","wall_clock_unknown_calls"]
  data={k:sum(r[k] for r in rows) for k in numeric}
  for key in ["thread_cpu_ns","wall_ns"]:
   entered=[r for r in rows if r["calls_started"]]
   data[key]=None if not entered or any(r[key] is None for r in entered) else sum(r[key] for r in entered)
  data["error_codes"]=dict(collections.Counter(r["last_error_code"] for r in rows if r["last_error_code"] is not None))
  result[name]=data
 return result
before=source()
assert before["head"]=="819309fd312298e099642e1253b1d4ba07113e98" and before["tree"]=="f9d63abb9e2931fd78e26ccb87e3a7955068f267" and before["status"]=="",before
core={"schema":"trnm-actual819-native-import-readback-v1","sample_definition":"Every independent_history_page_replay row in both phases of both exact original reports; failed rows and unentered phases retained; sums only across distinct replay rows, never parent plus child.","units":"integer nanoseconds; wall and CPU are independent; no wall-minus-CPU attribution","flags":FLAGS,"source_before":before,"inputs":[],"cases":[],"native_or_benchmark_executed":False,"raw_modified":False}
total_rows=total_accepted=total_failed=0
scopes=set()
for label,name,want in INPUTS:
 p=pathlib.Path(name);old=identity(p);raw=p.read_bytes();assert sha(raw)==want
 doc=json.loads(raw)
 inp={"label":label,"path":name,"sha256":want,"bytes":len(raw),"identity_before":old,"acquisition":{k:v for k,v in doc.items() if k.startswith("honest_chain")}}
 for phase in doc["phases"]:
  rows=phase["independent_history_page_replay"];obs=[r["native_import_observation"] for r in rows]
  assert len({r["history_call_index"] for r in rows})==len(rows)
  for n in obs:
   assert n["schema"]=="pon-local-history-import-observation-v1"
   assert all(n[k] is v for k,v in FLAGS.items())
   assert n["measurement_failures"]==0 and n["supplied_packets"]==len(n["packets"])==1
   assert n["packet_capacity"]==16
   scopes.add(n["clock_scope"])
   assert len(n["host_checks"])==4
   for h in n["host_checks"]:
    assert h["calls_started"]==h["calls_completed"]+h["calls_unfinished"]
    assert h["calls_completed"]==h["calls_accepted"]+h["calls_rejected"]
    assert h["calls_unfinished"]==h["calls_rejected"]==h["cpu_clock_unknown_calls"]==h["wall_clock_unknown_calls"]==0
    assert h["thread_cpu_ns"] is not None and h["wall_ns"] is not None
  case={"input":label,"mode":phase["mode"],"client_confirmed_transactions":phase["client_confirmed_transactions"],"replay_rows":len(rows),"accepted_rows":sum(r["replay_accepted"] for r in rows),"failed_rows":sum(not r["replay_accepted"] for r in rows),"caller_replay_cpu_ns":sum(r["replay_thread_cpu_ns"] for r in rows),"caller_replay_wall_ns":sum(r["replay_wall_ns"] for r in rows),"outer_replay_and_confirmation_cpu_ns":phase["independent_replay_and_confirmation_cpu_ns"],"outer_replay_and_confirmation_wall_ns":phase["independent_replay_and_confirmation_wall_ns"],"outer_interval_includes_History_network_caller_work":True,"host":aggregate_host(obs),"page_phases":aggregate_phases([n["phases"] for n in obs]),"packet_phases":aggregate_phases([pk["phases"] for n in obs for pk in n["packets"]]),"pages":[]}
  for r,n in zip(rows,obs):
   pk=phase_map(n["packets"][0]["phases"]);pg=phase_map(n["phases"]);h=next(h for h in n["host_checks"] if h["phase"]=="checkpoint")
   selected={}
   for name in ["context","work","admission","admission_prepare","execution","root_commitment","commit","submit_result"]:
    t=pk[name]
    selected[name]={"started":t["started"],"completed":t["completed"],"accepted":t["accepted"],"cpu_ns":t["thread_cpu_ns"],"wall_ns":t["wall_ns"],"error_code":t["error_code"]}
   case["pages"].append({"history_call_index":r["history_call_index"],"replay_started_ns":r["replay_started_ns"],"replay_ended_ns":r["replay_ended_ns"],"accepted":r["replay_accepted"],"error":r["replay_error"],"caller_cpu_ns":r["replay_thread_cpu_ns"],"caller_wall_ns":r["replay_wall_ns"],"checkpoint_host_calls":h["calls_started"],"checkpoint_host_cpu_ns":h["thread_cpu_ns"],"checkpoint_host_wall_ns":h["wall_ns"],"page_cpu_wait":{"cpu_ns":pg["cpu_wait"]["thread_cpu_ns"],"wall_ns":pg["cpu_wait"]["wall_ns"]},"packet_phases":selected})
  total_rows+=len(rows);total_accepted+=case["accepted_rows"];total_failed+=case["failed_rows"];core["cases"].append(case)
 inp["identity_after"]=identity(p);assert inp["identity_after"]==old
 core["inputs"].append(inp)
core["native_clock_scopes"]=sorted(scopes)
core["coverage"]={"replay_rows":total_rows,"accepted":total_accepted,"failed":total_failed,"rows_lost_by_analysis":0,"native_measurement_failures":0,"host_clock_unknown_calls":0,"host_rejected_calls":0,"host_unfinished_calls":0,"checkpoint_calls":sum(c["host"]["checkpoint"]["calls_started"] for c in core["cases"])}
core["source_after"]=source();assert core["source_after"]==before
core["source_unchanged"]=True
assert (total_rows,total_accepted,total_failed)==(21,20,1)
core["source_scope_notes"]={"fixed_fixture_workers":1,"harness":"tests/public_v3_from_zero.rs:1277-1286; fresh_challenge.rs:180,187 reuse same builder","exclusive_importer":"src/ingress.rs:2597-2598","all_three_owner_wait_phases_never_entered":all(all(name in c["packet_phases"]["never_entered"] for name in ["context_owner_wait","admission_owner_wait","commit_owner_wait"]) for c in core["cases"]),"executor_serial_path":"trnm-mvcc-fee/src/pon_executor.rs:3027-3033","host_frequency_preserved":"src/ingress/history_import.rs:258-285,301-307","observer_nested_scope":"src/ingress/history_import/observation.rs:226-232","root_commitment_only_M06_interval":"src/ingress/execution_observation.rs:67-112"}
assert core["source_scope_notes"]["all_three_owner_wait_phases_never_entered"]
blob=(json.dumps(core,sort_keys=True,separators=(",",":"))+"\n").encode()
with (OUT/"native-import-core-v1.json").open("xb") as f:f.write(blob)
print(json.dumps({"coverage":core["coverage"],"source_unchanged":core["source_unchanged"],"core_path":str(OUT/"native-import-core-v1.json"),"core_bytes":len(blob),"core_sha256":sha(blob),"cases":[{"input":c["input"],"mode":c["mode"],"rows":c["replay_rows"],"accepted":c["accepted_rows"],"failed":c["failed_rows"],"caller_cpu_ns":c["caller_replay_cpu_ns"],"host_checkpoint_cpu_ns":c["host"]["checkpoint"]["thread_cpu_ns"],"checkpoint_calls":c["host"]["checkpoint"]["calls_started"],"work_cpu_ns":c["packet_phases"]["entered"]["work"]["cpu"]["total_ns"]} for c in core["cases"]]},indent=2))
