import os,sys,json,pathlib,hashlib,stat,io,zipfile,time
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1")
O=pathlib.Path("/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/artifact-readback-v1");O.mkdir()
def read(p,cap):
 fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap
  chunks=[];n=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   n+=len(b);assert n<=cap;chunks.append(b)
  z=os.fstat(fd);c=os.lstat(p)
  fp=lambda q:(q.st_dev,q.st_ino,q.st_size,q.st_mtime_ns,q.st_ctime_ns)
  assert fp(a)==fp(z)==fp(c)
  return b"".join(chunks),{"path":str(p),"bytes":n,"sha256":hashlib.sha256(b"".join(chunks)).hexdigest(),"fingerprint":list(fp(a))}
 finally:os.close(fd)
def duplicate(xs):
 d={}
 for k,v in xs:
  if k in d:raise ValueError("duplicate key")
  d[k]=v
 return d
def parse(b):return json.loads(b,object_pairs_hook=duplicate,parse_constant=lambda x:(_ for _ in ()).throw(ValueError("nonfinite")))
def keep(d,keys):return {k:d[k] for k in keys if k in d}
def calls(xs):
 assert type(xs) is list
 rows=[keep(r,["status","error","started_ns","ended_ns","elapsed_wall_ns","client_thread_cpu_ns","returned_after_deadline","returned_after_window","packet_index"]) for r in xs]
 return {"count":len(xs),"status_ok":sum(r.get("status")=="ok" for r in xs),"on_time_ok":sum(r.get("status")=="ok" and r.get("returned_after_deadline") is False and r.get("returned_after_window") is False for r in xs),"rows":rows}
pins=[("head",14117751904,6479218,"b77dd9120901f5e4d3ccdd21be7f307fecabedabaca28a9d3c3d184d867d6ef8","1aa8604941327a834c9ae2897006f45cec3f71d19a97887734635bb1f32a1924"),("prospective-merge",14117403147,6451341,"2f13596450302835bcaf325d3b2364b95d1eeb6abe9f25dbc353a1efc4f2802a","c61b4c8d1e8c43d8f3b2f9555add5fc0bfffdf84606f995ca62d149f37058358")]
result={"schema":"trnm-R1-w1-fresh-original-report-readback-v1","read_at_unix_ns":time.time_ns(),"scope":"Original ZIP bytes and selected JSON fields only; no artifact code/import/test/native execution.","jobs":[]}
for kind,aid,size,sha,msha in pins:
 zraw,zpin=read(E/"R1-W1-complete-artifacts-v1"/(str(aid)+".zip"),10*1024*1024);assert(len(zraw),zpin["sha256"])==(size,sha)
 mraw,mpin=read(E/"R1-W1-inner-originals-v1"/str(aid)/"fresh-service"/"manifest.json",20000);assert mpin["sha256"]==msha
 m=parse(mraw);job={"source_kind":kind,"artifact_id":aid,"zip":zpin,"manifest":mpin,"source_before":m["source_before"],"source_after":m["source_after"],"runs":m["runs"],"reports":[]}
 with zipfile.ZipFile(io.BytesIO(zraw)) as z:
  infos=z.infolist();assert len(infos)==57 and len({i.filename for i in infos})==57
  for i in infos:
   p=pathlib.PurePosixPath(i.filename);assert not p.is_absolute() and ".." not in p.parts and "\\" not in i.filename and not stat.S_ISLNK(i.external_attr>>16)
  for variant in ["original","fresh"]:
   name="fresh-service/"+variant+"/report.json";info=z.getinfo(name);assert info.file_size<=32*1024*1024
   b=z.read(name);assert len(b)==info.file_size and hashlib.sha256(b).hexdigest()==m["files"][variant+"/report.json"]
   d=parse(b)
   report={"member":name,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"zip_crc32":format(info.CRC,"08x"),"top":keep(d,["schema","finite_target_met","invariant_target_met","same_packet_sequence_in_both_runs","requested_window_ns","attack_workers","construction_complete","fresh_construction_target_met","negative_cache_enabled","negative_cache_observation_source","honest_chain_process_cpu_ns","honest_chain_process_cpu_scope"]),"top_keys":sorted(d),"phases":[]}
   for pi,p in enumerate(d["phases"]):
    one={"json_pointer":"/phases/"+str(pi),**keep(p,["mode","requested_window_ns","workers","business_started_ns","confirmation_ended_ns","client_confirmation_latency_ns","client_confirmed_transactions","client_confirmed_before_original_window_end","independent_client_confirmation","independent_replay_and_confirmation_cpu_ns","independent_replay_and_confirmation_wall_ns","verification_errors","honest_head_successes_in_window","maximum_honest_head_gap_ns","attacker_workers_cpu_ns","reader_cpu_ns","overlap_demonstrated","completed_false_calls_before_business","completed_false_calls_at_confirmation","overlapping_false_calls","no_attack_accepted","accounting_closed","full_native_state_equal","invariant_target_met","finite_business_target_met","initial_meter","final_meter","service","independent_history_page_replay","independent_final_confirmation_stage"])}
    for field in ["honest_submissions","honest_history","honest_heads"]:one[field]=calls(p[field])
    recs=p["observations"]["records"];one["request_observation_summary"]={"records":len(recs),"complete_fields":keep(p["observations"],["complete","capacity","dropped","unretained","maximum_records"]),"full_work_started":sum(x.get("full_work_started") is True for x in recs),"full_work_accepted":sum(x.get("full_work_accepted") is True for x in recs),"record_field_names":sorted({k for x in recs for k in x})}
    report["phases"].append(one)
   job["reports"].append(report)
 result["jobs"].append(job)
raw=(json.dumps(result,indent=2,sort_keys=True)+"\n").encode();assert len(raw)<=4*1024*1024
with (O/"report-extract.json").open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
with (O/"producer.py").open("x") as f:f.write(sys.argv[1]);f.flush();os.fsync(f.fileno())
short=[]
for j in result["jobs"]:
 for r in j["reports"]:
  for p in r["phases"]:
   replays=p["independent_history_page_replay"]
   short.append({"kind":j["source_kind"],"variant":r["member"],"mode":p["mode"],"finite":p.get("finite_business_target_met"),"invariants":p.get("invariant_target_met"),"ACK":p["honest_submissions"]["on_time_ok"],"history":p["honest_history"]["on_time_ok"],"replays":len(replays),"accepted":sum(x.get("replay_accepted") is True for x in replays),"errors":p.get("verification_errors"),"start":p.get("business_started_ns"),"confirmation":p.get("confirmation_ended_ns"),"replay_rows": [{k:v for k,v in x.items() if k!="native_import_observation"} for x in replays]})
print(json.dumps({"output":{"path":str(O/"report-extract.json"),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()},"phases":short},sort_keys=True))
