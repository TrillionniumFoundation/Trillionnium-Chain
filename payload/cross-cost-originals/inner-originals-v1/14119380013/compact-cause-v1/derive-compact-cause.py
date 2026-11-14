import hashlib,json,os,pathlib,stat,sys,zipfile
E=pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-artifacts-20261114-v3");A=int(sys.argv[1]);I=E/"inner-originals-v1"/str(A);O=I/"compact-cause-v1"
def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def jb(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def fid(a):return (a.st_dev,a.st_ino,a.st_mode,a.st_nlink,a.st_size,a.st_mtime_ns,a.st_ctime_ns)
def read(p,cap):
 need(p.resolve()==p,"canonical")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap,"regular bounded")
  raw=f.read(cap+1);z=os.fstat(f.fileno())
 need(fid(a)==fid(z)==fid(p.lstat()) and len(raw)==a.st_size,"stable")
 return raw
def put(p,b):
 with p.open("xb") as f:f.write(b)
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
need(A in (14119380013,14119000610) and not O.exists(),"fixed/create only");O.mkdir(mode=0o700)
put(O/"derive-compact-cause.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
idx=json.loads(read(E/(str(A)+".index.json"),262144));zpath=E/(str(A)+".zip");zb=read(zpath,32*1024*1024);need(sha(zb)==idx["zip"]["sha256"],"ZIP SHA")
rp=next(x for x in idx["files"] if x["path"]=="from-zero-native/confirmation/report.json")
with zipfile.ZipFile(zpath) as z:raw=z.read(rp["path"])
need(len(raw)==rp["bytes"] and sha(raw)==rp["sha256"],"report SHA");r=json.loads(raw)
def scalar(v):return v is None or isinstance(v,(bool,int,float,str))
def response_summary(c):
 v=c.get("response");out={k:c.get(k) for k in ("status","error","started_ns","ended_ns","elapsed_wall_ns","client_thread_cpu_ns","deadline_ms","returned_after_deadline","returned_after_window")}
 if isinstance(v,dict):
  out["response"]={k:x for k,x in v.items() if scalar(x)}
  val=v.get("value")
  if isinstance(val,dict):
   out["value_scalar_fields"]={k:x for k,x in val.items() if scalar(x) and (not isinstance(x,str) or len(x)<=256)}
   out["value_keys"]=list(val)
  else:out["value_type"]=type(val).__name__
 return out
ph=[]
pins=[]
for i,p in enumerate(r["phases"]):
 bs="/phases/"+str(i)
 replays=[]
 for j,q in enumerate(p["independent_history_page_replay"]):
  row={k:v for k,v in q.items() if k!="native_import_observation"}
  row["json_pointer"]=bs+"/independent_history_page_replay/"+str(j)
  no=q["native_import_observation"]
  row["host_checks"]=no["host_checks"]
  row["native_measurement_failures"]=no["measurement_failures"]
  row["native_owner_mode"]=(no["native_attribution"]["page"] or {}).get("owner_mode")
  if p["mode"]=="from-zero-pressure":
   pn=put(O/("pressure-replay-"+str(j)+"-native-observation.json"),jb({"report":rp,"json_pointer":row["json_pointer"]+"/native_import_observation","original_value":no}))
   row["full_original_native_observation"]=pn;pins.append(pn)
  replays.append(row)
 ph.append({"json_pointer":bs,"phase_scalar_values":{k:v for k,v in p.items() if scalar(v)},"honest_submissions":[response_summary(c) for c in p["honest_submissions"]],"honest_history":[response_summary(c) for c in p["honest_history"]],"independent_history_page_replay":replays,"verification_errors":p["verification_errors"]})
out={"schema":"trnm-R1-cross-arch-compact-cause-v1","artifact_id":A,"run_id":43604217412,"run_attempt":1,"zip":idx["zip"],"report":rp,"phase_facts":ph,"finite_target_met":r["finite_target_met"],"invariant_target_met":r["invariant_target_met"],"same_packet_sequence_in_both_runs":r["same_packet_sequence_in_both_runs"],"qualification_flags":{k:r[k] for k in ("production_activation","public_network_ready","work_profile_qualified","strongest_honest_producer_used")},"bounds":"Raw report kept in verified ZIP. Phase and Host intervals are nested, not additive; Host CPU includes actual calling threads and is not all worker CPU. No scheduling or throttle causation inferred.","no_inner_code_executed":True}
b=jb(out);need(len(b)<=65536,"small review cap");pin=put(O/"summary.json",b)
print(json.dumps({"summary":pin,"native_observations":pins,"phase_counts":[{"mode":p["phase_scalar_values"]["mode"],"submit_response_values":[x.get("value_scalar_fields") for x in p["honest_submissions"]],"history_response_values":[x.get("value_scalar_fields") for x in p["honest_history"]],"replays":len(p["independent_history_page_replay"])} for p in ph]},sort_keys=True))
