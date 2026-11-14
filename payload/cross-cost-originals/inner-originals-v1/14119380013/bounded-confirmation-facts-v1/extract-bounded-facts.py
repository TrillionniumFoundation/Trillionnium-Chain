import hashlib,json,os,pathlib,stat,sys,zipfile
E=pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-artifacts-20261114-v3");A=int(sys.argv[1]);I=E/"inner-originals-v1"/str(A);O=I/"bounded-confirmation-facts-v1"
def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def jb(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def identity(a):return (a.st_dev,a.st_ino,a.st_mode,a.st_nlink,a.st_size,a.st_mtime_ns,a.st_ctime_ns)
def read(p,cap):
 need(p.resolve()==p,"canonical")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap,"bounded regular")
  b=f.read(cap+1);z=os.fstat(f.fileno())
 need(identity(a)==identity(z)==identity(p.lstat()) and len(b)==a.st_size,"stable")
 return b
def put(p,b):
 with p.open("xb") as f:f.write(b)
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
need(A in (14119380013,14119000610) and not O.exists(),"fixed/create only");O.mkdir(mode=0o700)
put(O/"extract-bounded-facts.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
index=json.loads(read(E/(str(A)+".index.json"),262144));zp=E/(str(A)+".zip");zipraw=read(zp,32*1024*1024);need(sha(zipraw)==index["zip"]["sha256"],"closed ZIP")
member="from-zero-native/confirmation/report.json";rp=next(x for x in index["files"] if x["path"]==member)
with zipfile.ZipFile(zp) as z:raw=z.read(member)
need(len(raw)==rp["bytes"] and sha(raw)==rp["sha256"],"report pin");r=json.loads(raw)
def scalar(v):return v is None or isinstance(v,(bool,int,float,str))
def simple(v,depth=0):
 if scalar(v):return v if not isinstance(v,str) or len(v)<=512 else {"type":"long_string","bytes":len(v.encode())}
 if isinstance(v,list):
  if len(v)<=12 and depth<2:return [simple(x,depth+1) for x in v]
  return {"type":"array","length":len(v),"first_element":simple(v[0],depth+1) if v else None}
 if depth>=4:return {"type":"object","keys":list(v)}
 return {k:simple(x,depth+1) for k,x in v.items()}
phase=[]
for i,p in enumerate(r["phases"]):
 base="/phases/"+str(i)
 rpclists={}
 for k in ("honest_submissions","honest_history"):
  rows=[]
  for j,c in enumerate(p[k]):
   resp=c.get("response");resp_summary=None
   if isinstance(resp,dict):
    resp_summary={key:val for key,val in resp.items() if key!="value"}
    value=resp.get("value");resp_summary["value_summary"]=simple(value)
   rows.append({"json_pointer":base+"/"+k+"/"+str(j),"record":{key:val for key,val in c.items() if key not in ("response","metrics")},"response":resp_summary})
  rpclists[k]=rows
 replays=[]
 for j,q in enumerate(p["independent_history_page_replay"]):
  no=q["native_import_observation"]
  selected={k:v for k,v in q.items() if k!="native_import_observation"}
  selected["native_observation_outline"]=simple(no)
  selected["json_pointer"]=base+"/independent_history_page_replay/"+str(j)
  replays.append(selected)
 phase.append({"json_pointer":base,"scalars":{k:v for k,v in p.items() if scalar(v)},"RPCs":rpclists,"replays":replays,"verification_errors":p["verification_errors"]})
out={"schema":"trnm-R1-cross-arch-bounded-original-confirmation-facts-v1","artifact_id":A,"zip":index["zip"],"report":rp,"phase_facts":phase,"qualification_flags":{k:r[k] for k in ("finite_target_met","invariant_target_met","production_activation","public_network_ready","work_profile_qualified","strongest_honest_producer_used")},"nested_intervals_not_additive":True,"no_CPU_wall_causation_inferred":True,"original_report_remains_only_in_verified_ZIP":True}
op=put(O/"facts.json",jb(out))
lines=raw.decode().splitlines()
selected_lines=set()
for n,line in enumerate(lines):
 if any(x in line for x in ('"finite_target_met"', '"finite_business_target_met"', '"client_confirmed_transactions"', '"requested_window_ns"', '"workers":', '"replay_error"', '"replay_started_ns"', '"replay_ended_ns"', '"replay_thread_cpu_ns"', '"replay_wall_ns"', '"replay_accepted"', '"replay_error": "PUBLIC_REQUEST_DEADLINE"')):
  for j in range(max(0,n-1),min(len(lines),n+2)):
   if len(lines[j])<=2048:selected_lines.add(j)
need(len(selected_lines)<=512,"bounded raw excerpts")
xp=put(O/"original-line-excerpts.json",jb({"report":rp,"line_numbering":"1-based original UTF-8 report bytes","lines":[{"line":n+1,"text":lines[n]} for n in sorted(selected_lines)]}))
print(json.dumps({"facts":op,"excerpts":xp,"pressure_first_replay":phase[1]["replays"][0] if phase[1]["replays"] else None,"RPC_counts":[{k:len(v) for k,v in x["RPCs"].items()} for x in phase]},sort_keys=True))
